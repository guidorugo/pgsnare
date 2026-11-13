// SPDX-License-Identifier: Apache-2.0

//! Handing events over, without ever making traffic wait.
//!
//! The session logic raises an event as an `EventBody`. The runtime seals
//! it with an identifier, the time and the labels of this instance, and
//! hands it to every sink of the proxy.
//!
//! A session never waits for that. Each delivery runs as a task of its
//! own, and only so many may be under way at once. When that many are, a
//! further event is dropped and counted.
//!
//! This is all there is: no queue per sink, no retry, no deduplication and
//! no rate limit. Those belong to the dispatcher, which will take the place
//! of this module between the sessions and the sinks.

use std::sync::Arc;
use std::time::{SystemTime, UNIX_EPOCH};

use pgsnare_core::event::{EventBody, EventId, Labels, SessionId, Timestamp};
use pgsnare_core::extension::EventSink;
use tokio::sync::Semaphore;

use super::status::Status;

/// Where the sessions of a proxy hand their events.
pub(crate) struct Events {
    sinks: Vec<Arc<dyn EventSink>>,
    labels: Labels,
    /// One permit for each delivery that may be under way.
    in_flight: Arc<Semaphore>,
    status: Arc<Status>,
}

impl Events {
    pub(crate) fn new(
        sinks: Vec<Arc<dyn EventSink>>,
        labels: Labels,
        capacity: usize,
        status: Arc<Status>,
    ) -> Self {
        Self {
            sinks,
            labels,
            in_flight: Arc::new(Semaphore::new(capacity.max(1))),
            status,
        }
    }

    /// Takes an event from a session. Returns at once.
    pub(crate) fn submit(&self, body: Box<EventBody>) {
        self.status.event_emitted();
        let event = Arc::new((*body).seal(
            EventId::from_u128(random_u128()),
            now(),
            self.labels.clone(),
        ));
        for sink in &self.sinks {
            let Ok(permit) = Arc::clone(&self.in_flight).try_acquire_owned() else {
                self.status.event_dropped();
                tracing::warn!(
                    sink = sink.name(),
                    "an event was dropped: too many are waiting to be delivered"
                );
                continue;
            };
            let sink = Arc::clone(sink);
            let event = Arc::clone(&event);
            let status = Arc::clone(&self.status);
            tokio::spawn(async move {
                let _permit = permit;
                if let Err(error) = sink.deliver(&event).await {
                    status.event_delivery_failed();
                    tracing::warn!(
                        sink = sink.name(),
                        retryable = error.is_retryable(),
                        "an event could not be delivered"
                    );
                }
            });
        }
    }
}

/// The time, for an event. A clock before 1970 or after 9999 gives the
/// nearest end of the range.
fn now() -> Timestamp {
    match SystemTime::now().duration_since(UNIX_EPOCH) {
        Ok(since) => {
            Timestamp::from_unix(since.as_secs(), since.subsec_nanos()).unwrap_or(Timestamp::MAX)
        }
        Err(_) => Timestamp::UNIX_EPOCH,
    }
}

/// 128 bits from the secure random generator of the TLS provider.
fn random_u128() -> u128 {
    let mut bytes = [0u8; 16];
    if crate::tls::provider()
        .secure_random
        .fill(&mut bytes)
        .is_err()
    {
        // The generator of the operating system has failed. An identifier
        // that is merely unlikely to repeat is better than none.
        return fallback_u128();
    }
    u128::from_be_bytes(bytes)
}

fn fallback_u128() -> u128 {
    use std::collections::hash_map::RandomState;
    use std::hash::{BuildHasher, Hasher};

    let half = || {
        let mut hasher = RandomState::new().build_hasher();
        hasher.write_u128(
            SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .map_or(0, |since| since.as_nanos()),
        );
        u128::from(hasher.finish())
    };
    (half() << 64) | half()
}

/// An identifier for a new session.
pub(crate) fn new_session_id() -> SessionId {
    SessionId::from_u128(random_u128())
}

#[cfg(test)]
mod tests {
    use std::net::{IpAddr, Ipv4Addr};
    use std::sync::Mutex;
    use std::time::Duration;

    use pgsnare_core::event::{Event, EventKind};
    use pgsnare_core::extension::{SinkError, SinkFuture};
    use pgsnare_core::session::SessionOrigin;
    use tokio::sync::Notify;

    use super::*;

    /// Keeps what it is given. It can be made to wait, and to fail.
    #[derive(Default)]
    struct Memory {
        delivered: Mutex<Vec<Event>>,
        gate: Option<Arc<Notify>>,
        fail: bool,
    }

    impl EventSink for Memory {
        fn name(&self) -> &str {
            "memory"
        }

        fn deliver<'a>(&'a self, event: &'a Event) -> SinkFuture<'a> {
            Box::pin(async move {
                if let Some(gate) = &self.gate {
                    gate.notified().await;
                }
                if self.fail {
                    return Err(SinkError::retryable("no"));
                }
                self.delivered.lock().unwrap().push(event.clone());
                Ok(())
            })
        }
    }

    fn body() -> Box<EventBody> {
        let origin = SessionOrigin::new(
            SessionId::from_u128(9),
            IpAddr::V4(Ipv4Addr::new(192, 0, 2, 10)),
            49_152,
            false,
        );
        Box::new(EventBody::new(EventKind::InspectionBypassed, &origin))
    }

    async fn settle() {
        for _ in 0..50 {
            tokio::task::yield_now().await;
        }
        tokio::time::sleep(Duration::from_millis(20)).await;
    }

    #[tokio::test]
    async fn an_event_is_sealed_and_reaches_every_sink() {
        let first = Arc::new(Memory::default());
        let second = Arc::new(Memory::default());
        let status = Arc::new(Status::new());
        let labels: Labels = [("pod".to_owned(), "pgsnare-0".to_owned())].into();
        let events = Events::new(
            vec![first.clone(), second.clone()],
            labels.clone(),
            8,
            status.clone(),
        );

        events.submit(body());
        events.submit(body());
        settle().await;

        for sink in [&first, &second] {
            let delivered = sink.delivered.lock().unwrap();
            assert_eq!(delivered.len(), 2);
            assert_eq!(delivered[0].body.kind, EventKind::InspectionBypassed);
            assert_eq!(delivered[0].labels, labels);
            assert_ne!(delivered[0].event_id, delivered[1].event_id);
            assert!(delivered[0].timestamp > Timestamp::UNIX_EPOCH);
        }
        // Both sinks got the same event.
        assert_eq!(
            first.delivered.lock().unwrap()[0],
            second.delivered.lock().unwrap()[0]
        );
        let counters = status.counters();
        assert_eq!(counters.events_emitted, 2);
        assert_eq!(counters.events_dropped, 0);
    }

    #[tokio::test]
    async fn a_slow_sink_never_holds_up_a_session_and_the_overflow_is_counted() {
        let gate = Arc::new(Notify::new());
        let sink = Arc::new(Memory {
            gate: Some(gate.clone()),
            ..Memory::default()
        });
        let status = Arc::new(Status::new());
        let events = Events::new(vec![sink.clone()], Labels::new(), 2, status.clone());

        // None of these calls waits, though no delivery can finish.
        for _ in 0..5 {
            events.submit(body());
        }
        settle().await;
        assert_eq!(status.counters().events_emitted, 5);
        assert_eq!(status.counters().events_dropped, 3);
        assert!(sink.delivered.lock().unwrap().is_empty());

        // The two that were taken are delivered once the sink moves again.
        gate.notify_waiters();
        settle().await;
        assert_eq!(sink.delivered.lock().unwrap().len(), 2);

        // And there is room again.
        gate.notify_one();
        events.submit(body());
        settle().await;
        assert_eq!(sink.delivered.lock().unwrap().len(), 3);
        assert_eq!(status.counters().events_dropped, 3);
    }

    #[tokio::test]
    async fn a_failed_delivery_is_counted() {
        let sink = Arc::new(Memory {
            fail: true,
            ..Memory::default()
        });
        let status = Arc::new(Status::new());
        let events = Events::new(vec![sink], Labels::new(), 2, status.clone());
        events.submit(body());
        settle().await;
        assert_eq!(status.counters().event_delivery_failures, 1);
    }

    #[test]
    fn identifiers_do_not_repeat() {
        let a = new_session_id();
        let b = new_session_id();
        assert_ne!(a, b);
        assert_ne!(fallback_u128(), fallback_u128());
    }
}
