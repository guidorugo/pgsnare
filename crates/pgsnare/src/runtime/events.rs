// SPDX-License-Identifier: Apache-2.0

//! Handing events over, without ever making traffic wait.
//!
//! The session logic raises an event as an `EventBody`. The runtime notes
//! the time and hands the event to the dispatcher of [`crate::sinks`],
//! which does everything else: it removes what must not be shown, folds
//! repeated hits, seals the event with an identifier and the labels of
//! this instance, and delivers it to every sink of the proxy.
//!
//! A session never waits for any of that. [`Events::submit`] puts the event
//! into a queue of fixed length and returns. When the queue is full, the
//! event is dropped and counted.

use std::sync::Arc;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use pgsnare_core::event::{EventBody, EventId, Labels, SessionId, Timestamp};
use pgsnare_core::extension::EventSink;

use crate::redact::Redaction;
use crate::sinks::SinkOptions;
use crate::sinks::dispatcher::{Dispatcher, DispatcherSettings};

use super::status::Status;

/// Where the sessions of a proxy hand their events.
pub(crate) struct Events {
    dispatcher: Dispatcher,
    status: Arc<Status>,
}

/// What the events of a proxy need apart from its sinks.
pub(crate) struct EventSettings {
    /// How many events may wait for the dispatcher.
    pub(crate) capacity: usize,
    /// How long repeated hits are folded into one event.
    pub(crate) dedup_window: Duration,
    /// The labels every event carries.
    pub(crate) labels: Labels,
    /// What removes from an event what must not be shown.
    pub(crate) redaction: Redaction,
}

impl Events {
    /// Starts the dispatcher for these sinks. Must be called inside a
    /// tokio runtime.
    pub(crate) fn new(
        sinks: Vec<(Arc<dyn EventSink>, SinkOptions)>,
        settings: EventSettings,
        status: Arc<Status>,
    ) -> Self {
        let dispatcher = Dispatcher::start(
            DispatcherSettings {
                queue_size: settings.capacity,
                dedup_window: settings.dedup_window,
                labels: settings.labels,
                redaction: settings.redaction,
                event_id: new_event_id,
            },
            sinks,
            Arc::clone(&status),
        );
        Self { dispatcher, status }
    }

    /// Takes an event from a session. Returns at once.
    pub(crate) fn submit(&self, body: Box<EventBody>) {
        self.status.event_emitted();
        self.dispatcher.submit(body, now());
    }

    /// Lets the events that wait be delivered, for up to `patience`, and
    /// stops the dispatcher. What is left then is dropped and counted.
    pub(crate) async fn close(&self, patience: Duration) {
        self.dispatcher.stop(patience).await;
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

/// 128 bits for an identifier.
///
/// They come from the secure random generator of the TLS provider. When
/// that generator reports a failure, they come from `fallback_u128`, which
/// is not a secure random generator. This function is therefore for
/// identifiers, which only have to differ from each other, and for nothing
/// that has to be secret or hard to guess.
fn random_u128() -> u128 {
    let mut bytes = [0u8; 16];
    if crate::tls::provider()
        .secure_random
        .fill(&mut bytes)
        .is_err()
    {
        // The generator of the TLS provider has reported a failure. An
        // identifier that is merely unlikely to repeat is better than none.
        return fallback_u128();
    }
    u128::from_be_bytes(bytes)
}

/// 128 bits that are unlikely to repeat, made without the generator of the
/// TLS provider. They are not secure random numbers.
///
/// Each half is a 64-bit hash of the time of the clock, in nanoseconds
/// since 1970, or of zero when the clock is set before 1970. The hasher is
/// the one a `HashMap` of the standard library uses, under keys that the
/// library chose at random, and each half gets a new one. Neither the
/// clock nor that hasher is made to give a value that cannot be guessed.
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

/// An identifier for a new event.
pub(crate) fn new_event_id() -> EventId {
    EventId::from_u128(random_u128())
}

#[cfg(test)]
mod tests {
    use std::net::{IpAddr, Ipv4Addr};
    use std::sync::Mutex;

    use pgsnare_core::event::{Event, EventKind};
    use pgsnare_core::extension::SinkFuture;
    use pgsnare_core::session::SessionOrigin;

    use super::*;

    /// Keeps what it is given.
    #[derive(Default)]
    struct Memory {
        delivered: Mutex<Vec<Event>>,
    }

    impl EventSink for Memory {
        fn name(&self) -> &str {
            "memory"
        }

        fn deliver<'a>(&'a self, event: &'a Event) -> SinkFuture<'a> {
            Box::pin(async move {
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

    #[tokio::test]
    async fn an_event_is_stamped_sealed_and_reaches_every_sink() {
        let first = Arc::new(Memory::default());
        let second = Arc::new(Memory::default());
        let status = Arc::new(Status::new());
        let labels: Labels = [("pod".to_owned(), "pgsnare-0".to_owned())].into();
        let events = Events::new(
            vec![
                (first.clone(), SinkOptions::default()),
                (second.clone(), SinkOptions::default()),
            ],
            EventSettings {
                capacity: 8,
                dedup_window: Duration::from_secs(60),
                labels: labels.clone(),
                redaction: Redaction::default(),
            },
            status.clone(),
        );

        let before = now();
        events.submit(body());
        events.submit(body());
        events.close(Duration::from_secs(10)).await;

        for sink in [&first, &second] {
            let delivered = sink.delivered.lock().unwrap();
            assert_eq!(delivered.len(), 2);
            assert_eq!(delivered[0].body.kind, EventKind::InspectionBypassed);
            assert_eq!(delivered[0].labels, labels);
            assert_ne!(delivered[0].event_id, delivered[1].event_id);
            // The time is the one of the moment the session raised it.
            assert!(delivered[0].timestamp >= before);
            assert!(delivered[0].timestamp <= now());
        }
        // Both sinks got the same event.
        assert_eq!(
            first.delivered.lock().unwrap()[0],
            second.delivered.lock().unwrap()[0]
        );
        let counters = status.counters();
        assert_eq!(counters.events_emitted, 2);
        assert_eq!(counters.events_dropped, 0);
        assert_eq!(counters.event_queue_depth, 0);

        // An event that is raised after the dispatcher has stopped is
        // dropped and counted. The session that raised it does not wait.
        events.submit(body());
        assert_eq!(status.counters().events_emitted, 3);
        assert_eq!(status.counters().events_dropped, 1);
    }

    #[test]
    fn identifiers_do_not_repeat() {
        assert_ne!(new_session_id(), new_session_id());
        assert_ne!(new_event_id(), new_event_id());
        assert_ne!(fallback_u128(), fallback_u128());
    }
}
