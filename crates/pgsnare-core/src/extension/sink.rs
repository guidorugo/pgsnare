// SPDX-License-Identifier: Apache-2.0

//! The event sink: where events are delivered.

use core::fmt;
use core::future::Future;
use core::pin::Pin;

use crate::event::Event;

/// The future an [`EventSink`] returns from a delivery.
pub type SinkFuture<'a> = Pin<Box<dyn Future<Output = Result<(), SinkError>> + Send + 'a>>;

/// A destination for events, such as a webhook, a file or standard output.
///
/// A sink makes one attempt to deliver one event. Queueing, rate limiting,
/// retrying and counting what was dropped are the job of the dispatcher that
/// calls it, so every sink gets them without implementing them.
///
/// A sink is never called on the data path. Database traffic does not wait
/// for it, however slow it is.
///
/// The event it receives has already been redacted. A sink must not add
/// anything to its output that could hold a honeytoken value, a password or
/// key material, and must not write any of those to a log.
pub trait EventSink: Send + Sync + 'static {
    /// A short fixed name for logs and metrics, such as `webhook`. It comes
    /// from the implementation or from configuration, never from the
    /// network.
    fn name(&self) -> &str;

    /// Makes one attempt to deliver one event.
    ///
    /// The returned future resolves to an error when the attempt failed.
    /// [`SinkError::is_retryable`] tells the dispatcher whether another
    /// attempt can succeed.
    fn deliver<'a>(&'a self, event: &'a Event) -> SinkFuture<'a>;
}

/// One attempt to deliver an event failed.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct SinkError {
    retryable: bool,
    message: String,
}

impl SinkError {
    /// A failure that may pass, such as a timeout or a refused connection.
    /// The dispatcher tries again later.
    ///
    /// The message ends up in a log. It must not contain the event, a
    /// secret, or anything else that should not be there.
    #[must_use]
    pub fn retryable(message: impl Into<String>) -> Self {
        Self {
            retryable: true,
            message: message.into(),
        }
    }

    /// A failure that another attempt cannot fix, such as a destination that
    /// rejects the event. The dispatcher drops the event and counts it.
    ///
    /// The message ends up in a log. It must not contain the event, a
    /// secret, or anything else that should not be there.
    #[must_use]
    pub fn permanent(message: impl Into<String>) -> Self {
        Self {
            retryable: false,
            message: message.into(),
        }
    }

    /// Whether another attempt can succeed.
    #[must_use]
    pub const fn is_retryable(&self) -> bool {
        self.retryable
    }

    /// What went wrong.
    #[must_use]
    pub fn message(&self) -> &str {
        &self.message
    }
}

impl fmt::Display for SinkError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.message)
    }
}

impl core::error::Error for SinkError {}

#[cfg(test)]
mod tests {
    use core::net::{IpAddr, Ipv4Addr};
    use core::task::{Context, Poll, Waker};
    use std::sync::{Arc, Mutex};

    use crate::event::{EventBody, EventId, EventKind, Labels, SessionId, Timestamp};
    use crate::session::SessionOrigin;

    use super::*;

    /// Keeps what it is given, and fails when told to.
    #[derive(Default)]
    struct Memory {
        delivered: Mutex<Vec<Event>>,
        fail_with: Option<SinkError>,
    }

    impl EventSink for Memory {
        fn name(&self) -> &str {
            "memory"
        }

        fn deliver<'a>(&'a self, event: &'a Event) -> SinkFuture<'a> {
            Box::pin(async move {
                if let Some(error) = &self.fail_with {
                    return Err(error.clone());
                }
                self.delivered.lock().unwrap().push(event.clone());
                Ok(())
            })
        }
    }

    /// Runs a future that never has to wait.
    fn run<T>(mut future: Pin<Box<dyn Future<Output = T> + Send + '_>>) -> T {
        let mut context = Context::from_waker(Waker::noop());
        match future.as_mut().poll(&mut context) {
            Poll::Ready(value) => value,
            Poll::Pending => panic!("the future was expected to finish at once"),
        }
    }

    fn event() -> Event {
        let origin = SessionOrigin::new(
            SessionId::from_u128(1),
            IpAddr::V4(Ipv4Addr::new(192, 0, 2, 10)),
            49_152,
            true,
        );
        EventBody::new(EventKind::TokenHit, &origin).seal(
            EventId::from_u128(2),
            Timestamp::UNIX_EPOCH,
            Labels::new(),
        )
    }

    #[test]
    fn a_sink_can_be_used_through_a_trait_object() {
        let memory = Arc::new(Memory::default());
        let sink: Arc<dyn EventSink> = memory.clone();
        assert_eq!(sink.name(), "memory");

        let event = event();
        assert_eq!(run(sink.deliver(&event)), Ok(()));
        assert_eq!(run(sink.deliver(&event)), Ok(()));
        assert_eq!(*memory.delivered.lock().unwrap(), [event.clone(), event]);
    }

    #[test]
    fn a_failure_says_whether_to_try_again() {
        let timeout = SinkError::retryable("timed out");
        assert!(timeout.is_retryable());
        assert_eq!(timeout.message(), "timed out");
        assert_eq!(timeout.to_string(), "timed out");

        let rejected = SinkError::permanent(String::from("rejected with status 400"));
        assert!(!rejected.is_retryable());

        let sink = Memory {
            fail_with: Some(timeout.clone()),
            ..Memory::default()
        };
        assert_eq!(run(sink.deliver(&event())), Err(timeout));
        assert!(sink.delivered.lock().unwrap().is_empty());
    }

    #[test]
    fn sinks_and_their_futures_can_move_between_threads() {
        fn assert_send_sync<T: Send + Sync + ?Sized>() {}
        fn assert_send<T: Send + ?Sized>() {}
        assert_send_sync::<Arc<dyn EventSink>>();
        assert_send::<SinkFuture<'static>>();
    }
}
