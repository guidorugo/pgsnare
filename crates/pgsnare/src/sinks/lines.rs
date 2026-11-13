// SPDX-License-Identifier: Apache-2.0

//! Events as JSON lines, written without holding up the runtime.
//!
//! Standard output and a file are written with calls that can block: a
//! pipe nobody reads from, a disk that is full or slow. Such a call must
//! never run on a thread that also relays traffic. Every write therefore
//! runs on the threads the runtime keeps for blocking work.
//!
//! One write at a time. When a write is still under way, because an
//! earlier attempt was given up while it was blocked, the next attempt
//! fails at once and is tried again later. A destination that is stuck
//! therefore holds one thread and never more.

use std::sync::{Arc, Mutex, TryLockError};

use pgsnare_core::event::Event;
use pgsnare_core::extension::SinkError;

/// What a sink says when its last write has not come back yet.
pub(super) const BUSY: &str = "the write before this one has not finished";

/// An event as one line of JSON, with the line break.
///
/// The encoder escapes every control character, so whatever the texts of
/// an event contain, the result is exactly one line.
pub(super) fn json_line(event: &Event) -> Result<Vec<u8>, SinkError> {
    let mut line = serde_json::to_vec(event)
        .map_err(|_| SinkError::permanent("the event could not be written as JSON"))?;
    line.push(b'\n');
    Ok(line)
}

/// Where lines go. A call may block.
pub(super) trait LineOutput: Send + 'static {
    /// Writes one complete line.
    fn write_line(&mut self, line: &[u8]) -> Result<(), SinkError>;
}

/// Writes lines to an output, one at a time, off the threads that relay
/// traffic.
pub(super) struct Lines<O> {
    output: Arc<Mutex<O>>,
}

impl<O: LineOutput> Lines<O> {
    pub(super) fn new(output: O) -> Self {
        Self {
            output: Arc::new(Mutex::new(output)),
        }
    }

    /// Writes one line. Fails at once when the write before this one is
    /// still under way.
    pub(super) async fn write(&self, line: Vec<u8>) -> Result<(), SinkError> {
        let output = Arc::clone(&self.output);
        let written = tokio::task::spawn_blocking(move || {
            let mut output = match output.try_lock() {
                Ok(output) => output,
                Err(TryLockError::WouldBlock) => return Err(SinkError::retryable(BUSY)),
                // A write that panicked left the output as it was. The
                // next write may still work.
                Err(TryLockError::Poisoned(poisoned)) => poisoned.into_inner(),
            };
            output.write_line(&line)
        })
        .await;
        written.unwrap_or_else(|_| Err(SinkError::permanent("the write ended without an answer")))
    }
}

#[cfg(test)]
pub(super) mod tests {
    use std::sync::mpsc;
    use std::time::Duration;

    use pgsnare_core::event::{EventBody, EventId, EventKind, Labels, SessionId, Timestamp};
    use pgsnare_core::session::SessionOrigin;

    use super::*;

    /// An event whose user name is whatever a test wants it to be.
    pub(in crate::sinks) fn event(db_user: &str) -> Event {
        let origin = SessionOrigin::new(
            SessionId::from_u128(7),
            "192.0.2.10".parse().unwrap(),
            49_152,
            true,
        );
        let mut body = EventBody::new(EventKind::InspectionBypassed, &origin);
        body.db_user = Some(db_user.to_owned());
        body.seal(
            EventId::from_u128(9),
            Timestamp::from_unix_micros(1_794_416_791_123_456).unwrap(),
            Labels::from([("POD_NAME".to_owned(), "pgsnare-0".to_owned())]),
        )
    }

    /// Keeps the lines it is given. It can be made to wait.
    struct Memory {
        lines: Arc<Mutex<Vec<Vec<u8>>>>,
        wait: Option<mpsc::Receiver<()>>,
    }

    impl LineOutput for Memory {
        fn write_line(&mut self, line: &[u8]) -> Result<(), SinkError> {
            if let Some(wait) = &self.wait {
                let _ = wait.recv();
            }
            self.lines.lock().unwrap().push(line.to_vec());
            Ok(())
        }
    }

    #[test]
    fn an_event_is_one_line_whatever_its_texts_contain() {
        let line = json_line(&event("app\nwith \"two\" lines\r\n\u{0}\u{1b}[31m")).unwrap();
        assert_eq!(line.last(), Some(&b'\n'));
        let text = std::str::from_utf8(&line).unwrap();
        assert_eq!(text.matches('\n').count(), 1);
        assert!(!text.contains('\r'));
        assert!(!text.contains('\u{1b}'));
        assert!(text.contains(r#""db_user":"app\nwith \"two\" lines\r\n\u0000\u001b[31m""#));

        // What was written reads back as the same event.
        let back: Event = serde_json::from_str(text).unwrap();
        assert_eq!(back, event("app\nwith \"two\" lines\r\n\u{0}\u{1b}[31m"));
        assert!(
            text.starts_with(
                r#"{"schema_version":1,"event_id":"00000000000000000000000000000009","#
            )
        );
    }

    #[tokio::test]
    async fn lines_are_written_in_order() {
        let lines = Arc::new(Mutex::new(Vec::new()));
        let output = Lines::new(Memory {
            lines: Arc::clone(&lines),
            wait: None,
        });
        output.write(b"one\n".to_vec()).await.unwrap();
        output.write(b"two\n".to_vec()).await.unwrap();
        assert_eq!(
            *lines.lock().unwrap(),
            [b"one\n".to_vec(), b"two\n".to_vec()]
        );
    }

    #[tokio::test]
    async fn a_write_that_is_stuck_makes_the_next_one_fail_at_once() {
        let lines = Arc::new(Mutex::new(Vec::new()));
        let (release, wait) = mpsc::channel();
        let output = Lines::new(Memory {
            lines: Arc::clone(&lines),
            wait: Some(wait),
        });

        // The first write blocks, and whoever waited for it gives up.
        let stuck =
            tokio::time::timeout(Duration::from_millis(100), output.write(b"one\n".to_vec()));
        assert!(stuck.await.is_err());

        // The next attempts do not queue up behind it: each fails at once.
        for _ in 0..3 {
            let busy = output.write(b"two\n".to_vec()).await.unwrap_err();
            assert!(busy.is_retryable());
            assert_eq!(busy.message(), BUSY);
        }

        // Once the first write comes back it has been written, and the
        // output works again.
        release.send(()).unwrap();
        release.send(()).unwrap();
        let mut tries = 0;
        while output.write(b"three\n".to_vec()).await.is_err() {
            tries += 1;
            assert!(tries < 500, "the output is free again in time");
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
        assert_eq!(
            *lines.lock().unwrap(),
            [b"one\n".to_vec(), b"three\n".to_vec()]
        );
    }
}
