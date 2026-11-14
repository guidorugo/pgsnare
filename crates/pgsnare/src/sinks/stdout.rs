// SPDX-License-Identifier: Apache-2.0

//! The `stdout` sink: events on standard output, one JSON object per line.
//!
//! Standard output carries events and nothing else. The log goes to
//! standard error, so whatever collects the output of a container can tell
//! the two apart without reading them.

use std::io::{self, Write};

use pgsnare_core::event::Event;
use pgsnare_core::extension::{EventSink, SinkError, SinkFuture};

use super::lines::{LineOutput, Lines, json_line};

/// Writes each event to standard output as one line of JSON.
///
/// A write that fails because nobody reads standard output any more is
/// not tried again. Every other failure is.
pub struct StdoutSink {
    name: String,
    lines: Lines<io::Stdout>,
}

impl StdoutSink {
    /// A sink with this name, which logs and metrics use for it.
    #[must_use]
    pub fn new(name: impl Into<String>) -> Self {
        Self {
            name: name.into(),
            lines: Lines::new(io::stdout()),
        }
    }
}

impl std::fmt::Debug for StdoutSink {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("StdoutSink")
            .field("name", &self.name)
            .finish()
    }
}

impl LineOutput for io::Stdout {
    fn write_line(&mut self, line: &[u8]) -> Result<(), SinkError> {
        // The lock is held for the whole line, so that nothing else this
        // process may print ends up in the middle of an event.
        let mut out = self.lock();
        out.write_all(line)
            .and_then(|()| out.flush())
            .map_err(|error| match error.kind() {
                io::ErrorKind::BrokenPipe => SinkError::permanent("standard output is closed"),
                _ => SinkError::retryable("standard output could not be written to"),
            })
    }
}

impl EventSink for StdoutSink {
    fn name(&self) -> &str {
        &self.name
    }

    fn deliver<'a>(&'a self, event: &'a Event) -> SinkFuture<'a> {
        Box::pin(async move { self.lines.write(json_line(event)?).await })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_sink_goes_by_the_name_it_was_given() {
        let sink = StdoutSink::new("stdout-1");
        assert_eq!(sink.name(), "stdout-1");
        assert_eq!(format!("{sink:?}"), "StdoutSink { name: \"stdout-1\" }");
    }
}
