// SPDX-License-Identifier: Apache-2.0

//! The event dispatcher and the sinks that ship with pgsnare.
//!
//! # From a session to a sink
//!
//! A session raises an event and goes on. The dispatcher takes the event
//! from a queue, removes what must not be shown, folds repeated hits into
//! one event, and hands the result to every sink through a queue of its
//! own. [`dispatcher`](self) describes each step, and what happens when a
//! sink is slow, down or never answers: events are dropped and counted,
//! and database traffic never waits.
//!
//! # The sinks
//!
//! | Sink | What it does with an event |
//! |---|---|
//! | [`StdoutSink`] | Writes it to standard output as one line of JSON |
//!
//! Each implements [`EventSink`], the public interface for sinks, and
//! makes one attempt to deliver one event. Queueing, the rate limit, the
//! retries and the counting are the dispatcher's, for every sink alike. A
//! sink of another build gets them in the same way: it is added to the
//! proxy with
//! [`ProxyBuilder::event_sink_with`](crate::builder::ProxyBuilder::event_sink_with)
//! and its [`SinkOptions`].
//!
//! # From the configuration
//!
//! [`from_config`] builds the sinks of a configuration. It reads the
//! secrets a sink needs from where the configuration says they are, and
//! refuses to build a sink it cannot build completely.

use std::fmt;
use std::sync::Arc;
use std::time::Duration;

use pgsnare_core::extension::EventSink;

use crate::config;

mod dedup;
pub(crate) mod dispatcher;
mod lines;
mod pace;
mod stdout;

pub use stdout::StdoutSink;

/// How long one attempt to deliver an event may take, unless a sink is
/// given another limit.
pub const DEFAULT_ATTEMPT_TIMEOUT: Duration = Duration::from_secs(5);

/// How often a failed delivery is tried again, unless a sink is given
/// another number.
pub const DEFAULT_RETRIES: u32 = 5;

/// How the dispatcher treats one sink.
#[derive(Clone, Debug, PartialEq, Eq)]
#[non_exhaustive]
pub struct SinkOptions {
    /// How many events may wait for the sink. An event that does not fit is
    /// dropped and counted.
    pub queue_size: usize,
    /// The most events the sink is given per second. `None` is no limit.
    pub max_events_per_second: Option<u32>,
    /// How often a failed delivery is tried again before the event is
    /// dropped.
    pub max_retries: u32,
    /// How long one attempt may take. An attempt that takes longer is given
    /// up and counts as failed.
    pub attempt_timeout: Duration,
}

impl Default for SinkOptions {
    fn default() -> Self {
        Self {
            queue_size: usize::try_from(config::DEFAULT_QUEUE_SIZE).unwrap_or(usize::MAX),
            max_events_per_second: None,
            max_retries: DEFAULT_RETRIES,
            attempt_timeout: DEFAULT_ATTEMPT_TIMEOUT,
        }
    }
}

impl SinkOptions {
    /// The options a sink gets when nothing else is said.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Sets how many events may wait for the sink.
    #[must_use]
    pub const fn with_queue_size(mut self, queue_size: usize) -> Self {
        self.queue_size = queue_size;
        self
    }

    /// Sets the most events the sink is given per second.
    #[must_use]
    pub const fn with_max_events_per_second(mut self, limit: Option<u32>) -> Self {
        self.max_events_per_second = limit;
        self
    }

    /// Sets how often a failed delivery is tried again.
    #[must_use]
    pub const fn with_max_retries(mut self, max_retries: u32) -> Self {
        self.max_retries = max_retries;
        self
    }

    /// Sets how long one attempt may take.
    #[must_use]
    pub const fn with_attempt_timeout(mut self, attempt_timeout: Duration) -> Self {
        self.attempt_timeout = attempt_timeout;
        self
    }
}

/// A sink of a configuration, built, and how the dispatcher is to treat
/// it.
#[non_exhaustive]
pub struct Configured {
    /// The sink.
    pub sink: Arc<dyn EventSink>,
    /// Its queue, its rate limit, its retries and its time limit.
    pub options: SinkOptions,
}

impl fmt::Debug for Configured {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Configured")
            .field("sink", &self.sink.name())
            .field("options", &self.options)
            .finish()
    }
}

/// Why a sink of a configuration could not be built.
///
/// The message names the sink by its place in the configuration and says
/// what is wrong. It never contains a secret, and never the URL of a
/// webhook.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct SetupError {
    index: usize,
    kind: &'static str,
    problem: String,
}

impl SetupError {
    /// The place of the sink in `events.sinks`, counting from 0.
    #[must_use]
    pub const fn index(&self) -> usize {
        self.index
    }
}

impl fmt::Display for SetupError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "events.sinks[{}] ({}): {}",
            self.index, self.kind, self.problem
        )
    }
}

impl std::error::Error for SetupError {}

/// Builds the sinks of a configuration, in its order.
///
/// A sink goes by its type and its place in the configuration, such as
/// `webhook-0` and `stdout-1`: that is its name in logs and metrics.
///
/// # Errors
///
/// Returns the first sink that cannot be built, and why.
pub fn from_config(events: &config::Events) -> Result<Vec<Configured>, SetupError> {
    let mut sinks = Vec::with_capacity(events.sinks.len());
    for (index, sink) in events.sinks.iter().enumerate() {
        let kind = sink.kind();
        let name = format!("{kind}-{index}");
        let failed = |problem: String| SetupError {
            index,
            kind,
            problem,
        };
        let options = SinkOptions::new()
            .with_queue_size(usize::try_from(sink.queue_size()).unwrap_or(usize::MAX))
            .with_max_events_per_second(sink.max_events_per_second());

        let built: Arc<dyn EventSink> = match sink {
            config::Sink::Stdout(_) => Arc::new(StdoutSink::new(name)),
            _ => return Err(failed("this kind of sink is not built yet".to_owned())),
        };
        sinks.push(Configured {
            sink: built,
            options,
        });
    }
    Ok(sinks)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn events(sinks: &str) -> config::Events {
        let text = format!(
            "listeners:\n  - name: main\n    listen: 127.0.0.1:5432\n    upstream: db.example.com:5432\n    \
             client_tls: {{ mode: disable }}\n    upstream_tls: {{ mode: disable }}\nevents:\n  sinks:\n{sinks}"
        );
        config::Config::from_yaml(&text).unwrap().events
    }

    #[test]
    fn a_sink_gets_the_defaults_of_the_configuration() {
        let options = SinkOptions::default();
        assert_eq!(options.queue_size, 1_024);
        assert_eq!(options.max_events_per_second, None);
        assert_eq!(options.max_retries, 5);
        assert_eq!(options.attempt_timeout, Duration::from_secs(5));
        assert_eq!(SinkOptions::new(), options);

        let options = options
            .with_queue_size(8)
            .with_max_events_per_second(Some(2))
            .with_max_retries(0)
            .with_attempt_timeout(Duration::from_millis(100));
        assert_eq!(options.queue_size, 8);
        assert_eq!(options.max_events_per_second, Some(2));
        assert_eq!(options.max_retries, 0);
        assert_eq!(options.attempt_timeout, Duration::from_millis(100));
    }

    #[test]
    fn sinks_are_built_in_order_and_named_by_type_and_place() {
        let sinks = from_config(&events(
            "    - { type: stdout }\n    - { type: stdout, queue_size: 16, max_events_per_second: 3 }\n",
        ))
        .unwrap();
        let names: Vec<&str> = sinks.iter().map(|built| built.sink.name()).collect();
        assert_eq!(names, ["stdout-0", "stdout-1"]);
        assert_eq!(sinks[0].options, SinkOptions::default());
        assert_eq!(sinks[1].options.queue_size, 16);
        assert_eq!(sinks[1].options.max_events_per_second, Some(3));
        assert!(format!("{:?}", sinks[1]).contains("stdout-1"));
    }
}
