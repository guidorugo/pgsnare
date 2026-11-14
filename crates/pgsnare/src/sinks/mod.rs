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
//! | [`WebhookSink`] | Posts it to an HTTP endpoint, as a signed request: see [`webhook`] for the signature and what a receiver does with it |
//! | [`StdoutSink`] | Writes it to standard output as one line of JSON |
//! | [`FileSink`] | Appends it to a file as one line of JSON: see [`mod@file`] for how the file is opened and what happens when it is rotated |
//! | [`SyslogSink`] | Sends it to a syslog server as one message of RFC 5424: see [`syslog`] for the message |
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
//! refuses to build a sink it cannot build completely. What a sink must
//! keep to itself, such as the URL of a webhook, it hands to the redactor
//! of the process, so that it cannot turn up in anything that is written.

use std::fmt;
use std::sync::Arc;
use std::time::Duration;

use pgsnare_core::extension::EventSink;

use crate::config;
use crate::redact::RedactorBuilder;

mod dedup;
pub(crate) mod dispatcher;
pub mod file;
mod lines;
mod pace;
mod secret;
mod stdout;
pub mod syslog;
pub mod webhook;

pub use file::{FileError, FileSink};
pub use secret::MAX_SECRET_BYTES;
pub use stdout::StdoutSink;
pub use syslog::SyslogSink;
pub use webhook::{
    EVENT_ID_HEADER, RECOMMENDED_KEY_BYTES, SIGNATURE_HEADER, SIGNATURE_PREFIX, TIMESTAMP_HEADER,
    Trust, WebhookError, WebhookSettings, WebhookSink,
};

/// How much longer than its own time limit the dispatcher gives an attempt
/// of a webhook sink. The sink ends an attempt by itself, and says why.
/// The dispatcher only steps in should that ever fail.
const WEBHOOK_TIMEOUT_MARGIN: Duration = Duration::from_secs(1);

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

/// What the log of `pgsnare run` and the report of `pgsnare config check`
/// say about a signing key that is short.
const SHORT_KEY: &str = "the signing key of this webhook is shorter than 32 bytes, which makes \
                         its signatures weaker than they could be";

/// What the sinks of a configuration are put together for.
#[derive(Clone, Copy, PartialEq, Eq)]
enum Purpose {
    /// To deliver events. The first sink that cannot be built ends the
    /// work.
    Deliver,
    /// To report on them. Every sink is looked at, and nothing is created
    /// or written.
    Check,
}

/// What came of putting the sinks of a configuration together.
struct Assembled {
    sinks: Vec<Configured>,
    redactor: RedactorBuilder,
    errors: Vec<SetupError>,
    warnings: Vec<SetupError>,
}

/// Builds the sinks of a configuration, in its order.
///
/// A sink goes by its type and its place in the configuration, such as
/// `webhook-0` and `stdout-1`: that is its name in logs and metrics.
///
/// What a sink must keep to itself is added to `redactor`, which is handed
/// back with the sinks: the URL of every webhook, which can hold a secret
/// in its path or its query.
///
/// # Errors
///
/// Returns the first sink that cannot be built, and why. The reason names
/// an environment variable or a file where one is at fault, and never
/// contains what was read from it.
pub fn from_config(
    events: &config::Events,
    redactor: RedactorBuilder,
) -> Result<(Vec<Configured>, RedactorBuilder), SetupError> {
    let mut assembled = assemble(events, redactor, Purpose::Deliver);
    match assembled.errors.pop() {
        Some(error) => Err(error),
        None => Ok((assembled.sinks, assembled.redactor)),
    }
}

/// What [`check_config`] found out about the sinks of a configuration.
#[non_exhaustive]
pub struct Checked {
    /// The sinks that cannot be built, and why. [`from_config`] fails with
    /// the first of them.
    pub errors: Vec<SetupError>,
    /// What is valid and gives up some protection, each with the sink it
    /// is about, in the words [`from_config`] writes to the log.
    pub warnings: Vec<String>,
    /// The redactor, with what the sinks that can be built must keep to
    /// themselves.
    pub redactor: RedactorBuilder,
}

impl fmt::Debug for Checked {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Checked")
            .field("errors", &self.errors)
            .field("warnings", &self.warnings)
            .finish_non_exhaustive()
    }
}

/// Looks at the sinks of a configuration the way [`from_config`] builds
/// them, and reports on every one of them.
///
/// The steps are those of `from_config`, in the same code: a secret is
/// read from where the configuration says it is, the URL of a webhook is
/// taken apart, and its TLS settings are put together. Two things differ.
/// The work does not end at the first sink that cannot be built, so that
/// one check reports all of them. And the file of a `file` sink is not
/// created: see [`FileSink::check`].
///
/// Nothing is connected to. Whether a receiver or a syslog server answers
/// is found out when the first event is delivered.
#[must_use]
pub fn check_config(events: &config::Events, redactor: RedactorBuilder) -> Checked {
    let assembled = assemble(events, redactor, Purpose::Check);
    Checked {
        errors: assembled.errors,
        warnings: assembled.warnings.iter().map(ToString::to_string).collect(),
        redactor: assembled.redactor,
    }
}

/// Puts the sinks of a configuration together, for one purpose or the
/// other, so that building them and checking them cannot disagree.
fn assemble(events: &config::Events, mut redactor: RedactorBuilder, purpose: Purpose) -> Assembled {
    let mut sinks = Vec::with_capacity(events.sinks.len());
    let mut errors = Vec::new();
    let mut warnings = Vec::new();
    for (index, sink) in events.sinks.iter().enumerate() {
        let kind = sink.kind();
        let name = format!("{kind}-{index}");
        let found = |problem: String| SetupError {
            index,
            kind,
            problem,
        };
        let mut options = SinkOptions::new()
            .with_queue_size(usize::try_from(sink.queue_size()).unwrap_or(usize::MAX))
            .with_max_events_per_second(sink.max_events_per_second());

        let built: Result<Option<Arc<dyn EventSink>>, String> = match sink {
            config::Sink::Webhook(webhook) => match webhook_from_config(&name, webhook) {
                Ok((sink, url, short_key)) => {
                    redactor = redactor.secret_text(&url).secret_text(sink.path());
                    options = options
                        .with_max_retries(webhook.max_retries)
                        .with_attempt_timeout(
                            webhook.timeout.saturating_add(WEBHOOK_TIMEOUT_MARGIN),
                        );
                    if short_key {
                        warnings.push(found(SHORT_KEY.to_owned()));
                    }
                    Ok(Some(Arc::new(sink)))
                }
                Err(problem) => Err(problem),
            },
            config::Sink::Stdout(_) => Ok(Some(Arc::new(StdoutSink::new(name)))),
            config::Sink::File(file) => {
                let outcome: Result<Option<Arc<dyn EventSink>>, FileError> = match purpose {
                    Purpose::Deliver => match FileSink::new(name, &file.path) {
                        Ok(sink) => Ok(Some(Arc::new(sink))),
                        Err(error) => Err(error),
                    },
                    Purpose::Check => match FileSink::check(&file.path) {
                        Ok(open_to_others) => {
                            if open_to_others {
                                warnings.push(found(format!(
                                    "{}: {}",
                                    file.path.display(),
                                    file::OPEN_TO_OTHERS
                                )));
                            }
                            Ok(None)
                        }
                        Err(error) => Err(error),
                    },
                };
                outcome.map_err(|error| format!("{}: {error}", file.path.display()))
            }
            config::Sink::Syslog(syslog) => Ok(Some(Arc::new(SyslogSink::new(
                name,
                &syslog.address,
                syslog.transport,
                syslog.facility,
            )))),
        };
        match built {
            Ok(Some(sink)) => sinks.push(Configured { sink, options }),
            Ok(None) => {}
            Err(problem) => {
                errors.push(found(problem));
                if purpose == Purpose::Deliver {
                    break;
                }
            }
        }
    }
    Assembled {
        sinks,
        redactor,
        errors,
        warnings,
    }
}

/// Builds a webhook sink and returns it with its URL, which the caller
/// hides, and with whether its signing key is shorter than it should be.
fn webhook_from_config(
    name: &str,
    webhook: &config::WebhookSink,
) -> Result<(WebhookSink, String, bool), String> {
    let url = match &webhook.url {
        config::UrlSource::Inline(url) => url.as_str().to_owned(),
        config::UrlSource::Env(variable) => {
            // Never the bytes themselves: they are the URL, or what was
            // found in its place.
            String::from_utf8(secret::from_env(variable)?.to_vec()).map_err(|_| {
                format!("the value of the environment variable {variable} is not valid UTF-8")
            })?
        }
        config::UrlSource::File(file) => String::from_utf8(secret::from_file(file)?.to_vec())
            .map_err(|_| format!("{}: the file is not valid UTF-8", file.display()))?,
    };
    let key = secret::read(&webhook.hmac_secret)?;
    let settings = WebhookSettings::new()
        .with_allow_insecure_http(webhook.allow_insecure_http)
        .with_timeout(webhook.timeout);
    let sink = WebhookSink::new(name, &url, &key, settings).map_err(|error| error.to_string())?;

    let short_key = key.len() < RECOMMENDED_KEY_BYTES;
    if short_key {
        tracing::warn!(sink = name, "{SHORT_KEY}");
    }
    if !sink.is_encrypted() {
        tracing::warn!(
            sink = name,
            "events are sent to this webhook unencrypted, because its URL is an http URL and \
             allow_insecure_http is set: whoever is on the way can read them"
        );
    }
    Ok((sink, url, short_key))
}

#[cfg(test)]
mod tests {
    use std::path::PathBuf;
    use std::sync::atomic::{AtomicU32, Ordering};

    use crate::redact::Redactor;

    use super::*;

    /// A directory that is removed again when the test ends.
    struct TempDir(PathBuf);

    impl TempDir {
        fn new() -> Self {
            static NEXT: AtomicU32 = AtomicU32::new(0);
            let path = std::env::temp_dir().join(format!(
                "pgsnare-sinks-test-{}-{}",
                std::process::id(),
                NEXT.fetch_add(1, Ordering::Relaxed)
            ));
            std::fs::create_dir_all(&path).unwrap();
            Self(path)
        }

        fn file(&self, name: &str, content: &str) -> String {
            let path = self.0.join(name);
            std::fs::write(&path, content).unwrap();
            path.display().to_string()
        }
    }

    impl Drop for TempDir {
        fn drop(&mut self) {
            let _ = std::fs::remove_dir_all(&self.0);
        }
    }

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
        let (sinks, redactor) = from_config(
            &events(
                "    - { type: stdout }\n    - { type: stdout, queue_size: 16, max_events_per_second: 3 }\n",
            ),
            Redactor::builder(),
        )
        .unwrap();
        assert!(redactor.build().unwrap().is_empty());
        let names: Vec<&str> = sinks.iter().map(|built| built.sink.name()).collect();
        assert_eq!(names, ["stdout-0", "stdout-1"]);
        assert_eq!(sinks[0].options, SinkOptions::default());
        assert_eq!(sinks[1].options.queue_size, 16);
        assert_eq!(sinks[1].options.max_events_per_second, Some(3));
        assert!(format!("{:?}", sinks[1]).contains("stdout-1"));
    }

    const URL: &str = "https://alerts.example.com/hooks/T0p-S3cret-Path";
    const KEY: &str = "0123456789abcdef0123456789abcdef";

    #[test]
    fn a_webhook_is_built_from_its_url_and_the_file_with_its_key() {
        let dir = TempDir::new();
        let key = dir.file("key", &format!("{KEY}\n"));
        let (sinks, redactor) = from_config(
            &events(&format!(
                "    - type: webhook\n      url: {URL}\n      hmac_secret_file: {key}\n      \
                 timeout: 2s\n      max_retries: 7\n      queue_size: 32\n      max_events_per_second: 9\n\
                 \x20   - type: stdout\n"
            )),
            Redactor::builder(),
        )
        .unwrap();

        assert_eq!(sinks.len(), 2);
        assert_eq!(sinks[0].sink.name(), "webhook-0");
        assert_eq!(sinks[1].sink.name(), "stdout-1");
        let options = &sinks[0].options;
        assert_eq!(options.queue_size, 32);
        assert_eq!(options.max_events_per_second, Some(9));
        assert_eq!(options.max_retries, 7);
        // The sink ends an attempt after two seconds. The dispatcher waits
        // a little longer before it steps in.
        assert_eq!(options.attempt_timeout, Duration::from_secs(3));

        // The URL is handed to the redactor, whole and by its path.
        let redactor = redactor.build().unwrap();
        assert_eq!(
            redactor.text(&format!("could not reach {URL}")),
            "could not reach [redacted]"
        );
        assert_eq!(
            redactor.text("POST /hooks/T0p-S3cret-Path HTTP/1.1"),
            "POST [redacted] HTTP/1.1"
        );
    }

    #[test]
    fn a_url_can_come_from_a_file() {
        let dir = TempDir::new();
        let key = dir.file("key", KEY);
        let url = dir.file("url", &format!("{URL}\n"));
        let (sinks, redactor) = from_config(
            &events(&format!(
                "    - type: webhook\n      url_file: {url}\n      hmac_secret_file: {key}\n"
            )),
            Redactor::builder(),
        )
        .unwrap();
        assert_eq!(sinks[0].sink.name(), "webhook-0");
        assert_eq!(sinks[0].options.max_retries, 5);
        assert_eq!(redactor.build().unwrap().text(URL), "[redacted]");
    }

    #[test]
    fn a_webhook_that_cannot_be_built_says_why_and_shows_no_secret() {
        let dir = TempDir::new();
        let key = dir.file("key", KEY);
        let build = |sink: &str| {
            from_config(&events(sink), Redactor::builder())
                .map(|_| ())
                .unwrap_err()
                .to_string()
        };

        // The key: a file that is not there, a file that is empty, and a
        // variable that is not set.
        let missing = dir.0.join("missing").display().to_string();
        assert_eq!(
            build(&format!(
                "    - type: webhook\n      url: {URL}\n      hmac_secret_file: {missing}\n"
            )),
            format!("events.sinks[0] (webhook): {missing}: cannot read the file: entity not found")
        );
        let empty = dir.file("empty", "\n");
        assert_eq!(
            build(&format!(
                "    - type: stdout\n    - type: webhook\n      url: {URL}\n      hmac_secret_file: {empty}\n"
            )),
            format!("events.sinks[1] (webhook): {empty}: the file is empty")
        );
        assert_eq!(
            build(&format!(
                "    - type: webhook\n      url: {URL}\n      hmac_secret_env: PGSNARE_TEST_KEY_THAT_IS_NOT_SET\n"
            )),
            "events.sinks[0] (webhook): the environment variable PGSNARE_TEST_KEY_THAT_IS_NOT_SET is not set"
        );

        // The URL: a file whose content is no URL, and one that holds a
        // plain http URL where none is allowed. Neither is repeated.
        let not_a_url = dir.file("not-a-url", "S3cret-but-not-a-URL\n");
        let error = build(&format!(
            "    - type: webhook\n      url_file: {not_a_url}\n      hmac_secret_file: {key}\n"
        ));
        assert!(
            error.starts_with("events.sinks[0] (webhook): the URL cannot be used"),
            "{error}"
        );
        assert!(!error.contains("S3cret"), "{error}");

        let http = dir.file("http", "http://alerts.example.com/hooks/T0p-S3cret-Path\n");
        let error = build(&format!(
            "    - type: webhook\n      url_file: {http}\n      hmac_secret_file: {key}\n"
        ));
        assert!(
            error.starts_with("events.sinks[0] (webhook): the URL is a plain http URL"),
            "{error}"
        );
        assert!(!error.contains("S3cret"), "{error}");
        assert!(!error.contains("example.com"), "{error}");

        // With the setting, plain http is taken.
        assert!(
            from_config(
                &events(&format!(
                    "    - type: webhook\n      url_file: {http}\n      hmac_secret_file: {key}\n      \
                     allow_insecure_http: true\n"
                )),
                Redactor::builder()
            )
            .is_ok()
        );
    }

    #[test]
    fn every_kind_of_sink_of_a_configuration_is_built() {
        let dir = TempDir::new();
        let key = dir.file("key", KEY);
        let events_file = dir.0.join("events.jsonl").display().to_string();
        let (sinks, _) = from_config(
            &events(&format!(
                "    - type: webhook\n      url: {URL}\n      hmac_secret_file: {key}\n\
                 \x20   - type: stdout\n\
                 \x20   - type: file\n      path: {events_file}\n      queue_size: 4\n\
                 \x20   - type: syslog\n      address: syslog.example.com:514\n      max_events_per_second: 50\n"
            )),
            Redactor::builder(),
        )
        .unwrap();
        let names: Vec<&str> = sinks.iter().map(|built| built.sink.name()).collect();
        assert_eq!(names, ["webhook-0", "stdout-1", "file-2", "syslog-3"]);
        assert_eq!(sinks[2].options.queue_size, 4);
        assert_eq!(sinks[3].options.max_events_per_second, Some(50));
        // The sinks without a setting for it get the default number of
        // retries.
        assert_eq!(sinks[2].options.max_retries, DEFAULT_RETRIES);
        assert_eq!(sinks[3].options.max_retries, DEFAULT_RETRIES);
        // The file of the file sink is there once the sink is built.
        assert!(dir.0.join("events.jsonl").is_file());
    }

    #[test]
    fn a_file_that_cannot_be_opened_keeps_its_sink_from_being_built() {
        let dir = TempDir::new();
        let missing = dir.0.join("no-such-directory").join("events.jsonl");
        let error = from_config(
            &events(&format!(
                "    - type: stdout\n    - type: file\n      path: {}\n",
                missing.display()
            )),
            Redactor::builder(),
        )
        .unwrap_err();
        assert_eq!(error.index(), 1);
        assert_eq!(
            error.to_string(),
            format!(
                "events.sinks[1] (file): {}: the file cannot be opened: entity not found",
                missing.display()
            )
        );
    }
}
