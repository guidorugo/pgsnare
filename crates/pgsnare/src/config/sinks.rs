// SPDX-License-Identifier: Apache-2.0

//! Sinks: where events are delivered.

use std::path::PathBuf;
use std::time::Duration;

use serde::Deserialize;

use super::error::{At, Problems, Reason};
use super::names::{Endpoint, EnvVarName, WebhookUrl};
use super::tls::check_path;
use super::units;

/// The default length of a sink's queue, in events.
pub const DEFAULT_QUEUE_SIZE: u32 = 1_024;

/// The longest accepted queue, in events.
pub const MAX_QUEUE_SIZE: u32 = 1_000_000;

const fn default_queue_size() -> u32 {
    DEFAULT_QUEUE_SIZE
}

/// One destination for events.
///
/// Every sink has a bounded queue of its own. A sink that is slow or down
/// loses events, which are counted, and never holds up database traffic or
/// the other sinks.
#[derive(Clone, Debug, PartialEq, Eq, Deserialize)]
#[serde(tag = "type", rename_all = "snake_case")]
#[non_exhaustive]
pub enum Sink {
    /// An HTTP endpoint that receives each event as a signed request.
    Webhook(WebhookSink),
    /// Standard output, one JSON object per line.
    Stdout(StdoutSink),
    /// A file, one JSON object per line.
    File(FileSink),
    /// A syslog server, in the format of RFC 5424.
    Syslog(SyslogSink),
}

impl Sink {
    /// The name of the sink type, as written in the configuration.
    #[must_use]
    pub const fn kind(&self) -> &'static str {
        match self {
            Self::Webhook(_) => "webhook",
            Self::Stdout(_) => "stdout",
            Self::File(_) => "file",
            Self::Syslog(_) => "syslog",
        }
    }

    /// The length of the sink's queue, in events.
    #[must_use]
    pub const fn queue_size(&self) -> u32 {
        match self {
            Self::Webhook(sink) => sink.queue_size,
            Self::Stdout(sink) => sink.queue_size,
            Self::File(sink) => sink.queue_size,
            Self::Syslog(sink) => sink.queue_size,
        }
    }

    /// The most events the sink delivers per second, if that is limited.
    #[must_use]
    pub const fn max_events_per_second(&self) -> Option<u32> {
        match self {
            Self::Webhook(sink) => sink.max_events_per_second,
            Self::Stdout(sink) => sink.max_events_per_second,
            Self::File(sink) => sink.max_events_per_second,
            Self::Syslog(sink) => sink.max_events_per_second,
        }
    }

    pub(super) fn validate(&self, at: &At, problems: &mut Problems) {
        if self.queue_size() == 0 || self.queue_size() > MAX_QUEUE_SIZE {
            problems.add(&at.field("queue_size"), "must be between 1 and 1000000");
        }
        if self.max_events_per_second() == Some(0) {
            problems.add(&at.field("max_events_per_second"), "must be at least 1");
        }
        match self {
            Self::Webhook(sink) => sink.validate(at, problems),
            Self::File(sink) => check_path(&sink.path, &at.field("path"), problems),
            Self::Stdout(_) | Self::Syslog(_) => {}
        }
    }

    /// Calls `visit` with every file path of the sink.
    pub(super) fn for_each_path_mut(&mut self, visit: &mut dyn FnMut(&mut PathBuf)) {
        match self {
            Self::Webhook(sink) => {
                if let UrlSource::File(path) = &mut sink.url {
                    visit(path);
                }
                if let SecretRef::File(path) = &mut sink.hmac_secret {
                    visit(path);
                }
            }
            Self::File(sink) => visit(&mut sink.path),
            Self::Stdout(_) | Self::Syslog(_) => {}
        }
    }
}

/// Where a secret comes from.
///
/// A secret is never written in the configuration. It is named by an
/// environment variable or by a file, and this type has no way to hold the
/// secret itself.
#[derive(Clone, Debug, PartialEq, Eq, Hash)]
#[non_exhaustive]
pub enum SecretRef {
    /// The secret is the value of this environment variable.
    Env(EnvVarName),
    /// The secret is the content of this file.
    File(PathBuf),
}

/// Where the URL of a webhook comes from.
///
/// Some webhook URLs are secrets themselves, because whoever knows the URL
/// can post to it. Such a URL is named by an environment variable or a file
/// instead of being written in the configuration.
#[derive(Clone, Debug, PartialEq, Eq, Hash)]
#[non_exhaustive]
pub enum UrlSource {
    /// The URL is written in the configuration.
    Inline(WebhookUrl),
    /// The URL is the value of this environment variable.
    Env(EnvVarName),
    /// The URL is the content of this file.
    File(PathBuf),
}

/// An HTTP endpoint that receives each event as a signed request.
///
/// In the configuration, the URL is given by exactly one of `url`,
/// `url_env` and `url_file`, and the signing key by exactly one of
/// `hmac_secret_env` and `hmac_secret_file`:
///
/// ```yaml
/// - type: webhook
///   url: https://alerts.example.com/hooks/pgsnare
///   hmac_secret_env: PGSNARE_WEBHOOK_SECRET
/// ```
#[derive(Clone, Debug, PartialEq, Eq, Deserialize)]
#[serde(try_from = "RawWebhookSink")]
#[non_exhaustive]
pub struct WebhookSink {
    /// Where the URL comes from.
    pub url: UrlSource,
    /// Where the key comes from that signs each request, so the receiver can
    /// reject forged and replayed ones.
    pub hmac_secret: SecretRef,
    /// Whether a plain `http://` URL is accepted. The default is `false`:
    /// events are sent over HTTPS with the certificate verified.
    pub allow_insecure_http: bool,
    /// How long one delivery attempt may take.
    pub timeout: Duration,
    /// How often a failed delivery is tried again before the event is
    /// dropped.
    pub max_retries: u32,
    /// The length of the sink's queue, in events.
    pub queue_size: u32,
    /// The most events delivered per second, if that is limited.
    pub max_events_per_second: Option<u32>,
}

/// The default for [`WebhookSink::timeout`].
pub const DEFAULT_WEBHOOK_TIMEOUT: Duration = Duration::from_secs(5);

/// The default for [`WebhookSink::max_retries`].
pub const DEFAULT_WEBHOOK_RETRIES: u32 = 5;

const fn default_webhook_timeout() -> Duration {
    DEFAULT_WEBHOOK_TIMEOUT
}

const fn default_webhook_retries() -> u32 {
    DEFAULT_WEBHOOK_RETRIES
}

/// A webhook as it is written, before the either-or fields are resolved.
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct RawWebhookSink {
    #[serde(default)]
    url: Option<WebhookUrl>,
    #[serde(default)]
    url_env: Option<EnvVarName>,
    #[serde(default)]
    url_file: Option<PathBuf>,
    #[serde(default)]
    hmac_secret_env: Option<EnvVarName>,
    #[serde(default)]
    hmac_secret_file: Option<PathBuf>,
    #[serde(default)]
    allow_insecure_http: bool,
    #[serde(
        default = "default_webhook_timeout",
        deserialize_with = "units::duration"
    )]
    timeout: Duration,
    #[serde(default = "default_webhook_retries")]
    max_retries: u32,
    #[serde(default = "default_queue_size")]
    queue_size: u32,
    #[serde(default)]
    max_events_per_second: Option<u32>,
}

impl TryFrom<RawWebhookSink> for WebhookSink {
    type Error = Reason;

    fn try_from(raw: RawWebhookSink) -> Result<Self, Reason> {
        let url = match (raw.url, raw.url_env, raw.url_file) {
            (Some(url), None, None) => UrlSource::Inline(url),
            (None, Some(variable), None) => UrlSource::Env(variable),
            (None, None, Some(file)) => UrlSource::File(file),
            _ => return Err(Reason::OneUrlSource),
        };
        let hmac_secret = match (raw.hmac_secret_env, raw.hmac_secret_file) {
            (Some(variable), None) => SecretRef::Env(variable),
            (None, Some(file)) => SecretRef::File(file),
            _ => return Err(Reason::OneSecretSource),
        };
        Ok(Self {
            url,
            hmac_secret,
            allow_insecure_http: raw.allow_insecure_http,
            timeout: raw.timeout,
            max_retries: raw.max_retries,
            queue_size: raw.queue_size,
            max_events_per_second: raw.max_events_per_second,
        })
    }
}

impl WebhookSink {
    fn validate(&self, at: &At, problems: &mut Problems) {
        match &self.url {
            UrlSource::Inline(url) if !url.is_https() && !self.allow_insecure_http => {
                problems.add(
                    &at.field("url"),
                    "a plain http URL sends events unencrypted; use https, or set allow_insecure_http: true",
                );
            }
            UrlSource::File(path) => check_path(path, &at.field("url_file"), problems),
            UrlSource::Inline(_) | UrlSource::Env(_) => {}
        }
        if let SecretRef::File(path) = &self.hmac_secret {
            check_path(path, &at.field("hmac_secret_file"), problems);
        }
        if self.timeout < Duration::from_millis(100) || self.timeout > Duration::from_secs(60) {
            problems.add(&at.field("timeout"), "must be between 100ms and 60s");
        }
        if self.max_retries > 100 {
            problems.add(&at.field("max_retries"), "must be at most 100");
        }
    }
}

/// Standard output, one JSON object per line.
#[derive(Clone, Debug, PartialEq, Eq, Deserialize)]
#[serde(deny_unknown_fields)]
#[non_exhaustive]
pub struct StdoutSink {
    /// The length of the sink's queue, in events.
    #[serde(default = "default_queue_size")]
    pub queue_size: u32,
    /// The most events delivered per second, if that is limited.
    #[serde(default)]
    pub max_events_per_second: Option<u32>,
}

/// A file, one JSON object per line.
#[derive(Clone, Debug, PartialEq, Eq, Deserialize)]
#[serde(deny_unknown_fields)]
#[non_exhaustive]
pub struct FileSink {
    /// The file to append to.
    pub path: PathBuf,
    /// The length of the sink's queue, in events.
    #[serde(default = "default_queue_size")]
    pub queue_size: u32,
    /// The most events delivered per second, if that is limited.
    #[serde(default)]
    pub max_events_per_second: Option<u32>,
}

/// How a syslog server is reached.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Hash, Deserialize)]
#[serde(rename_all = "snake_case")]
#[non_exhaustive]
pub enum SyslogTransport {
    /// One datagram per event. This is the default.
    #[default]
    Udp,
    /// A stream connection.
    Tcp,
}

/// The syslog facility events are filed under.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Hash, Deserialize)]
#[serde(rename_all = "snake_case")]
#[non_exhaustive]
pub enum SyslogFacility {
    /// Security and authorisation messages.
    Auth,
    /// Security and authorisation messages that are kept private.
    Authpriv,
    /// System daemons.
    Daemon,
    /// User-level messages.
    User,
    /// Local use 0. This is the default, as it is for PostgreSQL.
    #[default]
    Local0,
    /// Local use 1.
    Local1,
    /// Local use 2.
    Local2,
    /// Local use 3.
    Local3,
    /// Local use 4.
    Local4,
    /// Local use 5.
    Local5,
    /// Local use 6.
    Local6,
    /// Local use 7.
    Local7,
}

impl SyslogFacility {
    /// The facility number of RFC 5424.
    #[must_use]
    pub const fn code(self) -> u8 {
        match self {
            Self::User => 1,
            Self::Daemon => 3,
            Self::Auth => 4,
            Self::Authpriv => 10,
            Self::Local0 => 16,
            Self::Local1 => 17,
            Self::Local2 => 18,
            Self::Local3 => 19,
            Self::Local4 => 20,
            Self::Local5 => 21,
            Self::Local6 => 22,
            Self::Local7 => 23,
        }
    }
}

/// A syslog server, in the format of RFC 5424.
#[derive(Clone, Debug, PartialEq, Eq, Deserialize)]
#[serde(deny_unknown_fields)]
#[non_exhaustive]
pub struct SyslogSink {
    /// The server: a host and a port such as `syslog.example.com:514`, or
    /// `unix:` followed by the path of a socket.
    pub address: Endpoint,
    /// How the server is reached.
    #[serde(default)]
    pub transport: SyslogTransport,
    /// The facility events are filed under.
    #[serde(default)]
    pub facility: SyslogFacility,
    /// The length of the sink's queue, in events.
    #[serde(default = "default_queue_size")]
    pub queue_size: u32,
    /// The most events delivered per second, if that is limited.
    #[serde(default)]
    pub max_events_per_second: Option<u32>,
}

#[cfg(test)]
mod tests {
    use std::path::Path;

    use super::super::yaml;
    use super::*;

    fn sink(text: &str) -> Result<Sink, String> {
        yaml::from_str::<Sink>(text).map_err(|problem| problem.to_string())
    }

    fn problems(text: &str) -> Vec<String> {
        let sink = sink(text).unwrap();
        let mut problems = Problems::new();
        sink.validate(&At::root().field("sinks").index(0), &mut problems);
        match problems.into_result() {
            Ok(()) => Vec::new(),
            Err(error) => error.problems().iter().map(ToString::to_string).collect(),
        }
    }

    const WEBHOOK: &str = "\
type: webhook
url: https://alerts.example.com/hooks/pgsnare
hmac_secret_env: PGSNARE_WEBHOOK_SECRET
";

    #[test]
    fn a_webhook_has_a_url_and_a_signing_key() {
        let Sink::Webhook(webhook) = sink(WEBHOOK).unwrap() else {
            panic!("expected a webhook");
        };
        assert!(
            matches!(&webhook.url, UrlSource::Inline(url) if url.as_str() == "https://alerts.example.com/hooks/pgsnare")
        );
        assert!(
            matches!(&webhook.hmac_secret, SecretRef::Env(name) if name.as_str() == "PGSNARE_WEBHOOK_SECRET")
        );
        assert!(!webhook.allow_insecure_http);
        assert_eq!(webhook.timeout, Duration::from_secs(5));
        assert_eq!(webhook.max_retries, 5);
        assert_eq!(webhook.queue_size, 1_024);
        assert_eq!(webhook.max_events_per_second, None);
        assert!(problems(WEBHOOK).is_empty());
    }

    #[test]
    fn the_url_and_the_key_can_come_from_the_environment_or_a_file() {
        let Sink::Webhook(webhook) = sink(
            "\
type: webhook
url_env: PGSNARE_WEBHOOK_URL
hmac_secret_file: /run/secrets/webhook-hmac
timeout: 2s
max_retries: 0
queue_size: 64
max_events_per_second: 10
",
        )
        .unwrap() else {
            panic!("expected a webhook");
        };
        assert!(
            matches!(&webhook.url, UrlSource::Env(name) if name.as_str() == "PGSNARE_WEBHOOK_URL")
        );
        assert_eq!(
            webhook.hmac_secret,
            SecretRef::File(PathBuf::from("/run/secrets/webhook-hmac"))
        );
        assert_eq!(webhook.timeout, Duration::from_secs(2));
        assert_eq!(webhook.max_retries, 0);
        assert_eq!(webhook.queue_size, 64);
        assert_eq!(webhook.max_events_per_second, Some(10));

        let Sink::Webhook(webhook) =
            sink("type: webhook\nurl_file: /run/secrets/webhook-url\nhmac_secret_env: KEY\n")
                .unwrap()
        else {
            panic!("expected a webhook");
        };
        assert_eq!(
            webhook.url,
            UrlSource::File(PathBuf::from("/run/secrets/webhook-url"))
        );
    }

    #[test]
    fn a_webhook_needs_exactly_one_url_source() {
        for text in [
            "type: webhook\nhmac_secret_env: KEY\n",
            "type: webhook\nurl: https://alerts.example.com/a\nurl_env: URL\nhmac_secret_env: KEY\n",
            "type: webhook\nurl_env: URL\nurl_file: /run/secrets/url\nhmac_secret_env: KEY\n",
        ] {
            let error = sink(text).unwrap_err();
            assert!(
                error.ends_with("set exactly one of url, url_env and url_file"),
                "{error}"
            );
        }
    }

    #[test]
    fn a_webhook_needs_exactly_one_source_for_its_key() {
        for text in [
            "type: webhook\nurl: https://alerts.example.com/a\n",
            "type: webhook\nurl: https://alerts.example.com/a\nhmac_secret_env: KEY\nhmac_secret_file: /run/secrets/key\n",
        ] {
            let error = sink(text).unwrap_err();
            assert!(
                error.contains("set exactly one of hmac_secret_env and hmac_secret_file"),
                "{error}"
            );
        }
    }

    #[test]
    fn a_secret_cannot_be_written_in_the_configuration() {
        // No field takes the key itself, whatever it is called.
        for field in [
            "hmac_secret",
            "hmac_key",
            "secret",
            "key",
            "password",
            "token",
            "authorization",
        ] {
            let text = format!("{WEBHOOK}{field}: \"0123456789abcdef0123456789abcdef\"\n");
            let error = sink(&text).unwrap_err();
            assert!(error.contains("unknown field"), "{field}: {error}");
            assert!(!error.contains("0123456789abcdef"), "{field}: {error}");
        }
        // And the URL cannot smuggle credentials in.
        let error = sink("type: webhook\nurl: https://user:hunter2-hunter2@alerts.example.com/a\nhmac_secret_env: KEY\n")
            .unwrap_err();
        assert!(error.contains("without a user name or password"), "{error}");
        assert!(!error.contains("hunter2"), "{error}");
        // The name of an environment variable is a name, not a value.
        assert!(sink("type: webhook\nurl: https://alerts.example.com/a\nhmac_secret_env: \"not a name\"\n").is_err());
    }

    #[test]
    fn plain_http_must_be_allowed_explicitly() {
        let http = "type: webhook\nurl: http://alerts.example.com/hook\nhmac_secret_env: KEY\n";
        assert_eq!(
            problems(http),
            [
                "sinks[0].url: a plain http URL sends events unencrypted; use https, or set allow_insecure_http: true"
            ]
        );
        assert!(problems(&format!("{http}allow_insecure_http: true\n")).is_empty());
        assert!(problems(&format!("{WEBHOOK}allow_insecure_http: true\n")).is_empty());
    }

    #[test]
    fn webhook_limits_are_checked() {
        assert_eq!(
            problems(&format!("{WEBHOOK}timeout: 50ms\n")),
            ["sinks[0].timeout: must be between 100ms and 60s"]
        );
        assert_eq!(
            problems(&format!("{WEBHOOK}timeout: 2m\n")),
            ["sinks[0].timeout: must be between 100ms and 60s"]
        );
        assert_eq!(
            problems(&format!("{WEBHOOK}max_retries: 101\n")),
            ["sinks[0].max_retries: must be at most 100"]
        );
        assert_eq!(
            problems(&format!(
                "{WEBHOOK}queue_size: 0\nmax_events_per_second: 0\n"
            )),
            [
                "sinks[0].queue_size: must be between 1 and 1000000",
                "sinks[0].max_events_per_second: must be at least 1",
            ]
        );
        assert_eq!(
            problems("type: webhook\nurl_file: \"\"\nhmac_secret_file: \"\"\n"),
            [
                "sinks[0].url_file: the path must not be empty",
                "sinks[0].hmac_secret_file: the path must not be empty",
            ]
        );
    }

    #[test]
    fn the_other_sinks_are_read() {
        let stdout = sink("type: stdout\n").unwrap();
        assert_eq!(stdout.kind(), "stdout");
        assert_eq!(stdout.queue_size(), 1_024);
        assert_eq!(stdout.max_events_per_second(), None);
        assert!(problems("type: stdout\n").is_empty());

        let file =
            sink("type: file\npath: /var/log/pgsnare/events.jsonl\nqueue_size: 10\n").unwrap();
        assert_eq!(file.kind(), "file");
        assert_eq!(file.queue_size(), 10);
        assert!(
            matches!(&file, Sink::File(f) if f.path == Path::new("/var/log/pgsnare/events.jsonl"))
        );
        assert_eq!(
            problems("type: file\npath: \"\"\n"),
            ["sinks[0].path: the path must not be empty"]
        );

        let Sink::Syslog(syslog) = sink("type: syslog\naddress: syslog.example.com:514\n").unwrap()
        else {
            panic!("expected syslog");
        };
        assert_eq!(syslog.address.to_string(), "syslog.example.com:514");
        assert_eq!(syslog.transport, SyslogTransport::Udp);
        assert_eq!(syslog.facility, SyslogFacility::Local0);
        assert_eq!(syslog.facility.code(), 16);

        let Sink::Syslog(syslog) = sink(
            "type: syslog\naddress: unix:/dev/log\ntransport: tcp\nfacility: authpriv\nmax_events_per_second: 100\n",
        )
        .unwrap() else {
            panic!("expected syslog");
        };
        assert!(syslog.address.is_unix());
        assert_eq!(syslog.transport, SyslogTransport::Tcp);
        assert_eq!(syslog.facility.code(), 10);
        assert_eq!(sink(WEBHOOK).unwrap().kind(), "webhook");
    }

    #[test]
    fn a_sink_needs_a_known_type_and_only_its_own_fields() {
        let error = sink("url: https://alerts.example.com/a\n").unwrap_err();
        assert!(error.ends_with("missing field `type`"), "{error}");

        let error = sink("type: kafka\n").unwrap_err();
        assert!(
            error
                .ends_with("unknown value; expected one of: `webhook`, `stdout`, `file`, `syslog`"),
            "{error}"
        );
        for text in [
            "type: stdout\npath: /tmp/x\n",
            "type: file\n",
            "type: file\npath: /var/log/x\nurl: https://alerts.example.com/a\n",
            "type: syslog\n",
            "type: syslog\naddress: syslog.example.com\n",
            "type: syslog\naddress: syslog.example.com:514\nfacility: kern\n",
            "type: syslog\naddress: syslog.example.com:514\ntransport: tls\n",
            "type: stdout\nqueue_size: many\n",
            "type: stdout\nqueue_size: -1\n",
        ] {
            assert!(sink(text).is_err(), "{text}");
        }
    }

    #[test]
    fn every_path_of_a_sink_is_visited() {
        let mut visited = Vec::new();
        for text in [
            "type: stdout\n",
            "type: file\npath: events.jsonl\n",
            "type: webhook\nurl_file: url.txt\nhmac_secret_file: key.txt\n",
            WEBHOOK,
            "type: syslog\naddress: unix:/dev/log\n",
        ] {
            let mut sink = sink(text).unwrap();
            sink.for_each_path_mut(&mut |path| visited.push(path.clone()));
        }
        assert_eq!(
            visited,
            [
                PathBuf::from("events.jsonl"),
                PathBuf::from("url.txt"),
                PathBuf::from("key.txt")
            ]
        );
    }
}
