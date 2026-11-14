// SPDX-License-Identifier: Apache-2.0

//! The `webhook` sink: each event as a signed HTTP request.
//!
//! # The request
//!
//! ```text
//! POST /hooks/pgsnare HTTP/1.1
//! host: alerts.example.com
//! content-type: application/json
//! content-length: 512
//! user-agent: pgsnare/0.0.0
//! connection: close
//! x-pgsnare-event-id: 0123456789abcdef0123456789abcdef
//! x-pgsnare-timestamp: 1794416791
//! x-pgsnare-signature: v1=<64 hexadecimal digits>
//!
//! {"schema_version":1,"event_id":"0123456789abcdef0123456789abcdef",...}
//! ```
//!
//! The body is one event as JSON, as every other sink writes it. Each
//! attempt is a connection of its own, which is closed when the answer has
//! come.
//!
//! # The signature
//!
//! Every request is signed with HMAC-SHA256 and the key of the sink.
//!
//! **What is signed** is these bytes, in this order:
//!
//! 1. the value of `x-pgsnare-timestamp` as it stands in the header: the
//!    time of the attempt in seconds since 1970-01-01T00:00:00Z, in
//!    decimal digits without a sign or leading zeros
//! 2. one full stop, the byte `0x2e`
//! 3. the body of the request, byte for byte as it was received
//!
//! **The signature** is the 32 bytes of the HMAC as 64 lowercase
//! hexadecimal digits, after the prefix `v1=`. The prefix names the scheme,
//! so that another scheme can be told apart should one ever be needed.
//!
//! Nothing has to be parsed to check a signature: the timestamp comes from
//! a header, and the body is taken as the bytes it is.
//!
//! An example to check an implementation against. With the key `key`, the
//! timestamp `1794416791` and the body `{"kind":"token_hit"}`, the signed
//! bytes are `1794416791.{"kind":"token_hit"}` and the header is
//!
//! ```text
//! x-pgsnare-signature: v1=1ad65063af22662a8d9232e6855fb29791caa9f2f31fd45812a4132f9cd64f52
//! ```
//!
//! which is what this prints:
//!
//! ```text
//! printf '%s' '1794416791.{"kind":"token_hit"}' | openssl dgst -sha256 -hmac key
//! ```
//!
//! # What a receiver does
//!
//! 1. **Reject a request without both headers**, or with a timestamp that
//!    is not a decimal number, or with a signature that is not `v1=` and 64
//!    hexadecimal digits.
//! 2. **Reject an old request.** If the timestamp is further from the
//!    receiver's own clock than it tolerates, five minutes for example, the
//!    request is refused. A request that somebody recorded cannot be sent
//!    again later.
//! 3. **Reject a forged request.** Compute the HMAC over the timestamp, the
//!    full stop and the body with the shared key, and compare it with the
//!    signature in constant time. Whoever does not hold the key cannot
//!    produce a signature that matches, for any timestamp or body.
//! 4. **Reject a request it has seen.** Inside the time it tolerates, a
//!    recorded request would still pass the two checks above. Each event
//!    has an identifier, `event_id` in the body, which is signed with it
//!    and repeated in `x-pgsnare-event-id`. A receiver that remembers the
//!    identifiers it accepted for as long as it tolerates old requests
//!    refuses a repetition. The header is only a convenience: it is not
//!    signed, so the identifier to trust is the one in the body.
//!
//! An attempt that is made again carries the same event and identifier
//! under a new timestamp and signature: a retry is signed at the time it is
//! sent. A receiver that answered the first attempt and whose answer was
//! lost therefore sees the event twice, and its memory of identifiers is
//! also what makes that harmless.
//!
//! # The answer
//!
//! | Status | Meaning |
//! |---|---|
//! | 2xx | The event is delivered |
//! | 408, 425, 429, 5xx | Not now: the attempt is made again later |
//! | 3xx | A redirect, which is never followed: the event is dropped |
//! | Anything else | Refused: the event is dropped |
//!
//! # What holds for every request
//!
//! - **HTTPS, verified.** The certificate of the receiver must chain to an
//!   authority of the system's certificate store and carry the name of the
//!   host in the URL. TLS 1.2 is the floor. A plain `http` URL is refused
//!   unless the sink was told to allow it, and a sink that was says so in
//!   the log when it is built.
//! - **No redirect is followed.**
//! - **No proxy is used**, whatever the environment says.
//! - **Everything has a limit**: the time of an attempt, from resolving the
//!   name to the last byte of the answer; the size of the head of the
//!   answer; and how much of its body is read at all.
//! - **Nothing of the URL or the key is ever written anywhere.** The URL
//!   can hold a secret in its path or its query. Log lines and errors name
//!   the sink, and say what went wrong in fixed words.

use std::fmt;
use std::io;
use std::sync::Arc;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use aws_lc_rs::hmac;
use hyper::header::{CONNECTION, CONTENT_LENGTH, CONTENT_TYPE, HOST, USER_AGENT};
use hyper::{Method, Request, StatusCode, Uri};
use pgsnare_core::event::Event;
use pgsnare_core::extension::{EventSink, SinkError, SinkFuture};
use rustls::pki_types::ServerName;
use rustls::{CertificateError, ClientConfig, RootCertStore};
use tokio_rustls::TlsConnector;

use crate::http::{self, Body};

/// The header with the time of the attempt.
pub const TIMESTAMP_HEADER: &str = "x-pgsnare-timestamp";

/// The header with the signature.
pub const SIGNATURE_HEADER: &str = "x-pgsnare-signature";

/// The header that repeats the identifier of the event.
pub const EVENT_ID_HEADER: &str = "x-pgsnare-event-id";

/// What a signature of the scheme this sink signs with begins with.
pub const SIGNATURE_PREFIX: &str = "v1=";

/// The shortest key that is used without a warning, in bytes: the length
/// of the output of the hash, below which a key is weaker than it could
/// be.
pub const RECOMMENDED_KEY_BYTES: usize = 32;

const USER_AGENT_VALUE: &str = concat!("pgsnare/", env!("CARGO_PKG_VERSION"));

/// Whom a webhook sink trusts to vouch for a receiver.
#[derive(Clone, Debug, Default)]
#[non_exhaustive]
pub enum Trust {
    /// The certificate store of the system. This is what a sink of a
    /// configuration uses.
    #[default]
    System,
    /// These authorities and no others.
    Roots(RootCertStore),
}

/// What a webhook sink is built with, apart from its URL and its key.
#[derive(Clone, Debug)]
#[non_exhaustive]
pub struct WebhookSettings {
    /// Whether a plain `http` URL is accepted. The default is `false`.
    pub allow_insecure_http: bool,
    /// How long one attempt may take, from resolving the name of the
    /// receiver to the end of its answer.
    pub timeout: Duration,
    /// Whom the sink trusts to vouch for the receiver.
    pub trust: Trust,
}

impl Default for WebhookSettings {
    fn default() -> Self {
        Self {
            allow_insecure_http: false,
            timeout: crate::config::DEFAULT_WEBHOOK_TIMEOUT,
            trust: Trust::System,
        }
    }
}

impl WebhookSettings {
    /// The settings a sink gets when nothing else is said.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Sets whether a plain `http` URL is accepted.
    #[must_use]
    pub const fn with_allow_insecure_http(mut self, allow: bool) -> Self {
        self.allow_insecure_http = allow;
        self
    }

    /// Sets how long one attempt may take.
    #[must_use]
    pub const fn with_timeout(mut self, timeout: Duration) -> Self {
        self.timeout = timeout;
        self
    }

    /// Sets whom the sink trusts to vouch for the receiver.
    #[must_use]
    pub fn with_trust(mut self, trust: Trust) -> Self {
        self.trust = trust;
        self
    }
}

/// Why a webhook sink could not be built. No message contains the URL or
/// the key.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[non_exhaustive]
pub enum WebhookError {
    /// The URL is not an `https` or `http` URL with a host that this sink
    /// can use.
    Url,
    /// The URL is a plain `http` URL and the sink was not told to allow
    /// one.
    InsecureUrl,
    /// The key is empty.
    EmptyKey,
    /// The certificate store of the system holds no usable certificate.
    NoSystemRoots,
    /// The TLS library refused the settings.
    Tls,
}

impl fmt::Display for WebhookError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            Self::Url => {
                "the URL cannot be used: it must be an https or http URL with a host, without a \
                 user name or password, and with nothing in its path or query that has to be \
                 percent-encoded and is not"
            }
            Self::InsecureUrl => {
                "the URL is a plain http URL, which sends events unencrypted; use https, or set \
                 allow_insecure_http: true"
            }
            Self::EmptyKey => "the signing key is empty",
            Self::NoSystemRoots => {
                "the system's certificate store holds no usable certificate, so no receiver \
                 could be verified"
            }
            Self::Tls => "the TLS settings were refused",
        })
    }
}

impl std::error::Error for WebhookError {}

/// Where the requests go.
struct Target {
    /// The host to connect to: a name, or an address without brackets.
    host: String,
    port: u16,
    /// The host as the `host` header names it, with its port when the URL
    /// has one.
    authority: String,
    /// The path and the query of the URL.
    path: String,
    /// What starts TLS, and the name the certificate must carry. `None`
    /// for a plain `http` URL.
    tls: Option<(TlsConnector, ServerName<'static>)>,
}

/// Sends each event to an HTTP endpoint as a signed request.
///
/// See the [module documentation](self) for the request, the signature and
/// what a receiver does with them.
pub struct WebhookSink {
    name: String,
    target: Target,
    key: hmac::Key,
    timeout: Duration,
}

impl WebhookSink {
    /// A sink that posts to `url` and signs with `key`.
    ///
    /// `name` is what logs and metrics call the sink. The bytes of the key
    /// are handed to the cryptographic library and not kept: the caller
    /// wipes its own copy.
    ///
    /// # Errors
    ///
    /// Returns why the sink cannot be built. The error contains neither
    /// the URL nor the key.
    pub fn new(
        name: impl Into<String>,
        url: &str,
        key: &[u8],
        settings: WebhookSettings,
    ) -> Result<Self, WebhookError> {
        if key.is_empty() {
            return Err(WebhookError::EmptyKey);
        }
        let target = Target::new(url, &settings)?;
        Ok(Self {
            name: name.into(),
            target,
            key: hmac::Key::new(hmac::HMAC_SHA256, key),
            timeout: settings.timeout,
        })
    }

    /// Whether events travel encrypted. A sink that was allowed a plain
    /// `http` URL and was given one says `false`.
    #[must_use]
    pub const fn is_encrypted(&self) -> bool {
        self.target.tls.is_some()
    }

    /// The path and the query of the URL, which can hold a secret: for the
    /// redactor, and for nothing that writes it anywhere.
    pub(crate) fn path(&self) -> &str {
        &self.target.path
    }

    /// The signature of a body sent at a time: `v1=` and the HMAC as
    /// hexadecimal digits.
    fn sign(&self, timestamp: &str, body: &[u8]) -> String {
        let mut context = hmac::Context::with_key(&self.key);
        context.update(timestamp.as_bytes());
        context.update(b".");
        context.update(body);
        let tag = context.sign();

        let mut signature = String::with_capacity(SIGNATURE_PREFIX.len() + 64);
        signature.push_str(SIGNATURE_PREFIX);
        for byte in tag.as_ref() {
            use fmt::Write as _;
            // Writing to a `String` cannot fail.
            let _ = write!(signature, "{byte:02x}");
        }
        signature
    }

    /// One attempt, without its time limit.
    async fn post(&self, event: &Event) -> Result<(), SinkError> {
        let body = serde_json::to_vec(event)
            .map_err(|_| SinkError::permanent("the event could not be written as JSON"))?;
        let timestamp = unix_seconds().to_string();
        let request = Request::builder()
            .method(Method::POST)
            .uri(self.target.path.as_str())
            .header(HOST, self.target.authority.as_str())
            .header(CONTENT_TYPE, "application/json")
            .header(CONTENT_LENGTH, body.len())
            .header(USER_AGENT, USER_AGENT_VALUE)
            .header(CONNECTION, "close")
            .header(EVENT_ID_HEADER, event.event_id.to_string())
            .header(TIMESTAMP_HEADER, timestamp.as_str())
            .header(SIGNATURE_HEADER, self.sign(&timestamp, &body))
            .body(Body::new(body))
            .map_err(|_| SinkError::permanent("the request could not be put together"))?;

        let stream = http::connect(&self.target.host, self.target.port)
            .await
            .map_err(SinkError::retryable)?;
        let status = match &self.target.tls {
            Some((connector, name)) => {
                let stream = connector
                    .connect(name.clone(), stream)
                    .await
                    .map_err(|error| SinkError::retryable(describe_handshake(&error)))?;
                http::exchange(stream, request).await
            }
            None => http::exchange(stream, request).await,
        };
        judge(status.map_err(SinkError::retryable)?)
    }
}

/// What the answer of a receiver means for the event.
fn judge(status: StatusCode) -> Result<(), SinkError> {
    let code = status.as_u16();
    match code {
        200..=299 => Ok(()),
        300..=399 => Err(SinkError::permanent(format!(
            "the receiver answered with status {code}, a redirect, and redirects are not followed"
        ))),
        408 | 425 | 429 | 500..=599 => Err(SinkError::retryable(format!(
            "the receiver answered with status {code}"
        ))),
        _ => Err(SinkError::permanent(format!(
            "the receiver refused the event with status {code}"
        ))),
    }
}

/// The time, in whole seconds since the Unix epoch.
fn unix_seconds() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_or(0, |since| since.as_secs())
}

impl Target {
    fn new(url: &str, settings: &WebhookSettings) -> Result<Self, WebhookError> {
        // The rules of the configuration first: http or https, a host, no
        // user name and no password. Then the HTTP library takes the URL
        // apart, so that nothing here cuts a URL by hand.
        url.parse::<crate::config::WebhookUrl>()
            .map_err(|_| WebhookError::Url)?;
        let uri: Uri = url.parse().map_err(|_| WebhookError::Url)?;

        let https = match uri.scheme_str() {
            Some("https") => true,
            Some("http") => false,
            _ => return Err(WebhookError::Url),
        };
        if !https && !settings.allow_insecure_http {
            return Err(WebhookError::InsecureUrl);
        }
        let authority = uri.authority().ok_or(WebhookError::Url)?;
        // An IPv6 address stands in brackets in a URL and nowhere else.
        let host = authority
            .host()
            .trim_start_matches('[')
            .trim_end_matches(']')
            .to_owned();
        if host.is_empty() {
            return Err(WebhookError::Url);
        }
        let port = authority.port_u16().unwrap_or(if https { 443 } else { 80 });
        let path = match uri.path_and_query() {
            Some(path) if !path.as_str().is_empty() => path.as_str().to_owned(),
            _ => "/".to_owned(),
        };

        let tls = if https {
            let name = ServerName::try_from(host.clone()).map_err(|_| WebhookError::Url)?;
            Some((connector(&settings.trust)?, name))
        } else {
            None
        };
        Ok(Self {
            host,
            port,
            authority: authority.as_str().to_owned(),
            path,
            tls,
        })
    }
}

/// What starts TLS with a receiver: the cryptography and the floor of
/// TLS 1.2 that both legs of a listener have, and HTTP/1.1 as the protocol.
fn connector(trust: &Trust) -> Result<TlsConnector, WebhookError> {
    let roots = match trust {
        Trust::Roots(roots) => roots.clone(),
        Trust::System => {
            // Certificates the store cannot use are skipped, as every TLS
            // client does. An empty store would trust nobody.
            let mut roots = RootCertStore::empty();
            roots.add_parsable_certificates(rustls_native_certs::load_native_certs().certs);
            if roots.is_empty() {
                return Err(WebhookError::NoSystemRoots);
            }
            roots
        }
    };
    let mut config = ClientConfig::builder_with_provider(crate::tls::provider())
        .with_protocol_versions(&[&rustls::version::TLS13, &rustls::version::TLS12])
        .map_err(|_| WebhookError::Tls)?
        .with_root_certificates(roots)
        .with_no_client_auth();
    config.alpn_protocols = vec![b"http/1.1".to_vec()];
    Ok(TlsConnector::from(Arc::new(config)))
}

/// Says what went wrong in a handshake with a receiver, in a fixed text.
/// The text of the error is never used: parts of it can come from the
/// other side.
fn describe_handshake(error: &io::Error) -> &'static str {
    let Some(tls) = error
        .get_ref()
        .and_then(|inner| inner.downcast_ref::<rustls::Error>())
    else {
        return match error.kind() {
            io::ErrorKind::UnexpectedEof => "the connection was closed during the TLS handshake",
            _ => "the connection failed during the TLS handshake",
        };
    };
    match tls {
        rustls::Error::InvalidCertificate(reason) => match reason {
            CertificateError::Expired | CertificateError::ExpiredContext { .. } => {
                "the certificate of the receiver has expired"
            }
            CertificateError::NotValidYet | CertificateError::NotValidYetContext { .. } => {
                "the certificate of the receiver is not valid yet"
            }
            CertificateError::NotValidForName | CertificateError::NotValidForNameContext { .. } => {
                "the certificate of the receiver is not valid for the host of the URL"
            }
            CertificateError::UnknownIssuer => {
                "the certificate of the receiver is not signed by a trusted authority"
            }
            _ => "the certificate of the receiver was not accepted",
        },
        rustls::Error::PeerIncompatible(_) => {
            "the receiver supports no protocol version or cipher that is acceptable"
        }
        rustls::Error::AlertReceived(_) => "the receiver refused the TLS handshake",
        _ => "the TLS handshake with the receiver failed",
    }
}

/// Shows the name of the sink and whether it encrypts. The URL and the key
/// are not shown.
impl fmt::Debug for WebhookSink {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("WebhookSink")
            .field("name", &self.name)
            .field("encrypted", &self.is_encrypted())
            .field("timeout", &self.timeout)
            .finish_non_exhaustive()
    }
}

impl EventSink for WebhookSink {
    fn name(&self) -> &str {
        &self.name
    }

    fn deliver<'a>(&'a self, event: &'a Event) -> SinkFuture<'a> {
        Box::pin(async move {
            match tokio::time::timeout(self.timeout, self.post(event)).await {
                Ok(outcome) => outcome,
                Err(_) => Err(SinkError::retryable("the receiver did not answer in time")),
            }
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const URL: &str = "https://alerts.example.com/hooks/T0p-S3cret-Path?token=Qu3ry-S3cret";
    const KEY: &[u8] = b"0123456789abcdef0123456789abcdef";

    fn settings() -> WebhookSettings {
        // No test of this module connects anywhere, so an empty store of
        // authorities will do.
        WebhookSettings::new().with_trust(Trust::Roots(RootCertStore::empty()))
    }

    fn sink(url: &str) -> Result<WebhookSink, WebhookError> {
        WebhookSink::new("webhook-0", url, KEY, settings())
    }

    #[test]
    fn the_signature_is_the_hmac_of_the_timestamp_a_full_stop_and_the_body() {
        let sink = WebhookSink::new("webhook-0", URL, b"key", settings()).unwrap();
        // The expected value comes from two other implementations, which
        // agree:
        //   printf '%s' '1794416791.{"kind":"token_hit"}' \
        //       | openssl dgst -sha256 -hmac key
        //   python3 -c 'import hmac, hashlib; print(hmac.new(b"key",
        //       b"1794416791.{\"kind\":\"token_hit\"}", hashlib.sha256).hexdigest())'
        assert_eq!(
            sink.sign("1794416791", br#"{"kind":"token_hit"}"#),
            "v1=1ad65063af22662a8d9232e6855fb29791caa9f2f31fd45812a4132f9cd64f52"
        );
        // Another timestamp, another body or another key: another
        // signature.
        let signature = sink.sign("1794416791", br#"{"kind":"token_hit"}"#);
        assert_ne!(
            sink.sign("1794416792", br#"{"kind":"token_hit"}"#),
            signature
        );
        assert_ne!(
            sink.sign("1794416791", br#"{"kind":"rule_hit"}"#),
            signature
        );
        let other = WebhookSink::new("webhook-0", URL, b"another key", settings()).unwrap();
        assert_ne!(
            other.sign("1794416791", br#"{"kind":"token_hit"}"#),
            signature
        );
        // The full stop keeps the timestamp and the body apart.
        assert_ne!(
            sink.sign("17944167", b"91.x"),
            sink.sign("1794416791", b"x")
        );

        assert!(signature.starts_with(SIGNATURE_PREFIX));
        assert_eq!(signature.len(), 3 + 64);
        assert!(
            signature[3..]
                .bytes()
                .all(|byte| matches!(byte, b'0'..=b'9' | b'a'..=b'f'))
        );
    }

    #[test]
    fn a_url_is_taken_apart_into_where_to_connect_and_what_to_ask_for() {
        let target = |url: &str| sink(url).unwrap().target;

        let hook = target(URL);
        assert_eq!(hook.host, "alerts.example.com");
        assert_eq!(hook.port, 443);
        assert_eq!(hook.authority, "alerts.example.com");
        assert_eq!(hook.path, "/hooks/T0p-S3cret-Path?token=Qu3ry-S3cret");
        assert!(hook.tls.is_some());

        let with_port = target("https://alerts.example.com:8443/hook#fragment");
        assert_eq!(with_port.port, 8443);
        assert_eq!(with_port.authority, "alerts.example.com:8443");
        assert_eq!(with_port.path, "/hook");

        let bare = target("https://alerts.example.com");
        assert_eq!(bare.path, "/");

        let address = target("https://192.0.2.20/hook");
        assert_eq!(address.host, "192.0.2.20");

        let v6 = target("https://[2001:db8::20]:8443/hook");
        assert_eq!(v6.host, "2001:db8::20");
        assert_eq!(v6.port, 8443);
        assert_eq!(v6.authority, "[2001:db8::20]:8443");
    }

    #[test]
    fn plain_http_takes_an_explicit_setting() {
        let http = "http://alerts.example.com/hook";
        assert_eq!(sink(http).err(), Some(WebhookError::InsecureUrl));

        let allowed = WebhookSink::new(
            "webhook-0",
            http,
            KEY,
            settings().with_allow_insecure_http(true),
        )
        .unwrap();
        assert!(!allowed.is_encrypted());
        assert_eq!(allowed.target.port, 80);
        assert!(allowed.target.tls.is_none());

        // Allowing plain HTTP does not take TLS away from an https URL.
        let secure = WebhookSink::new(
            "webhook-0",
            URL,
            KEY,
            settings().with_allow_insecure_http(true),
        )
        .unwrap();
        assert!(secure.is_encrypted());
    }

    #[test]
    fn a_url_that_cannot_be_used_is_refused_without_being_shown() {
        for url in [
            "",
            "alerts.example.com/hook",
            "ftp://alerts.example.com/hook",
            "https://",
            "https://user:hunter2-hunter2@alerts.example.com/hook",
            "https://alerts.example.com/h\u{f6}\u{f6}k",
            "https://alerts.example.com/hook with space",
            "https://alerts.example.com/S3cret\nsecond-line",
        ] {
            let error = sink(url)
                .err()
                .unwrap_or_else(|| panic!("{url:?} is refused"));
            assert_eq!(error, WebhookError::Url, "{url:?}");
            let shown = format!("{error} {error:?}");
            assert!(!shown.contains("hunter2"), "{shown}");
            assert!(!shown.contains("S3cret"), "{shown}");
            assert!(!shown.contains("example.com"), "{shown}");
        }
    }

    #[test]
    fn an_empty_key_is_refused() {
        assert_eq!(
            WebhookSink::new("webhook-0", URL, b"", settings()).err(),
            Some(WebhookError::EmptyKey)
        );
    }

    #[test]
    fn nothing_about_a_sink_shows_its_url_or_its_key() {
        let sink = sink(URL).unwrap();
        assert_eq!(sink.name(), "webhook-0");
        let shown = format!("{sink:?}");
        assert_eq!(
            shown,
            "WebhookSink { name: \"webhook-0\", encrypted: true, timeout: 5s, .. }"
        );
        for part in ["example.com", "S3cret", "0123456789abcdef", "hooks"] {
            assert!(!shown.contains(part), "{shown}");
        }
    }

    #[test]
    fn the_status_of_the_answer_decides_what_becomes_of_the_event() {
        let outcome = |code: u16| judge(StatusCode::from_u16(code).unwrap());
        for code in [200, 201, 202, 204, 299] {
            assert_eq!(outcome(code), Ok(()), "{code}");
        }
        for code in [408, 425, 429, 500, 502, 503, 504, 599] {
            let error = outcome(code).unwrap_err();
            assert!(error.is_retryable(), "{code}");
            assert_eq!(
                error.message(),
                format!("the receiver answered with status {code}")
            );
        }
        for code in [301, 302, 303, 307, 308] {
            let error = outcome(code).unwrap_err();
            assert!(!error.is_retryable(), "{code}");
            assert!(
                error.message().contains("redirects are not followed"),
                "{code}"
            );
        }
        for code in [400, 401, 403, 404, 410, 413, 422] {
            let error = outcome(code).unwrap_err();
            assert!(!error.is_retryable(), "{code}");
            assert_eq!(
                error.message(),
                format!("the receiver refused the event with status {code}")
            );
        }
        // An answer that is no answer yet.
        assert!(!outcome(101).unwrap_err().is_retryable());
    }

    #[test]
    fn the_defaults_are_the_safe_ones() {
        let settings = WebhookSettings::default();
        assert!(!settings.allow_insecure_http);
        assert_eq!(settings.timeout, Duration::from_secs(5));
        assert!(matches!(settings.trust, Trust::System));
    }
}
