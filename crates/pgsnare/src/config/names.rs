// SPDX-License-Identifier: Apache-2.0

//! Names, addresses and other short texts of the configuration, each with
//! its own rules.

use std::fmt;
use std::net::{IpAddr, Ipv6Addr, SocketAddr};
use std::path::PathBuf;
use std::str::FromStr;

use serde::{Deserialize, Deserializer, de};

/// Reads text through a parser and never repeats what it could not read.
struct TextVisitor<T> {
    expecting: &'static str,
    parse: fn(&str) -> Option<T>,
}

impl<T> de::Visitor<'_> for TextVisitor<T> {
    type Value = T;

    fn expecting(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.expecting)
    }

    fn visit_str<E: de::Error>(self, text: &str) -> Result<T, E> {
        (self.parse)(text)
            .ok_or_else(|| E::invalid_value(de::Unexpected::Other("other text"), &self.expecting))
    }
}

/// Implements `Deserialize` and `FromStr` for a type that is read from text.
macro_rules! from_text {
    ($name:ident, $expecting:expr, $parse:expr) => {
        impl $name {
            const EXPECTING: &'static str = $expecting;

            fn parse(text: &str) -> Option<Self> {
                let parse: fn(&str) -> Option<Self> = $parse;
                parse(text)
            }
        }

        impl FromStr for $name {
            type Err = InvalidText;

            fn from_str(text: &str) -> Result<Self, InvalidText> {
                Self::parse(text).ok_or(InvalidText {
                    expecting: Self::EXPECTING,
                })
            }
        }

        impl<'de> Deserialize<'de> for $name {
            fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
                deserializer.deserialize_str(TextVisitor {
                    expecting: Self::EXPECTING,
                    parse: Self::parse,
                })
            }
        }
    };
}

/// Text that does not follow the rules of the type it was meant for.
///
/// The error says what was expected and does not repeat the text.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct InvalidText {
    expecting: &'static str,
}

impl fmt::Display for InvalidText {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "expected {}", self.expecting)
    }
}

impl std::error::Error for InvalidText {}

/// The name of a listener.
///
/// It appears in logs and as a metric label, so it is short and uses a
/// restricted alphabet: 1 to 64 ASCII letters, digits, `.`, `_` and `-`,
/// starting with a letter or a digit.
#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct Name(String);

impl Name {
    /// The name as text.
    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

from_text!(
    Name,
    "a name of 1 to 64 characters: ASCII letters, digits, '.', '_' and '-', \
     starting with a letter or a digit",
    |text| {
        let mut bytes = text.bytes();
        let first = bytes.next()?;
        let valid = text.len() <= 64
            && first.is_ascii_alphanumeric()
            && bytes.all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'.' | b'_' | b'-'));
        valid.then(|| Name(text.to_owned()))
    }
);

impl fmt::Display for Name {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.0)
    }
}

/// The name of an environment variable: 1 to 128 ASCII letters, digits and
/// `_`, not starting with a digit.
#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct EnvVarName(String);

impl EnvVarName {
    /// The name as text.
    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

from_text!(
    EnvVarName,
    "the name of an environment variable: ASCII letters, digits and '_', \
     not starting with a digit",
    |text| {
        let mut bytes = text.bytes();
        let first = bytes.next()?;
        let valid = text.len() <= 128
            && (first.is_ascii_alphabetic() || first == b'_')
            && bytes.all(|byte| byte.is_ascii_alphanumeric() || byte == b'_');
        valid.then(|| EnvVarName(text.to_owned()))
    }
);

impl fmt::Display for EnvVarName {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.0)
    }
}

/// The name of an instance label: 1 to 64 ASCII letters, digits, `.`, `_`
/// and `-`, starting with a letter or `_`.
#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct LabelName(String);

impl LabelName {
    /// The name as text.
    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.0
    }

    /// The label an environment variable gives: its own name.
    #[must_use]
    pub fn from_env_var(name: &EnvVarName) -> Option<Self> {
        Self::parse(name.as_str())
    }
}

from_text!(
    LabelName,
    "a label name of 1 to 64 characters: ASCII letters, digits, '.', '_' and '-', \
     starting with a letter or '_'",
    |text| {
        let mut bytes = text.bytes();
        let first = bytes.next()?;
        let valid = text.len() <= 64
            && (first.is_ascii_alphabetic() || first == b'_')
            && bytes.all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'.' | b'_' | b'-'));
        valid.then(|| LabelName(text.to_owned()))
    }
);

impl fmt::Display for LabelName {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.0)
    }
}

/// An address to listen on: an IP address and a port, such as
/// `0.0.0.0:5432` or `[::]:5432`. A host name is not accepted.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct ListenAddr(SocketAddr);

impl ListenAddr {
    /// A listen address from a socket address.
    #[must_use]
    pub const fn new(address: SocketAddr) -> Self {
        Self(address)
    }

    /// The socket address.
    #[must_use]
    pub const fn socket_addr(&self) -> SocketAddr {
        self.0
    }

    /// Whether only the machine itself can reach the address.
    #[must_use]
    pub const fn is_loopback(&self) -> bool {
        self.0.ip().is_loopback()
    }
}

from_text!(
    ListenAddr,
    "an IP address and a port, such as 0.0.0.0:5432 or [::]:5432",
    |text| {
        let address: SocketAddr = text.parse().ok()?;
        // No zone identifiers or flow labels, and a real port.
        let plain = match address {
            SocketAddr::V4(_) => true,
            SocketAddr::V6(v6) => v6.scope_id() == 0 && v6.flowinfo() == 0,
        };
        (plain && address.port() != 0).then_some(ListenAddr(address))
    }
);

impl fmt::Display for ListenAddr {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.0)
    }
}

/// A host: a DNS name or an IP address.
#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct Host(String);

impl Host {
    /// The host as text. An IPv6 address has no brackets.
    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.0
    }

    /// The IP address, if the host is one and not a name.
    #[must_use]
    pub fn ip(&self) -> Option<IpAddr> {
        self.0.parse().ok()
    }
}

/// Whether `text` is a DNS name: labels of ASCII letters, digits and `-`,
/// separated by dots, at most 253 bytes in all and 63 per label.
fn is_dns_name(text: &str) -> bool {
    !text.is_empty()
        && text.len() <= 253
        && text.split('.').all(|label| {
            !label.is_empty()
                && label.len() <= 63
                && !label.starts_with('-')
                && !label.ends_with('-')
                && label
                    .bytes()
                    .all(|byte| byte.is_ascii_alphanumeric() || byte == b'-')
        })
}

from_text!(
    Host,
    "a host name such as db.example.com, or an IP address",
    |text| {
        if let Ok(address) = text.parse::<IpAddr>() {
            return Some(Host(address.to_string()));
        }
        // Text made of digits and dots only is a malformed address, not a
        // name: no top-level domain is a number.
        let numeric = text
            .bytes()
            .all(|byte| byte.is_ascii_digit() || byte == b'.');
        (is_dns_name(text) && !numeric).then(|| Host(text.to_owned()))
    }
);

impl fmt::Display for Host {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.0)
    }
}

/// Where to connect to: a host and a port, or a Unix socket.
///
/// In the configuration it is written as `db.example.com:5432`,
/// `192.0.2.10:5432`, `[2001:db8::10]:5432` or
/// `unix:/var/run/postgresql/.s.PGSQL.5432`.
#[derive(Clone, Debug, PartialEq, Eq, Hash)]
#[non_exhaustive]
pub enum Endpoint {
    /// A TCP connection.
    Tcp {
        /// The host to connect to.
        host: Host,
        /// The port to connect to.
        port: u16,
    },
    /// A Unix socket.
    Unix {
        /// The absolute path of the socket.
        path: PathBuf,
    },
}

impl Endpoint {
    /// Whether this is a Unix socket.
    #[must_use]
    pub const fn is_unix(&self) -> bool {
        matches!(self, Self::Unix { .. })
    }
}

/// Parses a port: plain digits, 1 to 65535.
fn parse_port(text: &str) -> Option<u16> {
    let plain = !text.is_empty()
        && text.len() <= 5
        && text.bytes().all(|byte| byte.is_ascii_digit())
        && !text.starts_with('0');
    if !plain {
        return None;
    }
    text.parse().ok()
}

from_text!(
    Endpoint,
    "a host and a port such as db.example.com:5432 or [2001:db8::10]:5432, \
     or unix: followed by the absolute path of a socket",
    |text| {
        if let Some(path) = text.strip_prefix("unix:") {
            let valid = path.starts_with('/') && path.len() <= 4096 && !path.contains('\0');
            return valid.then(|| Endpoint::Unix {
                path: PathBuf::from(path),
            });
        }
        let (host, port) = text.rsplit_once(':')?;
        let port = parse_port(port)?;
        let host = match host.strip_prefix('[') {
            // Brackets are for IPv6 addresses, and required for them.
            Some(rest) => {
                let address: Ipv6Addr = rest.strip_suffix(']')?.parse().ok()?;
                Host(address.to_string())
            }
            None if host.contains(':') => return None,
            None => Host::parse(host)?,
        };
        Some(Endpoint::Tcp { host, port })
    }
);

impl fmt::Display for Endpoint {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Tcp { host, port } if host.as_str().contains(':') => {
                write!(f, "[{host}]:{port}")
            }
            Self::Tcp { host, port } => write!(f, "{host}:{port}"),
            Self::Unix { path } => write!(f, "unix:{}", path.display()),
        }
    }
}

/// The URL of a webhook.
///
/// Only `https` and `http` URLs are accepted, and a URL must not carry a
/// user name or a password: credentials do not belong in the configuration.
/// Whether plain `http` is allowed is decided by the sink that uses the URL.
#[derive(Clone, PartialEq, Eq, Hash)]
pub struct WebhookUrl(String);

impl WebhookUrl {
    /// The URL as text.
    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.0
    }

    /// Whether the URL uses TLS.
    #[must_use]
    pub fn is_https(&self) -> bool {
        self.0.starts_with("https://")
    }
}

from_text!(
    WebhookUrl,
    "an https:// or http:// URL with a host and without a user name or password",
    |text| {
        let rest = text
            .strip_prefix("https://")
            .or_else(|| text.strip_prefix("http://"))?;
        let authority = rest.split(['/', '?', '#']).next()?;
        // A port is allowed, a user name or password is not.
        let host = match authority.strip_prefix('[') {
            Some(bracketed) => {
                let (address, after) = bracketed.split_once(']')?;
                address.parse::<Ipv6Addr>().ok()?;
                match after.strip_prefix(':') {
                    Some(port) => parse_port(port).map(|_| ())?,
                    None if after.is_empty() => {}
                    None => return None,
                }
                None
            }
            None => match authority.rsplit_once(':') {
                Some((host, port)) => {
                    parse_port(port)?;
                    Some(host)
                }
                None => Some(authority),
            },
        };
        if let Some(host) = host {
            Host::parse(host)?;
        }
        let printable = text.len() <= 2048 && text.bytes().all(|byte| byte.is_ascii_graphic());
        printable.then(|| WebhookUrl(text.to_owned()))
    }
);

/// The URL may carry a secret in its path, so it is not shown.
impl fmt::Debug for WebhookUrl {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("WebhookUrl(<not shown>)")
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn listener_names_are_short_and_plain() {
        for text in ["main", "pg-1", "eu.west_2", "7", &"n".repeat(64)] {
            assert_eq!(text.parse::<Name>().unwrap().as_str(), text);
        }
        for text in [
            "",
            "-main",
            ".main",
            "ma in",
            "ma/in",
            "caf\u{e9}",
            &"n".repeat(65),
        ] {
            assert!(text.parse::<Name>().is_err(), "{text:?}");
        }
    }

    #[test]
    fn environment_variable_names_follow_the_usual_rules() {
        for text in ["POD_NAME", "_x", "a1", "PGSNARE_WEBHOOK_SECRET"] {
            assert_eq!(text.parse::<EnvVarName>().unwrap().as_str(), text);
        }
        for text in [
            "",
            "1A",
            "POD-NAME",
            "POD NAME",
            "A=B",
            "$HOME",
            &"A".repeat(129),
        ] {
            assert!(text.parse::<EnvVarName>().is_err(), "{text:?}");
        }
    }

    #[test]
    fn label_names_are_short_and_plain() {
        for text in ["env", "POD_NAME", "_private", "app.kubernetes.io-name"] {
            assert_eq!(text.parse::<LabelName>().unwrap().as_str(), text);
        }
        for text in ["", "1st", "-x", "has space", "a=b", &"l".repeat(65)] {
            assert!(text.parse::<LabelName>().is_err(), "{text:?}");
        }
        let variable: EnvVarName = "POD_NAME".parse().unwrap();
        assert_eq!(
            LabelName::from_env_var(&variable).unwrap().as_str(),
            "POD_NAME"
        );
        let long: EnvVarName = "A".repeat(100).parse().unwrap();
        assert_eq!(LabelName::from_env_var(&long), None);
    }

    #[test]
    fn listen_addresses_are_an_ip_address_and_a_port() {
        for text in [
            "0.0.0.0:5432",
            "127.0.0.1:9641",
            "192.0.2.10:6432",
            "[::]:5432",
            "[2001:db8::1]:5432",
        ] {
            let address: ListenAddr = text.parse().unwrap();
            assert_eq!(address.to_string(), text);
        }
        assert!(
            "127.0.0.1:9641"
                .parse::<ListenAddr>()
                .unwrap()
                .is_loopback()
        );
        assert!("[::1]:9641".parse::<ListenAddr>().unwrap().is_loopback());
        assert!(!"0.0.0.0:9641".parse::<ListenAddr>().unwrap().is_loopback());
        assert!(
            !"192.0.2.10:9641"
                .parse::<ListenAddr>()
                .unwrap()
                .is_loopback()
        );

        for text in [
            "",
            "5432",
            ":5432",
            "0.0.0.0",
            "0.0.0.0:0", // port 0 would pick a random port
            "0.0.0.0:65536",
            "localhost:5432", // a name, not an address
            "db.example.com:5432",
            "::1:5432", // IPv6 needs brackets
            "[::1]",
            "[2001:db8::1%eth0]:5432", // a zone identifier
            " 0.0.0.0:5432",
        ] {
            assert!(text.parse::<ListenAddr>().is_err(), "{text:?}");
        }
    }

    #[test]
    fn hosts_are_names_or_addresses() {
        for text in [
            "db.example.com",
            "db",
            "db-1.example.com",
            "xn--bcher-kva.example",
            "192.0.2.10",
            "2001:db8::10",
        ] {
            assert_eq!(text.parse::<Host>().unwrap().as_str(), text);
        }
        assert_eq!(
            "192.0.2.10".parse::<Host>().unwrap().ip(),
            Some("192.0.2.10".parse().unwrap())
        );
        assert_eq!("db.example.com".parse::<Host>().unwrap().ip(), None);
        // An address is stored in its usual form.
        assert_eq!(
            "2001:DB8:0:0::10".parse::<Host>().unwrap().as_str(),
            "2001:db8::10"
        );

        for text in [
            "",
            ".",
            "db..example.com",
            ".example.com",
            "example.com.",
            "-db.example.com",
            "db-.example.com",
            "db_1.example.com",
            "db.example.com:5432",
            "db example",
            "192.0.2", // not an address, and not a name either
            "192.0.2.256",
            "1.2.3.4.5",
            "b\u{fc}cher.example",
            &format!("{}.example.com", "a".repeat(64)),
            &"a.".repeat(127),
        ] {
            assert!(text.parse::<Host>().is_err(), "{text:?}");
        }
    }

    #[test]
    fn endpoints_are_a_host_and_a_port_or_a_unix_socket() {
        let cases = [
            ("db.example.com:5432", "db.example.com", 5432),
            ("192.0.2.10:6432", "192.0.2.10", 6432),
            ("[2001:db8::10]:5432", "2001:db8::10", 5432),
            ("localhost:1", "localhost", 1),
            ("db:65535", "db", 65535),
        ];
        for (text, host, port) in cases {
            let endpoint: Endpoint = text.parse().unwrap();
            assert!(!endpoint.is_unix());
            assert!(
                matches!(&endpoint, Endpoint::Tcp { host: h, port: p } if h.as_str() == host && *p == port),
                "{text}"
            );
            assert_eq!(endpoint.to_string(), text);
        }

        let socket: Endpoint = "unix:/var/run/postgresql/.s.PGSQL.5432".parse().unwrap();
        assert!(socket.is_unix());
        assert_eq!(
            socket,
            Endpoint::Unix {
                path: PathBuf::from("/var/run/postgresql/.s.PGSQL.5432")
            }
        );
        assert_eq!(socket.to_string(), "unix:/var/run/postgresql/.s.PGSQL.5432");

        for text in [
            "",
            "db.example.com", // no port
            "db.example.com:",
            "db.example.com:0",
            "db.example.com:05432",
            "db.example.com:65536",
            "db.example.com:+5432",
            "db.example.com:5432/app", // not a URL
            ":5432",
            "2001:db8::10:5432", // IPv6 needs brackets
            "[2001:db8::10]",
            "[192.0.2.10]:5432", // brackets are for IPv6 only
            "[db.example.com]:5432",
            "unix:",
            "unix:relative/path",
            "unix:/has\0nul",
            "tcp://db.example.com:5432",
            "postgres://db.example.com:5432",
        ] {
            assert!(text.parse::<Endpoint>().is_err(), "{text:?}");
        }
    }

    #[test]
    fn webhook_urls_are_http_urls_without_credentials() {
        for text in [
            "https://alerts.example.com/hooks/pgsnare",
            "https://alerts.example.com",
            "https://alerts.example.com:8443/hook?source=pgsnare#top",
            "http://alerts.example.com/hook",
            "https://192.0.2.20/hook",
            "https://[2001:db8::20]:8443/hook",
            "https://[2001:db8::20]/hook",
        ] {
            let url: WebhookUrl = text.parse().unwrap();
            assert_eq!(url.as_str(), text);
            assert_eq!(url.is_https(), text.starts_with("https://"));
        }

        for text in [
            "",
            "alerts.example.com/hook",
            "ftp://alerts.example.com/hook",
            "HTTPS://alerts.example.com/hook",
            "https://",
            "https:///hook",
            "https://user@alerts.example.com/hook",
            "https://user:password@alerts.example.com/hook",
            "https://alerts.example.com:0/hook",
            "https://alerts.example.com:port/hook",
            "https://alerts example.com/hook",
            "https://alerts.example.com/hook with space",
            "https://alerts.example.com/h\u{f6}\u{f6}k",
            "https://[2001:db8::20/hook",
            "https://[alerts.example.com]/hook",
            "https://[2001:db8::20]x/hook",
        ] {
            assert!(text.parse::<WebhookUrl>().is_err(), "{text:?}");
        }
    }

    #[test]
    fn a_webhook_url_is_not_shown_by_debug() {
        let url: WebhookUrl = "https://alerts.example.com/hooks/T0p-S3cret-Path"
            .parse()
            .unwrap();
        let shown = format!("{url:?}");
        assert!(!shown.contains("S3cret"), "{shown}");
        assert!(!shown.contains("example.com"), "{shown}");
    }

    #[test]
    fn rejected_text_is_not_repeated() {
        let error = "Zq7honeytokenValue9xK!"
            .parse::<Name>()
            .unwrap_err()
            .to_string();
        assert!(
            error.starts_with("expected a name of 1 to 64 characters"),
            "{error}"
        );
        assert!(!error.contains("Zq7"), "{error}");
    }
}
