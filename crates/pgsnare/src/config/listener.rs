// SPDX-License-Identifier: Apache-2.0

//! Listeners: where pgsnare accepts clients and where it sends them.

use std::time::Duration;

use serde::Deserialize;

use super::error::{At, Problems};
use super::names::{Endpoint, ListenAddr, Name};
use super::tls::{ClientTls, UpstreamTls};
use super::units;

/// One listener: an address clients connect to, and the database behind it.
#[derive(Clone, Debug, PartialEq, Eq, Deserialize)]
#[serde(deny_unknown_fields)]
#[non_exhaustive]
pub struct Listener {
    /// A name for logs and metrics. No two listeners share one.
    pub name: Name,
    /// The address to accept clients on.
    pub listen: ListenAddr,
    /// The database to relay to.
    pub upstream: Endpoint,
    /// TLS between applications and pgsnare.
    pub client_tls: ClientTls,
    /// TLS between pgsnare and the database.
    pub upstream_tls: UpstreamTls,
    /// How many clients may be connected at once. Further clients are
    /// refused.
    #[serde(default = "default_max_connections")]
    pub max_connections: u32,
    /// How long a client may take to log in. A connection that has not
    /// finished logging in by then is closed.
    #[serde(
        default = "default_login_timeout",
        deserialize_with = "units::duration"
    )]
    pub login_timeout: Duration,
}

/// The default for [`Listener::max_connections`].
pub const DEFAULT_MAX_CONNECTIONS: u32 = 1_000;

/// The largest accepted [`Listener::max_connections`].
pub const MAX_MAX_CONNECTIONS: u32 = 1_000_000;

/// The default for [`Listener::login_timeout`]: one minute, which is also
/// PostgreSQL's own default for `authentication_timeout`.
pub const DEFAULT_LOGIN_TIMEOUT: Duration = Duration::from_secs(60);

/// The longest accepted [`Listener::login_timeout`]: ten minutes, which is
/// also PostgreSQL's own maximum for `authentication_timeout`.
pub const MAX_LOGIN_TIMEOUT: Duration = Duration::from_secs(600);

const fn default_max_connections() -> u32 {
    DEFAULT_MAX_CONNECTIONS
}

const fn default_login_timeout() -> Duration {
    DEFAULT_LOGIN_TIMEOUT
}

impl Listener {
    pub(super) fn validate(&self, at: &At, problems: &mut Problems) {
        if self.max_connections == 0 || self.max_connections > MAX_MAX_CONNECTIONS {
            problems.add(
                &at.field("max_connections"),
                "must be between 1 and 1000000",
            );
        }
        if self.login_timeout < Duration::from_secs(1) || self.login_timeout > MAX_LOGIN_TIMEOUT {
            problems.add(&at.field("login_timeout"), "must be between 1s and 10m");
        }
        self.client_tls.validate(&at.field("client_tls"), problems);
        self.upstream_tls
            .validate(self.upstream.is_unix(), &at.field("upstream_tls"), problems);
    }
}

/// Checks what the listeners must agree on among themselves.
pub(super) fn validate_all(listeners: &[Listener], at: &At, problems: &mut Problems) {
    if listeners.is_empty() {
        problems.add(at, "at least one listener is required");
    }
    for (index, listener) in listeners.iter().enumerate() {
        let here = at.index(index);
        listener.validate(&here, problems);

        let earlier = listeners.iter().take(index).enumerate();
        for (other_index, other) in earlier {
            let there = at.index(other_index);
            if other.name == listener.name {
                problems.add_with(
                    &here.field("name"),
                    "this name is already used",
                    &there.field("name"),
                );
            }
            if other.listen == listener.listen {
                problems.add_with(
                    &here.field("listen"),
                    "this address is already used",
                    &there.field("listen"),
                );
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::super::yaml;
    use super::*;

    const MINIMAL: &str = "\
name: main
listen: 0.0.0.0:5432
upstream: db.example.com:5432
client_tls: { mode: disable }
upstream_tls: { mode: verify-full }
";

    fn listener(text: &str) -> Listener {
        yaml::from_str(text).unwrap()
    }

    fn problems(listeners: &[Listener]) -> Vec<String> {
        let mut problems = Problems::new();
        validate_all(listeners, &At::root().field("listeners"), &mut problems);
        match problems.into_result() {
            Ok(()) => Vec::new(),
            Err(error) => error.problems().iter().map(ToString::to_string).collect(),
        }
    }

    #[test]
    fn a_minimal_listener_gets_the_defaults() {
        let listener = listener(MINIMAL);
        assert_eq!(listener.name.as_str(), "main");
        assert_eq!(listener.listen.to_string(), "0.0.0.0:5432");
        assert_eq!(listener.upstream.to_string(), "db.example.com:5432");
        assert_eq!(listener.max_connections, 1_000);
        assert_eq!(listener.login_timeout, Duration::from_secs(60));
        assert!(problems(&[listener]).is_empty());
    }

    #[test]
    fn every_field_can_be_set() {
        let listener = listener(
            "\
name: replica
listen: \"[::]:6432\"
upstream: unix:/var/run/postgresql/.s.PGSQL.5432
client_tls:
  mode: require
  cert: /etc/pgsnare/server.crt
  key: /etc/pgsnare/server.key
  min_version: tls1.3
upstream_tls: { mode: disable }
max_connections: 250
login_timeout: 15s
",
        );
        assert_eq!(listener.listen.to_string(), "[::]:6432");
        assert!(listener.upstream.is_unix());
        assert_eq!(listener.max_connections, 250);
        assert_eq!(listener.login_timeout, Duration::from_secs(15));
        assert!(problems(&[listener]).is_empty());
    }

    #[test]
    fn the_required_fields_are_required() {
        for field in ["name", "listen", "upstream", "client_tls", "upstream_tls"] {
            let without: String = MINIMAL
                .lines()
                .filter(|line| !line.starts_with(&format!("{field}:")))
                .map(|line| format!("{line}\n"))
                .collect();
            let error = yaml::from_str::<Listener>(&without)
                .unwrap_err()
                .to_string();
            assert!(
                error.ends_with(&format!("missing field `{field}`")),
                "{error}"
            );
        }
    }

    #[test]
    fn unknown_fields_are_rejected() {
        let error = yaml::from_str::<Listener>(&format!("{MINIMAL}tls: on\n"))
            .unwrap_err()
            .to_string();
        assert!(
            error.contains("unknown field; the fields here are: `name`, `listen`"),
            "{error}"
        );
    }

    #[test]
    fn limits_must_be_in_range() {
        let with = |extra: &str| problems(&[listener(&format!("{MINIMAL}{extra}"))]);
        assert_eq!(
            with("max_connections: 0\n"),
            ["listeners[0].max_connections: must be between 1 and 1000000"]
        );
        assert_eq!(
            with("max_connections: 1000001\n"),
            ["listeners[0].max_connections: must be between 1 and 1000000"]
        );
        assert!(with("max_connections: 1000000\n").is_empty());
        assert_eq!(
            with("login_timeout: 500ms\n"),
            ["listeners[0].login_timeout: must be between 1s and 10m"]
        );
        assert_eq!(
            with("login_timeout: 11m\n"),
            ["listeners[0].login_timeout: must be between 1s and 10m"]
        );
        assert!(with("login_timeout: 10m\n").is_empty());
        assert!(yaml::from_str::<Listener>(&format!("{MINIMAL}login_timeout: 60\n")).is_err());
        assert!(yaml::from_str::<Listener>(&format!("{MINIMAL}max_connections: -1\n")).is_err());
    }

    #[test]
    fn tls_rules_apply_to_each_listener() {
        let unix_with_tls =
            listener(&MINIMAL.replace("db.example.com:5432", "unix:/run/pg/.s.PGSQL.5432"));
        assert_eq!(
            problems(&[unix_with_tls]),
            [
                "listeners[0].upstream_tls: PostgreSQL does not use TLS over a Unix socket; set mode to disable"
            ]
        );
        let no_cert = listener(&MINIMAL.replace("mode: disable", "mode: require"));
        assert_eq!(
            problems(&[no_cert]),
            ["listeners[0].client_tls: cert and key are both required unless mode is disable"]
        );
    }

    #[test]
    fn listeners_must_differ_in_name_and_address() {
        let first = listener(MINIMAL);
        let same_name = listener(&MINIMAL.replace("0.0.0.0:5432", "0.0.0.0:5433"));
        let same_address = listener(&MINIMAL.replace("name: main", "name: other"));
        let different = listener(
            &MINIMAL
                .replace("name: main", "name: third")
                .replace("0.0.0.0:5432", "0.0.0.0:5434"),
        );

        assert_eq!(
            problems(&[]),
            ["listeners: at least one listener is required"]
        );
        assert!(problems(&[first.clone(), different.clone()]).is_empty());
        assert_eq!(
            problems(&[first.clone(), different, same_name, same_address]),
            [
                "listeners[2].name: this name is already used (see listeners[0].name)",
                "listeners[3].listen: this address is already used (see listeners[0].listen)",
            ]
        );
        assert_eq!(
            problems(&[first.clone(), first]),
            [
                "listeners[1].name: this name is already used (see listeners[0].name)",
                "listeners[1].listen: this address is already used (see listeners[0].listen)",
            ]
        );
    }
}
