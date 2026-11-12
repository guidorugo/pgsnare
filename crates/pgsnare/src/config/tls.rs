// SPDX-License-Identifier: Apache-2.0

//! TLS settings of the two legs of a listener.
//!
//! Both sections are required for every listener, and each names its mode.
//! Whether a leg is encrypted is never left to a default.

use std::path::PathBuf;

use serde::Deserialize;

use super::error::{At, Problems};
use super::names::Host;

/// The oldest TLS version a leg accepts.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, PartialOrd, Ord, Hash, Deserialize)]
#[non_exhaustive]
pub enum TlsVersion {
    /// TLS 1.2, the floor. This is the default.
    #[default]
    #[serde(rename = "tls1.2")]
    Tls12,
    /// TLS 1.3 only.
    #[serde(rename = "tls1.3")]
    Tls13,
}

/// Whether clients may or must use TLS.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, Deserialize)]
#[serde(rename_all = "kebab-case")]
#[non_exhaustive]
pub enum ClientTlsMode {
    /// TLS is not offered. Clients connect in plaintext.
    Disable,
    /// TLS is offered and plaintext is accepted too.
    Prefer,
    /// TLS is required. A plaintext client is refused.
    Require,
}

/// TLS on the client leg, between an application and pgsnare.
///
/// Logging in with client certificates is not supported, so there is no
/// mode that verifies the client.
#[derive(Clone, Debug, PartialEq, Eq, Deserialize)]
#[serde(deny_unknown_fields)]
#[non_exhaustive]
pub struct ClientTls {
    /// Whether clients may or must use TLS.
    pub mode: ClientTlsMode,
    /// The certificate chain pgsnare presents, in PEM. Required unless the
    /// mode is `disable`.
    #[serde(default)]
    pub cert: Option<PathBuf>,
    /// The private key for the certificate, in PEM. Required unless the mode
    /// is `disable`.
    #[serde(default)]
    pub key: Option<PathBuf>,
    /// The oldest TLS version accepted.
    #[serde(default)]
    pub min_version: TlsVersion,
}

impl ClientTls {
    pub(super) fn validate(&self, at: &At, problems: &mut Problems) {
        match (self.mode, &self.cert, &self.key) {
            (ClientTlsMode::Disable, None, None) => {}
            (ClientTlsMode::Disable, _, _) => {
                problems.add(
                    at,
                    "cert and key are set, but mode is disable; remove them or choose another mode",
                );
            }
            (_, Some(cert), Some(key)) => {
                check_path(cert, &at.field("cert"), problems);
                check_path(key, &at.field("key"), problems);
            }
            (_, _, _) => problems.add(at, "cert and key are both required unless mode is disable"),
        }
    }
}

/// Whether and how the connection to the database uses TLS.
///
/// The modes mean what they mean to a PostgreSQL client.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, Deserialize)]
#[serde(rename_all = "kebab-case")]
#[non_exhaustive]
pub enum UpstreamTlsMode {
    /// Plaintext. For a database reached over loopback or a Unix socket.
    Disable,
    /// TLS if the database offers it, plaintext otherwise, and no
    /// verification. An attacker on the path can remove the encryption.
    Prefer,
    /// TLS always, but the certificate is not verified. An attacker on the
    /// path can impersonate the database.
    Require,
    /// TLS always, with the certificate chain and the host name verified.
    VerifyFull,
}

impl UpstreamTlsMode {
    /// Whether the database's certificate is verified.
    #[must_use]
    pub const fn verifies(self) -> bool {
        matches!(self, Self::VerifyFull)
    }
}

/// TLS on the backend leg, between pgsnare and the database.
#[derive(Clone, Debug, PartialEq, Eq, Deserialize)]
#[serde(deny_unknown_fields)]
#[non_exhaustive]
pub struct UpstreamTls {
    /// Whether and how the connection uses TLS.
    pub mode: UpstreamTlsMode,
    /// The certificate authorities that may have signed the database's
    /// certificate, in PEM. Without it the system's store is used. Only for
    /// `verify-full`.
    #[serde(default)]
    pub ca: Option<PathBuf>,
    /// The name the database's certificate must carry, and the name sent to
    /// it during the handshake, when it differs from the host of `upstream`.
    #[serde(default)]
    pub server_name: Option<Host>,
    /// The oldest TLS version accepted.
    #[serde(default)]
    pub min_version: TlsVersion,
}

impl UpstreamTls {
    pub(super) fn validate(&self, upstream_is_unix: bool, at: &At, problems: &mut Problems) {
        if upstream_is_unix && self.mode != UpstreamTlsMode::Disable {
            problems.add(
                at,
                "PostgreSQL does not use TLS over a Unix socket; set mode to disable",
            );
        }
        if self.mode == UpstreamTlsMode::Disable && self.server_name.is_some() {
            problems.add(
                at,
                "server_name is set, but mode is disable; remove it or choose another mode",
            );
        }
        match &self.ca {
            Some(ca) if self.mode.verifies() => check_path(ca, &at.field("ca"), problems),
            Some(_) => problems.add(
                at,
                "ca is only used with mode verify-full; this mode does not verify the certificate",
            ),
            None => {}
        }
    }
}

/// A file path must at least name something.
pub(super) fn check_path(path: &std::path::Path, at: &At, problems: &mut Problems) {
    if path.as_os_str().is_empty() {
        problems.add(at, "the path must not be empty");
    }
}

#[cfg(test)]
mod tests {
    use super::super::yaml;
    use super::*;

    fn problems_of(check: impl FnOnce(&At, &mut Problems)) -> Vec<String> {
        let mut problems = Problems::new();
        check(&At::root().field("tls"), &mut problems);
        match problems.into_result() {
            Ok(()) => Vec::new(),
            Err(error) => error.problems().iter().map(ToString::to_string).collect(),
        }
    }

    fn client(text: &str) -> Vec<String> {
        let tls: ClientTls = yaml::from_str(text).unwrap();
        problems_of(|at, problems| tls.validate(at, problems))
    }

    fn upstream(text: &str, unix: bool) -> Vec<String> {
        let tls: UpstreamTls = yaml::from_str(text).unwrap();
        problems_of(|at, problems| tls.validate(unix, at, problems))
    }

    #[test]
    fn the_modes_have_their_postgresql_names() {
        for (text, mode) in [
            ("disable", ClientTlsMode::Disable),
            ("prefer", ClientTlsMode::Prefer),
            ("require", ClientTlsMode::Require),
        ] {
            let tls: ClientTls = yaml::from_str(&format!("mode: {text}\n")).unwrap();
            assert_eq!(tls.mode, mode);
        }
        for (text, mode) in [
            ("disable", UpstreamTlsMode::Disable),
            ("prefer", UpstreamTlsMode::Prefer),
            ("require", UpstreamTlsMode::Require),
            ("verify-full", UpstreamTlsMode::VerifyFull),
        ] {
            let tls: UpstreamTls = yaml::from_str(&format!("mode: {text}\n")).unwrap();
            assert_eq!(tls.mode, mode);
            assert_eq!(mode.verifies(), text == "verify-full");
        }
    }

    #[test]
    fn the_mode_is_required_and_other_modes_do_not_exist() {
        assert!(yaml::from_str::<ClientTls>("cert: /a\nkey: /b\n").is_err());
        assert!(yaml::from_str::<UpstreamTls>("ca: /a\n").is_err());
        // Clients cannot be verified, so the client leg has no such mode.
        assert!(yaml::from_str::<ClientTls>("mode: verify-full\n").is_err());
        assert!(yaml::from_str::<UpstreamTls>("mode: verify-ca\n").is_err());
        assert!(yaml::from_str::<UpstreamTls>("mode: allow\n").is_err());
        assert!(yaml::from_str::<UpstreamTls>("mode: require\ninsecure: true\n").is_err());
    }

    #[test]
    fn the_tls_floor_is_1_2_and_can_be_raised() {
        let tls: ClientTls = yaml::from_str("mode: disable\n").unwrap();
        assert_eq!(tls.min_version, TlsVersion::Tls12);
        let tls: ClientTls = yaml::from_str("mode: disable\nmin_version: tls1.3\n").unwrap();
        assert_eq!(tls.min_version, TlsVersion::Tls13);
        let tls: UpstreamTls = yaml::from_str("mode: verify-full\nmin_version: tls1.2\n").unwrap();
        assert_eq!(tls.min_version, TlsVersion::Tls12);
        assert!(TlsVersion::Tls12 < TlsVersion::Tls13);
        for old in ["tls1.1", "tls1.0", "ssl3", "1.2", "\"1.3\""] {
            assert!(
                yaml::from_str::<ClientTls>(&format!("mode: disable\nmin_version: {old}\n"))
                    .is_err(),
                "{old}"
            );
        }
    }

    #[test]
    fn a_client_leg_with_tls_needs_a_certificate_and_a_key() {
        assert!(client("mode: disable\n").is_empty());
        assert!(
            client("mode: require\ncert: /etc/pgsnare/server.crt\nkey: /etc/pgsnare/server.key\n")
                .is_empty()
        );
        assert!(client("mode: prefer\ncert: server.crt\nkey: server.key\n").is_empty());

        for text in [
            "mode: require\n",
            "mode: prefer\ncert: /a\n",
            "mode: require\nkey: /b\n",
        ] {
            assert_eq!(
                client(text),
                ["tls: cert and key are both required unless mode is disable"],
                "{text}"
            );
        }
        assert_eq!(
            client("mode: disable\ncert: /a\nkey: /b\n"),
            ["tls: cert and key are set, but mode is disable; remove them or choose another mode"]
        );
        assert_eq!(
            client("mode: require\ncert: \"\"\nkey: /b\n"),
            ["tls.cert: the path must not be empty"]
        );
    }

    #[test]
    fn a_backend_leg_is_consistent_with_its_mode() {
        assert!(upstream("mode: disable\n", false).is_empty());
        assert!(upstream("mode: disable\n", true).is_empty());
        assert!(upstream("mode: verify-full\n", false).is_empty());
        assert!(
            upstream(
                "mode: verify-full\nca: /etc/pgsnare/root.crt\nserver_name: db.example.com\n",
                false
            )
            .is_empty()
        );
        assert!(upstream("mode: require\nserver_name: db.example.com\n", false).is_empty());
        assert!(upstream("mode: prefer\n", false).is_empty());

        assert_eq!(
            upstream("mode: verify-full\n", true),
            ["tls: PostgreSQL does not use TLS over a Unix socket; set mode to disable"]
        );
        assert_eq!(
            upstream("mode: require\nca: /etc/pgsnare/root.crt\n", false),
            [
                "tls: ca is only used with mode verify-full; this mode does not verify the certificate"
            ]
        );
        assert_eq!(
            upstream("mode: disable\nserver_name: db.example.com\n", false),
            ["tls: server_name is set, but mode is disable; remove it or choose another mode"]
        );
        assert_eq!(
            upstream("mode: verify-full\nca: \"\"\n", false),
            ["tls.ca: the path must not be empty"]
        );
        assert!(
            yaml::from_str::<UpstreamTls>("mode: verify-full\nserver_name: \"not a host\"\n")
                .is_err()
        );
    }
}
