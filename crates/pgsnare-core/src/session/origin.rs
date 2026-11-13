// SPDX-License-Identifier: Apache-2.0

//! Where a session and its messages come from.

use core::net::IpAddr;

use serde::{Deserialize, Serialize};

use crate::event::SessionId;

/// One of the two connections of a session.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum Leg {
    /// The connection between an application and pgsnare.
    Client,
    /// The connection between pgsnare and the database.
    Backend,
}

/// The direction a message travels in.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Direction {
    /// Sent by the application.
    FromClient,
    /// Sent by the database.
    FromServer,
}

impl Direction {
    /// The connection the message arrived on.
    #[must_use]
    pub const fn source(self) -> Leg {
        match self {
            Self::FromClient => Leg::Client,
            Self::FromServer => Leg::Backend,
        }
    }

    /// The connection the message is meant for.
    #[must_use]
    pub const fn destination(self) -> Leg {
        match self {
            Self::FromClient => Leg::Backend,
            Self::FromServer => Leg::Client,
        }
    }
}

/// Whether the client leg of a listener may or must be encrypted.
///
/// The session logic needs this to answer a client that asks for TLS, and
/// to refuse one that must use TLS and does not.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Hash)]
pub enum TlsPolicy {
    /// TLS is not offered. A client that asks for it is told so.
    #[default]
    Disabled,
    /// TLS is offered, and a client may also stay in plaintext.
    Optional,
    /// TLS is required. A client that stays in plaintext is refused.
    Required,
}

/// What the runtime knows about a session when it accepts the connection.
///
/// Everything else, such as the database user, is learned later from the
/// traffic.
#[derive(Clone, Debug, PartialEq, Eq)]
#[non_exhaustive]
pub struct SessionOrigin {
    /// The identifier the runtime gave this session.
    pub session_id: SessionId,
    /// The address the client connected from, as the proxy saw it.
    pub client_ip: IpAddr,
    /// The port the client connected from.
    pub client_port: u16,
    /// Whether the client leg is encrypted. A connection is accepted in
    /// plaintext, so this starts as `false` unless the runtime ends TLS
    /// before the session logic sees the first byte. The session logic sets
    /// it when a handshake it asked for has succeeded.
    pub client_tls: bool,
    /// Whether the listener offers or requires TLS on the client leg.
    pub client_tls_policy: TlsPolicy,
}

impl SessionOrigin {
    /// Describes a newly accepted connection on a listener that does not
    /// offer TLS. Use [`SessionOrigin::with_client_tls_policy`] for one
    /// that does.
    #[must_use]
    pub const fn new(
        session_id: SessionId,
        client_ip: IpAddr,
        client_port: u16,
        client_tls: bool,
    ) -> Self {
        Self {
            session_id,
            client_ip,
            client_port,
            client_tls,
            client_tls_policy: TlsPolicy::Disabled,
        }
    }

    /// Sets whether the listener offers or requires TLS on the client leg.
    #[must_use]
    pub const fn with_client_tls_policy(mut self, policy: TlsPolicy) -> Self {
        self.client_tls_policy = policy;
        self
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_direction_names_both_ends() {
        assert_eq!(Direction::FromClient.source(), Leg::Client);
        assert_eq!(Direction::FromClient.destination(), Leg::Backend);
        assert_eq!(Direction::FromServer.source(), Leg::Backend);
        assert_eq!(Direction::FromServer.destination(), Leg::Client);
    }

    #[test]
    fn an_origin_offers_no_tls_unless_told_otherwise() {
        let origin = SessionOrigin::new(
            SessionId::from_u128(1),
            "192.0.2.10".parse().unwrap(),
            49_152,
            false,
        );
        assert_eq!(origin.client_tls_policy, TlsPolicy::Disabled);
        assert_eq!(TlsPolicy::default(), TlsPolicy::Disabled);

        let origin = origin.with_client_tls_policy(TlsPolicy::Required);
        assert_eq!(origin.client_tls_policy, TlsPolicy::Required);
        assert!(!origin.client_tls);
    }

    #[test]
    fn a_direction_serialises_in_snake_case() {
        assert_eq!(
            serde_json::to_string(&Direction::FromClient).unwrap(),
            "\"from_client\""
        );
        assert_eq!(
            serde_json::from_str::<Direction>("\"from_server\"").unwrap(),
            Direction::FromServer
        );
    }
}
