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
    /// Whether the client leg is encrypted.
    pub client_tls: bool,
}

impl SessionOrigin {
    /// Describes a newly accepted connection.
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
        }
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
