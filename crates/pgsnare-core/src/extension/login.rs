// SPDX-License-Identifier: Apache-2.0

//! The login strategy: how a client is authenticated to the database.

use core::fmt;

use crate::session::{Direction, SessionOrigin};

/// Decides how a client is authenticated to the database.
///
/// The protocol module frames the messages of the login phase and asks the
/// strategy, through a [`LoginExchange`], what to do with each one. A
/// strategy does no I/O and sees messages as opaque bytes that only it and
/// the protocol module understand.
pub trait LoginStrategy: Send + Sync + 'static {
    /// A short fixed name for logs and metrics, such as `relay`.
    fn name(&self) -> &'static str;

    /// Starts the login of one session.
    fn begin(&self, origin: &SessionOrigin) -> Box<dyn LoginExchange>;
}

/// One login in progress.
pub trait LoginExchange: Send {
    /// Called for every message of the login phase, in the order the
    /// messages arrived. `message` is one complete message.
    ///
    /// # Errors
    ///
    /// Returns an error when the login cannot go on. The session then ends.
    fn on_message(&mut self, from: Direction, message: &[u8]) -> Result<LoginDecision, LoginError>;
}

/// What to do with one message of the login phase.
#[derive(Clone, Debug, PartialEq, Eq)]
#[non_exhaustive]
pub enum LoginDecision {
    /// Pass the message on to the other side, unchanged.
    Forward,
    /// Hold the message back and send these bytes instead. Either part may
    /// be empty.
    Replace {
        /// Bytes for the client.
        to_client: Vec<u8>,
        /// Bytes for the database.
        to_server: Vec<u8>,
    },
}

/// A login could not go on.
///
/// The reason is a fixed text. It cannot carry anything taken from the
/// network, and so cannot leak a password into a log.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct LoginError {
    reason: &'static str,
}

impl LoginError {
    /// An error with a fixed reason.
    #[must_use]
    pub const fn new(reason: &'static str) -> Self {
        Self { reason }
    }

    /// The reason.
    #[must_use]
    pub const fn reason(&self) -> &'static str {
        self.reason
    }
}

impl fmt::Display for LoginError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "login failed: {}", self.reason)
    }
}

impl core::error::Error for LoginError {}

/// The login strategy pgsnare ships: every message of the login passes
/// through unchanged.
///
/// The client authenticates to the database itself. pgsnare never learns a
/// password and holds no database credentials.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct Relay;

impl LoginStrategy for Relay {
    fn name(&self) -> &'static str {
        "relay"
    }

    fn begin(&self, _origin: &SessionOrigin) -> Box<dyn LoginExchange> {
        Box::new(RelayExchange)
    }
}

struct RelayExchange;

impl LoginExchange for RelayExchange {
    fn on_message(
        &mut self,
        _from: Direction,
        _message: &[u8],
    ) -> Result<LoginDecision, LoginError> {
        Ok(LoginDecision::Forward)
    }
}

#[cfg(test)]
mod tests {
    use core::net::{IpAddr, Ipv4Addr};

    use crate::event::SessionId;

    use super::*;

    fn origin() -> SessionOrigin {
        SessionOrigin::new(
            SessionId::from_u128(1),
            IpAddr::V4(Ipv4Addr::new(192, 0, 2, 10)),
            49_152,
            true,
        )
    }

    #[test]
    fn relay_forwards_every_message_in_both_directions() {
        let strategy: Box<dyn LoginStrategy> = Box::new(Relay);
        assert_eq!(strategy.name(), "relay");

        let mut exchange = strategy.begin(&origin());
        for message in [&b""[..], b"R\x00\x00\x00\x08\x00\x00\x00\x00", &[0xff; 64]] {
            assert_eq!(
                exchange.on_message(Direction::FromServer, message),
                Ok(LoginDecision::Forward)
            );
            assert_eq!(
                exchange.on_message(Direction::FromClient, message),
                Ok(LoginDecision::Forward)
            );
        }
    }

    #[test]
    fn a_login_error_carries_a_fixed_reason() {
        let error = LoginError::new("the server offered no supported mechanism");
        assert_eq!(error.reason(), "the server offered no supported mechanism");
        assert_eq!(
            error.to_string(),
            "login failed: the server offered no supported mechanism"
        );
    }
}
