// SPDX-License-Identifier: Apache-2.0

//! The PostgreSQL protocol module.
//!
//! [`Postgres`] is the [`ProtocolModule`] that ships with pgsnare, and
//! [`PostgresSession`] is the logic of one session: the state machine that
//! follows a client from its first byte through the login into queries,
//! COPY and replication. This is the only part of the crate that uses
//! `pgsnare-proto`. Detection, policy and events know nothing of it.
//!
//! # What a session does
//!
//! 1. **Startup.** It reads the first packets of the client. An
//!    `SSLRequest` is answered and followed by a handshake, a
//!    `GSSENCRequest` is declined, a `CancelRequest` is passed on to the
//!    database and a `StartupMessage` begins a login. A connection may also
//!    open with a TLS handshake, which then has to select the `postgresql`
//!    ALPN protocol, as the server itself requires.
//! 2. **Login.** It asks the runtime for the connection to the database,
//!    sends the startup message and relays the login through the
//!    [`LoginStrategy`], until the server sends `AuthenticationOk`.
//! 3. **Relay.** From then on every message passes through as the bytes
//!    that arrived, in both directions.
//!
//! # What is rewritten
//!
//! Three things only, and each only when it has to be:
//!
//! - **The startup message**, when it asks for a protocol version above
//!   3.2 or carries protocol options (`_pq_.` parameters). pgsnare knows no
//!   such option, so the message is sent on as version 3.2 at most and
//!   without them. Client and server can then never agree on a format
//!   pgsnare cannot read.
//! - **`NegotiateProtocolVersion`**, to tell the client about that. If the
//!   server sends one of its own, the options pgsnare removed are added to
//!   it. If it does not, pgsnare sends one ahead of the server's first
//!   message, which is where a server puts it.
//! - **The SASL mechanism list**, when the client leg is in plaintext and
//!   the backend leg uses TLS. The server then offers mechanisms with
//!   channel binding (`SCRAM-SHA-256-PLUS`) that a client without TLS
//!   cannot use, and libpq ends the login when it sees one. They are
//!   removed from the offer.
//!
//! # Limits
//!
//! Every size is bounded before it is used. A startup packet is at most
//! 10 kB, PostgreSQL's own limit. Until the server has accepted the login,
//! a message is at most [`MAX_LOGIN_FRAME`] bytes. After that, a message
//! of up to `max_buffered_frame` bytes is held until it is complete and
//! then shown to the [`Inspector`] in one piece, and a larger one is passed
//! on in chunks as it arrives, so the memory a session needs does not
//! depend on the size of a message.
//!
//! # When something cannot be understood
//!
//! Before the server has accepted the login, the session ends, whatever
//! the policy says. After that the policy decides: with `fail_closed` the
//! session ends, and with `fail_open` it becomes a tunnel that relays
//! bytes without looking at them and raises an `inspection_bypassed`
//! event.
//!
//! # Inspection
//!
//! The session shows everything it is about to pass on to an
//! [`Inspector`], which decides whether it goes through. That is the one
//! place where detection attaches. The inspector that ships today,
//! [`PassThrough`], lets everything through.
//!
//! [`LoginStrategy`]: crate::extension::LoginStrategy
//! [`ProtocolModule`]: crate::extension::ProtocolModule

use std::sync::Arc;

use crate::extension::{LoginStrategy, ProtocolModule, ProtocolSession, TlsRequest};
use crate::session::SessionOrigin;

mod inspect;
mod messages;
mod names;
mod session;

#[cfg(test)]
mod tests;

pub use inspect::{Context, InspectionError, Inspector, InspectorFactory, PassThrough, Verdict};
pub use session::PostgresSession;

/// The name PostgreSQL uses for itself in the ALPN extension of a TLS
/// handshake.
pub const ALPN_PROTOCOL: &[u8] = b"postgresql";

/// The largest message accepted from either side until the server has
/// accepted the login: a body of 65535 bytes, which is the most PostgreSQL
/// reads from a client that has not logged in, and the header.
pub const MAX_LOGIN_FRAME: usize = 65_535 + pgsnare_proto::HEADER_LEN;

/// An `SSLRequest`, as it goes on the wire.
const SSL_REQUEST: [u8; 8] = [0, 0, 0, 8, 0x04, 0xd2, 0x16, 0x2f];

/// The PostgreSQL protocol module.
#[derive(Clone)]
pub struct Postgres {
    inspectors: Arc<dyn InspectorFactory>,
}

impl Postgres {
    /// A module whose sessions relay everything.
    #[must_use]
    pub fn new() -> Self {
        Self::with_inspectors(|_: &SessionOrigin| -> Box<dyn Inspector> { Box::new(PassThrough) })
    }

    /// A module whose sessions show what they relay to the inspectors
    /// `factory` makes, one for each session.
    #[must_use]
    pub fn with_inspectors(factory: impl InspectorFactory) -> Self {
        Self {
            inspectors: Arc::new(factory),
        }
    }

    /// Creates the logic for one accepted connection, as its own type.
    #[must_use]
    pub fn session(&self, origin: SessionOrigin, login: Arc<dyn LoginStrategy>) -> PostgresSession {
        let inspector = self.inspectors.inspector(&origin);
        PostgresSession::new(origin, login, inspector)
    }
}

impl Default for Postgres {
    fn default() -> Self {
        Self::new()
    }
}

impl core::fmt::Debug for Postgres {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("Postgres").finish_non_exhaustive()
    }
}

impl ProtocolModule for Postgres {
    fn name(&self) -> &'static str {
        "postgresql"
    }

    fn start_session(
        &self,
        origin: SessionOrigin,
        login: Arc<dyn LoginStrategy>,
    ) -> Box<dyn ProtocolSession> {
        Box::new(self.session(origin, login))
    }

    fn alpn_protocol(&self) -> Option<&'static [u8]> {
        Some(ALPN_PROTOCOL)
    }

    fn backend_tls_request(&self) -> Option<TlsRequest> {
        Some(TlsRequest {
            request: &SSL_REQUEST,
            accepted: pgsnare_proto::startup::SSL_ACCEPTED,
            refused: pgsnare_proto::startup::ENCRYPTION_REFUSED,
        })
    }
}
