// SPDX-License-Identifier: Apache-2.0

//! What the session logic hands back to the runtime.

use core::time::Duration;

use crate::event::EventBody;
use crate::policy::{ActionSet, TokenId};

use super::Leg;

/// Something the session logic asks the runtime to do.
///
/// The session logic decides and the runtime acts: only the runtime owns
/// sockets and timers.
#[derive(Clone, Debug, PartialEq)]
#[non_exhaustive]
pub enum Effect {
    /// Close one connection, after the bytes queued for it have been sent.
    Close(Leg),
    /// Send this cancel request to the database on a new connection.
    ///
    /// The bytes are the complete request, built by the protocol module from
    /// the key the server issued to this session.
    Cancel {
        /// The request to send, verbatim.
        request: Vec<u8>,
    },
    /// Wait this long before sending the queued bytes to the client.
    Delay(Duration),
    /// Hand this event to the dispatcher, without waiting for it.
    Emit(Box<EventBody>),
    /// Start TLS on the client connection, as its server side, once the
    /// bytes queued for the client have been sent.
    ///
    /// The runtime answers with [`Report::ClientTlsEstablished`] when the
    /// handshake succeeds, and ends the session when it fails. Until then
    /// it hands the session no bytes from the client: everything the
    /// client sends belongs to the handshake.
    ///
    /// [`Report::ClientTlsEstablished`]: super::Report::ClientTlsEstablished
    AcceptTls {
        /// Bytes the client has already sent that are the beginning of the
        /// handshake. They are empty unless the client opened the
        /// connection with a handshake, without asking first.
        handshake: Vec<u8>,
        /// Whether the handshake must select the ALPN protocol of the
        /// protocol module. A handshake that does not is refused.
        alpn_required: bool,
    },
    /// Open the connection to the database, with TLS as configured for the
    /// listener.
    ///
    /// The runtime answers with [`Report::BackendConnected`] or
    /// [`Report::BackendUnavailable`].
    ///
    /// [`Report::BackendConnected`]: super::Report::BackendConnected
    /// [`Report::BackendUnavailable`]: super::Report::BackendUnavailable
    ConnectBackend,
    /// The database has accepted the login. The limits for clients that
    /// have not logged in, such as the time allowed for it, no longer
    /// apply to this session.
    LoginFinished,
    /// The client sent a message that runs a statement. The runtime counts
    /// it.
    QuerySeen,
    /// A honeytoken was found in a message. The runtime counts the hit and
    /// the responses to it.
    ///
    /// This is the count only. The event of a hit travels separately, as
    /// [`Effect::Emit`], because a hit can be counted without one.
    TokenHit {
        /// The token, by the id the configuration gives it.
        token_id: TokenId,
        /// Whether the session is exempt, so that the hit triggers
        /// nothing.
        exempt: bool,
        /// The responses that were carried out. Empty for an exempt hit.
        actions: ActionSet,
    },
}

/// Everything one step of the session logic produced.
///
/// The runtime sends the bytes and then carries out the effects, in order.
#[derive(Clone, Debug, Default, PartialEq)]
pub struct Output {
    /// Bytes to send to the client.
    pub to_client: Vec<u8>,
    /// Bytes to send to the database.
    pub to_server: Vec<u8>,
    /// What else the runtime must do.
    pub effects: Vec<Effect>,
}

impl Output {
    /// An empty output.
    #[must_use]
    pub const fn new() -> Self {
        Self {
            to_client: Vec::new(),
            to_server: Vec::new(),
            effects: Vec::new(),
        }
    }

    /// Whether this step produced nothing at all.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.to_client.is_empty() && self.to_server.is_empty() && self.effects.is_empty()
    }

    /// Empties the output and keeps its buffers, so it can be reused for the
    /// next step without allocating again.
    pub fn clear(&mut self) {
        self.to_client.clear();
        self.to_server.clear();
        self.effects.clear();
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_new_output_is_empty_and_clear_empties_it() {
        let mut out = Output::new();
        assert!(out.is_empty());

        out.to_client.extend_from_slice(b"abc");
        out.effects.push(Effect::Close(Leg::Client));
        out.effects.push(Effect::Delay(Duration::from_millis(5)));
        out.effects.push(Effect::AcceptTls {
            handshake: Vec::new(),
            alpn_required: false,
        });
        out.effects.push(Effect::ConnectBackend);
        out.effects.push(Effect::LoginFinished);
        assert!(!out.is_empty());

        out.clear();
        assert!(out.is_empty());
        assert_eq!(out, Output::default());
    }
}
