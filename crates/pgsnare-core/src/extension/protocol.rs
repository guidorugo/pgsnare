// SPDX-License-Identifier: Apache-2.0

//! The protocol module: everything specific to one database protocol.

use core::fmt;
use std::sync::Arc;

use crate::policy::PolicySnapshot;
use crate::session::{Direction, Output, Report, SessionOrigin};

use super::LoginStrategy;

/// Everything that is specific to one database protocol.
///
/// A protocol module knows how the protocol frames its messages, what they
/// mean, and how a session moves from connection to login to queries. It
/// does no I/O: for each accepted connection it creates a
/// [`ProtocolSession`], which the runtime feeds with bytes.
pub trait ProtocolModule: Send + Sync + 'static {
    /// A short fixed name for logs and metrics, such as `postgresql`.
    fn name(&self) -> &'static str;

    /// Creates the logic for one accepted connection.
    ///
    /// The session uses `login` for the login phase.
    fn start_session(
        &self,
        origin: SessionOrigin,
        login: Arc<dyn LoginStrategy>,
    ) -> Box<dyn ProtocolSession>;

    /// The name this protocol uses for itself in the ALPN extension of a
    /// TLS handshake, if it has one.
    ///
    /// The runtime offers it on the backend leg and accepts it on the
    /// client leg. A session can require it for one handshake with
    /// [`Effect::AcceptTls`].
    ///
    /// [`Effect::AcceptTls`]: crate::session::Effect::AcceptTls
    fn alpn_protocol(&self) -> Option<&'static [u8]> {
        None
    }

    /// How a client of this protocol asks a server to switch a new
    /// connection to TLS, if that is settled in the clear before the
    /// handshake.
    ///
    /// The runtime uses it on every connection it opens to the database
    /// with TLS: the one of a session and the one that carries a cancel
    /// request. With `None`, the handshake starts with the first byte.
    fn backend_tls_request(&self) -> Option<TlsRequest> {
        None
    }
}

/// How a client asks a server to switch a new connection to TLS.
///
/// The client sends `request` and the server answers with exactly one
/// byte. The handshake follows `accepted` at once, so the runtime reads
/// that one byte and nothing more before it: a byte that arrives later
/// belongs to the handshake and can never be taken for an answer that was
/// sent in the clear.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct TlsRequest {
    /// The bytes that ask for TLS.
    pub request: &'static [u8],
    /// The answer of a server that goes on with a handshake.
    pub accepted: u8,
    /// The answer of a server that stays in plaintext.
    pub refused: u8,
}

/// The logic of one session: bytes in, bytes and effects out.
///
/// It never touches a socket or a clock. The runtime calls it with whatever
/// it read from either connection, and with a [`Report`] when something
/// else happened, and then carries out the [`Output`].
///
/// A session starts with the client connection only. It asks for the
/// connection to the database with [`Effect::ConnectBackend`], when it
/// knows that the client is going to log in.
///
/// [`Effect::ConnectBackend`]: crate::session::Effect::ConnectBackend
pub trait ProtocolSession: Send {
    /// Takes bytes that arrived from one side.
    ///
    /// `input` need not end at a message boundary. The session keeps what it
    /// needs of an incomplete message, within the limits of `policy`.
    /// Everything the step produces is appended to `out`.
    ///
    /// `policy` is the snapshot in force for this call. The runtime takes a
    /// fresh one for each call, so a reload takes effect at the next one.
    ///
    /// # Errors
    ///
    /// Returns an error when the session must end. The session has applied
    /// the failure policy of `policy` by then: where the policy lets a
    /// session go on without inspection, the session does so and returns
    /// `Ok`. The runtime sends what `out` holds and closes both
    /// connections.
    fn on_bytes(
        &mut self,
        from: Direction,
        input: &[u8],
        policy: &PolicySnapshot,
        out: &mut Output,
    ) -> Result<(), SessionError>;

    /// Takes a report from the runtime: the outcome of something the
    /// session asked for with an effect, or news such as the proxy shutting
    /// down. Everything the step produces is appended to `out`.
    ///
    /// The default does nothing, which suits a session that never asks for
    /// anything a report answers.
    ///
    /// # Errors
    ///
    /// Returns an error when the session must end, as
    /// [`ProtocolSession::on_bytes`] does.
    fn on_report(
        &mut self,
        report: Report,
        policy: &PolicySnapshot,
        out: &mut Output,
    ) -> Result<(), SessionError> {
        let _ = (report, policy, out);
        Ok(())
    }
}

/// A session could not go on.
///
/// The reason is a fixed text. It cannot carry anything taken from the
/// network, and so cannot leak traffic into a log.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct SessionError {
    reason: &'static str,
}

impl SessionError {
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

impl fmt::Display for SessionError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "session failed: {}", self.reason)
    }
}

impl core::error::Error for SessionError {}

#[cfg(test)]
mod tests {
    use core::net::{IpAddr, Ipv4Addr};

    use crate::event::{EventBody, EventKind, SessionId};
    use crate::extension::Relay;
    use crate::session::{Effect, Leg};

    use super::*;

    /// A protocol with no framing at all: every byte is passed on, and a
    /// byte of zero from the client ends the session.
    struct Echo;

    struct EchoSession {
        origin: SessionOrigin,
    }

    impl ProtocolModule for Echo {
        fn name(&self) -> &'static str {
            "echo"
        }

        fn start_session(
            &self,
            origin: SessionOrigin,
            _login: Arc<dyn LoginStrategy>,
        ) -> Box<dyn ProtocolSession> {
            Box::new(EchoSession { origin })
        }
    }

    impl ProtocolSession for EchoSession {
        fn on_bytes(
            &mut self,
            from: Direction,
            input: &[u8],
            policy: &PolicySnapshot,
            out: &mut Output,
        ) -> Result<(), SessionError> {
            if input.len() > policy.inspection().max_buffered_frame {
                return Err(SessionError::new("input larger than the buffer limit"));
            }
            match from {
                Direction::FromClient if input.contains(&0) => {
                    let body = EventBody::new(EventKind::InspectionBypassed, &self.origin);
                    out.effects.push(Effect::Emit(Box::new(body)));
                    out.effects.push(Effect::Close(Leg::Client));
                    out.effects.push(Effect::Close(Leg::Backend));
                }
                Direction::FromClient => out.to_server.extend_from_slice(input),
                Direction::FromServer => out.to_client.extend_from_slice(input),
            }
            Ok(())
        }
    }

    fn origin() -> SessionOrigin {
        SessionOrigin::new(
            SessionId::from_u128(7),
            IpAddr::V4(Ipv4Addr::new(192, 0, 2, 10)),
            49_152,
            false,
        )
    }

    #[test]
    fn a_module_can_be_driven_through_trait_objects() {
        let module: Arc<dyn ProtocolModule> = Arc::new(Echo);
        assert_eq!(module.name(), "echo");

        let policy = PolicySnapshot::builder().build().unwrap();
        let mut session = module.start_session(origin(), Arc::new(Relay));
        let mut out = Output::new();

        session
            .on_bytes(Direction::FromClient, b"query", &policy, &mut out)
            .unwrap();
        session
            .on_bytes(Direction::FromServer, b"rows", &policy, &mut out)
            .unwrap();
        assert_eq!(out.to_server, b"query");
        assert_eq!(out.to_client, b"rows");
        assert!(out.effects.is_empty());

        out.clear();
        session
            .on_bytes(Direction::FromClient, b"\0", &policy, &mut out)
            .unwrap();
        assert!(out.to_server.is_empty());
        assert_eq!(out.effects.len(), 3);
        assert!(matches!(
            out.effects.first(),
            Some(Effect::Emit(body)) if body.kind == EventKind::InspectionBypassed
                && body.session_id == SessionId::from_u128(7)
        ));
        assert_eq!(out.effects.get(1), Some(&Effect::Close(Leg::Client)));
        assert_eq!(out.effects.get(2), Some(&Effect::Close(Leg::Backend)));
    }

    #[test]
    fn a_module_needs_no_tls_conventions_and_a_session_may_ignore_reports() {
        assert_eq!(Echo.alpn_protocol(), None);
        assert_eq!(Echo.backend_tls_request(), None);

        let policy = PolicySnapshot::builder().build().unwrap();
        let mut session = Echo.start_session(origin(), Arc::new(Relay));
        let mut out = Output::new();
        for report in [
            Report::ClientTlsEstablished,
            Report::BackendConnected { tls: true },
            Report::BackendUnavailable,
            Report::ShuttingDown,
        ] {
            session.on_report(report, &policy, &mut out).unwrap();
        }
        assert!(out.is_empty());
    }

    #[test]
    fn a_session_error_carries_a_fixed_reason() {
        let policy = PolicySnapshot::builder()
            .inspection(crate::policy::Inspection::new(
                crate::policy::OnError::FailClosed,
                1024,
            ))
            .build()
            .unwrap();
        let mut session = Echo.start_session(origin(), Arc::new(Relay));
        let mut out = Output::new();
        let error = session
            .on_bytes(Direction::FromClient, &[1; 2048], &policy, &mut out)
            .unwrap_err();
        assert_eq!(error.reason(), "input larger than the buffer limit");
        assert_eq!(
            error.to_string(),
            "session failed: input larger than the buffer limit"
        );
        assert!(out.is_empty());
    }

    #[test]
    fn sessions_can_move_between_threads() {
        fn assert_send<T: Send + ?Sized>() {}
        assert_send::<Box<dyn ProtocolSession>>();
        assert_send::<Arc<dyn ProtocolModule>>();
        assert_send::<Arc<dyn LoginStrategy>>();
    }
}
