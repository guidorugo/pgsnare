// SPDX-License-Identifier: Apache-2.0

//! The state machine of one PostgreSQL session.

use core::fmt;
use core::mem;
use std::sync::Arc;

use pgsnare_proto::backend::{self, Authentication, BackendKeyData};
use pgsnare_proto::startup::{
    self, Classification, MAX_STARTUP_PACKET_LEN, StartupMessage, StartupPacket,
};
use pgsnare_proto::{
    Chunk, Frame, FrameError, FrameHeader, Framer, Limits, StartupError, Step, encode, frontend,
};

use crate::event::{EventBody, EventKind};
use crate::extension::{
    LoginDecision, LoginExchange, LoginStrategy, ProtocolSession, SessionError,
};
use crate::policy::{OnError, PolicySnapshot};
use crate::session::{Direction, Effect, Leg, Output, Report, SessionOrigin, TlsPolicy};

use super::MAX_LOGIN_FRAME;
use super::inspect::{Context, InspectionError, Inspector, Verdict};
use super::messages::{self, Identity, Negotiation};
use super::names::message_name;

/// The most bytes a client may have sent before the login begins without
/// any of them being passed on: the largest startup packet, and what may
/// follow it while the connection to the database is being opened.
const MAX_BEFORE_LOGIN: usize = MAX_STARTUP_PACKET_LEN.saturating_add(MAX_LOGIN_FRAME);

/// Where a session stands.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Phase {
    /// Reading the first packets of the client.
    Startup,
    /// The runtime runs a TLS handshake with the client.
    AcceptingTls,
    /// The runtime opens the connection to the database.
    Connecting,
    /// The login is being relayed.
    Login,
    /// The server has accepted the login: messages are relayed.
    Established,
    /// Inspection has been given up: bytes are relayed as they come.
    Tunnel,
    /// The session is over. Nothing more is produced.
    Closed,
}

/// The state of one direction of a session.
struct Half {
    framer: Framer,
    /// The beginning of a message that is not complete yet. Nothing of it
    /// has been passed on.
    held: Vec<u8>,
    /// How many bytes `held` must reach before the framer can go on. Zero
    /// when that is not known yet.
    need: usize,
    /// Whether the server has announced a COPY that carries data in this
    /// direction and has not ended.
    in_copy: bool,
    /// The type byte of the message that is being passed on in chunks.
    stream_tag: Option<u8>,
    /// Whether that message is passed on at all. It is not when its header
    /// was held back.
    stream_forwarded: bool,
}

impl Half {
    fn new(direction: Direction) -> Self {
        Self {
            // The limits are set anew before every message.
            framer: Framer::new(wire(direction), Limits::buffered_only(MAX_LOGIN_FRAME)),
            held: Vec::new(),
            need: 0,
            in_copy: false,
            stream_tag: None,
            stream_forwarded: false,
        }
    }
}

/// Why a message could not be handled, and which message it was.
struct Fault {
    error: SessionError,
    /// The type byte of the message, when there is one to name.
    tag: Option<u8>,
}

impl Fault {
    const fn new(reason: &'static str) -> Self {
        Self {
            error: SessionError::new(reason),
            tag: None,
        }
    }

    const fn at(mut self, tag: u8) -> Self {
        self.tag = Some(tag);
        self
    }
}

impl From<SessionError> for Fault {
    fn from(error: SessionError) -> Self {
        Self { error, tag: None }
    }
}

impl From<FrameError> for Fault {
    fn from(error: FrameError) -> Self {
        match error {
            FrameError::LengthTooSmall { tag, .. } => {
                Self::new("a message announces a length below the minimum").at(tag)
            }
            FrameError::FrameTooLarge { tag, .. } => {
                Self::new("a message is larger than the limit").at(tag)
            }
            _ => Self::new("a message could not be framed"),
        }
    }
}

impl From<InspectionError> for Fault {
    fn from(error: InspectionError) -> Self {
        Self::new(error.reason())
    }
}

fn startup_error(error: StartupError) -> SessionError {
    SessionError::new(match error {
        StartupError::InvalidLength { .. } => "a startup packet has an invalid length",
        StartupError::InvalidRequestLength { .. } => {
            "a request for encryption has an invalid length"
        }
        StartupError::InvalidCancelRequestLength { .. } => "a cancel request has an invalid length",
        StartupError::UnsupportedVersion(_) => "the client asks for an unsupported protocol",
        StartupError::MalformedParameters => "a startup message has malformed parameters",
        _ => "a startup packet could not be read",
    })
}

/// The direction as the wire-protocol crate names it.
const fn wire(direction: Direction) -> pgsnare_proto::Direction {
    match direction {
        Direction::FromClient => pgsnare_proto::Direction::FromClient,
        Direction::FromServer => pgsnare_proto::Direction::FromServer,
    }
}

const fn opposite(direction: Direction) -> Direction {
    match direction {
        Direction::FromClient => Direction::FromServer,
        Direction::FromServer => Direction::FromClient,
    }
}

/// The bytes queued for the side a message in `direction` travels to.
const fn destination(out: &mut Output, direction: Direction) -> &mut Vec<u8> {
    match direction {
        Direction::FromClient => &mut out.to_server,
        Direction::FromServer => &mut out.to_client,
    }
}

/// Makes room for `incoming` more bytes of a message that will be `need`
/// bytes long when it is complete.
///
/// The buffer grows with what has arrived, by doubling, and never beyond
/// the size of the message. A sender therefore cannot make pgsnare set
/// memory aside by announcing a large message and then sending none of it.
fn make_room(held: &mut Vec<u8>, incoming: usize, need: usize) -> Result<(), Fault> {
    let wanted = held.len().saturating_add(incoming);
    if wanted <= held.capacity() {
        return Ok(());
    }
    let doubled = held.capacity().saturating_mul(2);
    let target = wanted.max(doubled.min(need.max(wanted)));
    held.try_reserve_exact(target.saturating_sub(held.len()))
        .map_err(|_| Fault::new("no memory to hold a message"))
}

fn context<'a>(
    origin: &'a SessionOrigin,
    identity: &'a Identity,
    cancel_request: Option<&'a [u8]>,
    policy: &'a PolicySnapshot,
    in_copy: bool,
) -> Context<'a> {
    Context {
        policy,
        origin,
        db_user: identity.db_user.as_deref(),
        database: identity.database.as_deref(),
        application_name: identity.application_name.as_deref(),
        in_copy,
        cancel_request,
    }
}

/// The logic of one PostgreSQL session: bytes in, bytes and effects out.
///
/// See the [module documentation](super) for what it does.
pub struct PostgresSession {
    origin: SessionOrigin,
    strategy: Arc<dyn LoginStrategy>,
    inspector: Box<dyn Inspector>,
    phase: Phase,

    /// Whether nothing has been read yet. Only the very first byte of a
    /// connection can open a TLS handshake.
    at_first_byte: bool,
    /// Whether the client may no longer ask for TLS: it has asked, or TLS
    /// is in use.
    tls_settled: bool,
    /// Whether the client may no longer ask for GSSAPI encryption.
    gss_settled: bool,

    from_client: Half,
    from_server: Half,

    identity: Identity,
    /// The startup message for the server, kept while the runtime opens
    /// the connection.
    startup_for_server: Vec<u8>,
    /// What the client still has to be told about a capped startup
    /// message.
    negotiation: Option<Negotiation>,
    login: Option<Box<dyn LoginExchange>>,
    backend_tls: bool,
    /// The request that cancels the query of this session.
    cancel_request: Option<Vec<u8>>,
}

impl PostgresSession {
    /// The logic for one accepted connection.
    #[must_use]
    pub fn new(
        origin: SessionOrigin,
        strategy: Arc<dyn LoginStrategy>,
        inspector: Box<dyn Inspector>,
    ) -> Self {
        Self {
            origin,
            strategy,
            inspector,
            phase: Phase::Startup,
            at_first_byte: true,
            tls_settled: false,
            gss_settled: false,
            from_client: Half::new(Direction::FromClient),
            from_server: Half::new(Direction::FromServer),
            identity: Identity::default(),
            startup_for_server: Vec::new(),
            negotiation: None,
            login: None,
            backend_tls: false,
            cancel_request: None,
        }
    }

    /// The `CancelRequest` that cancels the query this session is running,
    /// built from the process id and the key the server issued. `None`
    /// until the server has sent them.
    ///
    /// The key is whatever length the server chose: 4 bytes in protocol
    /// 3.0 and up to 256 bytes in protocol 3.2.
    #[must_use]
    pub fn cancel_request(&self) -> Option<&[u8]> {
        self.cancel_request.as_deref()
    }

    /// How many bytes the session holds that it has received and not yet
    /// passed on or dropped: the beginnings of messages that are not
    /// complete.
    #[must_use]
    pub fn buffered_bytes(&self) -> usize {
        self.from_client
            .held
            .len()
            .saturating_add(self.from_server.held.len())
            .saturating_add(self.startup_for_server.len())
    }

    /// Whether the server has accepted the login and the session has not
    /// ended since.
    #[must_use]
    pub fn is_established(&self) -> bool {
        matches!(self.phase, Phase::Established | Phase::Tunnel)
    }

    /// Whether inspection has been given up for this session, which then
    /// relays bytes without looking at them.
    #[must_use]
    pub fn is_tunnel(&self) -> bool {
        self.phase == Phase::Tunnel
    }

    /// Whether the session is over and produces nothing more.
    #[must_use]
    pub fn is_closed(&self) -> bool {
        self.phase == Phase::Closed
    }

    /// Whether the server has announced a COPY that carries data in
    /// `direction` and has not ended.
    #[must_use]
    pub fn in_copy(&self, direction: Direction) -> bool {
        self.half(direction).in_copy
    }

    const fn half(&self, direction: Direction) -> &Half {
        match direction {
            Direction::FromClient => &self.from_client,
            Direction::FromServer => &self.from_server,
        }
    }

    const fn half_mut(&mut self, direction: Direction) -> &mut Half {
        match direction {
            Direction::FromClient => &mut self.from_client,
            Direction::FromServer => &mut self.from_server,
        }
    }

    /// Ends the session and lets go of everything it held.
    fn close(&mut self) {
        self.phase = Phase::Closed;
        self.release();
    }

    fn release(&mut self) {
        self.from_client.held = Vec::new();
        self.from_client.need = 0;
        self.from_server.held = Vec::new();
        self.from_server.need = 0;
        self.startup_for_server = Vec::new();
        self.negotiation = None;
        self.login = None;
    }

    // ----------------------------------------------------------------------
    // Startup: the first packets of the client
    // ----------------------------------------------------------------------

    fn startup_bytes(
        &mut self,
        input: &[u8],
        policy: &PolicySnapshot,
        out: &mut Output,
    ) -> Result<(), SessionError> {
        let mut held = mem::take(&mut self.from_client.held);
        if held.len().saturating_add(input.len()) > MAX_BEFORE_LOGIN {
            self.close();
            return Err(SessionError::new(
                "the client sent too much before logging in",
            ));
        }
        held.extend_from_slice(input);

        let mut consumed = 0usize;
        if let Err(error) = self.startup_packets(&held, &mut consumed, policy, out) {
            self.close();
            return Err(error);
        }
        // Only a session that reads on, or that is about to log in, keeps
        // what it has not read yet.
        if matches!(self.phase, Phase::Startup | Phase::Connecting) {
            held.drain(..consumed.min(held.len()));
            self.from_client.held = held;
        }
        Ok(())
    }

    fn startup_packets(
        &mut self,
        held: &[u8],
        consumed: &mut usize,
        policy: &PolicySnapshot,
        out: &mut Output,
    ) -> Result<(), SessionError> {
        while self.phase == Phase::Startup {
            let view = held.get(*consumed..).unwrap_or_default();
            let packet = if self.at_first_byte {
                match startup::classify(view).map_err(startup_error)? {
                    Classification::Incomplete => return Ok(()),
                    Classification::DirectTls => return self.direct_tls(view, out),
                    Classification::Packet(packet) => packet,
                }
            } else {
                match StartupPacket::parse(view).map_err(startup_error)? {
                    None => return Ok(()),
                    Some(packet) => packet,
                }
            };
            self.at_first_byte = false;

            let length = packet.wire_len();
            let followed = view.len() > length;
            *consumed = consumed.saturating_add(length);

            match packet {
                StartupPacket::SslRequest => {
                    if self.tls_settled {
                        return Err(SessionError::new("the client asked for TLS twice"));
                    }
                    // Whatever follows the request was sent before any
                    // handshake, so it was not encrypted and may have been
                    // put there by someone on the path.
                    if followed {
                        return Err(SessionError::new(
                            "unencrypted bytes follow the request for TLS",
                        ));
                    }
                    self.tls_settled = true;
                    if self.origin.client_tls_policy == TlsPolicy::Disabled {
                        out.to_client.push(startup::ENCRYPTION_REFUSED);
                    } else {
                        out.to_client.push(startup::SSL_ACCEPTED);
                        out.effects.push(Effect::AcceptTls {
                            handshake: Vec::new(),
                            alpn_required: false,
                        });
                        self.gss_settled = true;
                        self.phase = Phase::AcceptingTls;
                    }
                }
                StartupPacket::GssEncRequest => {
                    if self.gss_settled {
                        return Err(SessionError::new(
                            "the client asked for GSSAPI encryption twice, or inside TLS",
                        ));
                    }
                    if followed {
                        return Err(SessionError::new(
                            "unencrypted bytes follow the request for GSSAPI encryption",
                        ));
                    }
                    self.gss_settled = true;
                    out.to_client.push(startup::ENCRYPTION_REFUSED);
                }
                StartupPacket::CancelRequest(request) => {
                    // The server answers a cancel request with nothing, and
                    // so does pgsnare. The request goes on as it arrived.
                    out.effects.push(Effect::Cancel {
                        request: request.as_bytes().to_vec(),
                    });
                    out.effects.push(Effect::Close(Leg::Client));
                    self.phase = Phase::Closed;
                }
                StartupPacket::StartupMessage(message) => {
                    self.begin_login(&message, policy, out)?;
                }
            }
        }
        Ok(())
    }

    /// The connection opens with a TLS handshake.
    fn direct_tls(&mut self, handshake: &[u8], out: &mut Output) -> Result<(), SessionError> {
        if self.origin.client_tls_policy == TlsPolicy::Disabled {
            return Err(SessionError::new(
                "a TLS handshake on a listener that does not offer TLS",
            ));
        }
        out.effects.push(Effect::AcceptTls {
            handshake: handshake.to_vec(),
            alpn_required: true,
        });
        self.at_first_byte = false;
        self.tls_settled = true;
        self.gss_settled = true;
        self.phase = Phase::AcceptingTls;
        Ok(())
    }

    fn begin_login(
        &mut self,
        message: &StartupMessage<'_>,
        policy: &PolicySnapshot,
        out: &mut Output,
    ) -> Result<(), SessionError> {
        if self.origin.client_tls_policy == TlsPolicy::Required && !self.origin.client_tls {
            messages::encryption_required(message, self.origin.client_ip, &mut out.to_client)?;
            out.effects.push(Effect::Close(Leg::Client));
            self.phase = Phase::Closed;
            return Ok(());
        }

        self.identity = Identity::of(message);
        let context = context(&self.origin, &self.identity, None, policy, false);
        let verdict = self
            .inspector
            .startup(message, &context, out)
            .map_err(|error| SessionError::new(error.reason()))?;
        if verdict != Verdict::Forward {
            // There is no session without a startup message.
            self.phase = Phase::Closed;
            return Ok(());
        }

        let (bytes, negotiation) = messages::cap(message)?;
        self.startup_for_server = bytes;
        self.negotiation = negotiation;
        out.effects.push(Effect::ConnectBackend);
        self.phase = Phase::Connecting;
        Ok(())
    }

    /// Keeps what the client sends while the connection to the database is
    /// being opened. It is read when the login begins.
    fn hold_before_login(&mut self, input: &[u8]) -> Result<(), SessionError> {
        let held = self.from_client.held.len();
        if held.saturating_add(input.len()) > MAX_BEFORE_LOGIN {
            self.close();
            return Err(SessionError::new(
                "the client sent too much before logging in",
            ));
        }
        self.from_client.held.extend_from_slice(input);
        Ok(())
    }

    // ----------------------------------------------------------------------
    // Login and relay: framed messages
    // ----------------------------------------------------------------------

    /// The limits for the next message.
    fn limits(&self, policy: &PolicySnapshot) -> Limits {
        match self.phase {
            // Before the login is accepted a message is small or refused.
            Phase::Login => Limits::buffered_only(MAX_LOGIN_FRAME),
            // After it, a message is held up to the configured size and
            // passed on in chunks above it, up to what the protocol allows.
            _ => Limits::new(policy.inspection().max_buffered_frame, usize::MAX),
        }
    }

    /// Takes bytes of one direction: completes the message that was begun,
    /// handles every whole message, and keeps the beginning of the next.
    fn pump(
        &mut self,
        from: Direction,
        input: &[u8],
        policy: &PolicySnapshot,
        out: &mut Output,
    ) -> Result<(), SessionError> {
        let mut held = mem::take(&mut self.half_mut(from).held);
        let mut rest = input;
        match self.pump_units(from, &mut held, &mut rest, policy, out) {
            Ok(()) => {
                let half = self.half_mut(from);
                if held.is_empty() {
                    // An idle direction holds no memory.
                    half.held = Vec::new();
                    half.need = 0;
                } else {
                    half.held = held;
                }
                Ok(())
            }
            Err(fault) => self.fail(from, &fault, &held, rest, policy, out),
        }
    }

    /// On success, everything in `held` and `rest` has been handled, or
    /// `held` holds the beginning of a message and `rest` is empty. On a
    /// fault, `held` followed by `rest` is everything that has not been
    /// handled, beginning with the message at fault.
    fn pump_units(
        &mut self,
        from: Direction,
        held: &mut Vec<u8>,
        rest: &mut &[u8],
        policy: &PolicySnapshot,
        out: &mut Output,
    ) -> Result<(), Fault> {
        loop {
            if held.is_empty() {
                if rest.is_empty() {
                    return Ok(());
                }
                // Messages that arrived whole are handled where they are.
                // What is left is the beginning of one that did not.
                if let Some(need) = self.run(from, rest, policy, out)? {
                    make_room(held, rest.len(), need)?;
                    held.extend_from_slice(rest);
                    *rest = &[];
                    self.half_mut(from).need = need;
                }
                return Ok(());
            }

            // Complete the message that was begun.
            let need = self.half(from).need;
            let missing = need.saturating_sub(held.len());
            let (now, later) = rest
                .split_at_checked(missing.min(rest.len()))
                .unwrap_or((rest, &[]));
            make_room(held, now.len(), need)?;
            held.extend_from_slice(now);
            *rest = later;
            if held.len() < need {
                return Ok(());
            }

            let mut view = held.as_slice();
            let outcome = self.run(from, &mut view, policy, out);
            let handled = held.len().saturating_sub(view.len());
            held.drain(..handled.min(held.len()));
            match outcome? {
                None => {}
                Some(next) if next > held.len() => self.half_mut(from).need = next,
                Some(_) => return Err(Fault::new("a message could not be framed")),
            }
            if held.is_empty() && rest.is_empty() {
                return Ok(());
            }
        }
    }

    /// Handles the messages at the front of `bytes` and advances it past
    /// them.
    ///
    /// Returns `None` when `bytes` has been used up, and the number of
    /// bytes the message at its front needs when that message is not
    /// complete. On a fault, `bytes` begins with the message at fault.
    fn run(
        &mut self,
        from: Direction,
        bytes: &mut &[u8],
        policy: &PolicySnapshot,
        out: &mut Output,
    ) -> Result<Option<usize>, Fault> {
        loop {
            if !matches!(self.phase, Phase::Login | Phase::Established) {
                // The session ended with the last message. What follows it
                // is dropped.
                *bytes = &[];
                return Ok(None);
            }
            if bytes.is_empty() {
                return Ok(None);
            }
            let limits = self.limits(policy);
            let half = self.half_mut(from);
            half.framer.set_limits(limits);

            let before = *bytes;
            let step = half.framer.next(bytes)?;
            if let Step::NeedMore(need) = step {
                return Ok(Some(need));
            }
            if let Err(fault) = self.unit(from, step, policy, out) {
                *bytes = before;
                return Err(fault);
            }
        }
    }

    fn unit(
        &mut self,
        from: Direction,
        step: Step<'_>,
        policy: &PolicySnapshot,
        out: &mut Output,
    ) -> Result<(), Fault> {
        match step {
            Step::Frame(frame) => {
                let handled = if self.phase == Phase::Login {
                    self.login_frame(from, frame, out)
                } else {
                    self.relay_frame(from, frame, policy, out)
                };
                handled.map_err(|fault| fault.at(frame.tag()))
            }
            Step::StreamStart(header) => self
                .relay_stream_start(from, header, policy, out)
                .map_err(|fault| fault.at(header.tag())),
            Step::StreamChunk(chunk) => {
                let tag = self.half(from).stream_tag;
                self.relay_stream_chunk(from, chunk, policy, out)
                    .map_err(|mut fault| {
                        fault.tag = tag;
                        fault
                    })
            }
            Step::NeedMore(_) => Ok(()),
        }
    }

    /// One message of the login, in either direction.
    fn login_frame(
        &mut self,
        from: Direction,
        frame: Frame<'_>,
        out: &mut Output,
    ) -> Result<(), Fault> {
        // What passing the message on means, when it is not passed on as
        // the bytes that arrived.
        let mut rewritten: Option<Vec<u8>> = None;
        let mut accepted = false;

        if from == Direction::FromServer {
            match frame.tag() {
                backend::tag::NEGOTIATE_PROTOCOL_VERSION => {
                    if let Some(negotiation) = self.negotiation.take() {
                        let mut bytes = Vec::new();
                        negotiation.merge(frame, &mut bytes)?;
                        rewritten = Some(bytes);
                    }
                }
                backend::tag::AUTHENTICATION => {
                    let message = Authentication::from_frame(frame).map_err(|_| {
                        Fault::new("the server sent a malformed authentication message")
                    })?;
                    match message {
                        Authentication::Ok => accepted = true,
                        // A client without TLS cannot bind the login to a
                        // TLS channel, and gives up when it is offered a
                        // mechanism that does.
                        Authentication::Sasl(mechanisms)
                            if self.backend_tls && !self.origin.client_tls =>
                        {
                            rewritten = messages::without_channel_binding(mechanisms)?;
                        }
                        _ => {}
                    }
                }
                _ => {}
            }
            // A server that accepted a capped startup message without a
            // word leaves it to pgsnare to tell the client, ahead of
            // whatever the server says first.
            if let Some(negotiation) = self.negotiation.take() {
                negotiation.announce(&mut out.to_client)?;
            }
        }

        let login = self
            .login
            .as_mut()
            .ok_or(Fault::new("a login message outside a login"))?;
        let decision = login
            .on_message(from, frame.as_bytes())
            .map_err(|error| Fault::new(error.reason()))?;
        match decision {
            LoginDecision::Forward => {
                let bytes = rewritten.as_deref().unwrap_or(frame.as_bytes());
                destination(out, from).extend_from_slice(bytes);
            }
            LoginDecision::Replace {
                to_client,
                to_server,
            } => {
                out.to_client.extend_from_slice(&to_client);
                out.to_server.extend_from_slice(&to_server);
            }
        }

        if accepted {
            self.login = None;
            self.phase = Phase::Established;
            out.effects.push(Effect::LoginFinished);
        }
        Ok(())
    }

    /// Updates what the session knows from a message, before the message
    /// is shown to the inspector. `frame` is `None` for a message that is
    /// passed on in chunks.
    fn track(&mut self, from: Direction, tag: u8, frame: Option<Frame<'_>>) -> Result<(), Fault> {
        match from {
            Direction::FromServer => match tag {
                backend::tag::BACKEND_KEY_DATA => {
                    let frame = frame.ok_or(Fault::new("BackendKeyData is too large"))?;
                    let key = BackendKeyData::from_frame(frame)
                        .map_err(|_| Fault::new("the server sent a malformed BackendKeyData"))?;
                    let mut request = Vec::new();
                    encode::cancel_request(key.process_id(), key.secret_key(), &mut request)
                        .map_err(|_| Fault::new("the cancel key could not be recorded"))?;
                    self.cancel_request = Some(request);
                }
                backend::tag::COPY_IN_RESPONSE => self.set_copy(Direction::FromClient, true),
                backend::tag::COPY_OUT_RESPONSE => self.set_copy(Direction::FromServer, true),
                backend::tag::COPY_BOTH_RESPONSE => {
                    self.set_copy(Direction::FromClient, true);
                    self.set_copy(Direction::FromServer, true);
                }
                backend::tag::COPY_DONE => self.set_copy(Direction::FromServer, false),
                // An error ends a COPY in either direction, and nothing is
                // being copied when the server is ready for a query.
                backend::tag::ERROR_RESPONSE | backend::tag::READY_FOR_QUERY => {
                    self.set_copy(Direction::FromServer, false);
                    self.set_copy(Direction::FromClient, false);
                }
                _ => {}
            },
            Direction::FromClient => match tag {
                frontend::tag::COPY_DONE | frontend::tag::COPY_FAIL => {
                    self.set_copy(Direction::FromClient, false);
                }
                _ => {}
            },
        }
        Ok(())
    }

    fn set_copy(&mut self, direction: Direction, active: bool) {
        let half = self.half_mut(direction);
        if half.in_copy == active {
            return;
        }
        half.in_copy = active;
        if active {
            self.inspector.copy_started(direction);
        } else {
            self.inspector.copy_ended(direction);
        }
    }

    /// One whole message of an established session.
    fn relay_frame(
        &mut self,
        from: Direction,
        frame: Frame<'_>,
        policy: &PolicySnapshot,
        out: &mut Output,
    ) -> Result<(), Fault> {
        self.track(from, frame.tag(), Some(frame))?;
        let context = context(
            &self.origin,
            &self.identity,
            self.cancel_request.as_deref(),
            policy,
            self.half(from).in_copy,
        );
        match self.inspector.frame(frame, &context, out)? {
            Verdict::Forward => destination(out, from).extend_from_slice(frame.as_bytes()),
            Verdict::Withhold => {}
            Verdict::End => self.close(),
        }
        Ok(())
    }

    /// The header of a message that is passed on in chunks.
    fn relay_stream_start(
        &mut self,
        from: Direction,
        header: FrameHeader,
        policy: &PolicySnapshot,
        out: &mut Output,
    ) -> Result<(), Fault> {
        self.track(from, header.tag(), None)?;
        let context = context(
            &self.origin,
            &self.identity,
            self.cancel_request.as_deref(),
            policy,
            self.half(from).in_copy,
        );
        let verdict = self.inspector.stream_start(from, header, &context, out)?;
        let half = self.half_mut(from);
        half.stream_tag = Some(header.tag());
        half.stream_forwarded = verdict == Verdict::Forward;
        match verdict {
            Verdict::Forward => destination(out, from).extend_from_slice(&header.to_bytes()),
            Verdict::Withhold => {}
            Verdict::End => self.close(),
        }
        Ok(())
    }

    /// A part of the body of a message that is passed on in chunks.
    fn relay_stream_chunk(
        &mut self,
        from: Direction,
        chunk: Chunk<'_>,
        policy: &PolicySnapshot,
        out: &mut Output,
    ) -> Result<(), Fault> {
        let context = context(
            &self.origin,
            &self.identity,
            self.cancel_request.as_deref(),
            policy,
            self.half(from).in_copy,
        );
        match self.inspector.stream_chunk(from, chunk, &context, out)? {
            Verdict::Forward => {
                if self.half(from).stream_forwarded {
                    destination(out, from).extend_from_slice(chunk.data());
                }
            }
            Verdict::Withhold => {}
            Verdict::End => self.close(),
        }
        Ok(())
    }

    /// Applies the failure policy to a message that could not be handled.
    ///
    /// `held` followed by `rest` is everything of the direction `from`
    /// that has not been handled.
    fn fail(
        &mut self,
        from: Direction,
        fault: &Fault,
        held: &[u8],
        rest: &[u8],
        policy: &PolicySnapshot,
        out: &mut Output,
    ) -> Result<(), SessionError> {
        // Only a session the server has accepted may go on uninspected.
        let fail_open = matches!(policy.inspection().on_error, OnError::FailOpen);
        if self.phase != Phase::Established || !fail_open {
            self.close();
            return Err(fault.error);
        }

        // From here on bytes pass as they come. What either direction
        // still holds goes first, so that no byte is lost or reordered.
        let other = opposite(from);
        let pending = mem::take(&mut self.half_mut(other).held);
        destination(out, other).extend_from_slice(&pending);
        let to = destination(out, from);
        to.extend_from_slice(held);
        to.extend_from_slice(rest);

        let mut body = EventBody::new(EventKind::InspectionBypassed, &self.origin);
        body.direction = Some(from);
        body.message_type = fault
            .tag
            .and_then(|tag| message_name(from, tag))
            .map(Into::into);
        body.db_user.clone_from(&self.identity.db_user);
        body.database.clone_from(&self.identity.database);
        body.application_name
            .clone_from(&self.identity.application_name);
        out.effects.push(Effect::Emit(Box::new(body)));

        self.phase = Phase::Tunnel;
        self.release();
        if self.from_client.in_copy {
            self.set_copy(Direction::FromClient, false);
        }
        if self.from_server.in_copy {
            self.set_copy(Direction::FromServer, false);
        }
        Ok(())
    }

    // ----------------------------------------------------------------------
    // Reports
    // ----------------------------------------------------------------------

    /// The proxy is stopping: tells the client what the database tells a
    /// session an administrator ends, and closes both connections.
    fn farewell(&mut self, out: &mut Output) -> Result<(), SessionError> {
        // A client can read a message only once it has sent its startup
        // message, and only when everything it was sent so far ends at
        // the end of a message.
        let can_be_told = match self.phase {
            Phase::Connecting | Phase::Login | Phase::Established => {
                self.from_server.framer.is_at_frame_boundary()
            }
            Phase::Startup | Phase::AcceptingTls | Phase::Tunnel | Phase::Closed => false,
        };
        let already_closed = self.phase == Phase::Closed;
        self.close();
        if already_closed {
            return Ok(());
        }
        if can_be_told {
            messages::admin_shutdown(&mut out.to_client)?;
        }
        out.effects.push(Effect::Close(Leg::Client));
        out.effects.push(Effect::Close(Leg::Backend));
        Ok(())
    }
}

impl ProtocolSession for PostgresSession {
    fn on_bytes(
        &mut self,
        from: Direction,
        input: &[u8],
        policy: &PolicySnapshot,
        out: &mut Output,
    ) -> Result<(), SessionError> {
        match (self.phase, from) {
            (Phase::Closed, _) => Ok(()),
            (Phase::Tunnel, _) => {
                destination(out, from).extend_from_slice(input);
                Ok(())
            }
            (Phase::Login | Phase::Established, _) => self.pump(from, input, policy, out),
            (Phase::Startup, Direction::FromClient) => self.startup_bytes(input, policy, out),
            (Phase::Connecting, Direction::FromClient) => self.hold_before_login(input),
            (Phase::AcceptingTls, Direction::FromClient) => {
                self.close();
                Err(SessionError::new(
                    "bytes from the client during its TLS handshake",
                ))
            }
            (Phase::Startup | Phase::AcceptingTls | Phase::Connecting, Direction::FromServer) => {
                self.close();
                Err(SessionError::new(
                    "bytes from the database before the session asked for it",
                ))
            }
        }
    }

    fn on_report(
        &mut self,
        report: Report,
        policy: &PolicySnapshot,
        out: &mut Output,
    ) -> Result<(), SessionError> {
        match (report, self.phase) {
            (Report::ShuttingDown, _) => self.farewell(out),
            (_, Phase::Closed) => Ok(()),
            (Report::ClientTlsEstablished, Phase::AcceptingTls) => {
                self.origin.client_tls = true;
                self.phase = Phase::Startup;
                Ok(())
            }
            (Report::BackendConnected { tls }, Phase::Connecting) => {
                self.backend_tls = tls;
                out.to_server
                    .extend_from_slice(&mem::take(&mut self.startup_for_server));
                self.login = Some(self.strategy.begin(&self.origin));
                self.phase = Phase::Login;
                // What the client sent while the connection was opened.
                self.pump(Direction::FromClient, &[], policy, out)
            }
            (Report::BackendUnavailable, Phase::Connecting) => {
                self.close();
                messages::cannot_connect_now(&mut out.to_client)?;
                out.effects.push(Effect::Close(Leg::Client));
                Ok(())
            }
            _ => {
                self.close();
                Err(SessionError::new(
                    "a report that does not fit the state of the session",
                ))
            }
        }
    }
}

impl fmt::Debug for PostgresSession {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        // Nothing that came from the network is shown.
        f.debug_struct("PostgresSession")
            .field("session_id", &self.origin.session_id)
            .field("phase", &self.phase)
            .field("buffered_bytes", &self.buffered_bytes())
            .finish_non_exhaustive()
    }
}
