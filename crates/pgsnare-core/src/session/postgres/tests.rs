// SPDX-License-Identifier: Apache-2.0

//! Tests of the PostgreSQL session logic.

use std::net::IpAddr;
use std::sync::{Arc, Mutex};

use pgsnare_proto::startup::StartupMessage;
use pgsnare_proto::{Chunk, Frame, FrameHeader, ProtocolVersion, encode};
use proptest::prelude::*;

use crate::event::{EventKind, SessionId};
use crate::extension::{ProtocolModule, ProtocolSession, Relay, SessionError};
use crate::policy::{Inspection, OnError, PolicySnapshot};
use crate::session::{Direction, Effect, Leg, Output, Report, SessionOrigin, TlsPolicy};

use super::{
    ALPN_PROTOCOL, Context, InspectionError, Inspector, MAX_LOGIN_FRAME, Postgres, PostgresSession,
    Verdict,
};

// ---------------------------------------------------------------------------
// Messages
// ---------------------------------------------------------------------------

/// A message with a type byte, as it goes on the wire.
fn frame(tag: u8, body: &[u8]) -> Vec<u8> {
    let mut bytes = vec![tag];
    bytes.extend_from_slice(&u32::try_from(body.len() + 4).unwrap().to_be_bytes());
    bytes.extend_from_slice(body);
    bytes
}

fn startup(version: ProtocolVersion, parameters: &[(&[u8], &[u8])]) -> Vec<u8> {
    let mut bytes = Vec::new();
    encode::startup_message(version, parameters, &mut bytes).unwrap();
    bytes
}

fn plain_startup() -> Vec<u8> {
    startup(
        ProtocolVersion::V3_0,
        &[
            (b"user", b"app"),
            (b"database", b"shop"),
            (b"application_name", b"psql"),
        ],
    )
}

const SSL_REQUEST: [u8; 8] = [0, 0, 0, 8, 0x04, 0xd2, 0x16, 0x2f];
const GSSENC_REQUEST: [u8; 8] = [0, 0, 0, 8, 0x04, 0xd2, 0x16, 0x30];

fn cancel_request(process_id: i32, key: &[u8]) -> Vec<u8> {
    let mut bytes = Vec::new();
    encode::cancel_request(process_id, key, &mut bytes).unwrap();
    bytes
}

fn authentication(code: u32, rest: &[u8]) -> Vec<u8> {
    let mut body = code.to_be_bytes().to_vec();
    body.extend_from_slice(rest);
    frame(b'R', &body)
}

fn authentication_ok() -> Vec<u8> {
    authentication(0, &[])
}

fn sasl_offer(mechanisms: &[&[u8]]) -> Vec<u8> {
    let mut bytes = Vec::new();
    encode::authentication_sasl(mechanisms, &mut bytes).unwrap();
    bytes
}

fn backend_key_data(process_id: i32, key: &[u8]) -> Vec<u8> {
    let mut body = process_id.to_be_bytes().to_vec();
    body.extend_from_slice(key);
    frame(b'K', &body)
}

fn ready_for_query() -> Vec<u8> {
    frame(b'Z', b"I")
}

fn query(sql: &str) -> Vec<u8> {
    let mut body = sql.as_bytes().to_vec();
    body.push(0);
    frame(b'Q', &body)
}

fn error_response(sqlstate: &[u8]) -> Vec<u8> {
    let mut bytes = Vec::new();
    encode::error_response(
        &[(b'S', b"ERROR"), (b'C', sqlstate), (b'M', b"it failed")],
        &mut bytes,
    )
    .unwrap();
    bytes
}

fn negotiate(version: ProtocolVersion, options: &[&[u8]]) -> Vec<u8> {
    let mut bytes = Vec::new();
    encode::negotiate_protocol_version(version, options, &mut bytes).unwrap();
    bytes
}

// ---------------------------------------------------------------------------
// An inspector that records what it is shown and does as it is told
// ---------------------------------------------------------------------------

#[derive(Clone, Debug, PartialEq, Eq)]
enum Seen {
    Startup { client_tls: bool },
    Frame(Direction, u8, usize, bool),
    StreamStart(Direction, u8, u32),
    StreamChunk(Direction, usize, bool),
    CopyStarted(Direction),
    CopyEnded(Direction),
}

#[derive(Default)]
struct Script {
    seen: Vec<Seen>,
    /// What to answer for a whole message with this type byte.
    on_tag: Vec<(u8, Result<Verdict, InspectionError>)>,
    /// What to answer for the header of a message passed on in chunks.
    on_stream_start: Option<Result<Verdict, InspectionError>>,
    /// What to answer for a chunk.
    on_stream_chunk: Option<Result<Verdict, InspectionError>>,
    on_startup: Option<Result<Verdict, InspectionError>>,
    /// The cancel request the context offered with the last message.
    cancel_request: Option<Vec<u8>>,
    identity: Option<(Option<String>, Option<String>, Option<String>)>,
}

#[derive(Clone, Default)]
struct Recorder(Arc<Mutex<Script>>);

impl Recorder {
    fn script(&self) -> std::sync::MutexGuard<'_, Script> {
        self.0.lock().unwrap()
    }

    fn seen(&self) -> Vec<Seen> {
        self.script().seen.clone()
    }

    fn answer(&self, tag: u8, verdict: Result<Verdict, InspectionError>) {
        self.script().on_tag.push((tag, verdict));
    }
}

fn from_wire(direction: pgsnare_proto::Direction) -> Direction {
    match direction {
        pgsnare_proto::Direction::FromClient => Direction::FromClient,
        pgsnare_proto::Direction::FromServer => Direction::FromServer,
    }
}

impl Inspector for Recorder {
    fn startup(
        &mut self,
        _message: &StartupMessage<'_>,
        context: &Context<'_>,
        _out: &mut Output,
    ) -> Result<Verdict, InspectionError> {
        let mut script = self.script();
        script.seen.push(Seen::Startup {
            client_tls: context.origin.client_tls,
        });
        script.identity = Some((
            context.db_user.map(str::to_owned),
            context.database.map(str::to_owned),
            context.application_name.map(str::to_owned),
        ));
        script.on_startup.unwrap_or(Ok(Verdict::Forward))
    }

    fn frame(
        &mut self,
        frame: Frame<'_>,
        context: &Context<'_>,
        out: &mut Output,
    ) -> Result<Verdict, InspectionError> {
        let mut script = self.script();
        script.seen.push(Seen::Frame(
            from_wire(frame.direction()),
            frame.tag(),
            frame.wire_len(),
            context.in_copy,
        ));
        script.cancel_request = context.cancel_request.map(<[u8]>::to_vec);
        let verdict = script
            .on_tag
            .iter()
            .find(|(tag, _)| *tag == frame.tag())
            .map_or(Ok(Verdict::Forward), |(_, verdict)| *verdict);
        if verdict == Ok(Verdict::End) {
            // What an inspector that ends a session leaves behind.
            out.to_client.extend_from_slice(b"<farewell>");
            out.effects.push(Effect::Close(Leg::Client));
            out.effects.push(Effect::Close(Leg::Backend));
        }
        verdict
    }

    fn stream_start(
        &mut self,
        direction: Direction,
        header: FrameHeader,
        _context: &Context<'_>,
        _out: &mut Output,
    ) -> Result<Verdict, InspectionError> {
        let mut script = self.script();
        script.seen.push(Seen::StreamStart(
            direction,
            header.tag(),
            header.body_len(),
        ));
        script.on_stream_start.unwrap_or(Ok(Verdict::Forward))
    }

    fn stream_chunk(
        &mut self,
        direction: Direction,
        chunk: Chunk<'_>,
        _context: &Context<'_>,
        _out: &mut Output,
    ) -> Result<Verdict, InspectionError> {
        let mut script = self.script();
        script.seen.push(Seen::StreamChunk(
            direction,
            chunk.data().len(),
            chunk.is_last(),
        ));
        script.on_stream_chunk.unwrap_or(Ok(Verdict::Forward))
    }

    fn copy_started(&mut self, direction: Direction) {
        self.script().seen.push(Seen::CopyStarted(direction));
    }

    fn copy_ended(&mut self, direction: Direction) {
        self.script().seen.push(Seen::CopyEnded(direction));
    }
}

// ---------------------------------------------------------------------------
// A session and everything it produced
// ---------------------------------------------------------------------------

struct Harness {
    session: PostgresSession,
    policy: PolicySnapshot,
    recorder: Recorder,
    to_client: Vec<u8>,
    to_server: Vec<u8>,
    effects: Vec<Effect>,
}

fn policy(on_error: OnError, max_buffered_frame: usize) -> PolicySnapshot {
    PolicySnapshot::builder()
        .inspection(Inspection::new(on_error, max_buffered_frame))
        .build()
        .unwrap()
}

fn origin(tls: TlsPolicy) -> SessionOrigin {
    SessionOrigin::new(
        SessionId::from_u128(0x6a),
        "192.0.2.10".parse::<IpAddr>().unwrap(),
        49_152,
        false,
    )
    .with_client_tls_policy(tls)
}

impl Harness {
    fn new(tls: TlsPolicy) -> Self {
        let recorder = Recorder::default();
        let for_sessions = recorder.clone();
        let module = Postgres::with_inspectors(move |_: &SessionOrigin| -> Box<dyn Inspector> {
            Box::new(for_sessions.clone())
        });
        Self {
            session: module.session(origin(tls), Arc::new(Relay)),
            policy: policy(OnError::FailClosed, 1024 * 1024),
            recorder,
            to_client: Vec::new(),
            to_server: Vec::new(),
            effects: Vec::new(),
        }
    }

    fn with_policy(mut self, on_error: OnError, max_buffered_frame: usize) -> Self {
        self.policy = policy(on_error, max_buffered_frame);
        self
    }

    fn collect(&mut self, mut out: Output) {
        self.to_client.append(&mut out.to_client);
        self.to_server.append(&mut out.to_server);
        self.effects.append(&mut out.effects);
    }

    fn bytes(&mut self, from: Direction, input: &[u8]) -> Result<(), SessionError> {
        let mut out = Output::new();
        let result = self.session.on_bytes(from, input, &self.policy, &mut out);
        self.collect(out);
        result
    }

    fn client(&mut self, input: &[u8]) -> Result<(), SessionError> {
        self.bytes(Direction::FromClient, input)
    }

    fn server(&mut self, input: &[u8]) -> Result<(), SessionError> {
        self.bytes(Direction::FromServer, input)
    }

    fn report(&mut self, report: Report) -> Result<(), SessionError> {
        let mut out = Output::new();
        let result = self.session.on_report(report, &self.policy, &mut out);
        self.collect(out);
        result
    }

    /// Everything queued for the client since the last call.
    fn take_to_client(&mut self) -> Vec<u8> {
        std::mem::take(&mut self.to_client)
    }

    fn take_to_server(&mut self) -> Vec<u8> {
        std::mem::take(&mut self.to_server)
    }

    fn take_effects(&mut self) -> Vec<Effect> {
        std::mem::take(&mut self.effects)
    }

    /// Takes a session through a plaintext login. Everything produced on
    /// the way is discarded.
    fn established(tls: TlsPolicy) -> Self {
        let mut harness = Self::new(tls);
        harness.log_in();
        harness
    }

    fn log_in(&mut self) {
        self.client(&plain_startup()).unwrap();
        self.report(Report::BackendConnected { tls: false })
            .unwrap();
        self.server(&authentication_ok()).unwrap();
        self.server(&ready_for_query()).unwrap();
        assert!(self.session.is_established());
        self.take_to_client();
        self.take_to_server();
        self.take_effects();
        self.recorder.script().seen.clear();
    }
}

fn emitted(effects: &[Effect]) -> Vec<&crate::event::EventBody> {
    effects
        .iter()
        .filter_map(|effect| match effect {
            Effect::Emit(body) => Some(&**body),
            _ => None,
        })
        .collect()
}

// ---------------------------------------------------------------------------
// The module
// ---------------------------------------------------------------------------

#[test]
fn the_module_describes_how_postgresql_uses_tls() {
    let module = Postgres::new();
    assert_eq!(module.name(), "postgresql");
    assert_eq!(module.alpn_protocol(), Some(&b"postgresql"[..]));
    assert_eq!(ALPN_PROTOCOL, b"postgresql");

    let request = module.backend_tls_request().unwrap();
    let mut expected = Vec::new();
    encode::ssl_request(&mut expected).unwrap();
    assert_eq!(request.request, expected);
    assert_eq!(request.accepted, b'S');
    assert_eq!(request.refused, b'N');
    assert_eq!(SSL_REQUEST.as_slice(), expected);

    // The session of the module is reachable through the trait as well.
    let mut session = module.start_session(origin(TlsPolicy::Disabled), Arc::new(Relay));
    let mut out = Output::new();
    session
        .on_bytes(
            Direction::FromClient,
            &plain_startup(),
            &policy(OnError::FailClosed, 1024),
            &mut out,
        )
        .unwrap();
    assert_eq!(out.effects, [Effect::ConnectBackend]);
    assert_eq!(format!("{module:?}"), "Postgres { .. }");
}

// ---------------------------------------------------------------------------
// Startup
// ---------------------------------------------------------------------------

#[test]
fn a_plaintext_session_is_relayed_as_the_bytes_that_arrived() {
    let mut harness = Harness::new(TlsPolicy::Disabled);

    // Nothing reaches the database before the runtime has connected.
    let startup = plain_startup();
    harness.client(&startup).unwrap();
    assert_eq!(harness.take_effects(), [Effect::ConnectBackend]);
    assert!(harness.take_to_server().is_empty());
    assert!(harness.take_to_client().is_empty());

    harness
        .report(Report::BackendConnected { tls: false })
        .unwrap();
    assert_eq!(harness.take_to_server(), startup);

    // The login passes in both directions.
    let offer = sasl_offer(&[b"SCRAM-SHA-256"]);
    harness.server(&offer).unwrap();
    assert_eq!(harness.take_to_client(), offer);
    let response = frame(b'p', b"SCRAM-SHA-256\0\0\0\0\x05n,,n=");
    harness.client(&response).unwrap();
    assert_eq!(harness.take_to_server(), response);
    assert!(!harness.session.is_established());
    assert!(harness.take_effects().is_empty());

    let mut welcome = authentication_ok();
    welcome.extend_from_slice(&frame(b'S', b"server_version\x0018.6\0"));
    welcome.extend_from_slice(&backend_key_data(4242, &[1, 2, 3, 4]));
    welcome.extend_from_slice(&ready_for_query());
    harness.server(&welcome).unwrap();
    assert_eq!(harness.take_to_client(), welcome);
    assert_eq!(harness.take_effects(), [Effect::LoginFinished]);
    assert!(harness.session.is_established());

    // Queries and results.
    let ask = query("SELECT 1");
    harness.client(&ask).unwrap();
    assert_eq!(harness.take_to_server(), ask);
    let mut answer = frame(b'T', b"\0\0");
    answer.extend_from_slice(&frame(b'D', b"\0\x01\0\0\0\x011"));
    answer.extend_from_slice(&frame(b'C', b"SELECT 1\0"));
    answer.extend_from_slice(&ready_for_query());
    harness.server(&answer).unwrap();
    assert_eq!(harness.take_to_client(), answer);

    // A message type nobody has heard of passes like any other.
    let unknown = frame(b'~', b"whatever this is");
    harness.server(&unknown).unwrap();
    harness.client(&unknown).unwrap();
    assert_eq!(harness.take_to_client(), unknown);
    assert_eq!(harness.take_to_server(), unknown);

    assert!(harness.take_effects().is_empty());
    assert_eq!(harness.session.buffered_bytes(), 0);

    // The inspector was shown the startup message and every message after
    // the login, and none of the login itself.
    let seen = harness.recorder.seen();
    assert_eq!(seen[0], Seen::Startup { client_tls: false });
    assert!(!seen.contains(&Seen::Frame(
        Direction::FromClient,
        b'p',
        response.len(),
        false
    )));
    assert!(seen.contains(&Seen::Frame(Direction::FromClient, b'Q', ask.len(), false)));
    assert_eq!(
        harness.recorder.script().identity,
        Some((
            Some("app".to_owned()),
            Some("shop".to_owned()),
            Some("psql".to_owned())
        ))
    );
}

#[test]
fn a_request_for_tls_is_declined_on_a_listener_without_tls() {
    let mut harness = Harness::new(TlsPolicy::Disabled);
    harness.client(&SSL_REQUEST).unwrap();
    assert_eq!(harness.take_to_client(), b"N");
    assert!(harness.take_effects().is_empty());

    // The client goes on in plaintext.
    harness.client(&plain_startup()).unwrap();
    assert_eq!(harness.take_effects(), [Effect::ConnectBackend]);
}

#[test]
fn a_request_for_tls_is_followed_by_a_handshake() {
    for tls in [TlsPolicy::Optional, TlsPolicy::Required] {
        let mut harness = Harness::new(tls);
        harness.client(&SSL_REQUEST).unwrap();
        assert_eq!(harness.take_to_client(), b"S");
        assert_eq!(
            harness.take_effects(),
            [Effect::AcceptTls {
                handshake: Vec::new(),
                alpn_required: false
            }]
        );

        harness.report(Report::ClientTlsEstablished).unwrap();
        harness.client(&plain_startup()).unwrap();
        assert_eq!(harness.take_effects(), [Effect::ConnectBackend]);
        // The session knows that the client leg is encrypted now.
        assert_eq!(
            harness.recorder.seen(),
            [Seen::Startup { client_tls: true }]
        );
    }
}

#[test]
fn bytes_that_follow_a_request_for_tls_are_refused() {
    // In the same read as the request.
    for tls in [
        TlsPolicy::Disabled,
        TlsPolicy::Optional,
        TlsPolicy::Required,
    ] {
        let mut harness = Harness::new(tls);
        let mut bytes = SSL_REQUEST.to_vec();
        bytes.extend_from_slice(&plain_startup());
        let error = harness.client(&bytes).unwrap_err();
        assert_eq!(
            error.reason(),
            "unencrypted bytes follow the request for TLS"
        );
        // Nothing was answered and no handshake was asked for.
        assert!(harness.take_to_client().is_empty());
        assert!(harness.take_effects().is_empty());
        assert!(harness.session.is_closed());
    }

    // One byte is enough.
    let mut harness = Harness::new(TlsPolicy::Optional);
    let mut bytes = SSL_REQUEST.to_vec();
    bytes.push(0x16);
    assert!(harness.client(&bytes).is_err());

    // After the request, while the handshake is still to come: the runtime
    // gives everything to the handshake, so bytes handed to the session
    // would be bytes read outside it.
    let mut harness = Harness::new(TlsPolicy::Optional);
    harness.client(&SSL_REQUEST).unwrap();
    let error = harness.client(&plain_startup()).unwrap_err();
    assert_eq!(
        error.reason(),
        "bytes from the client during its TLS handshake"
    );

    // The same holds for a request for GSSAPI encryption.
    let mut harness = Harness::new(TlsPolicy::Disabled);
    let mut bytes = GSSENC_REQUEST.to_vec();
    bytes.extend_from_slice(&plain_startup());
    let error = harness.client(&bytes).unwrap_err();
    assert_eq!(
        error.reason(),
        "unencrypted bytes follow the request for GSSAPI encryption"
    );
}

#[test]
fn a_request_for_gssapi_encryption_is_declined() {
    for tls in [
        TlsPolicy::Disabled,
        TlsPolicy::Optional,
        TlsPolicy::Required,
    ] {
        let mut harness = Harness::new(tls);
        harness.client(&GSSENC_REQUEST).unwrap();
        assert_eq!(harness.take_to_client(), b"N");
        assert!(harness.take_effects().is_empty());

        // A client then asks for TLS on the same connection, as libpq does.
        harness.client(&SSL_REQUEST).unwrap();
        let expected: &[u8] = if tls == TlsPolicy::Disabled {
            b"N"
        } else {
            b"S"
        };
        assert_eq!(harness.take_to_client(), expected);
    }
}

#[test]
fn each_request_for_encryption_is_answered_once() {
    // TLS declined, GSSAPI declined, then neither again.
    let mut harness = Harness::new(TlsPolicy::Disabled);
    harness.client(&SSL_REQUEST).unwrap();
    harness.client(&GSSENC_REQUEST).unwrap();
    assert_eq!(harness.take_to_client(), b"NN");
    assert_eq!(
        harness.client(&SSL_REQUEST).unwrap_err().reason(),
        "the client asked for TLS twice"
    );

    let mut harness = Harness::new(TlsPolicy::Disabled);
    harness.client(&GSSENC_REQUEST).unwrap();
    assert!(harness.client(&GSSENC_REQUEST).is_err());

    // Inside TLS neither request is answered.
    for request in [SSL_REQUEST, GSSENC_REQUEST] {
        let mut harness = Harness::new(TlsPolicy::Optional);
        harness.client(&SSL_REQUEST).unwrap();
        harness.report(Report::ClientTlsEstablished).unwrap();
        harness.take_to_client();
        assert!(harness.client(&request).is_err());
        assert!(harness.take_to_client().is_empty());
    }
}

#[test]
fn a_connection_that_opens_with_a_handshake_must_negotiate_the_protocol() {
    // The first flight of a TLS handshake, in two reads.
    let hello = [0x16, 0x03, 0x01, 0x00, 0x05, 1, 2, 3, 4, 5];
    for tls in [TlsPolicy::Optional, TlsPolicy::Required] {
        let mut harness = Harness::new(tls);
        harness.client(&hello[..3]).unwrap();
        assert_eq!(
            harness.take_effects(),
            [Effect::AcceptTls {
                handshake: hello[..3].to_vec(),
                alpn_required: true
            }]
        );
        // Nothing is answered in the clear.
        assert!(harness.take_to_client().is_empty());

        harness.report(Report::ClientTlsEstablished).unwrap();
        harness.client(&plain_startup()).unwrap();
        assert_eq!(harness.take_effects(), [Effect::ConnectBackend]);
    }

    let mut harness = Harness::new(TlsPolicy::Disabled);
    let error = harness.client(&hello).unwrap_err();
    assert_eq!(
        error.reason(),
        "a TLS handshake on a listener that does not offer TLS"
    );

    // Only the very first byte of a connection can open a handshake.
    let mut harness = Harness::new(TlsPolicy::Optional);
    harness.client(&GSSENC_REQUEST).unwrap();
    assert_eq!(
        harness.client(&hello).unwrap_err().reason(),
        "a startup packet has an invalid length"
    );
}

#[test]
fn a_cancel_request_goes_to_the_database_as_it_arrived() {
    for key_len in [4usize, 32, 256] {
        let key: Vec<u8> = (0..key_len).map(|byte| byte as u8).collect();
        let request = cancel_request(-7, &key);
        // In plaintext, even where TLS is required: older clients send it
        // that way, and the server takes it that way.
        for tls in [TlsPolicy::Disabled, TlsPolicy::Required] {
            let mut harness = Harness::new(tls);
            // In pieces, to prove nothing is acted on early.
            let (first, second) = request.split_at(9);
            harness.client(first).unwrap();
            assert!(harness.take_effects().is_empty());
            harness.client(second).unwrap();
            assert_eq!(
                harness.take_effects(),
                [
                    Effect::Cancel {
                        request: request.clone()
                    },
                    Effect::Close(Leg::Client)
                ]
            );
            // The server answers a cancel request with nothing.
            assert!(harness.take_to_client().is_empty());
            assert!(harness.take_to_server().is_empty());
            assert!(harness.session.is_closed());
        }
    }

    // Inside TLS as well.
    let mut harness = Harness::new(TlsPolicy::Required);
    harness.client(&SSL_REQUEST).unwrap();
    harness.report(Report::ClientTlsEstablished).unwrap();
    harness.take_effects();
    let request = cancel_request(1, &[9; 32]);
    harness.client(&request).unwrap();
    assert_eq!(
        harness.take_effects(),
        [Effect::Cancel { request }, Effect::Close(Leg::Client)]
    );

    // A key that is too short or too long is not a cancel request.
    for key_len in [0usize, 257] {
        let mut packet = u32::try_from(12 + key_len).unwrap().to_be_bytes().to_vec();
        packet.extend_from_slice(&80_877_102u32.to_be_bytes());
        packet.extend_from_slice(&1i32.to_be_bytes());
        packet.extend_from_slice(&vec![7; key_len]);
        let mut harness = Harness::new(TlsPolicy::Disabled);
        assert_eq!(
            harness.client(&packet).unwrap_err().reason(),
            "a cancel request has an invalid length"
        );
        assert!(harness.take_effects().is_empty());
    }
}

#[test]
fn a_listener_that_requires_tls_refuses_a_plaintext_login() {
    let mut harness = Harness::new(TlsPolicy::Required);
    harness.client(&plain_startup()).unwrap();
    let answer = harness.take_to_client();
    assert_eq!(answer[0], b'E');
    let text = String::from_utf8_lossy(&answer);
    assert!(text.contains("C28000\0"), "{text}");
    assert!(
        text.contains(
            "Mno pg_hba.conf entry for host \"192.0.2.10\", user \"app\", database \"shop\", \
             no encryption\0"
        ),
        "{text}"
    );
    assert_eq!(harness.take_effects(), [Effect::Close(Leg::Client)]);
    assert!(harness.take_to_server().is_empty());
    // The database is never contacted, and the inspector is not asked.
    assert!(harness.recorder.seen().is_empty());

    // After a declined request for TLS on such a listener nothing changes.
    let mut harness = Harness::new(TlsPolicy::Required);
    harness.client(&GSSENC_REQUEST).unwrap();
    harness.take_to_client();
    harness.client(&plain_startup()).unwrap();
    assert_eq!(harness.take_effects(), [Effect::Close(Leg::Client)]);
}

#[test]
fn a_startup_phase_that_cannot_be_parsed_ends_the_connection_whatever_the_policy() {
    let cases: [(&[u8], &str); 5] = [
        (
            &[0, 0, 0, 7, 0, 3, 0, 0],
            "a startup packet has an invalid length",
        ),
        (
            &[0xff, 0xff, 0xff, 0xff],
            "a startup packet has an invalid length",
        ),
        (
            &[0, 0, 0, 9, 0x04, 0xd2, 0x16, 0x2f, 0],
            "a request for encryption has an invalid length",
        ),
        (
            &[0, 0, 0, 8, 0, 2, 0, 0],
            "the client asks for an unsupported protocol",
        ),
        (
            &[0, 0, 0, 10, 0, 3, 0, 0, b'u', b's'],
            "a startup message has malformed parameters",
        ),
    ];
    for on_error in [OnError::FailClosed, OnError::FailOpen] {
        for (bytes, reason) in cases {
            let mut harness = Harness::new(TlsPolicy::Optional).with_policy(on_error, 1024);
            assert_eq!(harness.client(bytes).unwrap_err().reason(), reason);
            assert!(harness.take_to_client().is_empty());
            assert!(harness.take_to_server().is_empty());
            assert!(harness.take_effects().is_empty());
            assert!(harness.session.is_closed());
            // A session that has ended stays silent.
            harness.client(&plain_startup()).unwrap();
            assert!(harness.take_effects().is_empty());
        }
    }
}

#[test]
fn a_startup_packet_may_arrive_in_any_number_of_pieces() {
    let startup = plain_startup();
    for size in [1usize, 2, 7, 8, 9, 1000] {
        let mut harness = Harness::new(TlsPolicy::Disabled);
        for piece in startup.chunks(size) {
            harness.client(piece).unwrap();
        }
        assert_eq!(harness.take_effects(), [Effect::ConnectBackend], "{size}");
        harness
            .report(Report::BackendConnected { tls: false })
            .unwrap();
        assert_eq!(harness.take_to_server(), startup);
    }
}

#[test]
fn what_a_client_sends_before_the_login_is_bounded() {
    // A packet of the largest size is accepted.
    let value = vec![b'x'; 10_004 - 8 - b"user\0".len() - 2];
    let largest = startup(ProtocolVersion::V3_0, &[(b"user", &value)]);
    assert_eq!(largest.len(), 10_004);
    let mut harness = Harness::new(TlsPolicy::Disabled);
    harness.client(&largest).unwrap();
    assert_eq!(harness.take_effects(), [Effect::ConnectBackend]);

    // A larger one is refused from its first four bytes.
    let mut harness = Harness::new(TlsPolicy::Disabled);
    assert!(harness.client(&10_005u32.to_be_bytes()).is_err());

    // While the database is being connected to, the client may send a
    // little more. It is kept, not passed on, and bounded.
    let mut harness = Harness::new(TlsPolicy::Disabled);
    harness.client(&plain_startup()).unwrap();
    let early = frame(b'p', b"early\0");
    harness.client(&early).unwrap();
    assert!(harness.take_to_server().is_empty());
    assert_eq!(
        harness.session.buffered_bytes(),
        plain_startup().len() + early.len()
    );
    harness
        .report(Report::BackendConnected { tls: false })
        .unwrap();
    let mut expected = plain_startup();
    expected.extend_from_slice(&early);
    assert_eq!(harness.take_to_server(), expected);

    // More than one message of a login is not kept, however it arrives:
    // after the startup message, with it, or all at once.
    let mut harness = Harness::new(TlsPolicy::Disabled);
    harness.client(&plain_startup()).unwrap();
    harness.client(&vec![0u8; MAX_LOGIN_FRAME]).unwrap();
    assert_eq!(
        harness.client(&[0]).unwrap_err().reason(),
        "the client sent too much before logging in"
    );
    assert_eq!(harness.session.buffered_bytes(), 0);

    let mut harness = Harness::new(TlsPolicy::Disabled);
    let mut together = plain_startup();
    together.extend_from_slice(&vec![0u8; MAX_LOGIN_FRAME + 1]);
    assert!(harness.client(&together).is_err());
    // The database is not asked for on behalf of a session that has ended.
    assert!(harness.take_effects().is_empty());
    assert_eq!(harness.session.buffered_bytes(), 0);

    let mut harness = Harness::new(TlsPolicy::Disabled);
    assert!(
        harness
            .client(&vec![0u8; 10_004 + MAX_LOGIN_FRAME + 1])
            .is_err()
    );
    assert_eq!(harness.session.buffered_bytes(), 0);
}

// ---------------------------------------------------------------------------
// Protocol version
// ---------------------------------------------------------------------------

#[test]
fn a_capped_startup_message_is_announced_when_the_server_says_nothing() {
    let mut harness = Harness::new(TlsPolicy::Disabled);
    harness
        .client(&startup(
            ProtocolVersion::new(3, 99),
            &[(b"user", b"app"), (b"_pq_.fancy", b"on")],
        ))
        .unwrap();
    harness
        .report(Report::BackendConnected { tls: false })
        .unwrap();
    assert_eq!(
        harness.take_to_server(),
        startup(ProtocolVersion::V3_2, &[(b"user", b"app")])
    );
    assert!(harness.take_to_client().is_empty());

    // A server that speaks 3.2 goes straight to the login. The client is
    // told first, as a server tells it.
    let offer = sasl_offer(&[b"SCRAM-SHA-256"]);
    harness.server(&offer).unwrap();
    let mut expected = negotiate(ProtocolVersion::V3_2, &[b"_pq_.fancy"]);
    expected.extend_from_slice(&offer);
    assert_eq!(harness.take_to_client(), expected);

    // Once only.
    harness.server(&authentication_ok()).unwrap();
    assert_eq!(harness.take_to_client(), authentication_ok());
}

#[test]
fn a_capped_startup_message_is_merged_into_the_answer_of_the_server() {
    let mut harness = Harness::new(TlsPolicy::Disabled);
    harness
        .client(&startup(
            ProtocolVersion::new(3, 99),
            &[(b"_pq_.fancy", b"on"), (b"user", b"app")],
        ))
        .unwrap();
    harness
        .report(Report::BackendConnected { tls: false })
        .unwrap();
    harness.take_to_server();

    // An older server answers 3.2 with its own NegotiateProtocolVersion.
    let mut first = negotiate(ProtocolVersion::V3_0, &[]);
    first.extend_from_slice(&authentication(3, &[]));
    harness.server(&first).unwrap();
    let mut expected = negotiate(ProtocolVersion::V3_0, &[b"_pq_.fancy"]);
    expected.extend_from_slice(&authentication(3, &[]));
    assert_eq!(harness.take_to_client(), expected);
}

#[test]
fn an_error_is_also_preceded_by_the_announcement() {
    let mut harness = Harness::new(TlsPolicy::Disabled);
    harness
        .client(&startup(ProtocolVersion::new(3, 4), &[(b"user", b"app")]))
        .unwrap();
    harness
        .report(Report::BackendConnected { tls: false })
        .unwrap();
    let refused = error_response(b"28P01");
    harness.server(&refused).unwrap();
    let mut expected = negotiate(ProtocolVersion::V3_2, &[]);
    expected.extend_from_slice(&refused);
    assert_eq!(harness.take_to_client(), expected);
}

#[test]
fn the_negotiation_of_an_untouched_startup_message_passes_unchanged() {
    // libpq 18 asks an older server for 3.2 and is told 3.0.
    let mut harness = Harness::new(TlsPolicy::Disabled);
    let asked = startup(ProtocolVersion::V3_2, &[(b"user", b"app")]);
    harness.client(&asked).unwrap();
    harness
        .report(Report::BackendConnected { tls: false })
        .unwrap();
    assert_eq!(harness.take_to_server(), asked);
    let answer = negotiate(ProtocolVersion::V3_0, &[]);
    harness.server(&answer).unwrap();
    assert_eq!(harness.take_to_client(), answer);
}

// ---------------------------------------------------------------------------
// Login
// ---------------------------------------------------------------------------

/// Takes a session to the point where the server makes its SASL offer and
/// returns what the client is shown.
fn offer_seen_by_client(client_tls: bool, backend_tls: bool, offer: &[u8]) -> Vec<u8> {
    let mut harness = Harness::new(TlsPolicy::Optional);
    if client_tls {
        harness.client(&SSL_REQUEST).unwrap();
        harness.report(Report::ClientTlsEstablished).unwrap();
        harness.take_to_client();
    }
    harness.client(&plain_startup()).unwrap();
    harness
        .report(Report::BackendConnected { tls: backend_tls })
        .unwrap();
    harness.server(offer).unwrap();
    harness.take_to_client()
}

#[test]
fn channel_binding_is_removed_only_between_a_plaintext_client_and_a_tls_backend() {
    let with_binding = sasl_offer(&[b"SCRAM-SHA-256-PLUS", b"SCRAM-SHA-256"]);
    let without = sasl_offer(&[b"SCRAM-SHA-256"]);

    // Client leg in plaintext, backend leg with TLS: removed.
    assert_eq!(offer_seen_by_client(false, true, &with_binding), without);
    // Every other combination: the offer passes as it arrived.
    assert_eq!(
        offer_seen_by_client(true, true, &with_binding),
        with_binding
    );
    assert_eq!(
        offer_seen_by_client(true, false, &with_binding),
        with_binding
    );
    assert_eq!(
        offer_seen_by_client(false, false, &with_binding),
        with_binding
    );
    // An offer without channel binding is never written again.
    for (client_tls, backend_tls) in [(false, true), (true, true), (true, false), (false, false)] {
        assert_eq!(
            offer_seen_by_client(client_tls, backend_tls, &without),
            without
        );
    }
}

#[test]
fn every_other_message_of_the_login_passes_unchanged() {
    let messages = [
        authentication(3, &[]),
        authentication(5, &[1, 2, 3, 4]),
        authentication(11, b"r=nonce,s=salt,i=4096"),
        authentication(12, b"v=signature"),
        authentication(7, &[]),
        authentication(8, &[0xde, 0xad]),
        authentication(99, b"a method of the future"),
        frame(b'N', b"SNOTICE\0\0"),
        error_response(b"28P01"),
    ];
    for client_tls in [false, true] {
        for backend_tls in [false, true] {
            for message in &messages {
                assert_eq!(
                    &offer_seen_by_client(client_tls, backend_tls, message),
                    message
                );
            }
        }
    }
}

#[test]
fn a_login_that_cannot_be_followed_ends_the_session_whatever_the_policy() {
    let malformed: [(Vec<u8>, &str); 4] = [
        // An authentication message without its code.
        (
            frame(b'R', &[0, 0]),
            "the server sent a malformed authentication message",
        ),
        // AuthenticationOk with something after it.
        (
            authentication(0, &[1]),
            "the server sent a malformed authentication message",
        ),
        // A length below the minimum.
        (
            vec![b'R', 0, 0, 0, 3],
            "a message announces a length below the minimum",
        ),
        // A message larger than anything a login needs.
        (
            {
                let mut header = vec![b'R'];
                header.extend_from_slice(&u32::try_from(MAX_LOGIN_FRAME).unwrap().to_be_bytes());
                header
            },
            "a message is larger than the limit",
        ),
    ];
    for on_error in [OnError::FailClosed, OnError::FailOpen] {
        for (message, reason) in &malformed {
            let mut harness = Harness::new(TlsPolicy::Disabled).with_policy(on_error, 1024 * 1024);
            harness.client(&plain_startup()).unwrap();
            harness
                .report(Report::BackendConnected { tls: false })
                .unwrap();
            harness.take_effects();
            assert_eq!(harness.server(message).unwrap_err().reason(), *reason);
            assert!(harness.take_to_client().is_empty());
            assert!(harness.take_effects().is_empty());
            assert!(harness.session.is_closed());
            assert!(!harness.session.is_tunnel());
        }

        // The client is held to the same size before it has logged in.
        let mut harness = Harness::new(TlsPolicy::Disabled).with_policy(on_error, 1024 * 1024);
        harness.client(&plain_startup()).unwrap();
        harness
            .report(Report::BackendConnected { tls: false })
            .unwrap();
        harness.take_to_server();
        let mut oversized = vec![b'p'];
        oversized.extend_from_slice(&u32::try_from(MAX_LOGIN_FRAME).unwrap().to_be_bytes());
        assert_eq!(
            harness.client(&oversized).unwrap_err().reason(),
            "a message is larger than the limit"
        );
        assert!(harness.take_to_server().is_empty());
    }

    // The largest message a login may contain does pass.
    let mut harness = Harness::new(TlsPolicy::Disabled);
    harness.client(&plain_startup()).unwrap();
    harness
        .report(Report::BackendConnected { tls: false })
        .unwrap();
    harness.take_to_server();
    let largest = frame(b'p', &vec![7; 65_535]);
    assert_eq!(largest.len(), MAX_LOGIN_FRAME);
    harness.client(&largest).unwrap();
    assert_eq!(harness.take_to_server(), largest);
}

#[test]
fn the_database_must_not_speak_before_it_is_asked() {
    let mut harness = Harness::new(TlsPolicy::Disabled);
    assert_eq!(
        harness.server(&authentication_ok()).unwrap_err().reason(),
        "bytes from the database before the session asked for it"
    );

    let mut harness = Harness::new(TlsPolicy::Disabled);
    harness.client(&plain_startup()).unwrap();
    assert!(harness.server(&authentication_ok()).is_err());
    assert!(harness.session.is_closed());
}

#[test]
fn a_database_that_cannot_be_reached_is_reported_to_the_client() {
    let mut harness = Harness::new(TlsPolicy::Disabled);
    harness.client(&plain_startup()).unwrap();
    harness.take_effects();
    harness.report(Report::BackendUnavailable).unwrap();
    let answer = harness.take_to_client();
    let text = String::from_utf8_lossy(&answer);
    assert_eq!(answer[0], b'E');
    assert!(text.contains("SFATAL\0"), "{text}");
    assert!(text.contains("C57P03\0"), "{text}");
    assert_eq!(harness.take_effects(), [Effect::Close(Leg::Client)]);
    assert!(harness.take_to_server().is_empty());
    assert!(harness.session.is_closed());
}

#[test]
fn a_report_that_does_not_fit_ends_the_session() {
    let unexpected = [
        Report::ClientTlsEstablished,
        Report::BackendConnected { tls: true },
        Report::BackendUnavailable,
    ];
    for report in unexpected {
        // Nothing was asked for yet.
        let mut harness = Harness::new(TlsPolicy::Optional);
        assert_eq!(
            harness.report(report).unwrap_err().reason(),
            "a report that does not fit the state of the session"
        );
        assert!(harness.session.is_closed());

        // An established session asked for nothing either.
        let mut harness = Harness::established(TlsPolicy::Optional);
        assert!(harness.report(report).is_err());

        // A session that has ended ignores what still comes in.
        let mut harness = Harness::new(TlsPolicy::Optional);
        harness.client(&cancel_request(1, &[0; 4])).unwrap();
        harness.take_effects();
        harness.report(report).unwrap();
        assert!(harness.take_effects().is_empty());
    }
}

// ---------------------------------------------------------------------------
// The cancel key
// ---------------------------------------------------------------------------

#[test]
fn the_cancel_key_is_recorded_whatever_its_length() {
    for key_len in [4usize, 5, 32, 255, 256] {
        let key: Vec<u8> = (0..key_len).map(|byte| (byte % 251) as u8).collect();
        let mut harness = Harness::new(TlsPolicy::Disabled);
        harness.client(&plain_startup()).unwrap();
        harness
            .report(Report::BackendConnected { tls: false })
            .unwrap();
        assert_eq!(harness.session.cancel_request(), None);
        harness.server(&authentication_ok()).unwrap();
        let message = backend_key_data(31_337, &key);
        harness.server(&message).unwrap();
        // The message itself passes unchanged.
        assert!(harness.take_to_client().ends_with(&message));
        assert_eq!(
            harness.session.cancel_request(),
            Some(cancel_request(31_337, &key).as_slice()),
            "{key_len}"
        );

        // The inspector is offered the request from the next message on.
        harness.server(&ready_for_query()).unwrap();
        assert_eq!(
            harness.recorder.script().cancel_request,
            Some(cancel_request(31_337, &key))
        );
    }
}

#[test]
fn a_cancel_key_of_an_impossible_length_is_an_inspection_error() {
    for key_len in [0usize, 3, 257, 2000] {
        let message = backend_key_data(1, &vec![7; key_len]);

        let mut harness = Harness::established(TlsPolicy::Disabled);
        let error = harness.server(&message).unwrap_err();
        assert!(
            [
                "the server sent a malformed BackendKeyData",
                "BackendKeyData is too large"
            ]
            .contains(&error.reason()),
            "{}",
            error.reason()
        );
        assert_eq!(harness.session.cancel_request(), None);
        assert!(harness.take_to_client().is_empty());

        // With fail_open the message passes, unread.
        let mut harness =
            Harness::established(TlsPolicy::Disabled).with_policy(OnError::FailOpen, 1024);
        harness.server(&message).unwrap();
        assert_eq!(harness.take_to_client(), message);
        assert!(harness.session.is_tunnel());
        assert_eq!(harness.session.cancel_request(), None);
    }
}

// ---------------------------------------------------------------------------
// COPY
// ---------------------------------------------------------------------------

#[test]
fn the_start_and_the_end_of_a_copy_are_known_in_each_direction() {
    use Direction::{FromClient, FromServer};
    let copy_data = frame(b'd', b"1\talpha\n");
    let copy_done = frame(b'c', b"");
    let response = |tag: u8| frame(tag, &[0, 0, 0]);

    // COPY ... TO STDOUT: the server sends the data.
    let mut harness = Harness::established(TlsPolicy::Disabled);
    harness.server(&response(b'H')).unwrap();
    assert!(harness.session.in_copy(FromServer));
    assert!(!harness.session.in_copy(FromClient));
    harness.server(&copy_data).unwrap();
    harness.server(&copy_done).unwrap();
    assert!(!harness.session.in_copy(FromServer));
    assert_eq!(
        harness.recorder.seen(),
        [
            Seen::CopyStarted(FromServer),
            // The response itself still belongs to what came before.
            Seen::Frame(FromServer, b'H', 8, true),
            Seen::Frame(FromServer, b'd', copy_data.len(), true),
            Seen::CopyEnded(FromServer),
            Seen::Frame(FromServer, b'c', 5, false),
        ]
    );

    // COPY ... FROM STDIN: the client sends the data and ends it.
    for end in [frame(b'c', b""), frame(b'f', b"changed my mind\0")] {
        let mut harness = Harness::established(TlsPolicy::Disabled);
        harness.server(&response(b'G')).unwrap();
        assert!(harness.session.in_copy(FromClient));
        assert!(!harness.session.in_copy(FromServer));
        harness.client(&copy_data).unwrap();
        harness.client(&copy_data).unwrap();
        harness.client(&end).unwrap();
        assert!(!harness.session.in_copy(FromClient));
        let seen = harness.recorder.seen();
        assert_eq!(seen[0], Seen::CopyStarted(FromClient));
        assert_eq!(
            seen[2..],
            [
                Seen::Frame(FromClient, b'd', copy_data.len(), true),
                Seen::Frame(FromClient, b'd', copy_data.len(), true),
                Seen::CopyEnded(FromClient),
                Seen::Frame(FromClient, end[0], end.len(), false),
            ]
        );
    }

    // The server ends a COPY of either direction with an error.
    for start in *b"GHW" {
        let mut harness = Harness::established(TlsPolicy::Disabled);
        harness.server(&response(start)).unwrap();
        harness.server(&error_response(b"22P02")).unwrap();
        assert!(!harness.session.in_copy(FromClient));
        assert!(!harness.session.in_copy(FromServer));
        // What the client had already sent arrives after the end, and is
        // shown as outside a COPY.
        harness.recorder.script().seen.clear();
        harness.client(&copy_data).unwrap();
        assert_eq!(
            harness.recorder.seen(),
            [Seen::Frame(FromClient, b'd', copy_data.len(), false)]
        );
    }

    // Replication: both sides send data, and each ends its own half.
    let mut harness = Harness::established(TlsPolicy::Disabled);
    harness.server(&response(b'W')).unwrap();
    assert!(harness.session.in_copy(FromClient));
    assert!(harness.session.in_copy(FromServer));
    harness.server(&copy_data).unwrap();
    harness.client(&copy_data).unwrap();
    harness.client(&copy_done).unwrap();
    assert!(!harness.session.in_copy(FromClient));
    assert!(harness.session.in_copy(FromServer));
    harness.server(&copy_done).unwrap();
    assert!(!harness.session.in_copy(FromServer));

    // ReadyForQuery ends whatever was left open.
    let mut harness = Harness::established(TlsPolicy::Disabled);
    harness.server(&response(b'W')).unwrap();
    harness.server(&ready_for_query()).unwrap();
    assert!(!harness.session.in_copy(FromClient));
    assert!(!harness.session.in_copy(FromServer));

    // Every byte went through unchanged all along.
    let mut expected = response(b'W');
    expected.extend_from_slice(&ready_for_query());
    assert_eq!(harness.take_to_client(), expected);
}

// ---------------------------------------------------------------------------
// Buffering and streaming
// ---------------------------------------------------------------------------

#[test]
fn a_message_within_the_limit_is_complete_before_any_byte_of_it_is_passed_on() {
    let mut harness =
        Harness::established(TlsPolicy::Disabled).with_policy(OnError::FailClosed, 4096);
    // Exactly at the limit, header included.
    let row = frame(b'D', &vec![b'x'; 4096 - 5]);
    assert_eq!(row.len(), 4096);

    let (last, head) = row.split_last().unwrap();
    for piece in head.chunks(97) {
        harness.server(piece).unwrap();
        assert!(harness.to_client.is_empty());
    }
    assert_eq!(harness.session.buffered_bytes(), row.len() - 1);
    assert!(harness.recorder.seen().is_empty());

    harness.server(&[*last]).unwrap();
    assert_eq!(harness.take_to_client(), row);
    assert_eq!(harness.session.buffered_bytes(), 0);
    assert_eq!(
        harness.recorder.seen(),
        [Seen::Frame(Direction::FromServer, b'D', 4096, false)]
    );
}

#[test]
fn a_message_above_the_limit_is_passed_on_in_chunks_and_never_held() {
    for direction in [Direction::FromServer, Direction::FromClient] {
        let mut harness =
            Harness::established(TlsPolicy::Disabled).with_policy(OnError::FailClosed, 4096);
        // One byte more than the limit, then a megabyte.
        for body_len in [4096 - 5 + 1, 1024 * 1024] {
            let body: Vec<u8> = (0..body_len).map(|index| (index % 251) as u8).collect();
            let large = frame(b'D', &body);
            // A small message before and after, in the same reads.
            let mut stream = frame(b'1', b"");
            stream.extend_from_slice(&large);
            stream.extend_from_slice(&frame(b'2', b""));

            let mut passed = Vec::new();
            let mut most_held = 0;
            for piece in stream.chunks(1500) {
                harness.bytes(direction, piece).unwrap();
                most_held = most_held.max(harness.session.buffered_bytes());
                passed.append(match direction {
                    Direction::FromServer => &mut harness.to_client,
                    Direction::FromClient => &mut harness.to_server,
                });
            }
            assert_eq!(passed, stream);
            // Never more than the beginning of a header.
            assert!(most_held < 5, "{most_held}");

            let seen = harness.recorder.seen();
            harness.recorder.script().seen.clear();
            assert_eq!(seen[0], Seen::Frame(direction, b'1', 5, false));
            assert_eq!(
                seen[1],
                Seen::StreamStart(direction, b'D', u32::try_from(body_len).unwrap())
            );
            let chunks: Vec<(usize, bool)> = seen
                .iter()
                .filter_map(|seen| match seen {
                    Seen::StreamChunk(_, len, last) => Some((*len, *last)),
                    _ => None,
                })
                .collect();
            assert_eq!(chunks.iter().map(|(len, _)| len).sum::<usize>(), body_len);
            // Only the last chunk says that it is the last.
            let (last, others) = chunks.split_last().unwrap();
            assert!(last.1);
            assert!(others.iter().all(|(_, last)| !last));
            assert_eq!(seen.last(), Some(&Seen::Frame(direction, b'2', 5, false)));
        }
    }
}

#[test]
fn a_new_limit_applies_to_a_message_that_is_already_held() {
    let mut harness =
        Harness::established(TlsPolicy::Disabled).with_policy(OnError::FailClosed, 1024 * 1024);
    let row = frame(b'D', &vec![b'x'; 10_000]);
    harness.server(&row[..6000]).unwrap();
    assert_eq!(harness.session.buffered_bytes(), 6000);
    assert!(harness.to_client.is_empty());

    // The limit shrinks below the size of the message. The message is
    // completed all the same and then passed on in chunks.
    harness.policy = policy(OnError::FailClosed, 1024);
    harness.server(&row[6000..]).unwrap();
    assert_eq!(harness.take_to_client(), row);
    assert_eq!(harness.session.buffered_bytes(), 0);
    let seen = harness.recorder.seen();
    assert_eq!(
        seen[0],
        Seen::StreamStart(Direction::FromServer, b'D', 10_000)
    );
    assert_eq!(
        seen[1],
        Seen::StreamChunk(Direction::FromServer, 10_000, true)
    );
}

#[test]
fn a_length_no_server_would_send_is_refused_without_buffering() {
    // Above what the protocol allows.
    let mut harness = Harness::established(TlsPolicy::Disabled);
    let error = harness.server(&[b'D', 0x80, 0, 0, 0, 1, 2, 3]).unwrap_err();
    assert_eq!(error.reason(), "a message is larger than the limit");
    assert_eq!(harness.session.buffered_bytes(), 0);
    assert!(harness.take_to_client().is_empty());

    // The largest length the protocol allows is passed on as it comes.
    let mut harness = Harness::established(TlsPolicy::Disabled);
    let mut huge = vec![b'D', 0x7f, 0xff, 0xff, 0xff];
    huge.extend_from_slice(&[9; 100]);
    harness.server(&huge).unwrap();
    assert_eq!(harness.take_to_client(), huge);
    assert_eq!(harness.session.buffered_bytes(), 0);
}

// ---------------------------------------------------------------------------
// The failure policy
// ---------------------------------------------------------------------------

#[test]
fn with_fail_closed_an_inspection_error_ends_the_session() {
    // A message that cannot be framed.
    let mut harness = Harness::established(TlsPolicy::Disabled);
    let mut bytes = query("SELECT 1");
    bytes.extend_from_slice(&[b'Q', 0, 0, 0, 2, 0xff]);
    let error = harness.client(&bytes).unwrap_err();
    assert_eq!(
        error.reason(),
        "a message announces a length below the minimum"
    );
    // What came before it had been passed on. Nothing of it or after it is.
    assert_eq!(harness.take_to_server(), query("SELECT 1"));
    assert!(harness.take_effects().is_empty());
    assert!(harness.session.is_closed());
    assert!(!harness.session.is_established());

    // An inspector that fails.
    let mut harness = Harness::established(TlsPolicy::Disabled);
    harness
        .recorder
        .answer(b'D', Err(InspectionError::new("the scanner broke")));
    let error = harness.server(&frame(b'D', b"\0\0")).unwrap_err();
    assert_eq!(error.reason(), "the scanner broke");
    assert_eq!(error.to_string(), "session failed: the scanner broke");
    assert!(harness.take_to_client().is_empty());
    assert!(emitted(&harness.take_effects()).is_empty());

    // Afterwards the session is silent.
    harness.server(&ready_for_query()).unwrap();
    harness.client(&query("SELECT 2")).unwrap();
    assert!(harness.take_to_client().is_empty());
    assert!(harness.take_to_server().is_empty());
}

#[test]
fn with_fail_open_the_session_becomes_a_tunnel_and_says_so_once() {
    let mut harness =
        Harness::established(TlsPolicy::Disabled).with_policy(OnError::FailOpen, 4096);

    // The server is halfway through a message when the client breaks the
    // framing of its own direction.
    let row = frame(b'D', &[b'r'; 100]);
    harness.server(&row[..40]).unwrap();
    assert!(harness.to_client.is_empty());

    let mut bytes = query("SELECT 1");
    let broken = [b'Q', 0, 0, 0, 2, 0xff, 0xfe];
    bytes.extend_from_slice(&broken);
    harness.client(&bytes).unwrap();

    // Every byte of both directions goes through, in order.
    assert_eq!(harness.take_to_server(), bytes);
    assert_eq!(harness.take_to_client(), &row[..40]);
    assert!(harness.session.is_tunnel());
    assert!(harness.session.is_established());
    assert_eq!(harness.session.buffered_bytes(), 0);

    // One event says what happened and where, and nothing of the traffic.
    let effects = harness.take_effects();
    assert_eq!(effects.len(), 1);
    let events = emitted(&effects);
    let event = events[0];
    assert_eq!(event.kind, EventKind::InspectionBypassed);
    assert_eq!(event.session_id, SessionId::from_u128(0x6a));
    assert_eq!(event.direction, Some(Direction::FromClient));
    assert_eq!(event.message_type.as_deref(), Some("Query"));
    assert_eq!(event.db_user.as_deref(), Some("app"));
    assert_eq!(event.database.as_deref(), Some("shop"));
    assert_eq!(event.application_name.as_deref(), Some("psql"));
    assert!(!event.tls);

    // From here on bytes pass as they come, framed or not, and the
    // inspector sees none of them.
    harness.recorder.script().seen.clear();
    harness.server(&row[40..]).unwrap();
    harness.client(b"\xff\xff not a message").unwrap();
    harness.server(&[b'K', 0, 0]).unwrap();
    assert_eq!(harness.take_to_server(), b"\xff\xff not a message");
    let mut expected = row[40..].to_vec();
    expected.extend_from_slice(&[b'K', 0, 0]);
    assert_eq!(harness.take_to_client(), expected);
    assert!(harness.take_effects().is_empty());
    assert!(harness.recorder.seen().is_empty());
}

#[test]
fn with_fail_open_a_failing_inspector_is_bypassed_from_the_message_it_failed_on() {
    let mut harness =
        Harness::established(TlsPolicy::Disabled).with_policy(OnError::FailOpen, 4096);
    harness
        .recorder
        .answer(b'D', Err(InspectionError::new("the scanner broke")));

    let mut bytes = frame(b'T', b"\0\0");
    let row = frame(b'D', b"\0\x01\0\0\0\x011");
    bytes.extend_from_slice(&row);
    bytes.extend_from_slice(&ready_for_query());
    // The row arrives split, so that it is completed from what was held.
    let cut = bytes.len() - ready_for_query().len() - 3;
    harness.server(&bytes[..cut]).unwrap();
    harness.server(&bytes[cut..]).unwrap();

    assert_eq!(harness.take_to_client(), bytes);
    assert!(harness.session.is_tunnel());
    let effects = harness.take_effects();
    let events = emitted(&effects);
    assert_eq!(events.len(), 1);
    assert_eq!(events[0].direction, Some(Direction::FromServer));
    assert_eq!(events[0].message_type.as_deref(), Some("DataRow"));

    // The same for a message that was being passed on in chunks.
    let mut harness =
        Harness::established(TlsPolicy::Disabled).with_policy(OnError::FailOpen, 1024);
    harness.recorder.script().on_stream_chunk = Some(Err(InspectionError::new("chunk")));
    let large = frame(b'd', &vec![b'c'; 5000]);
    harness.server(&large[..2000]).unwrap();
    harness.server(&large[2000..]).unwrap();
    assert_eq!(harness.take_to_client(), large);
    let effects = harness.take_effects();
    assert_eq!(
        emitted(&effects)[0].message_type.as_deref(),
        Some("CopyData")
    );
}

#[test]
fn a_copy_ends_for_the_inspector_when_inspection_is_given_up() {
    let mut harness =
        Harness::established(TlsPolicy::Disabled).with_policy(OnError::FailOpen, 4096);
    harness.server(&frame(b'W', &[0, 0, 0])).unwrap();
    harness.recorder.script().seen.clear();
    harness.client(&[b'd', 0, 0, 0, 0]).unwrap();
    assert!(harness.session.is_tunnel());
    let seen = harness.recorder.seen();
    assert!(seen.contains(&Seen::CopyEnded(Direction::FromClient)));
    assert!(seen.contains(&Seen::CopyEnded(Direction::FromServer)));
}

// ---------------------------------------------------------------------------
// What an inspector can decide
// ---------------------------------------------------------------------------

#[test]
fn a_message_can_be_held_back_and_the_session_goes_on() {
    let mut harness = Harness::established(TlsPolicy::Disabled);
    harness.recorder.answer(b'D', Ok(Verdict::Withhold));
    // Held back or not, the session reads what it needs from a message.
    harness.recorder.answer(b'K', Ok(Verdict::Withhold));

    let mut bytes = frame(b'T', b"\0\0");
    bytes.extend_from_slice(&frame(b'D', b"\0\x01\0\0\0\x011"));
    bytes.extend_from_slice(&backend_key_data(5, &[1, 2, 3, 4]));
    bytes.extend_from_slice(&frame(b'C', b"SELECT 1\0"));
    harness.server(&bytes).unwrap();

    let mut expected = frame(b'T', b"\0\0");
    expected.extend_from_slice(&frame(b'C', b"SELECT 1\0"));
    assert_eq!(harness.take_to_client(), expected);
    assert_eq!(
        harness.session.cancel_request(),
        Some(cancel_request(5, &[1, 2, 3, 4]).as_slice())
    );
    assert!(harness.take_effects().is_empty());
}

#[test]
fn a_session_can_be_ended_in_the_middle_of_a_read() {
    let mut harness = Harness::established(TlsPolicy::Disabled);
    harness.recorder.answer(b'D', Ok(Verdict::End));

    let mut bytes = frame(b'T', b"\0\0");
    bytes.extend_from_slice(&frame(b'D', b"\0\x01\0\0\0\x011"));
    bytes.extend_from_slice(&frame(b'D', b"\0\x01\0\0\0\x012"));
    bytes.extend_from_slice(&ready_for_query());
    harness.server(&bytes).unwrap();

    // What came before goes out, then what the inspector left, and
    // nothing of what followed.
    let mut expected = frame(b'T', b"\0\0");
    expected.extend_from_slice(b"<farewell>");
    assert_eq!(harness.take_to_client(), expected);
    assert_eq!(
        harness.take_effects(),
        [Effect::Close(Leg::Client), Effect::Close(Leg::Backend)]
    );
    assert!(harness.session.is_closed());
    // The inspector was not shown the second row.
    assert_eq!(
        harness
            .recorder
            .seen()
            .iter()
            .filter(|seen| matches!(seen, Seen::Frame(_, b'D', _, _)))
            .count(),
        1
    );

    harness.client(&query("SELECT 2")).unwrap();
    harness.server(&ready_for_query()).unwrap();
    assert!(harness.take_to_server().is_empty());
    assert!(harness.take_to_client().is_empty());
}

#[test]
fn a_large_message_whose_header_is_held_back_is_held_back_whole() {
    let mut harness =
        Harness::established(TlsPolicy::Disabled).with_policy(OnError::FailClosed, 1024);
    harness.recorder.script().on_stream_start = Some(Ok(Verdict::Withhold));
    let mut bytes = frame(b'D', &vec![b'x'; 5000]);
    bytes.extend_from_slice(&frame(b'C', b"SELECT 1\0"));
    for piece in bytes.chunks(700) {
        harness.server(piece).unwrap();
    }
    assert_eq!(harness.take_to_client(), frame(b'C', b"SELECT 1\0"));

    // A chunk can be held back on its own, which the inspector answers for.
    let mut harness =
        Harness::established(TlsPolicy::Disabled).with_policy(OnError::FailClosed, 1024);
    harness.recorder.script().on_stream_chunk = Some(Ok(Verdict::Withhold));
    harness.server(&frame(b'D', &vec![b'x'; 5000])).unwrap();
    assert_eq!(harness.take_to_client(), [b'D', 0, 0, 0x13, 0x8c]);
}

#[test]
fn the_startup_message_can_be_refused() {
    for verdict in [Verdict::Withhold, Verdict::End] {
        let mut harness = Harness::new(TlsPolicy::Disabled);
        harness.recorder.script().on_startup = Some(Ok(verdict));
        harness.client(&plain_startup()).unwrap();
        // The database is never asked for.
        assert!(harness.take_effects().is_empty());
        assert!(harness.session.is_closed());
    }

    // A failure at this point ends the session even with fail_open.
    let mut harness = Harness::new(TlsPolicy::Disabled).with_policy(OnError::FailOpen, 1024);
    harness.recorder.script().on_startup = Some(Err(InspectionError::new("no scanner")));
    assert_eq!(
        harness.client(&plain_startup()).unwrap_err().reason(),
        "no scanner"
    );
    assert!(harness.take_effects().is_empty());
    assert!(harness.session.is_closed());
}

// ---------------------------------------------------------------------------
// Shutdown
// ---------------------------------------------------------------------------

const ADMIN_SHUTDOWN: &[u8] =
    b"E\0\0\0\x4fSFATAL\0VFATAL\0C57P01\0Mterminating connection due to administrator command\0\0";

#[test]
fn a_session_that_is_shut_down_is_told_what_the_database_would_tell_it() {
    let closes = [Effect::Close(Leg::Client), Effect::Close(Leg::Backend)];

    // Established and between messages.
    let mut harness = Harness::established(TlsPolicy::Disabled);
    harness.report(Report::ShuttingDown).unwrap();
    assert_eq!(harness.take_to_client(), ADMIN_SHUTDOWN);
    assert_eq!(harness.take_effects(), closes);
    assert!(harness.session.is_closed());
    // Once.
    harness.report(Report::ShuttingDown).unwrap();
    assert!(harness.take_to_client().is_empty());
    assert!(harness.take_effects().is_empty());

    // With the beginning of a message held: the client has seen none of
    // it, so the error still fits.
    let mut harness = Harness::established(TlsPolicy::Disabled);
    harness.server(&frame(b'D', &[1; 50])[..20]).unwrap();
    harness.report(Report::ShuttingDown).unwrap();
    assert_eq!(harness.take_to_client(), ADMIN_SHUTDOWN);

    // During the login, and while the database is being connected to.
    let mut harness = Harness::new(TlsPolicy::Disabled);
    harness.client(&plain_startup()).unwrap();
    harness.take_effects();
    harness.report(Report::ShuttingDown).unwrap();
    assert_eq!(harness.take_to_client(), ADMIN_SHUTDOWN);
    assert_eq!(harness.take_effects(), closes);
}

#[test]
fn a_session_that_cannot_be_told_is_closed_without_a_word() {
    let closes = [Effect::Close(Leg::Client), Effect::Close(Leg::Backend)];

    // In the middle of a message that is being passed on in chunks.
    let mut harness =
        Harness::established(TlsPolicy::Disabled).with_policy(OnError::FailClosed, 1024);
    harness
        .server(&frame(b'D', &vec![1; 5000])[..3000])
        .unwrap();
    harness.take_to_client();
    harness.report(Report::ShuttingDown).unwrap();
    assert!(harness.take_to_client().is_empty());
    assert_eq!(harness.take_effects(), closes);

    // Before the startup message: the client may be about to start TLS.
    let mut harness = Harness::new(TlsPolicy::Optional);
    harness.report(Report::ShuttingDown).unwrap();
    assert!(harness.take_to_client().is_empty());
    assert_eq!(harness.take_effects(), closes);

    let mut harness = Harness::new(TlsPolicy::Optional);
    harness.client(&SSL_REQUEST).unwrap();
    harness.take_to_client();
    harness.take_effects();
    harness.report(Report::ShuttingDown).unwrap();
    assert!(harness.take_to_client().is_empty());
    assert_eq!(harness.take_effects(), closes);

    // A tunnel: pgsnare no longer knows where a message ends.
    let mut harness =
        Harness::established(TlsPolicy::Disabled).with_policy(OnError::FailOpen, 1024);
    harness.client(&[b'Q', 0, 0, 0, 0]).unwrap();
    harness.take_effects();
    harness.report(Report::ShuttingDown).unwrap();
    assert!(harness.take_to_client().is_empty());
    assert_eq!(harness.take_effects(), closes);
}

#[test]
fn the_admin_shutdown_error_is_well_formed() {
    let mut expected = Vec::new();
    encode::error_response(
        &[
            (b'S', b"FATAL"),
            (b'V', b"FATAL"),
            (b'C', b"57P01"),
            (b'M', b"terminating connection due to administrator command"),
        ],
        &mut expected,
    )
    .unwrap();
    assert_eq!(ADMIN_SHUTDOWN, expected);
}

// ---------------------------------------------------------------------------
// Nothing depends on how the bytes are cut
// ---------------------------------------------------------------------------

/// A whole session, as each side sends it.
fn scripted_session() -> (Vec<u8>, Vec<u8>) {
    let mut client = startup(
        ProtocolVersion::V3_2,
        &[(b"user", b"app"), (b"database", b"shop")],
    );
    client.extend_from_slice(&frame(b'p', b"SCRAM-SHA-256\0\0\0\0\x05n,,n="));
    client.extend_from_slice(&query("COPY t FROM STDIN"));
    client.extend_from_slice(&frame(b'd', &[b'c'; 300]));
    client.extend_from_slice(&frame(b'c', b""));
    client.extend_from_slice(&query(&"x".repeat(3000)));
    client.extend_from_slice(&frame(b'X', b""));

    let mut server = sasl_offer(&[b"SCRAM-SHA-256"]);
    server.extend_from_slice(&authentication_ok());
    server.extend_from_slice(&backend_key_data(77, &[5; 32]));
    server.extend_from_slice(&ready_for_query());
    server.extend_from_slice(&frame(b'G', &[0, 0, 0]));
    server.extend_from_slice(&frame(b'C', b"COPY 1\0"));
    server.extend_from_slice(&ready_for_query());
    server.extend_from_slice(&frame(b'D', &vec![b'r'; 2500]));
    server.extend_from_slice(&frame(b'C', b"SELECT 1\0"));
    server.extend_from_slice(&ready_for_query());
    (client, server)
}

proptest! {
    /// However the two streams are cut and interleaved, each side receives
    /// exactly what the other sent, and the session never holds more than
    /// one message that fits the limit.
    #[test]
    fn a_session_is_relayed_identically_however_it_is_cut(
        cuts in proptest::collection::vec((any::<bool>(), 1usize..700), 1..200),
        max_buffered in prop_oneof![Just(1024usize), Just(4096), Just(1024 * 1024)],
    ) {
        let (client, server) = scripted_session();
        let startup_len = usize::try_from(u32::from_be_bytes(client[..4].try_into().unwrap())).unwrap();
        let mut harness = Harness::new(TlsPolicy::Disabled)
            .with_policy(OnError::FailClosed, max_buffered);

        // The startup message comes first, and the client waits for the
        // answer to it, as every client does.
        let (first, mut client_rest) = client.split_at(startup_len);
        harness.client(first).unwrap();
        prop_assert_eq!(harness.take_effects(), [Effect::ConnectBackend]);
        harness.report(Report::BackendConnected { tls: false }).unwrap();

        let mut server_rest = server.as_slice();
        // The client does not send its first query before it is logged in.
        let login_len = sasl_offer(&[b"SCRAM-SHA-256"]).len() + authentication_ok().len();
        let (login, after_login) = server_rest.split_at(login_len);
        let response_len = frame(b'p', b"SCRAM-SHA-256\0\0\0\0\x05n,,n=").len();
        let (response, after_response) = client_rest.split_at(response_len);
        harness.server(login).unwrap();
        harness.client(response).unwrap();
        server_rest = after_login;
        client_rest = after_response;

        let mut cuts = cuts.into_iter().cycle();
        while !client_rest.is_empty() || !server_rest.is_empty() {
            let (from_client, size) = cuts.next().unwrap();
            let (rest, from) = if from_client && !client_rest.is_empty() || server_rest.is_empty() {
                (&mut client_rest, Direction::FromClient)
            } else {
                (&mut server_rest, Direction::FromServer)
            };
            let (piece, later) = rest.split_at(size.min(rest.len()));
            *rest = later;
            harness.bytes(from, piece).unwrap();
            // A whole message of at most `max_buffered` bytes, or the
            // beginning of a header.
            prop_assert!(harness.session.buffered_bytes() <= 2 * max_buffered.max(MAX_LOGIN_FRAME));
        }

        prop_assert_eq!(&harness.to_server, &client);
        prop_assert_eq!(&harness.to_client, &server);
        prop_assert_eq!(harness.session.buffered_bytes(), 0);
        let expected = cancel_request(77, &[5; 32]);
        prop_assert_eq!(harness.session.cancel_request(), Some(expected.as_slice()));
        prop_assert!(!harness.session.in_copy(Direction::FromClient));
    }
}
