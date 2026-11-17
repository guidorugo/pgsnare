// SPDX-License-Identifier: Apache-2.0

//! Replays traffic captured from PostgreSQL 15 to 18 through the session
//! logic.
//!
//! The captures are the golden-byte fixtures of `pgsnare-proto`: for each
//! scenario, every byte a real client sent and every byte a real server
//! sent. A relay is transparent when each side receives exactly what the
//! other sent, however the two streams are cut and interleaved on their
//! way through it. These tests check that, and they check what the session
//! logic rewrites against what real servers answered.
//!
//! The interleaving is any that a real connection can have: a client sends
//! nothing but its login messages before the server has accepted its
//! login, so the rest of its stream waits for the server's
//! `AuthenticationOk`. A client that does not wait has its session ended,
//! which is checked too.
//!
//! `crates/pgsnare-proto/tests/fixtures/README.md` describes the captures.
//! Every value in them is synthetic.

use std::fs;
use std::net::IpAddr;
use std::path::PathBuf;
use std::sync::Arc;

use pgsnare_core::event::SessionId;
use pgsnare_core::extension::{ProtocolSession, Relay};
use pgsnare_core::policy::{Inspection, OnError, PolicySnapshot};
use pgsnare_core::session::postgres::{Postgres, PostgresSession};
use pgsnare_core::session::{Direction, Effect, Leg, Output, Report, SessionOrigin, TlsPolicy};
use proptest::prelude::*;

/// The directories of captures: a server version and the protocol version
/// the client asked for.
const CAPTURES: [&str; 5] = ["pg15-3.0", "pg16-3.0", "pg17-3.0", "pg18-3.0", "pg18-3.2"];

/// The scenarios that are one whole session each, from the startup message
/// on.
const SESSIONS: [&str; 9] = [
    "simple",
    "extended",
    "copy",
    "cancel",
    "replication",
    "auth-md5",
    "auth-cleartext",
    "auth-failed",
    "crafted-binary",
];

fn fixture_path(capture: &str, file: &str) -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("../pgsnare-proto/tests/fixtures")
        .join(capture)
        .join(file)
}

fn has(capture: &str, file: &str) -> bool {
    fixture_path(capture, file).exists()
}

fn read(capture: &str, file: &str) -> Vec<u8> {
    let path = fixture_path(capture, file);
    fs::read(&path).unwrap_or_else(|error| panic!("{}: {error}", path.display()))
}

/// The length of the startup-phase packet at the front of `bytes`.
fn packet_len(bytes: &[u8]) -> usize {
    usize::try_from(u32::from_be_bytes(bytes[..4].try_into().unwrap())).unwrap()
}

/// The length of the message with a type byte at the front of `bytes`.
fn frame_len(bytes: &[u8]) -> usize {
    1 + usize::try_from(u32::from_be_bytes(bytes[1..5].try_into().unwrap())).unwrap()
}

/// How many bytes at the front of a client stream, after the startup
/// message, are login messages.
fn login_messages_len(client: &[u8]) -> usize {
    let mut len = 0;
    while client.get(len) == Some(&b'p') {
        len += frame_len(&client[len..]);
    }
    len
}

/// How many bytes at the front of a server stream end with its
/// `AuthenticationOk`: all of them, for a login that is not accepted.
fn accepting_len(server: &[u8]) -> usize {
    let mut len = 0;
    while len < server.len() {
        let end = len + frame_len(&server[len..]);
        if server[len..end] == [b'R', 0, 0, 0, 8, 0, 0, 0, 0] {
            return end;
        }
        len = end;
    }
    server.len()
}

/// What is left of the two streams of a session after its startup
/// message, taken in pieces in an order a real connection can have.
struct Streams<'a> {
    client: &'a [u8],
    server: &'a [u8],
    /// What is left of the client's login messages.
    login: usize,
    /// What is left of the server stream up to its `AuthenticationOk`.
    accepting: usize,
}

impl<'a> Streams<'a> {
    fn new(client: &'a [u8], server: &'a [u8]) -> Self {
        Self {
            client,
            server,
            login: login_messages_len(client),
            accepting: accepting_len(server),
        }
    }

    fn is_empty(&self) -> bool {
        self.client.is_empty() && self.server.is_empty()
    }

    /// Takes the next piece, of at most `size` bytes: from the client when
    /// `client_turn` says so and the client has something it may send,
    /// and from the server otherwise.
    fn next(&mut self, client_turn: bool, size: usize) -> (Direction, &'a [u8]) {
        // Until the server has accepted the login, the client may send
        // only its login messages. Once the server stream is used up, the
        // login has been accepted or has failed, and nothing waits.
        let ready = if self.accepting == 0 {
            self.client.len()
        } else {
            self.login
        };
        if (client_turn && ready > 0) || self.server.is_empty() {
            let (piece, later) = self.client.split_at(size.clamp(1, ready));
            self.client = later;
            self.login = self.login.saturating_sub(piece.len());
            (Direction::FromClient, piece)
        } else {
            let (piece, later) = self.server.split_at(size.clamp(1, self.server.len()));
            self.server = later;
            self.accepting = self.accepting.saturating_sub(piece.len());
            (Direction::FromServer, piece)
        }
    }
}

fn policy(max_buffered_frame: usize) -> PolicySnapshot {
    PolicySnapshot::builder()
        .inspection(Inspection::new(OnError::FailClosed, max_buffered_frame))
        .build()
        .unwrap()
}

/// A session, and everything it has produced so far.
struct Replay {
    session: PostgresSession,
    policy: PolicySnapshot,
    to_client: Vec<u8>,
    to_server: Vec<u8>,
    effects: Vec<Effect>,
}

impl Replay {
    fn new(tls: TlsPolicy, max_buffered_frame: usize) -> Self {
        let origin = SessionOrigin::new(
            SessionId::from_u128(1),
            "192.0.2.10".parse::<IpAddr>().unwrap(),
            49_152,
            false,
        )
        .with_client_tls_policy(tls);
        Self {
            session: Postgres::new().session(origin, Arc::new(Relay)),
            policy: policy(max_buffered_frame),
            to_client: Vec::new(),
            to_server: Vec::new(),
            effects: Vec::new(),
        }
    }

    fn collect(&mut self, mut out: Output) {
        self.to_client.append(&mut out.to_client);
        self.to_server.append(&mut out.to_server);
        self.effects.append(&mut out.effects);
    }

    fn bytes(&mut self, from: Direction, input: &[u8]) {
        let mut out = Output::new();
        self.session
            .on_bytes(from, input, &self.policy, &mut out)
            .unwrap_or_else(|error| panic!("{error}"));
        self.collect(out);
    }

    fn report(&mut self, report: Report) {
        let mut out = Output::new();
        self.session
            .on_report(report, &self.policy, &mut out)
            .unwrap_or_else(|error| panic!("{error}"));
        self.collect(out);
    }

    /// Feeds the startup message at the front of the client stream, and
    /// connects the session to its database. Returns the rest of the
    /// client stream.
    fn start<'a>(&mut self, client: &'a [u8], backend_tls: bool) -> &'a [u8] {
        let (startup, rest) = client.split_at(packet_len(client));
        self.bytes(Direction::FromClient, startup);
        assert_eq!(
            std::mem::take(&mut self.effects),
            [Effect::ConnectBackend],
            "a startup message asks for the database"
        );
        assert!(self.to_server.is_empty(), "nothing is sent before then");
        self.report(Report::BackendConnected { tls: backend_tls });
        rest
    }

    /// Feeds both streams to their ends, in pieces of the given sizes,
    /// taking turns as `client_first` says.
    fn feed(&mut self, client: &[u8], server: &[u8], sizes: &[usize], client_first: bool) {
        let mut streams = Streams::new(client, server);
        let mut sizes = sizes.iter().copied().cycle();
        let mut client_turn = client_first;
        while !streams.is_empty() {
            let (from, piece) = streams.next(client_turn, sizes.next().unwrap());
            self.bytes(from, piece);
            client_turn = !client_turn;
        }
    }
}

/// Ways to cut a stream: byte by byte, in small pieces, in pieces that do
/// not line up with anything, in the sizes a socket delivers, and whole.
const CUTS: [&[usize]; 5] = [&[1], &[3, 1, 5], &[97, 13, 1021], &[4096], &[usize::MAX]];

#[test]
fn every_captured_session_passes_unchanged_however_it_is_cut() {
    let mut replayed = 0;
    for capture in CAPTURES {
        for scenario in SESSIONS {
            if !has(capture, &format!("{scenario}.client.bin")) {
                continue;
            }
            let client = read(capture, &format!("{scenario}.client.bin"));
            let server = read(capture, &format!("{scenario}.server.bin"));
            for sizes in CUTS {
                for client_first in [true, false] {
                    for max_buffered_frame in [1024, 1024 * 1024] {
                        let mut replay = Replay::new(TlsPolicy::Disabled, max_buffered_frame);
                        let rest = replay.start(&client, false);
                        replay.feed(rest, &server, sizes, client_first);
                        let what = format!("{capture}/{scenario}, cut {sizes:?}");
                        assert!(replay.to_server == client, "{what}: the server's view");
                        assert!(replay.to_client == server, "{what}: the client's view");
                        assert_eq!(replay.session.buffered_bytes(), 0, "{what}");
                        // A login that failed is the only session that is
                        // never established.
                        assert_eq!(
                            replay.session.is_established(),
                            scenario != "auth-failed",
                            "{what}"
                        );
                        replayed += 1;
                    }
                }
            }
        }
    }
    // Nine scenarios, five captures, twenty ways each. One scenario does
    // not exist for every capture.
    assert!(replayed >= 5 * 8 * 20, "{replayed} replays");
}

#[test]
fn a_captured_client_that_does_not_wait_for_its_login_ends_its_session() {
    let mut refused = 0;
    for capture in CAPTURES {
        for scenario in SESSIONS {
            if !has(capture, &format!("{scenario}.client.bin")) {
                continue;
            }
            let client = read(capture, &format!("{scenario}.client.bin"));
            let mut replay = Replay::new(TlsPolicy::Disabled, 1024 * 1024);
            let rest = replay.start(&client, false);
            let login = login_messages_len(rest);
            if login == rest.len() {
                // Nothing but the login, as in a login that fails.
                continue;
            }
            // Everything the client sent, before the server has said a
            // word: the login messages go on, nothing behind them does.
            let mut out = Output::new();
            let error = replay
                .session
                .on_bytes(Direction::FromClient, rest, &replay.policy, &mut out)
                .unwrap_err();
            let what = format!("{capture}/{scenario}");
            assert_eq!(
                error.reason(),
                "the client sent a message other than a login message before the login finished",
                "{what}"
            );
            assert!(out.to_server == rest[..login], "{what}");
            assert!(out.to_client.is_empty(), "{what}");
            assert!(replay.session.is_closed(), "{what}");
            refused += 1;
        }
    }
    // Every scenario but the failed login, in every capture. One scenario
    // does not exist for every capture.
    assert!(refused >= 5 * 7, "{refused} sessions");
}

#[test]
fn the_cancel_request_a_session_builds_is_the_one_a_real_client_sent() {
    for capture in CAPTURES {
        // The session whose query was cancelled, and the connection that
        // carried the cancel request.
        let client = read(capture, "cancel.client.bin");
        let server = read(capture, "cancel.server.bin");
        let request = read(capture, "cancel.2.client.bin");

        let mut replay = Replay::new(TlsPolicy::Disabled, 1024 * 1024);
        let rest = replay.start(&client, false);
        replay.feed(rest, &server, &[64], false);
        assert_eq!(
            replay.session.cancel_request(),
            Some(request.as_slice()),
            "{capture}"
        );
        // 4 bytes of key in protocol 3.0, 32 in protocol 3.2.
        let key_len = if capture == "pg18-3.2" { 32 } else { 4 };
        assert_eq!(request.len(), 12 + key_len, "{capture}");

        // On its own connection, the request goes to the database as it
        // arrived, and nothing is answered.
        let mut cancelling = Replay::new(TlsPolicy::Disabled, 1024 * 1024);
        cancelling.bytes(Direction::FromClient, &request);
        assert_eq!(
            cancelling.effects,
            [
                Effect::Cancel {
                    request: request.clone()
                },
                Effect::Close(Leg::Client)
            ],
            "{capture}"
        );
        assert!(cancelling.to_client.is_empty());
        assert!(cancelling.to_server.is_empty());
        assert!(read(capture, "cancel.2.server.bin").is_empty());
    }
}

#[test]
fn a_declined_request_for_tls_is_answered_as_the_server_answered_it() {
    for capture in CAPTURES {
        let client = read(capture, "ssl-refused.client.bin");
        let server = read(capture, "ssl-refused.server.bin");
        // The capture begins with the request and the server's `N`.
        let (request, client_rest) = client.split_at(8);
        let (declined, server_rest) = server.split_at(1);
        assert_eq!(declined, b"N");

        let mut replay = Replay::new(TlsPolicy::Disabled, 1024 * 1024);
        replay.bytes(Direction::FromClient, request);
        assert_eq!(replay.to_client, b"N", "{capture}");
        assert!(replay.effects.is_empty());

        let rest = replay.start(client_rest, false);
        replay.feed(rest, server_rest, &[512], true);
        // The database never sees the request, and the client sees what
        // the server on its own would have sent.
        assert!(replay.to_server == client_rest, "{capture}");
        assert!(replay.to_client == server, "{capture}");
    }
}

#[test]
fn a_captured_tls_handshake_is_handed_to_the_runtime_whole() {
    let hello = read("pg18-3.0", "direct-tls.client.bin");
    assert_eq!(hello[0], 0x16);

    for sizes in CUTS {
        let mut replay = Replay::new(TlsPolicy::Optional, 1024 * 1024);
        // Once the session has asked for the handshake, the runtime gives
        // it nothing more, so only the first piece is fed.
        let first = sizes[0].clamp(1, hello.len());
        replay.bytes(Direction::FromClient, &hello[..first]);
        assert_eq!(
            replay.effects,
            [Effect::AcceptTls {
                handshake: hello[..first].to_vec(),
                alpn_required: true
            }]
        );
        assert!(replay.to_client.is_empty());
    }
}

#[test]
fn a_capped_startup_message_gets_the_answer_a_real_server_gave() {
    for capture in ["pg15-3.0", "pg16-3.0", "pg17-3.0", "pg18-3.0"] {
        // The client asked for protocol 3.99 with an option no server
        // knows, and the server answered with NegotiateProtocolVersion
        // and an authentication request.
        let client = read(capture, "crafted-negotiate.client.bin");
        let server = read(capture, "crafted-negotiate.server.bin");
        assert_eq!(&client[4..8], &[0, 3, 0, 99]);
        assert_eq!(server[0], b'v');
        let (negotiation, login) = server.split_at(frame_len(&server));

        let mut replay = Replay::new(TlsPolicy::Disabled, 1024 * 1024);
        replay.start(&client, false);
        // What the database is sent asks for 3.2 and has no option.
        assert_eq!(&replay.to_server[4..8], &[0, 3, 0, 2], "{capture}");
        assert!(
            !replay.to_server.windows(5).any(|window| window == b"_pq_."),
            "{capture}"
        );
        assert!(replay.to_server.len() < client.len());

        // What a server answers to that depends on its version. From
        // version 18 on it speaks 3.2 and has nothing to negotiate, so it
        // goes straight to the login. Before that it speaks 3.0 only, and
        // says so, with no option to complain about.
        let answer = if capture.starts_with("pg18") {
            login.to_vec()
        } else {
            let mut answer = vec![b'v', 0, 0, 0, 12, 0, 3, 0, 0, 0, 0, 0, 0];
            answer.extend_from_slice(login);
            answer
        };
        replay.bytes(Direction::FromServer, &answer);

        // Either way the client is shown exactly what the server sent it
        // when it was asked directly: the version in force and the option
        // that was not accepted.
        assert!(replay.to_client == server, "{capture}");
        assert_eq!(
            &negotiation[5..9],
            if capture.starts_with("pg18") {
                &[0, 3, 0, 2]
            } else {
                &[0, 3, 0, 0]
            }
        );
    }
}

#[test]
fn an_older_server_negotiating_with_libpq_18_passes_unchanged() {
    // libpq 18 asks for 3.2, which pgsnare does not touch, and a server
    // before version 18 answers with NegotiateProtocolVersion.
    for capture in ["pg15-3.0", "pg16-3.0", "pg17-3.0"] {
        let client = read(capture, "negotiate.client.bin");
        let server = read(capture, "negotiate.server.bin");
        assert_eq!(&client[4..8], &[0, 3, 0, 2]);
        assert_eq!(server[0], b'v');

        let mut replay = Replay::new(TlsPolicy::Disabled, 1024 * 1024);
        let rest = replay.start(&client, false);
        replay.feed(rest, &server, &[32], false);
        assert!(replay.to_server == client, "{capture}");
        assert!(replay.to_client == server, "{capture}");
    }
}

#[test]
fn a_copy_is_followed_through_a_captured_session() {
    for capture in CAPTURES {
        let client = read(capture, "copy.client.bin");
        let server = read(capture, "copy.server.bin");
        let mut replay = Replay::new(TlsPolicy::Disabled, 1024 * 1024);
        let rest = replay.start(&client, false);

        // Message by message from the server, to see the state in between.
        let mut server = server.as_slice();
        let mut seen_in = false;
        let mut seen_out = false;
        while !server.is_empty() {
            let (message, later) = server.split_at(frame_len(server));
            server = later;
            replay.bytes(Direction::FromServer, message);
            match message[0] {
                b'G' => {
                    assert!(replay.session.in_copy(Direction::FromClient));
                    seen_in = true;
                }
                b'H' => {
                    assert!(replay.session.in_copy(Direction::FromServer));
                    seen_out = true;
                }
                b'Z' => {
                    assert!(!replay.session.in_copy(Direction::FromClient));
                    assert!(!replay.session.in_copy(Direction::FromServer));
                }
                _ => {}
            }
        }
        assert!(
            seen_in && seen_out,
            "{capture}: the capture copies both ways"
        );
        replay.feed(rest, &[], &[4096], true);
        assert!(replay.to_server == client, "{capture}");
    }

    // Replication runs a COPY in both directions at once.
    for capture in CAPTURES {
        let client = read(capture, "replication.client.bin");
        let server = read(capture, "replication.server.bin");
        let mut replay = Replay::new(TlsPolicy::Disabled, 1024 * 1024);
        replay.start(&client, false);
        let mut server = server.as_slice();
        let mut both = false;
        while !server.is_empty() {
            let (message, later) = server.split_at(frame_len(server));
            server = later;
            replay.bytes(Direction::FromServer, message);
            if message[0] == b'W' {
                both = replay.session.in_copy(Direction::FromClient)
                    && replay.session.in_copy(Direction::FromServer);
            }
        }
        assert!(both, "{capture}: a CopyBothResponse starts both directions");
    }
}

proptest! {
    #![proptest_config(ProptestConfig::with_cases(64))]

    /// Any way of cutting a captured session, interleaved in any order a
    /// real connection can have, gives each side what the other sent.
    #[test]
    fn a_captured_session_passes_unchanged_under_any_cut(
        capture in proptest::sample::select(CAPTURES.to_vec()),
        scenario in proptest::sample::select(vec!["simple", "extended", "copy", "replication"]),
        cuts in proptest::collection::vec((any::<bool>(), 1usize..600), 1..64),
        max_buffered_frame in prop_oneof![Just(1024usize), Just(64 * 1024)],
    ) {
        let client = read(capture, &format!("{scenario}.client.bin"));
        let server = read(capture, &format!("{scenario}.server.bin"));
        let mut replay = Replay::new(TlsPolicy::Disabled, max_buffered_frame);
        let rest = replay.start(&client, false);
        let mut streams = Streams::new(rest, &server);

        let mut cuts = cuts.into_iter().cycle();
        while !streams.is_empty() {
            let (from_client, size) = cuts.next().unwrap();
            let (from, piece) = streams.next(from_client, size);
            replay.bytes(from, piece);
        }
        prop_assert!(replay.to_server == client);
        prop_assert!(replay.to_client == server);
        prop_assert_eq!(replay.session.buffered_bytes(), 0);
    }
}
