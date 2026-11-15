// SPDX-License-Identifier: Apache-2.0

//! The `scanning` target: a session that looks for honeytokens and
//! carries out every response to them.
//!
//! The `session` target drives a session that only relays, or one that
//! holds statements for the SQL rules. This one drives the session
//! [`Postgres::responding`] makes: it searches everything for the tokens
//! of its policy, and answers a hit with `alert`, `kill`, `tarpit` or
//! `fake_data`. The policy has a token for each response, for the
//! combinations of them, and for an escalation, and one token that is
//! found whatever the case of its letters.
//!
//! # What is checked
//!
//! For every input, cut as given and again byte by byte:
//!
//! - **A session that has ended produces no byte**, and no effect but
//!   the report of a hit it had kept back.
//! - **What the client is sent is a run of whole messages**, for as long
//!   as the session inspects it, whatever the server sent.
//! - **A value that is answered with `kill` reaches nobody.** The token
//!   whose only response is `kill` is never in what was passed on to
//!   either side: not as written, not in another case, not in
//!   hexadecimal.
//! - **A `kill` ends the session** in the same call.
//! - **A hit is reported as it is counted**: every count is followed by
//!   its event, and both name the same token and the same responses.
//! - **A report says `fake_data` only when rows were added**, and rows
//!   are added only when a report says so. The number of rows the client
//!   gets beyond those of the server, and the number its command tags
//!   count beyond those of the server, are the same.
//! - **No report is lost or sent twice**: when the session is over, the
//!   runtime asks for what was kept back, and a second question gets
//!   nothing.
//! - **The session holds no more than it may.**
//!
//! # Inputs
//!
//! The first byte chooses the failure policy and the limit for a message
//! that is held whole. The session is then logged in, and the rest of the
//! input is steps of three bytes, a kind and two arguments, some followed
//! by a payload:
//!
//! - bytes from the client or the server, as they are;
//! - a whole message of the client or of the server, chosen from a list:
//!   statements, the messages of the extended protocol, results with and
//!   without a token in any of its forms, rows too large to hold, and the
//!   messages of a COPY;
//! - a report of the runtime: the tarpit is over, a report must not wait
//!   any longer, the proxy stops, the database is connected;
//! - a new policy, as after a reload.

use std::net::IpAddr;
use std::sync::Arc;
use std::time::Duration;

use pgsnare_core::actions::TarpitPlaces;
use pgsnare_core::bait::{Entropy, EntropyError};
use pgsnare_core::detect::{Matcher, TokenSpec};
use pgsnare_core::event::{EventKind, SessionId};
use pgsnare_core::extension::{ProtocolSession, Relay};
use pgsnare_core::policy::{
    Action, ActionSet, ActionSettings, Escalation, FakeDataSettings, Inspection, KillSettings,
    OnError, PolicySnapshot, TarpitSettings, TokenId, TokenPolicy,
};
use pgsnare_core::session::postgres::{MAX_LOGIN_FRAME, Postgres, PostgresSession, Responses};
use pgsnare_core::session::{Direction, Effect, Output, Report, SessionOrigin};

/// The tokens of the policy: an id and a value. All values are made up.
const TOKENS: [(&str, &str); 6] = [
    ("fuzz-alert", "zq0.alert.4kx9@fuzz.example"),
    ("fuzz-kill", "ZQ1-Kill-7M2P-XK4T"),
    ("fuzz-tarpit", "zq2tarpit9d1bq7w"),
    ("fuzz-fake", "zq3.fake.8f3k2q@fuzz.example"),
    ("fuzz-escalating", "zq4-escalating-5t8v"),
    ("fuzz-all", "zq5-fake-tarpit-alert-2c6n"),
];

/// The token whose only response is `kill`, in every policy of a run.
const KILL: usize = 1;

/// How many rows `fake_data` adds to a result.
const ADDED: u32 = 3;

/// The longest message a client or a server sends in a login.
const MAX_BEFORE_LOGIN: usize = 10_004 + MAX_LOGIN_FRAME;

fn set(actions: &[Action]) -> ActionSet {
    ActionSet::of(actions)
}

/// The policy of a run. `variant` changes what some tokens are answered
/// with, as a reload does; the token for `kill` keeps its answer.
fn policy(on_error: OnError, max_buffered_frame: usize, generation: u64) -> PolicySnapshot {
    let swapped = generation % 2 == 1;
    let responses: [ActionSet; 6] = [
        if swapped {
            set(&[Action::FakeData])
        } else {
            ActionSet::ALERT
        },
        set(&[Action::Kill]),
        set(&[Action::Tarpit]),
        if swapped {
            set(&[Action::Alert, Action::Tarpit])
        } else {
            set(&[Action::FakeData])
        },
        ActionSet::ALERT,
        set(&[Action::FakeData, Action::Tarpit, Action::Alert]),
    ];
    let mut builder = PolicySnapshot::builder()
        .generation(generation)
        .inspection(Inspection::new(on_error, max_buffered_frame))
        .actions(ActionSettings::new(
            KillSettings::default(),
            TarpitSettings::new(
                Duration::from_millis(1),
                Duration::from_millis(5),
                Duration::from_secs(60),
                2,
                Some(1024),
            ),
            FakeDataSettings::new(ADDED),
        ));
    let mut specs = Vec::new();
    for (index, ((id, value), actions)) in TOKENS.iter().zip(responses).enumerate() {
        let mut token = TokenPolicy::new(TokenId::new(id).expect("a valid id"));
        token.actions = actions;
        if index == 4 {
            token.escalate = Some(Escalation::new(2, set(&[Action::Alert, Action::Kill])));
        }
        builder = builder.token(token);
        specs.push(TokenSpec::new(*id, [*value]).case_insensitive(index == KILL));
    }
    builder
        .matcher(Matcher::build(&specs).expect("tokens that can be looked for"))
        .build()
        .expect("a valid policy")
}

/// A limit for messages that are held whole: 1 KiB to 8 KiB, so that a
/// message larger than it stays small.
fn buffered_limit(choice: u8) -> usize {
    1024 << (choice % 4)
}

/// A stand-in for the hash function of the runtime.
fn digest(_: &[u8]) -> [u8; 32] {
    [0; 32]
}

/// Bytes that change at every call, and are the same in every run.
struct Counting(u64);

impl Entropy for Counting {
    fn fill(&mut self, dest: &mut [u8]) -> Result<(), EntropyError> {
        for byte in dest.iter_mut() {
            self.0 ^= self.0 << 13;
            self.0 ^= self.0 >> 7;
            self.0 ^= self.0 << 17;
            *byte = self.0.to_le_bytes()[0];
        }
        Ok(())
    }
}

fn frame(tag: u8, body: &[u8]) -> Vec<u8> {
    let length = u32::try_from(body.len() + 4).expect("a message of the harness is small");
    let mut bytes = vec![tag];
    bytes.extend_from_slice(&length.to_be_bytes());
    bytes.extend_from_slice(body);
    bytes
}

fn hex(value: &[u8]) -> Vec<u8> {
    const DIGITS: &[u8; 16] = b"0123456789abcdef";
    value
        .iter()
        .flat_map(|byte| {
            [
                DIGITS[usize::from(byte >> 4)],
                DIGITS[usize::from(byte & 15)],
            ]
        })
        .collect()
}

/// The value of a token in one of the forms it is looked for in: the low
/// four bits of `which` choose the token, and the two above them the form.
fn token(which: u8) -> Vec<u8> {
    let value = TOKENS[usize::from(which & 0x0f) % TOKENS.len()]
        .1
        .as_bytes();
    match ((which >> 4) & 3) % 3 {
        0 => value.to_vec(),
        1 => hex(value),
        _ => value.to_ascii_uppercase(),
    }
}

/// A `RowDescription` of an `id`, a `note` and a `ref`, with the note in
/// text or in binary format.
fn description(binary_note: bool) -> Vec<u8> {
    let mut body = 3i16.to_be_bytes().to_vec();
    for (name, oid, format) in [
        ("id", 23u32, 0i16),
        ("note", 25, i16::from(binary_note)),
        ("ref", 2950, 0),
    ] {
        body.extend_from_slice(name.as_bytes());
        body.push(0);
        body.extend_from_slice(&16_384u32.to_be_bytes());
        body.extend_from_slice(&1i16.to_be_bytes());
        body.extend_from_slice(&oid.to_be_bytes());
        body.extend_from_slice(&(-1i16).to_be_bytes());
        body.extend_from_slice(&(-1i32).to_be_bytes());
        body.extend_from_slice(&format.to_be_bytes());
    }
    frame(b'T', &body)
}

fn row(values: &[&[u8]]) -> Vec<u8> {
    let count = i16::try_from(values.len()).expect("a few columns");
    let mut body = count.to_be_bytes().to_vec();
    for value in values {
        let length = u32::try_from(value.len()).expect("a value of the harness is small");
        body.extend_from_slice(&length.to_be_bytes());
        body.extend_from_slice(value);
    }
    frame(b'D', &body)
}

fn row_with(id: u8, note: &[u8]) -> Vec<u8> {
    row(&[
        id.to_string().as_bytes(),
        note,
        b"0f8a1c52-7d3e-4b6a-9c21-5e4f3a2b1c0d",
    ])
}

/// A whole message of the server, chosen by `kind` and shaped by
/// `argument`. `limit` is the limit for a message that is held whole.
fn server_message(kind: u8, argument: u8, limit: usize) -> Vec<u8> {
    match kind % 24 {
        0 => description(false),
        1 => description(true),
        2 | 3 => row_with(argument, b"nothing to see"),
        4 | 5 => row_with(argument, &token(argument)),
        6 | 7 => frame(b'C', format!("SELECT {argument}\0").as_bytes()),
        8 | 9 => frame(b'Z', b"I"),
        10 => frame(b'Z', b"T"),
        11 => frame(b'E', b"SERROR\0C57014\0Mcancelled\0\0"),
        12 => frame(b's', b""),
        13 => frame(b'1', b""),
        14 => frame(b'2', b""),
        15 => frame(b'n', b""),
        16 => frame(b't', &[0, 0]),
        17 => frame(b'3', b""),
        18 => frame(b'I', b""),
        19 => {
            // A row too large to hold, with or without a token in it.
            let mut note = vec![b'y'; limit + 64];
            if argument & 0x80 != 0 {
                let value = token(argument);
                let at = usize::from(argument & 0x0f) * 64;
                note.splice(at..at, value);
            }
            row_with(argument, &note)
        }
        20 => frame(b'H', &[0, 0, 1, 0, 0]),
        21 => {
            // A piece of a token, as a COPY cuts its rows anywhere.
            let value = token(argument);
            let half = value.len() / 2;
            let piece = if argument & 0x40 == 0 {
                &value[..half]
            } else {
                &value[half..]
            };
            frame(b'd', piece)
        }
        22 => frame(b'c', b""),
        _ => row(&[b"7", b"too few columns"]),
    }
}

const STATEMENT: &[u8] = b"SELECT id, note, ref FROM notes";

fn portal(argument: u8) -> &'static [u8] {
    [&b""[..], b"a", b"b"][usize::from(argument) % 3]
}

/// A whole message of the client, chosen by `kind` and shaped by
/// `argument`.
fn client_message(kind: u8, argument: u8) -> Vec<u8> {
    match kind % 12 {
        0 | 1 => frame(b'Q', &[STATEMENT, b"\0"].concat()),
        2 => {
            let mut text = b"SELECT '".to_vec();
            text.extend_from_slice(&token(argument));
            text.extend_from_slice(b"'\0");
            frame(b'Q', &text)
        }
        3 => frame(b'P', &[b"\0", STATEMENT, b"\0\0\0"].concat()),
        4 => frame(
            b'B',
            &[portal(argument), b"\0\0", &[0, 0, 0, 0, 0, 0]].concat(),
        ),
        5 => frame(b'D', &[b"P", portal(argument), b"\0"].concat()),
        6 => frame(b'D', b"S\0"),
        7 => frame(b'E', &[portal(argument), b"\0", &[0, 0, 0, 0]].concat()),
        8 => frame(b'E', &[portal(argument), b"\0", &[0, 0, 0, 1]].concat()),
        9 => frame(b'S', b""),
        10 => frame(b'C', &[b"P", portal(argument), b"\0"].concat()),
        _ => frame(b'H', b""),
    }
}

/// One thing a runtime does to a session.
#[derive(Clone, Debug, PartialEq, Eq)]
enum Step {
    /// Bytes as they are, or a whole message of the harness when
    /// `whole`.
    Bytes {
        from: Direction,
        bytes: Vec<u8>,
        whole: bool,
    },
    Report(Report),
    Policy(OnError, u8),
}

/// Reads steps from an input: a kind, two arguments, and a payload for
/// the kinds that have one.
fn steps(mut input: &[u8], limit: usize) -> Vec<Step> {
    let mut steps = Vec::new();
    while let Some((&[kind, high, low], rest)) = input.split_first_chunk::<3>() {
        input = rest;
        match kind % 12 {
            kind @ (0 | 1) => {
                let length = usize::from(u16::from_be_bytes([high, low]));
                let (payload, rest) = input.split_at(length.min(input.len()));
                input = rest;
                let from = if kind == 0 {
                    Direction::FromClient
                } else {
                    Direction::FromServer
                };
                steps.push(Step::Bytes {
                    from,
                    bytes: payload.to_vec(),
                    whole: false,
                });
            }
            2 | 3 => steps.push(Step::Bytes {
                from: Direction::FromClient,
                bytes: client_message(high, low),
                whole: true,
            }),
            4..=7 => steps.push(Step::Bytes {
                from: Direction::FromServer,
                bytes: server_message(high, low, limit),
                whole: true,
            }),
            8 => steps.push(Step::Report(Report::EventDue)),
            9 => steps.push(Step::Report(match high % 4 {
                0 => Report::TarpitOver,
                1 => Report::ShuttingDown,
                2 => Report::BackendConnected { tls: low & 1 == 1 },
                _ => Report::EventDue,
            })),
            _ => {
                let on_error = if high & 1 == 0 {
                    OnError::FailClosed
                } else {
                    OnError::FailOpen
                };
                steps.push(Step::Policy(on_error, low));
            }
        }
    }
    steps
}

/// Reads a stream of messages as it arrives, piece by piece.
#[derive(Default)]
struct Messages {
    /// The beginning of the message that is not complete yet.
    partial: Vec<u8>,
}

impl Messages {
    /// Takes the next bytes of the stream and returns the type and the
    /// body of every message they complete.
    fn feed(&mut self, bytes: &[u8]) -> Vec<(u8, Vec<u8>)> {
        self.partial.extend_from_slice(bytes);
        let mut complete = Vec::new();
        while let Some((&[tag, a, b, c, d], _)) = self.partial.split_first_chunk::<5>() {
            let length = usize::try_from(u32::from_be_bytes([a, b, c, d])).expect("32 bits fit");
            assert!(
                length >= 4,
                "the client was sent a message with an impossible length"
            );
            let total = 1 + length;
            if self.partial.len() < total {
                break;
            }
            complete.push((tag, self.partial[5..total].to_vec()));
            self.partial.drain(..total);
        }
        complete
    }
}

/// The count of a command tag that counts selected rows.
fn selected(body: &[u8]) -> Option<u64> {
    let text = body.strip_suffix(b"\0")?.strip_prefix(b"SELECT ")?;
    core::str::from_utf8(text).ok()?.parse().ok()
}

/// What a stream of messages held of results.
#[derive(Default)]
struct Results {
    rows: u64,
    selected: u64,
}

impl Results {
    fn note(&mut self, messages: &[(u8, Vec<u8>)]) {
        for (tag, body) in messages {
            match tag {
                b'D' => self.rows += 1,
                b'C' => self.selected += selected(body).unwrap_or(0),
                _ => {}
            }
        }
    }
}

/// What a run reached, for the tests of the seeds.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct Reached {
    /// A hit was reported.
    pub hit: bool,
    /// A hit was answered with `kill`.
    pub kill: bool,
    /// A session was tarpitted.
    pub tarpit: bool,
    /// A report said that rows were added.
    pub fake_data: bool,
    /// A report was kept back and left as `alert`.
    pub kept_back_in_vain: bool,
}

struct Run {
    session: PostgresSession,
    policy: PolicySnapshot,
    generation: u64,
    largest_limit: usize,
    to_client: Vec<u8>,
    to_server: Vec<u8>,
    /// How much of each stream was passed on while the session inspected
    /// what it passed on.
    inspected: Option<(usize, usize)>,
    /// What the client was sent, read as messages.
    client: Messages,
    client_results: Results,
    /// The messages of the server, when all of them were whole messages
    /// of the harness.
    server_results: Option<Results>,
    /// The reports that said `fake_data`, and the reports kept back.
    fake_reports: u64,
    kept_back: u64,
    reports: u64,
    ever_closed: bool,
    reached: Reached,
}

impl Run {
    fn new(on_error: OnError, limit: usize) -> Self {
        let origin = SessionOrigin::new(
            SessionId::from_u128(1),
            "192.0.2.10"
                .parse::<IpAddr>()
                .expect("a documentation address"),
            49_152,
            false,
        );
        let responses = Responses::new(
            || -> Box<dyn Entropy + Send> { Box::new(Counting(0x9e37_79b9_7f4a_7c15)) },
            Arc::new(TarpitPlaces::new()),
        );
        let module = Postgres::responding(Arc::new(digest), responses);
        let mut run = Self {
            session: module.session(origin, Arc::new(Relay)),
            policy: policy(on_error, limit, 0),
            generation: 0,
            largest_limit: limit,
            to_client: Vec::new(),
            to_server: Vec::new(),
            inspected: None,
            client: Messages::default(),
            client_results: Results::default(),
            server_results: Some(Results::default()),
            fake_reports: 0,
            kept_back: 0,
            reports: 0,
            ever_closed: false,
            reached: Reached::default(),
        };
        run.log_in();
        run
    }

    /// Takes the session through a login, as a client and a server that
    /// behave do. What it produces is not part of what is checked.
    fn log_in(&mut self) {
        let mut startup = Vec::new();
        startup.extend_from_slice(&196_608u32.to_be_bytes());
        startup.extend_from_slice(b"user\0app\0database\0shop\0\0");
        let length = u32::try_from(startup.len() + 4).expect("a short packet");
        let packet = [&length.to_be_bytes()[..], &startup].concat();

        let mut out = Output::new();
        let policy = &self.policy;
        let session = &mut self.session;
        session
            .on_bytes(Direction::FromClient, &packet, policy, &mut out)
            .expect("a startup message");
        session
            .on_report(Report::BackendConnected { tls: false }, policy, &mut out)
            .expect("a connection");
        let mut key = 4242i32.to_be_bytes().to_vec();
        key.extend_from_slice(&[1, 2, 3, 4]);
        let welcome = [
            frame(b'R', &0u32.to_be_bytes()),
            frame(b'S', b"client_encoding\0UTF8\0"),
            frame(b'K', &key),
            frame(b'Z', b"I"),
        ]
        .concat();
        session
            .on_bytes(Direction::FromServer, &welcome, policy, &mut out)
            .expect("a login");
        assert!(session.is_established(), "the login of the harness failed");
    }

    /// Calls into the session and checks everything that must hold after
    /// every call.
    fn call(
        &mut self,
        is_due: bool,
        call: impl FnOnce(&mut PostgresSession, &PolicySnapshot, &mut Output) -> Result<(), ()>,
    ) {
        let ended_before = self.session.is_closed();
        let inspecting_before = !self.session.is_tunnel() && self.inspected.is_none();
        let mut out = Output::new();
        let result = call(&mut self.session, &self.policy, &mut out);

        if ended_before {
            assert!(
                result.is_ok() && out.to_client.is_empty() && out.to_server.is_empty(),
                "a session that had ended produced something"
            );
            assert!(
                out.effects.is_empty() || is_due,
                "a session that had ended asked for something"
            );
        }
        if result.is_err() {
            assert!(
                self.session.is_closed(),
                "a session that failed is still open"
            );
        }
        self.ever_closed |= self.session.is_closed();

        let largest = self.largest_limit.max(MAX_LOGIN_FRAME);
        let held = self.session.buffered_bytes();
        assert!(
            held <= MAX_BEFORE_LOGIN + 2 * largest,
            "the session holds {held} bytes"
        );
        assert!(
            !self.session.holds_client(),
            "a message is held without rules"
        );

        // A session that goes on without inspection passes on what it is
        // given: nothing is promised about that.
        let bypassed = out.effects.iter().any(|effect| {
            matches!(effect, Effect::Emit(body) if body.kind == EventKind::InspectionBypassed)
        });
        if inspecting_before && (bypassed || self.session.is_tunnel()) {
            self.inspected = Some((self.to_client.len(), self.to_server.len()));
        }
        let inspecting = self.inspected.is_none();

        let complete = if inspecting {
            self.client.feed(&out.to_client)
        } else {
            Vec::new()
        };
        self.client_results.note(&complete);

        self.effects(&out.effects, &complete, ended_before);

        self.to_client.append(&mut out.to_client);
        self.to_server.append(&mut out.to_server);
    }

    /// Checks the effects of one call. `complete` is what the call
    /// completed of the messages for the client.
    fn effects(&mut self, effects: &[Effect], complete: &[(u8, Vec<u8>)], ended_before: bool) {
        let mut fake_reports = 0;
        let mut effects = effects.iter();
        while let Some(effect) = effects.next() {
            match effect {
                Effect::TokenHit {
                    token_id,
                    exempt,
                    decided: _,
                    actions,
                } => {
                    assert!(!exempt, "no session of the harness is exempt");
                    let Some(Effect::Emit(body)) = effects.next() else {
                        panic!("a hit was counted and not reported");
                    };
                    assert_eq!(body.kind, EventKind::TokenHit, "a count without its event");
                    assert_eq!(
                        body.token_id.as_ref().map(TokenId::as_str),
                        Some(token_id.as_str()),
                        "the count and the event name different tokens"
                    );
                    assert_eq!(
                        body.action_taken, *actions,
                        "the count and the event name different responses"
                    );
                    assert!(!actions.is_empty(), "a hit without a response");
                    self.reports += 1;
                    self.reached.hit = true;
                    if actions.contains(Action::Kill) {
                        self.reached.kill = true;
                        assert!(
                            self.session.is_closed(),
                            "a hit was answered with kill and the session goes on"
                        );
                        assert!(
                            !actions.contains(Action::FakeData)
                                && !actions.contains(Action::Tarpit),
                            "a session that is ended is not answered otherwise"
                        );
                    }
                    if actions.contains(Action::FakeData) {
                        fake_reports += 1;
                    }
                }
                Effect::Emit(body) => {
                    assert_ne!(
                        body.kind,
                        EventKind::TokenHit,
                        "a hit was reported and not counted"
                    );
                }
                Effect::EventHeld => {
                    assert!(!ended_before, "a session that had ended kept a report back");
                    self.kept_back += 1;
                }
                Effect::Tarpit { .. } => self.reached.tarpit = true,
                _ => {}
            }
        }

        if fake_reports > 0 {
            self.reached.fake_data = true;
            assert!(
                !ended_before,
                "rows cannot be added to a session that ended"
            );
            // The rows and the count that includes them left in this
            // call: a row, and right behind it a count of selected rows.
            let added = complete.windows(2).any(|pair| {
                pair[0].0 == b'D' && pair[1].0 == b'C' && selected(&pair[1].1).is_some()
            });
            assert!(
                added || self.inspected.is_some(),
                "a report says fake_data and no rows were added"
            );
        }
        self.fake_reports += fake_reports;
    }

    fn bytes(&mut self, from: Direction, input: &[u8]) {
        self.call(false, |session, policy, out| {
            session.on_bytes(from, input, policy, out).map_err(|_| ())
        });
    }

    fn report(&mut self, report: Report) {
        let is_due = report == Report::EventDue;
        self.call(is_due, |session, policy, out| {
            session.on_report(report, policy, out).map_err(|_| ())
        });
    }

    fn step(&mut self, step: &Step, byte_by_byte: bool) {
        match step {
            Step::Bytes { from, bytes, whole } => {
                if *from == Direction::FromServer {
                    match (&mut self.server_results, *whole) {
                        (Some(results), true) if !self.session.is_closed() => {
                            let tag = bytes.first().copied().unwrap_or(0);
                            results.note(&[(tag, bytes.get(5..).unwrap_or_default().to_vec())]);
                        }
                        (results, false) => *results = None,
                        _ => {}
                    }
                }
                if byte_by_byte {
                    for byte in bytes {
                        self.bytes(*from, std::slice::from_ref(byte));
                    }
                } else {
                    self.bytes(*from, bytes);
                }
            }
            Step::Report(report) => self.report(report.clone()),
            Step::Policy(on_error, choice) => {
                self.generation += 1;
                let limit = buffered_limit(*choice);
                self.policy = policy(*on_error, limit, self.generation);
                self.largest_limit = self.largest_limit.max(limit);
            }
        }
    }

    /// The session is over for the runtime: what was kept back is asked
    /// for, and everything that must hold of a whole run is checked.
    fn finish(mut self) -> Reached {
        let before = self.reports;
        self.report(Report::EventDue);
        let handed_over = self.reports - before;
        assert!(handed_over <= 1, "more than one report was kept back");
        self.report(Report::EventDue);
        assert_eq!(
            self.reports,
            before + handed_over,
            "a report was handed over twice"
        );
        assert!(
            self.reports >= self.kept_back,
            "a report that was kept back never left"
        );
        self.reached.kept_back_in_vain = self.kept_back > self.fake_reports;

        // The token that is answered with `kill` reached nobody, in any
        // form it is looked for in.
        let (client, server) = self
            .inspected
            .unwrap_or((self.to_client.len(), self.to_server.len()));
        let value = TOKENS[KILL].1.as_bytes();
        let lowercase = value.to_ascii_lowercase();
        let in_hex = hex(value);
        for passed_on in [&self.to_client[..client], &self.to_server[..server]] {
            let folded = passed_on.to_ascii_lowercase();
            assert!(
                !folded
                    .windows(lowercase.len())
                    .any(|window| window == lowercase),
                "a value that is answered with kill was passed on"
            );
            assert!(
                !passed_on
                    .windows(in_hex.len())
                    .any(|window| window == in_hex),
                "a value that is answered with kill was passed on in hexadecimal"
            );
        }

        // A session that inspected everything, never ended, and whose
        // server sent whole messages only: the client got every message
        // of the server, and beyond them exactly the rows that reports
        // say were added, counted in its command tags.
        if let Some(server) = &self.server_results
            && self.inspected.is_none()
            && !self.ever_closed
        {
            assert!(
                self.client.partial.is_empty(),
                "the client was left in the middle of a message"
            );
            let rows = self.client_results.rows;
            assert!(rows >= server.rows, "a row of the server was lost");
            let added = rows - server.rows;
            assert!(
                added >= self.fake_reports && added <= self.fake_reports * u64::from(ADDED),
                "{added} rows were added and {} reports say fake_data",
                self.fake_reports
            );
            assert_eq!(
                self.client_results.selected,
                server.selected + added,
                "the command tags do not count the rows that were added"
            );
        }
        self.reached
    }
}

/// Runs one input, cut as given or byte by byte, and returns what it
/// reached.
fn play(data: &[u8], byte_by_byte: bool) -> Reached {
    let Some((&first, rest)) = data.split_first() else {
        return Reached::default();
    };
    let on_error = if first & 1 == 0 {
        OnError::FailClosed
    } else {
        OnError::FailOpen
    };
    let limit = buffered_limit(first >> 1);
    let mut run = Run::new(on_error, limit);
    for step in &steps(rest, limit) {
        run.step(step, byte_by_byte);
    }
    run.finish()
}

/// Runs one input both ways and returns what it reached as it was given.
#[must_use]
pub fn run_scanning(data: &[u8]) -> Reached {
    let reached = play(data, false);
    let _ = play(data, true);
    reached
}

/// Fuzzes a session that looks for honeytokens and responds to them.
pub fn fuzz_scanning(data: &[u8]) {
    let _ = run_scanning(data);
}
