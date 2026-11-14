// SPDX-License-Identifier: Apache-2.0

//! Tests of the scanner, through a whole session: bytes in, effects out.

use std::net::IpAddr;
use std::sync::Arc;

use pgsnare_proto::{ProtocolVersion, encode};

use crate::detect::{Matcher, TokenSpec};
use crate::event::{EventBody, EventKind, Query, SessionId};
use crate::extension::{ProtocolSession, Relay};
use crate::policy::{
    ActionSet, Inspection, OnError, PolicySnapshot, QueryRedaction, TokenId, TokenPolicy,
};
use crate::session::{Direction, Effect, Output, Report, SessionOrigin};

use super::{Inspector as _, Postgres, PostgresSession, Scanner};

pub(super) const EMAIL_ID: &str = "users-admin-backup";
pub(super) const EMAIL: &str = "svc.backup.8f3k2q@mail.example";
pub(super) const CANARY_ID: &str = "billing-canary";
pub(super) const CANARY: &str = "CANARY-7Q2M-XK4T-9D1B";

/// The smallest limit a policy accepts.
pub(super) const LIMIT: usize = Inspection::MIN_MAX_BUFFERED_FRAME;

// ---------------------------------------------------------------------------
// Messages
// ---------------------------------------------------------------------------

pub(super) fn frame(tag: u8, body: &[u8]) -> Vec<u8> {
    let mut bytes = vec![tag];
    bytes.extend_from_slice(&u32::try_from(body.len() + 4).unwrap().to_be_bytes());
    bytes.extend_from_slice(body);
    bytes
}

pub(super) fn startup(parameters: &[(&[u8], &[u8])]) -> Vec<u8> {
    let mut bytes = Vec::new();
    encode::startup_message(ProtocolVersion::V3_0, parameters, &mut bytes).unwrap();
    bytes
}

pub(super) fn join(parts: &[&[u8]]) -> Vec<u8> {
    parts.concat()
}

/// A `DataRow` with one column.
pub(super) fn data_row(value: &[u8]) -> Vec<u8> {
    let length = u32::try_from(value.len()).unwrap().to_be_bytes();
    frame(b'D', &join(&[&[0, 1], &length, value]))
}

/// A `Bind` with one parameter in the given format.
fn bind(format: u16, value: &[u8]) -> Vec<u8> {
    let length = u32::try_from(value.len()).unwrap().to_be_bytes();
    frame(
        b'B',
        &join(&[
            b"\0s1\0",
            &[0, 1],
            &format.to_be_bytes(),
            &[0, 1],
            &length,
            value,
            &[0, 0],
        ]),
    )
}

/// The value inside bytes no text would hold, as a binary format sends it.
fn binary(value: &str) -> Vec<u8> {
    join(&[&[0xff, 0x00, 0x80], value.as_bytes(), &[0x00, 0xfe]])
}

fn hex(value: &str) -> String {
    value.bytes().map(|byte| format!("{byte:02x}")).collect()
}

// ---------------------------------------------------------------------------
// A session
// ---------------------------------------------------------------------------

/// A stand-in for the hash function of the runtime: different texts give
/// different bytes, which is all these tests need.
pub(super) fn digest(statement: &[u8]) -> [u8; 32] {
    let mut bytes = [0x5a_u8; 32];
    for (at, byte) in statement.iter().enumerate() {
        let slot = &mut bytes[at % 32];
        *slot = slot.rotate_left(3) ^ byte;
    }
    bytes
}

fn policy_of(generation: u64, tokens: &[(&str, &str, bool)], limit: usize) -> PolicySnapshot {
    let specs: Vec<TokenSpec> = tokens
        .iter()
        .map(|(id, value, fold)| TokenSpec::new(*id, [*value]).case_insensitive(*fold))
        .collect();
    PolicySnapshot::builder()
        .generation(generation)
        .inspection(Inspection::new(OnError::FailClosed, limit))
        .tokens(
            tokens
                .iter()
                .map(|(id, _, _)| TokenPolicy::new(TokenId::new(id).unwrap())),
        )
        .matcher(Matcher::build(&specs).unwrap())
        .build()
        .unwrap()
}

fn policy(limit: usize) -> PolicySnapshot {
    policy_of(
        1,
        &[(EMAIL_ID, EMAIL, false), (CANARY_ID, CANARY, true)],
        limit,
    )
}

pub(super) fn origin() -> SessionOrigin {
    SessionOrigin::new(
        SessionId::from_u128(0x7e),
        "192.0.2.10".parse::<IpAddr>().unwrap(),
        49_152,
        false,
    )
}

/// What one hit looked like from outside.
#[derive(Debug, PartialEq, Eq)]
pub(super) struct Hit {
    token: String,
    direction: Direction,
    message: &'static str,
}

fn hit(token: &str, direction: Direction, message: &'static str) -> Hit {
    Hit {
        token: token.to_owned(),
        direction,
        message,
    }
}

pub(super) struct Harness {
    pub(super) session: PostgresSession,
    pub(super) policy: PolicySnapshot,
    pub(super) to_client: Vec<u8>,
    pub(super) to_server: Vec<u8>,
    pub(super) effects: Vec<Effect>,
}

impl Harness {
    fn new(limit: usize) -> Self {
        Self::with_policy(policy(limit))
    }

    /// A session that has sent nothing yet.
    pub(super) fn with_policy(policy: PolicySnapshot) -> Self {
        Self {
            session: Postgres::scanning(Arc::new(digest)).session(origin(), Arc::new(Relay)),
            policy,
            to_client: Vec::new(),
            to_server: Vec::new(),
            effects: Vec::new(),
        }
    }

    /// A session that has logged in as `app`.
    pub(super) fn established(limit: usize) -> Self {
        let mut harness = Self::logged_in(
            policy(limit),
            &[
                (b"user", b"app"),
                (b"database", b"shop"),
                (b"application_name", b"psql"),
            ],
        );
        assert!(harness.hits().is_empty());
        harness
    }

    /// A session the database has accepted, with the startup parameters
    /// given. What the login raised is still in `effects`.
    pub(super) fn logged_in(policy: PolicySnapshot, parameters: &[(&[u8], &[u8])]) -> Self {
        let mut harness = Self::with_policy(policy);
        harness.client(&startup(parameters));
        let mut out = Output::new();
        harness
            .session
            .on_report(
                Report::BackendConnected { tls: false },
                &harness.policy,
                &mut out,
            )
            .unwrap();
        harness.server(&frame(b'R', &0u32.to_be_bytes()));
        harness.server(&frame(b'Z', b"I"));
        assert!(harness.session.is_established());
        harness.to_client.clear();
        harness.to_server.clear();
        harness
    }

    pub(super) fn bytes(&mut self, from: Direction, input: &[u8]) {
        let mut out = Output::new();
        self.session
            .on_bytes(from, input, &self.policy, &mut out)
            .unwrap();
        self.to_client.append(&mut out.to_client);
        self.to_server.append(&mut out.to_server);
        self.effects.append(&mut out.effects);
    }

    pub(super) fn client(&mut self, input: &[u8]) {
        self.bytes(Direction::FromClient, input);
    }

    pub(super) fn server(&mut self, input: &[u8]) {
        self.bytes(Direction::FromServer, input);
    }

    fn one_byte_at_a_time(&mut self, from: Direction, input: &[u8]) {
        for byte in input {
            self.bytes(from, &[*byte]);
        }
    }

    pub(super) fn events(&self) -> Vec<&EventBody> {
        self.effects
            .iter()
            .filter_map(|effect| match effect {
                Effect::Emit(body) => Some(&**body),
                _ => None,
            })
            .collect()
    }

    /// The hits raised since the last call. Each hit must come as a count
    /// followed by its event, and the two must agree.
    pub(super) fn hits(&mut self) -> Vec<Hit> {
        let effects = std::mem::take(&mut self.effects);
        let mut hits = Vec::new();
        let mut counted: Option<TokenId> = None;
        for effect in effects {
            match effect {
                Effect::TokenHit {
                    token_id,
                    exempt,
                    actions,
                    decided: _,
                } => {
                    assert_eq!(counted, None, "a hit was counted and not reported");
                    assert!(!exempt);
                    assert_eq!(actions, ActionSet::ALERT);
                    counted = Some(token_id);
                }
                Effect::Emit(body) if body.kind == EventKind::SessionActivity => {}
                Effect::Emit(body) => {
                    assert_eq!(body.kind, EventKind::TokenHit);
                    assert_eq!(body.token_id, counted.take(), "a hit was not counted");
                    assert_eq!(body.action_taken, ActionSet::ALERT);
                    assert_eq!(body.hit_count, 1);
                    hits.push(Hit {
                        token: body.token_id.as_ref().unwrap().as_str().to_owned(),
                        direction: body.direction.unwrap(),
                        message: match body.message_type.as_ref().unwrap() {
                            std::borrow::Cow::Borrowed(name) => name,
                            std::borrow::Cow::Owned(_) => panic!("a name that is not fixed"),
                        },
                    });
                }
                _ => {}
            }
        }
        assert_eq!(counted, None, "a hit was counted and not reported");
        hits
    }

    pub(super) fn statements(&self) -> usize {
        self.effects
            .iter()
            .filter(|effect| matches!(effect, Effect::QuerySeen))
            .count()
    }
}

use Direction::{FromClient, FromServer};

// ---------------------------------------------------------------------------
// Every way a value travels
// ---------------------------------------------------------------------------

#[test]
fn a_value_is_found_in_every_kind_of_message_from_the_server() {
    let text = EMAIL.as_bytes();
    let cases: Vec<(&'static str, Vec<u8>)> = vec![
        ("DataRow", data_row(text)),
        ("DataRow", data_row(&binary(EMAIL))),
        ("DataRow", data_row(format!("\\x{}", hex(EMAIL)).as_bytes())),
        ("CopyData", frame(b'd', &join(&[b"7\t", text, b"\t\\N\n"]))),
        (
            "ErrorResponse",
            frame(
                b'E',
                &join(&[b"SERROR\0C23505\0MKey (email)=(", text, b") exists.\0\0"]),
            ),
        ),
        (
            "NoticeResponse",
            frame(b'N', &join(&[b"SNOTICE\0C00000\0M", text, b"\0\0"])),
        ),
        (
            "NotificationResponse",
            frame(b'A', &join(&[&[0, 0, 0, 9], b"jobs\0", text, b"\0"])),
        ),
        (
            "ParameterStatus",
            frame(b'S', &join(&[b"application_name\0", text, b"\0"])),
        ),
        (
            "FunctionCallResponse",
            frame(b'V', &join(&[&[0, 0, 0, 30], text])),
        ),
        // A message whose type means nothing here is searched all the same.
        ("RowDescription", frame(b'T', &join(&[&[0, 1], text]))),
    ];
    for (name, message) in cases {
        let mut harness = Harness::established(LIMIT);
        harness.server(&message);
        assert_eq!(harness.to_client, message, "{name}");
        let query = harness.events().first().and_then(|body| body.query.clone());
        assert_eq!(query, Some(Query::unknown(QueryRedaction::Fingerprint)));
        assert_eq!(harness.hits(), [hit(EMAIL_ID, FromServer, name)], "{name}");
    }
}

#[test]
fn a_value_is_found_in_every_kind_of_message_from_the_client() {
    let text = EMAIL.as_bytes();
    let cases: Vec<(&'static str, Vec<u8>)> = vec![
        ("Query", frame(b'Q', &join(&[b"SELECT '", text, b"'\0"]))),
        (
            "Parse",
            frame(b'P', &join(&[b"s1\0SELECT '", text, b"'\0", &[0, 0]])),
        ),
        ("Bind", bind(0, text)),
        ("Bind", bind(1, &binary(EMAIL))),
        // No COPY has been announced.
        ("CopyData", frame(b'd', &join(&[text, b"\n"]))),
        ("CopyFail", frame(b'f', &join(&[text, b"\0"]))),
        (
            "FunctionCall",
            frame(
                b'F',
                &join(&[&[0, 0, 4, 0, 0, 0, 0, 1, 0, 0, 0, 30], text, &[0, 0]]),
            ),
        ),
        ("Describe", frame(b'D', &join(&[b"S", text, b"\0"]))),
        ("Close", frame(b'C', &join(&[b"S", text, b"\0"]))),
    ];
    for (name, message) in cases {
        let mut harness = Harness::established(LIMIT);
        harness.client(&message);
        assert_eq!(harness.to_server, message, "{name}");
        assert_eq!(harness.hits(), [hit(EMAIL_ID, FromClient, name)], "{name}");
    }
}

#[test]
fn a_value_is_found_in_every_parameter_of_the_startup_message() {
    let options = format!("-c search_path={EMAIL}");
    let cases: [&[(&[u8], &[u8])]; 4] = [
        &[(b"user", EMAIL.as_bytes()), (b"database", b"shop")],
        &[(b"user", b"app"), (b"application_name", EMAIL.as_bytes())],
        &[(b"user", b"app"), (b"options", options.as_bytes())],
        // A parameter nobody has heard of, and the value as a name.
        &[(b"user", b"app"), (EMAIL.as_bytes(), b"on")],
    ];
    for parameters in cases {
        let mut harness = Harness::new(LIMIT);
        harness.client(&startup(parameters));
        // The login goes on: the response is `alert`.
        assert!(harness.effects.contains(&Effect::ConnectBackend));
        // No statement can be behind a startup message.
        assert_eq!(harness.events().first().unwrap().query, None);
        assert_eq!(
            harness.hits(),
            [hit(EMAIL_ID, FromClient, "StartupMessage")]
        );
    }
}

#[test]
fn every_form_of_a_value_is_found_and_each_token_is_reported_once() {
    let mut harness = Harness::established(LIMIT);
    // The same token three times, and another in lower case.
    let row = format!(
        "{EMAIL}\t{EMAIL}\t\\x{}\t{}",
        hex(EMAIL),
        CANARY.to_lowercase()
    );
    harness.server(&data_row(row.as_bytes()));
    let mut hits = harness.hits();
    hits.sort_by(|a, b| a.token.cmp(&b.token));
    assert_eq!(
        hits,
        [
            hit(CANARY_ID, FromServer, "DataRow"),
            hit(EMAIL_ID, FromServer, "DataRow"),
        ]
    );
}

#[test]
fn traffic_without_a_value_raises_nothing_and_passes_unchanged() {
    let mut harness = Harness::established(LIMIT);
    let almost = &EMAIL[..EMAIL.len() - 1];
    let from_client = join(&[
        &frame(b'Q', format!("SELECT '{almost}'\0").as_bytes()),
        &bind(0, almost.as_bytes()),
        &frame(b'S', b""),
    ]);
    let from_server = join(&[&data_row(almost.as_bytes()), &frame(b'Z', b"I")]);
    harness.client(&from_client);
    harness.server(&from_server);
    assert_eq!(harness.to_server, from_client);
    assert_eq!(harness.to_client, from_server);
    assert_eq!(harness.effects, [Effect::QuerySeen]);

    // A policy without tokens finds nothing, even the values of another.
    let mut harness = Harness::established(LIMIT);
    harness.policy = policy_of(2, &[], LIMIT);
    harness.server(&data_row(EMAIL.as_bytes()));
    assert!(harness.effects.is_empty());
}

// ---------------------------------------------------------------------------
// Values in more than one piece
// ---------------------------------------------------------------------------

/// The value in two halves.
fn halves() -> (&'static [u8], &'static [u8]) {
    EMAIL.as_bytes().split_at(EMAIL.len() / 2)
}

fn copy_data(body: &[u8]) -> Vec<u8> {
    frame(b'd', body)
}

#[test]
fn a_value_split_across_two_copy_data_messages_is_found_in_both_directions() {
    let (first, second) = halves();

    // COPY ... TO STDOUT.
    let mut harness = Harness::established(LIMIT);
    harness.server(&frame(b'H', &[0, 0, 0]));
    harness.server(&copy_data(&join(&[b"7\t", first])));
    assert!(harness.hits().is_empty());
    harness.server(&copy_data(&join(&[second, b"\t\\N\n"])));
    assert_eq!(harness.hits(), [hit(EMAIL_ID, FromServer, "CopyData")]);

    // COPY ... FROM STDIN.
    let mut harness = Harness::established(LIMIT);
    harness.server(&frame(b'G', &[0, 0, 0]));
    harness.client(&copy_data(first));
    assert!(harness.hits().is_empty());
    harness.client(&copy_data(second));
    assert_eq!(harness.hits(), [hit(EMAIL_ID, FromClient, "CopyData")]);

    // One byte in each message, and both in one read.
    let mut harness = Harness::established(LIMIT);
    harness.server(&frame(b'H', &[0, 0, 0]));
    let messages: Vec<u8> = EMAIL.bytes().flat_map(|byte| copy_data(&[byte])).collect();
    harness.server(&messages);
    assert_eq!(harness.hits(), [hit(EMAIL_ID, FromServer, "CopyData")]);
}

#[test]
fn other_messages_between_two_copy_data_messages_do_not_hide_a_value() {
    let (first, second) = halves();
    let mut harness = Harness::established(LIMIT);
    harness.server(&frame(b'H', &[0, 0, 0]));
    harness.server(&copy_data(first));
    harness.server(&frame(b'N', b"SNOTICE\0C00000\0Mslow\0\0"));
    harness.server(&frame(b'S', b"TimeZone\0UTC\0"));
    harness.client(&frame(b'H', b""));
    harness.server(&copy_data(second));
    assert_eq!(harness.hits(), [hit(EMAIL_ID, FromServer, "CopyData")]);
}

#[test]
fn copy_data_sent_before_the_copy_is_announced_belongs_to_it() {
    let (first, second) = halves();
    let mut harness = Harness::established(LIMIT);
    harness.client(&frame(b'Q', b"COPY t FROM STDIN\0"));
    harness.client(&copy_data(first));
    harness.server(&frame(b'G', &[0, 0, 0]));
    harness.client(&copy_data(second));
    assert_eq!(harness.hits(), [hit(EMAIL_ID, FromClient, "CopyData")]);
}

#[test]
fn only_the_copy_data_of_one_copy_in_one_direction_is_joined() {
    let (first, second) = halves();

    // Two rows of a result are two values.
    let mut harness = Harness::established(LIMIT);
    harness.server(&data_row(first));
    harness.server(&data_row(second));
    // So are two statements.
    harness.client(&frame(b'Q', first));
    harness.client(&frame(b'Q', second));
    assert!(harness.hits().is_empty());

    // The server ends one COPY and begins another.
    let mut harness = Harness::established(LIMIT);
    harness.server(&frame(b'H', &[0, 0, 0]));
    harness.server(&copy_data(first));
    harness.server(&frame(b'c', b""));
    harness.server(&frame(b'H', &[0, 0, 0]));
    harness.server(&copy_data(second));
    assert!(harness.hits().is_empty());

    // The client ends one and the server announces another.
    for end in [frame(b'c', b""), frame(b'f', b"no\0")] {
        let mut harness = Harness::established(LIMIT);
        harness.server(&frame(b'G', &[0, 0, 0]));
        harness.client(&copy_data(first));
        harness.client(&end);
        harness.server(&frame(b'G', &[0, 0, 0]));
        harness.client(&copy_data(second));
        assert!(harness.hits().is_empty());
    }

    // An error ends a COPY in both directions.
    let mut harness = Harness::established(LIMIT);
    harness.server(&frame(b'W', &[0, 0, 0]));
    harness.server(&copy_data(first));
    harness.client(&copy_data(first));
    harness.server(&frame(b'E', b"SERROR\0C57014\0Mcancelled\0\0"));
    harness.server(&frame(b'W', &[0, 0, 0]));
    harness.server(&copy_data(second));
    harness.client(&copy_data(second));
    assert!(harness.hits().is_empty());

    // The two directions of one COPY are two streams.
    let mut harness = Harness::established(LIMIT);
    harness.server(&frame(b'W', &[0, 0, 0]));
    harness.server(&copy_data(first));
    harness.client(&copy_data(second));
    assert!(harness.hits().is_empty());
}

#[test]
fn a_value_split_across_tcp_reads_is_found() {
    // A message the session holds until it is complete.
    let row = data_row(format!("7\t{EMAIL}\tx").as_bytes());
    let mut harness = Harness::established(LIMIT);
    harness.one_byte_at_a_time(FromServer, &row);
    assert_eq!(harness.to_client, row);
    assert_eq!(harness.hits(), [hit(EMAIL_ID, FromServer, "DataRow")]);

    let statement = frame(b'Q', format!("SELECT '{EMAIL}'\0").as_bytes());
    let mut harness = Harness::established(LIMIT);
    harness.one_byte_at_a_time(FromClient, &statement);
    assert_eq!(harness.to_server, statement);
    assert_eq!(harness.statements(), 1);
    assert_eq!(harness.hits(), [hit(EMAIL_ID, FromClient, "Query")]);

    // A message too large to hold: every read is passed on as it arrives.
    let large = padded(b'D', LIMIT * 2, LIMIT);
    let mut harness = Harness::established(LIMIT);
    harness.one_byte_at_a_time(FromServer, &large);
    assert_eq!(harness.to_client, large);
    assert_eq!(harness.hits(), [hit(EMAIL_ID, FromServer, "DataRow")]);

    // The startup message.
    let mut harness = Harness::new(LIMIT);
    harness.one_byte_at_a_time(FromClient, &startup(&[(b"user", EMAIL.as_bytes())]));
    assert_eq!(
        harness.hits(),
        [hit(EMAIL_ID, FromClient, "StartupMessage")]
    );
}

/// A value in a message of `total` bytes on the wire, `before` bytes into
/// its body.
fn padded(tag: u8, total: usize, before: usize) -> Vec<u8> {
    let mut body = vec![b'.'; total - 5];
    body[before..before + EMAIL.len()].copy_from_slice(EMAIL.as_bytes());
    frame(tag, &body)
}

#[test]
fn a_value_split_across_the_chunks_of_a_large_message_is_found() {
    // Three times the limit, so the session never holds it.
    let total = LIMIT * 3;
    for tag in *b"Dd" {
        let name = if tag == b'D' { "DataRow" } else { "CopyData" };
        let message = padded(tag, total, LIMIT + 100);
        let value_at = 5 + LIMIT + 100;

        // One byte in each read: every chunk is one byte.
        let mut harness = Harness::established(LIMIT);
        harness.one_byte_at_a_time(FromServer, &message);
        assert_eq!(harness.to_client, message);
        assert_eq!(harness.hits(), [hit(EMAIL_ID, FromServer, name)]);

        // Every place the value can be cut in two.
        for cut in 1..EMAIL.len() {
            let (first, second) = message.split_at(value_at + cut);
            let mut harness = Harness::established(LIMIT);
            harness.server(first);
            assert!(harness.hits().is_empty(), "cut at {cut}");
            harness.server(second);
            assert_eq!(harness.to_client, message);
            assert_eq!(harness.hits(), [hit(EMAIL_ID, FromServer, name)]);
        }
    }

    // From the client, a statement.
    let message = padded(b'Q', total, LIMIT + 100);
    let mut harness = Harness::established(LIMIT);
    harness.one_byte_at_a_time(FromClient, &message);
    assert_eq!(harness.to_server, message);
    assert_eq!(harness.statements(), 1);
    assert_eq!(harness.hits(), [hit(EMAIL_ID, FromClient, "Query")]);
}

#[test]
fn a_large_copy_data_message_belongs_to_the_stream_of_its_copy() {
    let (first, second) = halves();
    let filler = vec![b'.'; LIMIT * 2];

    // Small, large, small: the value crosses each border.
    let mut harness = Harness::established(LIMIT);
    harness.server(&frame(b'H', &[0, 0, 0]));
    harness.server(&copy_data(first));
    harness.server(&copy_data(&join(&[second, &filler, first])));
    assert_eq!(harness.hits(), [hit(EMAIL_ID, FromServer, "CopyData")]);
    harness.server(&copy_data(second));
    assert_eq!(harness.hits(), [hit(EMAIL_ID, FromServer, "CopyData")]);

    // A COPY that ends while a large message of it is arriving takes the
    // rest of that message with it, and nothing after.
    let mut harness = Harness::established(LIMIT);
    harness.server(&frame(b'G', &[0, 0, 0]));
    let large = copy_data(&join(&[&filler, EMAIL.as_bytes(), &filler, first]));
    let (begun, rest) = large.split_at(5 + filler.len() + 7);
    harness.client(begun);
    harness.server(&frame(b'E', b"SERROR\0C22P04\0Mbad row\0\0"));
    harness.client(rest);
    assert_eq!(harness.hits(), [hit(EMAIL_ID, FromClient, "CopyData")]);
    harness.client(&copy_data(second));
    assert!(harness.hits().is_empty());
}

#[test]
fn a_value_is_found_just_below_and_just_above_the_limit_for_held_messages() {
    for total in [LIMIT - 1, LIMIT, LIMIT + 1, LIMIT + 2] {
        // At the very end of the message, and at its very beginning.
        for before in [total - 5 - EMAIL.len(), 0] {
            let message = padded(b'D', total, before);
            let mut harness = Harness::established(LIMIT);
            harness.server(&message);
            assert_eq!(harness.to_client, message);
            assert_eq!(
                harness.hits(),
                [hit(EMAIL_ID, FromServer, "DataRow")],
                "{total} bytes, the value after {before}"
            );
        }
    }
}

// ---------------------------------------------------------------------------
// The policy in force
// ---------------------------------------------------------------------------

#[test]
fn a_new_policy_applies_from_the_next_message_and_a_copy_keeps_its_own() {
    let (first, second) = halves();
    let without_email = policy_of(2, &[(CANARY_ID, CANARY, true)], LIMIT);

    // The next message is searched with the new matcher.
    let mut harness = Harness::established(LIMIT);
    harness.policy = without_email.clone();
    harness.server(&data_row(EMAIL.as_bytes()));
    assert!(harness.hits().is_empty());
    harness.server(&data_row(CANARY.as_bytes()));
    assert_eq!(harness.hits(), [hit(CANARY_ID, FromServer, "DataRow")]);

    // A COPY that has begun keeps the matcher it began with.
    let mut harness = Harness::established(LIMIT);
    harness.server(&frame(b'H', &[0, 0, 0]));
    harness.server(&copy_data(first));
    harness.policy = without_email.clone();
    harness.server(&copy_data(second));
    assert_eq!(harness.hits(), [hit(EMAIL_ID, FromServer, "CopyData")]);
    // The next COPY has the new one.
    harness.server(&frame(b'c', b""));
    harness.server(&frame(b'H', &[0, 0, 0]));
    harness.server(&copy_data(EMAIL.as_bytes()));
    assert!(harness.hits().is_empty());
    harness.server(&copy_data(CANARY.as_bytes()));
    assert_eq!(harness.hits(), [hit(CANARY_ID, FromServer, "CopyData")]);

    // So does a COPY that was announced under the old policy and has not
    // carried anything yet, and CopyData that no COPY announced.
    let mut harness = Harness::established(LIMIT);
    harness.client(&copy_data(first));
    harness.policy = without_email.clone();
    harness.client(&copy_data(second));
    harness.server(&frame(b'G', &[0, 0, 0]));
    harness.client(&copy_data(EMAIL.as_bytes()));
    assert!(harness.hits().is_empty());

    // A message that arrives in chunks keeps its matcher to its end.
    let message = padded(b'D', LIMIT * 2, LIMIT);
    let (begun, rest) = message.split_at(5 + LIMIT + 3);
    let mut harness = Harness::established(LIMIT);
    harness.server(begun);
    harness.policy = without_email;
    harness.server(rest);
    assert_eq!(harness.hits(), [hit(EMAIL_ID, FromServer, "DataRow")]);
}

// ---------------------------------------------------------------------------
// What a hit says, and what is counted
// ---------------------------------------------------------------------------

#[test]
fn a_hit_names_the_token_and_the_session_and_holds_no_value() {
    let mut harness = Harness::established(LIMIT);
    harness.client(&frame(b'Q', format!("SELECT '{EMAIL}'\0").as_bytes()));
    harness.client(&bind(1, &binary(EMAIL)));
    harness.server(&data_row(format!("\\x{}", hex(EMAIL)).as_bytes()));
    harness.server(&data_row(CANARY.to_lowercase().as_bytes()));
    // A COPY with half a value carried over.
    harness.server(&frame(b'H', &[0, 0, 0]));
    harness.server(&copy_data(halves().0));

    let first = harness.events()[0];
    assert_eq!(first.session_id, SessionId::from_u128(0x7e));
    assert_eq!(first.client_ip, "192.0.2.10".parse::<IpAddr>().unwrap());
    assert_eq!(first.client_port, 49_152);
    assert_eq!(first.db_user.as_deref(), Some("app"));
    assert_eq!(first.database.as_deref(), Some("shop"));
    assert_eq!(first.application_name.as_deref(), Some("psql"));
    // The statement is named by its fingerprint, and the text stays out.
    assert_eq!(
        first.query,
        Some(Query::from_statement(
            format!("SELECT '{EMAIL}'").as_bytes(),
            QueryRedaction::Fingerprint,
            &digest
        ))
    );
    assert_eq!(first.rows_so_far, None);

    assert_eq!(harness.events().len(), 4);
    let mut said = format!("{:?}", harness.effects);
    for body in harness.events() {
        said.push_str(&serde_json::to_string(body).unwrap());
    }
    let scanner = {
        let mut scanner = Scanner::new(Arc::new(digest));
        scanner.copy_started(FromServer);
        format!("{scanner:?}")
    };
    said.push_str(&scanner);
    let said = said.to_lowercase();
    assert!(said.contains(EMAIL_ID));
    for value in [EMAIL, CANARY] {
        let value = value.to_lowercase();
        for form in [value.clone(), hex(&value), value[..12].to_owned()] {
            assert!(!said.contains(&form), "an effect holds part of a value");
        }
    }
    assert!(!said.contains("select"), "an effect holds a statement");
}

#[test]
fn each_query_execute_and_function_call_is_counted_as_a_statement() {
    let mut harness = Harness::established(LIMIT);
    harness.client(&join(&[
        &frame(b'Q', b"SELECT 1\0"),
        &frame(b'P', b"s1\0SELECT $1\0\0\0"),
        &bind(0, b"1"),
        &frame(b'D', b"P\0"),
        &frame(b'E', b"\0\0\0\0\0"),
        &frame(b'E', b"\0\0\0\0\0"),
        &frame(b'S', b""),
        &frame(b'F', &[0, 0, 4, 0, 0, 0, 0, 0, 0, 0]),
        &frame(b'd', b"1\n"),
        &frame(b'H', b""),
    ]));
    assert_eq!(harness.statements(), 4);
    assert_eq!(harness.effects.len(), 4);

    // The server sends messages with the same type bytes. They are not
    // statements.
    let mut harness = Harness::established(LIMIT);
    harness.server(&join(&[
        &frame(b'E', b"SERROR\0C42601\0Msyntax\0\0"),
        &frame(b'Z', b"I"),
    ]));
    assert!(harness.effects.is_empty());
}
