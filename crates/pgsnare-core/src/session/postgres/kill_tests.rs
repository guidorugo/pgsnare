// SPDX-License-Identifier: Apache-2.0

//! Tests of `kill`: the message with the token goes no further, the client
//! is told what the database tells a session an administrator ends, the
//! query is cancelled and both connections are closed.

use pgsnare_proto::encode;

use crate::detect::{Matcher, TokenSpec};
use crate::extension::ProtocolSession as _;
use crate::policy::{
    Action, ActionSet, ActionSettings, Inspection, KillSettings, OnError, PolicySnapshot, SqlState,
    TokenId, TokenPolicy,
};
use crate::session::{Direction, Effect, Leg, Output, Report};

use super::messages::admin_shutdown;
use super::scan_tests::{
    CANARY, CANARY_ID, EMAIL, EMAIL_ID, Harness, LIMIT, data_row, frame, join, startup,
};

const PROCESS_ID: i32 = 4242;
const KEY: [u8; 4] = [9, 8, 7, 6];

fn kill() -> ActionSet {
    ActionSet::of(&[Action::Kill])
}

/// `EMAIL` is answered with `kill`, `CANARY` with `alert`.
fn policy(settings: KillSettings) -> PolicySnapshot {
    let tokens = [
        (EMAIL_ID, EMAIL, kill()),
        (CANARY_ID, CANARY, ActionSet::ALERT),
    ];
    let specs: Vec<TokenSpec> = tokens
        .iter()
        .map(|(id, value, _)| TokenSpec::new(*id, [*value]))
        .collect();
    let actions = ActionSettings {
        kill: settings,
        ..ActionSettings::default()
    };
    PolicySnapshot::builder()
        .inspection(Inspection::new(OnError::FailClosed, LIMIT))
        .tokens(tokens.iter().map(|(id, _, set)| {
            let mut token = TokenPolicy::new(TokenId::new(id).unwrap());
            token.actions = *set;
            token
        }))
        .actions(actions)
        .matcher(Matcher::build(&specs).unwrap())
        .build()
        .unwrap()
}

/// A session the database has accepted and given a cancel key.
fn session_with(settings: KillSettings) -> Harness {
    let mut harness = Harness::with_policy(policy(settings));
    harness.client(&startup(&[(b"user", b"app"), (b"database", b"shop")]));
    let mut out = Output::new();
    harness
        .session
        .on_report(
            Report::BackendConnected { tls: false },
            &harness.policy,
            &mut out,
        )
        .unwrap();
    let mut key = PROCESS_ID.to_be_bytes().to_vec();
    key.extend_from_slice(&KEY);
    harness.server(&join(&[
        &frame(b'R', &0u32.to_be_bytes()),
        &frame(b'K', &key),
        &frame(b'Z', b"I"),
    ]));
    assert!(harness.session.is_established());
    harness.to_client.clear();
    harness.to_server.clear();
    harness.effects.clear();
    harness
}

fn session() -> Harness {
    session_with(KillSettings::default())
}

fn fatal() -> Vec<u8> {
    let mut bytes = Vec::new();
    admin_shutdown(&mut bytes).unwrap();
    bytes
}

fn cancel() -> Vec<u8> {
    let mut bytes = Vec::new();
    encode::cancel_request(PROCESS_ID, &KEY, &mut bytes).unwrap();
    bytes
}

fn query(sql: &str) -> Vec<u8> {
    frame(b'Q', &join(&[sql.as_bytes(), b"\0"]))
}

fn bind(format: u16, value: &[u8]) -> Vec<u8> {
    let length = u32::try_from(value.len()).unwrap().to_be_bytes();
    frame(
        b'B',
        &join(&[
            b"\0\0",
            &[0, 1],
            &format.to_be_bytes(),
            &[0, 1],
            &length,
            value,
            &[0, 0],
        ]),
    )
}

/// What the effects since the last call end with, from the hit on: what
/// was counted, the event, and how the session ended.
fn ending(harness: &mut Harness) -> Vec<Effect> {
    let effects = std::mem::take(&mut harness.effects);
    let first = effects
        .iter()
        .position(|effect| matches!(effect, Effect::TokenHit { .. }))
        .unwrap();
    effects[first..].to_vec()
}

fn killed_hit(harness: &Harness) -> Vec<Effect> {
    let event = harness
        .effects
        .iter()
        .find(|effect| matches!(effect, Effect::Emit(_)))
        .unwrap()
        .clone();
    let Effect::Emit(body) = &event else {
        unreachable!()
    };
    assert_eq!(body.action_taken, kill());
    vec![
        Effect::TokenHit {
            token_id: TokenId::new(EMAIL_ID).unwrap(),
            exempt: false,
            decided: kill(),
            actions: kill(),
        },
        event,
        Effect::Cancel { request: cancel() },
        Effect::Close(Leg::Client),
        Effect::Close(Leg::Backend),
    ]
}

/// Nothing more passes in either direction.
fn assert_over(harness: &mut Harness) {
    let (to_client, to_server) = (harness.to_client.len(), harness.to_server.len());
    harness.client(&query("SELECT 1"));
    harness.server(&data_row(b"later"));
    assert_eq!(
        (harness.to_client.len(), harness.to_server.len()),
        (to_client, to_server)
    );
    assert!(harness.effects.is_empty());
}

#[test]
fn a_row_with_a_token_never_reaches_the_client_and_the_session_ends() {
    let mut harness = session();
    harness.client(&query("SELECT name FROM users"));
    harness.to_server.clear();
    let before = data_row(b"first");
    harness.server(&join(&[
        &before,
        &data_row(EMAIL.as_bytes()),
        &frame(b'C', b"SELECT 2\0"),
        &frame(b'Z', b"I"),
    ]));
    assert_eq!(harness.to_client, join(&[&before, &fatal()]));
    let expected = killed_hit(&harness);
    assert_eq!(ending(&mut harness), expected);
    assert_over(&mut harness);
}

#[test]
fn a_token_the_client_sends_never_reaches_the_server() {
    for format in [0, 1] {
        let mut harness = session();
        let parse = frame(b'P', b"\0SELECT $1\0\0\0");
        let value = join(&[&[0xff, 0x00], EMAIL.as_bytes(), &[0x80]]);
        harness.client(&join(&[
            &parse,
            &bind(format, &value),
            &frame(b'E', b"\0\0\0\0\0"),
            &frame(b'S', b""),
        ]));
        assert_eq!(harness.to_server, parse);
        assert_eq!(harness.to_client, fatal());
        let expected = killed_hit(&harness);
        assert_eq!(ending(&mut harness), expected);
        assert_over(&mut harness);
    }

    let mut harness = session();
    harness.client(&query(&format!("SELECT '{EMAIL}'")));
    assert!(harness.to_server.is_empty());
    assert_eq!(harness.to_client, fatal());
}

#[test]
fn a_token_split_across_copy_data_ends_the_copy_in_both_directions() {
    let (head, tail) = EMAIL.as_bytes().split_at(7);

    // From the client.
    let mut harness = session();
    harness.client(&query("COPY users FROM STDIN"));
    harness.server(&frame(b'G', &[0, 0, 1, 0, 0]));
    harness.to_server.clear();
    harness.to_client.clear();
    let first = frame(b'd', head);
    harness.client(&join(&[&first, &frame(b'd', tail), &frame(b'c', b"")]));
    assert_eq!(harness.to_server, first);
    assert_eq!(harness.to_client, fatal());
    let expected = killed_hit(&harness);
    assert_eq!(ending(&mut harness), expected);
    assert_over(&mut harness);

    // From the server.
    let mut harness = session();
    harness.client(&query("COPY users TO STDOUT"));
    harness.server(&frame(b'H', &[0, 0, 1, 0, 0]));
    harness.to_client.clear();
    let first = frame(b'd', head);
    harness.server(&join(&[&first, &frame(b'd', tail), &frame(b'c', b"")]));
    assert_eq!(harness.to_client, join(&[&first, &fatal()]));
    let expected = killed_hit(&harness);
    assert_eq!(ending(&mut harness), expected);
    assert_over(&mut harness);
}

#[test]
fn a_token_at_startup_is_answered_before_the_database_is_reached() {
    let mut harness = Harness::with_policy(policy(KillSettings::default()));
    harness.client(&startup(&[(b"user", EMAIL.as_bytes())]));
    assert_eq!(harness.to_client, fatal());
    assert!(harness.to_server.is_empty());
    assert!(!harness.effects.contains(&Effect::ConnectBackend));
    let tail: Vec<Effect> = ending(&mut harness).into_iter().skip(2).collect();
    assert_eq!(
        tail,
        [Effect::Close(Leg::Client), Effect::Close(Leg::Backend)]
    );
}

#[test]
fn a_message_the_client_has_received_in_part_ends_without_an_error() {
    let mut harness = session();
    harness.client(&query("SELECT name FROM users"));
    let row = data_row(&join(&[&vec![b'x'; LIMIT * 2], EMAIL.as_bytes()]));
    let (start, rest) = row.split_at(LIMIT);
    harness.server(start);
    assert!(!harness.to_client.is_empty());
    harness.server(rest);
    // What the client received is the start of the row and nothing else:
    // an error would be read as part of the row.
    assert!(row.starts_with(&harness.to_client));
    assert!(harness.to_client.len() < row.len());
    let expected = killed_hit(&harness);
    assert_eq!(ending(&mut harness), expected);
    assert_over(&mut harness);
}

#[test]
fn every_hit_of_the_message_is_raised_and_the_configured_error_is_sent() {
    let settings = KillSettings::new(
        "XX000".parse::<SqlState>().unwrap(),
        "server closed the connection".to_owned(),
    );
    let mut harness = session_with(settings);
    harness.client(&query("SELECT name FROM users"));
    // An `alert` alone passes.
    let alerted = data_row(CANARY.as_bytes());
    harness.server(&alerted);
    assert_eq!(harness.to_client, alerted);
    harness.to_client.clear();
    harness.effects.clear();

    harness.server(&data_row(format!("{EMAIL} {CANARY}").as_bytes()));
    let mut expected = Vec::new();
    encode::error_response(
        &[
            (b'S', b"FATAL"),
            (b'V', b"FATAL"),
            (b'C', b"XX000"),
            (b'M', b"server closed the connection"),
        ],
        &mut expected,
    )
    .unwrap();
    assert_eq!(harness.to_client, expected);
    let counted: Vec<ActionSet> = harness
        .effects
        .iter()
        .filter_map(|effect| match effect {
            Effect::TokenHit { actions, .. } => Some(*actions),
            _ => None,
        })
        .collect();
    assert_eq!(counted, [kill(), ActionSet::ALERT]);
    assert_eq!(harness.effects.last(), Some(&Effect::Close(Leg::Backend)));
}

#[test]
fn a_decision_for_a_response_not_built_is_carried_out_as_an_alert() {
    let specs = [TokenSpec::new(EMAIL_ID, [EMAIL])];
    let mut token = TokenPolicy::new(TokenId::new(EMAIL_ID).unwrap());
    token.actions = ActionSet::of(&[Action::Tarpit, Action::FakeData]);
    let policy = PolicySnapshot::builder()
        .inspection(Inspection::new(OnError::FailClosed, LIMIT))
        .token(token)
        .matcher(Matcher::build(&specs).unwrap())
        .build()
        .unwrap();
    let mut harness = Harness::logged_in(policy, &[(b"user", b"app")]);
    harness.effects.clear();
    let row = data_row(EMAIL.as_bytes());
    harness.bytes(Direction::FromServer, &row);
    assert_eq!(harness.to_client, row);
    assert!(harness.effects.iter().any(|effect| matches!(
        effect,
        Effect::TokenHit { actions, .. } if *actions == ActionSet::ALERT
    )));
}
