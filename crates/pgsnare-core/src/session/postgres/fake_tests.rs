// SPDX-License-Identifier: Apache-2.0

//! Tests of `fake_data`: made-up rows at the end of a text result with a
//! known description, the row count raised to match, and `alert` in every
//! case where rows cannot be added safely.

use std::cell::Cell;
use std::sync::Arc;

use crate::actions::TarpitPlaces;
use crate::detect::{Matcher, TokenSpec};
use crate::policy::{
    Action, ActionSet, ActionSettings, FakeDataSettings, Inspection, KillSettings, OnError,
    PolicySnapshot, TarpitSettings, TokenId, TokenPolicy,
};
use crate::session::Effect;

use super::scan_tests::{EMAIL, EMAIL_ID, Harness, LIMIT, data_row, frame, join};
use super::tarpit_tests::session_in;
use super::track::{QUERIES_MADE, SINGLE_SELECT_SCANS};

const ADDED: u32 = 3;
const INT4: u32 = 23;
const TEXT: u32 = 25;
const VARCHAR: u32 = 1043;
const UUID: u32 = 2950;
const SELECT: &str = "SELECT id, name, email, password, ref FROM users";

fn set(actions: &[Action]) -> ActionSet {
    ActionSet::of(actions)
}

fn policy(actions: ActionSet, rows: u32) -> PolicySnapshot {
    let mut token = TokenPolicy::new(TokenId::new(EMAIL_ID).unwrap());
    token.actions = actions;
    PolicySnapshot::builder()
        .inspection(Inspection::new(OnError::FailClosed, LIMIT))
        .token(token)
        .actions(ActionSettings::new(
            KillSettings::default(),
            TarpitSettings::default(),
            FakeDataSettings::new(rows),
        ))
        .matcher(Matcher::build(&[TokenSpec::new(EMAIL_ID, [EMAIL])]).unwrap())
        .build()
        .unwrap()
}

fn session(actions: ActionSet) -> Harness {
    session_in(&Arc::new(TarpitPlaces::new()), policy(actions, ADDED))
}

/// A `RowDescription` of columns given as name, type, modifier and format.
fn description(columns: &[(&str, u32, i32, i16)]) -> Vec<u8> {
    let mut body = i16::try_from(columns.len()).unwrap().to_be_bytes().to_vec();
    for (name, oid, modifier, format) in columns {
        body.extend_from_slice(name.as_bytes());
        body.push(0);
        body.extend_from_slice(&16_384u32.to_be_bytes());
        body.extend_from_slice(&1i16.to_be_bytes());
        body.extend_from_slice(&oid.to_be_bytes());
        body.extend_from_slice(&(-1i16).to_be_bytes());
        body.extend_from_slice(&modifier.to_be_bytes());
        body.extend_from_slice(&format.to_be_bytes());
    }
    frame(b'T', &body)
}

fn users(format: i16) -> Vec<u8> {
    description(&[
        ("id", INT4, -1, 0),
        ("name", TEXT, -1, 0),
        ("email", VARCHAR, 64 + 4, 0),
        ("password", TEXT, -1, format),
        ("ref", UUID, -1, 0),
    ])
}

fn row(values: &[Option<&str>]) -> Vec<u8> {
    let mut body = i16::try_from(values.len()).unwrap().to_be_bytes().to_vec();
    for value in values {
        match value {
            Some(text) => {
                body.extend_from_slice(&u32::try_from(text.len()).unwrap().to_be_bytes());
                body.extend_from_slice(text.as_bytes());
            }
            None => body.extend_from_slice(&(-1i32).to_be_bytes()),
        }
    }
    frame(b'D', &body)
}

const UUID_A: &str = "0f8a1c52-7d3e-4b6a-9c21-5e4f3a2b1c0d";

/// The rows of the result: two plain ones, then the token in a row whose
/// name appears nowhere else.
fn rows() -> Vec<u8> {
    join(&[
        &row(&[
            Some("1"),
            Some("alice"),
            Some("alice@example.com"),
            Some("x1"),
            Some(UUID_A),
        ]),
        &row(&[
            Some("2"),
            Some("bob"),
            Some("bob@example.org"),
            None,
            Some(UUID_A),
        ]),
        &row(&[
            Some("7"),
            Some("mallory"),
            Some(EMAIL),
            Some("x3"),
            Some(UUID_A),
        ]),
    ])
}

fn complete(tag: &str) -> Vec<u8> {
    frame(b'C', &join(&[tag.as_bytes(), b"\0"]))
}

fn query(sql: &str) -> Vec<u8> {
    frame(b'Q', &join(&[sql.as_bytes(), b"\0"]))
}

/// The messages in `bytes`, as type and body.
fn messages(bytes: &[u8]) -> Vec<(u8, Vec<u8>)> {
    let mut all = Vec::new();
    let mut rest = bytes;
    while let Some((&tag, after)) = rest.split_first() {
        let length = usize::try_from(u32::from_be_bytes(after[..4].try_into().unwrap())).unwrap();
        all.push((tag, after[4..length].to_vec()));
        rest = &after[length..];
    }
    all
}

/// The fields of a `DataRow` body, as text.
fn fields(body: &[u8]) -> Vec<Option<String>> {
    let count = usize::from(u16::from_be_bytes([body[0], body[1]]));
    let mut rest = &body[2..];
    let mut all = Vec::new();
    for _ in 0..count {
        let length = i32::from_be_bytes(rest[..4].try_into().unwrap());
        rest = &rest[4..];
        if length < 0 {
            all.push(None);
        } else {
            let length = usize::try_from(length).unwrap();
            all.push(Some(String::from_utf8(rest[..length].to_vec()).unwrap()));
            rest = &rest[length..];
        }
    }
    all
}

fn actions_taken(harness: &Harness) -> Vec<ActionSet> {
    harness
        .effects
        .iter()
        .filter_map(|effect| match effect {
            Effect::TokenHit { actions, .. } => Some(*actions),
            _ => None,
        })
        .collect()
}

/// Runs `sql` against a server that answers with `answer`, and returns
/// the data rows and the command tag the client got.
fn run(harness: &mut Harness, sql: &str, answer: &[u8]) -> (Vec<Vec<Option<String>>>, String) {
    harness.client(&query(sql));
    harness.server(answer);
    let mut data = Vec::new();
    let mut tag = String::new();
    for (kind, body) in messages(&harness.to_client) {
        match kind {
            b'D' => data.push(fields(&body)),
            b'C' => tag = String::from_utf8(body[..body.len() - 1].to_vec()).unwrap(),
            _ => {}
        }
    }
    (data, tag)
}

fn answer(head: &[u8], tag: &str) -> Vec<u8> {
    join(&[head, &rows(), &complete(tag), &frame(b'Z', b"I")])
}

#[test]
fn rows_are_added_before_the_end_of_the_result_and_counted() {
    let mut harness = session(set(&[Action::FakeData]));
    let (data, tag) = run(&mut harness, SELECT, &answer(&users(0), "SELECT 3"));
    assert_eq!(actions_taken(&harness), [set(&[Action::FakeData])]);
    assert_eq!(data.len(), 6);
    assert_eq!(tag, "SELECT 6");

    for (number, fake) in data[3..].iter().enumerate() {
        assert_eq!(fake.len(), 5, "every column");
        // A new id above every id of the result, so none repeats.
        assert_eq!(fake[0].as_deref(), Some(["8", "9", "10"][number]));
        // Recombined from the clean rows only.
        assert!(matches!(fake[1].as_deref(), Some("alice" | "bob")));
        let email = fake[2].as_deref().unwrap();
        assert!(
            email.ends_with("@example.com") || email.ends_with("@example.org"),
            "{email}"
        );
        assert!(email.len() <= 64);
        assert!(fake[3].as_deref().unwrap().starts_with("$2"), "bcrypt bait");
        let uuid = fake[4].as_deref().unwrap();
        assert_eq!(uuid.len(), 36);
        assert_eq!(uuid.as_bytes()[14], b'4');
        assert_ne!(uuid, UUID_A);
    }
    let all = String::from_utf8_lossy(&harness.to_client).into_owned();
    assert_eq!(
        all.matches(EMAIL).count(),
        1,
        "the token only in its own row"
    );
    assert_eq!(
        all.matches("mallory").count(),
        1,
        "nothing sampled from a hit"
    );
}

#[test]
fn fake_data_with_alert_adds_rows_and_reports_both() {
    let mut harness = session(set(&[Action::FakeData, Action::Alert]));
    let (data, tag) = run(&mut harness, SELECT, &answer(&users(0), "SELECT 3"));
    assert_eq!(
        actions_taken(&harness),
        [set(&[Action::FakeData, Action::Alert])]
    );
    assert_eq!((data.len(), tag.as_str()), (6, "SELECT 6"));
}

#[test]
fn kill_with_fake_data_only_kills() {
    let mut harness = session(set(&[Action::FakeData, Action::Kill]));
    let (data, _) = run(&mut harness, SELECT, &answer(&users(0), "SELECT 3"));
    assert_eq!(actions_taken(&harness), [set(&[Action::Kill])]);
    assert_eq!(data.len(), 2, "the token row and nothing after it");
    assert!(harness.session.is_closed());
}

/// A case where rows cannot be added: the hit is answered with `alert`
/// and the client gets the result as the server sent it.
fn falls_back(harness: &mut Harness, sql: &str, answer: &[u8], rows: usize, tag: &str) {
    let (data, got) = run(harness, sql, answer);
    assert_eq!(actions_taken(harness), [ActionSet::ALERT]);
    assert_eq!(data.len(), rows);
    assert_eq!(got, tag);
}

#[test]
fn a_binary_column_falls_back_to_alert() {
    let mut harness = session(set(&[Action::FakeData]));
    falls_back(
        &mut harness,
        SELECT,
        &answer(&users(1), "SELECT 3"),
        3,
        "SELECT 3",
    );
}

#[test]
fn rows_with_no_description_fall_back_to_alert() {
    let mut harness = session(set(&[Action::FakeData]));
    falls_back(
        &mut harness,
        SELECT,
        &answer(b"", "SELECT 3"),
        3,
        "SELECT 3",
    );
}

#[test]
fn a_description_of_a_prepared_statement_falls_back_to_alert() {
    // Results asked for in binary would be described as text there.
    let mut harness = session(set(&[Action::FakeData]));
    let parse = frame(b'P', &join(&[b"\0", SELECT.as_bytes(), b"\0\0\0"]));
    let describe = frame(b'D', b"S\0");
    let bind = frame(b'B', &[0, 0, 0, 0, 0, 0, 0, 0]);
    let execute = frame(b'E', &[0, 0, 0, 0, 0]);
    harness.client(&join(&[
        &parse,
        &describe,
        &bind,
        &execute,
        &frame(b'S', b""),
    ]));
    let answer = join(&[
        &frame(b'1', b""),
        &frame(b't', &[0, 0]),
        &users(0),
        &frame(b'2', b""),
        &rows()[..],
        &complete("SELECT 3"),
        &frame(b'Z', b"I"),
    ]);
    harness.server(&answer);
    assert_eq!(actions_taken(&harness), [ActionSet::ALERT]);
    let tags: Vec<u8> = messages(&harness.to_client)
        .iter()
        .map(|(kind, _)| *kind)
        .collect();
    assert_eq!(tags, b"1tT2DDDCZ");
}

#[test]
fn a_statement_that_is_not_one_select_falls_back_to_alert() {
    for sql in [
        "DELETE FROM users RETURNING *",
        "SELECT 1; DELETE FROM users RETURNING *",
        "/* x */ SELECT * FROM users",
        "FETCH ALL FROM c",
    ] {
        let mut harness = session(set(&[Action::FakeData]));
        falls_back(
            &mut harness,
            sql,
            &answer(&users(0), "SELECT 3"),
            3,
            "SELECT 3",
        );
    }
}

#[test]
fn a_command_tag_other_than_select_adds_nothing() {
    let mut harness = session(set(&[Action::FakeData]));
    let (data, tag) = run(&mut harness, SELECT, &answer(&users(0), "FETCH 3"));
    assert_eq!((data.len(), tag.as_str()), (3, "FETCH 3"));
}

#[test]
fn a_result_asked_for_in_parts_falls_back_to_alert() {
    let mut harness = session(set(&[Action::FakeData]));
    let parse = frame(b'P', &join(&[b"\0", SELECT.as_bytes(), b"\0\0\0"]));
    let bind = frame(b'B', &[0, 0, 0, 0, 0, 0, 0, 0]);
    let describe = frame(b'D', b"P\0");
    let execute = frame(b'E', &[0, 0, 0, 0, 2]);
    harness.client(&join(&[
        &parse,
        &bind,
        &describe,
        &execute,
        &frame(b'S', b""),
    ]));
    let answer = join(&[
        &frame(b'1', b""),
        &frame(b'2', b""),
        &users(0),
        &rows()[..],
        &frame(b's', b""),
        &frame(b'Z', b"I"),
    ]);
    harness.server(&answer);
    assert_eq!(actions_taken(&harness), [ActionSet::ALERT]);
    let data = messages(&harness.to_client)
        .iter()
        .filter(|(kind, _)| *kind == b'D')
        .count();
    assert_eq!(data, 3);
}

#[test]
fn the_extended_protocol_with_all_rows_gets_rows() {
    let mut harness = session(set(&[Action::FakeData]));
    let parse = frame(b'P', &join(&[b"\0", SELECT.as_bytes(), b"\0\0\0"]));
    let bind = frame(b'B', &[0, 0, 0, 0, 0, 0, 0, 0]);
    let describe = frame(b'D', b"P\0");
    let execute = frame(b'E', &[0, 0, 0, 0, 0]);
    harness.client(&join(&[
        &parse,
        &bind,
        &describe,
        &execute,
        &frame(b'S', b""),
    ]));
    let answer = join(&[
        &frame(b'1', b""),
        &frame(b'2', b""),
        &answer(&users(0), "SELECT 3"),
    ]);
    harness.server(&answer);
    assert_eq!(actions_taken(&harness), [set(&[Action::FakeData])]);
    let tags: Vec<u8> = messages(&harness.to_client)
        .iter()
        .map(|(kind, _)| *kind)
        .collect();
    assert_eq!(tags, b"12TDDDDDDCZ");
}

#[test]
fn many_rows_stay_within_the_bound_and_the_count_matches() {
    let mut harness = session_in(
        &Arc::new(TarpitPlaces::new()),
        policy(set(&[Action::FakeData]), FakeDataSettings::MAX_ROWS),
    );
    let big = "y".repeat(1000);
    let answer = join(&[
        &description(&[("note", TEXT, -1, 0)]),
        &row(&[Some(big.as_str())]),
        &row(&[Some(EMAIL)]),
        &complete("SELECT 2"),
        &frame(b'Z', b"I"),
    ]);
    let (data, tag) = run(&mut harness, "SELECT note FROM notes", &answer);
    assert!(harness.to_client.len() <= 8 * 1024 * 1024 + 64 * 1024);
    assert!(data.len() > 1000);
    assert_eq!(tag, format!("SELECT {}", data.len()));
}

#[test]
fn a_scanner_without_responses_answers_fake_data_with_alert() {
    let mut harness = Harness::logged_in(
        policy(set(&[Action::FakeData]), ADDED),
        &[(b"user", b"app")],
    );
    harness.effects.clear();
    falls_back(
        &mut harness,
        SELECT,
        &answer(&users(0), "SELECT 3"),
        3,
        "SELECT 3",
    );
}

#[test]
fn tarpit_with_fake_data_adds_rows_and_holds_them_back() {
    let mut harness = session(set(&[Action::FakeData, Action::Tarpit]));
    let (data, tag) = run(&mut harness, SELECT, &answer(&users(0), "SELECT 3"));
    assert_eq!(
        actions_taken(&harness),
        [set(&[Action::FakeData, Action::Tarpit])]
    );
    assert_eq!((data.len(), tag.as_str()), (6, "SELECT 6"));
    assert!(
        harness
            .effects
            .iter()
            .any(|effect| matches!(effect, Effect::Delay(_)))
    );
}

#[test]
fn escalation_turns_alert_into_fake_data() {
    let mut token = TokenPolicy::new(TokenId::new(EMAIL_ID).unwrap());
    token.escalate = Some(crate::policy::Escalation::new(2, set(&[Action::FakeData])));
    let mut snapshot = policy(ActionSet::ALERT, ADDED);
    snapshot = PolicySnapshot::builder()
        .inspection(Inspection::new(OnError::FailClosed, LIMIT))
        .token(token)
        .actions(snapshot.actions().clone())
        .matcher(Matcher::build(&[TokenSpec::new(EMAIL_ID, [EMAIL])]).unwrap())
        .build()
        .unwrap();
    let mut harness = session_in(&Arc::new(TarpitPlaces::new()), snapshot);
    let (first, _) = run(&mut harness, SELECT, &answer(&users(0), "SELECT 3"));
    assert_eq!(first.len(), 3);
    harness.to_client.clear();
    let (second, tag) = run(&mut harness, SELECT, &answer(&users(0), "SELECT 3"));
    assert_eq!(
        actions_taken(&harness),
        [ActionSet::ALERT, set(&[Action::FakeData])]
    );
    assert_eq!((second.len(), tag.as_str()), (6, "SELECT 6"));
}

#[test]
fn a_held_statement_is_searched_for_its_kind_once() {
    let mut harness = session(set(&[Action::FakeData]));
    let before = SINGLE_SELECT_SCANS.with(Cell::get);
    let (data, tag) = run(&mut harness, SELECT, &answer(&users(0), "SELECT 3"));
    assert_eq!((data.len(), tag.as_str()), (6, "SELECT 6"), "rows added");
    assert_eq!(
        SINGLE_SELECT_SCANS.with(Cell::get) - before,
        1,
        "once for the statement, not once for each row"
    );
}

#[test]
fn the_query_of_a_held_statement_is_made_once() {
    let mut harness = session(set(&[Action::Alert]));
    let before = QUERIES_MADE.with(Cell::get);
    let hit = data_row(EMAIL.as_bytes());
    harness.client(&query(SELECT));
    harness.server(&join(&[
        &users(0),
        &hit,
        &hit,
        &hit,
        &complete("SELECT 3"),
        &frame(b'Z', b"I"),
    ]));
    let events = harness.events();
    assert_eq!(events.len(), 3, "one event for each hit");
    assert!(events[0].query.as_ref().is_some_and(|query| query.known));
    assert!(events.iter().all(|event| event.query == events[0].query));
    assert_eq!(
        QUERIES_MADE.with(Cell::get) - before,
        1,
        "once for the statement, not once for each hit"
    );
}
