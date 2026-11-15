// SPDX-License-Identifier: Apache-2.0

//! Tests of `fake_data`: made-up rows at the end of a text result with a
//! known description, the row count raised to match, and `alert` in every
//! case where rows cannot be added safely.

use std::cell::Cell;
use std::sync::Arc;

use crate::actions::TarpitPlaces;
use crate::detect::{Matcher, TokenSpec};
use crate::event::EventKind;
use crate::extension::ProtocolSession;
use crate::policy::{
    Action, ActionSet, ActionSettings, FakeDataSettings, Inspection, KillSettings, OnError,
    PolicySnapshot, TarpitSettings, TokenId, TokenPolicy,
};
use crate::session::{Direction, Effect, Output, Report};

use super::scan_tests::{
    CANARY, CANARY_ID, EMAIL, EMAIL_ID, Harness, LIMIT, data_row, frame, join,
};
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
pub(super) fn description(columns: &[(&str, u32, i32, i16)]) -> Vec<u8> {
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

/// A case where rows cannot be added: the hit is answered with `alert`,
/// its count and its event say so, once, and the client gets the result
/// as the server sent it.
fn falls_back(harness: &mut Harness, sql: &str, answer: &[u8], rows: usize, tag: &str) {
    let (data, got) = run(harness, sql, answer);
    assert_eq!(reports(harness), [ActionSet::ALERT]);
    assert_eq!(data.len(), rows);
    assert_eq!(got, tag);
    assert_eq!(
        harness.to_client, answer,
        "the result as the server sent it"
    );
    due(harness);
    assert_eq!(reports(harness).len(), 1, "reported once");
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
fn a_command_tag_other_than_select_falls_back_to_alert() {
    let mut harness = session(set(&[Action::FakeData]));
    falls_back(
        &mut harness,
        SELECT,
        &answer(&users(0), "FETCH 3"),
        3,
        "FETCH 3",
    );
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

// ---------------------------------------------------------------------------
// What the report of a hit says, and when it leaves
// ---------------------------------------------------------------------------

/// The responses each hit reported so far says were carried out, in the
/// order the reports left. The count and the event of a hit must agree.
fn reports(harness: &Harness) -> Vec<ActionSet> {
    let said: Vec<ActionSet> = harness
        .events()
        .iter()
        .filter(|event| event.kind == EventKind::TokenHit)
        .map(|event| event.action_taken)
        .collect();
    assert_eq!(actions_taken(harness), said, "a count and its event");
    said
}

/// The tokens of the hits reported so far, in the order the reports left.
fn reported(harness: &Harness) -> Vec<String> {
    harness
        .events()
        .iter()
        .filter(|event| event.kind == EventKind::TokenHit)
        .map(|event| event.token_id.as_ref().unwrap().as_str().to_owned())
        .collect()
}

/// The runtime says that a report must not wait any longer, or that the
/// session is over.
fn due(harness: &mut Harness) {
    let mut out = Output::new();
    harness
        .session
        .on_report(Report::EventDue, &harness.policy, &mut out)
        .unwrap();
    assert!(out.to_client.is_empty() && out.to_server.is_empty());
    harness.effects.append(&mut out.effects);
}

/// How often the session said that it keeps a report back.
fn kept_back(harness: &Harness) -> usize {
    harness
        .effects
        .iter()
        .filter(|effect| matches!(effect, Effect::EventHeld))
        .count()
}

/// The data rows and the command tag the client has been sent.
fn result(harness: &Harness) -> (usize, String) {
    let mut rows = 0;
    let mut tag = String::new();
    for (kind, body) in messages(&harness.to_client) {
        match kind {
            b'D' => rows += 1,
            b'C' => tag = String::from_utf8(body[..body.len() - 1].to_vec()).unwrap(),
            _ => {}
        }
    }
    (rows, tag)
}

fn end(tag: &str) -> Vec<u8> {
    join(&[&complete(tag), &frame(b'Z', b"I")])
}

/// A session of a policy with two tokens: the email address answered
/// with `fake_data`, and the canary answered with `other`.
fn session_with_two_tokens(other: ActionSet) -> Harness {
    let mut email = TokenPolicy::new(TokenId::new(EMAIL_ID).unwrap());
    email.actions = set(&[Action::FakeData]);
    let mut canary = TokenPolicy::new(TokenId::new(CANARY_ID).unwrap());
    canary.actions = other;
    let snapshot = PolicySnapshot::builder()
        .inspection(Inspection::new(OnError::FailClosed, LIMIT))
        .token(email)
        .token(canary)
        .actions(ActionSettings::new(
            KillSettings::default(),
            TarpitSettings::default(),
            FakeDataSettings::new(ADDED),
        ))
        .matcher(
            Matcher::build(&[
                TokenSpec::new(EMAIL_ID, [EMAIL]),
                TokenSpec::new(CANARY_ID, [CANARY]),
            ])
            .unwrap(),
        )
        .build()
        .unwrap();
    session_in(&Arc::new(TarpitPlaces::new()), snapshot)
}

fn row_with(id: &str, name: &str, email: &str) -> Vec<u8> {
    row(&[Some(id), Some(name), Some(email), Some("x9"), Some(UUID_A)])
}

#[test]
fn the_report_of_a_hit_waits_for_the_end_of_its_result_and_leaves_once() {
    let mut harness = session(set(&[Action::FakeData]));
    harness.client(&query(SELECT));
    harness.server(&join(&[&users(0), &rows()]));
    assert!(reports(&harness).is_empty(), "nothing can be said yet");
    assert_eq!(kept_back(&harness), 1, "the runtime is told to keep time");

    harness.server(&end("SELECT 3"));
    assert_eq!(reports(&harness), [set(&[Action::FakeData])]);
    assert_eq!(result(&harness), (6, "SELECT 6".to_owned()));
    let event = harness.events()[0];
    assert_eq!(event.token_id.as_ref().unwrap().as_str(), EMAIL_ID);
    assert_eq!(event.message_type.as_deref(), Some("DataRow"));

    // Nothing is left to hand over, whenever the runtime asks.
    due(&mut harness);
    due(&mut harness);
    assert_eq!(reports(&harness).len(), 1);
    assert_eq!(kept_back(&harness), 1);
}

#[test]
fn a_result_without_a_clean_row_falls_back_to_alert() {
    // Nothing to draw the name of a made-up row from.
    let mut harness = session(set(&[Action::FakeData]));
    let answer = join(&[
        &users(0),
        &row_with("7", "mallory", EMAIL),
        &end("SELECT 1"),
    ]);
    falls_back(&mut harness, SELECT, &answer, 1, "SELECT 1");
}

#[test]
fn a_row_that_does_not_fit_the_description_falls_back_to_alert() {
    let mut harness = session(set(&[Action::FakeData]));
    let answer = join(&[
        &users(0),
        &rows(),
        &row(&[Some("8"), Some("carol")]),
        &end("SELECT 4"),
    ]);
    falls_back(&mut harness, SELECT, &answer, 4, "SELECT 4");
}

#[test]
fn an_id_that_is_not_a_number_falls_back_to_alert() {
    let mut harness = session(set(&[Action::FakeData]));
    let answer = join(&[
        &users(0),
        &rows(),
        &row_with("eight", "carol", "carol@example.com"),
        &end("SELECT 4"),
    ]);
    falls_back(&mut harness, SELECT, &answer, 4, "SELECT 4");
}

#[test]
fn a_result_that_ends_with_an_error_falls_back_to_alert() {
    let mut harness = session(set(&[Action::FakeData]));
    let answer = join(&[
        &users(0),
        &rows(),
        &frame(b'E', b"SERROR\0C57014\0Mcancelled\0\0"),
        &frame(b'Z', b"I"),
    ]);
    falls_back(&mut harness, SELECT, &answer, 3, "");
}

#[test]
fn a_row_that_arrives_in_chunks_falls_back_to_alert() {
    // The row is not sampled, so an id in it could be repeated.
    let mut harness = session(set(&[Action::FakeData]));
    let large = "y".repeat(LIMIT);
    let answer = join(&[
        &users(0),
        &rows(),
        &row_with("8", &large, "carol@example.com"),
        &end("SELECT 4"),
    ]);
    harness.client(&query(SELECT));
    harness.server(&join(&[&users(0), &rows()]));
    assert!(reports(&harness).is_empty());
    // The report leaves with the header of the row, before its body.
    let header_of_large = users(0).len() + rows().len() + 5;
    harness.server(&answer[users(0).len() + rows().len()..header_of_large]);
    assert_eq!(reports(&harness), [ActionSet::ALERT]);
    harness.server(&answer[header_of_large..]);
    assert_eq!(reports(&harness), [ActionSet::ALERT]);
    assert_eq!(harness.to_client, answer);
}

/// `Parse`, two `Bind`s that make the portals `a` and `b`, a `Describe`
/// of the portal `a`, and an `Execute` of `run` for all its rows.
fn describe_a_and_run(run: &str) -> Vec<u8> {
    let parse = frame(b'P', &join(&[b"\0", SELECT.as_bytes(), b"\0\0\0"]));
    let bind = |portal: &str| {
        frame(
            b'B',
            &join(&[portal.as_bytes(), b"\0\0", &[0, 0, 0, 0, 0, 0]]),
        )
    };
    join(&[
        &parse,
        &bind("a"),
        &bind("b"),
        &frame(b'D', b"Pa\0"),
        &frame(b'E', &join(&[run.as_bytes(), b"\0", &[0, 0, 0, 0]])),
        &frame(b'S', b""),
    ])
}

#[test]
fn rows_of_a_portal_other_than_the_one_described_fall_back_to_alert() {
    let answer = join(&[
        &frame(b'1', b""),
        &frame(b'2', b""),
        &frame(b'2', b""),
        &answer(&users(0), "SELECT 3"),
    ]);

    // The portal that was described: rows are added.
    let mut harness = session(set(&[Action::FakeData]));
    harness.client(&describe_a_and_run("a"));
    harness.server(&answer);
    assert_eq!(reports(&harness), [set(&[Action::FakeData])]);
    assert_eq!(result(&harness), (6, "SELECT 6".to_owned()));

    // Another one, whose columns nobody described: nothing is added.
    let mut harness = session(set(&[Action::FakeData]));
    harness.client(&describe_a_and_run("b"));
    harness.server(&answer);
    assert_eq!(reports(&harness), [ActionSet::ALERT]);
    assert_eq!(harness.to_client, answer);
}

#[test]
fn a_portal_made_again_after_its_description_falls_back_to_alert() {
    let mut harness = session(set(&[Action::FakeData]));
    let parse = frame(b'P', &join(&[b"\0", SELECT.as_bytes(), b"\0\0\0"]));
    let bind = frame(b'B', &[0, 0, 0, 0, 0, 0, 0, 0]);
    harness.client(&join(&[
        &parse,
        &bind,
        &frame(b'D', b"P\0"),
        &bind,
        &frame(b'E', &[0, 0, 0, 0, 0]),
        &frame(b'S', b""),
    ]));
    let answer = join(&[
        &frame(b'1', b""),
        &frame(b'2', b""),
        &users(0),
        &frame(b'2', b""),
        &rows(),
        &end("SELECT 3"),
    ]);
    harness.server(&answer);
    assert_eq!(reports(&harness), [ActionSet::ALERT]);
    assert_eq!(harness.to_client, answer);
}

#[test]
fn a_report_that_must_not_wait_leaves_as_alert_and_the_result_stays_as_it_is() {
    let mut harness = session(set(&[Action::FakeData]));
    let answer = join(&[
        &users(0),
        &rows(),
        &row_with("9", "eve", EMAIL),
        &end("SELECT 4"),
    ]);
    let waited = users(0).len() + rows().len();
    harness.client(&query(SELECT));
    harness.server(&answer[..waited]);
    assert!(reports(&harness).is_empty());

    // The time the runtime allows has passed.
    due(&mut harness);
    assert_eq!(reports(&harness), [ActionSet::ALERT]);

    // The report said `alert`, so it stays true: a later hit in the same
    // result is an `alert` too, at once, and no row is added.
    harness.server(&answer[waited..]);
    assert_eq!(reports(&harness), [ActionSet::ALERT, ActionSet::ALERT]);
    assert_eq!(kept_back(&harness), 1);
    assert_eq!(harness.to_client, answer);
    due(&mut harness);
    assert_eq!(reports(&harness).len(), 2);

    // The next result is a new one.
    harness.to_client.clear();
    harness.effects.clear();
    let (data, tag) = run(&mut harness, SELECT, &self::answer(&users(0), "SELECT 3"));
    assert_eq!(reports(&harness), [set(&[Action::FakeData])]);
    assert_eq!((data.len(), tag.as_str()), (6, "SELECT 6"));
}

#[test]
fn of_the_hits_of_one_result_the_last_reports_the_rows() {
    let mut harness = session(set(&[Action::FakeData]));
    harness.client(&query(SELECT));
    harness.server(&join(&[&users(0), &rows()]));
    assert!(reports(&harness).is_empty());

    // A second hit sends the first report on its way: the one of the hit
    // that flagged the session.
    harness.server(&row_with("9", "eve", EMAIL));
    assert_eq!(reports(&harness), [ActionSet::ALERT]);
    assert!(!harness.events()[0].session_flagged);
    assert_eq!(kept_back(&harness), 2, "the time is counted anew");

    harness.server(&end("SELECT 4"));
    assert_eq!(
        reports(&harness),
        [ActionSet::ALERT, set(&[Action::FakeData])]
    );
    assert!(harness.events()[1].session_flagged);
    assert_eq!(result(&harness), (7, "SELECT 7".to_owned()), "added once");
}

#[test]
fn a_hit_that_asks_for_no_rows_leaves_the_report_that_waits_alone() {
    let mut harness = session_with_two_tokens(ActionSet::ALERT);
    harness.client(&query(SELECT));
    harness.server(&join(&[&users(0), &rows(), &row_with("9", "eve", CANARY)]));
    assert_eq!(reported(&harness), [CANARY_ID]);
    assert_eq!(reports(&harness), [ActionSet::ALERT]);

    harness.server(&end("SELECT 4"));
    assert_eq!(reported(&harness), [CANARY_ID, EMAIL_ID]);
    assert_eq!(
        reports(&harness),
        [ActionSet::ALERT, set(&[Action::FakeData])]
    );
    assert_eq!(result(&harness), (7, "SELECT 7".to_owned()));
}

#[test]
fn a_kill_sends_the_report_that_waits_first_and_as_alert() {
    let mut harness = session_with_two_tokens(set(&[Action::Kill]));
    harness.client(&query(SELECT));
    harness.server(&join(&[&users(0), &rows()]));
    assert!(reports(&harness).is_empty());

    harness.server(&join(&[&row_with("9", "eve", CANARY), &end("SELECT 4")]));
    assert!(harness.session.is_closed());
    assert_eq!(reported(&harness), [EMAIL_ID, CANARY_ID]);
    assert_eq!(reports(&harness), [ActionSet::ALERT, set(&[Action::Kill])]);
    let sent = messages(&harness.to_client);
    assert_eq!(
        sent.iter().filter(|(kind, _)| *kind == b'D').count(),
        3,
        "no made-up row, and not the row that ended the session"
    );

    due(&mut harness);
    assert_eq!(reports(&harness).len(), 2, "nothing twice");
}

#[test]
fn a_session_that_ends_hands_over_the_report_that_waits() {
    // The server sends something that is no message: the session ends.
    let mut harness = session(set(&[Action::FakeData]));
    harness.client(&query(SELECT));
    harness.server(&join(&[&users(0), &rows()]));
    let mut out = Output::new();
    let ended = harness.session.on_bytes(
        Direction::FromServer,
        &[b'D', 0, 0, 0, 1],
        &harness.policy,
        &mut out,
    );
    assert!(ended.is_err());
    assert!(harness.session.is_closed());
    assert!(reports(&harness).is_empty());
    due(&mut harness);
    assert_eq!(reports(&harness), [ActionSet::ALERT]);
    due(&mut harness);
    assert_eq!(reports(&harness).len(), 1);

    // The proxy stops.
    let mut harness = session(set(&[Action::FakeData]));
    harness.client(&query(SELECT));
    harness.server(&join(&[&users(0), &rows()]));
    let mut out = Output::new();
    harness
        .session
        .on_report(Report::ShuttingDown, &harness.policy, &mut out)
        .unwrap();
    assert!(harness.session.is_closed());
    due(&mut harness);
    assert_eq!(reports(&harness), [ActionSet::ALERT]);
}

#[test]
fn a_session_that_goes_on_uninspected_hands_over_the_report_that_waits() {
    let token = {
        let mut token = TokenPolicy::new(TokenId::new(EMAIL_ID).unwrap());
        token.actions = set(&[Action::FakeData]);
        token
    };
    let snapshot = PolicySnapshot::builder()
        .inspection(Inspection::new(OnError::FailOpen, LIMIT))
        .token(token)
        .actions(ActionSettings::new(
            KillSettings::default(),
            TarpitSettings::default(),
            FakeDataSettings::new(ADDED),
        ))
        .matcher(Matcher::build(&[TokenSpec::new(EMAIL_ID, [EMAIL])]).unwrap())
        .build()
        .unwrap();
    let mut harness = session_in(&Arc::new(TarpitPlaces::new()), snapshot);
    harness.client(&query(SELECT));
    harness.server(&join(&[&users(0), &rows()]));
    harness.server(&[b'D', 0, 0, 0, 1]);
    assert!(!harness.session.is_closed(), "the session goes on");
    assert!(reports(&harness).is_empty());
    due(&mut harness);
    assert_eq!(reports(&harness), [ActionSet::ALERT]);
    // What follows passes as it comes: no row is added any more.
    harness.to_client.clear();
    harness.server(&end("SELECT 3"));
    assert_eq!(harness.to_client, end("SELECT 3"));
}
