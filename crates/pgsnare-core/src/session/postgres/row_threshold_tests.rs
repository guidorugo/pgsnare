// SPDX-License-Identifier: Apache-2.0

//! Tests of the row threshold in a session: which results are counted,
//! what a result is, and what the session does when one passes it.

use pgsnare_proto::backend;

use crate::event::EventKind;
use crate::policy::{Action, ActionSet, Exemption, OnError};
use crate::rules::{OnParseFailure, ParseFailure, ROW_THRESHOLD, RuleScope, RuleSet};
use crate::session::Effect;

use super::fake_tests::description;
use super::rule_hit_tests::{fatal, judge, policy, rule_events, rule_hits, run, session};
use super::rules_tests::with_rules::{answer, asked, bind, sync};
use super::rules_tests::{LIMIT, base, parse, query};
use super::scan_tests::{Harness, data_row, frame, join};

const ALERT: ActionSet = ActionSet::ALERT;
const TEXT: u32 = 25;

fn set(actions: &[Action]) -> ActionSet {
    ActionSet::of(actions)
}

/// The row threshold on `users`, at `max_rows`, answered with `actions`.
fn threshold(max_rows: u64, actions: ActionSet) -> RuleSet {
    threshold_with(max_rows, actions, OnParseFailure::Alert)
}

fn threshold_with(max_rows: u64, actions: ActionSet, on_failure: OnParseFailure) -> RuleSet {
    RuleSet::builder()
        .on_parse_failure(on_failure)
        .row_threshold(
            &["users".to_owned()],
            max_rows,
            actions,
            RuleScope::default(),
        )
        .unwrap()
        .build()
}

/// `count` rows of one text column, numbered from `first`.
fn rows(first: usize, count: usize) -> Vec<u8> {
    (first..first + count)
        .map(|at| data_row(format!("row-{at}").as_bytes()))
        .collect::<Vec<_>>()
        .concat()
}

fn complete(tag: &str) -> Vec<u8> {
    frame(b'C', &join(&[tag.as_bytes(), b"\0"]))
}

fn ready(status: u8) -> Vec<u8> {
    frame(b'Z', &[status])
}

fn execute_some(portal: &str, max_rows: u32) -> Vec<u8> {
    frame(
        b'E',
        &join(&[portal.as_bytes(), b"\0", &max_rows.to_be_bytes()]),
    )
}

/// The types of the messages in `bytes`.
fn tags(mut bytes: &[u8]) -> Vec<u8> {
    let mut tags = Vec::new();
    while bytes.len() >= 5 {
        tags.push(bytes[0]);
        let length = u32::from_be_bytes(bytes[1..5].try_into().unwrap()) as usize;
        bytes = &bytes[1 + length..];
    }
    tags
}

/// The row threshold hits: whether exempt, what was decided and what was
/// carried out.
fn threshold_hits(harness: &Harness) -> Vec<(bool, ActionSet, ActionSet)> {
    rule_hits(harness)
        .into_iter()
        .map(|(rule, exempt, decided, actions)| {
            assert_eq!(rule, ROW_THRESHOLD);
            (exempt, decided, actions)
        })
        .collect()
}

#[test]
fn a_result_that_passes_the_threshold_fires_once() {
    let mut harness = session(policy(threshold(3, ALERT)));
    run(&mut harness, "SELECT * FROM users");
    harness.server(&rows(0, 3));
    assert!(threshold_hits(&harness).is_empty());

    harness.server(&rows(3, 5));
    assert_eq!(threshold_hits(&harness), [(false, ALERT, ALERT)]);
    let events = rule_events(&harness);
    assert_eq!(events.len(), 1);
    assert_eq!(events[0].rule_id.as_ref().unwrap().as_str(), ROW_THRESHOLD);
    assert_eq!(events[0].token_id, None);
    assert_eq!(events[0].rows_so_far, Some(3));
    assert_eq!(events[0].action_taken, ALERT);
    // `alert` lets every row through.
    assert_eq!(harness.to_client, rows(0, 8));

    // The next result is counted from the start.
    harness.server(&join(&[&complete("SELECT 8"), &ready(b'I')]));
    run(&mut harness, "SELECT name FROM users");
    harness.server(&rows(0, 3));
    assert_eq!(threshold_hits(&harness).len(), 1);
    harness.server(&rows(3, 1));
    assert_eq!(threshold_hits(&harness).len(), 2);
}

#[test]
fn a_result_of_a_table_that_is_not_listed_is_not_counted() {
    let mut harness = session(policy(threshold(3, ALERT)));
    run(&mut harness, "SELECT * FROM orders");
    harness.server(&rows(0, 50));
    assert!(threshold_hits(&harness).is_empty());

    // The rule is not on for this user.
    let scoped = RuleSet::builder()
        .row_threshold(
            &["users".to_owned()],
            3,
            ALERT,
            RuleScope::new(None, None, &["app".to_owned()]),
        )
        .unwrap()
        .functions(&["pg_sleep".to_owned()], ALERT, RuleScope::default())
        .unwrap()
        .build();
    let mut harness = session(policy(scoped));
    run(&mut harness, "SELECT * FROM users");
    harness.server(&rows(0, 50));
    assert!(threshold_hits(&harness).is_empty());
}

#[test]
fn every_statement_of_a_query_counts_toward_one_result() {
    let mut harness = session(policy(threshold(3, ALERT)));
    run(
        &mut harness,
        "SELECT * FROM users LIMIT 2; SELECT * FROM users LIMIT 2 OFFSET 2",
    );
    harness.server(&join(&[&rows(0, 2), &complete("SELECT 2")]));
    assert!(threshold_hits(&harness).is_empty());
    harness.server(&rows(2, 2));
    assert_eq!(threshold_hits(&harness).len(), 1);
}

#[test]
fn a_portal_is_one_result_over_all_its_executes() {
    let sql = "SELECT * FROM users";
    let mut harness = session(policy(threshold(3, ALERT)));
    judge(&mut harness, &parse("", sql), sql);
    harness.client(&join(&[&bind("p", ""), &execute_some("p", 2)]));
    harness.server(&join(&[
        &frame(backend::tag::PARSE_COMPLETE, b""),
        &frame(backend::tag::BIND_COMPLETE, b""),
        &rows(0, 2),
        &frame(backend::tag::PORTAL_SUSPENDED, b""),
    ]));
    assert!(threshold_hits(&harness).is_empty());
    harness.client(&execute_some("p", 2));
    harness.server(&join(&[
        &rows(2, 2),
        &frame(backend::tag::PORTAL_SUSPENDED, b""),
    ]));
    assert_eq!(threshold_hits(&harness).len(), 1);
    assert_eq!(rule_events(&harness)[0].rows_so_far, Some(3));

    // A portal bound again is a new result, counted from the start.
    harness.client(&join(&[&sync(), &bind("p", ""), &execute_some("p", 4)]));
    harness.server(&join(&[
        &ready(b'T'),
        &frame(backend::tag::BIND_COMPLETE, b""),
        &rows(0, 3),
    ]));
    assert_eq!(threshold_hits(&harness).len(), 1);
    harness.server(&join(&[
        &rows(3, 1),
        &frame(backend::tag::PORTAL_SUSPENDED, b""),
    ]));
    assert_eq!(threshold_hits(&harness).len(), 2);
}

#[test]
fn a_statement_without_an_analysis_is_held_to_the_threshold() {
    for reason in [
        ParseFailure::Rejected,
        ParseFailure::Busy,
        ParseFailure::TimedOut,
    ] {
        let mut harness = session(policy(threshold_with(3, ALERT, OnParseFailure::Allow)));
        harness.client(&query("SELECT * FROM orders"));
        let requests = asked(&mut harness);
        answer(&mut harness, requests[0].0, Err(reason));
        assert_eq!(harness.to_server, query("SELECT * FROM orders"));
        harness.server(&rows(0, 4));
        assert_eq!(threshold_hits(&harness).len(), 1, "{reason:?}");
    }
}

#[test]
fn a_statement_that_runs_what_was_stored_is_held_to_the_threshold() {
    let mut harness = session(policy(threshold(3, ALERT)));
    run(&mut harness, "FETCH ALL FROM c");
    harness.server(&rows(0, 4));
    assert_eq!(threshold_hits(&harness).len(), 1);
}

#[test]
fn rows_the_tracker_cannot_place_are_counted_until_the_transaction_ends() {
    let mut harness = session(policy(threshold(3, ALERT)));
    // Rows nothing asked for: the tracker loses its place.
    harness.server(&rows(0, 3));
    assert!(threshold_hits(&harness).is_empty());
    harness.server(&ready(b'T'));
    harness.server(&rows(3, 1));
    assert_eq!(threshold_hits(&harness).len(), 1);

    // The transaction ends, and the count with it.
    harness.server(&ready(b'I'));
    harness.server(&rows(0, 3));
    assert_eq!(threshold_hits(&harness).len(), 1);
    harness.server(&rows(3, 1));
    assert_eq!(threshold_hits(&harness).len(), 2);
}

#[test]
fn a_statement_too_large_to_hold_is_held_to_the_threshold() {
    let mut harness = session(policy(threshold_with(3, ALERT, OnParseFailure::Allow)));
    let long = format!("SELECT * FROM orders WHERE note <> '{}'", "x".repeat(LIMIT));
    harness.client(&query(&long));
    assert!(asked(&mut harness).is_empty());
    harness.server(&rows(0, 4));
    assert_eq!(threshold_hits(&harness).len(), 1);
}

#[test]
fn copy_data_of_the_server_counts_as_rows() {
    let mut harness = session(policy(threshold(3, set(&[Action::FakeData]))));
    run(&mut harness, "COPY users TO STDOUT");
    harness.server(&frame(backend::tag::COPY_OUT_RESPONSE, &[0, 0, 1, 0, 0]));
    harness.server(
        &(0..4)
            .map(|at| frame(backend::tag::COPY_DATA, format!("{at}\n").as_bytes()))
            .collect::<Vec<_>>()
            .concat(),
    );
    // No result rows can be added to: `alert`.
    assert_eq!(
        threshold_hits(&harness),
        [(false, set(&[Action::FakeData]), ALERT)]
    );
}

#[test]
fn a_row_past_the_threshold_answered_with_kill_never_reaches_the_client() {
    let kill = set(&[Action::Kill]);
    let mut harness = session(policy(threshold(3, kill)));
    run(&mut harness, "SELECT * FROM users");
    harness.server(&rows(0, 5));
    assert_eq!(threshold_hits(&harness), [(false, kill, kill)]);
    assert_eq!(harness.to_client, join(&[&rows(0, 3), &fatal()]));
    assert!(harness.session.is_closed());
    assert!(
        harness
            .effects
            .iter()
            .any(|effect| matches!(effect, Effect::Cancel { .. }))
    );
}

#[test]
fn a_row_in_parts_counts_and_kill_stops_it_before_any_part_is_sent() {
    let kill = set(&[Action::Kill]);
    let mut harness = session(policy(threshold(1, kill)));
    run(&mut harness, "SELECT * FROM users");
    let large = data_row(&vec![b'y'; LIMIT + 10]);
    harness.server(&join(&[&rows(0, 1), &large]));
    assert_eq!(threshold_hits(&harness), [(false, kill, kill)]);
    assert_eq!(harness.to_client, join(&[&rows(0, 1), &fatal()]));
    assert!(harness.session.is_closed());
}

#[test]
fn tarpit_slows_the_session_down_and_the_rows_go_on() {
    let tarpit = set(&[Action::Tarpit]);
    let mut harness = session(policy(threshold(2, tarpit)));
    run(&mut harness, "SELECT * FROM users");
    harness.server(&rows(0, 3));
    assert_eq!(threshold_hits(&harness), [(false, tarpit, tarpit)]);
    assert!(
        harness
            .effects
            .iter()
            .any(|effect| matches!(effect, Effect::Tarpit { .. }))
    );
    assert_eq!(harness.to_client, rows(0, 3));
    assert!(!harness.session.is_closed());
}

#[test]
fn fake_data_adds_rows_to_a_result_that_can_take_them() {
    let fake = set(&[Action::FakeData]);
    let mut harness = session(policy(threshold(2, fake)));
    run(&mut harness, "SELECT name FROM users");
    harness.server(&join(&[
        &description(&[("name", TEXT, -1, 0)]),
        &rows(0, 3),
        &complete("SELECT 3"),
        &ready(b'I'),
    ]));
    assert_eq!(threshold_hits(&harness), [(false, fake, fake)]);
    let data_rows = tags(&harness.to_client)
        .into_iter()
        .filter(|tag| *tag == b'D')
        .count();
    assert!(data_rows > 3, "{data_rows}");
    assert!(!harness.session.is_closed());
}

#[test]
fn an_exempt_session_is_counted_and_nothing_else() {
    let exempting = base(OnError::FailClosed, LIMIT)
        .rules(threshold(1, set(&[Action::Kill])))
        .exemption(Exemption::new(Some("app".to_owned()), None))
        .build()
        .unwrap();
    let mut harness = session(exempting);
    run(&mut harness, "SELECT * FROM users");
    harness.server(&rows(0, 5));
    assert_eq!(
        threshold_hits(&harness),
        [(true, ActionSet::EMPTY, ActionSet::EMPTY)]
    );
    assert!(rule_events(&harness).is_empty());
    assert!(
        harness
            .events()
            .iter()
            .all(|body| body.kind != EventKind::RuleHit)
    );
    assert_eq!(harness.to_client, rows(0, 5));
}
