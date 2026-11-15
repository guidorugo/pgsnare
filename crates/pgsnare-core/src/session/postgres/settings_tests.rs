// SPDX-License-Identifier: Apache-2.0

//! Tests of when a session takes the settings of the database as known: a
//! statement is only analysed when the database reads it as the parser
//! does, also when the client sends it without waiting for an answer.

use crate::policy::ActionSet;
use crate::rules::{OnParseFailure, ParseFailure, RuleScope, RuleSet};

use super::rule_hit_tests::{policy, session};
use super::rules_tests::with_rules::{
    analysis, answer, asked, bind, blocked, execute, failures, parameter, sync,
};
use super::rules_tests::{LIMIT, parse, query};
use super::scan_tests::{Harness, frame, join};

const ALERT: ActionSet = ActionSet::ALERT;

/// A statement the database reads as two when
/// `standard_conforming_strings` is off, and the parser as one.
const HIDDEN: &str = r"SELECT '\'; SELECT pg_sleep(1); --'";

const TURN_OFF: &str = "SET standard_conforming_strings = off";

fn rules(on_failure: OnParseFailure) -> RuleSet {
    RuleSet::builder()
        .on_parse_failure(on_failure)
        .max_parse_bytes(4096)
        .unwrap()
        .functions(&["pg_sleep".to_owned()], ALERT, RuleScope::default())
        .unwrap()
        .build()
}

fn alerting() -> Harness {
    session(policy(rules(OnParseFailure::Alert)))
}

fn ready(status: u8) -> Vec<u8> {
    frame(b'Z', &[status])
}

/// Answers the one request the session has made with what the parser
/// makes of its text. Returns the text.
fn release(harness: &mut Harness) -> String {
    let requests = asked(harness);
    assert_eq!(requests.len(), 1);
    let (id, text) = &requests[0];
    let sql = String::from_utf8(text.clone()).unwrap();
    answer(harness, *id, Ok(analysis(&sql)));
    sql
}

/// Sends `sql` as a `Query` when the server has answered all before it,
/// and has it analysed. Fails when the session does not ask.
fn run(harness: &mut Harness, sql: &str) {
    harness.client(&query(sql));
    assert_eq!(release(harness), sql);
}

/// Whether a `Query` sent now is analysed. The server answers it.
fn is_analysed(harness: &mut Harness) -> bool {
    harness.client(&query("SELECT 2"));
    let analysed = !asked_and_released(harness);
    harness.server(&ready(b'I'));
    analysed
}

/// Releases a held statement if there is one. Returns whether there was
/// none.
fn asked_and_released(harness: &mut Harness) -> bool {
    let requests = asked(harness);
    for (id, text) in &requests {
        let sql = String::from_utf8(text.clone()).unwrap();
        answer(harness, *id, Ok(analysis(&sql)));
    }
    requests.is_empty()
}

#[test]
fn a_query_sent_behind_a_change_of_a_setting_is_not_analysed() {
    for on_failure in [
        OnParseFailure::Allow,
        OnParseFailure::Alert,
        OnParseFailure::Block,
    ] {
        let mut harness = session(policy(rules(on_failure)));
        let change = query(TURN_OFF);
        let hidden = query(HIDDEN);
        // Both in one write: the server has not answered the first when
        // the second is looked at.
        harness.client(&join(&[&change, &hidden]));
        assert_eq!(release(&mut harness), TURN_OFF);

        // The second statement was not handed to the parser, which would
        // read it under the setting the first one changes.
        assert!(asked(&mut harness).is_empty(), "{on_failure:?}");
        let expected = match on_failure {
            OnParseFailure::Allow => ActionSet::EMPTY,
            OnParseFailure::Alert => ALERT,
            OnParseFailure::Block => blocked(),
        };
        assert_eq!(
            failures(&harness),
            [(ParseFailure::Encoding, expected)],
            "{on_failure:?}"
        );
        if on_failure == OnParseFailure::Block {
            assert_eq!(harness.to_server, change);
            assert!(harness.session.is_closed());
        } else {
            assert_eq!(harness.to_server, join(&[&change, &hidden]));
        }
    }
}

#[test]
fn a_parse_sent_behind_an_execute_that_changes_a_setting_is_not_analysed() {
    let mut harness = alerting();
    harness.client(&join(&[
        &parse("", TURN_OFF),
        &bind("", ""),
        &execute(""),
        &parse("", HIDDEN),
        &bind("", ""),
        &execute(""),
        &sync(),
    ]));
    assert_eq!(release(&mut harness), TURN_OFF);
    assert!(asked(&mut harness).is_empty());
    assert_eq!(failures(&harness), [(ParseFailure::Encoding, ALERT)]);

    // Nor is anything else before the server has answered the `Sync`.
    assert!(!is_analysed(&mut harness));
}

#[test]
fn a_stored_statement_that_changes_a_setting_counts_when_it_is_executed() {
    let mut harness = alerting();
    harness.client(&join(&[&parse("s1", TURN_OFF), &sync()]));
    assert_eq!(release(&mut harness), TURN_OFF);
    harness.server(&join(&[&frame(b'1', b""), &ready(b'I')]));
    // Storing it changed nothing.
    assert!(failures(&harness).is_empty());
    assert!(is_analysed(&mut harness));

    harness.client(&join(&[
        &bind("", "s1"),
        &execute(""),
        &parse("", HIDDEN),
        &sync(),
    ]));
    assert!(asked(&mut harness).is_empty());
    assert_eq!(failures(&harness), [(ParseFailure::Encoding, ALERT)]);
}

#[test]
fn a_stored_statement_that_changes_nothing_does_not_hold_up_the_next() {
    let mut harness = alerting();
    harness.client(&join(&[
        &parse("", "SELECT 1"),
        &bind("", ""),
        &execute(""),
        &parse("", "SELECT 2"),
        &bind("", ""),
        &execute(""),
        &sync(),
    ]));
    assert_eq!(release(&mut harness), "SELECT 1");
    assert_eq!(release(&mut harness), "SELECT 2");
    assert!(failures(&harness).is_empty());
}

#[test]
fn an_execute_of_a_statement_that_is_not_known_counts_as_a_change() {
    let mut harness = alerting();
    // No `Parse` and no `Bind` of this session made the portal.
    harness.client(&join(&[&execute("elsewhere"), &parse("", "SELECT 2")]));
    assert!(asked(&mut harness).is_empty());
    assert_eq!(failures(&harness), [(ParseFailure::Encoding, ALERT)]);
}

#[test]
fn every_statement_that_may_change_a_setting_holds_up_the_next() {
    for sql in [
        TURN_OFF,
        "SET \"Standard_Conforming_Strings\" TO off",
        "SET LOCAL standard_conforming_strings = off",
        "RESET standard_conforming_strings",
        "SET client_encoding = 'LATIN1'",
        "SET NAMES 'LATIN1'",
        "RESET ALL",
        "DISCARD ALL",
        "SELECT 1; RESET ALL",
        "SELECT set_config('standard_conforming_strings', 'off', false)",
        "SELECT pg_catalog.set_config($1, $2, false)",
        "DO $$ BEGIN PERFORM 1; END $$",
        "EXECUTE stored",
    ] {
        let mut harness = alerting();
        harness.client(&join(&[&query(sql), &query("SELECT 2")]));
        assert_eq!(release(&mut harness), sql);
        assert!(asked(&mut harness).is_empty(), "{sql}");
        assert_eq!(
            failures(&harness).last(),
            Some(&(ParseFailure::Encoding, ALERT)),
            "{sql}"
        );
    }
    for sql in [
        "SELECT 1",
        "BEGIN",
        "COMMIT",
        "SET search_path = public",
        "SET statement_timeout = 0",
        "SET TIME ZONE 'UTC'",
        "SET TRANSACTION ISOLATION LEVEL SERIALIZABLE",
        "SHOW standard_conforming_strings",
    ] {
        let mut harness = alerting();
        harness.client(&join(&[&query(sql), &query("SELECT 2")]));
        assert_eq!(release(&mut harness), sql);
        assert_eq!(release(&mut harness), "SELECT 2", "{sql}");
        assert!(failures(&harness).is_empty(), "{sql}");
    }
}

#[test]
fn a_statement_that_is_passed_on_unread_holds_up_the_next() {
    // Longer than the parser is given.
    let mut harness = alerting();
    let long = format!("SELECT '{}'", "x".repeat(5000));
    harness.client(&join(&[&query(&long), &query("SELECT 2")]));
    assert!(asked(&mut harness).is_empty());
    assert_eq!(
        failures(&harness),
        [
            (ParseFailure::TooLarge, ALERT),
            (ParseFailure::Encoding, ALERT)
        ]
    );

    // Too large to hold: it arrives in parts.
    let mut harness = alerting();
    let huge = format!("SELECT '{}'", "x".repeat(LIMIT + 1));
    harness.client(&join(&[&query(&huge), &query("SELECT 2")]));
    assert!(asked(&mut harness).is_empty());
    assert_eq!(
        failures(&harness),
        [
            (ParseFailure::Streamed, ALERT),
            (ParseFailure::Encoding, ALERT)
        ]
    );

    // A call of a function by its number.
    let mut harness = alerting();
    let call = frame(b'F', &[0, 0, 8, 30, 0, 0, 0, 0, 0, 0]);
    harness.client(&join(&[&call, &query("SELECT 2")]));
    assert!(asked(&mut harness).is_empty());
    assert_eq!(
        failures(&harness),
        [
            (ParseFailure::FunctionCall, ALERT),
            (ParseFailure::Encoding, ALERT)
        ]
    );

    // The parser had no answer.
    let mut harness = alerting();
    harness.client(&join(&[&query("SELECT 1"), &query("SELECT 2")]));
    let requests = asked(&mut harness);
    answer(&mut harness, requests[0].0, Err(ParseFailure::TimedOut));
    assert!(asked(&mut harness).is_empty());
    assert_eq!(
        failures(&harness),
        [
            (ParseFailure::TimedOut, ALERT),
            (ParseFailure::Encoding, ALERT)
        ]
    );
}

#[test]
fn the_settings_are_known_again_when_the_server_has_answered_the_change() {
    let mut harness = alerting();
    run(&mut harness, "SELECT 1");
    run(&mut harness, "SET standard_conforming_strings = on");
    // The answer to the statement before the change is not the answer to
    // the change.
    harness.server(&ready(b'I'));
    harness.client(&query("SELECT 3"));
    assert!(asked(&mut harness).is_empty());
    assert_eq!(failures(&harness), [(ParseFailure::Encoding, ALERT)]);

    // The answer to the change. The statement that was not read is still
    // unanswered, and may have been a change itself.
    harness.server(&join(&[
        &parameter(b"standard_conforming_strings", b"on"),
        &ready(b'I'),
    ]));
    harness.client(&query("SELECT 4"));
    assert!(asked(&mut harness).is_empty());

    harness.server(&join(&[&ready(b'I'), &ready(b'I')]));
    assert!(is_analysed(&mut harness));
    // An answer too many, were the server to send one, opens nothing.
    harness.server(&join(&[&ready(b'I'), &ready(b'I')]));
    harness.client(&join(&[&query(TURN_OFF), &query(HIDDEN)]));
    assert_eq!(release(&mut harness), TURN_OFF);
    assert!(asked(&mut harness).is_empty());
}

#[test]
fn a_change_inside_a_transaction_can_be_undone_by_any_statement() {
    let mut harness = alerting();
    run(&mut harness, "BEGIN");
    harness.server(&ready(b'T'));
    run(&mut harness, "SET standard_conforming_strings = on");
    harness.server(&join(&[
        &parameter(b"standard_conforming_strings", b"on"),
        &ready(b'T'),
    ]));

    // One statement at a time, each after the answer to the last, is read
    // under what the server reported.
    run(&mut harness, "SELECT 1");
    harness.server(&ready(b'T'));

    // A statement that fails undoes the change, and the next one is read
    // under the old setting: it is not analysed while the first is
    // unanswered, whatever the first is.
    harness.client(&join(&[&query("SELECT 1/0"), &query(HIDDEN)]));
    assert_eq!(release(&mut harness), "SELECT 1/0");
    assert!(asked(&mut harness).is_empty());
    assert_eq!(failures(&harness), [(ParseFailure::Encoding, ALERT)]);
    harness.server(&join(&[&ready(b'E'), &ready(b'E')]));
    harness.effects.clear();

    // The same for the messages of a prepared statement.
    harness.client(&join(&[
        &parse("", "SELECT 1"),
        &bind("", ""),
        &execute(""),
        &parse("", HIDDEN),
        &sync(),
    ]));
    assert_eq!(release(&mut harness), "SELECT 1");
    assert!(asked(&mut harness).is_empty());
    assert_eq!(failures(&harness), [(ParseFailure::Encoding, ALERT)]);
    harness.server(&ready(b'E'));
    harness.effects.clear();

    // Outside the transaction nothing is left to undo.
    run(&mut harness, "ROLLBACK");
    harness.server(&ready(b'I'));
    harness.client(&join(&[&query("SELECT 1/0"), &query("SELECT 2")]));
    assert_eq!(release(&mut harness), "SELECT 1/0");
    assert_eq!(release(&mut harness), "SELECT 2");
    assert!(failures(&harness).is_empty());
}

#[test]
fn a_statement_run_without_rules_counts_as_a_change_for_rules_loaded_later() {
    // No rule applies to the session yet, so nothing reads the statement.
    let none = RuleSet::builder().build();
    let mut harness = session(policy(none));
    harness.client(&query(TURN_OFF));
    assert!(asked(&mut harness).is_empty());
    assert!(failures(&harness).is_empty());

    harness.policy = policy(rules(OnParseFailure::Alert));
    harness.client(&query(HIDDEN));
    assert!(asked(&mut harness).is_empty());
    assert_eq!(failures(&harness), [(ParseFailure::Encoding, ALERT)]);
}

const COPY: &str = "COPY t FROM STDIN";

fn copy_in_response() -> Vec<u8> {
    frame(b'G', &[0, 0, 0])
}

fn copy_data() -> Vec<u8> {
    frame(b'd', b"1\n")
}

fn copy_done() -> Vec<u8> {
    frame(b'c', b"")
}

fn complete(tag: &str) -> Vec<u8> {
    frame(b'C', &join(&[tag.as_bytes(), b"\0"]))
}

fn error() -> Vec<u8> {
    frame(b'E', b"SERROR\0C22P02\0Mrefused\0\0")
}

/// Whether a statement sent behind a change of a setting, after the
/// server has sent one more `ReadyForQuery`, is analysed. It must not be
/// when that `ReadyForQuery` answers something sent before the change.
fn an_earlier_answer_settles_a_change(harness: &mut Harness) -> bool {
    harness.client(&query(TURN_OFF));
    assert_eq!(release(harness), TURN_OFF);
    harness.server(&ready(b'I'));
    harness.client(&query(HIDDEN));
    !asked(harness).is_empty()
}

#[test]
fn a_sync_the_server_ignores_during_a_copy_is_not_waited_for() {
    let mut harness = alerting();
    // What a client library sends: the `Sync` follows the `Execute` at
    // once, and the server reads it as part of the copy.
    harness.client(&join(&[
        &parse("", COPY),
        &bind("", ""),
        &execute(""),
        &sync(),
    ]));
    assert_eq!(release(&mut harness), COPY);
    harness.server(&join(&[
        &frame(b'1', b""),
        &frame(b'2', b""),
        &copy_in_response(),
    ]));
    harness.client(&join(&[
        &copy_data(),
        &sync(),
        &copy_data(),
        &copy_done(),
        &sync(),
    ]));
    harness.server(&join(&[&complete("COPY 2"), &ready(b'I')]));
    assert!(failures(&harness).is_empty());

    // Every answer the server owes has come: a change of a setting is
    // settled by its own answer, and statements are analysed again.
    run(&mut harness, "SET client_encoding = 'UTF8'");
    harness.server(&ready(b'I'));
    assert!(is_analysed(&mut harness));
    assert!(failures(&harness).is_empty());

    // The same for a copy sent as a `Query`.
    let mut harness = alerting();
    run(&mut harness, COPY);
    harness.server(&copy_in_response());
    harness.client(&join(&[&copy_data(), &sync(), &copy_done()]));
    harness.server(&join(&[&complete("COPY 1"), &ready(b'I')]));
    run(&mut harness, "SET client_encoding = 'UTF8'");
    harness.server(&ready(b'I'));
    assert!(is_analysed(&mut harness));
}

#[test]
fn a_sync_behind_a_copy_that_failed_stays_in_the_count() {
    let mut harness = alerting();
    harness.client(&join(&[
        &parse("", COPY),
        &bind("", ""),
        &execute(""),
        &sync(),
    ]));
    assert_eq!(release(&mut harness), COPY);
    // The copy fails before the server reads on: it answers the `Sync`.
    harness.server(&join(&[
        &frame(b'1', b""),
        &frame(b'2', b""),
        &copy_in_response(),
        &error(),
        &ready(b'I'),
    ]));
    // What the client had sent for the copy, which the server now drops,
    // and a `Sync` it answers.
    harness.client(&join(&[&copy_data(), &copy_done(), &sync()]));
    run(&mut harness, "SELECT 1");
    harness.server(&join(&[&ready(b'I'), &complete("SELECT 1")]));

    // The answer to `SELECT 1` is still to come. It is not the answer to
    // a change sent now.
    assert!(!an_earlier_answer_settles_a_change(&mut harness));
}

#[test]
fn a_copy_is_only_taken_for_that_of_the_one_statement_it_can_belong_to() {
    let mut harness = alerting();
    // Two statements on their way, the first of them the copy, with no
    // `Sync` of its own.
    harness.client(&join(&[
        &parse("", COPY),
        &bind("", ""),
        &execute(""),
        &copy_data(),
        &copy_done(),
        &sync(),
        &parse("", "SELECT 1"),
        &bind("", ""),
        &execute(""),
        &sync(),
        &copy_done(),
    ]));
    assert_eq!(release(&mut harness), COPY);
    assert_eq!(release(&mut harness), "SELECT 1");
    harness.server(&join(&[
        &frame(b'1', b""),
        &frame(b'2', b""),
        &copy_in_response(),
        &complete("COPY 1"),
        &ready(b'I'),
    ]));

    // The second `Sync` is unanswered, whatever followed the second
    // statement.
    assert!(!an_earlier_answer_settles_a_change(&mut harness));
}

#[test]
fn a_message_that_ends_a_copy_with_an_error_keeps_every_sync_in_the_count() {
    let mut harness = alerting();
    run(&mut harness, COPY);
    harness.server(&copy_in_response());
    // The `Describe` makes the server give up the copy. The `Sync` behind
    // it is no part of the copy, though the client ends the copy after it.
    harness.client(&join(&[&frame(b'D', b"S\0"), &sync(), &copy_done()]));
    // Were the server to report the copy complete all the same, the
    // `Sync` stays counted.
    harness.server(&join(&[&complete("COPY 0"), &ready(b'I')]));
    assert!(!an_earlier_answer_settles_a_change(&mut harness));
}

#[test]
fn a_sync_behind_the_end_of_a_copy_is_waited_for() {
    let mut harness = alerting();
    harness.client(&join(&[
        &parse("", COPY),
        &bind("", ""),
        &execute(""),
        &sync(),
    ]));
    assert_eq!(release(&mut harness), COPY);
    harness.server(&join(&[
        &frame(b'1', b""),
        &frame(b'2', b""),
        &copy_in_response(),
    ]));
    // The `Sync` behind `CopyDone` is one the server answers.
    harness.client(&join(&[&copy_data(), &copy_done(), &sync()]));
    harness.server(&complete("COPY 1"));
    assert!(!an_earlier_answer_settles_a_change(&mut harness));
}
