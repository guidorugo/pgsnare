// SPDX-License-Identifier: Apache-2.0

//! Tests of the SQL rules in a session: which statements set a rule off,
//! for whom, and what the session does about it.
//!
//! Each statement is read by the parser itself and the answer is given to
//! the session as the runtime would give it, so a name that is written in
//! an unusual way is judged as the database would read it.

use core::time::Duration;
use std::sync::Arc;

use pgsnare_proto::encode;

use crate::actions::TarpitPlaces;
use crate::bait::Entropy;
use crate::event::{EventBody, EventKind};
use crate::extension::{ProtocolSession as _, Relay};
use crate::policy::{
    Action, ActionSet, ActionSettings, Exemption, OnError, PolicySnapshot, TarpitSettings,
};
use crate::rules::{
    CATALOG_ENUMERATION, FUNCTIONS, OnParseFailure, ParseFailure, RuleScope, RuleSet,
    UNBOUNDED_READ,
};
use crate::session::{Direction, Effect, Leg, Output, Report};

use super::messages::admin_shutdown;
use super::rules_tests::with_rules::{
    analysis, answer, asked, bind, blocked, execute, failures, parameter, sync,
};
use super::rules_tests::{LIMIT, base, parse, query, token_hits};
use super::scan_tests::{EMAIL, Harness, data_row, digest, frame, join, origin, startup};
use super::tarpit_tests::Counting;
use super::{Postgres, Responses};

const PROCESS_ID: i32 = 4242;
const KEY: [u8; 4] = [9, 8, 7, 6];

const ALERT: ActionSet = ActionSet::ALERT;

fn set(actions: &[Action]) -> ActionSet {
    ActionSet::of(actions)
}

fn kill() -> ActionSet {
    set(&[Action::Kill])
}

fn names(list: &[&str]) -> Vec<String> {
    list.iter().map(|name| (*name).to_owned()).collect()
}

/// The tables whose unbounded read is a hit.
fn tables() -> Vec<String> {
    names(&["users", "public.cards"])
}

/// The functions whose use is a hit.
fn functions() -> Vec<String> {
    names(&["pg_read_file", "lo_export"])
}

fn everybody() -> RuleScope {
    RuleScope::default()
}

/// The three rules that judge a statement before it runs, on for
/// everybody and each answered with `actions`.
fn every_rule(actions: ActionSet) -> RuleSet {
    RuleSet::builder()
        .catalog_enumeration(actions, everybody())
        .unwrap()
        .unbounded_read(&tables(), actions, everybody())
        .unwrap()
        .functions(&functions(), actions, everybody())
        .unwrap()
        .build()
}

/// Only the rule about functions, answered with `alert`.
fn functions_only(on_failure: OnParseFailure, scope: RuleScope) -> RuleSet {
    RuleSet::builder()
        .on_parse_failure(on_failure)
        .functions(&functions(), ALERT, scope)
        .unwrap()
        .build()
}

/// A policy with `rules`, in which one place for a tarpitted session
/// exists.
pub(super) fn policy(rules: RuleSet) -> PolicySnapshot {
    let tarpit = TarpitSettings::new(
        Duration::from_millis(2_000),
        Duration::from_millis(30_000),
        Duration::from_secs(600),
        1,
        None,
    );
    base(OnError::FailClosed, LIMIT)
        .actions(ActionSettings {
            tarpit,
            ..ActionSettings::default()
        })
        .rules(rules)
        .build()
        .unwrap()
}

/// A session of `user` on `listener` that can carry out every response,
/// was given a cancel key, and whose server reads statements as the parser
/// does.
pub(super) fn session_of(
    listener: Option<&str>,
    user: &str,
    places: &Arc<TarpitPlaces>,
    policy: PolicySnapshot,
) -> Harness {
    let responses = Responses::new(
        || -> Box<dyn Entropy + Send> { Box::new(Counting(3)) },
        Arc::clone(places),
    );
    let module = Postgres::responding(Arc::new(digest), responses);
    let origin = match listener {
        Some(name) => origin().with_listener(name),
        None => origin(),
    };
    let mut harness = Harness::with_policy(policy);
    harness.session = module.session(origin, Arc::new(Relay));
    harness.client(&startup(&[
        (b"user", user.as_bytes()),
        (b"database", b"shop"),
    ]));
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
        &parameter(b"client_encoding", b"UTF8"),
        &parameter(b"standard_conforming_strings", b"on"),
        &frame(b'Z', b"I"),
    ]));
    assert!(harness.session.is_established());
    harness.to_client.clear();
    harness.to_server.clear();
    harness.effects.clear();
    harness
}

/// A session of `app` on the listener `main`.
pub(super) fn session(policy: PolicySnapshot) -> Harness {
    session_of(Some("main"), "app", &Arc::new(TarpitPlaces::new()), policy)
}

/// Sends `message`, which carries the statement `sql`, and answers the
/// request of the session with what the parser makes of `sql`.
pub(super) fn judge(harness: &mut Harness, message: &[u8], sql: &str) {
    harness.client(message);
    let requests = asked(harness);
    assert_eq!(requests.len(), 1, "{sql}");
    let (id, text) = &requests[0];
    assert_eq!(text, sql.as_bytes(), "{sql}");
    answer(harness, *id, Ok(analysis(sql)));
}

/// Sends `sql` as a `Query` and has it judged.
pub(super) fn run(harness: &mut Harness, sql: &str) {
    judge(harness, &query(sql), sql);
}

/// The rule hits that were counted: the rule, whether the session is
/// exempt, what the rule asks for and what was carried out.
pub(super) fn rule_hits(harness: &Harness) -> Vec<(&str, bool, ActionSet, ActionSet)> {
    harness
        .effects
        .iter()
        .filter_map(|effect| match effect {
            Effect::RuleHit {
                rule_id,
                exempt,
                decided,
                actions,
            } => Some((rule_id.as_str(), *exempt, *decided, *actions)),
            _ => None,
        })
        .collect()
}

/// The rules that were set off, in the order they were raised.
fn fired(harness: &Harness) -> Vec<&str> {
    rule_hits(harness).into_iter().map(|hit| hit.0).collect()
}

pub(super) fn rule_events(harness: &Harness) -> Vec<&EventBody> {
    harness
        .events()
        .into_iter()
        .filter(|body| body.kind == EventKind::RuleHit)
        .collect()
}

pub(super) fn fatal() -> Vec<u8> {
    let mut bytes = Vec::new();
    admin_shutdown(&mut bytes).unwrap();
    bytes
}

fn cancel() -> Vec<u8> {
    let mut bytes = Vec::new();
    encode::cancel_request(PROCESS_ID, &KEY, &mut bytes).unwrap();
    bytes
}

/// Runs each statement in a session of its own, with every rule answered
/// by `alert`, and checks which rules it sets off and how each is
/// reported.
fn assert_fired(cases: &[(&str, &[&str])]) {
    for (sql, expected) in cases {
        let mut harness = session(policy(every_rule(ALERT)));
        run(&mut harness, sql);
        assert_eq!(fired(&harness), *expected, "{sql}");
        for hit in rule_hits(&harness) {
            assert_eq!((hit.1, hit.2, hit.3), (false, ALERT, ALERT), "{sql}");
        }
        // `alert` reports and lets the statement on.
        assert_eq!(harness.to_server, query(sql), "{sql}");
        assert!(!harness.session.is_closed(), "{sql}");
        assert!(failures(&harness).is_empty(), "{sql}");

        let events = rule_events(&harness);
        assert_eq!(events.len(), expected.len(), "{sql}");
        for (event, rule) in events.iter().zip(*expected) {
            let named = event.rule_id.as_ref().map(|id| id.as_str());
            assert_eq!(named, Some(*rule), "{sql}");
            assert_eq!(event.token_id, None, "{sql}");
            assert_eq!(event.action_taken, ALERT, "{sql}");
            assert_eq!(event.message_type.as_deref(), Some("Query"), "{sql}");
            assert_eq!(event.direction, Some(Direction::FromClient), "{sql}");
            assert_eq!(event.db_user.as_deref(), Some("app"), "{sql}");
            assert!(event.query.is_some(), "{sql}");
        }
    }
}

// ---------------------------------------------------------------------------
// The rules
// ---------------------------------------------------------------------------

#[test]
fn a_statement_that_breaks_no_rule_raises_nothing() {
    assert_fired(&[
        ("SELECT 1", &[]),
        ("SELECT * FROM orders", &[]),
        ("INSERT INTO users (id) VALUES (1)", &[]),
        ("UPDATE users SET seen = now() WHERE id = 1", &[]),
        ("SELECT now(), lower('A'), public.my_function(1)", &[]),
        ("BEGIN; SELECT * FROM users WHERE id = 1; COMMIT", &[]),
    ]);
}

#[test]
fn a_read_of_the_catalogues_sets_off_its_rule() {
    let hit: &[&str] = &[CATALOG_ENUMERATION];
    assert_fired(&[
        ("SELECT relname FROM pg_class WHERE relkind = 'r'", hit),
        ("SELECT * FROM pg_catalog.pg_tables WHERE true", hit),
        (
            "SELECT table_name FROM information_schema.tables WHERE table_schema = 'public'",
            hit,
        ),
        ("SELECT usename FROM pg_user LIMIT 5", hit),
        ("SELECT 1 FROM shop.pg_catalog.pg_roles LIMIT 1", hit),
        ("COPY (SELECT * FROM pg_namespace) TO STDOUT", hit),
        (
            "SELECT * FROM orders WHERE id IN (SELECT oid FROM pg_proc)",
            hit,
        ),
        // Not a catalogue: another schema, and a name the catalogues do
        // not have.
        ("SELECT * FROM public.pg_things WHERE id = 1", &[]),
        ("SELECT * FROM audit.tables WHERE id = 1", &[]),
        ("SELECT 'pg_class', 'information_schema.tables'", &[]),
    ]);
}

#[test]
fn a_read_of_a_listed_table_with_no_filter_and_no_limit_sets_off_its_rule() {
    let hit: &[&str] = &[UNBOUNDED_READ];
    assert_fired(&[
        ("SELECT * FROM users", hit),
        ("SELECT id, email FROM users ORDER BY id", hit),
        ("TABLE users", hit),
        ("SELECT * FROM cards", hit),
        ("SELECT * FROM public.cards", hit),
        ("COPY users TO STDOUT", hit),
        ("COPY (SELECT * FROM users) TO STDOUT", hit),
        ("WITH u AS (SELECT * FROM users) SELECT * FROM u", hit),
        ("SELECT * FROM (SELECT * FROM users) AS s", hit),
        ("SELECT * FROM orders UNION ALL SELECT * FROM users", hit),
        ("SELECT * FROM orders JOIN users ON true", hit),
        ("SELECT * FROM users LIMIT ALL", hit),
        ("SELECT * FROM users LIMIT NULL", hit),
        ("SELECT * FROM users OFFSET 10", hit),
        ("SELECT * FROM users WHERE true", hit),
        ("DELETE FROM users RETURNING *", hit),
        ("CREATE TABLE copy_of AS SELECT * FROM users", hit),
        ("PREPARE p AS SELECT * FROM users", hit),
        ("DECLARE c CURSOR FOR SELECT * FROM users", hit),
        ("SELECT 1; SELECT * FROM users; SELECT 2", hit),
        // Narrowed down, or not a read, or not a listed table.
        ("SELECT * FROM users WHERE id = 1", &[]),
        ("SELECT * FROM users LIMIT 10", &[]),
        ("SELECT * FROM users FETCH FIRST 5 ROWS ONLY", &[]),
        ("SELECT * FROM (SELECT * FROM users) AS s LIMIT 3", &[]),
        ("COPY users FROM STDIN", &[]),
        ("SELECT * FROM audit.cards", &[]),
        ("SELECT * FROM users_archive", &[]),
    ]);
}

#[test]
fn the_use_of_a_listed_function_sets_off_its_rule() {
    let hit: &[&str] = &[FUNCTIONS];
    assert_fired(&[
        ("SELECT pg_read_file('x')", hit),
        ("SELECT pg_catalog.pg_read_file('x')", hit),
        ("SELECT lo_export(1, 'x')", hit),
        ("SELECT * FROM pg_read_file('x') AS t", hit),
        ("SELECT (SELECT pg_read_file('x'))", hit),
        ("SELECT id FROM orders ORDER BY pg_read_file('x')", hit),
        ("INSERT INTO notes VALUES (pg_read_file('x'))", hit),
        ("PREPARE p AS SELECT pg_read_file($1)", hit),
        ("COPY (SELECT pg_read_file('x')) TO STDOUT", hit),
        ("EXPLAIN ANALYZE SELECT pg_read_file('x')", hit),
        ("SELECT 1; SELECT 2; SELECT pg_read_file('x')", hit),
        // Another function.
        ("SELECT pg_read_file_of_mine('x')", &[]),
        ("SELECT pg_read_binary_file('x')", &[]),
    ]);
}

#[test]
fn one_text_can_set_off_every_rule_and_each_is_raised_once() {
    assert_fired(&[(
        "SELECT pg_read_file('x') FROM users; TABLE users; \
         SELECT lo_export(1, 'x') FROM pg_class; SELECT * FROM pg_proc",
        &[CATALOG_ENUMERATION, UNBOUNDED_READ, FUNCTIONS],
    )]);
}

// ---------------------------------------------------------------------------
// Names written to hide
// ---------------------------------------------------------------------------

#[test]
fn a_function_is_judged_by_the_name_the_database_reads() {
    let hit: &[&str] = &[FUNCTIONS];
    assert_fired(&[
        // Case: an unquoted name is folded to lower case.
        ("SELECT PG_READ_FILE('x')", hit),
        ("select Pg_Read_File('x')", hit),
        ("SELECT PG_CATALOG.PG_READ_FILE('x')", hit),
        // Quoted: the same name when it is in lower case.
        ("SELECT \"pg_read_file\"('x')", hit),
        ("SELECT \"pg_catalog\".\"pg_read_file\"('x')", hit),
        // Unicode escapes in a name.
        ("SELECT U&\"\\0070g_read_file\"('x')", hit),
        ("SELECT U&\"pg!005Fread!005ffile\" UESCAPE '!' ('x')", hit),
        // Comments and white space between the parts.
        ("SELECT pg_read_file /* a comment */ ('x')", hit),
        ("SELECT pg_catalog /* a */ . /* b */ pg_read_file('x')", hit),
        ("SELECT pg_read_file -- to the end of the line\n ('x')", hit),
        ("SELECT\tpg_read_file\n(\n'x'\n)", hit),
        ("/* SELECT 1 */ SELECT pg_read_file('x') -- SELECT 2", hit),
        // Strings of every kind around it.
        ("SELECT pg_read_file(E'\\x78')", hit),
        ("SELECT pg_read_file($$x$$)", hit),
        ("SELECT pg_read_file($tag$x$tag$)", hit),
        ("SELECT $$ ' $$, pg_read_file('x'), ' $$ '", hit),
        ("SELECT '/*', pg_read_file('x'), '*/'", hit),
        ("SELECT E'\\'', pg_read_file('x')", hit),
        // A name that only looks like it is another name.
        ("SELECT \"PG_READ_FILE\"('x')", &[]),
        ("SELECT \"pg_read_file \"('x')", &[]),
        // The name in a string, a comment or a column is no call.
        ("SELECT 'pg_read_file(''x'')'", &[]),
        ("SELECT $$pg_read_file('x')$$", &[]),
        ("SELECT 1 /* pg_read_file('x') */", &[]),
        ("SELECT 1 -- pg_read_file('x')", &[]),
        ("SELECT pg_read_file FROM notes WHERE id = 1", &[]),
    ]);
}

#[test]
fn a_table_is_judged_by_the_name_the_database_reads() {
    let unbounded: &[&str] = &[UNBOUNDED_READ];
    let catalogue: &[&str] = &[CATALOG_ENUMERATION];
    assert_fired(&[
        ("SELECT * FROM USERS", unbounded),
        ("SELECT * FROM \"users\"", unbounded),
        ("SELECT * FROM PUBLIC.Cards", unbounded),
        ("SELECT * FROM U&\"\\0075sers\"", unbounded),
        ("SELECT * FROM ONLY users", unbounded),
        ("SELECT * FROM users AS \"where\"", unbounded),
        // What looks like a filter and is none.
        ("SELECT * FROM users /* WHERE id = 1 */", unbounded),
        ("SELECT * FROM users -- LIMIT 1", unbounded),
        ("SELECT 'WHERE id = 1 LIMIT 1' FROM users", unbounded),
        ("SELECT $$ WHERE $$ FROM users", unbounded),
        // Another table.
        ("SELECT * FROM \"Users\"", &[]),
        ("SELECT * FROM \"USERS\"", &[]),
        ("SELECT 'users' FROM orders", &[]),
        ("SELECT * FROM orders /* FROM users */", &[]),
        // The catalogues.
        ("SELECT * FROM PG_CLASS WHERE oid = 1", catalogue),
        ("SELECT * FROM \"pg_class\" WHERE oid = 1", catalogue),
        ("SELECT * FROM U&\"pg\\005Fclass\" WHERE oid = 1", catalogue),
        ("SELECT * FROM PG_CATALOG.pg_class WHERE oid = 1", catalogue),
        (
            "SELECT * FROM INFORMATION_SCHEMA.COLUMNS WHERE true",
            catalogue,
        ),
        ("SELECT * FROM \"PG_CLASS\" WHERE oid = 1", &[]),
    ]);
}

// ---------------------------------------------------------------------------
// Where a statement is judged
// ---------------------------------------------------------------------------

#[test]
fn a_prepared_statement_is_judged_once_where_its_text_arrives() {
    let sql = "SELECT * FROM users";
    let mut harness = session(policy(every_rule(ALERT)));
    judge(&mut harness, &parse("s1", sql), sql);
    assert_eq!(fired(&harness), [UNBOUNDED_READ]);
    let events = rule_events(&harness);
    assert_eq!(events.len(), 1);
    assert_eq!(events[0].message_type.as_deref(), Some("Parse"));
    assert_eq!(harness.to_server, parse("s1", sql));

    // Running it asks nothing and raises nothing again.
    harness.effects.clear();
    for _ in 0..3 {
        harness.client(&join(&[&bind("", "s1"), &execute(""), &sync()]));
    }
    assert!(asked(&mut harness).is_empty());
    assert!(rule_hits(&harness).is_empty());
    assert!(rule_events(&harness).is_empty());
    assert!(!harness.session.holds_client());
}

#[test]
fn a_statement_is_judged_by_the_rules_it_was_held_under() {
    let sql = "TABLE users";
    for (held_under, loaded) in [(kill(), ALERT), (ALERT, kill())] {
        let mut harness = session(policy(every_rule(held_under)));
        harness.client(&query(sql));
        let requests = asked(&mut harness);
        // A reload while the statement waits.
        harness.policy = policy(every_rule(loaded));
        answer(&mut harness, requests[0].0, Ok(analysis(sql)));
        assert_eq!(
            rule_hits(&harness),
            [(UNBOUNDED_READ, false, held_under, held_under)]
        );
        assert_eq!(harness.session.is_closed(), held_under == kill());
    }
}

#[test]
fn a_token_in_a_statement_is_found_whatever_the_rules_make_of_it() {
    let sql = format!("SELECT pg_read_file('{EMAIL}')");
    let mut harness = session(policy(every_rule(kill())));
    harness.client(&query(&sql));
    // Reported before the parser has answered.
    assert_eq!(token_hits(&harness), 1);
    let requests = asked(&mut harness);
    answer(&mut harness, requests[0].0, Ok(analysis(&sql)));
    assert_eq!(token_hits(&harness), 1);
    assert_eq!(fired(&harness), [FUNCTIONS]);
    assert!(harness.session.is_closed());
}

// ---------------------------------------------------------------------------
// For whom a rule is on
// ---------------------------------------------------------------------------

#[test]
fn a_rule_is_on_for_the_listeners_and_users_it_names() {
    let sql = "SELECT pg_read_file('x')";
    let main = names(&["main"]);
    let on_main = RuleScope::new(Some(&main), None, &[]);
    let for_app = RuleScope::new(None, Some(&names(&["app"])), &[]);
    let not_etl = RuleScope::new(None, None, &names(&["etl"]));
    let narrow = RuleScope::new(Some(&main), Some(&names(&["app", "etl"])), &names(&["etl"]));
    for (scope, listener, user, on) in [
        (&on_main, Some("main"), "app", true),
        (&on_main, Some("replica"), "app", false),
        // A session whose listener is not known is on no list.
        (&on_main, None, "app", false),
        (&for_app, Some("replica"), "app", true),
        (&for_app, Some("main"), "etl", false),
        (&not_etl, None, "app", true),
        (&not_etl, Some("main"), "etl", false),
        (&narrow, Some("main"), "app", true),
        // Left out wins over listed.
        (&narrow, Some("main"), "etl", false),
        (&narrow, Some("replica"), "app", false),
    ] {
        let case = format!("{scope:?}, {listener:?}, {user}");
        let rules = functions_only(OnParseFailure::Block, scope.clone());
        let places = Arc::new(TarpitPlaces::new());
        let mut harness = session_of(listener, user, &places, policy(rules));
        harness.client(&query(sql));
        let requests = asked(&mut harness);
        if on {
            assert_eq!(requests.len(), 1, "{case}");
            answer(&mut harness, requests[0].0, Ok(analysis(sql)));
            assert_eq!(fired(&harness), [FUNCTIONS], "{case}");
        } else {
            // No rule applies to the session: nothing is held or judged.
            assert!(requests.is_empty(), "{case}");
            assert!(rule_hits(&harness).is_empty(), "{case}");
        }
        assert_eq!(harness.to_server, query(sql), "{case}");
    }
}

#[test]
fn each_rule_has_a_scope_of_its_own() {
    let sql = "SELECT pg_read_file('x') FROM pg_class, users";
    let rules = RuleSet::builder()
        .catalog_enumeration(ALERT, everybody())
        .unwrap()
        .unbounded_read(
            &tables(),
            ALERT,
            RuleScope::new(None, None, &names(&["app"])),
        )
        .unwrap()
        .functions(
            &functions(),
            kill(),
            RuleScope::new(None, Some(&names(&["app"])), &[]),
        )
        .unwrap()
        .build();
    let places = Arc::new(TarpitPlaces::new());

    let mut app = session_of(Some("main"), "app", &places, policy(rules.clone()));
    run(&mut app, sql);
    assert_eq!(fired(&app), [CATALOG_ENUMERATION, FUNCTIONS]);
    assert!(app.session.is_closed());
    assert!(app.to_server.is_empty());

    let mut reporting = session_of(Some("main"), "reporting", &places, policy(rules));
    run(&mut reporting, sql);
    assert_eq!(fired(&reporting), [CATALOG_ENUMERATION, UNBOUNDED_READ]);
    assert!(!reporting.session.is_closed());
    assert_eq!(reporting.to_server, query(sql));
}

// ---------------------------------------------------------------------------
// The responses
// ---------------------------------------------------------------------------

#[test]
fn a_rule_answered_with_kill_ends_the_session_before_the_statement_goes_on() {
    let sql = "SELECT pg_read_file('x')";
    for (message, name) in [(query(sql), "Query"), (parse("s1", sql), "Parse")] {
        for decided in [kill(), set(&[Action::Alert, Action::Kill])] {
            let mut harness = session(policy(every_rule(decided)));
            // Another statement is already behind it.
            harness.client(&join(&[&message, &query("SELECT 2")]));
            let requests = asked(&mut harness);
            assert_eq!(requests.len(), 1, "{name}");
            assert!(harness.to_server.is_empty(), "{name}");
            assert!(rule_hits(&harness).is_empty(), "{name}");

            answer(&mut harness, requests[0].0, Ok(analysis(sql)));
            // Not one byte of the statement, or of what came after it,
            // reached the database.
            assert!(harness.to_server.is_empty(), "{name}");
            assert_eq!(harness.to_client, fatal(), "{name}");
            assert!(harness.session.is_closed(), "{name}");
            assert_eq!(
                rule_hits(&harness),
                [(FUNCTIONS, false, decided, decided)],
                "{name}"
            );
            let events = rule_events(&harness);
            assert_eq!(events.len(), 1, "{name}");
            assert_eq!(events[0].action_taken, decided, "{name}");
            assert_eq!(events[0].message_type.as_deref(), Some(name));
            assert_eq!(events[0].token_id, None, "{name}");
            // What the client had running is cancelled, and both
            // connections close: the ending of a honeytoken hit.
            let ending = &harness.effects[harness.effects.len() - 3..];
            assert_eq!(
                ending,
                [
                    Effect::Cancel { request: cancel() },
                    Effect::Close(Leg::Client),
                    Effect::Close(Leg::Backend),
                ],
                "{name}"
            );
            // The statement behind it is never looked at.
            assert!(asked(&mut harness).is_empty(), "{name}");
        }
    }
}

#[test]
fn a_rule_answered_with_tarpit_slows_the_session_and_lets_the_statement_on() {
    let tarpit = set(&[Action::Tarpit]);
    let sql = "TABLE users";
    let places = Arc::new(TarpitPlaces::new());
    let mut harness = session_of(Some("main"), "app", &places, policy(every_rule(tarpit)));
    run(&mut harness, sql);
    assert_eq!(
        rule_hits(&harness),
        [(UNBOUNDED_READ, false, tarpit, tarpit)]
    );
    assert_eq!(rule_events(&harness)[0].action_taken, tarpit);
    assert_eq!(harness.to_server, query(sql));
    assert!(!harness.session.is_closed());
    assert_eq!(places.held(), 1);
    let started = |harness: &Harness| {
        harness
            .effects
            .iter()
            .filter(|effect| matches!(effect, Effect::Tarpit { .. }))
            .count()
    };
    assert_eq!(started(&harness), 1);

    // From now on what the server sends is held back.
    harness.effects.clear();
    harness.server(&data_row(b"a row"));
    assert!(
        harness
            .effects
            .iter()
            .any(|effect| matches!(effect, Effect::Delay(_)))
    );

    // A second hit takes no second place.
    harness.effects.clear();
    run(&mut harness, sql);
    assert_eq!(started(&harness), 0);
    assert_eq!(places.held(), 1);

    // The one place is taken: the next session is killed, not queued.
    let mut next = session_of(Some("main"), "app", &places, policy(every_rule(tarpit)));
    run(&mut next, sql);
    assert_eq!(rule_hits(&next), [(UNBOUNDED_READ, false, tarpit, kill())]);
    assert_eq!(rule_events(&next)[0].action_taken, kill());
    assert!(next.to_server.is_empty());
    assert!(next.session.is_closed());
    assert_eq!(places.held(), 1);
}

/// A result of one column and one row, as the server sends it.
fn result() -> Vec<u8> {
    let column = join(&[
        &1u16.to_be_bytes(),
        b"id\0",
        &0u32.to_be_bytes(),
        &0u16.to_be_bytes(),
        &23u32.to_be_bytes(),
        &4u16.to_be_bytes(),
        &u32::MAX.to_be_bytes(),
        &0u16.to_be_bytes(),
    ]);
    join(&[
        &frame(b'T', &column),
        &data_row(b"1"),
        &frame(b'C', b"SELECT 1\0"),
        &frame(b'Z', b"I"),
    ])
}

#[test]
fn fake_data_for_a_rule_that_fires_before_a_result_is_an_alert() {
    let fake = set(&[Action::FakeData]);
    let sql = "TABLE users";
    for decided in [fake, set(&[Action::Alert, Action::FakeData])] {
        let mut harness = session(policy(every_rule(decided)));
        run(&mut harness, sql);
        // The count and the event both say what was carried out.
        assert_eq!(
            rule_hits(&harness),
            [(UNBOUNDED_READ, false, decided, ALERT)]
        );
        assert_eq!(rule_events(&harness)[0].action_taken, ALERT);
        assert_eq!(harness.to_server, query(sql));
        assert!(!harness.session.is_closed());

        // The result that follows is the database's and nothing more.
        harness.to_client.clear();
        harness.server(&result());
        assert_eq!(harness.to_client, result());
    }
}

#[test]
fn an_exempt_session_is_counted_and_raises_nothing() {
    let sql = "SELECT pg_read_file('x') FROM pg_class, users";
    let decided = set(&[Action::Alert, Action::Kill]);
    let exempting = || {
        base(OnError::FailClosed, LIMIT)
            .rules(every_rule(decided))
            .exemption(Exemption::new(Some("app".to_owned()), None))
            .build()
            .unwrap()
    };
    let nothing = ActionSet::EMPTY;
    let mut harness = session(exempting());
    run(&mut harness, sql);
    assert_eq!(
        rule_hits(&harness),
        [
            (CATALOG_ENUMERATION, true, nothing, nothing),
            (UNBOUNDED_READ, true, nothing, nothing),
            (FUNCTIONS, true, nothing, nothing),
        ]
    );
    assert!(harness.events().is_empty());
    assert_eq!(harness.to_server, query(sql));
    assert!(!harness.session.is_closed());

    // The session is not flagged: its next statement is not reported.
    harness.effects.clear();
    run(&mut harness, "SELECT 1");
    assert!(harness.events().is_empty());

    // The same statement of anybody else ends the session.
    let places = Arc::new(TarpitPlaces::new());
    let mut other = session_of(Some("main"), "reporting", &places, exempting());
    run(&mut other, sql);
    assert_eq!(rule_events(&other).len(), 3);
    assert!(other.to_server.is_empty());
    assert!(other.session.is_closed());
}

#[test]
fn a_rule_hit_flags_the_session_like_a_honeytoken_hit() {
    let mut harness = session(policy(every_rule(ALERT)));
    run(&mut harness, "SELECT 1");
    assert!(harness.events().is_empty());

    run(&mut harness, "TABLE users");
    let events = harness.events();
    assert_eq!(events.len(), 1);
    assert!(!events[0].session_flagged);

    // From then on every statement is reported, and every hit says so.
    harness.effects.clear();
    run(&mut harness, &format!("SELECT '{EMAIL}' FROM users"));
    let events = harness.events();
    let kinds: Vec<EventKind> = events.iter().map(|event| event.kind).collect();
    assert_eq!(
        kinds,
        [
            EventKind::SessionActivity,
            EventKind::TokenHit,
            EventKind::RuleHit
        ]
    );
    assert!(events.iter().all(|event| event.session_flagged));
}

// ---------------------------------------------------------------------------
// What the rules cannot read
// ---------------------------------------------------------------------------

fn failure_actions(on_failure: OnParseFailure) -> ActionSet {
    match on_failure {
        OnParseFailure::Allow => ActionSet::EMPTY,
        OnParseFailure::Alert => ALERT,
        _ => blocked(),
    }
}

const POLICIES: [OnParseFailure; 3] = [
    OnParseFailure::Allow,
    OnParseFailure::Alert,
    OnParseFailure::Block,
];

#[test]
fn code_in_a_string_makes_a_statement_one_without_an_analysis() {
    for sql in [
        "DO $$ BEGIN PERFORM pg_read_file('x'); END $$",
        "DO LANGUAGE plpgsql 'BEGIN EXECUTE ''SELECT pg_read_'' || ''file(1)''; END'",
        "CREATE FUNCTION peek() RETURNS text LANGUAGE sql AS $$ SELECT pg_read_file('x') $$",
        "CREATE PROCEDURE peek() LANGUAGE plpgsql AS 'BEGIN PERFORM 1; END'",
        "SELECT 1; DO 'BEGIN NULL; END'",
    ] {
        for on_failure in POLICIES {
            let case = format!("{on_failure:?}, {sql}");
            let rules = functions_only(on_failure, everybody());
            let mut harness = session(policy(rules));
            run(&mut harness, sql);
            // The call is in a string, where no rule sees it.
            assert!(rule_hits(&harness).is_empty(), "{case}");
            assert_eq!(
                failures(&harness),
                [(ParseFailure::OpaqueBody, failure_actions(on_failure))],
                "{case}"
            );
            if on_failure == OnParseFailure::Block {
                assert!(harness.to_server.is_empty(), "{case}");
                assert_eq!(harness.to_client, fatal(), "{case}");
                assert!(harness.session.is_closed(), "{case}");
            } else {
                assert_eq!(harness.to_server, query(sql), "{case}");
                assert!(!harness.session.is_closed(), "{case}");
            }
        }
    }
}

#[test]
fn a_statement_with_code_in_a_string_is_still_judged_by_what_is_read() {
    // The function it defines has a listed name, and its body is a string.
    let sql = "CREATE FUNCTION pg_read_file(text) RETURNS text LANGUAGE sql AS 'SELECT $1'";
    let closes = |harness: &Harness| {
        harness
            .effects
            .iter()
            .filter(|effect| **effect == Effect::Close(Leg::Client))
            .count()
    };

    let rules = functions_only(OnParseFailure::Alert, everybody());
    let mut harness = session(policy(rules));
    run(&mut harness, sql);
    assert_eq!(fired(&harness), [FUNCTIONS]);
    assert_eq!(failures(&harness), [(ParseFailure::OpaqueBody, ALERT)]);
    assert_eq!(harness.to_server, query(sql));

    // Ended by the rule and by the policy for it: the session ends once.
    let rules = RuleSet::builder()
        .on_parse_failure(OnParseFailure::Block)
        .functions(&functions(), kill(), everybody())
        .unwrap()
        .build();
    let mut harness = session(policy(rules));
    run(&mut harness, sql);
    assert_eq!(rule_hits(&harness), [(FUNCTIONS, false, kill(), kill())]);
    assert_eq!(failures(&harness), [(ParseFailure::OpaqueBody, blocked())]);
    assert!(harness.to_server.is_empty());
    assert_eq!(harness.to_client, fatal());
    assert_eq!(closes(&harness), 1);
    // It ends as a rule hit ends: with what was running cancelled.
    assert!(
        harness
            .effects
            .contains(&Effect::Cancel { request: cancel() })
    );
    assert!(harness.session.is_closed());
}

/// A `FunctionCall`: the function by its number, and no arguments.
fn function_call() -> Vec<u8> {
    frame(b'F', &[0, 0, 0, 1, 0, 0, 0, 0, 0, 0])
}

#[test]
fn a_function_call_by_number_is_a_statement_without_an_analysis() {
    for on_failure in POLICIES {
        let rules = functions_only(on_failure, everybody());
        let mut harness = session(policy(rules));
        harness.client(&function_call());
        // There is no text to analyse.
        assert!(asked(&mut harness).is_empty(), "{on_failure:?}");
        assert!(!harness.session.holds_client(), "{on_failure:?}");
        assert_eq!(
            failures(&harness),
            [(ParseFailure::FunctionCall, failure_actions(on_failure))],
            "{on_failure:?}"
        );
        if on_failure == OnParseFailure::Block {
            assert!(harness.to_server.is_empty());
            assert_eq!(harness.to_client, fatal());
            assert!(harness.session.is_closed());
        } else {
            assert_eq!(harness.to_server, function_call(), "{on_failure:?}");
            assert!(!harness.session.is_closed(), "{on_failure:?}");
        }
    }
}

#[test]
fn a_function_call_is_let_on_where_no_rule_is_about_functions() {
    let other_rules = RuleSet::builder()
        .on_parse_failure(OnParseFailure::Block)
        .catalog_enumeration(ALERT, everybody())
        .unwrap()
        .unbounded_read(&tables(), ALERT, everybody())
        .unwrap()
        .build();
    let for_others = RuleSet::builder()
        .on_parse_failure(OnParseFailure::Block)
        .catalog_enumeration(ALERT, everybody())
        .unwrap()
        .functions(
            &functions(),
            ALERT,
            RuleScope::new(None, None, &names(&["app"])),
        )
        .unwrap()
        .build();
    for rules in [other_rules, for_others] {
        let mut harness = session(policy(rules));
        harness.client(&function_call());
        assert!(failures(&harness).is_empty());
        assert_eq!(harness.to_server, function_call());
        assert!(!harness.session.is_closed());
    }
}

#[test]
fn a_function_call_that_arrives_in_parts_meets_the_policy_at_its_header() {
    let message = frame(b'F', &vec![0; LIMIT + 1]);
    let (header, body) = message.split_at(5);
    for on_failure in POLICIES {
        let rules = functions_only(on_failure, everybody());
        let mut harness = session(policy(rules));
        harness.client(header);
        assert_eq!(
            failures(&harness),
            [(ParseFailure::FunctionCall, failure_actions(on_failure))],
            "{on_failure:?}"
        );
        harness.client(body);
        if on_failure == OnParseFailure::Block {
            assert!(harness.to_server.is_empty());
            assert!(harness.session.is_closed());
        } else {
            assert_eq!(harness.to_server, message, "{on_failure:?}");
            assert!(!harness.session.is_closed(), "{on_failure:?}");
        }
    }
}
