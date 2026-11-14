// SPDX-License-Identifier: Apache-2.0

//! Tests of what an event shows of a statement under `fingerprint` when
//! the SQL rules have analysed it: the parser's form, made once with the
//! analysis, and the digest of the text wherever that form could show
//! more than it should.

use std::sync::Arc;

use crate::event::{EventBody, EventKind, Query};
use crate::policy::{ActionSet, OnError, PolicySnapshot, QueryRedaction};
use crate::rules::{
    Limits, OnParseFailure, ParseFailure, RuleScope, RuleSet, analyse, on_parser_thread,
};
use crate::session::Effect;

use super::rule_hit_tests::session;
use super::rules::parsed_query;
use super::rules_tests::with_rules::answer;
use super::rules_tests::{LIMIT, base, query};
use super::scan_tests::{EMAIL, Harness};

/// The catalogue rule, answered with `alert`.
fn rules() -> RuleSet {
    RuleSet::builder()
        .on_parse_failure(OnParseFailure::Alert)
        .catalog_enumeration(ActionSet::ALERT, RuleScope::default())
        .unwrap()
        .build()
}

fn policy(redaction: QueryRedaction) -> PolicySnapshot {
    base(OnError::FailClosed, LIMIT)
        .rules(rules())
        .query_redaction(redaction)
        .build()
        .unwrap()
}

fn analysed(sql: &str, limits: Limits) -> Arc<crate::rules::Analysis> {
    Arc::new(
        on_parser_thread(|thread| analyse(sql.as_bytes(), &limits, thread))
            .unwrap()
            .unwrap(),
    )
}

/// Sends `sql` and answers the request with what the parser makes of it
/// under the limits the session asked for. Returns those limits.
fn run(harness: &mut Harness, sql: &str) -> Limits {
    harness.client(&query(sql));
    let mut requests = Vec::new();
    harness.effects.retain(|effect| match effect {
        Effect::Analyse { id, limits, .. } => {
            requests.push((*id, *limits));
            false
        }
        _ => true,
    });
    assert_eq!(requests.len(), 1, "{sql}");
    let (id, limits) = requests[0];
    answer(harness, id, Ok(analysed(sql, limits)));
    limits
}

/// The statement of the one event of `kind`.
fn shown(harness: &Harness, kind: EventKind) -> Query {
    let events: Vec<&EventBody> = harness
        .events()
        .into_iter()
        .filter(|body| body.kind == kind)
        .collect();
    assert_eq!(events.len(), 1);
    events[0].query.clone().unwrap()
}

fn is_hex(text: &str, length: usize) -> bool {
    text.len() == length && text.bytes().all(|byte| byte.is_ascii_hexdigit())
}

/// The form of an event that shows the digest of the whole text.
fn assert_digest(query: &Query) {
    assert_eq!(query.redaction, QueryRedaction::Fingerprint);
    assert!(
        is_hex(query.fingerprint.as_deref().unwrap(), 64),
        "{query:?}"
    );
    assert_eq!(query.normalized, None);
    assert_eq!(query.text, None);
}

#[test]
fn a_rule_hit_shows_the_parsers_form_without_its_constants() {
    let mut harness = session(policy(QueryRedaction::Fingerprint));
    let limits = run(
        &mut harness,
        "SELECT relname FROM pg_class WHERE relname = 'secret' AND relpages > 4711",
    );
    assert!(limits.normalise);
    let query = shown(&harness, EventKind::RuleHit);
    assert!(query.known);
    assert_eq!(query.redaction, QueryRedaction::Fingerprint);
    assert_eq!(query.text, None);
    assert!(
        is_hex(query.fingerprint.as_deref().unwrap(), 16),
        "{query:?}"
    );
    let normalized = query.normalized.unwrap();
    assert!(
        normalized.contains("pg_class") && normalized.contains("$1"),
        "{normalized}"
    );
    assert!(
        !normalized.contains("secret") && !normalized.contains("4711"),
        "{normalized}"
    );

    // The same statement with other constants has the same fingerprint.
    let mut other = session(policy(QueryRedaction::Fingerprint));
    run(
        &mut other,
        "SELECT relname FROM pg_class WHERE relname = 'other' AND relpages > 1",
    );
    assert_eq!(
        shown(&other, EventKind::RuleHit).fingerprint,
        shown(&harness, EventKind::RuleHit).fingerprint
    );
}

#[test]
fn other_modes_ask_for_no_form_and_show_what_they_did() {
    let sql = "SELECT relname FROM pg_class";
    let mut harness = session(policy(QueryRedaction::Full));
    assert!(!run(&mut harness, sql).normalise);
    assert_eq!(
        shown(&harness, EventKind::RuleHit).text.as_deref(),
        Some(sql)
    );

    let mut harness = session(policy(QueryRedaction::None));
    assert!(!run(&mut harness, sql).normalise);
    assert_eq!(shown(&harness, EventKind::RuleHit), Query::withheld());
}

#[test]
fn a_form_that_holds_a_honeytoken_gives_way_to_the_digest() {
    // The token is a name here, which the parser does not replace.
    let mut harness = session(policy(QueryRedaction::Fingerprint));
    run(
        &mut harness,
        &format!("SELECT 1 FROM pg_class AS \"{EMAIL}\""),
    );
    assert_digest(&shown(&harness, EventKind::RuleHit));
}

#[test]
fn a_form_that_may_hold_a_constant_gives_way_to_the_digest() {
    for sql in [
        // The parser keeps comments as they are written.
        "SELECT relname FROM pg_class /* secret */",
        "SELECT relname FROM pg_class -- secret",
        // A kind of statement whose constants the parser does not replace.
        "CREATE VIEW v AS SELECT relname, 4711 AS pin FROM pg_class",
    ] {
        let mut harness = session(policy(QueryRedaction::Fingerprint));
        run(&mut harness, sql);
        assert_digest(&shown(&harness, EventKind::RuleHit));
    }
}

#[test]
fn a_statement_without_an_analysis_shows_the_digest() {
    let mut harness = session(policy(QueryRedaction::Fingerprint));
    harness.client(&query("SELEC 1"));
    let id = harness
        .effects
        .iter()
        .find_map(|effect| match effect {
            Effect::Analyse { id, .. } => Some(*id),
            _ => None,
        })
        .unwrap();
    answer(&mut harness, id, Err(ParseFailure::Rejected));
    assert_digest(&shown(&harness, EventKind::ParseFailure));
}

#[test]
fn the_form_is_kept_only_for_kinds_the_parser_replaces_every_constant_of() {
    let normalised = Limits::default().normalised(true);
    let form = |sql: &str| parsed_query(&analysed(sql, normalised));
    let select = form("SELECT * FROM users WHERE pin = 4711").unwrap();
    assert!(!select.normalized.unwrap().contains("4711"));
    for sql in [
        "PREPARE p AS SELECT * FROM users WHERE pin = 4711",
        "COMMENT ON TABLE users IS 'secret'",
        "EXPLAIN CREATE TABLE t AS SELECT 4711",
        "SELECT $q$secret$q$ /* x */",
        "PREPARE TRANSACTION 'secret'",
    ] {
        assert_eq!(form(sql), None, "{sql}");
    }
    // Without the form, nothing to show.
    assert_eq!(parsed_query(&analysed("SELECT 1", Limits::default())), None);
}
