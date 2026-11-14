// SPDX-License-Identifier: Apache-2.0

//! Tests of what the SQL rules add to a session: a statement is held for
//! its analysis, and a statement without one meets `on_parse_failure`.
//!
//! The first tests run in every build. They show that a policy without
//! rules, and a build without them, hold nothing and find a honeytoken all
//! the same.

use crate::detect::{Matcher, TokenSpec};
use crate::policy::{
    Inspection, OnError, PolicySnapshot, PolicySnapshotBuilder, TokenId, TokenPolicy,
};
use crate::session::Effect;

use super::scan_tests::{EMAIL, EMAIL_ID, Harness, frame, join};

/// The largest message these sessions hold whole.
const LIMIT: usize = 64 * 1024;

fn base(on_error: OnError, limit: usize) -> PolicySnapshotBuilder {
    PolicySnapshot::builder()
        .generation(1)
        .inspection(Inspection::new(on_error, limit))
        .token(TokenPolicy::new(TokenId::new(EMAIL_ID).unwrap()))
        .matcher(Matcher::build(&[TokenSpec::new(EMAIL_ID, [EMAIL])]).unwrap())
}

fn query(sql: &str) -> Vec<u8> {
    frame(b'Q', &join(&[sql.as_bytes(), b"\0"]))
}

fn parse(name: &str, sql: &str) -> Vec<u8> {
    frame(
        b'P',
        &join(&[name.as_bytes(), b"\0", sql.as_bytes(), b"\0", &[0, 0]]),
    )
}

fn token_hits(harness: &Harness) -> usize {
    harness
        .effects
        .iter()
        .filter(|effect| matches!(effect, Effect::TokenHit { .. }))
        .count()
}

#[test]
fn without_rules_a_statement_is_searched_and_passed_on_at_once() {
    let policy = base(OnError::FailClosed, LIMIT).build().unwrap();
    let mut harness = Harness::logged_in(policy, &[(b"user", b"app")]);
    harness.effects.clear();

    let simple = query(&format!("SELECT '{EMAIL}'"));
    harness.client(&simple);
    assert_eq!(token_hits(&harness), 1);
    assert_eq!(harness.to_server, simple);
    assert!(!harness.session.holds_client());

    let extended = parse("s1", &format!("SELECT '{EMAIL}'"));
    harness.client(&extended);
    assert_eq!(token_hits(&harness), 2);
    assert_eq!(harness.to_server, join(&[&simple, &extended]));
    assert!(!harness.session.holds_client());
}

#[cfg(feature = "rules")]
mod with_rules {
    use std::sync::Arc;

    use pgsnare_proto::{Frame, Framer, Step};

    use crate::event::{EventBody, EventKind};
    use crate::extension::ProtocolSession;
    use crate::policy::{Action, ActionSet, Exemption};
    use crate::rules::{
        Analysis, Limits, OnParseFailure, ParseFailure, RuleScope, RuleSet, analyse,
        on_parser_thread,
    };
    use crate::session::{Direction, Leg, Output, Report};

    use super::super::session::MAX_BEHIND;
    use super::super::track::{Statement, Tracker};
    use super::*;

    /// The longest statement these rules have analysed.
    const MAX_PARSE_BYTES: usize = 16 * 1024;

    const POLICIES: [OnParseFailure; 3] = [
        OnParseFailure::Allow,
        OnParseFailure::Alert,
        OnParseFailure::Block,
    ];

    fn rules(on_failure: OnParseFailure, max_parse_bytes: usize, scope: RuleScope) -> RuleSet {
        RuleSet::builder()
            .on_parse_failure(on_failure)
            .max_parse_bytes(max_parse_bytes)
            .unwrap()
            .functions(&["pg_sleep".to_owned()], ActionSet::ALERT, scope)
            .unwrap()
            .build()
    }

    fn policy(on_failure: OnParseFailure) -> PolicySnapshot {
        base(OnError::FailClosed, LIMIT)
            .rules(rules(on_failure, MAX_PARSE_BYTES, RuleScope::default()))
            .build()
            .unwrap()
    }

    fn parameter(name: &[u8], value: &[u8]) -> Vec<u8> {
        frame(b'S', &join(&[name, b"\0", value, b"\0"]))
    }

    /// A session logged in as `app`, before the server has reported any
    /// setting.
    fn fresh(policy: PolicySnapshot) -> Harness {
        let mut harness = Harness::logged_in(policy, &[(b"user", b"app"), (b"database", b"shop")]);
        harness.effects.clear();
        harness
    }

    /// A session logged in as `app` whose server reads statements as the
    /// parser does.
    fn session(policy: PolicySnapshot) -> Harness {
        let mut harness = fresh(policy);
        harness.server(&parameter(b"client_encoding", b"UTF8"));
        harness.server(&parameter(b"standard_conforming_strings", b"on"));
        harness.to_client.clear();
        harness.effects.clear();
        harness
    }

    fn bind(portal: &str, statement: &str) -> Vec<u8> {
        frame(
            b'B',
            &join(&[
                portal.as_bytes(),
                b"\0",
                statement.as_bytes(),
                b"\0",
                &[0, 0, 0, 0, 0, 0],
            ]),
        )
    }

    fn describe(name: &str) -> Vec<u8> {
        frame(b'D', &join(&[b"S", name.as_bytes(), b"\0"]))
    }

    fn execute(portal: &str) -> Vec<u8> {
        frame(b'E', &join(&[portal.as_bytes(), b"\0", &[0, 0, 0, 0]]))
    }

    fn sync() -> Vec<u8> {
        frame(b'S', b"")
    }

    /// The requests for an analysis since the last call: their ids and
    /// texts.
    fn asked(harness: &mut Harness) -> Vec<(u64, Vec<u8>)> {
        let mut asked = Vec::new();
        harness.effects.retain(|effect| match effect {
            Effect::Analyse { id, text, .. } => {
                asked.push((*id, text.as_bytes().to_vec()));
                false
            }
            _ => true,
        });
        asked
    }

    fn report(harness: &mut Harness, report: Report) {
        let mut out = Output::new();
        harness
            .session
            .on_report(report, &harness.policy, &mut out)
            .unwrap();
        harness.to_client.append(&mut out.to_client);
        harness.to_server.append(&mut out.to_server);
        harness.effects.append(&mut out.effects);
    }

    fn answer(harness: &mut Harness, id: u64, outcome: Result<Arc<Analysis>, ParseFailure>) {
        report(harness, Report::Analysed { id, outcome });
    }

    /// What the parser makes of `sql`.
    fn analysis(sql: &str) -> Arc<Analysis> {
        let limits = Limits::with_max_bytes(4 * 1024 * 1024);
        let analysed = on_parser_thread(|thread| analyse(sql.as_bytes(), &limits, thread));
        Arc::new(analysed.unwrap().unwrap())
    }

    fn failures(harness: &Harness) -> Vec<(ParseFailure, ActionSet)> {
        harness
            .effects
            .iter()
            .filter_map(|effect| match effect {
                Effect::ParseFailed { reason, actions } => Some((*reason, *actions)),
                _ => None,
            })
            .collect()
    }

    fn failure_events(harness: &Harness) -> Vec<&EventBody> {
        harness
            .events()
            .into_iter()
            .filter(|body| body.kind == EventKind::ParseFailure)
            .collect()
    }

    fn blocked() -> ActionSet {
        ActionSet::of(&[Action::Alert, Action::Kill])
    }

    /// Checks what a statement without an analysis led to under
    /// `on_failure`. `passed_on` is what the database must have received if
    /// the statement went on, and `before` what it had received already.
    fn assert_failed(
        harness: &Harness,
        on_failure: OnParseFailure,
        reason: ParseFailure,
        message: &str,
        before: &[u8],
        passed_on: &[u8],
    ) {
        let case = format!("{on_failure:?}, {reason:?}, {message}");
        let events = failure_events(harness);
        match on_failure {
            OnParseFailure::Allow => {
                assert_eq!(failures(harness), [(reason, ActionSet::EMPTY)], "{case}");
                assert!(events.is_empty(), "{case}");
                assert_eq!(harness.to_server, passed_on, "{case}");
                assert!(!harness.session.is_closed(), "{case}");
            }
            OnParseFailure::Alert => {
                assert_eq!(failures(harness), [(reason, ActionSet::ALERT)], "{case}");
                assert_eq!(events.len(), 1, "{case}");
                assert_eq!(harness.to_server, passed_on, "{case}");
                assert!(!harness.session.is_closed(), "{case}");
            }
            OnParseFailure::Block => {
                assert_eq!(failures(harness), [(reason, blocked())], "{case}");
                assert_eq!(events.len(), 1, "{case}");
                // Not one byte of the statement reached the database.
                assert_eq!(harness.to_server, before, "{case}");
                assert!(harness.session.is_closed(), "{case}");
                assert_eq!(harness.to_client.first(), Some(&b'E'), "{case}");
                assert!(
                    harness.to_client.windows(5).any(|bytes| bytes == b"FATAL"),
                    "{case}"
                );
                for leg in [Leg::Client, Leg::Backend] {
                    assert!(harness.effects.contains(&Effect::Close(leg)), "{case}");
                }
                // Nothing of it runs, so nothing is cancelled.
                assert!(
                    !harness
                        .effects
                        .iter()
                        .any(|effect| matches!(effect, Effect::Cancel { .. })),
                    "{case}"
                );
            }
        }
        for event in events {
            assert_eq!(event.message_type.as_deref(), Some(message), "{case}");
            assert_eq!(event.direction, Some(Direction::FromClient), "{case}");
            assert_eq!(event.token_id, None, "{case}");
            assert_eq!(event.rule_id, None, "{case}");
            assert!(event.query.is_some(), "{case}");
            assert_eq!(event.db_user.as_deref(), Some("app"), "{case}");
            let expected = match on_failure {
                OnParseFailure::Block => blocked(),
                _ => ActionSet::ALERT,
            };
            assert_eq!(event.action_taken, expected, "{case}");
        }
    }

    // -----------------------------------------------------------------------
    // Holding
    // -----------------------------------------------------------------------

    #[test]
    fn a_query_is_held_until_its_analysis_is_there() {
        let sql = "SELECT pg_sleep(1)";
        let mut harness = session(policy(OnParseFailure::Block));
        harness.client(&query(sql));

        // Exactly the bytes the database would parse, and no byte sent.
        assert_eq!(asked(&mut harness), [(0, sql.as_bytes().to_vec())]);
        assert!(harness.to_server.is_empty());
        assert!(harness.session.holds_client());
        assert_eq!(harness.session.buffered_bytes(), query(sql).len());

        // What the server sends meanwhile goes on.
        let notice = frame(b'N', b"SNOTICE\0\0");
        harness.server(&notice);
        assert_eq!(harness.to_client, notice);
        assert!(harness.to_server.is_empty());

        answer(&mut harness, 0, Ok(analysis(sql)));
        assert_eq!(harness.to_server, query(sql));
        assert!(!harness.session.holds_client());
        assert_eq!(harness.session.buffered_bytes(), 0);
        assert!(failures(&harness).is_empty());
        assert!(failure_events(&harness).is_empty());
    }

    #[test]
    fn what_follows_a_held_parse_waits_behind_it_in_order() {
        let sql = "SELECT $1::int";
        let rest = join(&[&bind("", "s1"), &describe("s1"), &execute(""), &sync()]);
        let mut harness = session(policy(OnParseFailure::Block));
        harness.client(&join(&[&parse("s1", sql), &rest]));

        assert_eq!(asked(&mut harness), [(0, sql.as_bytes().to_vec())]);
        assert!(harness.to_server.is_empty());
        // The statement behind the held one has not been looked at.
        assert!(!harness.effects.contains(&Effect::QuerySeen));

        answer(&mut harness, 0, Ok(analysis(sql)));
        assert_eq!(harness.to_server, join(&[&parse("s1", sql), &rest]));
        assert!(harness.effects.contains(&Effect::QuerySeen));
        assert!(asked(&mut harness).is_empty());
    }

    #[test]
    fn statements_sent_ahead_are_held_one_at_a_time_and_keep_their_order() {
        let statements = ["SELECT 1", "SELECT 2", "SELECT 3", "SELECT 4"];
        let messages: Vec<Vec<u8>> = statements.iter().map(|sql| query(sql)).collect();
        let all = messages.concat();
        // Everything but the last five bytes in one read.
        let (first, last) = all.split_at(all.len() - 5);

        let mut harness = session(policy(OnParseFailure::Block));
        harness.client(first);
        let mut sent = Vec::new();
        for (index, sql) in statements.iter().enumerate() {
            let id = u64::try_from(index).unwrap();
            if index == 3 {
                // The end of the last statement arrives late, and in two
                // pieces, the first while another statement is held.
                assert!(asked(&mut harness).is_empty());
                harness.client(&last[2..]);
            }
            assert_eq!(asked(&mut harness), [(id, sql.as_bytes().to_vec())]);
            assert_eq!(harness.to_server, sent, "before statement {index}");
            if index == 2 {
                harness.client(&last[..2]);
                assert_eq!(harness.to_server, sent);
            }
            answer(&mut harness, id, Ok(analysis(sql)));
            sent.extend_from_slice(&messages[index]);
            assert_eq!(harness.to_server, sent, "after statement {index}");
        }
        assert_eq!(harness.to_server, all);
        assert!(!harness.session.holds_client());
        assert_eq!(harness.session.buffered_bytes(), 0);
    }

    #[test]
    fn an_answer_nobody_waits_for_changes_nothing() {
        let sql = "SELECT 1";
        let mut harness = session(policy(OnParseFailure::Block));

        // Before anything is held.
        answer(&mut harness, 0, Err(ParseFailure::Rejected));
        assert!(harness.effects.is_empty());

        harness.client(&query(sql));
        assert_eq!(asked(&mut harness).len(), 1);
        // The answer to another request.
        answer(&mut harness, 7, Err(ParseFailure::Rejected));
        assert!(harness.session.holds_client());
        assert!(harness.to_server.is_empty());
        assert!(failures(&harness).is_empty());

        answer(&mut harness, 0, Ok(analysis(sql)));
        assert_eq!(harness.to_server, query(sql));
        // A second answer to the same request.
        answer(&mut harness, 0, Err(ParseFailure::Rejected));
        assert!(failures(&harness).is_empty());
        assert!(!harness.session.is_closed());
        assert_eq!(harness.to_server, query(sql));
    }

    #[test]
    fn a_client_cannot_pile_up_bytes_behind_a_held_statement() {
        let mut harness = session(policy(OnParseFailure::Allow));
        harness.client(&query("SELECT 1"));
        assert!(harness.session.holds_client());

        // Up to the bound they wait.
        let chunk = vec![b'x'; MAX_BEHIND / 2];
        harness.client(&chunk);
        harness.client(&chunk);
        assert_eq!(
            harness.session.buffered_bytes(),
            query("SELECT 1").len() + MAX_BEHIND
        );

        // One byte more ends the session.
        let mut out = Output::new();
        let result =
            harness
                .session
                .on_bytes(Direction::FromClient, b"x", &harness.policy, &mut out);
        assert!(result.is_err());
        assert!(harness.session.is_closed());
        assert_eq!(harness.session.buffered_bytes(), 0);
        assert!(out.to_server.is_empty());
        assert!(harness.to_server.is_empty());
    }

    #[test]
    fn a_session_that_holds_a_statement_never_becomes_a_tunnel() {
        let policy = base(OnError::FailOpen, LIMIT)
            .rules(rules(
                OnParseFailure::Block,
                MAX_PARSE_BYTES,
                RuleScope::default(),
            ))
            .build()
            .unwrap();
        let mut harness = session(policy);
        harness.client(&query("SELECT pg_sleep(1)"));
        assert!(harness.session.holds_client());

        // A message of the server that cannot be framed.
        let mut out = Output::new();
        let result = harness.session.on_bytes(
            Direction::FromServer,
            &[b'D', 0, 0, 0, 1],
            &harness.policy,
            &mut out,
        );
        assert!(result.is_err());
        assert!(harness.session.is_closed());
        assert!(!harness.session.is_tunnel());
        assert!(out.to_server.is_empty());
        assert!(harness.to_server.is_empty());
    }

    #[test]
    fn a_held_statement_is_dropped_when_the_proxy_stops() {
        let mut harness = session(policy(OnParseFailure::Allow));
        harness.client(&query("SELECT 1"));
        report(&mut harness, Report::ShuttingDown);
        assert!(harness.session.is_closed());
        assert!(harness.to_server.is_empty());
        assert_eq!(harness.session.buffered_bytes(), 0);

        // The answer comes too late to matter.
        answer(&mut harness, 0, Ok(analysis("SELECT 1")));
        assert!(harness.to_server.is_empty());
    }

    // -----------------------------------------------------------------------
    // Who is held
    // -----------------------------------------------------------------------

    #[test]
    fn a_session_no_rule_applies_to_is_not_held() {
        let other_user = RuleScope::new(None, Some(&["reporting".to_owned()]), &[]);
        let other_listener = RuleScope::new(Some(&["replica".to_owned()]), None, &[]);
        for scope in [other_user, other_listener] {
            let policy = base(OnError::FailClosed, LIMIT)
                .rules(rules(OnParseFailure::Block, MAX_PARSE_BYTES, scope))
                .build()
                .unwrap();
            let mut harness = session(policy);
            harness.client(&query("SELECT pg_sleep(1)"));
            assert!(asked(&mut harness).is_empty());
            assert_eq!(harness.to_server, query("SELECT pg_sleep(1)"));
            assert!(failures(&harness).is_empty());
        }
    }

    #[test]
    fn only_query_and_parse_are_held() {
        let mut harness = session(policy(OnParseFailure::Block));
        let messages = join(&[
            &bind("", "s1"),
            &describe("s1"),
            &execute(""),
            &frame(b'C', b"Ss1\0"),
            &frame(b'H', b""),
            &sync(),
            &frame(b'F', &[0, 0, 0, 1, 0, 0, 0, 0, 0, 0]),
        ]);
        harness.client(&messages);
        assert!(asked(&mut harness).is_empty());
        assert_eq!(harness.to_server, messages);
        assert!(failures(&harness).is_empty());
    }

    // -----------------------------------------------------------------------
    // No analysis
    // -----------------------------------------------------------------------

    /// A statement that names more relations than an analysis holds.
    fn crowded() -> String {
        let tables: Vec<String> = (0..300).map(|index| format!("t{index}")).collect();
        format!("SELECT 1 FROM {}", tables.join(", "))
    }

    #[test]
    fn a_statement_the_runtime_has_no_analysis_for_meets_the_policy() {
        let reasons = [
            ParseFailure::Rejected,
            ParseFailure::TooDeep,
            ParseFailure::InvalidUtf8,
            ParseFailure::Busy,
            ParseFailure::TimedOut,
            ParseFailure::Panicked,
        ];
        let sql = "SELECT pg_sleep(1)";
        let simple = (query(sql), Vec::new(), "Query");
        let extended = (
            parse("", sql),
            join(&[&bind("", ""), &execute(""), &sync()]),
            "Parse",
        );
        for (statement, rest, message) in [simple, extended] {
            for on_failure in POLICIES {
                for reason in reasons {
                    let mut harness = session(policy(on_failure));
                    harness.client(&join(&[&statement, &rest]));
                    assert_eq!(asked(&mut harness), [(0, sql.as_bytes().to_vec())]);
                    assert!(harness.to_server.is_empty());

                    answer(&mut harness, 0, Err(reason));
                    let passed_on = join(&[&statement, &rest]);
                    assert_failed(&harness, on_failure, reason, message, &[], &passed_on);
                }
            }
        }
    }

    #[test]
    fn an_incomplete_analysis_is_no_analysis() {
        let sql = crowded();
        let incomplete = analysis(&sql);
        assert!(!incomplete.is_complete());
        for on_failure in POLICIES {
            let mut harness = session(policy(on_failure));
            harness.client(&query(&sql));
            assert_eq!(asked(&mut harness).len(), 1);
            answer(&mut harness, 0, Ok(Arc::clone(&incomplete)));
            assert_failed(
                &harness,
                on_failure,
                ParseFailure::Incomplete,
                "Query",
                &[],
                &query(&sql),
            );
        }
    }

    #[test]
    fn a_statement_over_the_size_cap_is_not_sent_to_the_parser() {
        // At the cap it is analysed.
        let at_cap = format!("SELECT '{}'", "a".repeat(MAX_PARSE_BYTES - 9));
        assert_eq!(at_cap.len(), MAX_PARSE_BYTES);
        let mut harness = session(policy(OnParseFailure::Block));
        harness.client(&query(&at_cap));
        assert_eq!(asked(&mut harness).len(), 1);
        assert!(failures(&harness).is_empty());

        // One byte over it is not.
        let over = format!("SELECT '{}'", "a".repeat(MAX_PARSE_BYTES - 8));
        for (message, name) in [(query(&over), "Query"), (parse("s1", &over), "Parse")] {
            for on_failure in POLICIES {
                let mut harness = session(policy(on_failure));
                harness.client(&message);
                assert!(asked(&mut harness).is_empty());
                assert!(!harness.session.holds_client());
                assert_failed(
                    &harness,
                    on_failure,
                    ParseFailure::TooLarge,
                    name,
                    &[],
                    &message,
                );
            }
        }
    }

    #[test]
    fn a_malformed_statement_message_is_not_sent_to_the_parser() {
        // The database stops reading at the NUL and refuses what follows.
        let message = frame(b'Q', b"SELECT 1\0; SELECT pg_sleep(1)\0");
        for on_failure in POLICIES {
            let mut harness = session(policy(on_failure));
            harness.client(&message);
            assert!(asked(&mut harness).is_empty());
            assert_failed(
                &harness,
                on_failure,
                ParseFailure::Unreadable,
                "Query",
                &[],
                &message,
            );
        }
    }

    #[test]
    fn a_statement_the_database_reads_differently_is_not_analysed() {
        type Settings = &'static [(&'static [u8], &'static [u8])];
        let cases: [Settings; 5] = [
            // The server has reported nothing yet.
            &[],
            &[(b"standard_conforming_strings", b"on")],
            &[(b"client_encoding", b"LATIN1")],
            &[(b"client_encoding", b"SJIS")],
            &[
                (b"client_encoding", b"UTF8"),
                (b"standard_conforming_strings", b"off"),
            ],
        ];
        let message = query("SELECT pg_sleep(1)");
        for settings in cases {
            for on_failure in POLICIES {
                let mut harness = fresh(policy(on_failure));
                for (name, value) in settings {
                    harness.server(&parameter(name, value));
                }
                harness.to_client.clear();
                harness.client(&message);
                assert!(asked(&mut harness).is_empty());
                assert_failed(
                    &harness,
                    on_failure,
                    ParseFailure::Encoding,
                    "Query",
                    &[],
                    &message,
                );
            }
        }
    }

    #[test]
    fn the_settings_the_server_reports_are_followed() {
        let message = query("SELECT 1");
        let mut harness = session(policy(OnParseFailure::Allow));

        harness.server(&parameter(b"client_encoding", b"EUC_JP"));
        harness.client(&message);
        assert!(asked(&mut harness).is_empty());
        assert_eq!(failures(&harness).len(), 1);

        harness.server(&parameter(b"client_encoding", b"UTF8"));
        harness.server(&parameter(b"standard_conforming_strings", b"off"));
        harness.client(&message);
        assert!(asked(&mut harness).is_empty());
        assert_eq!(failures(&harness).len(), 2);

        // A setting that has nothing to do with it changes nothing.
        harness.server(&parameter(b"application_name", b"LATIN1"));
        harness.server(&parameter(b"standard_conforming_strings", b"on"));
        harness.client(&message);
        assert_eq!(asked(&mut harness).len(), 1);
        assert_eq!(failures(&harness).len(), 2);
    }

    /// A `Query` too large for the session to hold whole, with a honeytoken
    /// near its end.
    fn oversized() -> Vec<u8> {
        let sql = format!("SELECT '{}', '{EMAIL}'", "a".repeat(LIMIT));
        query(&sql)
    }

    #[test]
    fn a_statement_that_arrives_in_parts_meets_the_policy_at_its_header() {
        let message = oversized();
        let (header, body) = message.split_at(5);
        for on_failure in POLICIES {
            let mut harness = session(policy(on_failure));
            harness.client(header);
            assert!(asked(&mut harness).is_empty());
            assert!(!harness.session.holds_client());
            // Decided from the header alone.
            let expected = match on_failure {
                OnParseFailure::Allow => ActionSet::EMPTY,
                OnParseFailure::Alert => ActionSet::ALERT,
                OnParseFailure::Block => blocked(),
            };
            assert_eq!(failures(&harness), [(ParseFailure::Streamed, expected)]);

            // The body is searched to its end, whatever becomes of it.
            let (most, end) = body.split_at(body.len() - 10);
            harness.client(most);
            if on_failure == OnParseFailure::Block {
                assert!(harness.to_server.is_empty());
                assert!(!harness.session.is_closed());
            }
            harness.client(end);
            assert_eq!(token_hits(&harness), 1, "{on_failure:?}");
            assert_failed(
                &harness,
                on_failure,
                ParseFailure::Streamed,
                "Query",
                &[],
                &message,
            );
        }
    }

    #[test]
    fn a_session_the_policy_exempts_is_counted_and_goes_on() {
        let sql = "SELECT pg_sleep(1)";
        let policy = base(OnError::FailClosed, LIMIT)
            .rules(rules(
                OnParseFailure::Block,
                MAX_PARSE_BYTES,
                RuleScope::default(),
            ))
            .exemption(Exemption::new(Some("app".to_owned()), None))
            .build()
            .unwrap();

        let mut harness = session(policy.clone());
        harness.client(&query(sql));
        assert_eq!(asked(&mut harness).len(), 1);
        answer(&mut harness, 0, Err(ParseFailure::Rejected));
        assert_eq!(
            failures(&harness),
            [(ParseFailure::Rejected, ActionSet::EMPTY)]
        );
        assert!(failure_events(&harness).is_empty());
        assert_eq!(harness.to_server, query(sql));
        assert!(!harness.session.is_closed());

        // And one that fails without the parser.
        let mut harness = fresh(policy);
        harness.client(&query(sql));
        assert_eq!(
            failures(&harness),
            [(ParseFailure::Encoding, ActionSet::EMPTY)]
        );
        assert!(failure_events(&harness).is_empty());
        assert_eq!(harness.to_server, query(sql));
    }

    #[test]
    fn a_held_statement_is_judged_by_the_rules_it_was_held_under() {
        let sql = "SELECT pg_sleep(1)";
        for (held_under, loaded) in [
            (OnParseFailure::Block, OnParseFailure::Allow),
            (OnParseFailure::Allow, OnParseFailure::Block),
        ] {
            // A reload, and one that drops the rules altogether.
            for replaced in [
                policy(loaded),
                base(OnError::FailClosed, LIMIT).build().unwrap(),
            ] {
                let mut harness = session(policy(held_under));
                harness.client(&query(sql));
                assert_eq!(asked(&mut harness).len(), 1);

                harness.policy = replaced;
                answer(&mut harness, 0, Err(ParseFailure::TimedOut));
                assert_failed(
                    &harness,
                    held_under,
                    ParseFailure::TimedOut,
                    "Query",
                    &[],
                    &query(sql),
                );
            }
        }
    }

    // -----------------------------------------------------------------------
    // Honeytokens are found whatever the parser does
    // -----------------------------------------------------------------------

    #[test]
    fn a_token_in_a_held_statement_is_reported_before_the_parser_answers() {
        let sql = format!("SELECT '{EMAIL}'");
        for message in [query(&sql), parse("s1", &sql)] {
            let mut harness = session(policy(OnParseFailure::Block));
            harness.client(&message);
            // The parser has not answered, and never does.
            assert_eq!(token_hits(&harness), 1);
            assert_eq!(
                harness
                    .events()
                    .iter()
                    .filter(|body| body.kind == EventKind::TokenHit)
                    .count(),
                1
            );
            assert!(harness.session.holds_client());
            assert!(harness.to_server.is_empty());
        }
    }

    #[test]
    fn a_token_in_a_statement_that_is_blocked_at_once_is_still_reported() {
        let mut harness = fresh(policy(OnParseFailure::Block));
        harness.client(&query(&format!("SELECT '{EMAIL}'")));
        assert_eq!(token_hits(&harness), 1);
        assert_eq!(failures(&harness), [(ParseFailure::Encoding, blocked())]);
        assert!(harness.session.is_closed());
        assert!(harness.to_server.is_empty());
    }

    #[test]
    fn a_statement_a_token_ends_the_session_for_is_not_analysed() {
        let mut token = TokenPolicy::new(TokenId::new(EMAIL_ID).unwrap());
        token.actions = ActionSet::of(&[Action::Alert, Action::Kill]);
        let policy = PolicySnapshot::builder()
            .generation(1)
            .inspection(Inspection::new(OnError::FailClosed, LIMIT))
            .token(token)
            .matcher(Matcher::build(&[TokenSpec::new(EMAIL_ID, [EMAIL])]).unwrap())
            .rules(rules(
                OnParseFailure::Allow,
                MAX_PARSE_BYTES,
                RuleScope::default(),
            ))
            .build()
            .unwrap();
        let mut harness = session(policy);
        harness.client(&query(&format!("SELECT '{EMAIL}'")));
        assert_eq!(token_hits(&harness), 1);
        assert!(harness.session.is_closed());
        assert!(asked(&mut harness).is_empty());
        assert!(harness.to_server.is_empty());
    }

    // -----------------------------------------------------------------------
    // Once per statement
    // -----------------------------------------------------------------------

    #[test]
    fn a_large_prepared_statement_is_analysed_once_however_often_it_runs() {
        const LARGE: usize = 1024 * 1024;
        let sql = format!("SELECT '{}'", "a".repeat(LARGE));
        let policy = base(OnError::FailClosed, 4 * LARGE)
            .rules(rules(
                OnParseFailure::Block,
                2 * LARGE,
                RuleScope::default(),
            ))
            .build()
            .unwrap();
        let mut harness = session(policy);

        harness.client(&join(&[&parse("big", &sql), &sync()]));
        let requests = asked(&mut harness);
        assert_eq!(requests.len(), 1);
        assert_eq!(requests[0].1.len(), sql.len());
        answer(&mut harness, 0, Ok(analysis(&sql)));
        harness.server(&join(&[&frame(b'1', b""), &frame(b'Z', b"I")]));

        let run = join(&[&bind("", "big"), &execute(""), &sync()]);
        let answered = join(&[
            &frame(b'2', b""),
            &frame(b'C', b"SELECT 1\0"),
            &frame(b'Z', b"I"),
        ]);
        for _ in 0..500 {
            harness.client(&run);
            harness.server(&answered);
        }
        // Not one more request, and nothing was held again.
        assert!(asked(&mut harness).is_empty());
        assert!(!harness.session.holds_client());
        assert!(failures(&harness).is_empty());
        assert_eq!(
            harness
                .effects
                .iter()
                .filter(|effect| **effect == Effect::QuerySeen)
                .count(),
            500
        );
    }

    fn whole(bytes: &[u8]) -> Frame<'_> {
        let mut framer = Framer::new(
            pgsnare_proto::Direction::FromClient,
            pgsnare_proto::Limits::buffered_only(1024 * 1024),
        );
        let mut rest = bytes;
        match framer.next(&mut rest).unwrap() {
            Step::Frame(frame) => frame,
            _ => panic!("not a whole message"),
        }
    }

    #[test]
    fn the_analysis_stays_with_the_statement_the_tracker_holds() {
        let sql = format!("SELECT '{}', $1::int", "a".repeat(100 * 1024));
        let analysed = analysis(&sql);
        let mut tracker = Tracker::default();

        let message = parse("s1", &sql);
        let statement = tracker.client(whole(&message), false);
        // No answer yet.
        assert!(statement.analysis().is_none());
        let Statement::Own {
            kept: Some(kept), ..
        } = statement
        else {
            panic!("the tracker did not keep the statement");
        };
        kept.analysed(Ok(Arc::clone(&analysed)));
        // The first answer stays.
        kept.analysed(Err(ParseFailure::Busy));
        tracker.server(b'1', Some(b""));

        for message in [bind("p1", "s1"), describe("s1")] {
            let statement = tracker.client(whole(&message), false);
            let found = statement.analysis().unwrap().as_ref().unwrap();
            assert!(Arc::ptr_eq(found, &analysed));
        }
        tracker.server(b'2', Some(b""));
        let message = execute("p1");
        let statement = tracker.client(whole(&message), false);
        let found = statement.analysis().unwrap().as_ref().unwrap();
        assert!(Arc::ptr_eq(found, &analysed));

        // Another statement has none.
        let other = parse("s2", "SELECT 2");
        assert!(tracker.client(whole(&other), false).analysis().is_none());
    }

    #[test]
    fn a_statement_without_an_analysis_is_reported_once_however_often_it_runs() {
        // A failure is kept like an analysis: the statement is not asked
        // about again, and no second failure is raised when it runs.
        let sql = "SELECT pg_sleep(1)";
        let mut harness = session(policy(OnParseFailure::Alert));
        harness.client(&join(&[&parse("s1", sql), &sync()]));
        assert_eq!(asked(&mut harness).len(), 1);
        answer(&mut harness, 0, Err(ParseFailure::Rejected));
        harness.server(&join(&[&frame(b'1', b""), &frame(b'Z', b"I")]));
        assert_eq!(failures(&harness).len(), 1);

        for _ in 0..3 {
            harness.client(&join(&[&bind("", "s1"), &execute(""), &sync()]));
        }
        assert!(asked(&mut harness).is_empty());
        assert_eq!(failures(&harness).len(), 1);
        assert_eq!(failure_events(&harness).len(), 1);
    }
}
