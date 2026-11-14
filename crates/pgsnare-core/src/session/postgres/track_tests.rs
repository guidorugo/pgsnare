// SPDX-License-Identifier: Apache-2.0

//! Tests of what a hit says about its statement and of what the policy
//! makes of a hit: attribution, exemptions, escalation and the flagged
//! session. Most go through a whole session: bytes in, effects out.

use pgsnare_proto::{Framer, Limits, Step};

use crate::detect::{Matcher, TokenSpec};
use crate::event::{EventBody, EventKind, MAX_STATEMENT_BYTES, Query};
use crate::policy::{
    Action, ActionSet, Escalation, Exemption, Inspection, OnError, PolicySnapshot, QueryRedaction,
    TokenId, TokenPolicy,
};
use crate::session::Direction::{FromClient, FromServer};
use crate::session::Effect;

use super::scan::MAX_COUNTED_TOKENS;
use super::scan_tests::{
    CANARY, CANARY_ID, EMAIL, EMAIL_ID, Harness, LIMIT, data_row, digest, frame, join,
};
use super::track::{
    MAX_NAME_BYTES, MAX_PENDING, MAX_PORTALS, MAX_STATEMENTS, MAX_TEXT_BYTES, Tracker,
};

// ---------------------------------------------------------------------------
// Messages
// ---------------------------------------------------------------------------

fn query(sql: &str) -> Vec<u8> {
    frame(b'Q', &join(&[sql.as_bytes(), b"\0"]))
}

fn parse(name: &str, sql: &str) -> Vec<u8> {
    frame(
        b'P',
        &join(&[name.as_bytes(), b"\0", sql.as_bytes(), b"\0", &[0, 0]]),
    )
}

/// A `Bind` with one text parameter.
fn bind(portal: &str, statement: &str, value: &str) -> Vec<u8> {
    let length = u32::try_from(value.len()).unwrap().to_be_bytes();
    frame(
        b'B',
        &join(&[
            portal.as_bytes(),
            b"\0",
            statement.as_bytes(),
            b"\0",
            &[0, 0, 0, 1],
            &length,
            value.as_bytes(),
            &[0, 0],
        ]),
    )
}

fn execute(portal: &str) -> Vec<u8> {
    frame(b'E', &join(&[portal.as_bytes(), b"\0", &[0, 0, 0, 0]]))
}

fn describe(target: u8, name: &str) -> Vec<u8> {
    frame(b'D', &join(&[&[target], name.as_bytes(), b"\0"]))
}

fn close(target: u8, name: &str) -> Vec<u8> {
    frame(b'C', &join(&[&[target], name.as_bytes(), b"\0"]))
}

fn sync() -> Vec<u8> {
    frame(b'S', b"")
}

fn function_call() -> Vec<u8> {
    frame(b'F', &[0, 0, 4, 0, 0, 0, 0, 0, 0, 0])
}

fn ready(status: u8) -> Vec<u8> {
    frame(b'Z', &[status])
}

fn complete() -> Vec<u8> {
    frame(b'C', b"SELECT 1\0")
}

fn error(message: &str) -> Vec<u8> {
    frame(
        b'E',
        &join(&[b"SERROR\0C22P02\0M", message.as_bytes(), b"\0\0"]),
    )
}

/// A row that holds the first token.
fn row() -> Vec<u8> {
    data_row(EMAIL.as_bytes())
}

/// One whole batch of the extended protocol, with the unnamed statement
/// and portal.
fn batch(sql: &str) -> Vec<u8> {
    join(&[&parse("", sql), &bind("", "", "1"), &execute(""), &sync()])
}

// ---------------------------------------------------------------------------
// Policies and what a session raised
// ---------------------------------------------------------------------------

struct Options {
    redaction: QueryRedaction,
    exemptions: Vec<Exemption>,
    escalate: Option<Escalation>,
    generation: u64,
}

impl Default for Options {
    fn default() -> Self {
        Self {
            redaction: QueryRedaction::Fingerprint,
            exemptions: Vec::new(),
            escalate: None,
            generation: 1,
        }
    }
}

fn policy(options: Options) -> PolicySnapshot {
    let tokens = [(EMAIL_ID, EMAIL), (CANARY_ID, CANARY)];
    let specs: Vec<TokenSpec> = tokens
        .iter()
        .map(|(id, value)| TokenSpec::new(*id, [*value]))
        .collect();
    PolicySnapshot::builder()
        .generation(options.generation)
        .inspection(Inspection::new(OnError::FailClosed, LIMIT))
        .tokens(tokens.iter().map(|(id, _)| {
            let mut token = TokenPolicy::new(TokenId::new(id).unwrap());
            token.escalate = options.escalate;
            token
        }))
        .exemptions(options.exemptions)
        .query_redaction(options.redaction)
        .matcher(Matcher::build(&specs).unwrap())
        .build()
        .unwrap()
}

fn user(name: &str) -> Exemption {
    Exemption::new(Some(name.to_owned()), None)
}

fn range(cidr: &str) -> Exemption {
    Exemption::new(None, Some(cidr.parse().unwrap()))
}

fn session(options: Options) -> Harness {
    session_of("app", options)
}

/// A session that has logged in as `name`, from 192.0.2.10.
fn session_of(name: &str, options: Options) -> Harness {
    let mut harness = Harness::logged_in(
        policy(options),
        &[(b"user", name.as_bytes()), (b"database", b"shop")],
    );
    assert!(harness.hits().is_empty());
    harness
}

fn known(sql: &str) -> Option<Query> {
    Some(Query::from_statement(
        sql.as_bytes(),
        QueryRedaction::Fingerprint,
        &digest,
    ))
}

fn unknown() -> Option<Query> {
    Some(Query::unknown(QueryRedaction::Fingerprint))
}

/// The events raised since the last call.
fn events(harness: &mut Harness) -> Vec<EventBody> {
    std::mem::take(&mut harness.effects)
        .into_iter()
        .filter_map(|effect| match effect {
            Effect::Emit(body) => Some(*body),
            _ => None,
        })
        .collect()
}

/// The statements of the hits raised since the last call.
fn statements(harness: &mut Harness) -> Vec<Option<Query>> {
    events(harness)
        .into_iter()
        .filter(|body| body.kind == EventKind::TokenHit)
        .map(|body| body.query)
        .collect()
}

/// What the hits raised since the last call were counted as: whether
/// exempt, what the policy decided, what was done.
fn counted(harness: &mut Harness) -> Vec<(bool, ActionSet, ActionSet)> {
    std::mem::take(&mut harness.effects)
        .into_iter()
        .filter_map(|effect| match effect {
            Effect::TokenHit {
                exempt,
                decided,
                actions,
                ..
            } => Some((exempt, decided, actions)),
            _ => None,
        })
        .collect()
}

const ALERT: ActionSet = ActionSet::ALERT;

fn kill() -> ActionSet {
    ActionSet::of(&[Action::Kill])
}

// ---------------------------------------------------------------------------
// Attribution
// ---------------------------------------------------------------------------

#[test]
fn a_hit_in_the_simple_protocol_names_its_statement() {
    let mut harness = session(Options::default());
    harness.client(&query("SELECT email FROM users"));
    harness.server(&frame(b'T', &[0, 0]));
    harness.server(&row());
    assert_eq!(statements(&mut harness), [known("SELECT email FROM users")]);
    harness.server(&join(&[&complete(), &ready(b'I')]));

    // The next statement is another one, and a notice belongs to the
    // statement that runs.
    harness.client(&query("SELECT 2"));
    harness.server(&row());
    harness.server(&frame(
        b'N',
        &join(&[b"SNOTICE\0M", EMAIL.as_bytes(), b"\0\0"]),
    ));
    assert_eq!(
        statements(&mut harness),
        [known("SELECT 2"), known("SELECT 2")]
    );
    harness.server(&join(&[&complete(), &ready(b'I')]));

    // A value in the statement itself.
    let sql = format!("SELECT '{EMAIL}'");
    harness.client(&query(&sql));
    assert_eq!(statements(&mut harness), [known(&sql)]);
    harness.server(&join(&[&complete(), &ready(b'I')]));

    // Nothing runs: a message of the server has no statement.
    harness.server(&frame(
        b'A',
        &join(&[&[0, 0, 0, 1], b"c\0", EMAIL.as_bytes(), b"\0"]),
    ));
    assert_eq!(statements(&mut harness), [unknown()]);
}

#[test]
fn a_hit_in_the_extended_protocol_names_its_statement() {
    let mut harness = session(Options::default());
    // Two batches sent before the server answers the first: one with the
    // unnamed statement and portal, one with names.
    harness.client(&join(&[
        &parse("", "SELECT a FROM one"),
        &bind("", "", "1"),
        &describe(b'P', ""),
        &execute(""),
        &sync(),
        &parse("s2", "SELECT b FROM two"),
        &bind("p2", "s2", "1"),
        &execute("p2"),
        &sync(),
    ]));
    harness.server(&join(&[&frame(b'1', b""), &frame(b'2', b"")]));
    // A column of the description is named like the value.
    harness.server(&frame(b'T', &join(&[&[0, 1], EMAIL.as_bytes()])));
    harness.server(&row());
    assert_eq!(
        statements(&mut harness),
        [known("SELECT a FROM one"), known("SELECT a FROM one")]
    );
    harness.server(&join(&[&complete(), &ready(b'T')]));
    harness.server(&join(&[&frame(b'1', b""), &frame(b'2', b""), &row()]));
    assert_eq!(statements(&mut harness), [known("SELECT b FROM two")]);
    // The portal is suspended and run again in the same transaction.
    harness.server(&join(&[&frame(b's', b""), &ready(b'T')]));
    harness.client(&join(&[&execute("p2"), &sync()]));
    harness.server(&row());
    assert_eq!(statements(&mut harness), [known("SELECT b FROM two")]);
    harness.server(&join(&[&complete(), &ready(b'I')]));

    // The named statement is used again later. A value in a parameter
    // belongs to the statement the parameter is bound to.
    harness.client(&join(&[&bind("", "s2", EMAIL), &execute(""), &sync()]));
    harness.server(&join(&[&frame(b'2', b""), &row()]));
    assert_eq!(
        statements(&mut harness),
        [known("SELECT b FROM two"), known("SELECT b FROM two")]
    );
    harness.server(&join(&[&complete(), &ready(b'I')]));

    // The transaction is over and the portal with it; a statement that
    // was closed is gone.
    harness.client(&join(&[&execute("p2"), &sync()]));
    harness.server(&row());
    harness.server(&join(&[&complete(), &ready(b'I')]));
    harness.client(&join(&[&close(b'S', "s2"), &sync()]));
    harness.server(&join(&[&frame(b'3', b""), &ready(b'I')]));
    harness.client(&join(&[&bind("", "s2", "1"), &execute(""), &sync()]));
    harness.server(&join(&[&frame(b'2', b""), &row()]));
    assert_eq!(statements(&mut harness), [unknown(), unknown()]);
}

#[test]
fn after_an_error_the_next_batch_is_attributed_to_its_own_statement() {
    let mut harness = session(Options::default());
    harness.client(&join(&[&batch("SELECT 'x'::int"), &batch("SELECT b")]));
    harness.server(&join(&[&frame(b'1', b""), &frame(b'2', b"")]));
    // The error quotes the value. It belongs to the statement that failed.
    harness.server(&error(EMAIL));
    assert_eq!(statements(&mut harness), [known("SELECT 'x'::int")]);
    // The server skipped the rest of the first batch.
    harness.server(&ready(b'I'));
    harness.server(&join(&[&frame(b'1', b""), &frame(b'2', b""), &row()]));
    assert_eq!(statements(&mut harness), [known("SELECT b")]);
    harness.server(&join(&[&complete(), &ready(b'I')]));

    // The server skips what follows an error until `Sync`, a `Query`
    // included, also when the client sends it after the error.
    harness.client(&parse("", "SELEC"));
    harness.server(&error("syntax error"));
    harness.client(&join(&[
        &bind("", "", "1"),
        &query("SELECT skipped"),
        &sync(),
    ]));
    harness.client(&query("SELECT c"));
    harness.server(&join(&[&ready(b'I'), &row()]));
    assert_eq!(statements(&mut harness), [known("SELECT c")]);
    harness.server(&join(&[&complete(), &ready(b'I')]));

    // An error in the simple protocol skips nothing.
    harness.client(&join(&[&query("SELECT 1/0"), &query("SELECT d")]));
    harness.server(&join(&[&error("division by zero"), &ready(b'I'), &row()]));
    assert_eq!(statements(&mut harness), [known("SELECT d")]);
}

#[test]
fn a_parse_the_server_refuses_does_not_rename_a_statement() {
    let mut harness = session(Options::default());
    harness.client(&join(&[&parse("s", "SELECT old"), &sync()]));
    harness.server(&join(&[&frame(b'1', b""), &ready(b'I')]));

    // The name is taken, so the server refuses the second `Parse`. The
    // client does not wait to learn that.
    harness.client(&join(&[&parse("s", "SELECT new"), &sync()]));
    // Before the answer nobody can tell what the name will stand for.
    harness.client(&join(&[&bind("", "s", EMAIL), &execute(""), &sync()]));
    assert_eq!(statements(&mut harness), [unknown()]);
    harness.server(&join(&[&error("already exists"), &ready(b'I')]));
    harness.server(&join(&[&frame(b'2', b""), &row()]));
    assert_eq!(statements(&mut harness), [known("SELECT old")]);

    // In one batch the `Bind` runs only if the `Parse` before it worked.
    let mut harness = session(Options::default());
    harness.client(&join(&[
        &parse("s", "SELECT new"),
        &bind("", "s", EMAIL),
        &execute(""),
        &sync(),
    ]));
    assert_eq!(statements(&mut harness), [known("SELECT new")]);
}

#[test]
fn a_hit_in_a_copy_names_the_statement_that_copies() {
    let mut harness = session(Options::default());
    harness.client(&query("COPY users TO STDOUT"));
    harness.server(&frame(b'H', &[0, 0, 0]));
    harness.server(&frame(b'd', EMAIL.as_bytes()));
    assert_eq!(statements(&mut harness), [known("COPY users TO STDOUT")]);
    harness.server(&join(&[&frame(b'c', b""), &complete(), &ready(b'I')]));

    harness.client(&query("COPY users FROM STDIN"));
    // Before the server announces the COPY, the data has no statement.
    harness.client(&frame(b'd', CANARY.as_bytes()));
    assert_eq!(statements(&mut harness), [unknown()]);
    harness.server(&frame(b'G', &[0, 0, 0]));
    harness.client(&frame(b'd', EMAIL.as_bytes()));
    // The message that ends the COPY is shown when the COPY is over.
    harness.client(&frame(b'f', EMAIL.as_bytes()));
    assert_eq!(
        statements(&mut harness),
        [known("COPY users FROM STDIN"), unknown()]
    );
    harness.server(&join(&[&error("COPY failed"), &ready(b'I')]));

    // A COPY inside a batch of the extended protocol.
    harness.client(&batch("COPY cards TO STDOUT"));
    harness.server(&join(&[&frame(b'1', b""), &frame(b'2', b"")]));
    harness.server(&frame(b'H', &[0, 0, 0]));
    harness.server(&frame(b'd', EMAIL.as_bytes()));
    assert_eq!(statements(&mut harness), [known("COPY cards TO STDOUT")]);
    harness.server(&join(&[&frame(b'c', b""), &complete(), &ready(b'I')]));
    harness.client(&query("SELECT after"));
    harness.server(&row());
    assert_eq!(statements(&mut harness), [known("SELECT after")]);
}

#[test]
fn a_message_in_chunks_keeps_its_statement() {
    let mut harness = session(Options::default());
    harness.client(&query("SELECT big"));
    let padding = "x".repeat(LIMIT * 2);
    let large = data_row(format!("{padding}{EMAIL}{padding}{CANARY}").as_bytes());
    harness.server(&large);
    assert_eq!(
        statements(&mut harness),
        [known("SELECT big"), known("SELECT big")]
    );
    harness.server(&join(&[&complete(), &ready(b'I')]));

    // A statement too large to hold has no text to show, and the tracker
    // keeps its place.
    harness.client(&query(&format!("SELECT '{padding}{EMAIL}'")));
    harness.server(&row());
    assert_eq!(statements(&mut harness), [unknown(), unknown()]);
    harness.server(&join(&[&complete(), &ready(b'I')]));
    harness.client(&query("SELECT small"));
    harness.server(&row());
    assert_eq!(statements(&mut harness), [known("SELECT small")]);
}

// ---------------------------------------------------------------------------
// Losing the place
// ---------------------------------------------------------------------------

#[test]
fn a_tracker_that_overflows_still_lets_the_hit_through_with_its_statement_unknown() {
    let mut harness = session(Options::default());
    // One message more than the queue holds, none answered yet.
    for _ in 0..=MAX_PENDING {
        harness.client(&parse("", "SELECT a"));
    }
    harness.client(&join(&[&bind("", "", "1"), &execute(""), &sync()]));
    for _ in 0..=MAX_PENDING {
        harness.server(&frame(b'1', b""));
    }
    harness.server(&join(&[&frame(b'2', b""), &row()]));
    assert_eq!(statements(&mut harness), [unknown()]);

    // A statement sent while the place is lost stays unknown: the tracker
    // waits for every answer that is outstanding.
    harness.client(&query("SELECT b"));
    harness.server(&join(&[&complete(), &ready(b'I'), &row()]));
    assert_eq!(statements(&mut harness), [unknown()]);
    harness.server(&join(&[&complete(), &ready(b'I')]));

    // From there on it follows again.
    harness.client(&query("SELECT c"));
    harness.server(&row());
    assert_eq!(statements(&mut harness), [known("SELECT c")]);
}

#[test]
fn a_message_the_tracker_does_not_expect_makes_the_statement_unknown_until_the_server_is_ready() {
    let unexpected: [(&str, Vec<u8>); 4] = [
        ("an answer to nothing that was asked", frame(b'2', b"")),
        ("a type that does not exist", frame(b'?', b"")),
        ("a login message", frame(b'R', &[0, 0, 0, 0])),
        ("the end of a portal no one ran", frame(b's', b"")),
    ];
    for (what, message) in unexpected {
        let mut harness = session(Options::default());
        harness.client(&query("SELECT a"));
        harness.server(&message);
        harness.server(&row());
        assert_eq!(statements(&mut harness), [unknown()], "{what}");
        harness.server(&join(&[&complete(), &ready(b'I')]));
        harness.client(&query("SELECT b"));
        harness.server(&row());
        assert_eq!(statements(&mut harness), [known("SELECT b")], "{what}");
    }

    // The client can make the tracker give up as well: a name the server
    // would cut, a message that is malformed.
    let long = "n".repeat(MAX_NAME_BYTES + 1);
    for message in [parse(&long, "SELECT a"), frame(b'B', b"\0")] {
        let mut harness = session(Options::default());
        harness.client(&join(&[
            &message,
            &bind("", &long, "1"),
            &execute(""),
            &sync(),
        ]));
        harness.server(&row());
        assert_eq!(statements(&mut harness), [unknown()]);
    }

    // A row without a statement in front of it.
    let mut harness = session(Options::default());
    harness.server(&row());
    assert_eq!(statements(&mut harness), [unknown()]);
}

fn feed(tracker: &mut Tracker, from_client: bool, bytes: &[u8]) {
    let direction = if from_client {
        pgsnare_proto::Direction::FromClient
    } else {
        pgsnare_proto::Direction::FromServer
    };
    let mut framer = Framer::new(direction, Limits::buffered_only(1 << 24));
    let mut rest = bytes;
    while !rest.is_empty() {
        let Step::Frame(frame) = framer.next(&mut rest).unwrap() else {
            panic!("not a whole message");
        };
        if from_client {
            let _ = tracker.client(frame, false);
        } else {
            let _ = tracker.server(frame.tag(), Some(frame.body()));
        }
        let [pending, statements, portals, text] = tracker.held();
        assert!(pending <= MAX_PENDING);
        assert!(statements <= MAX_STATEMENTS);
        assert!(portals <= MAX_PORTALS);
        assert!(text <= MAX_TEXT_BYTES);
    }
}

#[test]
fn what_a_tracker_holds_is_bounded() {
    let sql = "z".repeat(2000);

    // More statements and portals than it records, each confirmed.
    let mut tracker = Tracker::default();
    for n in 0..MAX_STATEMENTS * 3 {
        let name = format!("s{n}");
        feed(
            &mut tracker,
            true,
            &join(&[&parse(&name, &sql), &bind(&name, &name, "1"), &sync()]),
        );
        feed(
            &mut tracker,
            false,
            &join(&[&frame(b'1', b""), &frame(b'2', b""), &ready(b'T')]),
        );
    }
    let [pending, statements, portals, text] = tracker.held();
    assert_eq!(pending, 0);
    assert!(statements > 0 && portals > 0 && text > 0);
    assert!(!tracker.is_lost());

    // A text that does not fit is not kept.
    feed(&mut tracker, true, &query(&"y".repeat(MAX_TEXT_BYTES + 1)));
    assert!(tracker.held()[3] <= text);

    // Messages the server never answers: the queue fills, and then
    // everything is let go.
    let mut tracker = Tracker::default();
    for _ in 0..MAX_PENDING * 2 {
        feed(&mut tracker, true, &parse("", &sql));
    }
    assert!(tracker.is_lost());
    assert_eq!(tracker.held(), [0, 0, 0, 0]);

    // What is closed or replaced is given back.
    let mut tracker = Tracker::default();
    for _ in 0..3 {
        feed(&mut tracker, true, &join(&[&parse("s", &sql), &sync()]));
        feed(
            &mut tracker,
            false,
            &join(&[&frame(b'1', b""), &ready(b'I')]),
        );
        assert_eq!(tracker.held(), [0, 1, 0, sql.len()]);
        feed(&mut tracker, true, &join(&[&close(b'S', "s"), &sync()]));
        feed(
            &mut tracker,
            false,
            &join(&[&frame(b'3', b""), &ready(b'I')]),
        );
        assert_eq!(tracker.held(), [0, 0, 0, 0]);
    }
    assert!(!format!("{tracker:?}").contains('z'));
}

// ---------------------------------------------------------------------------
// What an event shows of a statement
// ---------------------------------------------------------------------------

#[test]
fn the_statement_of_an_event_is_shown_as_the_redaction_mode_says() {
    let sql = "SELECT email FROM users WHERE id = 4711";
    let shown = |redaction: QueryRedaction| {
        let mut harness = session(Options {
            redaction,
            ..Options::default()
        });
        harness.client(&query(sql));
        harness.server(&row());
        // The statement after the hit is reported too.
        harness.server(&join(&[&complete(), &ready(b'I')]));
        harness.client(&query(sql));
        let events = events(&mut harness);
        assert_eq!(events.len(), 2);
        for body in &events {
            assert_eq!(
                body.query,
                Some(Query::from_statement(sql.as_bytes(), redaction, &digest))
            );
        }
        format!("{events:?}{}", serde_json::to_string(&events).unwrap())
    };

    assert!(shown(QueryRedaction::Full).contains(sql));
    for redaction in [QueryRedaction::Fingerprint, QueryRedaction::None] {
        let said = shown(redaction);
        assert!(!said.contains("id = 4711"), "{redaction:?} shows the text");
        assert!(!said.contains("FROM users"), "{redaction:?} shows the text");
    }

    // A long statement is cut, also when the whole text may be shown.
    let long = format!("SELECT '{}'", "z".repeat(MAX_STATEMENT_BYTES * 2));
    let mut harness = Harness::logged_in(
        PolicySnapshot::builder()
            .inspection(Inspection::new(OnError::FailClosed, 64 * 1024))
            .token(TokenPolicy::new(TokenId::new(EMAIL_ID).unwrap()))
            .query_redaction(QueryRedaction::Full)
            .matcher(Matcher::build(&[TokenSpec::new(EMAIL_ID, [EMAIL])]).unwrap())
            .build()
            .unwrap(),
        &[(b"user", b"app")],
    );
    harness.client(&query(&long));
    harness.server(&row());
    let events = events(&mut harness);
    let text = events[0].query.as_ref().unwrap().text.as_ref().unwrap();
    assert!(text.len() < MAX_STATEMENT_BYTES + 64);
}

// ---------------------------------------------------------------------------
// Exemptions
// ---------------------------------------------------------------------------

#[test]
fn a_hit_of_an_exempt_user_or_address_is_counted_and_does_nothing_else() {
    let exempt = [
        user("app"),
        range("192.0.2.0/24"),
        Exemption::new(
            Some("app".to_owned()),
            Some("192.0.2.10/32".parse().unwrap()),
        ),
    ];
    for exemption in exempt {
        let mut harness = session(Options {
            exemptions: vec![exemption.clone()],
            ..Options::default()
        });
        harness.client(&query(&format!("SELECT '{EMAIL}'")));
        harness.server(&row());
        harness.server(&join(&[&complete(), &ready(b'I')]));
        // The session is not flagged: the next statement is not reported.
        harness.client(&query("SELECT 2"));
        let statements = harness.statements();
        assert_eq!(statements, 2);
        assert!(harness.events().is_empty(), "{exemption:?}");
        assert_eq!(
            counted(&mut harness),
            [(true, ActionSet::EMPTY, ActionSet::EMPTY); 2],
            "{exemption:?}"
        );
    }

    let not_exempt = [
        user("backup"),
        range("198.51.100.0/24"),
        Exemption::new(
            Some("app".to_owned()),
            Some("198.51.100.0/24".parse().unwrap()),
        ),
        Exemption::new(
            Some("backup".to_owned()),
            Some("192.0.2.0/24".parse().unwrap()),
        ),
    ];
    for exemption in not_exempt {
        let mut harness = session(Options {
            exemptions: vec![exemption.clone()],
            ..Options::default()
        });
        harness.server(&row());
        assert_eq!(harness.events().len(), 1, "{exemption:?}");
        assert_eq!(
            counted(&mut harness),
            [(false, ALERT, ALERT)],
            "{exemption:?}"
        );
    }
}

#[test]
fn a_user_exemption_cannot_be_claimed_before_the_database_accepts_the_login() {
    let options = || Options {
        exemptions: vec![user("backup")],
        ..Options::default()
    };
    // The client says it is the exempt user. Nothing has confirmed that
    // when its startup message is searched.
    let mut harness = Harness::with_policy(policy(options()));
    harness.client(&super::scan_tests::startup(&[
        (b"user", b"backup"),
        (b"application_name", EMAIL.as_bytes()),
    ]));
    assert_eq!(harness.events().len(), 1);
    assert_eq!(harness.events()[0].kind, EventKind::TokenHit);
    assert_eq!(counted(&mut harness), [(false, ALERT, ALERT)]);

    // An exemption for an address needs no login.
    let mut harness = Harness::with_policy(policy(Options {
        exemptions: vec![range("192.0.2.0/24")],
        ..Options::default()
    }));
    harness.client(&super::scan_tests::startup(&[
        (b"user", b"app"),
        (b"application_name", EMAIL.as_bytes()),
    ]));
    assert!(harness.events().is_empty());
    assert_eq!(
        counted(&mut harness),
        [(true, ActionSet::EMPTY, ActionSet::EMPTY)]
    );

    // Once the database has accepted the user, the exemption holds.
    let mut harness = session_of("backup", options());
    harness.server(&row());
    assert!(harness.events().is_empty());
    assert_eq!(
        counted(&mut harness),
        [(true, ActionSet::EMPTY, ActionSet::EMPTY)]
    );
}

#[test]
fn nothing_but_the_login_user_and_the_address_exempts_a_session() {
    let options = || Options {
        exemptions: vec![user("backup")],
        ..Options::default()
    };
    // Every other field a client sets names the exempt user.
    let mut harness = Harness::logged_in(
        policy(options()),
        &[
            (b"user", b"app"),
            (b"database", b"backup"),
            (b"application_name", b"backup"),
            (
                b"options",
                b"-c role=backup -c session_authorization=backup",
            ),
            (b"role", b"backup"),
        ],
    );
    for sql in ["SET ROLE backup", "SET SESSION AUTHORIZATION backup"] {
        harness.client(&query(sql));
        harness.server(&frame(b'S', b"session_authorization\0backup\0"));
        harness.server(&join(&[&complete(), &ready(b'I')]));
    }
    harness.server(&row());
    assert_eq!(counted(&mut harness), [(false, ALERT, ALERT)]);

    // The exempt user stays exempt whatever role it takes.
    let mut harness = session_of("backup", options());
    harness.client(&query("SET ROLE app"));
    harness.server(&join(&[&complete(), &ready(b'I'), &row()]));
    assert_eq!(
        counted(&mut harness),
        [(true, ActionSet::EMPTY, ActionSet::EMPTY)]
    );
}

// ---------------------------------------------------------------------------
// Escalation
// ---------------------------------------------------------------------------

#[test]
fn the_response_escalates_after_the_configured_hits_and_a_client_cannot_start_the_count_again() {
    let options = |generation| Options {
        escalate: Some(Escalation::new(3, kill())),
        generation,
        ..Options::default()
    };
    let mut harness = session(options(1));
    harness.client(&query("SELECT 1"));
    harness.server(&join(&[&row(), &row()]));
    assert_eq!(counted(&mut harness), [(false, ALERT, ALERT); 2]);
    harness.server(&join(&[&complete(), &ready(b'I')]));

    // Everything a client can do between two hits: end the statement and
    // the transaction, reset the session, make the tracker lose its place
    // and find it again. The policy is loaded again as well.
    for sql in ["COMMIT", "DISCARD ALL", "RESET ALL", "DEALLOCATE ALL"] {
        harness.client(&query(sql));
        harness.server(&join(&[&complete(), &ready(b'I')]));
    }
    for _ in 0..=MAX_PENDING {
        harness.client(&parse("", "SELECT 1"));
    }
    harness.client(&sync());
    harness.server(&join(&[&error("too much"), &ready(b'I')]));
    harness.policy = policy(options(2));
    assert!(counted(&mut harness).is_empty());

    harness.client(&query("SELECT 1"));
    harness.server(&join(&[&row(), &row()]));
    // Only `alert` is carried out so far, whatever was decided.
    assert_eq!(counted(&mut harness), [(false, kill(), ALERT); 2]);
    for body in harness.events() {
        assert_eq!(body.action_taken, ALERT);
    }

    // Each token has a count of its own.
    harness.server(&data_row(CANARY.as_bytes()));
    assert_eq!(counted(&mut harness), [(false, ALERT, ALERT)]);
}

#[test]
fn a_token_the_table_of_counts_has_no_room_for_gets_its_escalated_response() {
    let extra = 40;
    let ids: Vec<String> = (0..MAX_COUNTED_TOKENS + extra)
        .map(|n| format!("token-{n:05}"))
        .collect();
    let values: Vec<String> = (0..ids.len()).map(|n| format!("VALUE-{n:05}-Q7")).collect();
    let specs: Vec<TokenSpec> = ids
        .iter()
        .zip(&values)
        .map(|(id, value)| TokenSpec::new(id.as_str(), [value.as_str()]))
        .collect();
    let policy = PolicySnapshot::builder()
        .inspection(Inspection::new(OnError::FailClosed, 1024 * 1024))
        .tokens(ids.iter().map(|id| {
            let mut token = TokenPolicy::new(TokenId::new(id).unwrap());
            token.escalate = Some(Escalation::new(2, kill()));
            token
        }))
        .matcher(Matcher::build(&specs).unwrap())
        .build()
        .unwrap();
    let mut harness = Harness::logged_in(policy, &[(b"user", b"app")]);
    harness.server(&data_row(values.join(" ").as_bytes()));
    let counted = counted(&mut harness);
    assert_eq!(counted.len(), ids.len());
    let escalated = counted.iter().filter(|hit| hit.1 == kill()).count();
    assert_eq!(escalated, extra);
}

// ---------------------------------------------------------------------------
// The flagged session
// ---------------------------------------------------------------------------

#[test]
fn after_its_first_hit_a_session_reports_each_statement_in_order() {
    let mut harness = session(Options::default());
    harness.client(&query("SELECT before"));
    harness.server(&join(&[&complete(), &ready(b'I')]));
    assert!(events(&mut harness).is_empty());

    harness.client(&query("SELECT first"));
    harness.server(&join(&[&row(), &row(), &complete(), &ready(b'I')]));
    harness.client(&query("SELECT second"));
    harness.server(&join(&[&complete(), &ready(b'I')]));
    // `Parse`, `Bind` and `Sync` are not statements; `Execute` is.
    harness.client(&batch("SELECT third"));
    harness.client(&function_call());
    let sql = format!("SELECT '{EMAIL}'");
    harness.client(&query(&sql));

    let seen: Vec<_> = events(&mut harness)
        .into_iter()
        .map(|body| {
            assert_eq!(body.db_user.as_deref(), Some("app"));
            let message = body.message_type.as_deref().map(str::to_owned);
            if body.kind == EventKind::SessionActivity {
                assert_eq!(body.direction, Some(FromClient));
                assert_eq!(body.token_id, None);
                assert_eq!(body.action_taken, ActionSet::EMPTY);
            }
            (
                body.kind,
                body.session_flagged,
                message.unwrap(),
                body.query,
            )
        })
        .collect();
    let activity = EventKind::SessionActivity;
    let hit = EventKind::TokenHit;
    let expected = [
        (hit, false, "DataRow", known("SELECT first")),
        (hit, true, "DataRow", known("SELECT first")),
        (activity, true, "Query", known("SELECT second")),
        (activity, true, "Execute", known("SELECT third")),
        (activity, true, "FunctionCall", unknown()),
        // The statement is reported before the hit in it.
        (activity, true, "Query", known(&sql)),
        (hit, true, "Query", known(&sql)),
    ];
    assert_eq!(seen.len(), expected.len());
    for (seen, expected) in seen.iter().zip(expected) {
        let (kind, flagged, message, query) = expected;
        assert_eq!(*seen, (kind, flagged, message.to_owned(), query));
    }
    assert_eq!(FromServer, crate::session::Direction::FromServer);
}
