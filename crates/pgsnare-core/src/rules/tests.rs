// SPDX-License-Identifier: Apache-2.0

//! Tests that run the parser. Each one starts a parser thread, because the
//! parser may run nowhere else.

use crate::policy::{Action, ActionSet};

use super::*;

fn try_read(text: &[u8], limits: Limits) -> Result<Analysis, ParseFailure> {
    on_parser_thread(|thread| analyse(text, &limits, thread)).unwrap()
}

fn read(sql: &str) -> Analysis {
    try_read(sql.as_bytes(), Limits::default()).unwrap()
}

fn functions(sql: &str) -> Vec<String> {
    let mut found: Vec<String> = read(sql)
        .functions()
        .iter()
        .map(|function| match function.schema() {
            Some(schema) => format!("{schema}.{}", function.name()),
            None => function.name().to_owned(),
        })
        .collect();
    found.sort();
    found
}

fn usage(sql: &str, relation: &str) -> RelationUse {
    let analysis = read(sql);
    let found: Vec<_> = analysis
        .relations()
        .iter()
        .filter(|known| known.name() == relation)
        .collect();
    assert_eq!(found.len(), 1, "{sql}: {relation} is named once");
    found[0].usage()
}

/// A statement of exactly `bytes` bytes.
fn padded(bytes: usize) -> String {
    let frame = "SELECT ''".len();
    format!("SELECT '{}'", "x".repeat(bytes - frame))
}

#[test]
fn a_statement_at_the_size_cap_is_read_and_one_byte_more_is_not() {
    let limits = Limits::default();
    let at = padded(limits.max_bytes);
    assert_eq!(at.len(), limits.max_bytes);
    assert_eq!(
        try_read(at.as_bytes(), limits).unwrap().statement_count(),
        1
    );
    let over = padded(limits.max_bytes + 1);
    assert_eq!(
        try_read(over.as_bytes(), limits),
        Err(ParseFailure::TooLarge)
    );
}

#[test]
fn every_reason_for_a_failure_is_reported() {
    let limits = Limits::default();
    assert_eq!(
        try_read(b"SELECT '\xff'", limits),
        Err(ParseFailure::InvalidUtf8)
    );
    assert_eq!(
        try_read(b"SELECT 1\0; DROP TABLE t", limits),
        Err(ParseFailure::EmbeddedNul)
    );
    assert_eq!(try_read(b"SELEC 1", limits), Err(ParseFailure::Rejected));
    assert_eq!(try_read(b"SELECT (", limits), Err(ParseFailure::Rejected));
    assert_eq!(
        try_read(b"SELECT 'open", limits),
        Err(ParseFailure::Rejected)
    );
    assert_eq!(
        try_read(b"SELECT 1", Limits::with_max_bytes(7)),
        Err(ParseFailure::TooLarge)
    );
    let deep = format!("SELECT {}1{}", "(".repeat(300), ")".repeat(300));
    assert_eq!(
        try_read(deep.as_bytes(), limits),
        Err(ParseFailure::TooDeep)
    );
}

#[test]
fn a_message_that_quotes_the_statement_does_not_change_the_reason() {
    // The parser's message would read: syntax error at or near "stack ...".
    let limits = Limits::default();
    for text in [
        "SELECT 1 \"stack depth limit exceeded\" \"memory exhausted\" 2",
        "stack depth limit exceeded",
        "memory exhausted",
    ] {
        assert_eq!(
            try_read(text.as_bytes(), limits),
            Err(ParseFailure::Rejected),
            "{text}"
        );
    }
}

#[test]
fn nesting_ten_thousand_deep_never_reaches_the_parser() {
    let limits = Limits::with_max_bytes(1 << 20);
    let n = 10_000;
    for text in [
        format!("SELECT {}1{}", "(".repeat(n), ")".repeat(n)),
        format!("SELECT {}true", "NOT ".repeat(n)),
        format!("SELECT {}1", "- ".repeat(n)),
        format!("SELECT {}1{}", "ARRAY[".repeat(n), "]".repeat(n)),
    ] {
        assert_eq!(
            try_read(text.as_bytes(), limits),
            Err(ParseFailure::TooDeep)
        );
    }
}

#[test]
fn nesting_the_first_check_does_not_see_is_stopped_by_the_parser() {
    // With the first check out of the way, and for the forms it does not
    // look for, the parser or the decoder of its result refuses, and the
    // thread survives.
    let limits = Limits::with_max_bytes(1 << 20).with_max_depth(u32::MAX);
    let n = 10_000;
    for text in [
        format!("SELECT {}1{}", "(".repeat(n), ")".repeat(n)),
        format!("SELECT {}true", "NOT ".repeat(n)),
        format!("SELECT {}1", "- ".repeat(n)),
        format!("SELECT {}1{}", "ARRAY[".repeat(n), "]".repeat(n)),
        format!("SELECT 1{}", "+1".repeat(n)),
        format!("SELECT 1{}", " UNION SELECT 1".repeat(n)),
        format!(
            "SELECT 1 {}{}",
            "FROM (SELECT 1 ".repeat(n),
            ") x".repeat(n)
        ),
        format!("SELECT 1{}", "::int".repeat(n)),
        format!(
            "SELECT {}1{}",
            "CASE WHEN true THEN ".repeat(n),
            " END".repeat(n)
        ),
        format!("SELECT 1{}", "+1".repeat(200)),
    ] {
        assert_eq!(
            try_read(text.as_bytes(), limits),
            Err(ParseFailure::TooDeep),
            "{}",
            &text[..40]
        );
    }
    let fine = format!("SELECT 1{}", "+1".repeat(40));
    assert!(try_read(fine.as_bytes(), limits).is_ok());
}

#[test]
fn a_list_that_is_full_makes_the_analysis_incomplete() {
    let tables = |n: usize| {
        let names: Vec<String> = (0..n).map(|i| format!("t{i}")).collect();
        format!("SELECT 1 FROM {}", names.join(", "))
    };
    let at = read(&tables(MAX_RELATIONS));
    assert!(at.is_complete());
    assert_eq!(at.relations().len(), MAX_RELATIONS);
    let over = read(&tables(MAX_RELATIONS + 1));
    assert!(!over.is_complete());
    assert_eq!(over.relations().len(), MAX_RELATIONS);

    let calls = |n: usize| {
        let names: Vec<String> = (0..n).map(|i| format!("f{i}()")).collect();
        format!("SELECT {}", names.join(", "))
    };
    assert!(read(&calls(MAX_FUNCTIONS)).is_complete());
    let over = read(&calls(MAX_FUNCTIONS + 1));
    assert!(!over.is_complete());
    assert_eq!(over.functions().len(), MAX_FUNCTIONS);

    // The same name many times is one entry.
    let repeated = read(&format!("SELECT {}1", "f(), ".repeat(1000)));
    assert!(repeated.is_complete());
    assert_eq!(repeated.functions().len(), 1);
}

#[test]
fn a_function_is_named_as_postgresql_reads_the_name() {
    for sql in [
        "SELECT pg_read_file('x')",
        "select PG_READ_FILE('x')",
        "SELECT \"pg_read_file\"('x')",
        "SELECT U&\"\\0070g_read_file\"('x')",
        "SELECT U&\"!0070g_read_file\" UESCAPE '!' ('x')",
        "SELECT pg_read_file /* a comment */ ('x')",
        "SELECT pg_read_file\n-- a comment\n('x')",
        "SELECT pg_read_file(E'\\x78')",
        "SELECT pg_read_file($$x$$)",
    ] {
        assert_eq!(functions(sql), ["pg_read_file"], "{sql}");
    }
    // In quotes and in upper case it is another function.
    assert_eq!(functions("SELECT \"PG_READ_FILE\"('x')"), ["PG_READ_FILE"]);
    assert_eq!(
        functions("SELECT Pg_Catalog.Pg_Read_File('x')"),
        ["pg_catalog.pg_read_file"]
    );
    // A name inside a string or a comment is not a call.
    assert!(functions("SELECT 'pg_read_file(1)', $$pg_sleep(1)$$ /* lo_export(1) */").is_empty());
}

#[test]
fn a_function_is_found_wherever_the_grammar_allows_one() {
    for sql in [
        "SELECT * FROM pg_sleep(1)",
        "SELECT (SELECT pg_sleep(1))",
        "WITH a AS (SELECT pg_sleep(1)) SELECT * FROM a",
        "COPY (SELECT pg_sleep(1)) TO STDOUT",
        "PREPARE p AS SELECT pg_sleep($1)",
        "EXECUTE p(pg_sleep(1))",
        "EXPLAIN ANALYZE SELECT pg_sleep(1)",
        "CREATE TABLE t AS SELECT pg_sleep(1)",
        "DECLARE c CURSOR FOR SELECT pg_sleep(1)",
        "CALL pg_sleep(1)",
        "VALUES (pg_sleep(1))",
        "INSERT INTO t VALUES (1) RETURNING pg_sleep(1)",
        "UPDATE t SET a = 1 RETURNING pg_sleep(1)",
        "DELETE FROM t RETURNING pg_sleep(1)",
        "MERGE INTO t USING u ON t.a = u.a WHEN MATCHED THEN UPDATE SET a = pg_sleep(1)",
        "ALTER TABLE t ALTER COLUMN c TYPE text USING pg_sleep(1)",
        "ALTER TABLE t ADD COLUMN d text DEFAULT pg_sleep(1)",
        "CREATE TABLE t (a text DEFAULT pg_sleep(1))",
        "CREATE TABLE t PARTITION OF u FOR VALUES FROM (pg_sleep(1)) TO (2)",
        "CREATE INDEX ON t (pg_sleep(1))",
        "CREATE POLICY p ON t USING (pg_sleep(1) IS NULL)",
        "CREATE RULE r AS ON SELECT TO t DO INSTEAD SELECT pg_sleep(1)",
        "CREATE DOMAIN d AS text CHECK (pg_sleep(1) IS NULL)",
        "SELECT a FROM t ORDER BY pg_sleep(1)",
        "SELECT a FROM t GROUP BY a HAVING pg_sleep(1) IS NULL",
        "SELECT CASE WHEN pg_sleep(1) IS NULL THEN 1 END",
        "SELECT ARRAY[pg_sleep(1)], ROW(pg_sleep(1)), pg_sleep(1)::text",
        "SELECT COALESCE(pg_sleep(1), NULL)",
        "SELECT * FROM t TABLESAMPLE system (pg_sleep(1))",
        "SELECT * FROM ROWS FROM (pg_sleep(1))",
        "SELECT * FROM t WHERE a IN (SELECT pg_sleep(1))",
        "SELECT 1 LIMIT pg_sleep(1)",
        "SELECT * FROM t JOIN u ON pg_sleep(1) IS NULL",
        "SELECT count(*) FILTER (WHERE pg_sleep(1) IS NULL) FROM t",
        "SELECT 1; SELECT 2; SELECT pg_sleep(1)",
        "CREATE TRIGGER tr BEFORE INSERT ON t FOR EACH ROW EXECUTE FUNCTION pg_sleep()",
        "GRANT EXECUTE ON FUNCTION pg_sleep(float8) TO app",
        "CREATE CAST (int AS text) WITH FUNCTION pg_sleep(int)",
    ] {
        assert!(
            functions(sql).contains(&"pg_sleep".to_owned()),
            "{sql}: {:?}",
            functions(sql)
        );
    }
}

#[test]
fn a_relation_is_named_as_postgresql_reads_the_name() {
    let analysis = read("SELECT * FROM Public.Users, \"Public\".\"Users\", cards");
    let mut found: Vec<(Option<&str>, &str)> = analysis
        .relations()
        .iter()
        .map(|relation| (relation.schema(), relation.name()))
        .collect();
    found.sort();
    assert_eq!(
        found,
        [
            (None, "cards"),
            (Some("Public"), "Users"),
            (Some("public"), "users")
        ]
    );
}

#[test]
fn how_a_relation_is_used_is_told_apart() {
    let unbounded = RelationUse::UNBOUNDED_READ;
    let read_only = RelationUse::READ;
    let written = RelationUse::WRITTEN;
    for (sql, expected) in [
        ("SELECT * FROM users", unbounded),
        ("TABLE users", unbounded),
        ("SELECT * FROM ONLY users", unbounded),
        ("SELECT * FROM users WHERE id = 1", read_only),
        ("SELECT * FROM users LIMIT 5", read_only),
        ("SELECT * FROM users FETCH FIRST 5 ROWS ONLY", read_only),
        ("SELECT * FROM users LIMIT ALL", unbounded),
        ("SELECT * FROM users LIMIT NULL", unbounded),
        ("SELECT * FROM users OFFSET 5", unbounded),
        ("SELECT * FROM users ORDER BY id", unbounded),
        ("SELECT * FROM (SELECT * FROM users) s", unbounded),
        ("SELECT * FROM (SELECT * FROM users) s LIMIT 5", read_only),
        (
            "SELECT * FROM (SELECT * FROM users WHERE id = 1) s",
            read_only,
        ),
        ("SELECT * FROM a JOIN users u ON a.id = u.id", unbounded),
        (
            "SELECT * FROM a JOIN users u ON a.id = u.id WHERE a.id = 1",
            read_only,
        ),
        (
            "SELECT * FROM a, LATERAL (SELECT * FROM users) u",
            unbounded,
        ),
        (
            "SELECT * FROM users UNION ALL SELECT * FROM cards",
            unbounded,
        ),
        (
            "(SELECT * FROM users) UNION (SELECT * FROM cards) LIMIT 3",
            read_only,
        ),
        ("SELECT (SELECT count(*) FROM users)", unbounded),
        ("SELECT 1 WHERE EXISTS (SELECT 1 FROM users)", unbounded),
        (
            "WITH u AS (SELECT * FROM users) SELECT * FROM u LIMIT 1",
            unbounded,
        ),
        ("COPY users TO STDOUT", unbounded),
        ("COPY users (id) TO STDOUT", unbounded),
        ("COPY (SELECT * FROM users) TO STDOUT", unbounded),
        (
            "COPY (SELECT * FROM users WHERE id = 1) TO STDOUT",
            read_only,
        ),
        ("COPY users FROM STDIN", written),
        ("INSERT INTO users VALUES (1)", written),
        ("INSERT INTO users VALUES (1) RETURNING *", written),
        ("INSERT INTO t SELECT * FROM users", unbounded),
        ("CREATE TABLE t AS SELECT * FROM users", unbounded),
        ("SELECT * INTO t FROM users", unbounded),
        ("UPDATE users SET a = 1", written),
        (
            "UPDATE users SET a = a RETURNING *",
            written.union(unbounded),
        ),
        (
            "UPDATE users SET a = a WHERE id = 1 RETURNING *",
            written.union(read_only),
        ),
        ("DELETE FROM users RETURNING *", written.union(unbounded)),
        ("DELETE FROM t USING users WHERE t.id = users.id", read_only),
        ("UPDATE t SET a = 1 FROM users RETURNING users.*", unbounded),
        (
            "MERGE INTO t USING users u ON t.a = u.a WHEN MATCHED THEN DO NOTHING",
            read_only,
        ),
        ("DECLARE c CURSOR FOR SELECT * FROM users", unbounded),
        ("PREPARE p AS SELECT * FROM users", unbounded),
        ("EXPLAIN SELECT * FROM users", unbounded),
        (
            "SELECT 1; SELECT * FROM users WHERE id = 1; TABLE users",
            unbounded,
        ),
        ("TRUNCATE users", RelationUse::NAMED),
        ("ALTER TABLE users ADD COLUMN c int", RelationUse::NAMED),
        ("GRANT SELECT ON users TO app", RelationUse::NAMED),
    ] {
        assert_eq!(usage(sql, "users"), expected, "{sql}");
    }
    assert_eq!(usage("SELECT * INTO t FROM users", "t"), written);
    assert_eq!(usage("INSERT INTO t SELECT * FROM users", "t"), written);
}

#[test]
fn the_flags_tell_what_else_a_statement_does() {
    let flags = |sql: &str| read(sql).flags();
    assert_eq!(flags("SELECT 1"), StatementFlags::NONE);
    assert_eq!(flags("COPY t TO STDOUT"), StatementFlags::COPY_TO);
    assert_eq!(flags("COPY t FROM STDIN"), StatementFlags::COPY_FROM);
    assert_eq!(
        flags("COPY t TO '/tmp/out'"),
        StatementFlags::COPY_TO.union(StatementFlags::COPY_FILE)
    );
    assert_eq!(
        flags("COPY t FROM PROGRAM 'cat /etc/passwd'"),
        StatementFlags::COPY_FROM.union(StatementFlags::COPY_PROGRAM)
    );
    assert_eq!(
        flags("DO $$ BEGIN PERFORM pg_sleep(1); END $$"),
        StatementFlags::OPAQUE_BODY
    );
    assert_eq!(
        flags("CREATE FUNCTION f() RETURNS int LANGUAGE sql AS 'SELECT 1'"),
        StatementFlags::OPAQUE_BODY
    );
    assert_eq!(flags("EXECUTE p(1)"), StatementFlags::RUNS_STORED);
    assert_eq!(flags("FETCH ALL FROM c"), StatementFlags::RUNS_STORED);
    assert_eq!(
        flags("EXPLAIN ANALYZE EXECUTE p(1)"),
        StatementFlags::RUNS_STORED
    );
    // The body of DO is not read.
    assert!(functions("DO $$ BEGIN PERFORM pg_sleep(1); END $$").is_empty());
}

#[test]
fn the_statements_of_a_text_are_counted() {
    let empty = read("");
    assert_eq!((empty.statement_count(), empty.kinds().len()), (0, 0));
    assert!(empty.is_complete());
    assert_eq!(
        read("  -- nothing here\n /* at all */").statement_count(),
        0
    );

    let two = read("SELECT 1; ; SELECT 2");
    assert_eq!(two.statement_count(), 2);
    assert_eq!(two.kinds(), ["SelectStmt"]);

    let mixed = read("BEGIN; COPY t TO STDOUT; EXPLAIN SELECT 1; COMMIT");
    assert_eq!(mixed.statement_count(), 4);
    assert_eq!(
        mixed.kinds(),
        ["TransactionStmt", "CopyStmt", "ExplainStmt"]
    );

    let many = read(&"SELECT 1;".repeat(5000));
    assert_eq!(many.statement_count(), 5000);
    assert!(many.is_complete());
}

#[test]
fn the_normalised_text_holds_no_constant() {
    let limits = Limits::default().normalised(true);
    let read = |sql: &str| try_read(sql.as_bytes(), limits).unwrap();
    let one = read("SELECT * FROM users WHERE name = 'secret-value' AND id IN (17, 18)");
    let text = one.normalised().unwrap();
    assert!(
        !text.contains("secret-value") && !text.contains("17"),
        "{text}"
    );
    assert!(text.contains("$1"), "{text}");
    let other = read("SELECT * FROM users WHERE name = 'another' AND id IN (1, 2)");
    assert!(one.fingerprint().is_some());
    assert_eq!(one.fingerprint(), other.fingerprint());
    assert_ne!(one.fingerprint(), read("SELECT * FROM cards").fingerprint());
    assert!(one.covers(&limits));

    // Not asked for, it is not made, and the analysis says so.
    let plain = try_read(b"SELECT 'x'", Limits::default()).unwrap();
    assert_eq!((plain.normalised(), plain.fingerprint()), (None, None));
    assert!(plain.covers(&Limits::default()));
    assert!(!plain.covers(&limits));

    // A text that would be longer than an event shows is not kept, and
    // neither is one of a statement too long to normalise.
    let wide = format!("SELECT {}", "a_column_name, ".repeat(400)) + "1";
    assert!(wide.len() > MAX_NORMALISED_BYTES && wide.len() < MAX_NORMALISE_INPUT_BYTES);
    let wide = read(&wide);
    assert_eq!(wide.normalised(), None);
    assert!(wide.fingerprint().is_some() && wide.covers(&limits));
    let long = padded(MAX_NORMALISE_INPUT_BYTES + 1);
    let long = read(&long);
    assert_eq!(long.normalised(), None);
    assert!(long.covers(&limits));
}

#[test]
fn debug_output_shows_counts_and_no_name() {
    let analysis = try_read(
        b"SELECT hidden_function(1) FROM hidden_schema.hidden_table WHERE a = 'hidden_value'",
        Limits::default().normalised(true),
    )
    .unwrap();
    let shown = format!(
        "{analysis:?} {:?} {:?}",
        analysis.relations(),
        analysis.functions()
    );
    assert!(!shown.contains("hidden"), "{shown}");
    assert!(
        shown.contains("relations: 1") && shown.contains("functions: 1"),
        "{shown}"
    );
    assert!(analysis.weight() > "hidden_function".len());
}

fn scope(listeners: Option<&[&str]>, users: Option<&[&str]>, exclude: &[&str]) -> RuleScope {
    let owned = |names: &[&str]| {
        names
            .iter()
            .map(|name| (*name).to_owned())
            .collect::<Vec<_>>()
    };
    RuleScope::new(
        listeners.map(owned).as_deref(),
        users.map(owned).as_deref(),
        &owned(exclude),
    )
}

fn app() -> Subject<'static> {
    Subject {
        listener: "main",
        user: Some("app"),
    }
}

fn fired(rules: &RuleSet, sql: &str, subject: &Subject<'_>) -> Vec<String> {
    rules
        .evaluate(&read(sql), subject)
        .into_iter()
        .map(|(id, _)| id.to_string())
        .collect()
}

fn every_rule() -> RuleSet {
    let tables = ["public.users".to_owned(), "cards".to_owned()];
    RuleSet::builder()
        .catalog_enumeration(ActionSet::ALERT, RuleScope::default())
        .unwrap()
        .unbounded_read(
            &tables,
            ActionSet::of(&[Action::Alert, Action::Kill]),
            RuleScope::default(),
        )
        .unwrap()
        .row_threshold(
            &tables,
            100,
            ActionSet::of(&[Action::Tarpit]),
            RuleScope::default(),
        )
        .unwrap()
        .functions(
            &["pg_read_file".to_owned(), "pg_catalog.pg_sleep".to_owned()],
            ActionSet::of(&[Action::Kill]),
            RuleScope::default(),
        )
        .unwrap()
        .build()
}

#[test]
fn each_rule_fires_on_what_it_is_for_and_on_nothing_else() {
    let rules = every_rule();
    let app = app();
    let none: [&str; 0] = [];
    assert_eq!(
        fired(&rules, "SELECT * FROM orders WHERE id = 1", &app),
        none
    );
    assert_eq!(
        fired(&rules, "SELECT * FROM users WHERE id = 1", &app),
        none
    );
    assert_eq!(fired(&rules, "INSERT INTO users VALUES (1)", &app), none);

    for sql in [
        "SELECT * FROM pg_catalog.pg_tables",
        "SELECT * FROM information_schema.tables WHERE table_schema = 'public'",
        "SELECT relname FROM pg_class WHERE relkind = 'r'",
        "SELECT * FROM PG_CATALOG.\"pg_authid\"",
        "COPY pg_shadow TO STDOUT",
    ] {
        assert_eq!(fired(&rules, sql, &app), [CATALOG_ENUMERATION], "{sql}");
    }
    // A table of the application that only looks like a catalogue.
    assert_eq!(
        fired(&rules, "SELECT * FROM public.pg_things WHERE id = 1", &app),
        none
    );

    for sql in [
        "SELECT * FROM users",
        "TABLE public.users",
        "SELECT * FROM Public.Users",
        "COPY cards TO STDOUT",
        "SELECT * FROM other.cards",
        "WITH c AS (SELECT * FROM cards) SELECT count(*) FROM c",
    ] {
        assert_eq!(fired(&rules, sql, &app), [UNBOUNDED_READ], "{sql}");
    }
    // The same table name in another schema than the listed one.
    assert_eq!(fired(&rules, "SELECT * FROM audit.users", &app), none);
    assert_eq!(fired(&rules, "SELECT * FROM \"Users\"", &app), none);

    for sql in [
        "SELECT pg_read_file('/etc/passwd')",
        "SELECT PG_CATALOG.PG_READ_FILE('/etc/passwd')",
        "SELECT pg_sleep(10)",
        "SELECT pg_catalog.pg_sleep(10)",
        "SELECT other.pg_read_file('x')",
    ] {
        assert_eq!(fired(&rules, sql, &app), [FUNCTIONS], "{sql}");
    }
    assert_eq!(fired(&rules, "SELECT other.pg_sleep(10)", &app), none);
    assert_eq!(fired(&rules, "SELECT \"PG_SLEEP\"(10)", &app), none);

    // Several rules at once, each named once, with its own response.
    let hits = rules.evaluate(
        &read("SELECT pg_sleep(1), pg_read_file('x') FROM users, cards, pg_class"),
        &app,
    );
    let ids: Vec<&str> = hits.iter().map(|(id, _)| id.as_str()).collect();
    assert_eq!(ids, [CATALOG_ENUMERATION, UNBOUNDED_READ, FUNCTIONS]);
    assert_eq!(hits[1].1, ActionSet::of(&[Action::Alert, Action::Kill]));
}

#[test]
fn the_row_threshold_is_armed_by_a_read_of_a_listed_table() {
    let rules = every_rule();
    let armed = |sql: &str| rules.row_threshold(&read(sql), &app());
    let threshold = armed("SELECT * FROM users WHERE id > 5").unwrap();
    assert_eq!(threshold.rule.as_str(), ROW_THRESHOLD);
    assert_eq!(threshold.max_rows, 100);
    assert_eq!(threshold.actions, ActionSet::of(&[Action::Tarpit]));
    assert!(armed("DELETE FROM cards WHERE id > 5 RETURNING *").is_some());
    assert!(armed("SELECT * FROM orders").is_none());
    assert!(armed("INSERT INTO users VALUES (1) RETURNING *").is_none());
    assert!(
        RuleSet::builder()
            .build()
            .row_threshold(&read("TABLE users"), &app())
            .is_none()
    );
}

#[test]
fn a_rule_applies_per_listener_and_per_user() {
    let on = |scope: &RuleScope, listener: &str, user: Option<&str>| {
        scope.applies(&Subject { listener, user })
    };
    let everyone = RuleScope::default();
    assert!(on(&everyone, "main", Some("app")) && on(&everyone, "other", None));

    let listeners = scope(Some(&["main", "reports"]), None, &[]);
    assert!(on(&listeners, "main", Some("app")) && on(&listeners, "reports", None));
    assert!(!on(&listeners, "admin", Some("app")));
    assert!(!on(&listeners, "Main", Some("app")));
    assert!(!on(&scope(Some(&[]), None, &[]), "main", Some("app")));

    let users = scope(None, Some(&["app", "report"]), &[]);
    assert!(on(&users, "main", Some("app")) && on(&users, "x", Some("report")));
    assert!(!on(&users, "main", Some("migrator")));
    assert!(!on(&users, "main", Some("App")));
    // A session whose user is not known is not left out.
    assert!(on(&users, "main", None));

    let excluded = scope(None, None, &["migrator"]);
    assert!(on(&excluded, "main", Some("app")) && on(&excluded, "main", None));
    assert!(!on(&excluded, "main", Some("migrator")));
    // Excluded wins over listed.
    assert!(!on(
        &scope(None, Some(&["app"]), &["app"]),
        "main",
        Some("app")
    ));

    // Through a rule set: the rule is off for the excluded user only.
    let rules = RuleSet::builder()
        .functions(
            &["pg_sleep".to_owned()],
            ActionSet::ALERT,
            scope(Some(&["main"]), None, &["migrator"]),
        )
        .unwrap()
        .build();
    let sql = "SELECT pg_sleep(1)";
    let from = |listener, user| Subject { listener, user };
    assert_eq!(fired(&rules, sql, &from("main", Some("app"))), [FUNCTIONS]);
    assert!(fired(&rules, sql, &from("main", Some("migrator"))).is_empty());
    assert!(fired(&rules, sql, &from("admin", Some("app"))).is_empty());
    assert!(rules.applies_to(&from("main", Some("app"))));
    assert!(!rules.applies_to(&from("main", Some("migrator"))));
    assert!(!rules.applies_to(&from("admin", Some("app"))));
    assert!(
        !RuleSet::builder()
            .build()
            .applies_to(&from("main", Some("app")))
    );
}

#[test]
fn a_rule_set_refuses_what_makes_no_sense() {
    let alert = ActionSet::ALERT;
    let all = RuleScope::default;
    let table = ["t".to_owned()];
    let builder = RuleSet::builder;
    assert!(
        builder()
            .catalog_enumeration(ActionSet::EMPTY, all())
            .is_err()
    );
    assert!(builder().unbounded_read(&[], alert, all()).is_err());
    assert!(
        builder()
            .unbounded_read(&table, ActionSet::EMPTY, all())
            .is_err()
    );
    assert!(
        builder()
            .unbounded_read(&["a.b.c".to_owned()], alert, all())
            .is_err()
    );
    assert!(builder().row_threshold(&table, 0, alert, all()).is_err());
    assert!(builder().row_threshold(&[], 1, alert, all()).is_err());
    assert!(
        builder()
            .functions(&["pg_sleep(1)".to_owned()], alert, all())
            .is_err()
    );
    assert!(builder().functions(&[], alert, all()).is_err());
    assert!(builder().max_parse_bytes(0).is_err());

    let rules = builder()
        .on_parse_failure(OnParseFailure::Block)
        .max_parse_bytes(1234)
        .unwrap()
        .build();
    assert_eq!(rules.on_parse_failure(), OnParseFailure::Block);
    assert_eq!(rules.limits().max_bytes, 1234);
    assert_eq!(builder().build().on_parse_failure(), OnParseFailure::Alert);
    assert_eq!(builder().build().limits(), Limits::default());
}
