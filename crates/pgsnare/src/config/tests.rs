// SPDX-License-Identifier: Apache-2.0

//! Tests of the configuration as a whole.

use std::time::Duration;

use pgsnare_core::policy::{Action, ActionSet, OnError, QueryRedaction, TokenId};
use proptest::prelude::*;

use super::*;

/// The smallest configuration there is.
const MINIMAL: &str = "\
listeners:
  - name: main
    listen: 0.0.0.0:5432
    upstream: db.example.com:5432
    client_tls: { mode: disable }
    upstream_tls: { mode: verify-full }
events:
  sinks: [{ type: stdout }]
";

/// The complete example that ships with the repository.
const EXAMPLE: &str = include_str!("../../../../examples/config/pgsnare.yaml");

/// The shipped example, read. A build without SQL rules must reject it for
/// that one reason, and then reads it without its `rules` section.
fn example() -> Config {
    if cfg!(feature = "rules") {
        return Config::from_yaml(EXAMPLE).unwrap();
    }
    let found = problems(EXAMPLE);
    assert_eq!(found.len(), 1, "{found:?}");
    assert!(
        found[0].starts_with("rules: this build of pgsnare has no SQL rules"),
        "{found:?}"
    );

    let mut without_rules = String::new();
    let mut in_rules = false;
    for line in EXAMPLE.lines() {
        if line.starts_with("rules:") {
            in_rules = true;
            continue;
        }
        if in_rules && (line.starts_with(' ') || line.is_empty()) {
            continue;
        }
        in_rules = false;
        without_rules.push_str(line);
        without_rules.push('\n');
    }
    Config::from_yaml(&without_rules).unwrap()
}

fn problems(text: &str) -> Vec<String> {
    match Config::from_yaml(text) {
        Ok(_) => Vec::new(),
        Err(error) => error.problems().iter().map(ToString::to_string).collect(),
    }
}

/// `MINIMAL` with more text appended at the top level.
fn minimal_with(extra: &str) -> String {
    format!("{MINIMAL}{extra}")
}

#[test]
fn the_minimal_configuration_gets_the_safe_defaults() {
    let config = Config::from_yaml(MINIMAL).unwrap();
    assert_eq!(config.listeners.len(), 1);

    assert_eq!(config.inspection.on_error, OnError::FailClosed);
    assert_eq!(config.inspection.max_buffered_frame, 1024 * 1024);
    assert!(config.token_files.is_empty());
    assert!(config.tokens.is_empty());
    assert!(config.exemptions.is_empty());
    assert_eq!(config.rules, None);
    assert_eq!(config.actions, Actions::default());
    assert_eq!(config.events.query_redaction, QueryRedaction::Fingerprint);
    assert_eq!(config.events.dedup_window, Duration::from_secs(60));
    assert!(config.admin.listen.is_loopback());
    assert!(config.metrics.listen.is_loopback());
    assert_eq!(config.shutdown.grace_period, Duration::from_secs(25));
}

#[test]
fn the_shipped_example_is_valid_and_sets_everything() {
    let config = example();

    assert_eq!(config.listeners.len(), 2);
    let main = &config.listeners[0];
    assert_eq!(main.name.as_str(), "main");
    assert_eq!(main.client_tls.mode, ClientTlsMode::Require);
    assert_eq!(main.upstream_tls.mode, UpstreamTlsMode::VerifyFull);
    assert_eq!(
        main.upstream_tls.server_name.as_ref().unwrap().as_str(),
        "db.example.com"
    );
    assert!(config.listeners[1].upstream.is_unix());

    assert_eq!(
        config.token_files,
        [std::path::PathBuf::from("tokens/*.yaml")]
    );
    assert_eq!(config.tokens.len(), 1);
    assert_eq!(config.tokens[0].id.as_str(), "users-admin-backup");
    assert_eq!(
        config.tokens[0].actions,
        ActionSet::of(&[Action::Alert, Action::Kill])
    );
    assert_eq!(config.exemptions.len(), 2);

    if cfg!(feature = "rules") {
        let rules = config.rules.as_ref().unwrap();
        assert!(rules.catalog_enumeration.is_some());
        assert!(rules.unbounded_read.is_some());
        assert!(rules.row_threshold.is_some());
        assert!(rules.functions.is_some());
    } else {
        assert_eq!(config.rules, None);
    }

    assert_eq!(config.actions.tarpit.max_bytes_per_second, Some(1024));
    assert_eq!(config.events.labels.len(), 1);
    assert_eq!(config.events.labels_from_env.len(), 2);
    let kinds: Vec<&str> = config.events.sinks.iter().map(Sink::kind).collect();
    assert_eq!(kinds, ["webhook", "stdout", "file", "syslog"]);
}

#[test]
fn the_shipped_example_spells_out_the_defaults() {
    // Wherever the example says "default", the value it shows must be the
    // default. Removing the optional sections must change nothing.
    let example = example();
    let minimal = Config::from_yaml(MINIMAL).unwrap();
    assert_eq!(example.inspection, minimal.inspection);
    assert_eq!(example.admin, minimal.admin);
    assert_eq!(example.metrics, minimal.metrics);
    assert_eq!(example.shutdown, minimal.shutdown);
    assert_eq!(example.actions.kill, minimal.actions.kill);
    assert_eq!(example.actions.fake_data, minimal.actions.fake_data);
    assert_eq!(example.actions.tarpit.delay, minimal.actions.tarpit.delay);
    assert_eq!(
        example.actions.tarpit.max_duration,
        minimal.actions.tarpit.max_duration
    );
    assert_eq!(
        example.actions.tarpit.max_sessions,
        minimal.actions.tarpit.max_sessions
    );
    assert_eq!(
        example.events.query_redaction,
        minimal.events.query_redaction
    );
    assert_eq!(example.events.dedup_window, minimal.events.dedup_window);
    assert_eq!(example.events.queue_size, minimal.events.queue_size);
    assert_eq!(
        example.listeners[0].max_connections,
        minimal.listeners[0].max_connections
    );
    assert_eq!(
        example.listeners[0].login_timeout,
        minimal.listeners[0].login_timeout
    );
    if let Some(rules) = &example.rules {
        assert_eq!(rules.max_parse_bytes, DEFAULT_MAX_PARSE_BYTES);
        assert_eq!(rules.on_parse_failure, ParseFailurePolicy::default());
    }
}

#[test]
fn the_required_sections_are_required() {
    let error = problems("events:\n  sinks: [{ type: stdout }]\n");
    assert_eq!(error.len(), 1);
    assert!(error[0].ends_with("missing field `listeners`"), "{error:?}");

    let without_events: String = MINIMAL
        .lines()
        .take(6)
        .map(|line| format!("{line}\n"))
        .collect();
    let error = problems(&without_events);
    assert_eq!(error.len(), 1);
    assert!(error[0].ends_with("missing field `events`"), "{error:?}");

    assert_eq!(
        problems("listeners: []\nevents:\n  sinks: [{ type: stdout }]\n"),
        ["listeners: at least one listener is required"]
    );
}

#[test]
fn an_unknown_field_is_an_error_in_every_section() {
    // One unknown field in each mapping of the schema.
    let cases = [
        minimal_with("listener: []\n"),
        MINIMAL.replace(
            "    listen: 0.0.0.0:5432\n",
            "    listen: 0.0.0.0:5432\n    lissten: x\n",
        ),
        MINIMAL.replace("{ mode: disable }", "{ mode: disable, verify: false }"),
        MINIMAL.replace(
            "{ mode: verify-full }",
            "{ mode: verify-full, insecure_skip_verify: true }",
        ),
        MINIMAL.replace("{ type: stdout }", "{ type: stdout, color: true }"),
        MINIMAL.replace("  sinks:", "  format: json\n  sinks:"),
        minimal_with("inspection: { on_eror: fail_open }\n"),
        minimal_with("tokens:\n  - { id: t, values: [\"0123456789ab\"], action: [kill] }\n"),
        minimal_with(
            "tokens:\n  - { id: t, values: [\"0123456789ab\"], scope: { schema: public } }\n",
        ),
        minimal_with(
            "tokens:\n  - { id: t, values: [\"0123456789ab\"], escalate: { after_hits: 2, to: [kill], reset: 1h } }\n",
        ),
        minimal_with("exemptions:\n  - { db_user: backup, reason: nightly }\n"),
        minimal_with("rules: { on_parse_failure: alert, strict: true }\n"),
        minimal_with("rules: { row_threshold: { tables: [t], max_rows: 5, window: 1m } }\n"),
        minimal_with("actions: { kill: { sqlstate: \"57P01\", severity: FATAL } }\n"),
        minimal_with("actions: { tarpit: { delay: 2s, jitter: true } }\n"),
        minimal_with("actions: { fake_data: { rows: 5, seed: 1 } }\n"),
        minimal_with("actions: { drop: {} }\n"),
        minimal_with("admin: { listen: 127.0.0.1:9641, token: x }\n"),
        minimal_with("metrics: { listen: 127.0.0.1:9642, path: /metrics }\n"),
        minimal_with("shutdown: { grace_period: 5s, force: true }\n"),
        minimal_with("logging: { level: debug }\n"),
    ];
    for document in cases {
        assert_ne!(document, MINIMAL, "a case did not change the document");
        let found = problems(&document);
        assert_eq!(found.len(), 1, "{document}\n{found:?}");
        assert!(found[0].contains("unknown field"), "{document}\n{found:?}");
    }
}

#[test]
fn every_problem_is_reported_in_one_pass() {
    let document = "\
listeners:
  - name: main
    listen: 0.0.0.0:5432
    upstream: unix:/run/postgresql/.s.PGSQL.5432
    client_tls: { mode: require }
    upstream_tls: { mode: verify-full }
    max_connections: 0
  - name: main
    listen: 127.0.0.1:9641
    upstream: db.example.com:5432
    client_tls: { mode: disable }
    upstream_tls: { mode: disable }
inspection: { max_buffered_frame: 1B }
token_files: [\"\"]
tokens:
  - { id: a, values: [\"too-short\"] }
  - { id: a, values: [\"long-enough-value\"], actions: [] }
exemptions:
  - {}
actions:
  tarpit: { max_sessions: 0 }
events:
  queue_size: 0
  sinks: []
metrics: { listen: 127.0.0.1:9641 }
shutdown: { grace_period: 2h }
";
    assert_eq!(
        problems(document),
        [
            "listeners[0].max_connections: must be between 1 and 1000000",
            "listeners[0].client_tls: cert and key are both required unless mode is disable",
            "listeners[0].upstream_tls: PostgreSQL does not use TLS over a Unix socket; set mode to disable",
            "listeners[1].name: this name is already used (see listeners[0].name)",
            "metrics.listen: this address is already used (see admin.listen)",
            "listeners[1].listen: this address is already used (see admin.listen)",
            "listeners[1].listen: this address is already used (see metrics.listen)",
            "inspection.max_buffered_frame: must be between 1KiB and 1GiB",
            "token_files[0]: the path must not be empty",
            "tokens[0].values[0]: a value must be at least 12 bytes long",
            "tokens[1].actions: at least one action is required",
            "tokens[1].id: this id is already used (see tokens[0].id)",
            "exemptions[0]: an exemption needs db_user, client_cidr or both",
            "actions.tarpit: max_sessions must be at least 1",
            "events.queue_size: must be between 1 and 1000000",
            "events.sinks: at least one sink is required",
            "shutdown.grace_period: must be at most 1h",
        ]
    );
}

#[test]
fn rules_need_a_build_that_has_them() {
    let document = minimal_with("rules: { on_parse_failure: block }\n");
    let found = problems(&document);
    if cfg!(feature = "rules") {
        assert!(found.is_empty(), "{found:?}");
    } else {
        assert_eq!(found.len(), 1);
        assert!(
            found[0].starts_with("rules: this build of pgsnare has no SQL rules"),
            "{found:?}"
        );
    }
}

#[test]
fn a_configuration_becomes_a_policy_snapshot() {
    let config = Config::from_yaml(&minimal_with(
        "\
inspection: { on_error: fail_open, max_buffered_frame: 64KiB }
tokens:
  - id: zebra
    values: [\"zebra-value-0001\"]
  - id: users-admin-backup
    values: [\"svc.backup.8f3k2q@mail.example\"]
    scope: { database: app, table: public.users }
    actions: [alert, kill]
    escalate: { after_hits: 3, to: [kill] }
exemptions:
  - { db_user: backup, client_cidr: 192.0.2.5/32 }
actions:
  fake_data: { rows: 7 }
",
    ))
    .unwrap();

    let snapshot = config.policy(42).unwrap();
    assert_eq!(snapshot.generation(), 42);
    assert_eq!(snapshot.inspection().on_error, OnError::FailOpen);
    assert_eq!(snapshot.inspection().max_buffered_frame, 65_536);
    assert_eq!(snapshot.query_redaction(), QueryRedaction::Fingerprint);
    assert_eq!(snapshot.actions().fake_data.rows, 7);

    let ids: Vec<&str> = snapshot
        .tokens()
        .iter()
        .map(|token| token.id.as_str())
        .collect();
    assert_eq!(ids, ["users-admin-backup", "zebra"]);
    let token = snapshot
        .token(&TokenId::new("users-admin-backup").unwrap())
        .unwrap();
    assert_eq!(token.scope.table.as_deref(), Some("public.users"));
    assert_eq!(
        token.actions_for_hit(1),
        ActionSet::of(&[Action::Alert, Action::Kill])
    );
    assert_eq!(token.actions_for_hit(3), ActionSet::of(&[Action::Kill]));

    assert!(snapshot.is_exempt(Some("backup"), "192.0.2.5".parse().unwrap()));
    assert!(!snapshot.is_exempt(Some("backup"), "192.0.2.6".parse().unwrap()));
    assert!(!snapshot.is_exempt(None, "192.0.2.5".parse().unwrap()));

    // The snapshot holds no token value.
    let shown = format!("{snapshot:?}");
    assert!(!shown.contains("svc.backup"), "{shown}");
    assert!(!shown.contains("zebra-value"), "{shown}");

    // The shipped example converts too.
    example().policy(1).unwrap();
}

#[test]
fn debug_output_shows_no_token_value_and_no_webhook_url() {
    let config = example();
    let shown = format!("{config:?}");
    assert!(!shown.contains("svc.backup"), "{shown}");
    assert!(!shown.contains("mail.example"), "{shown}");
    assert!(!shown.contains("alerts.example.com"), "{shown}");
    assert!(shown.contains("TokenValue(<redacted>)"));
}

#[test]
fn every_path_of_a_configuration_is_visited() {
    let mut config = example();
    let mut seen = Vec::new();
    config.for_each_path_mut(&mut |path| seen.push(path.display().to_string()));
    assert_eq!(
        seen,
        [
            "/etc/pgsnare/server.crt",
            "/etc/pgsnare/server.key",
            "/etc/pgsnare/root.crt",
            "tokens/*.yaml",
            "/var/log/pgsnare/events.jsonl",
        ]
    );
}

/// The marker stands for a honeytoken value. No error may ever show it.
const MARKER: &str = "Zq7honeytokenValue9xK";

fn assert_no_leak(document: &str) {
    if let Err(error) = Config::from_yaml(document) {
        let text = error.to_string();
        assert!(!text.contains(MARKER), "{document:?} leaked into {text:?}");
        let debug = format!("{error:?}");
        assert!(
            !debug.contains(MARKER),
            "{document:?} leaked into {debug:?}"
        );
    }
    if let Err(error) = TokenFile::from_yaml(document) {
        let text = error.to_string();
        assert!(!text.contains(MARKER), "{document:?} leaked into {text:?}");
    }
}

#[test]
fn replacing_any_word_of_the_example_with_a_secret_does_not_leak_it() {
    // Put the marker in place of every word of the example, one at a time:
    // every key, every value, every piece of punctuation that is a word.
    let mut tried = 0;
    let mut start = None;
    let mut spans = Vec::new();
    for (index, character) in EXAMPLE.char_indices() {
        let in_word = character.is_ascii_alphanumeric() || "._-/@*".contains(character);
        match (in_word, start) {
            (true, None) => start = Some(index),
            (false, Some(from)) => {
                spans.push((from, index));
                start = None;
            }
            _ => {}
        }
    }
    for (from, to) in spans {
        // Skip the comments: nothing reads them.
        let line_start = EXAMPLE[..from].rfind('\n').map_or(0, |at| at + 1);
        if EXAMPLE[line_start..from].contains('#') {
            continue;
        }
        let document = format!("{}{MARKER}{}", &EXAMPLE[..from], &EXAMPLE[to..]);
        assert_no_leak(&document);
        tried += 1;
    }
    assert!(tried > 150, "only {tried} positions were tried");
}

proptest! {
    #[test]
    fn inserting_a_secret_anywhere_does_not_leak_it(
        position in 0..EXAMPLE.len(),
        quote in prop_oneof![Just(""), Just("\""), Just("'")],
        prefix in prop_oneof![Just(""), Just(" "), Just("\n"), Just(": "), Just("- "), Just("[ "), Just("{ ")],
    ) {
        let mut position = position;
        while !EXAMPLE.is_char_boundary(position) {
            position -= 1;
        }
        let document = format!(
            "{}{prefix}{quote}{MARKER}{quote}{}",
            &EXAMPLE[..position],
            &EXAMPLE[position..]
        );
        assert_no_leak(&document);
    }

    #[test]
    fn cutting_the_example_short_does_not_leak_a_token(cut in 0..EXAMPLE.len()) {
        let mut cut = cut;
        while !EXAMPLE.is_char_boundary(cut) {
            cut -= 1;
        }
        let document = EXAMPLE[..cut].replace("svc.backup.8f3k2q@mail.example", MARKER);
        assert_no_leak(&document);
    }

    #[test]
    fn arbitrary_text_never_panics_and_never_leaks(
        text in "(\\PC|\n|  |: |- |\\[|\\]|\\{|\\}|\"|#|&|\\*|!|\\||>){0,80}",
        position in 0usize..80,
    ) {
        let mut position = position.min(text.len());
        while !text.is_char_boundary(position) {
            position -= 1;
        }
        let document = format!("{}{MARKER}{}", &text[..position], &text[position..]);
        assert_no_leak(&document);
    }

    #[test]
    fn mangled_examples_never_panic(
        cut_from in 0..EXAMPLE.len(),
        cut_len in 0usize..200,
        insert in "[\\x00-\\x7f]{0,12}",
    ) {
        let mut from = cut_from;
        while !EXAMPLE.is_char_boundary(from) {
            from -= 1;
        }
        let mut to = (from + cut_len).min(EXAMPLE.len());
        while !EXAMPLE.is_char_boundary(to) {
            to -= 1;
        }
        let document = format!("{}{insert}{}", &EXAMPLE[..from], &EXAMPLE[to..]);
        let _ = Config::from_yaml(&document);
    }
}
