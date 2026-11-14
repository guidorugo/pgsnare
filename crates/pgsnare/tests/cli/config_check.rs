// SPDX-License-Identifier: Apache-2.0

//! `pgsnare config check`: one test for each kind of problem and for each
//! warning, and the exit status.
//!
//! A configuration that the check refuses is also given to `pgsnare run`,
//! which must refuse it too: the two commands share their code so that
//! they cannot disagree, and this is where that is seen.

use std::time::{Duration, Instant};

use crate::expected::{self, Run};
use crate::fixture::{self, Fixture};

/// Runs `pgsnare config check` on `pgsnare.yaml` of the fixture.
fn check(fixture: &Fixture, more: &[&str]) -> Run {
    let config = fixture.arg("pgsnare.yaml");
    let mut line = vec!["config", "check", "--config", &config];
    line.extend_from_slice(more);
    expected::run(&line)
}

/// The check printed what the expected file says and ended with `status`.
#[track_caller]
fn expect(fixture: &Fixture, run: &Run, status: i32, name: &str) {
    assert_eq!(run.stderr, "", "standard error");
    expected::check(name, &fixture.normalise(&run.stdout));
    assert_eq!(run.status, status);
}

/// `pgsnare run` refuses the configuration of the fixture as well: it ends
/// by itself with status 1, and does not sit there serving clients.
#[track_caller]
fn run_refuses_it_too(fixture: &Fixture) {
    let mut child = expected::pgsnare(&["run", "--config", &fixture.arg("pgsnare.yaml")])
        .spawn()
        .expect("the pgsnare binary can be run");
    let started = Instant::now();
    loop {
        if child
            .try_wait()
            .expect("the command can be waited for")
            .is_some()
        {
            break;
        }
        if started.elapsed() > Duration::from_secs(20) {
            let _ = child.kill();
            let _ = child.wait();
            panic!("pgsnare run started with a configuration that config check refuses");
        }
        std::thread::sleep(Duration::from_millis(20));
    }
    let run = expected::finish(child);
    assert_eq!(run.status, 1, "{}", run.stderr);
    // The log of `pgsnare run` is one JSON object for each line.
    assert!(
        run.stderr.contains("\"message\":\"pgsnare cannot go on\"")
            && run.stderr.contains("\"reason\":\""),
        "pgsnare run did not say why it refused: {}",
        run.stderr
    );
}

// --- A configuration that is in order -----------------------------------------

#[test]
fn a_valid_configuration_passes() {
    let fixture = Fixture::new();
    fixture.certificates();
    fixture.write(
        "tokens/more.yaml",
        &fixture::token_file("from-a-token-file", "from-the-token-file-0001"),
    );
    fixture.write(
        "pgsnare.yaml",
        &fixture::valid(
            "\
token_files: [\"tokens/*.yaml\"]
tokens:
  - id: users-admin-backup
    values: [\"svc.backup.aaaaaaaaaaaa\", \"ABCD-EFGH-IJKL-MNOP\"]
",
        ),
    );
    let run = check(&fixture, &[]);
    expect(&fixture, &run, 0, "config-check-ok.txt");
}

// --- Problems -------------------------------------------------------------------

#[test]
fn an_unknown_field_is_an_error() {
    let fixture = Fixture::new();
    fixture.certificates();
    fixture.write(
        "pgsnare.yaml",
        &fixture::valid("inspection: { on_eror: fail_closed }\n"),
    );
    let run = check(&fixture, &[]);
    expect(&fixture, &run, 1, "config-check-unknown-field.txt");
    run_refuses_it_too(&fixture);

    // In a token file as well.
    fixture.write(
        "tokens.yaml",
        "tokens:\n  - id: t\n    value: \"svc.backup.aaaaaaaaaaaa\"\n",
    );
    fixture.write(
        "pgsnare.yaml",
        &fixture::valid("token_files: [tokens.yaml]\n"),
    );
    let run = check(&fixture, &[]);
    expect(
        &fixture,
        &run,
        1,
        "config-check-unknown-field-in-a-token-file.txt",
    );
    assert!(!run.stdout.contains("svc.backup"));
    run_refuses_it_too(&fixture);
}

#[test]
fn honeytokens_that_are_not_valid_are_errors() {
    let fixture = Fixture::new();
    fixture.certificates();
    fixture.write(
        "pgsnare.yaml",
        &fixture::valid(
            "\
tokens:
  - id: not-ascii
    values: [\"caf\\xE9-au-lait-backup-account\"]
  - id: too-short
    values: [\"elevenbytes\"]
  - id: twice
    values: [\"svc.backup.aaaaaaaaaaaa\", \"svc.backup.aaaaaaaaaaaa\"]
  - id: twice
    values: [\"another-value-0001\"]
  - id: contains-another
    values: [\"prefix-another-value-0001-suffix\"]
  - id: no-values
    values: []
",
        ),
    );
    let run = check(&fixture, &[]);
    expect(&fixture, &run, 1, "config-check-invalid-tokens.txt");
    // The report names places and never a value.
    for value in [
        "caf",
        "elevenbytes",
        "svc.backup",
        "another-value",
        "prefix-",
    ] {
        assert!(!run.stdout.contains(value), "{value} was printed");
    }
    run_refuses_it_too(&fixture);
}

#[test]
fn a_token_file_that_is_missing_is_an_error() {
    let fixture = Fixture::new();
    fixture.certificates();
    fixture.write(
        "pgsnare.yaml",
        &fixture::valid("token_files: [missing.yaml]\n"),
    );
    let run = check(&fixture, &[]);
    expect(&fixture, &run, 1, "config-check-missing-token-file.txt");
    run_refuses_it_too(&fixture);

    // A pattern that matches no file loads no tokens, and says so.
    fixture.write(
        "pgsnare.yaml",
        &fixture::valid("token_files: [\"tokens/*.yaml\"]\n"),
    );
    std::fs::create_dir_all(fixture.path("tokens")).unwrap();
    let run = check(&fixture, &[]);
    expect(
        &fixture,
        &run,
        1,
        "config-check-token-files-match-nothing.txt",
    );
    run_refuses_it_too(&fixture);
}

#[test]
fn certificates_and_keys_that_are_missing_are_errors() {
    // No certificate, no key and no authority were written.
    let fixture = Fixture::new();
    fixture.write("pgsnare.yaml", &fixture::valid(""));
    let run = check(&fixture, &[]);
    expect(&fixture, &run, 1, "config-check-missing-certificates.txt");
    run_refuses_it_too(&fixture);

    // With the override for open files, a file that is not there is still
    // an error: pgsnare run cannot read it either.
    let run = check(&fixture, &["--allow-insecure-file-permissions"]);
    expect(&fixture, &run, 1, "config-check-missing-certificates.txt");
}

#[test]
fn a_certificate_or_a_key_that_cannot_be_used_is_an_error() {
    let fixture = Fixture::new();
    fixture.certificates();
    fixture.write_with_mode("server.crt", "this is not a certificate\n", 0o644);
    fixture.write_with_mode("ca.crt", "", 0o644);
    fixture.write("pgsnare.yaml", &fixture::valid(""));
    let run = check(&fixture, &[]);
    expect(&fixture, &run, 1, "config-check-unusable-certificates.txt");
    run_refuses_it_too(&fixture);

    // A key that belongs to another certificate.
    let other = Fixture::new();
    other.certificates();
    fixture.certificates();
    std::fs::copy(other.path("server.key"), fixture.path("server.key")).unwrap();
    let run = check(&fixture, &[]);
    expect(
        &fixture,
        &run,
        1,
        "config-check-key-of-another-certificate.txt",
    );
    run_refuses_it_too(&fixture);
}

#[test]
fn files_that_are_open_to_other_users_are_errors() {
    let fixture = Fixture::new();
    fixture.certificates();
    // The key and a token file can be read by the group, and the
    // configuration by everybody.
    let key = std::fs::read_to_string(fixture.path("server.key")).unwrap();
    fixture.write_with_mode("server.key", &key, 0o640);
    fixture.write_with_mode(
        "tokens.yaml",
        &fixture::token_file("t", "svc.backup.aaaaaaaaaaaa"),
        0o660,
    );
    fixture.write_with_mode(
        "pgsnare.yaml",
        &fixture::valid("token_files: [tokens.yaml]\n"),
        0o644,
    );
    let run = check(&fixture, &[]);
    expect(&fixture, &run, 1, "config-check-open-files.txt");
    run_refuses_it_too(&fixture);

    // With the option that lets pgsnare run start all the same, they are
    // warnings, and the check passes.
    let run = check(&fixture, &["--allow-insecure-file-permissions"]);
    expect(&fixture, &run, 0, "config-check-open-files-allowed.txt");
}

#[test]
fn each_file_that_holds_secrets_is_checked_on_its_own() {
    // One open file at a time fails the check, whichever it is.
    for open in ["pgsnare.yaml", "tokens.yaml", "server.key"] {
        let fixture = Fixture::new();
        fixture.certificates();
        fixture.write(
            "tokens.yaml",
            &fixture::token_file("t", "svc.backup.aaaaaaaaaaaa"),
        );
        fixture.write(
            "pgsnare.yaml",
            &fixture::valid("token_files: [tokens.yaml]\n"),
        );
        let run = check(&fixture, &[]);
        assert_eq!(run.status, 0, "{}", run.stdout);

        let content = std::fs::read_to_string(fixture.path(open)).unwrap();
        fixture.write_with_mode(open, &content, 0o604);
        let run = check(&fixture, &[]);
        assert_eq!(run.status, 1, "{open}: {}", run.stdout);
        assert!(
            fixture.normalise(&run.stdout).starts_with(&format!(
                "error: <dir>/{open}: the file is open to the group or to others"
            )),
            "{open}: {}",
            run.stdout
        );
        run_refuses_it_too(&fixture);
    }
}

#[test]
fn a_configuration_that_is_not_there_is_an_error() {
    let fixture = Fixture::new();
    let run = check(&fixture, &[]);
    expect(&fixture, &run, 1, "config-check-no-file.txt");
    run_refuses_it_too(&fixture);
}

// --- Warnings ----------------------------------------------------------------------

/// A valid configuration with `listener` as its upstream TLS mode and
/// `more` at its end.
fn with(mode: &str, more: &str) -> String {
    fixture::valid(more).replace("mode: verify-full, ca: ca.crt", mode)
}

/// The warnings a check prints for a configuration, and its status.
fn warnings(configuration: &str) -> (Vec<String>, i32) {
    let fixture = Fixture::new();
    fixture.certificates();
    fixture.write("pgsnare.yaml", configuration);
    let run = check(&fixture, &[]);
    assert_eq!(run.stderr, "");
    let lines: Vec<String> = run
        .stdout
        .lines()
        .filter_map(|line| line.strip_prefix("warning: "))
        .map(str::to_owned)
        .collect();
    assert!(
        !run.stdout.lines().any(|line| line.starts_with("error: ")),
        "unexpected error: {}",
        run.stdout
    );
    (lines, run.status)
}

#[test]
fn a_database_whose_certificate_is_not_verified_is_a_warning() {
    for mode in ["mode: require", "mode: prefer"] {
        let (found, status) = warnings(&with(mode, ""));
        assert_eq!(found.len(), 1, "{found:?}");
        assert!(
            found[0].starts_with(
                "listeners[0].upstream_tls.mode: the certificate of the database is not verified"
            ),
            "{found:?}"
        );
        assert_eq!(status, 0);
    }
}

#[test]
fn a_sink_over_plain_http_is_a_warning() {
    let sink = "    - type: webhook\n      url: http://alerts.example.com/hook\n      \
                hmac_secret_env: PGSNARE_WEBHOOK_SECRET\n      allow_insecure_http: true\n";
    let (found, status) = warnings(&fixture::valid(sink));
    assert_eq!(
        found,
        [
            "events.sinks[1].url: events are sent over plain HTTP: whoever is on the way can read \
          and change them"
        ]
    );
    assert_eq!(status, 0);
}

#[test]
fn fail_open_is_a_warning() {
    let (found, status) = warnings(&fixture::valid("inspection: { on_error: fail_open }\n"));
    assert_eq!(
        found,
        [
            "inspection.on_error: fail_open lets a session go on without inspection when \
          inspecting it fails: honeytokens then pass unseen"
        ]
    );
    assert_eq!(status, 0);
}

#[test]
fn an_admin_or_metrics_listener_beyond_loopback_is_a_warning() {
    let (found, status) = warnings(&fixture::valid("admin: { listen: 0.0.0.0:9641 }\n"));
    assert_eq!(
        found,
        [
            "admin.listen: the admin listener can be reached from other machines: it is meant for \
          this machine alone"
        ]
    );
    assert_eq!(status, 0);

    let (found, status) = warnings(&fixture::valid("metrics: { listen: 192.0.2.10:9642 }\n"));
    assert_eq!(
        found,
        [
            "metrics.listen: the metrics listener can be reached from other machines: make sure \
          that only the scraper can connect to it"
        ]
    );
    assert_eq!(status, 0);
}

#[test]
fn a_configuration_with_the_safe_defaults_has_no_warning() {
    let (found, status) = warnings(&fixture::valid(""));
    assert!(found.is_empty(), "{found:?}");
    assert_eq!(status, 0);
}

#[test]
fn all_warnings_together_still_pass() {
    let fixture = Fixture::new();
    fixture.certificates();
    fixture.write(
        "pgsnare.yaml",
        &with(
            "mode: require",
            "    - type: webhook\n      url: http://alerts.example.com/hook\n      \
             hmac_secret_env: PGSNARE_WEBHOOK_SECRET\n      allow_insecure_http: true\n\
             inspection: { on_error: fail_open }\n\
             admin: { listen: 0.0.0.0:9641 }\n\
             metrics: { listen: 0.0.0.0:9642 }\n",
        ),
    );
    let run = check(&fixture, &[]);
    expect(&fixture, &run, 0, "config-check-warnings.txt");
}

#[test]
fn errors_and_warnings_are_reported_together() {
    let fixture = Fixture::new();
    fixture.certificates();
    let key = std::fs::read_to_string(fixture.path("server.key")).unwrap();
    fixture.write_with_mode("server.key", &key, 0o644);
    std::fs::remove_file(fixture.path("ca.crt")).unwrap();
    fixture.write(
        "pgsnare.yaml",
        &fixture::valid("inspection: { on_error: fail_open }\nadmin: { listen: 0.0.0.0:9641 }\n"),
    );
    let run = check(&fixture, &[]);
    expect(&fixture, &run, 1, "config-check-errors-and-warnings.txt");
    run_refuses_it_too(&fixture);
}

#[test]
fn the_help_says_what_is_checked_and_what_is_not() {
    let run = expected::run(&["config", "check", "--help"]);
    assert_eq!(run.status, 0);
    assert_eq!(run.stderr, "");
    expected::check("config-check-help.txt", &run.stdout);
}
