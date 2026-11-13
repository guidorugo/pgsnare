// SPDX-License-Identifier: Apache-2.0

//! `pgsnare token test`: what it answers, its exit status, and that the
//! value it is given shows up nowhere.

use std::io::Write;
use std::process::Stdio;

use crate::expected::{self, Run};
use crate::fixture::{self, Fixture};

/// A configuration with two tokens.
fn configuration(fixture: &Fixture) -> String {
    fixture.write(
        "pgsnare.yaml",
        &fixture::valid(
            "\
tokens:
  - id: users-admin-backup
    values: [\"svc.backup.aaaaaaaaaaaa\"]
  - id: billing-canary
    values: [\"Canary.Invoice.000417\", \"ABCD-EFGH-IJKL-MNOP\"]
    case_insensitive: true
",
        ),
    );
    fixture.arg("pgsnare.yaml")
}

/// Runs `pgsnare token test` with `input` on standard input.
fn test_with(arguments: &[&str], input: &[u8]) -> Run {
    let mut line = vec!["token", "test"];
    line.extend_from_slice(arguments);
    let mut command = expected::pgsnare(&line);
    command.stdin(Stdio::piped());
    let mut child = command.spawn().expect("the pgsnare binary can be run");
    // The command may end before it has read everything, and then the
    // pipe is closed. That is no failure of the test.
    let _ = child.stdin.take().unwrap().write_all(input);
    expected::finish(child)
}

fn test(config: &str, input: &[u8]) -> Run {
    test_with(&["--config", config], input)
}

#[test]
fn a_value_of_a_token_is_answered_with_the_id_of_that_token() {
    let fixture = Fixture::new();
    let config = configuration(&fixture);

    let run = test(&config, b"svc.backup.aaaaaaaaaaaa\n");
    assert_eq!(run.stderr, "");
    assert_eq!(
        run.stdout,
        "matches honeytoken users-admin-backup: values[0], as it is\n"
    );
    assert_eq!(run.status, 0);

    // With or without a line break at the end, and with the line break of
    // another system.
    for input in [&b"ABCD-EFGH-IJKL-MNOP"[..], b"ABCD-EFGH-IJKL-MNOP\r\n"] {
        let run = test(&config, input);
        assert_eq!(
            run.stdout,
            "matches honeytoken billing-canary: values[1], as it is\n"
        );
        assert_eq!(run.status, 0);
    }
}

#[test]
fn a_value_of_no_token_is_answered_with_that_and_a_failure() {
    let fixture = Fixture::new();
    let config = configuration(&fixture);
    for input in [
        &b"svc.backup.aaaaaaaaaaab\n"[..],
        b"not-a-honeytoken-at-all\n",
        b"short\n",
        // The first token does not ignore letter case.
        b"SVC.BACKUP.AAAAAAAAAAAA\n",
    ] {
        let run = test(&config, input);
        assert_eq!(run.stderr, "");
        assert_eq!(run.stdout, "no honeytoken matches\n");
        assert_eq!(run.status, 1);
    }
}

#[test]
fn a_value_is_looked_for_the_way_traffic_is_scanned() {
    let fixture = Fixture::new();
    let config = configuration(&fixture);
    // A row that holds two tokens: one in hexadecimal, as a bytea column
    // is printed, and one in another letter case.
    let hex: String = b"svc.backup.aaaaaaaaaaaa"
        .iter()
        .map(|byte| format!("{byte:02x}"))
        .collect();
    let row = format!("1042\t\\\\x{hex}\tCANARY.INVOICE.000417\t2026-01-31\n");
    let run = test(&config, row.as_bytes());
    assert_eq!(run.stderr, "");
    expected::check("token-test-row.txt", &run.stdout);
    assert_eq!(run.status, 0);
}

#[test]
fn the_value_is_printed_nowhere() {
    let fixture = Fixture::new();
    let config = configuration(&fixture);
    let secret = "svc.backup.aaaaaaaaaaaa";
    let unknown = "an-unknown-value-0042";
    let shown = |run: &Run, value: &str| {
        run.stdout.contains(value)
            || run.stderr.contains(value)
            || run.stdout.contains(&value[..8])
            || run.stderr.contains(&value[..8])
    };

    // A match, no match, and every way the command can fail.
    let runs = [
        test(&config, secret.as_bytes()),
        test(&config, unknown.as_bytes()),
        test(&fixture.arg("missing.yaml"), secret.as_bytes()),
        test_with(&["--config", &config, secret], b""),
        test_with(&["--config", &config, "--value", secret], b""),
        test_with(&["--config", &config, &format!("--value={secret}")], b""),
        test_with(&[secret, "--config", &config], b""),
        test_with(&[secret], b""),
        test_with(&["--config", &config, "--", secret], b""),
    ];
    for (number, run) in runs.iter().enumerate() {
        assert!(!shown(run, secret), "run {number} printed the value");
        assert!(!shown(run, unknown), "run {number} printed the value");
    }
    // A value given as an argument is a mistake of usage, whatever else is
    // on the command line.
    for run in &runs[3..] {
        assert_eq!(run.status, 2);
        assert_eq!(run.stdout, "");
    }
    expected::check("token-test-argument.txt", &runs[3].stderr);
}

#[test]
fn a_terminal_is_refused() {
    use rustix::pty::{OpenptFlags, grantpt, ioctl_tiocgptpeer, openpt, unlockpt};

    let fixture = Fixture::new();
    let config = configuration(&fixture);

    // A terminal that nobody sits at: the two ends of a pseudo-terminal.
    // The command gets the end a shell would give it as standard input.
    let flags = OpenptFlags::RDWR | OpenptFlags::NOCTTY;
    let controller = openpt(flags).expect("a pseudo-terminal can be opened");
    grantpt(&controller).unwrap();
    unlockpt(&controller).unwrap();
    let terminal = ioctl_tiocgptpeer(&controller, flags).unwrap();

    // What somebody would type: a value of a token, Enter, and the end of
    // the input. A command that read its terminal would answer with a
    // match, so this test fails then, and does not wait for ever.
    let mut keyboard = std::fs::File::from(controller);
    keyboard
        .write_all(b"svc.backup.aaaaaaaaaaaa\n\x04")
        .unwrap();

    let mut command = expected::pgsnare(&["token", "test", "--config", &config]);
    command.stdin(Stdio::from(terminal));
    let run = expected::run_command(command);

    // No value is read from it, and so none is shown on it.
    assert_eq!(run.status, 1);
    assert_eq!(run.stdout, "");
    expected::check("token-test-terminal.txt", &run.stderr);
}

#[test]
fn without_a_value_no_test_is_made() {
    let fixture = Fixture::new();
    let config = configuration(&fixture);
    for input in [&b""[..], b"\n", b"\r\n"] {
        let run = test(&config, input);
        assert_eq!(run.status, 1);
        assert_eq!(run.stdout, "");
        assert_eq!(
            run.stderr,
            "pgsnare token test: no value was given on standard input\n"
        );
    }

    // More than the command reads.
    let long = vec![b'x'; 1024 * 1024 + 2];
    let run = test(&config, &long);
    assert_eq!(run.status, 1);
    assert_eq!(run.stdout, "");
    assert_eq!(
        run.stderr,
        "pgsnare token test: the input is longer than 1MiB\n"
    );

    // Exactly as much as it reads is tested.
    let mut longest = vec![b'x'; 1024 * 1024 - 23];
    longest.extend_from_slice(b"svc.backup.aaaaaaaaaaaa");
    let run = test(&config, &longest);
    assert_eq!(run.status, 0, "{}", run.stderr);
}

#[test]
fn a_configuration_that_does_not_load_gives_no_answer() {
    let fixture = Fixture::new();
    fixture.write("pgsnare.yaml", "listeners: []\n");
    let run = test(&fixture.arg("pgsnare.yaml"), b"svc.backup.aaaaaaaaaaaa\n");
    assert_eq!(run.status, 1);
    // Nothing on standard output: a script can tell "no match" from "no
    // test" by that.
    assert_eq!(run.stdout, "");
    assert!(
        run.stderr.starts_with("pgsnare token test: "),
        "{}",
        run.stderr
    );
}

#[test]
fn the_help_says_why_the_value_is_not_an_argument() {
    let run = expected::run(&["token", "test", "--help"]);
    assert_eq!(run.status, 0);
    assert_eq!(run.stderr, "");
    expected::check("token-test-help.txt", &run.stdout);
    assert!(run.stdout.contains("history of the shell"));
    assert!(run.stdout.contains("process list"));
}
