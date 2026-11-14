// SPDX-License-Identifier: Apache-2.0

//! `pgsnare token list`: what it prints, and that no value is in it.

use crate::expected;
use crate::fixture::{self, Fixture};

/// The values of the configuration below. None may ever be printed.
const VALUES: [&str; 5] = [
    "svc.backup.aaaaaaaaaaaa",
    "ABCD-EFGH-IJKL-MNOP",
    "9911111111111112",
    "Canary.Invoice.000417",
    "from-the-token-file-0001",
];

/// A configuration with tokens of its own and a token file.
fn configuration(fixture: &Fixture) -> String {
    fixture.write(
        "tokens/more.yaml",
        "\
tokens:
  - id: from-a-token-file
    values: [\"from-the-token-file-0001\"]
    scope: { table: \"caf\\xE9\" }
",
    );
    fixture.write(
        "pgsnare.yaml",
        &fixture::valid(
            "\
token_files: [\"tokens/*.yaml\"]
tokens:
  - id: users-admin-backup
    values: [\"svc.backup.aaaaaaaaaaaa\"]
    scope: { database: app, table: public.users, column: name }
    actions: [alert, kill]
    escalate: { after_hits: 3, to: [kill] }
  - id: notes-and-cards
    values: [\"ABCD-EFGH-IJKL-MNOP\", \"9911111111111112\"]
    scope: { database: shop }
    actions: [alert, fake_data, tarpit]
  - id: billing-canary
    values: [\"Canary.Invoice.000417\"]
    case_insensitive: true
    escalate: { after_hits: 1, to: [alert, kill] }
",
        ),
    );
    fixture.arg("pgsnare.yaml")
}

#[test]
fn the_list_shows_ids_scopes_and_responses() {
    let fixture = Fixture::new();
    let config = configuration(&fixture);
    let run = expected::run(&["token", "list", "--config", &config]);
    assert_eq!(run.stderr, "");
    assert_eq!(run.status, 0);
    expected::check("token-list.txt", &run.stdout);
}

#[test]
fn no_value_is_in_the_list_or_anywhere_else() {
    let fixture = Fixture::new();
    let config = configuration(&fixture);
    let run = expected::run(&["token", "list", "-c", &config]);
    for value in VALUES {
        for output in [&run.stdout, &run.stderr] {
            assert!(!output.contains(value), "a value was printed");
            // No part of a value either.
            assert!(
                !output.contains(&value[..8]),
                "the start of a value was printed"
            );
            assert!(
                !output.contains(&value[value.len() - 8..]),
                "the end of a value was printed"
            );
        }
    }
}

#[test]
fn a_configuration_without_tokens_says_so() {
    let fixture = Fixture::new();
    fixture.write("pgsnare.yaml", &fixture::valid(""));
    let run = expected::run(&["token", "list", "--config", &fixture.arg("pgsnare.yaml")]);
    assert_eq!(run.stderr, "");
    assert_eq!(run.status, 0);
    assert_eq!(run.stdout, "The configuration has no honeytokens.\n");
}

#[test]
fn the_list_does_not_ask_for_protected_files() {
    // Listing reads the files and starts nothing, so it does not insist on
    // their access rights. `config check` is what reports those.
    let fixture = Fixture::new();
    let config = configuration(&fixture);
    fixture.write_with_mode(
        "tokens/more.yaml",
        &fixture::token_file("open", "open-to-others-0001"),
        0o644,
    );
    let run = expected::run(&["token", "list", "--config", &config]);
    assert_eq!(run.status, 0, "{}", run.stderr);
    assert!(run.stdout.contains("\nopen "), "{}", run.stdout);
}

#[test]
fn a_configuration_that_does_not_load_fails_without_a_list() {
    let fixture = Fixture::new();
    // A value where an id belongs, a misspelt field, and a value that is
    // too short: the message names places and never repeats the text.
    fixture.write(
        "pgsnare.yaml",
        &fixture::valid(
            "\
tokens:
  - id: \"svc.backup.aaaaaaaaaaaa@mail.example\"
    values: [\"ABCD-EFGH-IJKL-MNOP\"]
",
        ),
    );
    let run = expected::run(&["token", "list", "--config", &fixture.arg("pgsnare.yaml")]);
    assert_eq!(run.status, 1);
    assert_eq!(run.stdout, "");
    expected::check("token-list-invalid.txt", &fixture.normalise(&run.stderr));
    assert!(!run.stderr.contains("svc.backup"));
    assert!(!run.stderr.contains("ABCD"));

    let run = expected::run(&["token", "list", "--config", &fixture.arg("missing.yaml")]);
    assert_eq!(run.status, 1);
    assert_eq!(run.stdout, "");
    assert_eq!(
        fixture.normalise(&run.stderr),
        "pgsnare token list: <dir>/missing.yaml: cannot read the file: No such file or \
         directory (os error 2)\n"
    );
}

#[test]
fn the_help_says_that_no_value_is_shown() {
    let run = expected::run(&["token", "list", "--help"]);
    assert_eq!(run.status, 0);
    assert_eq!(run.stderr, "");
    expected::check("token-list-help.txt", &run.stdout);
}
