// SPDX-License-Identifier: Apache-2.0

//! `pgsnare token generate`: what it prints, and that what it prints is
//! safe to run and matches itself.

use std::collections::HashSet;

use clap::Parser;
use pgsnare::cli::token_generate::{self, Args, Error};
use pgsnare::cli::{Cli, Command, TokenCommand};
use pgsnare::config::TokenFile;
use pgsnare_core::bait::{BaitError, Entropy, EntropyError};
use pgsnare_core::policy::ActionSet;
use proptest::prelude::*;

use crate::expected;
use crate::sql::{self, Insert};

/// The source of randomness of the expected files. Every read fills its
/// buffer with one byte value, and the next read with the next value.
///
/// The values this gives differ from each other, can be read, and look
/// nothing like secrets.
struct Stepping(u8);

impl Entropy for Stepping {
    fn fill(&mut self, dest: &mut [u8]) -> Result<(), EntropyError> {
        dest.fill(self.0);
        self.0 = self.0.wrapping_add(1);
        Ok(())
    }
}

/// A source that gives the same bytes every time.
struct Constant(u8);

impl Entropy for Constant {
    fn fill(&mut self, dest: &mut [u8]) -> Result<(), EntropyError> {
        dest.fill(self.0);
        Ok(())
    }
}

/// A source that fails after a number of reads.
struct Failing(u32);

impl Entropy for Failing {
    fn fill(&mut self, dest: &mut [u8]) -> Result<(), EntropyError> {
        if self.0 == 0 {
            return Err(EntropyError::from_os_error(5));
        }
        self.0 -= 1;
        dest.fill(0);
        Ok(())
    }
}

/// The arguments the command line gives for `pgsnare token generate` and
/// the rest of `line`.
fn arguments(line: &[&str]) -> Args {
    let all = ["pgsnare", "token", "generate"]
        .into_iter()
        .chain(line.iter().copied());
    match Cli::try_parse_from(all).map(|cli| cli.command) {
        Ok(Command::Token(TokenCommand::Generate(args))) => args,
        Ok(other) => panic!("expected token generate, got {other:?}"),
        Err(error) => panic!("the command line is refused: {error}"),
    }
}

/// What the command prints for `line` with the randomness of the expected
/// files.
fn generated(line: &[&str]) -> String {
    token_generate::generate(&arguments(line), &mut Stepping(0))
        .unwrap_or_else(|error| panic!("{line:?}: {error}"))
}

/// Why the command prints nothing for `line`.
fn refused(line: &[&str]) -> String {
    match token_generate::generate(&arguments(line), &mut Stepping(0)) {
        Ok(_) => panic!("{line:?} is accepted"),
        Err(error) => error.to_string(),
    }
}

/// Checks a script against itself and against what was asked for.
///
/// - It is printable ASCII.
/// - It holds exactly one statement: an `INSERT` into `table` with
///   `columns` and `count` rows of constants.
/// - Its token file loads, and has a token for every row, whose value is
///   the first constant of that row and whose scope is the table as it was
///   given and the first column.
fn examine(
    script: &str,
    table: &[&str],
    columns: &[&str],
    table_as_given: &str,
    count: usize,
) -> Insert {
    assert!(
        script
            .bytes()
            .all(|byte| byte == b'\n' || (b' '..=b'~').contains(&byte)),
        "the script is not printable ASCII"
    );
    let insert = sql::read(script).unwrap_or_else(|error| panic!("{error}:\n{script}"));
    assert_eq!(insert.table, table);
    assert_eq!(insert.columns, columns);
    assert_eq!(insert.rows.len(), count);
    assert!(insert.rows.iter().all(|row| row.len() == columns.len()));

    let file = sql::token_file(script).unwrap();
    assert!(!file.contains('*'), "the token file could end its comment");
    let file = TokenFile::from_yaml(file).unwrap_or_else(|error| panic!("{error}:\n{script}"));
    assert_eq!(file.tokens.len(), count);
    for (token, row) in file.tokens.iter().zip(&insert.rows) {
        assert_eq!(token.values.len(), 1);
        assert_eq!(token.values[0].expose(), row[0]);
        assert_eq!(token.scope.database, None);
        assert_eq!(token.scope.table.as_deref(), Some(table_as_given));
        assert_eq!(token.scope.column.as_deref(), Some(columns[0]));
        assert_eq!(token.actions, ActionSet::ALERT);
        assert!(!token.case_insensitive);
    }

    // Every value in the script is there once.
    let values: Vec<&String> = insert.rows.iter().flatten().collect();
    let distinct: HashSet<&String> = values.iter().copied().collect();
    assert_eq!(distinct.len(), values.len());
    insert
}

// --- Expected output of every kind ------------------------------------------

#[test]
fn identity() {
    let script = generated(&[
        "--kind",
        "identity",
        "--table",
        "public.users",
        "--domain",
        "mail.example",
        "--count",
        "2",
    ]);
    expected::check("token-generate-identity.sql", &script);
    let insert = examine(
        &script,
        &["public", "users"],
        &["name", "email"],
        "public.users",
        2,
    );
    for row in &insert.rows {
        // The address is the name at the domain that was given, and the
        // name is the value of the token.
        assert_eq!(row[1], format!("{}@mail.example", row[0]));
    }
}

#[test]
fn bcrypt() {
    let script = generated(&["--kind", "bcrypt", "--table", "public.users"]);
    expected::check("token-generate-bcrypt.sql", &script);
    let insert = examine(
        &script,
        &["public", "users"],
        &["password_hash"],
        "public.users",
        1,
    );
    assert!(insert.rows[0][0].starts_with("$2a$12$"));
    assert_eq!(insert.rows[0][0].len(), 60);
}

#[test]
fn argon2id() {
    let script = generated(&[
        "--kind",
        "argon2id",
        "--table",
        "public.users",
        "--column",
        "password",
    ]);
    expected::check("token-generate-argon2id.sql", &script);
    let insert = examine(
        &script,
        &["public", "users"],
        &["password"],
        "public.users",
        1,
    );
    assert!(insert.rows[0][0].starts_with("$argon2id$v=19$m=65536,t=3,p=4$"));
}

#[test]
fn scram_sha_256() {
    let script = generated(&[
        "--kind",
        "scram-sha-256",
        "--table",
        "auth.roles",
        "--column",
        "verifier",
    ]);
    expected::check("token-generate-scram-sha-256.sql", &script);
    let insert = examine(&script, &["auth", "roles"], &["verifier"], "auth.roles", 1);
    assert!(insert.rows[0][0].starts_with("SCRAM-SHA-256$4096:"));
}

#[test]
fn api_key() {
    let script = generated(&[
        "--kind",
        "api-key",
        "--table",
        "public.api_keys",
        "--count",
        "3",
    ]);
    expected::check("token-generate-api-key.sql", &script);
    let insert = examine(
        &script,
        &["public", "api_keys"],
        &["api_key"],
        "public.api_keys",
        3,
    );
    assert!(insert.rows.iter().all(|row| row[0].len() == 40));
}

#[test]
fn card() {
    let script = generated(&["--kind", "card", "--table", "shop.cards", "--count", "2"]);
    expected::check("token-generate-card.sql", &script);
    let insert = examine(
        &script,
        &["shop", "cards"],
        &["card_number"],
        "shop.cards",
        2,
    );
    for row in &insert.rows {
        assert_eq!(row[0].len(), 16);
        assert!(row[0].starts_with("99"));
    }
}

#[test]
fn marker() {
    let script = generated(&[
        "--kind",
        "marker",
        "--table",
        "notes",
        "--id",
        "notes-marker",
    ]);
    expected::check("token-generate-marker.sql", &script);
    let insert = examine(&script, &["notes"], &["note"], "notes", 1);
    // With an id of the operator, nothing random is spent on one, so the
    // first value is made of the first byte of the source.
    assert_eq!(insert.rows[0][0], "AAAA-AAAA-AAAA-AAAA");
    let file = TokenFile::from_yaml(sql::token_file(&script).unwrap()).unwrap();
    assert_eq!(file.tokens[0].id.as_str(), "notes-marker");
}

#[test]
fn the_ids_are_the_kind_and_random_characters_or_what_the_operator_gave() {
    let ids = |line: &[&str]| -> Vec<String> {
        let script = generated(line);
        TokenFile::from_yaml(sql::token_file(&script).unwrap())
            .unwrap()
            .tokens
            .iter()
            .map(|token| token.id.as_str().to_owned())
            .collect()
    };
    assert_eq!(ids(&["--kind", "card", "--table", "t"]), ["card-aaaaaa"]);
    assert_eq!(
        ids(&["--kind", "scram-sha-256", "--table", "t", "--count", "2"]),
        ["scram-sha-256-aaaaaa-1", "scram-sha-256-aaaaaa-2"]
    );
    assert_eq!(
        ids(&["--kind", "card", "--table", "t", "--id", "cards.Test_1"]),
        ["cards.Test_1"]
    );
    assert_eq!(
        ids(&[
            "--kind", "card", "--table", "t", "--id", "cards", "--count", "3"
        ]),
        ["cards-1", "cards-2", "cards-3"]
    );
}

// --- Names that try to get out of their quotes -------------------------------

#[test]
fn hostile_names_stay_names() {
    let table = "\"Shop\".\"Customer \"\"Logins\"\"; DROP TABLE users; --\"";
    let script = generated(&[
        "--kind",
        "identity",
        "--table",
        table,
        "--column",
        "\"na\"\"me\"",
        "--column",
        "e-mail'); DROP TABLE users; --",
        "--domain",
        "mail.example",
        "--id",
        "shop-logins",
        "--count",
        "2",
    ]);
    expected::check("token-generate-hostile-names.sql", &script);
    examine(
        &script,
        &["Shop", "Customer \"Logins\"; DROP TABLE users; --"],
        &["na\"me", "e-mail'); DROP TABLE users; --"],
        table,
        2,
    );
}

#[test]
fn names_outside_ascii_are_written_in_ascii() {
    let table = "caf\u{e9}.\"\u{8868}*/ \\ \u{1f600}\"";
    let script = generated(&["--kind", "marker", "--table", table, "--column", "a\\b"]);
    expected::check("token-generate-names-outside-ascii.sql", &script);
    examine(
        &script,
        &["caf\u{e9}", "\u{8868}*/ \\ \u{1f600}"],
        &["a\\b"],
        table,
        1,
    );
}

#[test]
fn a_name_that_cannot_be_written_is_refused_and_nothing_is_printed() {
    for (table, problem) in [
        ("", "the name, or a part of it between two dots, is empty"),
        (
            "public.",
            "the name, or a part of it between two dots, is empty",
        ),
        (
            "users\0",
            "the name contains a control character, which cannot be written in a statement",
        ),
        (
            "users\n; DROP TABLE users",
            "the name contains a control character, which cannot be written in a statement",
        ),
        (
            "us\"ers",
            "a double quote may only begin and end a part of the name; inside a quoted part, \
             write it twice",
        ),
        (
            "\"users",
            "a part of the name begins with a double quote and has no end",
        ),
        (
            "\"users\"; DROP TABLE users",
            "after the closing double quote of a part, only a dot may follow",
        ),
    ] {
        assert_eq!(
            refused(&["--kind", "marker", "--table", table]),
            format!("--table: {problem}"),
            "{table:?}"
        );
    }
    assert_eq!(
        refused(&["--kind", "marker", "--table", &"t".repeat(257)]),
        "--table: the name is longer than 256 bytes"
    );
    assert_eq!(
        refused(&["--kind", "marker", "--table", "a.b.c.d"]),
        "--table: the name has too many parts: a table is named as table, schema.table or \
         database.schema.table, and a column has one part; put double quotes around a part \
         that contains a dot"
    );
    assert!(
        refused(&["--kind", "marker", "--table", "t", "--column", "users.note"])
            .starts_with("--column: the name has too many parts")
    );
    assert_eq!(
        refused(&["--kind", "marker", "--table", "t", "--column", "no\tte"]),
        "--column: the name contains a control character, which cannot be written in a statement"
    );
}

// --- Arguments that do not fit together --------------------------------------

#[test]
fn arguments_that_do_not_fit_the_kind_are_refused() {
    assert_eq!(
        refused(&["--kind", "identity", "--table", "t"]),
        "--domain: the kind identity needs the domain of its email addresses, such as --domain \
         mail.example; no domain is built in"
    );
    assert_eq!(
        refused(&[
            "--kind",
            "marker",
            "--table",
            "t",
            "--domain",
            "mail.example"
        ]),
        "--domain: only the kind identity makes email addresses"
    );
    assert!(
        refused(&[
            "--kind",
            "identity",
            "--table",
            "t",
            "--domain",
            "not a domain"
        ])
        .starts_with("--domain: a mail domain is a host name such as mail.example")
    );
    assert_eq!(
        refused(&[
            "--kind",
            "identity",
            "--table",
            "t",
            "--domain",
            "mail.example",
            "--column",
            "a"
        ]),
        "--column: the kind identity fills 2 columns, so give --column 2 times or not at all"
    );
    assert_eq!(
        refused(&[
            "--kind", "card", "--table", "t", "--column", "a", "--column", "b"
        ]),
        "--column: the kind card fills one column, so give --column once or not at all"
    );
    let id = "--id: an id is 1 to 64 ASCII letters, digits, '.', '_' and '-', starting with a \
              letter or a digit; with more than one honeytoken it must leave room for a hyphen \
              and a number";
    assert_eq!(
        refused(&["--kind", "card", "--table", "t", "--id", "has space"]),
        id
    );
    assert_eq!(refused(&["--kind", "card", "--table", "t", "--id", ""]), id);
    assert_eq!(
        refused(&[
            "--kind",
            "card",
            "--table",
            "t",
            "--id",
            &"i".repeat(64),
            "--count",
            "2"
        ]),
        id
    );
}

// --- Randomness ---------------------------------------------------------------

#[test]
fn a_source_that_fails_prints_nothing() {
    let line = ["--kind", "scram-sha-256", "--table", "t", "--count", "3"];
    // The id, and two reads for each of three values.
    for reads in 0..7 {
        assert_eq!(
            token_generate::generate(&arguments(&line), &mut Failing(reads)),
            Err(Error::Bait(BaitError::Entropy(
                EntropyError::from_os_error(5)
            ))),
            "after {reads} reads"
        );
    }
    assert!(token_generate::generate(&arguments(&line), &mut Failing(7)).is_err());
    let message = token_generate::generate(&arguments(&line), &mut Failing(0))
        .unwrap_err()
        .to_string();
    assert_eq!(
        message,
        "no value could be generated: the source of randomness failed (operating system error 5)"
    );
}

#[test]
fn values_that_are_the_same_are_never_printed() {
    // A source that repeats itself gives the same value twice. That is
    // caught, tried again, and in the end refused.
    let line = ["--kind", "marker", "--table", "t", "--count", "2"];
    assert_eq!(
        token_generate::generate(&arguments(&line), &mut Constant(3)),
        Err(Error::Clash)
    );
    // One value has nothing to clash with.
    let line = ["--kind", "marker", "--table", "t"];
    assert!(token_generate::generate(&arguments(&line), &mut Constant(3)).is_ok());
}

#[test]
fn the_command_prints_new_values_every_time() {
    let line = [
        "token",
        "generate",
        "--kind",
        "api-key",
        "--table",
        "public.api_keys",
        "--count",
        "3",
    ];
    let mut seen = HashSet::new();
    for _ in 0..3 {
        let run = expected::run(&line);
        assert_eq!(run.status, 0, "{}", run.stderr);
        assert_eq!(run.stderr, "");
        let insert = examine(
            &run.stdout,
            &["public", "api_keys"],
            &["api_key"],
            "public.api_keys",
            3,
        );
        for row in insert.rows {
            assert!(seen.insert(row[0].clone()), "a value came twice");
        }
    }
    assert_eq!(seen.len(), 9);
}

#[test]
fn nothing_in_the_environment_makes_the_values_predictable() {
    // Names that a seed could plausibly hide behind. The values still
    // differ from run to run.
    let line = ["token", "generate", "--kind", "marker", "--table", "t"];
    let value = || {
        let mut command = expected::pgsnare(&line);
        for name in [
            "SEED",
            "RANDOM_SEED",
            "RNG_SEED",
            "PGSNARE_SEED",
            "PGSNARE_RANDOM_SEED",
            "PGSNARE_TEST",
            "PGSNARE_DETERMINISTIC",
            "SOURCE_DATE_EPOCH",
            "RUST_TEST_SEED",
            "PROPTEST_RNG_SEED",
        ] {
            command.env(name, "1");
        }
        let run = expected::run_command(command);
        assert_eq!(run.status, 0, "{}", run.stderr);
        examine(&run.stdout, &["t"], &["note"], "t", 1).rows[0][0].clone()
    };
    let values: HashSet<String> = (0..4).map(|_| value()).collect();
    assert_eq!(values.len(), 4);
}

#[test]
fn a_refused_command_line_fails_and_prints_nothing_to_standard_output() {
    let run = expected::run(&["token", "generate", "--kind", "identity", "--table", "t"]);
    assert_eq!(run.status, 1);
    assert_eq!(run.stdout, "");
    assert_eq!(
        run.stderr,
        "pgsnare token generate: --domain: the kind identity needs the domain of its email \
         addresses, such as --domain mail.example; no domain is built in\n"
    );

    let run = expected::run(&[
        "token", "generate", "--kind", "marker", "--table", "us\"ers",
    ]);
    assert_eq!(run.status, 1);
    assert_eq!(run.stdout, "");

    // What the command line itself does not take is a usage error.
    for line in [
        &[
            "token",
            "generate",
            "--kind",
            "no-such-kind",
            "--table",
            "t",
        ][..],
        &["token", "generate", "--kind", "marker"],
        &[
            "token", "generate", "--kind", "marker", "--table", "t", "--count", "1001",
        ],
        &[
            "token", "generate", "--kind", "marker", "--table", "t", "--seed", "1",
        ],
    ] {
        let run = expected::run(line);
        assert_eq!(run.status, 2, "{line:?}");
        assert_eq!(run.stdout, "", "{line:?}");
    }
}

#[test]
fn the_help_says_what_the_command_does_and_does_not_do() {
    let run = expected::run(&["token", "generate", "--help"]);
    assert_eq!(run.status, 0);
    assert_eq!(run.stderr, "");
    expected::check("token-generate-help.txt", &run.stdout);
}

// --- Any name at all ----------------------------------------------------------

/// A part of a name: anything but control characters.
fn part() -> impl Strategy<Value = String> {
    prop_oneof![
        3 => "\\PC{1,12}",
        // The characters that matter to SQL, to psql and to YAML, densely.
        2 => r#"["'\\;.*/\-!$&U ]{1,12}"#,
        1 => "[a-z_]{1,12}",
    ]
}

/// A part between double quotes, as the command line takes it.
fn quote(part: &str) -> String {
    format!("\"{}\"", part.replace('"', "\"\""))
}

proptest! {
    #![proptest_config(ProptestConfig::with_cases(600))]

    /// Whatever the names, the script is one statement with exactly those
    /// names, and its token file loads with exactly that scope.
    #[test]
    fn any_names_give_one_statement_with_those_names(
        table in proptest::collection::vec(part(), 1..=3),
        columns in proptest::collection::vec(part(), 2),
        count in 1u32..4,
    ) {
        let table_as_given = table.iter().map(|part| quote(part)).collect::<Vec<_>>().join(".");
        prop_assume!(table_as_given.len() <= token_generate::MAX_NAME_BYTES);
        let count_text = count.to_string();
        let column_arguments: Vec<String> = columns.iter().map(|column| quote(column)).collect();
        let line = [
            "--kind", "identity", "--domain", "mail.example", "--id", "t",
            "--table", &table_as_given,
            "--column", &column_arguments[0],
            "--column", &column_arguments[1],
            "--count", &count_text,
        ];
        let script = token_generate::generate(&arguments(&line), &mut Stepping(0)).unwrap();
        let table: Vec<&str> = table.iter().map(String::as_str).collect();
        let columns: Vec<&str> = columns.iter().map(String::as_str).collect();
        examine(&script, &table, &columns, &table_as_given, count as usize);
    }

    /// Whatever text is given for a table, without any care for quotes:
    /// it is refused, or the script is one statement that is safe to run.
    #[test]
    fn any_text_for_a_table_is_refused_or_gives_one_statement(
        table in r#"(\PC|["'\\;.*/\-!]|\x00|\n){0,24}"#,
    ) {
        // Joined to its option, so that a text that begins with a hyphen
        // is not taken for an option itself.
        let table_argument = format!("--table={table}");
        let line = ["--kind", "marker", &table_argument];
        match token_generate::generate(&arguments(&line), &mut Stepping(0)) {
            Ok(script) => {
                let insert = sql::read(&script);
                prop_assert!(insert.is_ok(), "{:?}", insert);
                let file = TokenFile::from_yaml(sql::token_file(&script).unwrap());
                prop_assert!(file.is_ok(), "{:?}", file);
                let scope = file.unwrap().tokens[0].scope.table.clone();
                prop_assert_eq!(scope, Some(table));
            }
            Err(Error::Name { option, .. }) => prop_assert_eq!(option, "--table"),
            Err(other) => prop_assert!(false, "{:?}", other),
        }
    }
}
