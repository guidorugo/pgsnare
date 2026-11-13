// SPDX-License-Identifier: Apache-2.0

//! `pgsnare token list`: list the honeytokens of a configuration by id,
//! scope and response. It never prints a value.
//!
//! The values are what must stay secret, so nothing that is printed is
//! made from one: not a value, not a part of one and not its length. A
//! token is shown with the number of its values, and that is all that is
//! said about them.

use std::fmt::Write as _;
use std::io::Write as _;
use std::path::PathBuf;

use crate::config::{Config, Token};

use super::config_check::{disable_core_dumps, load_for};
use super::{FAILURE, SUCCESS};

/// The arguments of `pgsnare token list`.
#[derive(Debug, clap::Args)]
#[command(
    after_long_help = "The list shows, for every honeytoken: its id, the database, table and column it\n\
        was planted in as the configuration says, its response and escalation, the\n\
        number of its values, and whether letter case is ignored. A value is never\n\
        shown, and neither is anything made from one.\n\n\
        Example:\n  pgsnare token list --config /etc/pgsnare/pgsnare.yaml"
)]
pub struct Args {
    /// The configuration file. Its token files are read as well.
    #[arg(short, long, value_name = "FILE")]
    pub config: PathBuf,
}

/// The headings of the table.
const HEADINGS: [&str; 8] = [
    "ID",
    "DATABASE",
    "TABLE",
    "COLUMN",
    "RESPONSE",
    "ESCALATION",
    "VALUES",
    "LETTER CASE",
];

/// What stands in a cell that has nothing to show.
const NOTHING: &str = "-";

/// Text from the configuration, made safe to print in one cell.
///
/// Printable ASCII and the letters and digits of other scripts are shown
/// as they are. Anything else is written as its code point, so that a name
/// in the configuration cannot move the cursor, hide text or break a line.
/// A backslash is doubled, which keeps what is printed unambiguous.
fn shown(text: &str) -> String {
    let mut out = String::with_capacity(text.len());
    for character in text.chars() {
        match character {
            '\\' => out.push_str("\\\\"),
            ' '..='~' => out.push(character),
            other if other.is_alphanumeric() => out.push(other),
            other => out.extend(other.escape_unicode()),
        }
    }
    out
}

/// The cells of the line of one token.
fn cells(token: &Token) -> [String; 8] {
    let scope = |part: &Option<String>| part.as_deref().map_or_else(|| NOTHING.to_owned(), shown);
    let actions = |set: pgsnare_core::policy::ActionSet| {
        set.iter()
            .map(|action| action.name())
            .collect::<Vec<_>>()
            .join(", ")
    };
    let escalation = token.escalate.map_or_else(
        || NOTHING.to_owned(),
        |escalation| {
            let hits = if escalation.after_hits == 1 {
                "hit"
            } else {
                "hits"
            };
            format!(
                "{} after {} {hits}",
                actions(escalation.to),
                escalation.after_hits
            )
        },
    );
    [
        token.id.as_str().to_owned(),
        scope(&token.scope.database),
        scope(&token.scope.table),
        scope(&token.scope.column),
        actions(token.actions),
        escalation,
        token.values.len().to_string(),
        if token.case_insensitive {
            "ignored"
        } else {
            "exact"
        }
        .to_owned(),
    ]
}

/// The list of the honeytokens of a configuration, in the order they are
/// defined: a table with a line for each, and a line that counts them.
///
/// No value is in it, and nothing made from one.
#[must_use]
pub fn list(config: &Config) -> String {
    if config.tokens.is_empty() {
        return "The configuration has no honeytokens.\n".to_owned();
    }
    let rows: Vec<[String; 8]> = config.tokens.iter().map(cells).collect();

    let mut widths = HEADINGS.map(|heading| heading.chars().count());
    for row in &rows {
        for (width, cell) in widths.iter_mut().zip(row) {
            *width = (*width).max(cell.chars().count());
        }
    }

    let mut out = String::new();
    let mut line = |cells: &[&str]| {
        let mut text = String::new();
        for (cell, width) in cells.iter().zip(widths) {
            // Two spaces between columns. Writing to a string cannot fail.
            let _ = write!(text, "{cell:<width$}  ");
        }
        out.push_str(text.trim_end());
        out.push('\n');
    };
    line(&HEADINGS);
    for row in &rows {
        let cells: Vec<&str> = row.iter().map(String::as_str).collect();
        line(&cells);
    }

    let values: usize = config.tokens.iter().map(|token| token.values.len()).sum();
    let plural = |count: usize, word: &str| {
        if count == 1 {
            format!("1 {word}")
        } else {
            format!("{count} {word}s")
        }
    };
    let _ = writeln!(
        out,
        "\n{}, {}. Values are never shown.",
        plural(config.tokens.len(), "honeytoken"),
        plural(values, "value")
    );
    out
}

/// Runs the command and returns its exit status.
#[must_use]
pub fn run(args: &Args) -> u8 {
    // Before the first secret is read: the token files hold some.
    disable_core_dumps();
    let loaded = match load_for("token list", &args.config) {
        Ok(loaded) => loaded,
        Err(status) => return status,
    };
    let listing = list(&loaded.config);
    let mut stdout = std::io::stdout().lock();
    match stdout
        .write_all(listing.as_bytes())
        .and_then(|()| stdout.flush())
    {
        Ok(()) => SUCCESS,
        Err(error) => {
            eprintln!(
                "pgsnare token list: the output could not be written: {}",
                error.kind()
            );
            FAILURE
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const HEAD: &str = "\
listeners:
  - name: main
    listen: 0.0.0.0:5432
    upstream: db.example.com:5432
    client_tls: { mode: disable }
    upstream_tls: { mode: verify-full }
events:
  sinks:
    - type: stdout
";

    fn listing(tokens: &str) -> String {
        list(&Config::from_yaml(&format!("{HEAD}{tokens}")).unwrap())
    }

    #[test]
    fn a_configuration_without_tokens_says_so() {
        assert_eq!(listing(""), "The configuration has no honeytokens.\n");
        assert_eq!(
            listing("tokens: []\n"),
            "The configuration has no honeytokens.\n"
        );
    }

    #[test]
    fn every_token_has_a_line_in_the_order_of_the_configuration() {
        let text = listing(
            "\
tokens:
  - id: users-admin-backup
    values: [\"svc.backup.aaaaaaaaaaaa\"]
    scope: { database: app, table: public.users, column: email }
    actions: [alert, kill]
    escalate: { after_hits: 3, to: [kill] }
  - id: a
    values: [\"first-value-0001\", \"first-value-0002\", \"first-value-0003\"]
    case_insensitive: true
    actions: [fake_data, tarpit, alert]
    escalate: { after_hits: 1, to: [kill, alert] }
",
        );
        assert_eq!(
            text,
            "\
ID                  DATABASE  TABLE         COLUMN  RESPONSE                  ESCALATION               VALUES  LETTER CASE
users-admin-backup  app       public.users  email   alert, kill               kill after 3 hits        1       exact
a                   -         -             -       alert, tarpit, fake_data  alert, kill after 1 hit  3       ignored

2 honeytokens, 4 values. Values are never shown.
"
        );
    }

    #[test]
    fn one_token_with_one_value_is_counted_in_the_singular() {
        let text = listing("tokens:\n  - id: t\n    values: [\"first-value-0001\"]\n");
        assert!(
            text.ends_with("\n1 honeytoken, 1 value. Values are never shown.\n"),
            "{text}"
        );
        // The default response is to alert.
        assert!(
            text.contains("\nt   -         -      -       alert     -           1       exact\n"),
            "{text}"
        );
    }

    #[test]
    fn no_value_and_nothing_made_from_one_is_in_the_list() {
        let values = [
            "svc.backup.aaaaaaaaaaaa",
            "9911111111111112",
            "ABCD-EFGH-IJKL-MNOP",
            "a-value-that-is-exactly-forty-bytes-long",
        ];
        let text = listing(&format!(
            "tokens:\n  - id: one\n    values: [\"{}\", \"{}\"]\n  - id: two\n    values: [\"{}\", \"{}\"]\n",
            values[0], values[1], values[2], values[3]
        ));
        for value in values {
            assert!(!text.contains(value), "{text}");
            // No part of a value either: not its beginning, not its end.
            assert!(!text.contains(&value[..6]), "{text}");
            assert!(!text.contains(&value[value.len() - 6..]), "{text}");
            // And not its length.
            assert!(!text.contains(&value.len().to_string()), "{text}");
        }
        assert!(text.contains("\n2 honeytokens, 4 values. "), "{text}");
    }

    #[test]
    fn text_of_the_scope_cannot_break_the_table() {
        // The loader refuses control characters in a scope. What it lets
        // through and a terminal would act on is written as a code point.
        assert_eq!(shown("public.users"), "public.users");
        assert_eq!(shown("caf\u{e9} \u{8868}"), "caf\u{e9} \u{8868}");
        assert_eq!(shown("a\u{202e}b"), "a\\u{202e}b");
        assert_eq!(shown("a\u{200b}b"), "a\\u{200b}b");
        assert_eq!(shown("a\u{2028}b"), "a\\u{2028}b");
        assert_eq!(shown("a\nb\u{1b}[2J"), "a\\u{a}b\\u{1b}[2J");
        assert_eq!(shown("a\\u{202e}b"), "a\\\\u{202e}b");

        let text = listing(
            "tokens:\n  - id: t\n    values: [\"first-value-0001\"]\n    scope: { table: \"a\\u202Eb\" }\n",
        );
        assert!(text.contains("a\\u{202e}b"), "{text}");
        assert!(!text.contains('\u{202e}'), "{text}");
    }

    #[test]
    fn a_wide_cell_widens_its_column_and_no_line_ends_with_a_space() {
        let text = listing(&format!(
            "tokens:\n  - id: {}\n    values: [\"first-value-0001\"]\n  - id: b\n    values: [\"first-value-0002\"]\n    scope: {{ column: \"{}\" }}\n",
            "i".repeat(64),
            "c".repeat(40)
        ));
        let lines: Vec<&str> = text.lines().collect();
        assert!(
            lines[0].starts_with(&format!("ID{}  DATABASE", " ".repeat(62))),
            "{text}"
        );
        assert!(lines.iter().all(|line| !line.ends_with(' ')), "{text}");
        // Every line of the table has its columns at the same places.
        let column = lines[0].find("VALUES").unwrap();
        assert_eq!(&lines[1][column..column + 1], "1");
        assert_eq!(&lines[2][column..column + 1], "1");
    }
}
