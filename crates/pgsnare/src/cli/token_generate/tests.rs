// SPDX-License-Identifier: Apache-2.0

//! Tests of the parts of `token generate`: names, quoting and the source
//! of randomness. What the command prints as a whole is compared with
//! expected output in `tests/cli`.

use std::collections::HashSet;

use proptest::prelude::*;

use super::*;
use crate::config::TokenFile;

fn parts(text: &str) -> Result<Vec<String>, NameProblem> {
    parse_name(text, 3)
}

fn identifier(name: &str) -> String {
    let mut out = String::new();
    push_identifier(&mut out, name);
    out
}

fn literal(text: &str) -> Result<String, Error> {
    let mut out = String::new();
    push_literal(&mut out, text).map(|()| out)
}

fn yaml(text: &str) -> String {
    let mut out = String::new();
    push_yaml_text(&mut out, text);
    out
}

/// Reads a quoted identifier the way PostgreSQL does, and returns the name
/// it stands for. Written from the rules in the PostgreSQL documentation,
/// section 4.1.1, and not from the code under test.
fn read_identifier(sql: &str) -> Option<String> {
    let (unicode, body) = match sql.strip_prefix("U&\"") {
        Some(body) => (true, body),
        None => (false, sql.strip_prefix('"')?),
    };
    let body = body.strip_suffix('"')?;
    let mut name = String::new();
    let mut characters = body.chars().peekable();
    while let Some(character) = characters.next() {
        match character {
            // A double quote must be followed by a second one.
            '"' => {
                if characters.next() != Some('"') {
                    return None;
                }
                name.push('"');
            }
            '\\' if unicode => {
                let digits = match characters.peek() {
                    Some('\\') => {
                        characters.next();
                        name.push('\\');
                        continue;
                    }
                    Some('+') => {
                        characters.next();
                        6
                    }
                    _ => 4,
                };
                let hex: String = characters.by_ref().take(digits).collect();
                if hex.len() != digits || !hex.bytes().all(|byte| byte.is_ascii_hexdigit()) {
                    return None;
                }
                name.push(char::from_u32(u32::from_str_radix(&hex, 16).ok()?)?);
            }
            other => name.push(other),
        }
    }
    Some(name)
}

/// Reads a string constant the way PostgreSQL does. `conforming` is the
/// setting `standard_conforming_strings`.
fn read_literal(sql: &str, conforming: bool) -> Option<String> {
    let (escapes, body) = match sql.strip_prefix("E'") {
        Some(body) => (true, body),
        None => (!conforming, sql.strip_prefix('\'')?),
    };
    let body = body.strip_suffix('\'')?;
    let mut text = String::new();
    let mut characters = body.chars();
    while let Some(character) = characters.next() {
        match character {
            '\'' => {
                if characters.next() != Some('\'') {
                    return None;
                }
                text.push('\'');
            }
            // The only escape the code under test may write is a doubled
            // backslash. Any other would change the text.
            '\\' if escapes => {
                if characters.next() != Some('\\') {
                    return None;
                }
                text.push('\\');
            }
            other => text.push(other),
        }
    }
    Some(text)
}

// --- Names -------------------------------------------------------------------

#[test]
fn a_name_is_parts_between_dots() {
    assert_eq!(parts("users"), Ok(vec!["users".to_owned()]));
    assert_eq!(
        parts("public.users"),
        Ok(vec!["public".to_owned(), "users".to_owned()])
    );
    assert_eq!(
        parts("app.public.users"),
        Ok(vec![
            "app".to_owned(),
            "public".to_owned(),
            "users".to_owned()
        ])
    );
    // A part is taken as written: no folding of case, and spaces count.
    assert_eq!(
        parts("Shop.Customer Logins"),
        Ok(vec!["Shop".to_owned(), "Customer Logins".to_owned()])
    );
    assert_eq!(parts(" users "), Ok(vec![" users ".to_owned()]));
    assert_eq!(
        parts("caf\u{e9}.\u{4e2d}\u{6587}"),
        Ok(vec!["caf\u{e9}".to_owned(), "\u{4e2d}\u{6587}".to_owned()])
    );
}

#[test]
fn a_quoted_part_may_contain_dots_and_quotes() {
    assert_eq!(
        parts("\"my.schema\".users"),
        Ok(vec!["my.schema".to_owned(), "users".to_owned()])
    );
    assert_eq!(parts("\"users\""), Ok(vec!["users".to_owned()]));
    assert_eq!(
        parts("\"a\"\"b\".\"c.d\""),
        Ok(vec!["a\"b".to_owned(), "c.d".to_owned()])
    );
    // Four double quotes are one part that is a single double quote.
    assert_eq!(parts("\"\"\"\""), Ok(vec!["\"".to_owned()]));
}

#[test]
fn a_name_that_cannot_be_taken_apart_is_refused() {
    for (text, problem) in [
        ("", NameProblem::Empty),
        (".", NameProblem::Empty),
        ("users.", NameProblem::Empty),
        (".users", NameProblem::Empty),
        ("public..users", NameProblem::Empty),
        ("\"\"", NameProblem::Empty),
        ("\"\".users", NameProblem::Empty),
        ("public.\"\"", NameProblem::Empty),
        ("us\"ers", NameProblem::StrayQuote),
        ("users\"", NameProblem::StrayQuote),
        ("public.us\"ers\"", NameProblem::StrayQuote),
        ("\"users", NameProblem::UnterminatedQuote),
        ("public.\"users", NameProblem::UnterminatedQuote),
        ("\"users\"\"", NameProblem::UnterminatedQuote),
        ("\"users\"x", NameProblem::TextAfterQuote),
        ("\"public\"\"users\"x.y", NameProblem::TextAfterQuote),
        ("\"a\" .b", NameProblem::TextAfterQuote),
        ("a.b.c.d", NameProblem::TooManyParts),
        ("\"a\".\"b\".\"c\".\"d\"", NameProblem::TooManyParts),
    ] {
        assert_eq!(parts(text), Err(problem), "{text:?}");
    }
    // A column has one part.
    assert_eq!(parse_name("users.email", 1), Err(NameProblem::TooManyParts));
    assert_eq!(
        parse_name("\"users.email\"", 1),
        Ok(vec!["users.email".to_owned()])
    );
}

#[test]
fn a_name_with_a_control_character_is_refused() {
    for text in [
        "users\0",
        "\0",
        "us\0ers",
        "users\n",
        "users\r\n; DROP TABLE users",
        "users\t",
        "users\u{1b}[2J",
        "users\u{7f}",
        "users\u{85}",
        "\"users\0\"",
        "\"users\n\"",
    ] {
        assert_eq!(parts(text), Err(NameProblem::ControlCharacter), "{text:?}");
    }
}

#[test]
fn a_name_has_a_longest_length() {
    assert!(parts(&"n".repeat(MAX_NAME_BYTES)).is_ok());
    assert_eq!(
        parts(&"n".repeat(MAX_NAME_BYTES + 1)),
        Err(NameProblem::TooLong)
    );
    // The length is counted in bytes, as the configuration counts it.
    assert_eq!(parts(&"\u{e9}".repeat(129)), Err(NameProblem::TooLong));
    assert!(parts(&"\u{e9}".repeat(128)).is_ok());
}

#[test]
fn no_problem_repeats_the_name() {
    for problem in [
        NameProblem::Empty,
        NameProblem::TooLong,
        NameProblem::ControlCharacter,
        NameProblem::StrayQuote,
        NameProblem::UnterminatedQuote,
        NameProblem::TextAfterQuote,
        NameProblem::TooManyParts,
    ] {
        let message = Error::Name {
            option: "--table",
            problem,
        }
        .to_string();
        assert!(message.starts_with("--table: "), "{message}");
        assert!(message.is_ascii(), "{message}");
    }
}

// --- Identifiers -------------------------------------------------------------

#[test]
fn an_identifier_is_written_between_double_quotes() {
    assert_eq!(identifier("users"), "\"users\"");
    assert_eq!(identifier("Customer Logins"), "\"Customer Logins\"");
    assert_eq!(identifier("my.schema"), "\"my.schema\"");
    // A reserved word is a name like any other once it is quoted.
    assert_eq!(identifier("select"), "\"select\"");
}

#[test]
fn a_double_quote_in_an_identifier_is_doubled() {
    assert_eq!(identifier("a\"b"), "\"a\"\"b\"");
    assert_eq!(identifier("\""), "\"\"\"\"");
    assert_eq!(
        identifier("users\"; DROP TABLE users; --"),
        "\"users\"\"; DROP TABLE users; --\""
    );
    // A backslash means nothing in the plain form and stays single.
    assert_eq!(identifier("a\\b"), "\"a\\b\"");
    assert_eq!(identifier("a'b"), "\"a'b\"");
}

#[test]
fn an_identifier_outside_ascii_is_written_with_code_points() {
    assert_eq!(identifier("caf\u{e9}"), "U&\"caf\\00E9\"");
    assert_eq!(identifier("\u{4e2d}\u{6587}"), "U&\"\\4E2D\\6587\"");
    // Above the first 65536 code points, the long form.
    assert_eq!(identifier("\u{1f600}"), "U&\"\\+01F600\"");
    // In this form the backslash is the escape character, so a backslash
    // of the name is written twice, and a quote still is.
    assert_eq!(identifier("\u{e9}\\\""), "U&\"\\00E9\\\\\"\"\"");
    // Characters that cannot be seen are written out as well.
    assert_eq!(identifier("a\u{200b}b"), "U&\"a\\200Bb\"");
    assert_eq!(identifier("a\u{202e}b"), "U&\"a\\202Eb\"");
}

#[test]
fn a_hostile_identifier_stays_one_identifier() {
    for name in [
        "users\"; DROP TABLE users; --",
        "\"; DROP TABLE users; --",
        "users\"\"",
        "x\" /* ",
        "x */ \"",
        "'); DROP TABLE users; --",
        "\\\"; DROP TABLE users; --",
        "\u{c1}\"; \\! touch pwned",
        "U&\"x\"",
        "x\" UESCAPE '!",
        "\\0022; DROP TABLE users",
        "\u{e9}\\0022; DROP TABLE users",
        "\u{e9}\\+000022",
        "$$; DROP TABLE users; $$",
    ] {
        let sql = identifier(name);
        assert!(sql.is_ascii(), "{sql}");
        assert_eq!(read_identifier(&sql).as_deref(), Some(name), "{sql}");
    }
}

#[test]
fn the_reader_of_the_tests_refuses_what_postgresql_refuses() {
    // If it accepted anything, it could show nothing.
    assert_eq!(read_identifier("\"a\"\"b\"").as_deref(), Some("a\"b"));
    assert_eq!(read_identifier("\"a\"b\""), None);
    assert_eq!(read_identifier("\"a"), None);
    assert_eq!(read_identifier("a\""), None);
    assert_eq!(read_identifier("U&\"\\00E9\"").as_deref(), Some("\u{e9}"));
    assert_eq!(read_identifier("U&\"\\00E\""), None);
    assert_eq!(read_identifier("U&\"\\+00E9\""), None);
    assert_eq!(read_identifier("U&\"\\D800\""), None);
    // In the plain form a backslash is a backslash.
    assert_eq!(read_identifier("\"\\00E9\"").as_deref(), Some("\\00E9"));

    assert_eq!(read_literal("'a''b'", true).as_deref(), Some("a'b"));
    assert_eq!(read_literal("'a'b'", true), None);
    assert_eq!(read_literal("'a\\b'", true).as_deref(), Some("a\\b"));
    // With the old setting, a lone backslash in a plain constant is an
    // escape, and the text changes.
    assert_eq!(read_literal("'a\\b'", false), None);
    assert_eq!(read_literal("E'a\\\\b'", false).as_deref(), Some("a\\b"));
    assert_eq!(read_literal("E'a\\\\b'", true).as_deref(), Some("a\\b"));
}

// --- String constants --------------------------------------------------------

#[test]
fn a_value_is_written_between_single_quotes() {
    assert_eq!(
        literal("svc.backup.aaaaaaaaaaaa").unwrap(),
        "'svc.backup.aaaaaaaaaaaa'"
    );
    assert_eq!(literal("").unwrap(), "''");
    assert_eq!(literal("a'b").unwrap(), "'a''b'");
    assert_eq!(literal("'").unwrap(), "''''");
    assert_eq!(
        literal("'); DROP TABLE users; --").unwrap(),
        "'''); DROP TABLE users; --'"
    );
    assert_eq!(literal("a\"b").unwrap(), "'a\"b'");
}

#[test]
fn a_value_with_a_backslash_is_written_in_the_escape_form() {
    assert_eq!(literal("a\\b").unwrap(), "E'a\\\\b'");
    assert_eq!(literal("\\").unwrap(), "E'\\\\'");
    // The attack on the old setting: a backslash that would swallow the
    // closing quote.
    assert_eq!(
        literal("\\'; DROP TABLE users; --").unwrap(),
        "E'\\\\''; DROP TABLE users; --'"
    );
}

#[test]
fn a_hostile_value_reads_back_unchanged_under_both_settings() {
    for text in [
        "'); DROP TABLE users; --",
        "\\'; DROP TABLE users; --",
        "\\\\'",
        "a\\",
        "''",
        "\\''\\",
        "$$",
        "E'x'",
        "/* */ --",
    ] {
        let sql = literal(text).unwrap();
        for conforming in [true, false] {
            assert_eq!(
                read_literal(&sql, conforming).as_deref(),
                Some(text),
                "{sql}"
            );
        }
    }
}

#[test]
fn a_value_that_is_not_printable_ascii_is_refused() {
    for text in ["a\0b", "a\nb", "a\tb", "caf\u{e9}", "a\u{7f}b"] {
        assert_eq!(literal(text), Err(Error::Defect), "{text:?}");
    }
}

// --- Text in the token file --------------------------------------------------

#[test]
fn text_in_the_token_file_is_a_double_quoted_scalar_in_ascii() {
    assert_eq!(yaml("public.users"), "\"public.users\"");
    assert_eq!(yaml("a\"b"), "\"a\\\"b\"");
    assert_eq!(yaml("a\\b"), "\"a\\\\b\"");
    assert_eq!(yaml("caf\u{e9}"), "\"caf\\xE9\"");
    assert_eq!(yaml("\u{4e2d}"), "\"\\u4E2D\"");
    assert_eq!(yaml("\u{1f600}"), "\"\\U0001F600\"");
    // Text that would be a number, a boolean or nothing at all without the
    // quotes.
    assert_eq!(yaml("123"), "\"123\"");
    assert_eq!(yaml("true"), "\"true\"");
    assert_eq!(yaml(""), "\"\"");
}

#[test]
fn text_in_the_token_file_cannot_end_the_comment_around_it() {
    for text in ["*/", "/*", "a */ DROP TABLE users; /* b", "***", "*"] {
        let written = yaml(text);
        assert!(!written.contains('*'), "{written}");
    }
    assert_eq!(yaml("a*/b"), "\"a\\x2A/b\"");
}

/// The scope of the token that a token file with this text as its table
/// gives, read by the loader of the configuration.
fn table_read_back(text: &str) -> Result<Option<String>, String> {
    let document = format!(
        "tokens:\n  - id: \"t\"\n    values: [\"0123456789ab\"]\n    scope: {{ table: {}, column: \"c\" }}\n",
        yaml(text)
    );
    TokenFile::from_yaml(&document)
        .map(|file| file.tokens[0].scope.table.clone())
        .map_err(|error| error.to_string())
}

#[test]
fn the_loader_reads_the_text_back_unchanged() {
    for text in [
        "public.users",
        "a\"b",
        "a\\b",
        "a*/b",
        "/* x */",
        "caf\u{e9}",
        "\u{4e2d}\u{6587}.\u{8868}",
        "\u{1f600}",
        "a\u{202e}b",
        "{ table: x }",
        "# not a comment",
        "a: b",
        "'single'",
        "%TAG",
        "- item",
        "x\\n",
        "\\x41",
    ] {
        assert_eq!(table_read_back(text), Ok(Some(text.to_owned())), "{text:?}");
    }
}

proptest! {
    #![proptest_config(ProptestConfig::with_cases(1500))]

    /// Whatever the name, the identifier is ASCII and PostgreSQL reads it
    /// back as exactly that name.
    #[test]
    fn any_identifier_reads_back_unchanged(name in "\\PC{1,40}") {
        let sql = identifier(&name);
        prop_assert!(sql.is_ascii());
        prop_assert!(sql.bytes().all(|byte| (b' '..=b'~').contains(&byte)));
        let read = read_identifier(&sql);
        prop_assert_eq!(read.as_deref(), Some(name.as_str()));
    }

    /// Whatever the printable ASCII text, the constant reads back as that
    /// text under both settings of `standard_conforming_strings`.
    #[test]
    fn any_value_reads_back_unchanged(text in "[ -~]{0,60}") {
        let sql = literal(&text).unwrap();
        let conforming = read_literal(&sql, true);
        prop_assert_eq!(conforming.as_deref(), Some(text.as_str()));
        let old = read_literal(&sql, false);
        prop_assert_eq!(old.as_deref(), Some(text.as_str()));
    }

    /// Whatever the name, the loader reads the scope back unchanged, and
    /// the text written has no `*` and nothing outside ASCII.
    #[test]
    fn any_scope_reads_back_unchanged(text in "\\PC{1,40}") {
        let written = yaml(&text);
        prop_assert!(written.bytes().all(|byte| (b' '..=b'~').contains(&byte)));
        prop_assert!(!written.contains('*'));
        prop_assert_eq!(table_read_back(&text), Ok(Some(text)));
    }

    /// Any text is taken apart into names, or refused. What it is taken
    /// apart into has no control character and no empty part.
    #[test]
    fn any_name_is_taken_apart_or_refused(text in "(\\PC|[\"\\.]|\\x00|\\n){0,30}") {
        match parse_name(&text, 3) {
            Ok(names) => {
                prop_assert!((1..=3).contains(&names.len()));
                for name in &names {
                    prop_assert!(!name.is_empty());
                    prop_assert!(!name.chars().any(char::is_control));
                }
                // Written out again in quotes, it is taken apart the same.
                let quoted: Vec<String> = names
                    .iter()
                    .map(|name| format!("\"{}\"", name.replace('"', "\"\"")))
                    .collect();
                let rejoined = quoted.join(".");
                if rejoined.len() <= MAX_NAME_BYTES {
                    prop_assert_eq!(parse_name(&rejoined, 3), Ok(names));
                }
            }
            Err(problem) => prop_assert!(!problem.to_string().is_empty()),
        }
    }
}

// --- The source of randomness ------------------------------------------------

#[test]
fn the_operating_system_gives_different_bytes_every_time() {
    let mut entropy = OsEntropy::new().unwrap();
    let mut seen = HashSet::new();
    for _ in 0..200 {
        let mut bytes = [0u8; 16];
        entropy.fill(&mut bytes).unwrap();
        assert!(seen.insert(bytes));
    }
    // A buffer above the size of one call is filled to the end: with 4096
    // random bytes, the last 256 are not all zero.
    let mut large = [0u8; 4096];
    entropy.fill(&mut large).unwrap();
    assert!(large[4096 - 256..].iter().any(|byte| *byte != 0));
    assert!(large[..256].iter().any(|byte| *byte != 0));
    entropy.fill(&mut []).unwrap();
}

// --- Ids ---------------------------------------------------------------------

#[test]
fn one_token_takes_the_id_and_several_take_a_number_each() {
    assert_eq!(ids("users-admin", 1), Ok(vec!["users-admin".to_owned()]));
    assert_eq!(
        ids("users-admin", 3),
        Ok(vec![
            "users-admin-1".to_owned(),
            "users-admin-2".to_owned(),
            "users-admin-3".to_owned()
        ])
    );
    // An id of 64 bytes leaves no room for a number.
    let longest = "i".repeat(64);
    assert_eq!(ids(&longest, 1), Ok(vec![longest.clone()]));
    assert_eq!(ids(&longest, 2), Err(Error::Id));
    assert_eq!(ids(&"i".repeat(62), 9).map(|ids| ids.len()), Ok(9));
    assert_eq!(ids(&"i".repeat(62), 10), Err(Error::Id));
    assert_eq!(ids("not an id", 1), Err(Error::Id));
}
