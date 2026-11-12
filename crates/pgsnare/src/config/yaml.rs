// SPDX-License-Identifier: Apache-2.0

//! Reading YAML into the schema, strictly, and reporting what went wrong
//! without repeating the document.

use std::borrow::Cow;

use serde::de::DeserializeOwned;
use serde_saphyr::budget::BudgetBreach;
use serde_saphyr::{DuplicateKeyPolicy, Error, MergeKeyPolicy};

use super::error::{Problem, Reason};

/// The deepest nesting a document may have. The schema needs six levels.
/// It is not recursive, so deeper nesting is a type error long before this
/// limit: the limit is a second line of defence.
const MAX_DEPTH: usize = 16;

/// How the YAML is read.
///
/// The settings are chosen so that a file means one thing only, and means
/// the same to pgsnare as to any other YAML tool that touches it:
///
/// - exactly one document
/// - a key may appear once in a mapping
/// - no anchors, aliases or merge keys, so nothing is defined in one place
///   and used in another
/// - no tags other than the standard ones
/// - only `true` and `false` are booleans
/// - text that looks like a number or a boolean must be quoted to be read
///   as text
///
/// Error messages carry no excerpt of the source.
fn options() -> serde_saphyr::Options {
    serde_saphyr::options! {
        budget: serde_saphyr::budget! {
            max_documents: 1,
            max_depth: MAX_DEPTH,
            max_aliases: 0,
            max_anchors: 0,
            max_merge_keys: 0,
            max_inclusion_depth: 0,
        },
        duplicate_keys: DuplicateKeyPolicy::Error,
        merge_keys: MergeKeyPolicy::Error,
        strict_booleans: true,
        no_schema: true,
        reject_unsupported_tags: true,
        reject_tagged_field_names: true,
        with_snippet: false,
    }
}

/// Reads one YAML document into `T`.
pub(super) fn from_str<T: DeserializeOwned>(text: &str) -> Result<T, Problem> {
    serde_saphyr::from_str_with_options(text, options()).map_err(|error| problem(&error))
}

/// Turns the library's error into a [`Problem`].
///
/// Only fixed text, numbers and the schema's own field names are taken from
/// the error. Everything the library copied from the document, such as an
/// unexpected value or an unknown key, is left behind.
fn problem(error: &Error) -> Problem {
    let location = error.location();
    let line = location.map(|at| at.line()).filter(|line| *line > 0);
    let column = location.map(|at| at.column()).filter(|column| *column > 0);
    Problem::at_position(line, column, message(innermost(error)))
}

/// Strips the wrappers that add context around the actual error.
fn innermost(mut error: &Error) -> &Error {
    loop {
        match error {
            Error::WithSnippet { error: inner, .. } | Error::AliasError { error: inner, .. } => {
                error = inner;
            }
            _ => return error,
        }
    }
}

fn message(error: &Error) -> String {
    match error {
        Error::SerdeUnknownField { expected, .. } if expected.is_empty() => {
            "unknown field; no field is expected here".to_owned()
        }
        Error::SerdeUnknownField { expected, .. } => {
            format!("unknown field; the fields here are: {}", list(expected))
        }
        Error::SerdeMissingField { field, .. } => format!("missing field `{field}`"),
        Error::SerdeInvalidType {
            unexpected,
            expected,
            ..
        } => format!(
            "expected {}, found {}",
            describe_expected(expected),
            describe_found(unexpected)
        ),
        Error::SerdeInvalidValue { expected, .. } => {
            format!("expected {}", describe_expected(expected))
        }
        Error::SerdeInvalidLength { len, expected, .. } => {
            format!("expected {}, found {len}", describe_expected(expected))
        }
        Error::SerdeUnknownVariant { expected, .. } => {
            format!("unknown value; expected one of: {}", list(expected))
        }
        Error::InvalidScalar { ty, .. } => format!("expected {}", describe_expected(ty)),
        Error::Unexpected { expected, .. } => match *expected {
            "sequence start" => "expected a list".to_owned(),
            "mapping start" => "expected a mapping".to_owned(),
            "string scalar" => "expected a single value, found a list or a mapping".to_owned(),
            _ => "this is not what the schema expects here".to_owned(),
        },
        Error::UnsupportedTag { .. }
        | Error::TaggedStructFieldName { .. }
        | Error::TaggedScalarCannotDeserializeIntoString { .. } => {
            "YAML tags are not supported".to_owned()
        }
        Error::InvalidBooleanStrict { .. } => "expected true or false".to_owned(),
        Error::NullIntoString { .. } => {
            "expected text, found nothing; write \"\" for empty text".to_owned()
        }
        Error::QuotingRequired { .. } => "this value must be quoted to be read as text".to_owned(),
        Error::DuplicateMappingKey { .. } => {
            "this key appears more than once in the same mapping".to_owned()
        }
        Error::MultipleDocuments { .. } => "a file must hold exactly one YAML document".to_owned(),
        Error::MergeKeyNotAllowed { .. } => "YAML merge keys are not supported".to_owned(),
        Error::UnknownAnchor { .. } => "YAML anchors and aliases are not supported".to_owned(),
        Error::Eof { .. } => "the document is empty or ends too early".to_owned(),
        Error::Budget { breach, .. } => budget_message(breach).to_owned(),
        Error::Message { msg, .. } => match Reason::recognise(msg) {
            Some(known) => known.to_owned(),
            None => "this value is not valid here".to_owned(),
        },
        Error::ExternalMessage { .. } => "this is not valid YAML".to_owned(),
        _ => "this is not valid YAML, or not what the schema expects here".to_owned(),
    }
}

fn budget_message(breach: &BudgetBreach) -> &'static str {
    match breach {
        BudgetBreach::Aliases { .. } | BudgetBreach::Anchors { .. } => {
            "YAML anchors and aliases are not supported"
        }
        BudgetBreach::MergeKeys { .. } => "YAML merge keys are not supported",
        BudgetBreach::Documents { .. } => "a file must hold exactly one YAML document",
        BudgetBreach::Depth { .. } => "the document is nested too deeply",
        _ => "the document is too large or too complex",
    }
}

/// Field or value names of the schema, as a list for a message.
fn list(names: &[&'static str]) -> String {
    let mut out = String::new();
    for (index, name) in names.iter().enumerate() {
        if index > 0 {
            out.push_str(", ");
        }
        out.push('`');
        out.push_str(name);
        out.push('`');
    }
    out
}

/// What a type of the schema expects, in the words of a YAML author.
///
/// The text comes from the `expecting` method of a visitor, which is fixed
/// text of this crate or of serde. It never holds text from the document.
fn describe_expected(expected: &str) -> Cow<'_, str> {
    if expected.starts_with("struct ") || expected == "a map" {
        return Cow::Borrowed("a mapping");
    }
    if expected.starts_with("internally tagged enum ") {
        return Cow::Borrowed("a mapping with a `type`");
    }
    match expected {
        "a sequence" => Cow::Borrowed("a list"),
        "path string" => Cow::Borrowed("a file path"),
        "u8" | "u16" | "u32" | "u64" | "usize" => {
            Cow::Borrowed("a whole number that is not negative")
        }
        "bool" | "a boolean" => Cow::Borrowed("true or false"),
        "a string" => Cow::Borrowed("text"),
        _ => Cow::Borrowed(expected),
    }
}

/// The kind of thing that was found instead, without the thing itself.
///
/// serde describes what it found as a kind followed by the value, such as
/// `string "..."`. Only the kind is used.
fn describe_found(unexpected: &str) -> &'static str {
    const KINDS: [(&str, &str); 9] = [
        ("boolean", "true or false"),
        ("integer", "a number"),
        ("floating point", "a number"),
        ("character", "text"),
        ("string", "text"),
        ("sequence", "a list"),
        ("map", "a mapping"),
        ("unit value", "nothing"),
        ("Option value", "nothing"),
    ];
    KINDS
        .iter()
        .find(|(kind, _)| unexpected.starts_with(kind))
        .map_or("something else", |(_, description)| description)
}

#[cfg(test)]
mod tests {
    use serde::Deserialize;

    use super::*;

    #[derive(Debug, Deserialize, PartialEq)]
    #[serde(deny_unknown_fields)]
    struct Sample {
        name: String,
        #[serde(default)]
        port: u16,
        #[serde(default)]
        enabled: bool,
        #[serde(default)]
        mode: Mode,
        #[serde(default)]
        tags: Vec<String>,
    }

    #[derive(Debug, Default, Deserialize, PartialEq)]
    #[serde(rename_all = "snake_case")]
    enum Mode {
        #[default]
        Fast,
        Slow,
    }

    fn read(text: &str) -> Result<Sample, String> {
        from_str::<Sample>(text).map_err(|problem| problem.to_string())
    }

    #[test]
    fn a_well_formed_document_is_read() {
        let sample =
            read("name: main\nport: 5432\nenabled: true\nmode: slow\ntags: [a, b]\n").unwrap();
        assert_eq!(
            sample,
            Sample {
                name: "main".to_owned(),
                port: 5432,
                enabled: true,
                mode: Mode::Slow,
                tags: vec!["a".to_owned(), "b".to_owned()],
            }
        );
    }

    #[test]
    fn schema_errors_name_the_place_and_the_expectation() {
        assert_eq!(
            read("name: main\nprot: 5432\n").unwrap_err(),
            "line 2, column 1: unknown field; the fields here are: `name`, `port`, `enabled`, `mode`, `tags`"
        );
        assert_eq!(
            read("port: 1\n").unwrap_err(),
            "line 1, column 1: missing field `name`"
        );
        assert_eq!(
            read("name: main\nmode: medium\n").unwrap_err(),
            "line 2, column 7: unknown value; expected one of: `fast`, `slow`"
        );
        assert_eq!(
            read("name: main\ntags: nope\n").unwrap_err(),
            "line 2, column 7: expected a list"
        );
        assert_eq!(
            read("name: [main]\n").unwrap_err(),
            "line 1, column 7: expected a single value, found a list or a mapping"
        );
        assert_eq!(
            read("- main\n").unwrap_err(),
            "line 1, column 1: expected a mapping"
        );
        assert_eq!(
            read("name: main\nport: 70000\n").unwrap_err(),
            "line 2, column 7: expected a whole number that is not negative"
        );
    }

    #[test]
    fn text_that_looks_like_something_else_must_be_quoted() {
        assert_eq!(read("name: \"5432\"\n").unwrap().name, "5432");
        assert_eq!(read("name: 'true'\n").unwrap().name, "true");
        for document in ["name: 5432\n", "name: true\n", "name: 1.5\n"] {
            assert_eq!(
                read(document).unwrap_err(),
                "line 1, column 7: this value must be quoted to be read as text",
                "{document}"
            );
        }
        let error = read("name:\n").unwrap_err();
        assert!(
            error.ends_with("expected text, found nothing; write \"\" for empty text"),
            "{error}"
        );
    }

    #[test]
    fn only_true_and_false_are_booleans() {
        assert!(read("name: a\nenabled: false\n").is_ok());
        for word in ["yes", "on", "y", "1"] {
            let error = read(&format!("name: a\nenabled: {word}\n")).unwrap_err();
            assert!(error.starts_with("line 2, column 10: "), "{word}: {error}");
        }
    }

    #[test]
    fn a_key_may_appear_once() {
        assert_eq!(
            read("name: a\nname: b\n").unwrap_err(),
            "line 2, column 1: this key appears more than once in the same mapping"
        );
    }

    #[test]
    fn one_document_per_file() {
        let error = read("name: a\n---\nname: b\n").unwrap_err();
        assert!(
            error.ends_with("a file must hold exactly one YAML document"),
            "{error}"
        );

        for empty in ["", "# only a comment\n", "---\n"] {
            let error = read(empty).unwrap_err();
            assert!(!error.is_empty(), "{empty:?}");
        }
        assert!(
            read("")
                .unwrap_err()
                .ends_with("the document is empty or ends too early")
        );
    }

    #[test]
    fn anchors_aliases_and_merge_keys_are_rejected() {
        let error = read("name: &n main\ntags: [*n]\n").unwrap_err();
        assert!(
            error.ends_with("YAML anchors and aliases are not supported"),
            "{error}"
        );

        let error = read("name: a\n<<: {port: 1}\n").unwrap_err();
        assert!(
            error.ends_with("YAML merge keys are not supported"),
            "{error}"
        );
    }

    #[test]
    fn tags_are_rejected() {
        let error = read("name: !custom main\n").unwrap_err();
        assert!(error.ends_with("YAML tags are not supported"), "{error}");
    }

    #[test]
    fn deep_nesting_is_rejected() {
        // Shallow nesting fails where it stops fitting the schema.
        assert_eq!(
            read("name: a\ntags: [[[x]]]\n").unwrap_err(),
            "line 2, column 8: expected a single value, found a list or a mapping"
        );
        // Very deep nesting is cut off by the parser's own limit, in flow
        // style and in block style, without exhausting the stack.
        let flow = format!(
            "name: a\ntags: {}x{}\n",
            "[".repeat(100_000),
            "]".repeat(100_000)
        );
        assert!(read(&flow).is_err());
        let mut block = String::from("name: a\ntags:\n");
        for level in 0..5_000 {
            block.push_str(&" ".repeat(level));
            block.push_str("- \n");
        }
        assert!(read(&block).is_err());
    }

    #[test]
    fn syntax_errors_are_reported_without_the_source() {
        for document in [
            "name: [a, b\n",
            "name: \"unterminated\n",
            "name: a\n  bad: indent\n",
            "\t- x\n",
        ] {
            let error = read(document).unwrap_err();
            assert!(!error.contains("unterminated"), "{error}");
            assert!(!error.contains("indent"), "{error}");
        }
    }

    #[test]
    fn nothing_from_the_document_is_repeated() {
        // The marker stands for a honeytoken value. It is placed wherever a
        // value, a key or broken syntax could carry it into an error.
        const MARKER: &str = "Zq7honeytokenValue9xK";
        let documents = [
            format!("name: main\n{MARKER}: 1\n"),           // an unknown key
            format!("{MARKER}\n"),                          // a bare scalar
            format!("- {MARKER}\n"),                        // a list instead of a mapping
            format!("name: [{MARKER}]\n"),                  // a list instead of text
            format!("name: {{a: {MARKER}}}\n"),             // a mapping instead of text
            format!("name: a\nport: {MARKER}\n"),           // text instead of a number
            format!("name: a\nenabled: {MARKER}\n"),        // text instead of a boolean
            format!("name: a\nmode: {MARKER}\n"),           // an unknown value
            format!("name: a\ntags: {MARKER}\n"),           // text instead of a list
            format!("name: a\ntags: [{{{MARKER}: 1}}]\n"),  // a mapping inside a list
            format!("name: a\nname: {MARKER}\n"),           // a repeated key
            format!("name: a\n{MARKER}: 1\n{MARKER}: 2\n"), // a repeated unknown key
            format!("name: \"{MARKER}\n"),                  // an unterminated quote
            format!("name: a\n  {MARKER}: [\n"),            // broken indentation
            format!("name: &{MARKER} a\n"),                 // an anchor
            format!("name: *{MARKER}\n"),                   // an alias to nothing
            format!("name: !{MARKER} a\n"),                 // a tag
            format!("!{MARKER}\nname: a\n"),                // a tag on the document
            format!("name: a\n---\nname: {MARKER}\n"),      // a second document
            format!("? {MARKER}\n: a\n"),                   // a complex key
            format!("name: a\nport: 99999999999{MARKER}\n"), // a number gone wrong
            format!("{MARKER}: {MARKER}\n"),
        ];
        for document in documents {
            let error = read(&document).unwrap_err();
            assert!(
                !error.contains(MARKER),
                "{document:?} leaked into {error:?}"
            );
            assert!(
                !error.to_lowercase().contains("honeytoken"),
                "{document:?} leaked into {error:?}"
            );
        }
    }
}
