// SPDX-License-Identifier: Apache-2.0

//! Token values are secrets. Nothing this module can print shows one.
//!
//! Each test formats a public type in every way a log line or an error
//! message could, and searches the result for the planted values: whole or
//! in part, in any letter case, and in hexadecimal.

use std::error::Error;
use std::fmt::Debug;

use pgsnare_core::detect::{BuildError, Matcher, TokenSpec, TokenValue, ValidationError};

/// The planted values. They share no fragment with any id, message or field
/// name that the module prints.
const PLANTED: &str = "Zebra.Quartz.0042.Violet";
const LONGER: &str = "xylo-Zebra.Quartz.0042.Violet-kumquat";
const SHORT: &str = "zebra-9";
const NOT_ASCII: &str = "z\u{e9}bra-quartz-0042";

/// The shortest fragment of a value that counts as a leak, in characters of
/// the value and in hexadecimal digits.
const FRAGMENT: usize = 5;
const HEX_FRAGMENT: usize = 8;

fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|byte| format!("{byte:02x}")).collect()
}

/// Fails if `output` contains a fragment of a planted value: as text in any
/// letter case, in hexadecimal, or as a list of byte values, which is how a
/// derived `Debug` prints bytes.
#[track_caller]
fn assert_no_value(output: &str) {
    let output = output.to_lowercase();
    let without_spaces: String = output.split_whitespace().collect();

    for value in [PLANTED, LONGER, SHORT, NOT_ASCII] {
        let spellings = [
            (value.to_lowercase(), FRAGMENT),
            (hex(value.as_bytes()), HEX_FRAGMENT),
            (hex(value.to_lowercase().as_bytes()), HEX_FRAGMENT),
            (hex(value.to_uppercase().as_bytes()), HEX_FRAGMENT),
        ];
        for (spelling, length) in spellings {
            let characters: Vec<char> = spelling.chars().collect();
            for window in characters.windows(length) {
                // A run of digits alone says nothing: counters and offsets
                // are full of them.
                if window.iter().all(char::is_ascii_digit) {
                    continue;
                }
                let fragment: String = window.iter().collect();
                assert!(
                    !output.contains(&fragment),
                    "found {fragment:?}, a part of a token value, in {output:?}"
                );
            }
        }

        for bytes in [
            value.as_bytes().to_vec(),
            value.to_lowercase().into_bytes(),
            value.to_uppercase().into_bytes(),
        ] {
            for window in bytes.windows(FRAGMENT) {
                let decimal: Vec<String> = window.iter().map(|byte| format!("{byte}")).collect();
                let hexadecimal: Vec<String> =
                    window.iter().map(|byte| format!("{byte:x}")).collect();
                for list in [decimal.join(","), hexadecimal.join(",")] {
                    assert!(
                        !without_spaces.contains(&list),
                        "found the bytes {list}, a part of a token value, in {output:?}"
                    );
                }
            }
        }
    }
}

/// Formats a value in every way `Debug` allows and checks each result.
#[track_caller]
fn assert_debug_is_clean(value: &impl Debug) {
    assert_no_value(&format!("{value:?}"));
    assert_no_value(&format!("{value:#?}"));
    assert_no_value(&format!("{value:x?}"));
    assert_no_value(&format!("{value:X?}"));
}

/// Formats an error as text and as debug output, follows its sources, and
/// checks each result.
#[track_caller]
fn assert_error_is_clean(error: &impl Error) {
    assert_no_value(&error.to_string());
    assert_no_value(&format!("{error:>80}"));
    assert_debug_is_clean(error);
    let mut source = error.source();
    while let Some(inner) = source {
        assert_no_value(&inner.to_string());
        assert_no_value(&format!("{inner:?}"));
        source = inner.source();
    }
}

fn tokens() -> Vec<TokenSpec> {
    vec![
        TokenSpec::new("token-a", [PLANTED]).case_insensitive(true),
        TokenSpec::new("token-b", ["another-planted-0001"]),
    ]
}

#[test]
fn the_check_itself_notices_a_leak() {
    for leak in [
        "value is Zebra.Quartz.0042.Violet",
        "ZEBRA.QUARTZ",
        "…uartz.0…",
        "5a656272612e5175",
        "5A656272",
        "zébra",
        "[90, 101, 98, 114, 97]",
        "[\n    90,\n    101,\n    98,\n    114,\n    97,\n]",
        "[5a, 65, 62, 72, 61]",
        "[5A, 45, 42, 52, 41]",
    ] {
        let caught = std::panic::catch_unwind(|| assert_no_value(leak));
        assert!(caught.is_err(), "{leak:?} was not noticed");
    }
    assert_no_value("TokenValue(<redacted>)");
    assert_no_value(r#"values[1] of token "token-a" is shorter than 12 bytes"#);
}

#[test]
fn a_token_value_is_redacted_however_it_is_formatted() {
    let value = TokenValue::from(PLANTED);
    assert_eq!(format!("{value}"), "<redacted>");
    assert_eq!(format!("{value:?}"), "TokenValue(<redacted>)");
    assert_eq!(format!("{value:#?}"), "TokenValue(<redacted>)");
    assert_eq!(value.to_string(), "<redacted>");
    assert_debug_is_clean(&value);
    assert_no_value(&format!("{value:>40}"));
    assert_no_value(&format!("{value:.3}"));

    // The same holds inside the containers a value usually travels in.
    assert_debug_is_clean(&Some(value.clone()));
    assert_debug_is_clean(&vec![value.clone(), TokenValue::from(LONGER)]);
    assert_debug_is_clean(&("token-a", value));
}

#[test]
fn a_token_description_shows_its_id_and_hides_its_values() {
    let token = TokenSpec::new("token-a", [PLANTED, LONGER, SHORT, NOT_ASCII]);
    assert_debug_is_clean(&token);
    assert_debug_is_clean(&tokens());

    let debug = format!("{token:?}");
    assert!(debug.contains("token-a"));
    assert_eq!(debug.matches("<redacted>").count(), 4);
}

/// Replaces every number by `#` and every automaton kind by `kind`, so that
/// debug output can be compared with a fixed shape.
fn shape(debug: &str) -> String {
    let mut shape = String::new();
    for character in debug.chars() {
        if !character.is_ascii_digit() {
            shape.push(character);
        } else if !shape.ends_with('#') {
            shape.push('#');
        }
    }
    for kind in ["NoncontiguousNFA", "ContiguousNFA", "DFA"] {
        shape = shape.replace(kind, "kind");
    }
    shape
}

#[test]
fn a_matcher_prints_counters_and_nothing_else() {
    // The compiled patterns are the values in another shape. A search for
    // fragments would not recognize them, so the whole output is pinned
    // down instead: anything added to it fails this test.
    let matcher = Matcher::build(&tokens()).expect("the token list is valid");
    assert_eq!(
        shape(&format!("{matcher:?}")),
        "Matcher { tokens: #, patterns: #, max_pattern_len: #, exact: Some(kind), \
         case_insensitive: Some(kind), memory_usage: # }"
    );

    let mut scanner = matcher.stream();
    let _ = scanner.feed(PLANTED.as_bytes());
    assert_eq!(
        shape(&format!("{scanner:?}")),
        "StreamScanner { position: #, carried_len: #, keep: #, .. }"
    );
    assert_eq!(
        format!("{:?}", matcher.scan(PLANTED.as_bytes())),
        "Matches { .. }"
    );
}

#[test]
fn a_matcher_and_its_scanners_show_no_values_and_no_traffic() {
    let matcher = Matcher::build(&tokens()).expect("the token list is valid");
    assert_debug_is_clean(&matcher);
    assert_debug_is_clean(&matcher.clone());

    // Traffic that contains the value in every form the matcher looks for.
    let traffic = format!(
        "{PLANTED}|{}|{}|{}",
        PLANTED.to_uppercase(),
        hex(PLANTED.as_bytes()),
        &PLANTED[..PLANTED.len() - 1],
    );

    let mut matches = matcher.scan(traffic.as_bytes());
    assert_debug_is_clean(&matches);
    let first = matches
        .next()
        .expect("the value is in the traffic")
        .expect("a scan does not fail");
    assert_debug_is_clean(&first);
    assert_debug_is_clean(&matches);
    let mut count = 1;
    for found in matches {
        assert_debug_is_clean(&found.expect("a scan does not fail"));
        count += 1;
    }
    assert_eq!(count, 3);

    // A scanner holds the last bytes of the traffic between chunks.
    let mut scanner = matcher.stream();
    assert_debug_is_clean(&scanner);
    for chunk in traffic.as_bytes().chunks(7) {
        let matches = scanner.feed(chunk);
        assert_debug_is_clean(&matches);
        for found in matches {
            assert_debug_is_clean(&found.expect("a scan does not fail"));
        }
        assert_debug_is_clean(&scanner);
    }
}

#[test]
fn no_validation_error_shows_a_value() {
    // One list that breaks every rule about values, with the planted values
    // in every role: too short, not ASCII, given twice, containing another
    // and contained in another, with and without case-insensitive matching.
    let no_values: [&str; 0] = [];
    let tokens = [
        TokenSpec::new("token-a", [PLANTED, SHORT, NOT_ASCII]),
        TokenSpec::new("token-b", [LONGER, PLANTED]).case_insensitive(true),
        TokenSpec::new("token-c", [PLANTED.to_uppercase()]),
        TokenSpec::new("token-d", [hex(PLANTED.as_bytes())]),
        TokenSpec::new(
            "token-e",
            [format!("id-{}", hex(PLANTED.as_bytes()).to_uppercase())],
        )
        .case_insensitive(true),
        TokenSpec::new("", [LONGER]),
        TokenSpec::new("token-a", [SHORT]),
        TokenSpec::new("token-f", no_values),
    ];

    let error = Matcher::build(&tokens).expect_err("the list breaks many rules");
    assert_error_is_clean(&error);

    let BuildError::Invalid(errors) = &error else {
        panic!("expected a list of problems, got {error:?}");
    };
    assert_error_is_clean(errors);
    for problem in errors.errors() {
        assert_error_is_clean(problem);
    }

    // Every kind of problem is in the list, so every message was checked.
    let has = |wanted: fn(&ValidationError) -> bool| errors.errors().iter().any(wanted);
    assert!(has(|problem| matches!(
        problem,
        ValidationError::EmptyId { .. }
    )));
    assert!(has(|problem| matches!(
        problem,
        ValidationError::DuplicateId { .. }
    )));
    assert!(has(|problem| matches!(
        problem,
        ValidationError::NoValues { .. }
    )));
    assert!(has(|problem| matches!(
        problem,
        ValidationError::NotAscii { .. }
    )));
    assert!(has(|problem| matches!(
        problem,
        ValidationError::TooShort { .. }
    )));
    assert!(has(|problem| matches!(
        problem,
        ValidationError::Duplicate { .. }
    )));
    assert!(has(|problem| matches!(
        problem,
        ValidationError::Contains { .. }
    )));

    // The errors still say where to look.
    let text = error.to_string();
    assert!(text.contains(r#"values[1] of token "token-a" is shorter than 12 bytes"#));
    assert!(text.contains(r#"values[2] of token "token-a" is not ASCII"#));
}

#[test]
fn a_capped_list_of_problems_shows_no_value_either() {
    let tokens: Vec<TokenSpec> = (0..200)
        .map(|index| TokenSpec::new(format!("copy-{index}"), [PLANTED]))
        .collect();
    let error = Matcher::build(&tokens).expect_err("every value is a duplicate");
    assert_error_is_clean(&error);
    let BuildError::Invalid(errors) = &error else {
        panic!("expected a list of problems, got {error:?}");
    };
    assert!(errors.is_truncated());
}
