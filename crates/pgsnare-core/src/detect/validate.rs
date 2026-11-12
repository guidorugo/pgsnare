// SPDX-License-Identifier: Apache-2.0

//! The rules a token list must follow before it is compiled.
//!
//! Two kinds of rule are checked here. The first kind concerns one token or
//! one value at a time: ids, the ASCII rule and the minimum length. The
//! second kind concerns pairs of values: no data that one value matches may
//! also set off another value.

use std::collections::HashSet;
use std::collections::hash_map::{Entry, HashMap};

use aho_corasick::automaton::OverlappingState;
use aho_corasick::{AhoCorasick, AhoCorasickKind, MatchKind};

use super::error::{BuildError, ValidationError, ValidationErrors, ValueLocation};
use super::pattern::{MIN_VALUE_LEN, PatternForm, hex_lower};
use super::token::TokenSpec;

/// A value that passed the rules for single values, with what is derived
/// from it.
pub(crate) struct Slot<'t> {
    pub(crate) location: ValueLocation,
    /// The value as configured.
    pub(crate) raw: &'t [u8],
    /// The value in lowercase hexadecimal.
    pub(crate) hex: Vec<u8>,
    /// Whether the value's token ignores ASCII letter case.
    pub(crate) case_insensitive: bool,
}

/// Checks ids and single values, and returns the values that passed.
///
/// A value that breaks a rule is reported and left out of the result, so the
/// pairwise check that follows only sees values that could be compiled.
pub(crate) fn check_tokens<'t>(
    tokens: &'t [TokenSpec],
    errors: &mut ValidationErrors,
) -> Vec<Slot<'t>> {
    let mut first_use: HashMap<&str, usize> = HashMap::new();
    let mut slots = Vec::new();

    for (token_index, token) in tokens.iter().enumerate() {
        let id = token.id();
        if id.as_str().is_empty() {
            errors.push(ValidationError::EmptyId { token_index });
        } else {
            match first_use.entry(id.as_str()) {
                Entry::Occupied(first) => errors.push(ValidationError::DuplicateId {
                    id: id.clone(),
                    token_index,
                    first_index: *first.get(),
                }),
                Entry::Vacant(unused) => {
                    unused.insert(token_index);
                }
            }
        }

        if token.values().is_empty() {
            errors.push(ValidationError::NoValues {
                token: id.clone(),
                token_index,
            });
        }

        for (value_index, value) in token.values().iter().enumerate() {
            let raw = value.expose();
            let location = ValueLocation {
                token: id.clone(),
                token_index,
                value_index,
            };
            let ascii = raw.is_ascii();
            let long_enough = raw.len() >= MIN_VALUE_LEN;
            if !ascii {
                errors.push(ValidationError::NotAscii {
                    location: location.clone(),
                });
            }
            if !long_enough {
                errors.push(ValidationError::TooShort {
                    location: location.clone(),
                });
            }
            if ascii && long_enough {
                slots.push(Slot {
                    location,
                    raw,
                    hex: hex_lower(raw),
                    case_insensitive: token.is_case_insensitive(),
                });
            }
        }
    }

    slots
}

/// One spelling of one value. It is used both as a text to search in and as
/// a pattern to search for.
struct Spelling<'s> {
    /// The position of the value in the list of slots.
    slot: usize,
    form: PatternForm,
    bytes: &'s [u8],
}

/// Reports every pair of values where data that matches one would also set
/// off the other.
///
/// The texts that match a value are: the value as configured, its hex form,
/// and, for a case-insensitive token, the value in any letter case. None of
/// them may contain a pattern of another value. When this check passes, each
/// of those texts makes the matcher report its own value and nothing else.
///
/// Comparing every pair directly would take time quadratic in the number of
/// values. Instead, all spellings go into one case-insensitive automaton and
/// each spelling is searched once. A hit is then judged by whether the
/// letter case really matches or one of the two tokens ignores it.
pub(crate) fn check_conflicts(
    slots: &[Slot<'_>],
    errors: &mut ValidationErrors,
) -> Result<(), BuildError> {
    if slots.is_empty() || errors.is_truncated() {
        return Ok(());
    }

    let spellings: Vec<Spelling<'_>> = slots
        .iter()
        .enumerate()
        .flat_map(|(slot, value)| {
            [
                Spelling {
                    slot,
                    form: PatternForm::Raw,
                    bytes: value.raw,
                },
                Spelling {
                    slot,
                    form: PatternForm::Hex,
                    bytes: &value.hex,
                },
            ]
        })
        .collect();

    // Built once and thrown away, so the cheapest automaton to construct is
    // the right one.
    let automaton = AhoCorasick::builder()
        .match_kind(MatchKind::Standard)
        .ascii_case_insensitive(true)
        .kind(Some(AhoCorasickKind::NoncontiguousNFA))
        .prefilter(false)
        .build(spellings.iter().map(|spelling| spelling.bytes))
        .map_err(|_| BuildError::TooLarge)?;

    // Each pair of values is reported once, however many ways it conflicts.
    let mut reported: HashSet<(usize, usize)> = HashSet::new();

    for text in &spellings {
        let Some(container) = slots.get(text.slot) else {
            return Err(BuildError::SearchUnavailable);
        };
        let mut state = OverlappingState::start();
        loop {
            if errors.is_truncated() {
                return Ok(());
            }
            automaton
                .try_find_overlapping(text.bytes, &mut state)
                .map_err(|_| BuildError::SearchUnavailable)?;
            let Some(hit) = state.get_match() else {
                break;
            };
            let (Some(pattern), Some(found)) = (
                spellings.get(hit.pattern().as_usize()),
                text.bytes.get(hit.range()),
            ) else {
                return Err(BuildError::SearchUnavailable);
            };
            if pattern.slot == text.slot {
                // A value may contain itself, for example in its hex form.
                continue;
            }
            let Some(contained) = slots.get(pattern.slot) else {
                return Err(BuildError::SearchUnavailable);
            };

            // The automaton ignores letter case. Decide whether the matcher
            // would see this hit too, and in which forms.
            let forms = if found == pattern.bytes {
                Some((text.form, pattern.form))
            } else if pattern.form == PatternForm::Raw && contained.case_insensitive {
                Some((text.form, PatternForm::CaseInsensitive))
            } else if text.form == PatternForm::Raw && container.case_insensitive {
                Some((PatternForm::CaseInsensitive, pattern.form))
            } else {
                None
            };
            let Some((container_form, contained_form)) = forms else {
                continue;
            };

            // Two spellings of the same form and length match each other in
            // both directions. That pair is reported from the later value.
            let whole = hit.len() == text.bytes.len();
            if whole && text.form == pattern.form && pattern.slot > text.slot {
                continue;
            }
            let pair = (text.slot.min(pattern.slot), text.slot.max(pattern.slot));
            if !reported.insert(pair) {
                continue;
            }

            let same_value =
                whole && container_form == PatternForm::Raw && contained_form == PatternForm::Raw;
            errors.push(if same_value {
                ValidationError::Duplicate {
                    location: container.location.clone(),
                    earlier: contained.location.clone(),
                }
            } else {
                ValidationError::Contains {
                    container: container.location.clone(),
                    container_form,
                    contained: contained.location.clone(),
                    contained_form,
                }
            });
        }
    }

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::detect::{Matcher, TokenId};

    /// The problems `Matcher::build` reports for `tokens`.
    fn problems(tokens: &[TokenSpec]) -> Vec<ValidationError> {
        match Matcher::build(tokens) {
            Err(BuildError::Invalid(errors)) => {
                assert!(!errors.is_truncated());
                errors.errors().to_vec()
            }
            other => panic!("expected the list to be refused, got {other:?}"),
        }
    }

    fn accepted(tokens: &[TokenSpec]) -> bool {
        Matcher::build(tokens).is_ok()
    }

    fn at(token: &str, token_index: usize, value_index: usize) -> ValueLocation {
        ValueLocation {
            token: TokenId::from(token),
            token_index,
            value_index,
        }
    }

    fn contains(
        container: ValueLocation,
        container_form: PatternForm,
        contained: ValueLocation,
        contained_form: PatternForm,
    ) -> ValidationError {
        ValidationError::Contains {
            container,
            container_form,
            contained,
            contained_form,
        }
    }

    #[test]
    fn a_value_of_twelve_ascii_bytes_is_accepted() {
        assert!(accepted(&[TokenSpec::new("a", ["0123456789ab"])]));
        assert!(accepted(&[TokenSpec::new(
            "a",
            ["svc.backup.8f3k2q@mail.example"]
        )]));
    }

    #[test]
    fn a_value_shorter_than_twelve_bytes_is_rejected() {
        assert_eq!(
            problems(&[TokenSpec::new("a", ["0123456789a"])]),
            [ValidationError::TooShort {
                location: at("a", 0, 0)
            }]
        );
        assert_eq!(
            problems(&[TokenSpec::new("a", [""])]),
            [ValidationError::TooShort {
                location: at("a", 0, 0)
            }]
        );
    }

    #[test]
    fn a_value_that_is_not_ascii_is_rejected() {
        // Thirteen characters, one of them outside ASCII.
        assert_eq!(
            problems(&[TokenSpec::new("a", ["canary-caf\u{e9}-01"])]),
            [ValidationError::NotAscii {
                location: at("a", 0, 0)
            }]
        );
        // Bytes that are not text at all.
        assert_eq!(
            problems(&[TokenSpec::new("a", [vec![0x80; 16]])]),
            [ValidationError::NotAscii {
                location: at("a", 0, 0)
            }]
        );
    }

    #[test]
    fn a_value_that_breaks_both_rules_is_reported_for_both() {
        assert_eq!(
            problems(&[TokenSpec::new("a", ["caf\u{e9}"])]),
            [
                ValidationError::NotAscii {
                    location: at("a", 0, 0)
                },
                ValidationError::TooShort {
                    location: at("a", 0, 0)
                },
            ]
        );
    }

    #[test]
    fn the_length_is_counted_in_bytes() {
        // Eleven characters but twelve bytes: still rejected, for not being
        // ASCII, and not reported as too short.
        assert_eq!(
            problems(&[TokenSpec::new("a", ["canary-caf\u{e9}"])]),
            [ValidationError::NotAscii {
                location: at("a", 0, 0)
            }]
        );
    }

    #[test]
    fn any_ascii_byte_is_allowed_in_a_value() {
        assert!(accepted(&[TokenSpec::new(
            "a",
            ["tab\tquote\"back\\slash\nnul\0del\x7f"]
        )]));
    }

    #[test]
    fn the_error_points_at_the_value_by_position() {
        let tokens = [
            TokenSpec::new("first", ["alpha-0001-zulu"]),
            TokenSpec::new(
                "second",
                ["bravo-0002-yankee", "short", "charlie-0003-xray"],
            ),
        ];
        assert_eq!(
            problems(&tokens),
            [ValidationError::TooShort {
                location: at("second", 1, 1)
            }]
        );
    }

    #[test]
    fn a_token_needs_an_id_and_at_least_one_value() {
        let no_values: [&str; 0] = [];
        let tokens = [
            TokenSpec::new("", ["alpha-0001-zulu"]),
            TokenSpec::new("empty", no_values),
        ];
        assert_eq!(
            problems(&tokens),
            [
                ValidationError::EmptyId { token_index: 0 },
                ValidationError::NoValues {
                    token: TokenId::from("empty"),
                    token_index: 1
                },
            ]
        );
    }

    #[test]
    fn an_id_may_be_used_once() {
        let tokens = [
            TokenSpec::new("same", ["alpha-0001-zulu"]),
            TokenSpec::new("other", ["bravo-0002-yankee"]),
            TokenSpec::new("same", ["charlie-0003-xray"]),
        ];
        assert_eq!(
            problems(&tokens),
            [ValidationError::DuplicateId {
                id: TokenId::from("same"),
                token_index: 2,
                first_index: 0
            }]
        );
    }

    #[test]
    fn all_problems_are_reported_together() {
        let tokens = [
            TokenSpec::new("a", ["short", "alpha-0001-zulu"]),
            TokenSpec::new("b", ["caf\u{e9}-0002-yankee"]),
            TokenSpec::new("c", ["alpha-0001-zulu"]),
        ];
        assert_eq!(
            problems(&tokens),
            [
                ValidationError::TooShort {
                    location: at("a", 0, 0)
                },
                ValidationError::NotAscii {
                    location: at("b", 1, 0)
                },
                ValidationError::Duplicate {
                    location: at("c", 2, 0),
                    earlier: at("a", 0, 1)
                },
            ]
        );
    }

    #[test]
    fn the_same_value_in_two_tokens_is_a_duplicate() {
        let tokens = [
            TokenSpec::new("a", ["alpha-0001-zulu"]),
            TokenSpec::new("b", ["bravo-0002-yankee", "alpha-0001-zulu"]),
        ];
        assert_eq!(
            problems(&tokens),
            [ValidationError::Duplicate {
                location: at("b", 1, 1),
                earlier: at("a", 0, 0)
            }]
        );
    }

    #[test]
    fn the_same_value_twice_in_one_token_is_a_duplicate() {
        let tokens = [TokenSpec::new("a", ["alpha-0001-zulu", "alpha-0001-zulu"])];
        assert_eq!(
            problems(&tokens),
            [ValidationError::Duplicate {
                location: at("a", 0, 1),
                earlier: at("a", 0, 0)
            }]
        );
    }

    #[test]
    fn every_pair_of_duplicates_is_reported_once() {
        let tokens = [
            TokenSpec::new("a", ["alpha-0001-zulu"]),
            TokenSpec::new("b", ["alpha-0001-zulu"]),
            TokenSpec::new("c", ["alpha-0001-zulu"]),
        ];
        assert_eq!(
            problems(&tokens),
            [
                ValidationError::Duplicate {
                    location: at("b", 1, 0),
                    earlier: at("a", 0, 0)
                },
                ValidationError::Duplicate {
                    location: at("c", 2, 0),
                    earlier: at("a", 0, 0)
                },
                ValidationError::Duplicate {
                    location: at("c", 2, 0),
                    earlier: at("b", 1, 0)
                },
            ]
        );
    }

    #[test]
    fn a_value_that_contains_another_is_reported() {
        let long = TokenSpec::new("long", ["prefix-alpha-0001-zulu-suffix"]);
        let short = TokenSpec::new("short", ["alpha-0001-zulu"]);
        let expected = |long_index, short_index| {
            [contains(
                at("long", long_index, 0),
                PatternForm::Raw,
                at("short", short_index, 0),
                PatternForm::Raw,
            )]
        };
        // The order of the tokens does not matter.
        assert_eq!(problems(&[long.clone(), short.clone()]), expected(0, 1));
        assert_eq!(problems(&[short, long]), expected(1, 0));
    }

    #[test]
    fn containment_within_one_token_is_reported_too() {
        let tokens = [TokenSpec::new(
            "a",
            ["alpha-0001-zulu", "prefix-alpha-0001-zulu"],
        )];
        assert_eq!(
            problems(&tokens),
            [contains(
                at("a", 0, 1),
                PatternForm::Raw,
                at("a", 0, 0),
                PatternForm::Raw
            )]
        );
    }

    #[test]
    fn values_that_only_share_a_part_are_accepted() {
        assert!(accepted(&[
            TokenSpec::new("a", ["alpha-0001-shared"]),
            TokenSpec::new("b", ["shared-0002-omega"]),
        ]));
    }

    #[test]
    fn letter_case_separates_values_unless_a_token_ignores_it() {
        let upper = "ALPHA-0001-ZULU";
        let lower = "alpha-0001-zulu";
        assert!(accepted(&[
            TokenSpec::new("a", [upper]),
            TokenSpec::new("b", [lower]),
        ]));

        // The later token ignores case, so it also matches the earlier value.
        assert_eq!(
            problems(&[
                TokenSpec::new("a", [upper]),
                TokenSpec::new("b", [lower]).case_insensitive(true),
            ]),
            [contains(
                at("b", 1, 0),
                PatternForm::CaseInsensitive,
                at("a", 0, 0),
                PatternForm::Raw
            )]
        );

        // The earlier token ignores case, so it also matches the later value.
        assert_eq!(
            problems(&[
                TokenSpec::new("a", [upper]).case_insensitive(true),
                TokenSpec::new("b", [lower]),
            ]),
            [contains(
                at("b", 1, 0),
                PatternForm::Raw,
                at("a", 0, 0),
                PatternForm::CaseInsensitive
            )]
        );
    }

    #[test]
    fn containment_in_another_case_counts_when_a_token_ignores_case() {
        let long = "prefix-ALPHA-0001-ZULU-suffix";
        let short = "alpha-0001-zulu";
        assert!(accepted(&[
            TokenSpec::new("long", [long]),
            TokenSpec::new("short", [short]),
        ]));

        // The contained token ignores case: the long value sets it off.
        assert_eq!(
            problems(&[
                TokenSpec::new("long", [long]),
                TokenSpec::new("short", [short]).case_insensitive(true),
            ]),
            [contains(
                at("long", 0, 0),
                PatternForm::Raw,
                at("short", 1, 0),
                PatternForm::CaseInsensitive
            )]
        );

        // The containing token ignores case: written in lowercase it still
        // matches, and then it contains the short value exactly.
        assert_eq!(
            problems(&[
                TokenSpec::new("long", [long]).case_insensitive(true),
                TokenSpec::new("short", [short]),
            ]),
            [contains(
                at("long", 0, 0),
                PatternForm::CaseInsensitive,
                at("short", 1, 0),
                PatternForm::Raw
            )]
        );
    }

    #[test]
    fn a_value_that_contains_the_hex_form_of_another_is_reported() {
        // The hex form of `abcdefghijkl`.
        let hex = "6162636465666768696a6b6c";
        assert_eq!(
            problems(&[
                TokenSpec::new("text", ["abcdefghijkl"]),
                TokenSpec::new("digits", [format!("id-{hex}-end")]),
            ]),
            [contains(
                at("digits", 1, 0),
                PatternForm::Raw,
                at("text", 0, 0),
                PatternForm::Hex
            )]
        );
        // When the value is nothing but that hex form, each of the two
        // texts contains the other. The pair is reported once, from the
        // value that comes first.
        assert_eq!(
            problems(&[
                TokenSpec::new("text", ["abcdefghijkl"]),
                TokenSpec::new("digits", [hex]),
            ]),
            [contains(
                at("text", 0, 0),
                PatternForm::Hex,
                at("digits", 1, 0),
                PatternForm::Raw
            )]
        );
        // Uppercase digits are a different text, unless case is ignored.
        let upper = hex.to_uppercase();
        assert!(accepted(&[
            TokenSpec::new("text", ["abcdefghijkl"]),
            TokenSpec::new("digits", [upper.as_str()]),
        ]));
        assert_eq!(
            problems(&[
                TokenSpec::new("text", ["abcdefghijkl"]),
                TokenSpec::new("digits", [upper.as_str()]).case_insensitive(true),
            ]),
            [contains(
                at("text", 0, 0),
                PatternForm::Hex,
                at("digits", 1, 0),
                PatternForm::CaseInsensitive
            )]
        );
        // A longer value in uppercase digits is found from its own side:
        // in lowercase it contains the hex form.
        assert_eq!(
            problems(&[
                TokenSpec::new("text", ["abcdefghijkl"]),
                TokenSpec::new("digits", [format!("ID-{upper}-END")]).case_insensitive(true),
            ]),
            [contains(
                at("digits", 1, 0),
                PatternForm::CaseInsensitive,
                at("text", 0, 0),
                PatternForm::Hex
            )]
        );
    }

    #[test]
    fn a_value_found_in_the_hex_form_of_another_is_reported() {
        // The hex form of `abcdefghijkl-pad` is
        // `6162636465666768696a6b6c2d706164`.
        assert_eq!(
            problems(&[
                TokenSpec::new("text", ["abcdefghijkl-pad"]),
                TokenSpec::new("digits", ["65666768696a6b6c"]),
            ]),
            [contains(
                at("text", 0, 0),
                PatternForm::Hex,
                at("digits", 1, 0),
                PatternForm::Raw
            )]
        );
        // Hex forms are lowercase, so an uppercase value is only found there
        // if its token ignores case.
        assert!(accepted(&[
            TokenSpec::new("text", ["abcdefghijkl-pad"]),
            TokenSpec::new("digits", ["65666768696A6B6C"]),
        ]));
        assert_eq!(
            problems(&[
                TokenSpec::new("text", ["abcdefghijkl-pad"]),
                TokenSpec::new("digits", ["65666768696A6B6C"]).case_insensitive(true),
            ]),
            [contains(
                at("text", 0, 0),
                PatternForm::Hex,
                at("digits", 1, 0),
                PatternForm::CaseInsensitive
            )]
        );
    }

    #[test]
    fn hex_forms_that_overlap_between_two_digits_are_reported() {
        // `#2#2#2#2#2#2` is `233223322332233223322332` in hex. The second
        // value is `32 33 22 33 22 ... 33 23` in hex, which contains that
        // text starting at its second digit, although neither value contains
        // the other.
        let inner = "#2#2#2#2#2#2";
        let outer = "23\"3\"3\"3\"3\"3#";
        assert!(!outer.contains(inner));
        assert_eq!(
            problems(&[
                TokenSpec::new("inner", [inner]),
                TokenSpec::new("outer", [outer]),
            ]),
            [contains(
                at("outer", 1, 0),
                PatternForm::Hex,
                at("inner", 0, 0),
                PatternForm::Hex
            )]
        );
    }

    #[test]
    fn a_value_may_contain_itself() {
        // The hex form of this value is twenty-four times `3`, which
        // contains the value itself. That is no conflict.
        assert!(accepted(&[TokenSpec::new("threes", ["333333333333"])]));
    }

    #[test]
    fn a_pair_is_reported_once_however_many_ways_it_conflicts() {
        // The long value contains the short one twice, and so do their hex
        // forms.
        let tokens = [
            TokenSpec::new("long", ["alpha-0001-zulu+alpha-0001-zulu"]),
            TokenSpec::new("short", ["alpha-0001-zulu"]),
        ];
        assert_eq!(problems(&tokens).len(), 1);
    }

    #[test]
    fn values_that_break_a_rule_are_left_out_of_the_pair_check() {
        // `short` is contained in the other value, but it is reported for
        // its length only: it would never be compiled.
        let tokens = [
            TokenSpec::new("a", ["short"]),
            TokenSpec::new("b", ["a-short-value-0001"]),
        ];
        assert_eq!(
            problems(&tokens),
            [ValidationError::TooShort {
                location: at("a", 0, 0)
            }]
        );
    }

    #[test]
    fn a_flood_of_problems_is_cut_off() {
        // Three hundred copies of one value: tens of thousands of pairs.
        let tokens: Vec<TokenSpec> = (0..300)
            .map(|index| TokenSpec::new(format!("copy-{index}"), ["alpha-0001-zulu"]))
            .collect();
        match Matcher::build(&tokens) {
            Err(BuildError::Invalid(errors)) => {
                assert!(errors.is_truncated());
                assert_eq!(errors.errors().len(), ValidationErrors::LIMIT);
            }
            other => panic!("expected the list to be refused, got {other:?}"),
        }
    }

    #[test]
    fn no_problem_ever_shows_a_value() {
        let values = [
            "alpha-0001-zulu",
            "prefix-alpha-0001-zulu",
            "ALPHA-0001-ZULU",
            "shrt-0002",
            "caf\u{e9}-0003-yankee",
            "616c7068612d303030312d7a756c75",
        ];
        let tokens = [
            TokenSpec::new("first", values).case_insensitive(true),
            TokenSpec::new("second", values),
            TokenSpec::new("", values),
        ];
        let error = Matcher::build(&tokens).expect_err("the list is refused");
        for rendered in [
            format!("{error}"),
            format!("{error:?}"),
            format!("{error:#?}"),
        ] {
            let rendered = rendered.to_lowercase();
            for needle in ["alpha", "zulu", "shrt", "caf", "yankee", "616c", "7a756c75"] {
                assert!(
                    !rendered.contains(needle),
                    "{needle:?} leaked into {rendered:?}"
                );
            }
        }
    }
}
