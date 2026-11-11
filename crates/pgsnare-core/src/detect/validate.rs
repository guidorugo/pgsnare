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
