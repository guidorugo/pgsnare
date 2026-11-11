// SPDX-License-Identifier: Apache-2.0

//! Property tests for the detection module.
//!
//! Each property compares the matcher with a plain, obviously correct search
//! written here, on generated token lists and generated input.

use std::collections::BTreeSet;
use std::sync::OnceLock;

use pgsnare_core::detect::{
    BuildError, MIN_VALUE_LEN, Match, Matcher, PatternForm, TokenSpec, ValidationError,
    ValueLocation,
};
use proptest::collection::vec;
use proptest::prelude::*;
use proptest::sample::{Index, select};

// ---------------------------------------------------------------------------
// Token lists
// ---------------------------------------------------------------------------

/// The characters generated values are made of. There are few of them, in
/// both letter cases, and `1` and `6` also occur in the hex forms of the
/// letters. Values therefore share parts, repeat, and nearly match each
/// other all the time.
const ALPHABET: &[u8] = b"aAbB16";

/// Parts that many generated values have in common.
const STEMS: &[&[u8]] = &[b"aAbB16aA", b"1616aAaA", b"BbBbAa61"];

#[derive(Debug, Clone)]
struct TokenDef {
    values: Vec<Vec<u8>>,
    case_insensitive: bool,
}

fn letters(len: impl Into<proptest::collection::SizeRange>) -> impl Strategy<Value = Vec<u8>> {
    vec(select(ALPHABET), len)
}

/// A value that follows the rules: ASCII and at least twelve bytes.
fn value() -> impl Strategy<Value = Vec<u8>> {
    prop_oneof![
        // Unrelated to anything else.
        4 => letters(MIN_VALUE_LEN..=16),
        // Begins like other values.
        2 => (select(STEMS), letters(4..=8)).prop_map(|(stem, tail)| [stem, tail.as_slice()].concat()),
        // Ends like other values begin.
        2 => (letters(4..=8), select(STEMS)).prop_map(|(head, stem)| [head.as_slice(), stem].concat()),
        // Repeats itself, so that its occurrences can overlap each other.
        1 => (letters(1..=3), MIN_VALUE_LEN..=16)
            .prop_map(|(unit, len)| unit.iter().copied().cycle().take(len).collect()),
    ]
}

fn token_defs() -> impl Strategy<Value = Vec<TokenDef>> {
    vec(
        (vec(value(), 1..=3), any::<bool>()).prop_map(|(values, case_insensitive)| TokenDef {
            values,
            case_insensitive,
        }),
        1..=4,
    )
}

fn id_of(token_index: usize) -> String {
    format!("token-{token_index}")
}

fn specs(defs: &[TokenDef]) -> Vec<TokenSpec> {
    defs.iter()
        .enumerate()
        .map(|(token_index, def)| {
            TokenSpec::new(id_of(token_index), def.values.iter().cloned())
                .case_insensitive(def.case_insensitive)
        })
        .collect()
}

/// A generated token list that the matcher accepts, with its matcher.
fn valid_tokens() -> impl Strategy<Value = (Vec<TokenDef>, Matcher)> {
    token_defs().prop_filter_map("the token list must be valid", |defs| {
        let matcher = Matcher::build(&specs(&defs)).ok()?;
        Some((defs, matcher))
    })
}

fn hex(bytes: &[u8]) -> Vec<u8> {
    bytes
        .iter()
        .flat_map(|byte| format!("{byte:02x}").into_bytes())
        .collect()
}

/// Changes the case of the letters picked by `flips`.
fn flip_case(bytes: &[u8], flips: &[bool]) -> Vec<u8> {
    bytes
        .iter()
        .zip(flips.iter().cycle())
        .map(|(&byte, &flip)| match (flip, byte.is_ascii_lowercase()) {
            (false, _) => byte,
            (true, true) => byte.to_ascii_uppercase(),
            (true, false) => byte.to_ascii_lowercase(),
        })
        .collect()
}

// ---------------------------------------------------------------------------
// Input
// ---------------------------------------------------------------------------

#[derive(Debug, Clone, Copy)]
enum Spelling {
    Raw,
    Hex,
    UpperHex,
    OtherCase,
}

/// One piece of generated input.
#[derive(Debug, Clone)]
enum Piece {
    /// Any bytes at all.
    Bytes(Vec<u8>),
    /// Characters the values are made of.
    Letters(Vec<u8>),
    /// A value in one of its spellings, possibly with its ends cut off.
    Value {
        pick: Index,
        spelling: Spelling,
        flips: Vec<bool>,
        cut_front: usize,
        cut_back: usize,
    },
}

fn piece() -> impl Strategy<Value = Piece> {
    let cut = || prop_oneof![3 => Just(0usize), 1 => 1usize..6];
    let spelling = prop_oneof![
        3 => Just(Spelling::Raw),
        2 => Just(Spelling::Hex),
        1 => Just(Spelling::UpperHex),
        2 => Just(Spelling::OtherCase),
    ];
    prop_oneof![
        1 => vec(any::<u8>(), 0..24).prop_map(Piece::Bytes),
        1 => letters(0..24).prop_map(Piece::Letters),
        3 => (any::<Index>(), spelling, vec(any::<bool>(), 1..16), cut(), cut()).prop_map(
            |(pick, spelling, flips, cut_front, cut_back)| Piece::Value {
                pick,
                spelling,
                flips,
                cut_front,
                cut_back,
            }
        ),
    ]
}

fn render(pieces: &[Piece], defs: &[TokenDef]) -> Vec<u8> {
    let values: Vec<&[u8]> = defs
        .iter()
        .flat_map(|def| def.values.iter().map(Vec::as_slice))
        .collect();
    let mut haystack = Vec::new();
    for piece in pieces {
        match piece {
            Piece::Bytes(bytes) | Piece::Letters(bytes) => haystack.extend_from_slice(bytes),
            Piece::Value {
                pick,
                spelling,
                flips,
                cut_front,
                cut_back,
            } => {
                let value = values[pick.index(values.len())];
                let text = match spelling {
                    Spelling::Raw => value.to_vec(),
                    Spelling::Hex => hex(value),
                    Spelling::UpperHex => hex(value).to_ascii_uppercase(),
                    Spelling::OtherCase => flip_case(value, flips),
                };
                let end = text.len().saturating_sub(*cut_back);
                let start = (*cut_front).min(end);
                haystack.extend_from_slice(&text[start..end]);
            }
        }
    }
    haystack
}

/// Cuts `haystack` at the given positions. Equal positions give empty
/// chunks.
fn chunks<'h>(haystack: &'h [u8], cuts: &[Index]) -> Vec<&'h [u8]> {
    let mut positions: Vec<usize> = cuts
        .iter()
        .map(|cut| cut.index(haystack.len() + 1))
        .collect();
    positions.push(0);
    positions.push(haystack.len());
    positions.sort_unstable();
    positions
        .windows(2)
        .map(|pair| &haystack[pair[0]..pair[1]])
        .collect()
}

// ---------------------------------------------------------------------------
// The plain search
// ---------------------------------------------------------------------------

/// A match as (start, end, token index, value index, form).
type Found = (u64, u64, usize, usize, PatternForm);

fn found(matched: &Match) -> Found {
    (
        matched.start(),
        matched.end(),
        matched.token_index(),
        matched.value_index(),
        matched.form(),
    )
}

/// Every match in `haystack`, found by trying every pattern at every
/// position.
fn plain_search(defs: &[TokenDef], haystack: &[u8]) -> Vec<Found> {
    let mut all = Vec::new();
    for (token_index, def) in defs.iter().enumerate() {
        for (value_index, value) in def.values.iter().enumerate() {
            let hex = hex(value);
            for start in 0..haystack.len() {
                let rest = &haystack[start..];
                let mut add = |form, len: usize| {
                    all.push((
                        start as u64,
                        (start + len) as u64,
                        token_index,
                        value_index,
                        form,
                    ));
                };
                if rest.starts_with(value) {
                    add(PatternForm::Raw, value.len());
                } else if def.case_insensitive
                    && rest.len() >= value.len()
                    && rest[..value.len()].eq_ignore_ascii_case(value)
                {
                    add(PatternForm::CaseInsensitive, value.len());
                }
                if rest.starts_with(&hex) {
                    add(PatternForm::Hex, hex.len());
                }
            }
        }
    }
    all.sort();
    all
}

fn whole_scan(matcher: &Matcher, haystack: &[u8]) -> Vec<Match> {
    let mut matches = matcher
        .scan(haystack)
        .collect::<Result<Vec<_>, _>>()
        .expect("a scan does not fail");
    matches.sort();
    matches
}

// ---------------------------------------------------------------------------
// Properties of scanning
// ---------------------------------------------------------------------------

proptest! {
    #![proptest_config(ProptestConfig::with_cases(400))]

    /// A whole-buffer scan finds exactly what the plain search finds, and
    /// names each token by its id.
    #[test]
    fn a_whole_scan_finds_what_a_plain_search_finds(
        (defs, matcher) in valid_tokens(),
        pieces in vec(piece(), 0..10),
    ) {
        let haystack = render(&pieces, &defs);
        let matches = whole_scan(&matcher, &haystack);

        let actual: Vec<Found> = matches.iter().map(found).collect();
        prop_assert_eq!(actual, plain_search(&defs, &haystack));
        for matched in &matches {
            prop_assert_eq!(matched.token_id().as_str(), id_of(matched.token_index()));
            prop_assert_eq!(matched.range(), matched.start()..matched.end());
        }
    }

    /// For arbitrary input and arbitrary chunking, the streaming scan finds
    /// exactly the matches the whole-buffer scan finds. Each match is
    /// reported by the chunk in which it ends, and the scanner never carries
    /// more than the longest pattern less one byte.
    #[test]
    fn a_stream_scan_finds_what_a_whole_scan_finds(
        (defs, matcher) in valid_tokens(),
        pieces in vec(piece(), 0..10),
        cuts in vec(any::<Index>(), 0..8),
    ) {
        let haystack = render(&pieces, &defs);
        let expected = whole_scan(&matcher, &haystack);
        let bound = matcher.max_pattern_len() - 1;

        let mut scanner = matcher.stream();
        let mut streamed = Vec::new();
        let mut fed = 0;
        for chunk in chunks(&haystack, &cuts) {
            let mut in_chunk = scanner
                .feed(chunk)
                .collect::<Result<Vec<_>, _>>()
                .expect("a scan does not fail");
            in_chunk.sort();

            let chunk_start = fed as u64;
            fed += chunk.len();
            let ending_here: Vec<Match> = expected
                .iter()
                .filter(|matched| matched.end() > chunk_start && matched.end() <= fed as u64)
                .cloned()
                .collect();
            prop_assert_eq!(&in_chunk, &ending_here);

            prop_assert_eq!(scanner.position(), fed as u64);
            prop_assert_eq!(scanner.carried_len(), fed.min(bound));
            streamed.extend(in_chunk);
        }

        streamed.sort();
        prop_assert_eq!(streamed, expected);
    }

    /// Reading only some of the matches of a chunk, or none, does not change
    /// what later chunks report.
    #[test]
    fn unread_matches_change_nothing_else(
        (defs, matcher) in valid_tokens(),
        pieces in vec(piece(), 0..10),
        cuts in vec(any::<Index>(), 0..8),
        reads in vec(prop_oneof![Just(None), (0usize..3).prop_map(Some)], 9),
    ) {
        let haystack = render(&pieces, &defs);
        let expected = whole_scan(&matcher, &haystack);

        let mut scanner = matcher.stream();
        let mut fed = 0;
        for (chunk, read) in chunks(&haystack, &cuts).into_iter().zip(reads) {
            let chunk_start = fed as u64;
            fed += chunk.len();
            let matches = scanner.feed(chunk);
            match read {
                // Read every match of this chunk and check it.
                None => {
                    let mut in_chunk = matches
                        .collect::<Result<Vec<_>, _>>()
                        .expect("a scan does not fail");
                    in_chunk.sort();
                    let ending_here: Vec<Match> = expected
                        .iter()
                        .filter(|matched| {
                            matched.end() > chunk_start && matched.end() <= fed as u64
                        })
                        .cloned()
                        .collect();
                    prop_assert_eq!(in_chunk, ending_here);
                }
                // Read a few matches, or none, and drop the rest.
                Some(count) => {
                    for matched in matches.take(count) {
                        prop_assert!(matched.is_ok());
                    }
                }
            }
        }
    }

    /// After a reset the scanner behaves like a new one.
    #[test]
    fn a_reset_scanner_is_like_a_new_one(
        (defs, matcher) in valid_tokens(),
        before in vec(piece(), 0..6),
        pieces in vec(piece(), 0..10),
        cuts in vec(any::<Index>(), 0..8),
    ) {
        let haystack = render(&pieces, &defs);
        let expected = whole_scan(&matcher, &haystack);

        let mut scanner = matcher.stream();
        let _ = scanner.feed(&render(&before, &defs));
        scanner.reset();

        let mut streamed = Vec::new();
        for chunk in chunks(&haystack, &cuts) {
            for matched in scanner.feed(chunk) {
                streamed.push(matched.expect("a scan does not fail"));
            }
        }
        streamed.sort();
        prop_assert_eq!(streamed, expected);
    }
}

// ---------------------------------------------------------------------------
// A long token list
// ---------------------------------------------------------------------------

/// A token list long enough that the matcher compiles it into its compact
/// kind of automaton instead of the DFA that the short lists above get.
///
/// It is the same for every case and built once: 1,200 tokens with one
/// value each, most of them case-insensitive.
fn long_token_list() -> &'static (Vec<TokenDef>, Matcher) {
    static LIST: OnceLock<(Vec<TokenDef>, Matcher)> = OnceLock::new();
    LIST.get_or_init(|| {
        // A fixed sequence of numbers (a linear congruential generator), so
        // that the list is the same in every run.
        let mut state = 0x5eed_u64;
        let mut next = move |limit: usize| {
            state = state
                .wrapping_mul(6_364_136_223_846_793_005)
                .wrapping_add(1_442_695_040_888_963_407);
            (state >> 33) as usize % limit
        };
        let defs: Vec<TokenDef> = (0..1200)
            .map(|index| {
                let len = 16 + next(9);
                let value = (0..len).map(|_| ALPHABET[next(ALPHABET.len())]).collect();
                TokenDef {
                    values: vec![value],
                    case_insensitive: index % 6 != 0,
                }
            })
            .collect();
        let matcher = Matcher::build(&specs(&defs)).expect("the long token list is valid");
        (defs, matcher)
    })
}

#[test]
fn the_long_token_list_is_not_compiled_into_a_dfa() {
    let (_, matcher) = long_token_list();
    let debug = format!("{matcher:?}");
    assert!(
        debug.contains("exact: Some(ContiguousNFA), case_insensitive: Some(ContiguousNFA)"),
        "{debug}"
    );
}

proptest! {
    #![proptest_config(ProptestConfig::with_cases(200))]

    /// With a long token list, a whole-buffer scan still finds exactly what
    /// the plain search finds, and a streaming scan finds the same, each
    /// match in the chunk where it ends.
    #[test]
    fn a_long_token_list_is_scanned_just_the_same(
        pieces in vec(piece(), 0..10),
        cuts in vec(any::<Index>(), 0..8),
    ) {
        let (defs, matcher) = long_token_list();
        let haystack = render(&pieces, defs);
        let expected = whole_scan(matcher, &haystack);

        let actual: Vec<Found> = expected.iter().map(found).collect();
        prop_assert_eq!(actual, plain_search(defs, &haystack));

        let mut scanner = matcher.stream();
        let mut fed = 0;
        for chunk in chunks(&haystack, &cuts) {
            let mut in_chunk = scanner
                .feed(chunk)
                .collect::<Result<Vec<_>, _>>()
                .expect("a scan does not fail");
            in_chunk.sort();

            let chunk_start = fed as u64;
            fed += chunk.len();
            let ending_here: Vec<Match> = expected
                .iter()
                .filter(|matched| matched.end() > chunk_start && matched.end() <= fed as u64)
                .cloned()
                .collect();
            prop_assert_eq!(in_chunk, ending_here);
        }
    }
}

// ---------------------------------------------------------------------------
// Properties of validation
// ---------------------------------------------------------------------------

/// How a generated value is made. Most values are derived from an earlier
/// one, so that lists with duplicates and containment are common.
#[derive(Debug, Clone)]
enum Recipe {
    Fresh(Vec<u8>),
    TooShort(Vec<u8>),
    NotAscii(Vec<u8>),
    Derived {
        from: Index,
        how: How,
        before: Vec<u8>,
        after: Vec<u8>,
        flips: Vec<bool>,
    },
}

#[derive(Debug, Clone, Copy)]
enum How {
    Same,
    OtherCase,
    Embedded,
    EmbeddedInOtherCase,
    Part,
    Hex,
    UpperHex,
    EmbeddedHex,
    PartOfHex,
}

fn recipe() -> impl Strategy<Value = Recipe> {
    let how = select(vec![
        How::Same,
        How::OtherCase,
        How::Embedded,
        How::EmbeddedInOtherCase,
        How::Part,
        How::Hex,
        How::UpperHex,
        How::EmbeddedHex,
        How::PartOfHex,
    ]);
    prop_oneof![
        6 => value().prop_map(Recipe::Fresh),
        1 => letters(0..MIN_VALUE_LEN).prop_map(Recipe::TooShort),
        1 => (letters(0..16), letters(0..16))
            .prop_map(|(before, after)| Recipe::NotAscii([&before[..], "\u{e9}".as_bytes(), &after[..]].concat())),
        6 => (any::<Index>(), how, letters(0..5), letters(0..5), vec(any::<bool>(), 1..16)).prop_map(
            |(from, how, before, after, flips)| Recipe::Derived {
                from,
                how,
                before,
                after,
                flips,
            }
        ),
    ]
}

/// Turns recipes into values. A derived value refers to a value made before
/// it, in this token or an earlier one.
fn cook(recipes: Vec<(Vec<Recipe>, bool)>) -> Vec<TokenDef> {
    let mut made: Vec<Vec<u8>> = Vec::new();
    let mut defs = Vec::new();
    for (token, case_insensitive) in recipes {
        let mut values = Vec::new();
        for recipe in token {
            let value = match recipe {
                Recipe::Fresh(value) | Recipe::TooShort(value) | Recipe::NotAscii(value) => value,
                Recipe::Derived { .. } if made.is_empty() => b"aAbB16aAbB16".to_vec(),
                Recipe::Derived {
                    from,
                    how,
                    before,
                    after,
                    flips,
                } => {
                    let source = made[from.index(made.len())].clone();
                    let embed = |inner: &[u8]| [&before[..], inner, &after[..]].concat();
                    // The middle of `text`, at least twelve bytes if it has
                    // that many.
                    let part = |text: &[u8]| {
                        let spare = text.len().saturating_sub(MIN_VALUE_LEN);
                        let front = before.len().min(spare);
                        let back = after.len().min(spare - front);
                        text[front..text.len() - back].to_vec()
                    };
                    match how {
                        How::Same => source,
                        How::OtherCase => flip_case(&source, &flips),
                        How::Embedded => embed(&source),
                        How::EmbeddedInOtherCase => embed(&flip_case(&source, &flips)),
                        How::Part => part(&source),
                        How::Hex => hex(&source),
                        How::UpperHex => hex(&source).to_ascii_uppercase(),
                        How::EmbeddedHex => embed(&hex(&source)),
                        How::PartOfHex => part(&hex(&source)),
                    }
                }
            };
            made.push(value.clone());
            values.push(value);
        }
        defs.push(TokenDef {
            values,
            case_insensitive,
        });
    }
    defs
}

fn related_tokens() -> impl Strategy<Value = Vec<TokenDef>> {
    vec((vec(recipe(), 1..=3), any::<bool>()), 1..=4).prop_map(cook)
}

fn contains(text: &[u8], pattern: &[u8]) -> bool {
    text.windows(pattern.len()).any(|window| window == pattern)
}

fn contains_in_any_case(text: &[u8], pattern: &[u8]) -> bool {
    text.windows(pattern.len())
        .any(|window| window.eq_ignore_ascii_case(pattern))
}

/// A value by (token index, value index).
type Slot = (usize, usize);

fn slot(location: &ValueLocation) -> Slot {
    (location.token_index, location.value_index)
}

fn is_valid(value: &[u8]) -> bool {
    value.is_ascii() && value.len() >= MIN_VALUE_LEN
}

/// Whether some text that matches the first value also contains a pattern of
/// the second.
///
/// The texts of a value are the value itself, its hex form and, if its token
/// ignores case, the value in any letter case. Its patterns are the value
/// itself, matched in any letter case if its token ignores case, and its hex
/// form.
fn sets_off(defs: &[TokenDef], first: Slot, second: Slot) -> bool {
    let (a, a_any_case) = (
        &defs[first.0].values[first.1],
        defs[first.0].case_insensitive,
    );
    let (b, b_any_case) = (
        &defs[second.0].values[second.1],
        defs[second.0].case_insensitive,
    );
    let (a_hex, b_hex) = (hex(a), hex(b));

    contains(a, b)
        || contains(a, &b_hex)
        || contains(&a_hex, b)
        || contains(&a_hex, &b_hex)
        || (b_any_case && (contains_in_any_case(a, b) || contains_in_any_case(&a_hex, b)))
        || (a_any_case && (contains_in_any_case(a, b) || contains_in_any_case(a, &b_hex)))
}

/// The pairs of values that conflict, found by comparing every pair.
fn conflicting_pairs(defs: &[TokenDef]) -> BTreeSet<(Slot, Slot)> {
    let slots: Vec<Slot> = defs
        .iter()
        .enumerate()
        .flat_map(|(token_index, def)| {
            def.values
                .iter()
                .enumerate()
                .filter(|(_, value)| is_valid(value))
                .map(move |(value_index, _)| (token_index, value_index))
        })
        .collect();
    let mut pairs = BTreeSet::new();
    for (position, &first) in slots.iter().enumerate() {
        for &second in &slots[position + 1..] {
            if sets_off(defs, first, second) || sets_off(defs, second, first) {
                pairs.insert((first, second));
            }
        }
    }
    pairs
}

/// The text of a value in the given form, for comparing. Case-insensitive
/// forms are compared in any case, so the value itself stands in for them.
fn text_in_form(defs: &[TokenDef], location: &ValueLocation, form: PatternForm) -> Vec<u8> {
    let value = &defs[location.token_index].values[location.value_index];
    match form {
        PatternForm::Hex => hex(value),
        _ => value.clone(),
    }
}

proptest! {
    #![proptest_config(ProptestConfig::with_cases(600))]

    /// The matcher refuses a list exactly when a value breaks a rule or two
    /// values conflict, reports exactly those values and pairs, and
    /// describes each conflict correctly.
    #[test]
    fn validation_reports_exactly_the_real_problems(defs in related_tokens()) {
        let mut expected_not_ascii = BTreeSet::new();
        let mut expected_too_short = BTreeSet::new();
        for (token_index, def) in defs.iter().enumerate() {
            for (value_index, value) in def.values.iter().enumerate() {
                if !value.is_ascii() {
                    expected_not_ascii.insert((token_index, value_index));
                }
                if value.len() < MIN_VALUE_LEN {
                    expected_too_short.insert((token_index, value_index));
                }
            }
        }
        let expected_pairs = conflicting_pairs(&defs);
        let expect_refusal = !(expected_not_ascii.is_empty()
            && expected_too_short.is_empty()
            && expected_pairs.is_empty());

        let errors = match Matcher::build(&specs(&defs)) {
            Ok(_) => {
                prop_assert!(!expect_refusal, "a list with problems was accepted");
                return Ok(());
            }
            Err(BuildError::Invalid(errors)) => errors,
            Err(other) => return Err(TestCaseError::fail(format!("unexpected error: {other}"))),
        };
        prop_assert!(expect_refusal, "a list without problems was refused: {}", errors);

        let mut not_ascii = BTreeSet::new();
        let mut too_short = BTreeSet::new();
        let mut pairs = BTreeSet::new();
        for error in errors.errors() {
            match error {
                ValidationError::NotAscii { location } => {
                    prop_assert!(not_ascii.insert(slot(location)));
                }
                ValidationError::TooShort { location } => {
                    prop_assert!(too_short.insert(slot(location)));
                }
                ValidationError::Duplicate { location, earlier } => {
                    prop_assert!(slot(earlier) < slot(location));
                    prop_assert_eq!(
                        text_in_form(&defs, location, PatternForm::Raw),
                        text_in_form(&defs, earlier, PatternForm::Raw)
                    );
                    prop_assert!(pairs.insert((slot(earlier), slot(location))));
                }
                ValidationError::Contains {
                    container,
                    container_form,
                    contained,
                    contained_form,
                } => {
                    let text = text_in_form(&defs, container, *container_form);
                    let pattern = text_in_form(&defs, contained, *contained_form);
                    let any_case = [(container, container_form), (contained, contained_form)]
                        .into_iter()
                        .any(|(_, form)| *form == PatternForm::CaseInsensitive);
                    // A form that ignores case may only be named for a token
                    // that does.
                    for (location, form) in [(container, container_form), (contained, contained_form)] {
                        if *form == PatternForm::CaseInsensitive {
                            prop_assert!(defs[location.token_index].case_insensitive);
                        }
                    }
                    if any_case {
                        prop_assert!(contains_in_any_case(&text, &pattern));
                    } else {
                        prop_assert!(contains(&text, &pattern));
                    }
                    let (low, high) = (
                        slot(container).min(slot(contained)),
                        slot(container).max(slot(contained)),
                    );
                    prop_assert_ne!(low, high);
                    prop_assert!(pairs.insert((low, high)));
                }
                other => {
                    return Err(TestCaseError::fail(format!("unexpected problem: {other}")));
                }
            }
        }
        if errors.is_truncated() {
            // The report is capped. What it does list must still be real.
            prop_assert!(not_ascii.is_subset(&expected_not_ascii));
            prop_assert!(too_short.is_subset(&expected_too_short));
            prop_assert!(pairs.is_subset(&expected_pairs));
        } else {
            prop_assert_eq!(not_ascii, expected_not_ascii);
            prop_assert_eq!(too_short, expected_too_short);
            prop_assert_eq!(pairs, expected_pairs);
        }
    }

    /// In an accepted list, no text that matches one value sets off another:
    /// scanning a value, its hex form or, for a token that ignores case, the
    /// value in another case reports that value and nothing else.
    #[test]
    fn in_an_accepted_list_a_value_sets_off_only_itself(
        defs in related_tokens(),
        flips in vec(any::<bool>(), 1..16),
    ) {
        let Ok(matcher) = Matcher::build(&specs(&defs)) else {
            return Ok(());
        };
        for (token_index, def) in defs.iter().enumerate() {
            for (value_index, value) in def.values.iter().enumerate() {
                let mut texts = vec![value.clone(), hex(value)];
                if def.case_insensitive {
                    texts.push(flip_case(value, &flips));
                    texts.push(value.to_ascii_lowercase());
                    texts.push(value.to_ascii_uppercase());
                }
                for text in texts {
                    let matches = whole_scan(&matcher, &text);
                    prop_assert!(!matches.is_empty());
                    for matched in matches {
                        prop_assert_eq!(
                            (matched.token_index(), matched.value_index()),
                            (token_index, value_index)
                        );
                    }
                }
            }
        }
    }
}
