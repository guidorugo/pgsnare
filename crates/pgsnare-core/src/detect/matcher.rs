// SPDX-License-Identifier: Apache-2.0

//! The compiled matcher and the whole-buffer scan.

use std::fmt;
use std::iter::FusedIterator;
use std::mem::size_of;
use std::ops::Range;
use std::sync::Arc;

use aho_corasick::automaton::OverlappingState;
use aho_corasick::{AhoCorasick, MatchKind};

use super::error::{BuildError, ScanError, ValidationErrors};
use super::pattern::PatternForm;
use super::stream::StreamScanner;
use super::token::{TokenId, TokenSpec};
use super::validate::{self, Slot};

/// One place where a token value was found.
///
/// A match says which token, which of its values, in which form, and where.
/// It does not contain the value.
///
/// Matches order by where they start, then by where they end.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct Match {
    start: u64,
    end: u64,
    token_index: usize,
    value_index: usize,
    form: PatternForm,
    token: TokenId,
}

impl Match {
    /// The id of the token that was found.
    pub fn token_id(&self) -> &TokenId {
        &self.token
    }

    /// The position of the token in the list the matcher was built from,
    /// counted from zero.
    pub fn token_index(&self) -> usize {
        self.token_index
    }

    /// Which of the token's values was found, counted from zero.
    pub fn value_index(&self) -> usize {
        self.value_index
    }

    /// The form in which the value was found.
    pub fn form(&self) -> PatternForm {
        self.form
    }

    /// The offset of the first matched byte.
    ///
    /// For [`Matcher::scan`] this is an index into the buffer. For
    /// [`StreamScanner::feed`] it counts from the first byte fed since the
    /// scanner was created or reset.
    pub fn start(&self) -> u64 {
        self.start
    }

    /// The offset just past the last matched byte.
    pub fn end(&self) -> u64 {
        self.end
    }

    /// The matched bytes as a range of offsets.
    pub fn range(&self) -> Range<u64> {
        self.start..self.end
    }
}

/// What is known about one compiled pattern.
struct PatternInfo {
    token: TokenId,
    token_index: usize,
    value_index: usize,
    form: PatternForm,
    /// For a case-insensitive pattern, the value in its configured case.
    /// Secret, like the value it was copied from.
    configured: Option<Box<[u8]>>,
}

impl PatternInfo {
    fn new(slot: &Slot<'_>, form: PatternForm) -> Self {
        Self {
            token: slot.location.token.clone(),
            token_index: slot.location.token_index,
            value_index: slot.location.value_index,
            form,
            configured: match form {
                PatternForm::CaseInsensitive => Some(slot.raw.into()),
                _ => None,
            },
        }
    }
}

/// A part of the input that is scanned in one pass.
#[derive(Clone, Copy)]
pub(crate) struct Region<'a> {
    pub(crate) haystack: &'a [u8],
    /// The offset of the first byte of `haystack`, as reported in matches.
    pub(crate) base: u64,
    /// If set, only matches that begin before this index and end after it
    /// are reported. The stream scanner uses this for the bytes around the
    /// joint between two chunks.
    pub(crate) straddling: Option<usize>,
}

/// One automaton and the patterns compiled into it.
struct PatternSet {
    automaton: AhoCorasick,
    /// Indexed by the automaton's pattern ids.
    patterns: Vec<PatternInfo>,
}

impl PatternSet {
    /// Compiles `entries` into one automaton, or returns `None` if there is
    /// nothing to compile.
    fn compile(
        entries: Vec<(PatternInfo, &[u8])>,
        ignore_case: bool,
    ) -> Result<Option<Self>, BuildError> {
        if entries.is_empty() {
            return Ok(None);
        }

        let automaton = AhoCorasick::builder()
            // Standard semantics are what allow an overlapping search, which
            // reports every occurrence of every pattern.
            .match_kind(MatchKind::Standard)
            .ascii_case_insensitive(ignore_case)
            .build(entries.iter().map(|(_, bytes)| bytes))
            .map_err(|_| BuildError::TooLarge)?;

        // Whether an automaton supports the search does not depend on the
        // input, so asking once here keeps a misconfiguration from showing
        // up later as a failure of every scan.
        let searchable = automaton.try_find_overlapping_iter(b"").is_ok();
        if !searchable || automaton.patterns_len() != entries.len() {
            return Err(BuildError::SearchUnavailable);
        }

        Ok(Some(Self {
            automaton,
            patterns: entries.into_iter().map(|(info, _)| info).collect(),
        }))
    }

    /// Finds the next match in `region`, continuing from `state`.
    fn next_match(
        &self,
        region: Region<'_>,
        state: &mut OverlappingState,
    ) -> Result<Option<Match>, ScanError> {
        loop {
            self.automaton
                .try_find_overlapping(region.haystack, state)
                .map_err(|_| ScanError::search_failed())?;
            let Some(found) = state.get_match() else {
                return Ok(None);
            };
            let Some(info) = self.patterns.get(found.pattern().as_usize()) else {
                return Err(ScanError::unknown_pattern());
            };

            if let Some(joint) = region.straddling
                && (found.start() >= joint || found.end() <= joint)
            {
                continue;
            }

            // A case-insensitive pattern also matches the value in its
            // configured case. The raw pattern reports that occurrence, so
            // it is not reported a second time here.
            if let Some(configured) = info.configured.as_deref()
                && region.haystack.get(found.range()) == Some(configured)
            {
                continue;
            }

            return Ok(Some(Match {
                start: region.base.saturating_add(widen(found.start())),
                end: region.base.saturating_add(widen(found.end())),
                token_index: info.token_index,
                value_index: info.value_index,
                form: info.form,
                token: info.token.clone(),
            }));
        }
    }

    fn memory_usage(&self) -> usize {
        let configured: usize = self
            .patterns
            .iter()
            .filter_map(|info| info.configured.as_deref())
            .map(<[u8]>::len)
            .fold(0, usize::saturating_add);
        self.automaton
            .memory_usage()
            .saturating_add(self.patterns.len().saturating_mul(size_of::<PatternInfo>()))
            .saturating_add(configured)
    }
}

/// Converts an index into an offset. Offsets are 64 bits wide on every
/// platform, so that a long stream cannot overflow them.
pub(crate) fn widen(index: usize) -> u64 {
    u64::try_from(index).unwrap_or(u64::MAX)
}

pub(crate) struct Inner {
    /// Raw and hex patterns of every value. Absent if there are no values.
    exact: Option<PatternSet>,
    /// Case-insensitive patterns. Absent unless a token asks for them.
    folded: Option<PatternSet>,
    token_count: usize,
    max_pattern_len: usize,
}

/// The compiled form of a token list: answers "is a token in these bytes?".
///
/// A matcher is built once, by [`Matcher::build`], and never changes.
/// Cloning it is cheap and every clone shares the same compiled patterns, so
/// one matcher can serve all threads.
///
/// # What is found
///
/// Every occurrence of every pattern is reported, including occurrences that
/// overlap. Two different tokens that appear in the same bytes are therefore
/// both found, wherever they are and however they overlap.
///
/// ```
/// use pgsnare_core::detect::{Matcher, PatternForm, TokenSpec};
///
/// let tokens = [TokenSpec::new("users-admin-backup", ["svc.backup.8f3k2q@mail.example"])];
/// let matcher = Matcher::build(&tokens)?;
///
/// let row = br#"{"id": 7, "email": "svc.backup.8f3k2q@mail.example"}"#;
/// let hits = matcher.scan(row).collect::<Result<Vec<_>, _>>()?;
///
/// assert_eq!(hits.len(), 1);
/// assert_eq!(hits[0].token_id().as_str(), "users-admin-backup");
/// assert_eq!(hits[0].form(), PatternForm::Raw);
/// assert_eq!(hits[0].start(), 20);
/// # Ok::<(), Box<dyn std::error::Error>>(())
/// ```
#[derive(Clone)]
pub struct Matcher {
    inner: Arc<Inner>,
}

impl Matcher {
    /// Checks a token list and compiles it.
    ///
    /// The list may be empty; the matcher then finds nothing.
    ///
    /// # Errors
    ///
    /// [`BuildError::Invalid`] lists every rule the list breaks (up to
    /// [`ValidationErrors::LIMIT`]):
    ///
    /// - an id is empty or used by two tokens;
    /// - a token has no values;
    /// - a value is not ASCII or is shorter than
    ///   [`MIN_VALUE_LEN`](super::MIN_VALUE_LEN) bytes;
    /// - a value is given twice;
    /// - a value contains another value, so that data matching the first
    ///   would also set off the second.
    ///
    /// The errors name tokens by id and values by position, never by
    /// content.
    ///
    /// [`BuildError::TooLarge`] is returned if the values are too many or
    /// too long to compile.
    pub fn build(tokens: &[TokenSpec]) -> Result<Self, BuildError> {
        let mut errors = ValidationErrors::new();
        let slots = validate::check_tokens(tokens, &mut errors);
        let conflicts = validate::check_conflicts(&slots, &mut errors);
        if !errors.is_empty() {
            return Err(BuildError::Invalid(errors));
        }
        conflicts?;

        let mut exact = Vec::with_capacity(slots.len().saturating_mul(2));
        let mut folded = Vec::new();
        for slot in &slots {
            exact.push((PatternInfo::new(slot, PatternForm::Raw), slot.raw));
            exact.push((
                PatternInfo::new(slot, PatternForm::Hex),
                slot.hex.as_slice(),
            ));
            // A value without letters reads the same in every case, and the
            // raw pattern already finds it.
            if slot.case_insensitive && slot.raw.iter().any(u8::is_ascii_alphabetic) {
                folded.push((
                    PatternInfo::new(slot, PatternForm::CaseInsensitive),
                    slot.raw,
                ));
            }
        }

        let exact = PatternSet::compile(exact, false)?;
        // The second automaton exists only if a token needs it.
        let folded = PatternSet::compile(folded, true)?;
        let max_pattern_len = [&exact, &folded]
            .into_iter()
            .flatten()
            .map(|set| set.automaton.max_pattern_len())
            .max()
            .unwrap_or(0);

        Ok(Self {
            inner: Arc::new(Inner {
                exact,
                folded,
                token_count: tokens.len(),
                max_pattern_len,
            }),
        })
    }

    /// Scans a whole buffer and returns every match in it.
    ///
    /// The result is lazy: bytes are scanned as the iterator is advanced, and
    /// stopping early costs nothing. The order of the matches is not
    /// specified.
    ///
    /// Each item is a `Result` so that a defect in the search surfaces as an
    /// error instead of a missed token; see [`ScanError`].
    pub fn scan<'a>(&'a self, haystack: &'a [u8]) -> Matches<'a> {
        Matches::new(
            &self.inner,
            None,
            Region {
                haystack,
                base: 0,
                straddling: None,
            },
        )
    }

    /// Creates a scanner for input that arrives in chunks.
    pub fn stream(&self) -> StreamScanner {
        StreamScanner::new(self)
    }

    /// The number of tokens the matcher was built from.
    pub fn token_count(&self) -> usize {
        self.inner.token_count
    }

    /// The number of compiled patterns: two per value, plus one per value
    /// that is also matched case-insensitively.
    pub fn pattern_count(&self) -> usize {
        self.sets()
            .map(|set| set.patterns.len())
            .fold(0, usize::saturating_add)
    }

    /// The length in bytes of the longest pattern, or zero if there are no
    /// patterns. The stream scanner carries one byte less than this from one
    /// chunk to the next.
    pub fn max_pattern_len(&self) -> usize {
        self.inner.max_pattern_len
    }

    /// Whether the matcher has no patterns and so can never find anything.
    pub fn is_empty(&self) -> bool {
        self.inner.exact.is_none() && self.inner.folded.is_none()
    }

    /// The approximate amount of heap memory the compiled patterns use, in
    /// bytes.
    pub fn memory_usage(&self) -> usize {
        self.sets()
            .map(PatternSet::memory_usage)
            .fold(0, usize::saturating_add)
    }

    pub(crate) fn inner(&self) -> &Inner {
        &self.inner
    }

    fn sets(&self) -> impl Iterator<Item = &PatternSet> {
        [&self.inner.exact, &self.inner.folded]
            .into_iter()
            .flatten()
    }
}

/// Shows sizes and automaton kinds only. The compiled patterns are the token
/// values, so they are never printed.
impl fmt::Debug for Matcher {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let kind = |set: &Option<PatternSet>| set.as_ref().map(|set| set.automaton.kind());
        f.debug_struct("Matcher")
            .field("tokens", &self.token_count())
            .field("patterns", &self.pattern_count())
            .field("max_pattern_len", &self.max_pattern_len())
            .field("exact", &kind(&self.inner.exact))
            .field("case_insensitive", &kind(&self.inner.folded))
            .field("memory_usage", &self.memory_usage())
            .finish()
    }
}

/// Which automaton is searching which region.
#[derive(Clone, Copy)]
enum Stage {
    SeamExact,
    SeamFolded,
    BodyExact,
    BodyFolded,
    Done,
}

/// The matches of one scan, found lazily.
///
/// Returned by [`Matcher::scan`] and [`StreamScanner::feed`]. After an error
/// the iterator yields nothing more.
#[must_use = "a scan does nothing until its matches are read"]
pub struct Matches<'a> {
    inner: &'a Inner,
    /// The bytes around the joint between two chunks. Stream scans only.
    seam: Option<Region<'a>>,
    body: Region<'a>,
    stage: Stage,
    state: OverlappingState,
}

impl<'a> Matches<'a> {
    pub(crate) fn new(inner: &'a Inner, seam: Option<Region<'a>>, body: Region<'a>) -> Self {
        Self {
            inner,
            seam,
            body,
            stage: Stage::SeamExact,
            state: OverlappingState::start(),
        }
    }

    fn advance(&mut self) {
        self.stage = match self.stage {
            Stage::SeamExact => Stage::SeamFolded,
            Stage::SeamFolded => Stage::BodyExact,
            Stage::BodyExact => Stage::BodyFolded,
            Stage::BodyFolded | Stage::Done => Stage::Done,
        };
        self.state = OverlappingState::start();
    }
}

impl Iterator for Matches<'_> {
    type Item = Result<Match, ScanError>;

    fn next(&mut self) -> Option<Self::Item> {
        let inner = self.inner;
        loop {
            let (region, set) = match self.stage {
                Stage::SeamExact => (self.seam, &inner.exact),
                Stage::SeamFolded => (self.seam, &inner.folded),
                Stage::BodyExact => (Some(self.body), &inner.exact),
                Stage::BodyFolded => (Some(self.body), &inner.folded),
                Stage::Done => return None,
            };
            let (Some(region), Some(set)) = (region, set) else {
                self.advance();
                continue;
            };
            match set.next_match(region, &mut self.state) {
                Ok(Some(found)) => return Some(Ok(found)),
                Ok(None) => self.advance(),
                Err(error) => {
                    self.stage = Stage::Done;
                    return Some(Err(error));
                }
            }
        }
    }
}

impl FusedIterator for Matches<'_> {}

/// Shows nothing of the bytes being scanned: they are traffic.
impl fmt::Debug for Matches<'_> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Matches").finish_non_exhaustive()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const EMAIL: &str = "svc.backup.8f3k2q@mail.example";
    const EMAIL_HEX: &str = "7376632e6261636b75702e3866336b3271406d61696c2e6578616d706c65";
    const INVOICE: &str = "Canary.Invoice.000417";

    fn build(tokens: &[TokenSpec]) -> Matcher {
        Matcher::build(tokens).expect("the token list is valid")
    }

    /// Every match in `haystack`, sorted, as (token id, value index, form,
    /// start, end).
    fn scan(matcher: &Matcher, haystack: &[u8]) -> Vec<(String, usize, PatternForm, u64, u64)> {
        let mut matches = matcher
            .scan(haystack)
            .collect::<Result<Vec<_>, _>>()
            .expect("the scan succeeds");
        matches.sort();
        matches
            .iter()
            .map(|found| {
                (
                    found.token_id().to_string(),
                    found.value_index(),
                    found.form(),
                    found.start(),
                    found.end(),
                )
            })
            .collect()
    }

    fn hit(
        token: &str,
        value_index: usize,
        form: PatternForm,
        range: Range<u64>,
    ) -> (String, usize, PatternForm, u64, u64) {
        (token.to_owned(), value_index, form, range.start, range.end)
    }

    #[test]
    fn an_empty_token_list_gives_a_matcher_that_finds_nothing() {
        let matcher = build(&[]);
        assert!(matcher.is_empty());
        assert_eq!(matcher.token_count(), 0);
        assert_eq!(matcher.pattern_count(), 0);
        assert_eq!(matcher.max_pattern_len(), 0);
        assert_eq!(scan(&matcher, b"anything at all"), []);
        assert_eq!(scan(&matcher, b""), []);
    }

    #[test]
    fn a_value_is_found_in_raw_form_with_its_offset() {
        let matcher = build(&[TokenSpec::new("users-admin-backup", [EMAIL])]);
        let haystack = format!("id=7 email={EMAIL} active=t");
        assert_eq!(
            scan(&matcher, haystack.as_bytes()),
            [hit("users-admin-backup", 0, PatternForm::Raw, 11..41)]
        );
    }

    #[test]
    fn a_value_is_found_in_hex_form_with_its_offset() {
        let matcher = build(&[TokenSpec::new("users-admin-backup", [EMAIL])]);
        let haystack = format!("\\x00{EMAIL_HEX}ff");
        assert_eq!(
            scan(&matcher, haystack.as_bytes()),
            [hit("users-admin-backup", 0, PatternForm::Hex, 4..64)]
        );
    }

    #[test]
    fn nothing_is_found_in_clean_or_nearly_matching_data() {
        let matcher = build(&[TokenSpec::new("users-admin-backup", [EMAIL])]);
        assert_eq!(scan(&matcher, b""), []);
        assert_eq!(scan(&matcher, b"svc.backup.8f3k2q@mail.exampl"), []);
        assert_eq!(scan(&matcher, b"vc.backup.8f3k2q@mail.example"), []);
        assert_eq!(scan(&matcher, b"svc.backup.8f3k2q@mail-example"), []);
        // Without the case-insensitive option, another case is another value.
        assert_eq!(scan(&matcher, b"SVC.BACKUP.8F3K2Q@MAIL.EXAMPLE"), []);
        // Only lowercase hexadecimal digits are looked for.
        assert_eq!(scan(&matcher, EMAIL_HEX.to_uppercase().as_bytes()), []);
    }

    #[test]
    fn the_match_names_the_token_and_the_value() {
        let matcher = build(&[
            TokenSpec::new("first", ["alpha-0001-zulu", "bravo-0002-yankee"]),
            TokenSpec::new("second", ["charlie-0003-xray"]),
        ]);
        let matches = matcher
            .scan(b"..charlie-0003-xray..bravo-0002-yankee..")
            .collect::<Result<Vec<_>, _>>()
            .expect("the scan succeeds");
        let mut found: Vec<_> = matches
            .iter()
            .map(|found| {
                (
                    found.token_id().as_str(),
                    found.token_index(),
                    found.value_index(),
                    found.range(),
                )
            })
            .collect();
        found.sort_by_key(|entry| entry.3.start);
        assert_eq!(found, [("second", 1, 0, 2..19), ("first", 0, 1, 21..38)]);
    }

    #[test]
    fn every_occurrence_is_reported() {
        let matcher = build(&[TokenSpec::new("users-admin-backup", [EMAIL])]);
        let haystack = format!("{EMAIL},{EMAIL}\n{EMAIL_HEX}{EMAIL}");
        assert_eq!(
            scan(&matcher, haystack.as_bytes()),
            [
                hit("users-admin-backup", 0, PatternForm::Raw, 0..30),
                hit("users-admin-backup", 0, PatternForm::Raw, 31..61),
                hit("users-admin-backup", 0, PatternForm::Hex, 62..122),
                hit("users-admin-backup", 0, PatternForm::Raw, 122..152),
            ]
        );
    }

    #[test]
    fn occurrences_that_overlap_themselves_are_all_reported() {
        let matcher = build(&[TokenSpec::new("repeating", ["abababababab"])]);
        assert_eq!(
            scan(&matcher, b"abababababababab"),
            [
                hit("repeating", 0, PatternForm::Raw, 0..12),
                hit("repeating", 0, PatternForm::Raw, 2..14),
                hit("repeating", 0, PatternForm::Raw, 4..16),
            ]
        );
    }

    #[test]
    fn two_tokens_that_overlap_each_other_are_both_found() {
        // The end of the first value is the start of the second.
        let matcher = build(&[
            TokenSpec::new("left", ["alpha-0001-shared"]),
            TokenSpec::new("right", ["shared-0002-omega"]),
        ]);
        assert_eq!(
            scan(&matcher, b"<alpha-0001-shared-0002-omega>"),
            [
                hit("left", 0, PatternForm::Raw, 1..18),
                hit("right", 0, PatternForm::Raw, 12..29),
            ]
        );
    }

    #[test]
    fn a_case_insensitive_token_is_found_in_any_letter_case() {
        let matcher = build(&[TokenSpec::new("billing-canary", [INVOICE]).case_insensitive(true)]);
        assert_eq!(
            scan(
                &matcher,
                b"canary.invoice.000417 CANARY.INVOICE.000417 cAnArY.iNvOiCe.000417"
            ),
            [
                hit("billing-canary", 0, PatternForm::CaseInsensitive, 0..21),
                hit("billing-canary", 0, PatternForm::CaseInsensitive, 22..43),
                hit("billing-canary", 0, PatternForm::CaseInsensitive, 44..65),
            ]
        );
    }

    #[test]
    fn the_configured_case_is_reported_once_and_as_raw() {
        let matcher = build(&[TokenSpec::new("billing-canary", [INVOICE]).case_insensitive(true)]);
        assert_eq!(
            scan(&matcher, format!("[{INVOICE}]").as_bytes()),
            [hit("billing-canary", 0, PatternForm::Raw, 1..22)]
        );
    }

    #[test]
    fn case_is_ignored_only_for_tokens_that_ask() {
        let matcher = build(&[
            TokenSpec::new("strict", ["Strict.Value.0001"]),
            TokenSpec::new("loose", ["Loose.Value.0002"]).case_insensitive(true),
        ]);
        assert_eq!(
            scan(&matcher, b"strict.value.0001 loose.value.0002"),
            [hit("loose", 0, PatternForm::CaseInsensitive, 18..34)]
        );
    }

    #[test]
    fn the_hex_form_follows_the_configured_case_only() {
        let matcher = build(&[TokenSpec::new("billing-canary", [INVOICE]).case_insensitive(true)]);
        let configured = String::from_utf8(crate::detect::pattern::hex_lower(INVOICE.as_bytes()))
            .expect("hex is ASCII");
        let lowered = String::from_utf8(crate::detect::pattern::hex_lower(
            INVOICE.to_lowercase().as_bytes(),
        ))
        .expect("hex is ASCII");
        assert_eq!(
            scan(&matcher, configured.as_bytes()),
            [hit("billing-canary", 0, PatternForm::Hex, 0..42)]
        );
        assert_eq!(scan(&matcher, lowered.as_bytes()), []);
    }

    #[test]
    fn the_second_automaton_exists_only_when_a_token_needs_it() {
        let strict = build(&[TokenSpec::new("strict", ["Strict.Value.0001"])]);
        assert!(strict.inner.exact.is_some());
        assert!(strict.inner.folded.is_none());
        assert_eq!(strict.pattern_count(), 2);

        let loose = build(&[
            TokenSpec::new("strict", ["Strict.Value.0001"]),
            TokenSpec::new("loose", ["Loose.Value.0002"]).case_insensitive(true),
        ]);
        assert!(loose.inner.folded.is_some());
        assert_eq!(loose.pattern_count(), 5);

        // A value without letters is the same in every case, so asking for
        // case-insensitive matching adds nothing.
        let digits =
            build(&[TokenSpec::new("digits", ["4929-0000-0000-0017"]).case_insensitive(true)]);
        assert!(digits.inner.folded.is_none());
        assert_eq!(digits.pattern_count(), 2);
        assert_eq!(
            scan(&digits, b"card 4929-0000-0000-0017"),
            [hit("digits", 0, PatternForm::Raw, 5..24)]
        );
    }

    #[test]
    fn the_longest_pattern_is_the_hex_form_of_the_longest_value() {
        let matcher = build(&[
            TokenSpec::new("short", ["0123456789ab"]),
            TokenSpec::new("long", [EMAIL]),
        ]);
        assert_eq!(matcher.token_count(), 2);
        assert_eq!(matcher.pattern_count(), 4);
        assert_eq!(matcher.max_pattern_len(), 2 * EMAIL.len());
        assert!(!matcher.is_empty());
        assert!(matcher.memory_usage() > 0);
    }

    #[test]
    fn bytes_outside_ascii_around_a_value_do_not_matter() {
        let matcher = build(&[TokenSpec::new("users-admin-backup", [EMAIL])]);
        let mut haystack = vec![0x00, 0xff, 0xc3, 0xa9];
        haystack.extend_from_slice(EMAIL.as_bytes());
        haystack.extend_from_slice(&[0x80, 0x00]);
        assert_eq!(
            scan(&matcher, &haystack),
            [hit("users-admin-backup", 0, PatternForm::Raw, 4..34)]
        );
    }

    #[test]
    fn stopping_early_is_allowed() {
        let matcher = build(&[TokenSpec::new("users-admin-backup", [EMAIL])]);
        let haystack = format!("{EMAIL} {EMAIL} {EMAIL}");
        let mut matches = matcher.scan(haystack.as_bytes());
        assert!(matches.next().is_some_and(|first| first.is_ok()));
        drop(matches);
        assert_eq!(matcher.scan(haystack.as_bytes()).count(), 3);
    }

    #[test]
    fn the_iterator_stays_finished() {
        let matcher = build(&[TokenSpec::new("users-admin-backup", [EMAIL])]);
        let mut matches = matcher.scan(EMAIL.as_bytes());
        assert!(matches.next().is_some());
        assert!(matches.next().is_none());
        assert!(matches.next().is_none());
    }

    #[test]
    fn matches_sort_by_offset() {
        let matcher = build(&[
            TokenSpec::new("a", ["alpha-0001-zulu"]),
            TokenSpec::new("b", ["bravo-0002-yankee"]),
        ]);
        let mut matches = matcher
            .scan(b"bravo-0002-yankee alpha-0001-zulu bravo-0002-yankee")
            .collect::<Result<Vec<_>, _>>()
            .expect("the scan succeeds");
        matches.sort();
        let starts: Vec<u64> = matches.iter().map(Match::start).collect();
        assert_eq!(starts, [0, 18, 34]);
    }

    #[test]
    fn a_matcher_is_shared_between_threads() {
        fn assert_shareable<T: Send + Sync + Clone>() {}
        assert_shareable::<Matcher>();
        fn assert_send<T: Send>() {}
        assert_send::<Match>();
        assert_send::<Matches<'_>>();

        let matcher = build(&[
            TokenSpec::new("users-admin-backup", [EMAIL]),
            TokenSpec::new("billing-canary", [INVOICE]).case_insensitive(true),
        ]);
        let counts: Vec<usize> = std::thread::scope(|scope| {
            let workers: Vec<_> = (0..4)
                .map(|worker| {
                    let matcher = matcher.clone();
                    scope.spawn(move || {
                        let haystack = format!("{worker}:{EMAIL}:{}", INVOICE.to_uppercase());
                        (0..200)
                            .map(|_| matcher.scan(haystack.as_bytes()).count())
                            .sum::<usize>()
                    })
                })
                .collect();
            workers
                .into_iter()
                .map(|worker| worker.join().expect("the worker does not panic"))
                .collect()
        });
        assert_eq!(counts, [400, 400, 400, 400]);
    }

    #[test]
    fn debug_output_shows_sizes_and_no_patterns() {
        let matcher = build(&[TokenSpec::new("billing-canary", [INVOICE]).case_insensitive(true)]);
        let debug = format!("{matcher:?}");
        assert!(debug.starts_with("Matcher { tokens: 1, patterns: 3, max_pattern_len: 42"));
        assert!(!debug.to_lowercase().contains("canary"));
        assert!(!debug.contains("43616e617279"));

        let matches = matcher.scan(INVOICE.as_bytes());
        assert_eq!(format!("{matches:?}"), "Matches { .. }");
    }
}
