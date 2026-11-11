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
