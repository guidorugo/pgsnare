// SPDX-License-Identifier: Apache-2.0

//! Redaction: the one place everything passes through before it leaves the
//! process.
//!
//! pgsnare writes in three ways, and all three come through this module:
//!
//! | What is written | How it passes |
//! |---|---|
//! | An event, to the sinks | The dispatcher calls [`Redactor::event`] on every event before any sink sees it |
//! | A line of the log | The format of [`crate::log`] passes every text of a line through [`Redactor::text`] |
//! | The label of a metric | A name becomes a label through [`Redactor::label`], and in no other way |
//!
//! # What is removed
//!
//! - **Honeytoken values**, in every form the matcher finds them in: as
//!   written, as lowercase hexadecimal digits and, for a token that asks
//!   for it, in any letter case. The patterns are the matcher's own, so
//!   what detection finds, redaction removes.
//! - **The beginning of a honeytoken value where a text was cut.** A name
//!   that is too long for an event is cut and marked, and the cut can fall
//!   inside a value. What is left of the value is removed with the rest.
//! - **Other texts that must not be shown**, such as the URL of a webhook,
//!   which can hold a secret of its own.
//!
//! Each is replaced by [`REDACTED`].
//!
//! # What is not here
//!
//! Key material is not looked for. A signing key and a private key never
//! exist in a form that could be written: they are handed to the
//! cryptographic library, the bytes that were read are wiped, and no
//! error, log line or event is built from them. Looking for them in
//! everything that is written would mean keeping a second copy of every key
//! for as long as the process runs.
//!
//! Passwords and bind parameters are not looked for either. pgsnare relays
//! them without keeping them, and no event, log line or metric has a place
//! for one.
//!
//! # One redactor for the process
//!
//! A [`Redaction`] is a handle on the [`Redactor`] in force. The log, the
//! dispatcher and the metrics hold the same handle, so replacing the
//! redactor, as a reload of the tokens will, takes effect for all three at
//! once.

use std::borrow::Cow;
use std::fmt;
use std::ops::Range;
use std::sync::{Arc, PoisonError, RwLock};

use aho_corasick::AhoCorasick;
use pgsnare_core::detect::{BuildError, Matcher, TokenSpec};
use pgsnare_core::event::{EventBody, TRUNCATION_MARK};

mod fingerprint;

pub use fingerprint::Sha256;

/// What stands where something was removed.
pub const REDACTED: &str = "[redacted]";

/// The shortest beginning of a honeytoken value that is removed where a
/// text was cut. A shorter one tells nothing, and would be found by chance
/// at the end of many texts.
pub const MIN_CUT_VALUE_BYTES: usize = 4;

/// The shortest other text a redactor takes. A shorter one would be found
/// by chance in what has nothing to do with it.
pub const MIN_SECRET_TEXT_BYTES: usize = 8;

/// The longest label a metric gets, in bytes.
pub const MAX_LABEL_BYTES: usize = 128;

/// Why a redactor could not be built.
#[derive(Debug)]
#[non_exhaustive]
pub enum RedactError {
    /// The honeytokens break a rule of the matcher. The error names tokens
    /// by id and values by position, never by content.
    Tokens(BuildError),
    /// The other texts could not be compiled into one search.
    Secrets,
}

impl fmt::Display for RedactError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Tokens(error) => write!(f, "{error}"),
            Self::Secrets => {
                f.write_str("the texts that must not be shown are too many or too long to compile")
            }
        }
    }
}

impl std::error::Error for RedactError {}

/// Knows what must not leave the process, and removes it from what does.
///
/// A redactor never changes. A reload builds a new one and puts it in the
/// place of the old one: see [`Redaction::replace`].
#[derive(Default)]
pub struct Redactor {
    /// The matcher over every honeytoken value. `None` without tokens.
    tokens: Option<Matcher>,
    /// For the search at a cut: what a value is found as when letter case
    /// counts, in order.
    cut_exact: Vec<Vec<u8>>,
    /// The same for the values whose letter case is ignored, in lower
    /// case.
    cut_folded: Vec<Vec<u8>>,
    /// The length of the longest of those patterns.
    longest_pattern: usize,
    /// The other texts. `None` when there are none.
    secrets: Option<AhoCorasick>,
    secret_count: usize,
}

impl Redactor {
    /// A redactor that knows nothing to remove.
    #[must_use]
    pub fn nothing() -> Self {
        Self::default()
    }

    /// Starts a redactor.
    #[must_use]
    pub fn builder() -> RedactorBuilder {
        RedactorBuilder::default()
    }

    /// A text without what must not be shown.
    ///
    /// The text is returned as it is when there is nothing to remove, which
    /// is the usual case.
    #[must_use]
    pub fn text<'a>(&self, text: &'a str) -> Cow<'a, str> {
        let Some(ranges) = self.find(text) else {
            // The search itself failed. Nothing of the text is shown.
            return Cow::Borrowed(REDACTED);
        };
        if ranges.is_empty() {
            return Cow::Borrowed(text);
        }

        let mut clean = String::with_capacity(text.len());
        let mut copied = 0;
        for range in ranges {
            clean.push_str(text.get(copied..range.start).unwrap_or_default());
            clean.push_str(REDACTED);
            copied = range.end;
        }
        clean.push_str(text.get(copied..).unwrap_or_default());
        Cow::Owned(clean)
    }

    /// Removes what must not be shown from every text of an event that
    /// comes from the network.
    pub fn event(&self, body: &mut EventBody) {
        body.for_each_text_mut(|text| {
            if let Cow::Owned(clean) = self.text(text) {
                *text = clean;
            }
        });
    }

    /// The label of a metric for a name from the configuration.
    ///
    /// The name is redacted like any other text. What then is not an ASCII
    /// letter, a digit or one of `.`, `_`, `:` and `-` becomes `_`, and the
    /// label is cut at [`MAX_LABEL_BYTES`]. A label can therefore neither
    /// break the format of the metrics nor grow without bound, whatever
    /// the name it was made from.
    #[must_use]
    pub fn label(&self, name: &str) -> String {
        self.text(name)
            .chars()
            .map(|character| {
                if character.is_ascii_alphanumeric() || matches!(character, '.' | '_' | ':' | '-') {
                    character
                } else {
                    '_'
                }
            })
            .take(MAX_LABEL_BYTES)
            .collect()
    }

    /// Whether there is anything this redactor would remove.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.tokens.is_none() && self.secrets.is_none()
    }

    /// The parts of `text` to remove, in order and without overlap, each
    /// from one character boundary to another. `None` when the search
    /// failed.
    fn find(&self, text: &str) -> Option<Vec<Range<usize>>> {
        let bytes = text.as_bytes();
        let mut found: Vec<Range<usize>> = Vec::new();

        if let Some(tokens) = &self.tokens {
            for hit in tokens.scan(bytes) {
                let hit = hit.ok()?;
                let start = usize::try_from(hit.start()).ok()?;
                let end = usize::try_from(hit.end()).ok()?;
                found.push(start..end);
            }
        }
        if let Some(secrets) = &self.secrets {
            for hit in secrets.find_overlapping_iter(bytes) {
                found.push(hit.start()..hit.end());
            }
        }
        if let Some(cut) = self.cut_value(text) {
            found.push(cut);
        }
        if found.is_empty() {
            return Some(found);
        }

        found.sort_by_key(|range| (range.start, range.end));
        let mut merged: Vec<Range<usize>> = Vec::with_capacity(found.len());
        for range in found {
            // A pattern is made of bytes, and the text of characters. A
            // range is widened to whole characters, so that cutting the
            // text there is always possible.
            let start = floor_char_boundary(text, range.start);
            let end = ceil_char_boundary(text, range.end);
            match merged.last_mut() {
                Some(last) if start <= last.end => last.end = last.end.max(end),
                _ => merged.push(start..end),
            }
        }
        Some(merged)
    }

    /// Where a text that was cut ends with the beginning of a honeytoken
    /// value: the part between that beginning and the mark of the cut.
    fn cut_value(&self, text: &str) -> Option<Range<usize>> {
        if self.longest_pattern == 0 {
            return None;
        }
        let kept = text.strip_suffix(TRUNCATION_MARK)?.as_bytes();
        // A value that is there in full has been found by the matcher. Only
        // a proper beginning is looked for, which is shorter than the
        // longest pattern.
        let window = self.longest_pattern.saturating_sub(1).min(kept.len());
        let first = kept.len().saturating_sub(window);
        let last = kept.len().checked_sub(MIN_CUT_VALUE_BYTES)?;
        let folded = if self.cut_folded.is_empty() {
            Vec::new()
        } else {
            kept.to_ascii_lowercase()
        };
        // The longest beginning first.
        (first..=last)
            .find(|start| {
                begins_one_of(&self.cut_exact, kept.get(*start..).unwrap_or_default())
                    || (!folded.is_empty()
                        && begins_one_of(
                            &self.cut_folded,
                            folded.get(*start..).unwrap_or_default(),
                        ))
            })
            .map(|start| start..kept.len())
    }
}

/// Whether one of `patterns`, which are in order, begins with `tail` and
/// goes on after it.
fn begins_one_of(patterns: &[Vec<u8>], tail: &[u8]) -> bool {
    // Everything that begins with `tail` sorts at or after `tail`, and the
    // first pattern there begins with it if any does.
    let at = patterns.partition_point(|pattern| pattern.as_slice() < tail);
    patterns
        .get(at..)
        .unwrap_or_default()
        .iter()
        .take_while(|pattern| pattern.starts_with(tail))
        .any(|pattern| pattern.len() > tail.len())
}

/// The last character boundary of `text` at or before `index`.
fn floor_char_boundary(text: &str, index: usize) -> usize {
    let mut index = index.min(text.len());
    while !text.is_char_boundary(index) {
        index = index.saturating_sub(1);
    }
    index
}

/// The first character boundary of `text` at or after `index`.
fn ceil_char_boundary(text: &str, index: usize) -> usize {
    let mut index = index.min(text.len());
    while !text.is_char_boundary(index) {
        index = index.saturating_add(1);
    }
    index
}

/// Shows what a redactor is made of in numbers. It holds honeytoken values.
impl fmt::Debug for Redactor {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Redactor")
            .field(
                "tokens",
                &self.tokens.as_ref().map_or(0, Matcher::token_count),
            )
            .field("other_texts", &self.secret_count)
            .finish()
    }
}

/// Collects what a [`Redactor`] must remove.
#[derive(Default)]
pub struct RedactorBuilder {
    tokens: Vec<TokenSpec>,
    secrets: Vec<Vec<u8>>,
}

impl RedactorBuilder {
    /// Adds a honeytoken: its id, its values, and whether its values are
    /// also found when their letters are in another case.
    #[must_use]
    pub fn token<'a>(
        mut self,
        id: &str,
        values: impl IntoIterator<Item = &'a str>,
        case_insensitive: bool,
    ) -> Self {
        self.tokens
            .push(TokenSpec::new(id, values).case_insensitive(case_insensitive));
        self
    }

    /// Adds a text that must not be shown, such as the URL of a webhook.
    ///
    /// A text shorter than [`MIN_SECRET_TEXT_BYTES`] is not taken: it would
    /// be found in what has nothing to do with it.
    #[must_use]
    pub fn secret_text(mut self, text: &str) -> Self {
        if text.len() >= MIN_SECRET_TEXT_BYTES
            && !self.secrets.iter().any(|known| known == text.as_bytes())
        {
            self.secrets.push(text.as_bytes().to_vec());
        }
        self
    }

    /// Compiles what was collected.
    ///
    /// # Errors
    ///
    /// Returns what is wrong with the honeytokens: the rules are those of
    /// [`Matcher::build`]. The error never contains a value.
    pub fn build(self) -> Result<Redactor, RedactError> {
        let Self { tokens, secrets } = self;

        let (mut cut_exact, mut cut_folded) = (Vec::new(), Vec::new());
        for token in &tokens {
            for value in token.values() {
                let raw = value.expose();
                if token.is_case_insensitive() {
                    cut_folded.push(raw.to_ascii_lowercase());
                } else {
                    cut_exact.push(raw.to_vec());
                }
                cut_exact.push(hexadecimal(raw));
            }
        }
        cut_exact.sort();
        cut_folded.sort();
        let longest_pattern = cut_exact
            .iter()
            .chain(&cut_folded)
            .map(Vec::len)
            .max()
            .unwrap_or(0);

        let tokens = if tokens.is_empty() {
            None
        } else {
            Some(Matcher::build(&tokens).map_err(RedactError::Tokens)?)
        };
        let secret_count = secrets.len();
        let secrets = if secrets.is_empty() {
            None
        } else {
            Some(AhoCorasick::new(&secrets).map_err(|_| RedactError::Secrets)?)
        };

        Ok(Redactor {
            tokens,
            cut_exact,
            cut_folded,
            longest_pattern,
            secrets,
            secret_count,
        })
    }
}

/// Bytes as lowercase hexadecimal digits, which is how the matcher looks
/// for a value inside a `bytea` that is printed as text.
fn hexadecimal(bytes: &[u8]) -> Vec<u8> {
    const DIGITS: &[u8; 16] = b"0123456789abcdef";
    let mut text = Vec::with_capacity(bytes.len().saturating_mul(2));
    for byte in bytes {
        text.push(DIGITS[usize::from(byte >> 4)]);
        text.push(DIGITS[usize::from(byte & 0x0f)]);
    }
    text
}

/// Shows how much was collected, and nothing of it.
impl fmt::Debug for RedactorBuilder {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("RedactorBuilder")
            .field("tokens", &self.tokens.len())
            .field("other_texts", &self.secrets.len())
            .finish()
    }
}

/// A handle on the redactor in force.
///
/// Cloning gives another handle on the same redactor. Every part of the
/// process that writes something holds one.
#[derive(Clone, Debug, Default)]
pub struct Redaction {
    current: Arc<RwLock<Arc<Redactor>>>,
}

impl Redaction {
    /// A handle on a redactor.
    #[must_use]
    pub fn new(redactor: Redactor) -> Self {
        Self {
            current: Arc::new(RwLock::new(Arc::new(redactor))),
        }
    }

    /// The redactor in force.
    #[must_use]
    pub fn current(&self) -> Arc<Redactor> {
        Arc::clone(&self.current.read().unwrap_or_else(PoisonError::into_inner))
    }

    /// Puts another redactor in force, for every holder of this handle.
    pub fn replace(&self, redactor: Redactor) {
        *self.current.write().unwrap_or_else(PoisonError::into_inner) = Arc::new(redactor);
    }

    /// A text without what must not be shown: [`Redactor::text`] of the
    /// redactor in force.
    #[must_use]
    pub fn text<'a>(&self, text: &'a str) -> Cow<'a, str> {
        self.current().text(text)
    }

    /// The label of a metric: [`Redactor::label`] of the redactor in force.
    #[must_use]
    pub fn label(&self, name: &str) -> String {
        self.current().label(name)
    }
}

#[cfg(test)]
mod tests;
