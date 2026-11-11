// SPDX-License-Identifier: Apache-2.0

//! The streaming scan: the same matches as a whole-buffer scan, for input
//! that arrives in chunks.

use std::fmt;

use super::matcher::{Matcher, Matches, Region, widen};

/// Scans a message that arrives in chunks.
///
/// Feeding the chunks of a message one after another finds exactly the
/// matches that [`Matcher::scan`] finds in the whole message, with the same
/// offsets, however the message is cut up. A value split across two or more
/// chunks is found when its last byte arrives.
///
/// # State
///
/// Between chunks the scanner keeps the last `longest pattern − 1` bytes it
/// was fed, which is the most a match can reach back from a new chunk. While
/// a chunk is scanned it also holds a copy of those bytes joined to the same
/// number of bytes from the start of the chunk. Its memory therefore stays
/// below three times [`Matcher::max_pattern_len`], whatever the length of
/// the stream and the size of the chunks, and it never copies a whole chunk.
///
/// The carried bytes are traffic and may be sensitive. They are never
/// printed.
///
/// ```
/// use pgsnare_core::detect::{Matcher, TokenSpec};
///
/// let tokens = [TokenSpec::new("users-admin-backup", ["svc.backup.8f3k2q@mail.example"])];
/// let matcher = Matcher::build(&tokens)?;
///
/// let mut scanner = matcher.stream();
/// let mut hits = Vec::new();
/// for chunk in [&b"7\tsvc.back"[..], b"up.8f3k2q@mail", b".example\t\\N\n"] {
///     for hit in scanner.feed(chunk) {
///         hits.push(hit?);
///     }
/// }
///
/// assert_eq!(hits.len(), 1);
/// assert_eq!(hits[0].range(), 2..32);
/// # Ok::<(), Box<dyn std::error::Error>>(())
/// ```
pub struct StreamScanner {
    matcher: Matcher,
    /// The most bytes that are carried from one chunk to the next: the
    /// length of the longest pattern, less one.
    keep: usize,
    /// The last `keep` bytes fed so far, or all of them if fewer were fed.
    carry: Vec<u8>,
    /// Work space for one call of `feed`: the carried bytes followed by the
    /// first bytes of the new chunk.
    seam: Vec<u8>,
    /// The number of bytes fed so far.
    position: u64,
}

impl StreamScanner {
    /// Creates a scanner at the start of a stream.
    pub fn new(matcher: &Matcher) -> Self {
        let keep = matcher.max_pattern_len().saturating_sub(1);
        Self {
            matcher: matcher.clone(),
            keep,
            carry: Vec::with_capacity(keep),
            seam: Vec::with_capacity(keep.saturating_mul(2)),
            position: 0,
        }
    }

    /// Scans the next chunk of the stream.
    ///
    /// Returns the matches that end in this chunk, including those that
    /// began in an earlier one. Their offsets count from the start of the
    /// stream. The order of the matches is not specified.
    ///
    /// The scanner has taken the chunk into account as soon as this method
    /// returns. Reading only some of the matches, or none, loses nothing but
    /// those matches.
    ///
    /// An empty chunk is allowed and changes nothing.
    pub fn feed<'a>(&'a mut self, chunk: &'a [u8]) -> Matches<'a> {
        let carried = self.carry.len();
        let chunk_start = self.position;

        // A match that began in an earlier chunk lies within the carried
        // bytes plus the first `keep` bytes of this chunk. Join the two so
        // that such a match can be found in one piece.
        self.seam.clear();
        let mut seam = None;
        if carried > 0 && !chunk.is_empty() {
            let head = chunk.get(..self.keep).unwrap_or(chunk);
            self.seam.extend_from_slice(&self.carry);
            self.seam.extend_from_slice(head);
            seam = Some((chunk_start.saturating_sub(widen(carried)), carried));
        }

        // Keep the last `keep` bytes of the stream for the next chunk.
        let tail = chunk
            .len()
            .checked_sub(self.keep)
            .and_then(|from| chunk.get(from..));
        match tail {
            Some(tail) => {
                self.carry.clear();
                self.carry.extend_from_slice(tail);
            }
            None => {
                // The chunk is shorter than `keep`: drop just enough of the
                // oldest bytes to make room for it.
                let surplus = carried
                    .saturating_add(chunk.len())
                    .saturating_sub(self.keep)
                    .min(carried);
                self.carry.drain(..surplus);
                self.carry.extend_from_slice(chunk);
            }
        }
        self.position = chunk_start.saturating_add(widen(chunk.len()));

        // Everything is up to date. From here on the scanner is only read.
        let this: &'a Self = self;
        Matches::new(
            this.matcher.inner(),
            seam.map(|(base, joint)| Region {
                haystack: &this.seam,
                base,
                straddling: Some(joint),
            }),
            Region {
                haystack: chunk,
                base: chunk_start,
                straddling: None,
            },
        )
    }

    /// Forgets the stream so far, so that the scanner can be used for the
    /// next message. Offsets count from zero again.
    pub fn reset(&mut self) {
        self.carry.clear();
        self.seam.clear();
        self.position = 0;
    }

    /// The number of bytes fed since the scanner was created or reset. Past
    /// `u64::MAX` it stops counting; matches are still found.
    pub fn position(&self) -> u64 {
        self.position
    }

    /// The number of bytes currently carried over to the next chunk. Never
    /// more than [`Matcher::max_pattern_len`] less one.
    pub fn carried_len(&self) -> usize {
        self.carry.len()
    }
}

/// Shows counters only. The carried bytes are traffic and are never printed.
impl fmt::Debug for StreamScanner {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("StreamScanner")
            .field("position", &self.position)
            .field("carried_len", &self.carry.len())
            .field("keep", &self.keep)
            .finish_non_exhaustive()
    }
}
