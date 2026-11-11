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

#[cfg(test)]
mod tests {
    use super::*;
    use crate::detect::{Match, PatternForm, TokenSpec};

    const EMAIL: &str = "svc.backup.8f3k2q@mail.example";
    const EMAIL_HEX: &str = "7376632e6261636b75702e3866336b3271406d61696c2e6578616d706c65";
    const INVOICE: &str = "Canary.Invoice.000417";

    fn matcher() -> Matcher {
        Matcher::build(&[
            TokenSpec::new("users-admin-backup", [EMAIL]),
            TokenSpec::new("billing-canary", [INVOICE]).case_insensitive(true),
            TokenSpec::new("repeating", ["abababababab"]),
        ])
        .expect("the token list is valid")
    }

    /// A message with every form in it, values next to each other, and an
    /// occurrence that overlaps itself.
    fn message() -> Vec<u8> {
        format!(
            "{EMAIL}|{}|\\x{EMAIL_HEX}|{INVOICE}{EMAIL}|ababababababababab|{}",
            INVOICE.to_uppercase(),
            &EMAIL[..EMAIL.len() - 1],
        )
        .into_bytes()
    }

    fn whole(matcher: &Matcher, haystack: &[u8]) -> Vec<Match> {
        let mut matches = matcher
            .scan(haystack)
            .collect::<Result<Vec<_>, _>>()
            .expect("the scan succeeds");
        matches.sort();
        matches
    }

    fn streamed<'c>(matcher: &Matcher, chunks: impl IntoIterator<Item = &'c [u8]>) -> Vec<Match> {
        let mut scanner = matcher.stream();
        let mut matches = Vec::new();
        for chunk in chunks {
            for found in scanner.feed(chunk) {
                matches.push(found.expect("the scan succeeds"));
            }
        }
        matches.sort();
        matches
    }

    #[test]
    fn the_message_used_here_contains_every_kind_of_match() {
        let found = whole(&matcher(), &message());
        let forms: Vec<PatternForm> = found.iter().map(Match::form).collect();
        assert_eq!(
            forms,
            [
                PatternForm::Raw,             // the email
                PatternForm::CaseInsensitive, // the invoice in uppercase
                PatternForm::Hex,             // the email in hex
                PatternForm::Raw,             // the invoice as configured
                PatternForm::Raw,             // the email right after it
                PatternForm::Raw,             // the repeating value,
                PatternForm::Raw,             // which overlaps itself
                PatternForm::Raw,
                PatternForm::Raw,
            ]
        );
    }

    #[test]
    fn one_chunk_gives_the_same_matches_as_a_whole_scan() {
        let matcher = matcher();
        let message = message();
        assert_eq!(
            streamed(&matcher, [message.as_slice()]),
            whole(&matcher, &message)
        );
    }

    #[test]
    fn a_split_at_any_position_changes_nothing() {
        let matcher = matcher();
        let message = message();
        let expected = whole(&matcher, &message);
        for cut in 0..=message.len() {
            let (head, tail) = message.split_at(cut);
            assert_eq!(streamed(&matcher, [head, tail]), expected, "cut at {cut}");
        }
    }

    #[test]
    fn two_splits_at_any_positions_change_nothing() {
        let matcher = matcher();
        // A shorter message keeps the number of combinations reasonable.
        let message = format!("{INVOICE}{EMAIL}|abababababababab").into_bytes();
        let expected = whole(&matcher, &message);
        assert_eq!(expected.len(), 5);
        for first in 0..=message.len() {
            for second in first..=message.len() {
                let chunks = [
                    &message[..first],
                    &message[first..second],
                    &message[second..],
                ];
                assert_eq!(
                    streamed(&matcher, chunks),
                    expected,
                    "cuts at {first} and {second}"
                );
            }
        }
    }

    #[test]
    fn chunks_of_any_fixed_size_change_nothing() {
        let matcher = matcher();
        let message = message();
        let expected = whole(&matcher, &message);
        // From one byte at a time to sizes around the carried length and
        // beyond the longest pattern.
        for size in 1..=(matcher.max_pattern_len() + 3) {
            assert_eq!(
                streamed(&matcher, message.chunks(size)),
                expected,
                "chunks of {size}"
            );
        }
    }

    #[test]
    fn empty_chunks_change_nothing() {
        let matcher = matcher();
        let message = message();
        let expected = whole(&matcher, &message);
        let (head, tail) = message.split_at(40);
        let empty: &[u8] = &[];
        assert_eq!(
            streamed(&matcher, [empty, head, empty, empty, tail, empty]),
            expected
        );
        assert_eq!(streamed(&matcher, [empty, empty]), []);
    }

    #[test]
    fn a_match_is_reported_by_the_chunk_that_completes_it() {
        let matcher = matcher();
        let mut scanner = matcher.stream();
        let chunks: [&[u8]; 4] = [b"7\tsvc.back", b"up.8f3k2q@", b"mail.example", b"\t\\N\n"];
        let mut seen = Vec::new();
        for chunk in chunks {
            let found = scanner
                .feed(chunk)
                .collect::<Result<Vec<_>, _>>()
                .expect("the scan succeeds");
            seen.push(
                found
                    .iter()
                    .map(|found| (found.start(), found.end()))
                    .collect::<Vec<_>>(),
            );
        }
        assert_eq!(seen, [vec![], vec![], vec![(2, 32)], vec![]]);
    }

    #[test]
    fn offsets_count_from_the_start_of_the_stream() {
        let matcher = matcher();
        let mut scanner = matcher.stream();
        let padding = vec![b'.'; 100_000];
        assert_eq!(scanner.feed(&padding).count(), 0);
        assert_eq!(scanner.feed(&padding).count(), 0);
        let found = scanner
            .feed(EMAIL.as_bytes())
            .collect::<Result<Vec<_>, _>>()
            .expect("the scan succeeds");
        assert_eq!(found.len(), 1);
        assert_eq!(found[0].range(), 200_000..200_030);
        assert_eq!(scanner.position(), 200_030);
    }

    #[test]
    fn unread_matches_do_not_disturb_later_chunks() {
        let matcher = matcher();
        let message = message();
        let expected = whole(&matcher, &message);
        let cut = 45;
        let (head, tail) = message.split_at(cut);

        let mut scanner = matcher.stream();
        // The matches of the first chunk are dropped without being read.
        let _ = scanner.feed(head);
        let mut later = scanner
            .feed(tail)
            .collect::<Result<Vec<_>, _>>()
            .expect("the scan succeeds");
        later.sort();

        let expected_later: Vec<Match> = expected
            .into_iter()
            .filter(|found| found.end() > cut as u64)
            .collect();
        assert_eq!(later, expected_later);
    }

    #[test]
    fn the_carried_bytes_stay_within_the_bound() {
        let matcher = matcher();
        let bound = matcher.max_pattern_len() - 1;
        let mut scanner = matcher.stream();
        assert_eq!(scanner.carried_len(), 0);

        let mut fed = 0;
        for size in [
            1,
            2,
            3,
            10,
            bound - 1,
            bound,
            bound + 1,
            1,
            5000,
            0,
            7,
            100_000,
            3,
        ] {
            let chunk = vec![b'x'; size];
            let _ = scanner.feed(&chunk);
            fed += size;
            assert_eq!(scanner.carried_len(), fed.min(bound), "after {fed} bytes");
            assert_eq!(scanner.position(), fed as u64);
        }
    }

    #[test]
    fn the_buffers_never_grow() {
        let matcher = matcher();
        let bound = matcher.max_pattern_len() - 1;
        let mut scanner = matcher.stream();
        let carry_capacity = scanner.carry.capacity();
        let seam_capacity = scanner.seam.capacity();
        assert!(carry_capacity >= bound);
        assert!(seam_capacity >= 2 * bound);

        let message = message();
        for size in [1, 7, bound - 1, bound, bound + 1, 4096] {
            for _ in 0..3 {
                for chunk in message.chunks(size) {
                    let _ = scanner.feed(chunk);
                    assert!(scanner.carry.len() <= bound);
                    assert!(scanner.seam.len() <= 2 * bound);
                }
            }
        }
        let megabyte = vec![b'a'; 1 << 20];
        let _ = scanner.feed(&megabyte);

        assert_eq!(scanner.carry.capacity(), carry_capacity);
        assert_eq!(scanner.seam.capacity(), seam_capacity);
    }

    #[test]
    fn reset_starts_a_new_stream() {
        let matcher = matcher();
        let mut scanner = matcher.stream();
        let (head, tail) = EMAIL.as_bytes().split_at(10);

        assert_eq!(scanner.feed(head).count(), 0);
        scanner.reset();
        assert_eq!(scanner.position(), 0);
        assert_eq!(scanner.carried_len(), 0);
        // The first half was forgotten, so the second half completes nothing.
        assert_eq!(scanner.feed(tail).count(), 0);

        scanner.reset();
        assert_eq!(scanner.feed(head).count(), 0);
        let found = scanner
            .feed(tail)
            .collect::<Result<Vec<_>, _>>()
            .expect("the scan succeeds");
        assert_eq!(found.len(), 1);
        assert_eq!(found[0].range(), 0..30);
    }

    #[test]
    fn a_scanner_of_an_empty_matcher_finds_nothing() {
        let matcher = Matcher::build(&[]).expect("an empty list is valid");
        let mut scanner = matcher.stream();
        assert_eq!(scanner.feed(b"some bytes").count(), 0);
        assert_eq!(scanner.feed(b"and more").count(), 0);
        assert_eq!(scanner.position(), 18);
        assert_eq!(scanner.carried_len(), 0);
    }

    #[test]
    fn a_scanner_can_move_to_another_thread() {
        fn assert_send<T: Send>() {}
        assert_send::<StreamScanner>();

        let matcher = matcher();
        let mut scanner = matcher.stream();
        let (head, tail) = EMAIL.as_bytes().split_at(17);
        assert_eq!(scanner.feed(head).count(), 0);
        let found = std::thread::spawn(move || scanner.feed(tail).count())
            .join()
            .expect("the worker does not panic");
        assert_eq!(found, 1);
    }

    #[test]
    fn debug_output_shows_counters_and_no_traffic() {
        let matcher = matcher();
        let mut scanner = matcher.stream();
        let _ = scanner.feed(b"password=hunter2-not-a-real-one");
        let debug = format!("{scanner:?}");
        assert_eq!(
            debug,
            "StreamScanner { position: 31, carried_len: 31, keep: 59, .. }"
        );
    }
}
