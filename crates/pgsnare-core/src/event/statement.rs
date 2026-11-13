// SPDX-License-Identifier: Apache-2.0

//! What an event shows of a statement: the redaction mode, applied.

use core::fmt::Write as _;

use crate::policy::QueryRedaction;

use super::{Query, text_from_wire};

/// The most bytes of a statement an event shows with
/// [`QueryRedaction::Full`]. A longer statement is cut and marked, so the
/// size of an event does not follow the size of a statement.
pub const MAX_STATEMENT_BYTES: usize = 4096;

/// The hash function behind the fingerprint of a statement.
///
/// This crate brings no hash function of its own. Whatever assembles the
/// proxy hands in the one of the cryptographic library it already uses, so
/// that a build holds one implementation and this crate keeps to
/// dependencies that are written in Rust.
///
/// A closure of the right shape is a `StatementDigest`.
pub trait StatementDigest: Send + Sync {
    /// The digest of a statement: the same 32 bytes whenever the statement
    /// is the same, and different ones, for all practical purposes, when
    /// it is not.
    fn digest(&self, statement: &[u8]) -> [u8; 32];
}

impl<F> StatementDigest for F
where
    F: Fn(&[u8]) -> [u8; 32] + Send + Sync,
{
    fn digest(&self, statement: &[u8]) -> [u8; 32] {
        self(statement)
    }
}

impl Query {
    /// What an event shows of a statement under a redaction mode.
    ///
    /// `statement` is the text of the statement as it came from the
    /// network, without its bind parameters, which no mode shows.
    ///
    /// | Mode | Result |
    /// |---|---|
    /// | `full` | The text, at most [`MAX_STATEMENT_BYTES`] of it |
    /// | `fingerprint` | The digest of the whole text, as 64 hexadecimal digits |
    /// | `none` | Nothing but the fact that the statement is known |
    ///
    /// # What a fingerprint tells
    ///
    /// The fingerprint is a hash of the text as it was sent, constants
    /// included. Two events with the same fingerprint belong to the same
    /// text, and somebody who has a statement can check whether an event
    /// belongs to it. That also holds for a guess: when a statement has a
    /// short constant in it, such as a four-digit code, a reader of events
    /// who knows the rest of the statement can try every value. A build
    /// with the SQL parser replaces this fingerprint with one that leaves
    /// constants out. Without it, `none` is the mode that tells nothing.
    ///
    /// # What this does not do
    ///
    /// A honeytoken value in the text of a statement is not removed here.
    /// That happens later, in one place, for every text of an event: see
    /// [`EventBody::for_each_text_mut`](super::EventBody::for_each_text_mut).
    #[must_use]
    pub fn from_statement(
        statement: &[u8],
        redaction: QueryRedaction,
        digest: &dyn StatementDigest,
    ) -> Self {
        match redaction {
            QueryRedaction::Full => Self::full(text_from_wire(statement, MAX_STATEMENT_BYTES)),
            QueryRedaction::Fingerprint => {
                Self::fingerprint(hexadecimal(&digest.digest(statement)), None)
            }
            QueryRedaction::None => Self::withheld(),
        }
    }
}

/// Bytes as lowercase hexadecimal digits.
fn hexadecimal(bytes: &[u8]) -> String {
    let mut text = String::with_capacity(bytes.len().saturating_mul(2));
    for byte in bytes {
        // Writing to a `String` cannot fail.
        let _ = write!(text, "{byte:02x}");
    }
    text
}

#[cfg(test)]
mod tests {
    use proptest::prelude::*;

    use super::super::TRUNCATION_MARK;
    use super::*;

    /// Not a hash anybody should use: it only has to depend on every byte.
    fn folding(statement: &[u8]) -> [u8; 32] {
        let mut digest = [0u8; 32];
        for (index, byte) in statement.iter().enumerate() {
            digest[index % 32] = digest[index % 32].rotate_left(3) ^ byte ^ (index as u8);
        }
        digest
    }

    const STATEMENT: &[u8] = b"SELECT * FROM users WHERE email = 'svc.backup.8f3k2q@mail.example'";

    #[test]
    fn full_shows_the_text() {
        let query = Query::from_statement(STATEMENT, QueryRedaction::Full, &folding);
        assert!(query.known);
        assert_eq!(query.redaction, QueryRedaction::Full);
        assert_eq!(query.text.as_deref().map(str::as_bytes), Some(STATEMENT));
        assert_eq!(query.fingerprint, None);
        assert_eq!(query.normalized, None);
    }

    #[test]
    fn fingerprint_shows_the_digest_and_nothing_of_the_text() {
        let query = Query::from_statement(STATEMENT, QueryRedaction::Fingerprint, &folding);
        assert!(query.known);
        assert_eq!(query.redaction, QueryRedaction::Fingerprint);
        assert_eq!(query.text, None);
        assert_eq!(query.normalized, None);

        let fingerprint = query.fingerprint.unwrap();
        assert_eq!(fingerprint.len(), 64);
        assert!(
            fingerprint
                .bytes()
                .all(|byte| matches!(byte, b'0'..=b'9' | b'a'..=b'f'))
        );
        assert_eq!(fingerprint, hexadecimal(&folding(STATEMENT)));

        // The same statement gives the same fingerprint, another one does
        // not.
        let again = Query::from_statement(STATEMENT, QueryRedaction::Fingerprint, &folding);
        assert_eq!(again.fingerprint.as_deref(), Some(fingerprint.as_str()));
        let other = Query::from_statement(b"SELECT 1", QueryRedaction::Fingerprint, &folding);
        assert_ne!(other.fingerprint.as_deref(), Some(fingerprint.as_str()));
    }

    #[test]
    fn none_shows_nothing() {
        let query = Query::from_statement(STATEMENT, QueryRedaction::None, &folding);
        assert_eq!(query, Query::withheld());
        let json = serde_json::to_string(&query).unwrap();
        assert!(!json.contains("users"), "{json}");
    }

    #[test]
    fn the_default_mode_is_fingerprint() {
        let query = Query::from_statement(STATEMENT, QueryRedaction::default(), &folding);
        assert_eq!(query.redaction, QueryRedaction::Fingerprint);
        assert!(query.fingerprint.is_some());
        assert_eq!(query.text, None);
    }

    #[test]
    fn a_long_statement_is_cut_and_its_fingerprint_covers_all_of_it() {
        let mut long = vec![b'x'; MAX_STATEMENT_BYTES];
        long.extend_from_slice(b" AND secret = 1");
        let shown = Query::from_statement(&long, QueryRedaction::Full, &folding)
            .text
            .unwrap();
        assert_eq!(
            shown.len(),
            MAX_STATEMENT_BYTES + TRUNCATION_MARK.len_utf8()
        );
        assert!(shown.ends_with(TRUNCATION_MARK));
        assert!(!shown.contains("secret"));

        // Two statements that differ only past the cut are told apart.
        let mut other = long.clone();
        *other.last_mut().unwrap() = b'2';
        let fingerprint = |statement: &[u8]| {
            Query::from_statement(statement, QueryRedaction::Fingerprint, &folding).fingerprint
        };
        assert_ne!(fingerprint(&long), fingerprint(&other));
    }

    #[test]
    fn text_that_is_not_utf8_is_still_text() {
        let query = Query::from_statement(b"SELECT '\xff'", QueryRedaction::Full, &folding);
        assert_eq!(query.text.as_deref(), Some("SELECT '\u{fffd}'"));
    }

    #[test]
    fn a_digest_can_be_a_type_of_its_own() {
        struct Zero;
        impl StatementDigest for Zero {
            fn digest(&self, _statement: &[u8]) -> [u8; 32] {
                [0; 32]
            }
        }
        let query = Query::from_statement(STATEMENT, QueryRedaction::Fingerprint, &Zero);
        assert_eq!(query.fingerprint.as_deref(), Some("0".repeat(64).as_str()));
    }

    proptest! {
        #[test]
        fn no_mode_shows_more_than_it_says(
            statement in proptest::collection::vec(any::<u8>(), 0..6000),
        ) {
            let full = Query::from_statement(&statement, QueryRedaction::Full, &folding);
            let text = full.text.unwrap();
            prop_assert!(text.len() <= MAX_STATEMENT_BYTES + TRUNCATION_MARK.len_utf8());

            let fingerprint =
                Query::from_statement(&statement, QueryRedaction::Fingerprint, &folding);
            prop_assert_eq!(fingerprint.text, None);
            prop_assert_eq!(fingerprint.fingerprint.map(|text| text.len()), Some(64));

            let none = Query::from_statement(&statement, QueryRedaction::None, &folding);
            prop_assert_eq!(none, Query::withheld());
        }
    }
}
