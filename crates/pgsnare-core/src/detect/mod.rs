// SPDX-License-Identifier: Apache-2.0

//! Honeytoken detection: pattern derivation, the matcher and the stream scanner.
//!
//! This module answers one question: is a honeytoken value in these bytes?
//! It knows nothing about the wire protocol, sessions or what happens after
//! a hit.
//!
//! # Overview
//!
//! - A [`TokenSpec`] describes one token: an id, its values and whether
//!   letter case is ignored.
//! - [`Matcher::build`] checks a list of tokens and compiles it. The matcher
//!   is immutable and can be shared by every thread.
//! - [`Matcher::scan`] looks through a whole buffer.
//! - [`Matcher::stream`] gives a [`StreamScanner`] for a message that arrives
//!   in chunks. It finds exactly what a scan of the whole message would.
//! - A [`Match`] names the token, the value by position, the
//!   [`PatternForm`] and the offset. It never contains the value.
//!
//! ```
//! use pgsnare_core::detect::{Matcher, PatternForm, TokenSpec};
//!
//! let tokens = [
//!     TokenSpec::new("users-admin-backup", ["svc.backup.8f3k2q@mail.example"]),
//!     TokenSpec::new("billing-canary", ["Canary.Invoice.000417"]).case_insensitive(true),
//! ];
//! let matcher = Matcher::build(&tokens)?;
//!
//! // A whole message: a CSV line as COPY sends it.
//! let hits = matcher
//!     .scan(b"417,CANARY.INVOICE.000417,2026-01-31\n")
//!     .collect::<Result<Vec<_>, _>>()?;
//! assert_eq!(hits.len(), 1);
//! assert_eq!(hits[0].token_id().as_str(), "billing-canary");
//! assert_eq!(hits[0].form(), PatternForm::CaseInsensitive);
//! assert_eq!(hits[0].start(), 4);
//!
//! // The same matcher, for a message that arrives in pieces. The value is
//! // in hexadecimal here, as PostgreSQL prints a `bytea` column.
//! let mut scanner = matcher.stream();
//! let mut hits = Vec::new();
//! for chunk in [&br"\x7376632e6261636b75702e3866"[..], b"336b327140", b"6d61696c2e6578616d706c65"] {
//!     for hit in scanner.feed(chunk) {
//!         hits.push(hit?);
//!     }
//! }
//! assert_eq!(hits.len(), 1);
//! assert_eq!(hits[0].token_id().as_str(), "users-admin-backup");
//! assert_eq!(hits[0].form(), PatternForm::Hex);
//! assert_eq!(hits[0].start(), 2);
//! # Ok::<(), Box<dyn std::error::Error>>(())
//! ```
//!
//! # Values and patterns
//!
//! A value must be ASCII and at least [`MIN_VALUE_LEN`] bytes long. ASCII
//! characters are the same bytes in every character encoding PostgreSQL
//! supports for clients, so matching does not depend on `client_encoding`.
//! The minimum length makes an accidental match implausible.
//!
//! Each value is compiled into these patterns:
//!
//! | Form | Pattern | Finds |
//! |---|---|---|
//! | [`PatternForm::Raw`] | The bytes of the value | The value wherever it is printed as it is: text and binary results, JSON, arrays, composite rows, CSV, COPY output, error messages, query text |
//! | [`PatternForm::Hex`] | The value as lowercase hexadecimal digits | The value inside a `bytea` printed in text format, and the output of `encode(…, 'hex')` |
//! | [`PatternForm::CaseInsensitive`] | The value with ASCII letter case ignored | Only for tokens that ask for it: the value after `upper()`, `lower()` or the like |
//!
//! Matching is on substrings of raw bytes. That is what lets one code path
//! find a value nested in JSON, in an array or in an aggregated string.
//!
//! All patterns are searched in one pass with the Aho-Corasick algorithm.
//! Case-insensitive patterns live in a second automaton, which is built only
//! if a token needs it.
//!
//! # What is reported
//!
//! Every occurrence of every pattern is reported, including occurrences that
//! overlap each other. If two tokens appear in the same message, both are
//! found, wherever they are.
//!
//! One occurrence gives one match. In particular, a case-insensitive token
//! found in exactly its configured case is reported as
//! [`PatternForm::Raw`], and as [`PatternForm::CaseInsensitive`] only when
//! at least one letter differs in case.
//!
//! The order in which matches are reported is not specified. [`Match`]
//! implements `Ord`, by offset, for callers that want to sort.
//!
//! # Rules for a token list
//!
//! [`Matcher::build`] refuses a list in which
//!
//! - an id is empty or is used by two tokens,
//! - a token has no values,
//! - a value is not ASCII or is shorter than [`MIN_VALUE_LEN`] bytes,
//! - the same value is given twice, or
//! - a value contains another value.
//!
//! The last two rules guarantee that data matching one value never sets off
//! another. They cover every text the matcher accepts for a value: the value
//! as configured, its hex form, and, for a case-insensitive token, the value
//! in any letter case. A value is therefore also refused if, for example, it
//! contains the hex form of another value.
//!
//! All problems are reported together, as a [`ValidationErrors`] list.
//!
//! # Secrecy
//!
//! Token values are secrets: someone who knows a value can avoid it.
//!
//! - [`TokenValue`] prints as `<redacted>` in `Debug` and `Display`.
//! - No error in this module has a field that can hold a value. Errors name
//!   a token by id and a value by position, as in
//!   `values[1] of token "users-admin-backup"`.
//! - [`Matcher`], [`StreamScanner`] and [`Matches`] print only counters in
//!   `Debug`. They hold the compiled values and the scanned traffic.
//!
//! Values are not wiped from memory when they are dropped.
//!
//! # Limits of substring matching
//!
//! A value is found only where its bytes appear unchanged, or in one of the
//! forms above.
//!
//! - **Escaped characters.** Text formats change some characters when they
//!   print a value:
//!
//!   | Character | Escaped or doubled in |
//!   |---|---|
//!   | Double quote | JSON, arrays, composite rows, CSV |
//!   | Backslash | JSON, arrays, composite rows, COPY text output |
//!   | Control characters, such as a tab | JSON, COPY text output |
//!   | `<`, `>` and `&` | XML |
//!   | Single quote | A string literal in a query |
//!
//!   A value that contains such a character is found where it is printed as
//!   it is, and missed where it was escaped. Values made of letters, digits
//!   and punctuation such as `.`, `-`, `_`, `@` and `:` are not affected.
//! - **Hexadecimal.** Only lowercase digits are looked for, and only for the
//!   value in its configured letter case.
//! - **Binary results.** In the binary result format a text, `bytea` or JSON
//!   value is sent as its bytes and is found. A number, a date or a `uuid`
//!   is sent in another encoding, so a value kept in such a column is missed
//!   there.
//! - **Other transformations.** A value that was hashed, cut, encoded in
//!   another way or encrypted before it was sent does not match.
//! - **Split values.** A scanner finds a value split across the chunks it is
//!   fed. Bytes it is never fed, such as the bytes of another message, are
//!   not seen.

mod error;
mod matcher;
mod pattern;
mod stream;
mod token;
mod validate;

pub use error::{BuildError, ScanError, ValidationError, ValidationErrors, ValueLocation};
pub use matcher::{Match, Matcher, Matches};
pub use pattern::{MIN_VALUE_LEN, PatternForm};
pub use stream::StreamScanner;
pub use token::{TokenId, TokenSpec, TokenValue};
