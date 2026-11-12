// SPDX-License-Identifier: Apache-2.0

//! The PostgreSQL wire format as pgsnare needs it: framing, typed views of
//! the messages it must understand, and encoders for the few messages it
//! injects.
//!
//! This crate performs no I/O. Every read of untrusted bytes is
//! bounds-checked and returns an error instead of panicking.
//!
//! # Parts
//!
//! - **Startup phase.** [`startup::classify`] tells what the first bytes of
//!   a connection are: a TLS handshake, an `SSLRequest`, a `GSSENCRequest`,
//!   a `CancelRequest` or a `StartupMessage`.
//! - **Framing.** A [`Framer`] locates the messages of one direction in a
//!   byte buffer. A [`Frame`] borrows from that buffer and can be forwarded
//!   as the identical bytes. A frame too large to hold is streamed: its
//!   header first, then its body in chunks. A streamed frame never exists
//!   in one piece, so it has no view.
//! - **Views.** The [`backend`] and [`frontend`] modules read a frame as a
//!   particular message and hand out its fields without copying them.
//! - **Encoders.** The [`encode`] module writes the few messages pgsnare
//!   injects or rewrites.
//!
//! # Guarantees
//!
//! - **A view never reads outside its frame.** A view is built from the
//!   bytes of one frame and holds nothing else, however much data follows
//!   the frame in the buffer.
//! - **Counts are checked before they are used.** A count taken from the
//!   wire is compared with the bytes left in the frame before anything
//!   loops over it. Nothing in this crate allocates in proportion to a
//!   number read from the wire.
//! - **A view accepts a whole message or nothing.** Parsing validates the
//!   complete body, including that no bytes are left over. Iterating over a
//!   parsed view cannot fail.
//! - **No content in errors or debug output.** Errors carry lengths and type
//!   bytes only, and the `Debug` output of frames and views shows sizes
//!   instead of content, so neither can carry a credential or a honeytoken
//!   value into a log.
//!
//! # Example
//!
//! ```
//! use pgsnare_proto::backend::{DataRow, Message};
//! use pgsnare_proto::{Direction, Framer, Limits, Step};
//!
//! # fn main() -> Result<(), Box<dyn std::error::Error>> {
//! // A DataRow with the columns "42" and NULL, as a server sends it.
//! let received = [
//!     b'D', 0, 0, 0, 16, // type and length
//!     0, 2, // two columns
//!     0, 0, 0, 2, b'4', b'2', // "42"
//!     0xff, 0xff, 0xff, 0xff, // NULL
//! ];
//!
//! let mut framer = Framer::new(Direction::FromServer, Limits::buffered_only(1 << 20));
//! let mut unread = &received[..];
//! let Step::Frame(frame) = framer.next(&mut unread)? else {
//!     return Err("the buffer holds one whole frame".into());
//! };
//!
//! // The frame is the bytes that arrived.
//! assert_eq!(frame.as_bytes(), received);
//!
//! let Message::DataRow(row) = Message::from_frame(frame)? else {
//!     return Err("the frame is a DataRow".into());
//! };
//! let columns: Vec<Option<&[u8]>> = row.iter().collect();
//! assert_eq!(columns, [Some(&b"42"[..]), None]);
//! assert_eq!(DataRow::TAG, b'D');
//! # Ok(())
//! # }
//! ```

#![forbid(unsafe_code)]
#![cfg_attr(
    not(test),
    deny(
        clippy::unwrap_used,
        clippy::expect_used,
        clippy::panic,
        clippy::indexing_slicing,
        clippy::arithmetic_side_effects
    )
)]
// Beyond the lints every pgsnare crate shares: no other way to panic, and
// no cast that could silently change a size read from the wire.
#![cfg_attr(
    not(test),
    deny(
        clippy::unreachable,
        clippy::todo,
        clippy::unimplemented,
        clippy::panic_in_result_fn,
        clippy::get_unwrap,
        clippy::string_slice,
        clippy::as_conversions
    )
)]
#![warn(missing_docs, missing_debug_implementations)]

pub mod backend;
pub mod encode;
mod error;
mod frame;
pub mod frontend;
mod message;
mod reader;
pub mod startup;
mod version;

pub use error::{EncodeError, FrameError, ParseError, StartupError};
pub use frame::{
    Chunk, Direction, Frame, FrameHeader, Framer, HEADER_LEN, Limits, MAX_LENGTH, MIN_LENGTH, Step,
};
pub use message::{CStrings, CopyData, FormatCode, FormatCodeIter, FormatCodes, ValueIter, Values};
pub use version::ProtocolVersion;

#[cfg(test)]
pub(crate) mod testutil {
    //! Helpers shared by the unit tests.

    use crate::frame::{Direction, Frame, Framer, Limits, Step};

    /// The wire bytes of a frame with the given type byte and body.
    pub(crate) fn wire(tag: u8, body: &[u8]) -> Vec<u8> {
        let mut bytes = vec![tag];
        bytes.extend_from_slice(&u32::try_from(body.len() + 4).unwrap().to_be_bytes());
        bytes.extend_from_slice(body);
        bytes
    }

    /// Frames `bytes`, which must hold exactly one frame.
    pub(crate) fn frame(direction: Direction, bytes: &[u8]) -> Frame<'_> {
        let mut framer = Framer::new(direction, Limits::buffered_only(usize::MAX));
        let mut unread = bytes;
        match framer.next(&mut unread) {
            Ok(Step::Frame(frame)) if unread.is_empty() => frame,
            other => panic!("expected exactly one frame, got {other:?}"),
        }
    }
}
