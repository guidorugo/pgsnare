// SPDX-License-Identifier: Apache-2.0

//! The errors this crate returns.
//!
//! No error carries message content. An error holds at most a type byte, a
//! length, a count or a protocol version, so it can be logged without
//! revealing what the message contained.

use core::fmt;

use crate::frame::Direction;
use crate::version::ProtocolVersion;

/// Why the framer refused a frame header.
///
/// A framing error is final for its stream. The position of the next frame
/// is unknown, so nothing after the error can be trusted.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[non_exhaustive]
pub enum FrameError {
    /// The length field is below four, the size of the length field itself.
    LengthTooSmall {
        /// The type byte of the frame.
        tag: u8,
        /// The value of the length field.
        length: u32,
    },
    /// The frame is larger than the configured maximum, or its length field
    /// is above the largest value PostgreSQL accepts.
    FrameTooLarge {
        /// The type byte of the frame.
        tag: u8,
        /// The value of the length field.
        length: u32,
    },
}

impl fmt::Display for FrameError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match *self {
            Self::LengthTooSmall { tag, length } => write!(
                f,
                "message of type 0x{tag:02x} has length {length}, below the minimum of 4"
            ),
            Self::FrameTooLarge { tag, length } => write!(
                f,
                "message of type 0x{tag:02x} has length {length}, above the maximum"
            ),
        }
    }
}

impl std::error::Error for FrameError {}

/// Why a frame could not be read as the message a view describes.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[non_exhaustive]
pub enum ParseError {
    /// The frame is not the message this view describes: it travels in the
    /// other direction or has another type byte.
    UnexpectedMessage {
        /// The direction of the frame.
        direction: Direction,
        /// The type byte of the frame.
        tag: u8,
    },
    /// The message ends before a field it must contain.
    Truncated,
    /// A string has no terminating zero byte inside the frame.
    UnterminatedString,
    /// Bytes remain after the last field of the message.
    TrailingBytes,
    /// A count promises more items than the rest of the frame can hold.
    CountExceedsFrame,
    /// A length or count field is negative, and is not the marker for NULL.
    NegativeLength,
    /// A field holds a value the protocol does not define.
    InvalidValue,
    /// A cancel key is shorter or longer than the protocol allows.
    InvalidKeyLength,
}

impl fmt::Display for ParseError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match *self {
            Self::UnexpectedMessage { direction, tag } => {
                write!(f, "unexpected message of type 0x{tag:02x} {direction}")
            }
            Self::Truncated => f.write_str("message ends before a field it must contain"),
            Self::UnterminatedString => f.write_str("string is not terminated inside the message"),
            Self::TrailingBytes => f.write_str("bytes remain after the last field of the message"),
            Self::CountExceedsFrame => {
                f.write_str("count promises more items than the message can hold")
            }
            Self::NegativeLength => f.write_str("length or count field is negative"),
            Self::InvalidValue => f.write_str("field holds a value the protocol does not define"),
            Self::InvalidKeyLength => f.write_str("cancel key length is outside the allowed range"),
        }
    }
}

impl std::error::Error for ParseError {}

/// Why the first bytes of a connection are not an acceptable startup-phase
/// packet.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[non_exhaustive]
pub enum StartupError {
    /// The length field is outside the range PostgreSQL accepts for a
    /// startup packet.
    InvalidLength {
        /// The value of the length field.
        length: u32,
    },
    /// An `SSLRequest` or `GSSENCRequest` that is not exactly eight bytes
    /// long.
    InvalidRequestLength {
        /// The value of the length field.
        length: u32,
    },
    /// A `CancelRequest` whose length leaves no room for a key of 1 to 256
    /// bytes.
    InvalidCancelRequestLength {
        /// The value of the length field.
        length: u32,
    },
    /// The packet asks for a protocol version whose layout this crate does
    /// not know: any major version other than 3.
    UnsupportedVersion(ProtocolVersion),
    /// The parameters of a `StartupMessage` are not pairs of a name and a
    /// value followed by one zero byte at the very end of the packet.
    MalformedParameters,
}

impl fmt::Display for StartupError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match *self {
            Self::InvalidLength { length } => {
                write!(f, "startup packet has invalid length {length}")
            }
            Self::InvalidRequestLength { length } => {
                write!(f, "encryption request has length {length}, expected 8")
            }
            Self::InvalidCancelRequestLength { length } => {
                write!(f, "cancel request has invalid length {length}")
            }
            Self::UnsupportedVersion(version) => {
                write!(f, "unsupported frontend protocol {version}")
            }
            Self::MalformedParameters => {
                f.write_str("invalid startup packet layout: expected terminator as last byte")
            }
        }
    }
}

impl std::error::Error for StartupError {}

/// Why a message could not be encoded. Nothing is written to the output
/// when an encoder fails.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[non_exhaustive]
pub enum EncodeError {
    /// A string contains a zero byte, which would end it early on the wire.
    NulInString,
    /// A name that must not be empty is empty.
    EmptyName,
    /// An error field has the code zero, which marks the end of the fields.
    InvalidFieldCode,
    /// The message has more items than its count field can express.
    TooManyItems,
    /// The message would be longer than the protocol allows.
    TooLong,
    /// A cancel key is not 1 to 256 bytes long.
    InvalidKeyLength,
    /// The protocol version cannot be written into a `StartupMessage`: its
    /// major version is not 3.
    UnsupportedVersion(ProtocolVersion),
    /// The output buffer cannot take the whole message.
    BufferFull,
}

impl fmt::Display for EncodeError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match *self {
            Self::NulInString => f.write_str("string contains a zero byte"),
            Self::EmptyName => f.write_str("name is empty"),
            Self::InvalidFieldCode => f.write_str("error field code is zero"),
            Self::TooManyItems => f.write_str("more items than the count field can express"),
            Self::TooLong => f.write_str("message is longer than the protocol allows"),
            Self::InvalidKeyLength => f.write_str("cancel key is not 1 to 256 bytes long"),
            Self::UnsupportedVersion(version) => {
                write!(f, "protocol version {version} cannot be encoded")
            }
            Self::BufferFull => f.write_str("output buffer cannot take the whole message"),
        }
    }
}

impl std::error::Error for EncodeError {}
