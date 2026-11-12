// SPDX-License-Identifier: Apache-2.0

//! Framing: locating messages in a stream of bytes.
//!
//! After the startup phase every message has the same shape in both
//! directions: a type byte, a four-byte big-endian length that counts itself
//! but not the type byte, and a body. The [`Framer`] finds these frames in a
//! buffer without copying them and without knowing what the type bytes
//! mean, so a message type it has never seen is framed like any other.

use core::fmt;

use crate::error::{FrameError, ParseError};
use crate::reader::Redacted;

/// The size of a frame header: the type byte and the length field.
pub const HEADER_LEN: usize = 5;

/// The smallest valid value of a length field: the length counts itself.
pub const MIN_LENGTH: u32 = 4;

/// The largest value of a length field that PostgreSQL accepts. Both the
/// server and libpq read the field as a signed 32-bit integer, so a value
/// with the top bit set is negative to them and never valid.
pub const MAX_LENGTH: u32 = 0x7fff_ffff;

/// Who sent a message.
///
/// The same type byte means different messages in the two directions (`D`
/// is `DataRow` from the server and `Describe` from the client), so every
/// frame records where it came from and every view checks it.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum Direction {
    /// Sent by the client, the frontend in PostgreSQL's terms.
    FromClient,
    /// Sent by the server, the backend in PostgreSQL's terms.
    FromServer,
}

impl fmt::Display for Direction {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            Self::FromClient => "from the client",
            Self::FromServer => "from the server",
        })
    }
}

/// The header of a frame: its type byte and its length field.
///
/// A header only exists for a length field between [`MIN_LENGTH`] and
/// [`MAX_LENGTH`].
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct FrameHeader {
    tag: u8,
    length: u32,
}

impl FrameHeader {
    /// Reads a header from the first [`HEADER_LEN`] bytes of `buf`.
    ///
    /// Returns `Ok(None)` when `buf` is shorter than a header.
    ///
    /// # Errors
    ///
    /// Fails when the length field is below [`MIN_LENGTH`] or above
    /// [`MAX_LENGTH`].
    pub fn parse(buf: &[u8]) -> Result<Option<Self>, FrameError> {
        let Some((&[tag, a, b, c, d], _)) = buf.split_first_chunk::<HEADER_LEN>() else {
            return Ok(None);
        };
        let length = u32::from_be_bytes([a, b, c, d]);
        if length < MIN_LENGTH {
            return Err(FrameError::LengthTooSmall { tag, length });
        }
        if length > MAX_LENGTH {
            return Err(FrameError::FrameTooLarge { tag, length });
        }
        Ok(Some(Self { tag, length }))
    }

    /// The type byte.
    #[must_use]
    pub const fn tag(self) -> u8 {
        self.tag
    }

    /// The value of the length field: the size of the body plus four.
    #[must_use]
    pub const fn length(self) -> u32 {
        self.length
    }

    /// The size of the body in bytes.
    #[must_use]
    pub const fn body_len(self) -> u32 {
        self.length.saturating_sub(MIN_LENGTH)
    }

    /// The size of the whole frame on the wire: header and body.
    ///
    /// The result saturates on a platform whose `usize` is narrower than 32
    /// bits.
    #[must_use]
    pub fn frame_len(self) -> usize {
        usize::try_from(self.frame_len_u64()).unwrap_or(usize::MAX)
    }

    /// The size of the whole frame, in a type that always holds it.
    fn frame_len_u64(self) -> u64 {
        // The length field does not count the type byte.
        u64::from(self.length).saturating_add(1)
    }

    /// The five header bytes, exactly as they appear on the wire.
    #[must_use]
    pub fn to_bytes(self) -> [u8; HEADER_LEN] {
        let [a, b, c, d] = self.length.to_be_bytes();
        [self.tag, a, b, c, d]
    }
}

/// One complete message, borrowed from the buffer it was found in.
///
/// [`Frame::as_bytes`] returns the bytes that arrived, header included, so
/// a frame can be forwarded unchanged.
#[derive(Clone, Copy, PartialEq, Eq)]
pub struct Frame<'a> {
    direction: Direction,
    tag: u8,
    bytes: &'a [u8],
    body: &'a [u8],
}

impl<'a> Frame<'a> {
    /// Who sent the frame.
    #[must_use]
    pub const fn direction(&self) -> Direction {
        self.direction
    }

    /// The type byte.
    #[must_use]
    pub const fn tag(&self) -> u8 {
        self.tag
    }

    /// The body: everything after the header.
    #[must_use]
    pub const fn body(&self) -> &'a [u8] {
        self.body
    }

    /// The whole frame as it appeared on the wire.
    #[must_use]
    pub const fn as_bytes(&self) -> &'a [u8] {
        self.bytes
    }

    /// The size of the whole frame on the wire.
    #[must_use]
    pub const fn wire_len(&self) -> usize {
        self.bytes.len()
    }

    /// The body, if the frame has the given direction and type byte.
    pub(crate) fn body_of(self, direction: Direction, tag: u8) -> Result<&'a [u8], ParseError> {
        if self.direction == direction && self.tag == tag {
            Ok(self.body)
        } else {
            Err(self.unexpected())
        }
    }

    /// The error for a frame that is not the message a view expected.
    pub(crate) const fn unexpected(self) -> ParseError {
        ParseError::UnexpectedMessage {
            direction: self.direction,
            tag: self.tag,
        }
    }
}

impl fmt::Debug for Frame<'_> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Frame")
            .field("direction", &self.direction)
            .field("tag", &self.tag)
            .field("body", &Redacted(self.body))
            .finish()
    }
}

/// How large a frame may be before it is streamed, and before it is refused.
///
/// Both limits count the whole frame on the wire: the type byte, the length
/// field and the body.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Limits {
    max_buffered: usize,
    max_frame: usize,
}

impl Limits {
    /// Creates limits.
    ///
    /// - A frame of at most `max_buffered` bytes is returned whole, once the
    ///   buffer holds all of it.
    /// - A larger frame of at most `max_frame` bytes is streamed: its header
    ///   first, then its body in chunks.
    /// - A frame larger than `max_frame` bytes is an error.
    ///
    /// A `max_buffered` below [`HEADER_LEN`] is raised to it, so a frame
    /// with an empty body is always returned whole and a streamed frame has
    /// at least one body byte. When `max_frame` is not above `max_buffered`,
    /// nothing is ever streamed.
    #[must_use]
    pub const fn new(max_buffered: usize, max_frame: usize) -> Self {
        Self {
            max_buffered: if max_buffered < HEADER_LEN {
                HEADER_LEN
            } else {
                max_buffered
            },
            max_frame,
        }
    }

    /// Limits under which a frame is either returned whole or refused.
    #[must_use]
    pub const fn buffered_only(max_frame: usize) -> Self {
        Self::new(max_frame, max_frame)
    }

    /// The largest frame returned whole.
    #[must_use]
    pub const fn max_buffered(&self) -> usize {
        self.max_buffered
    }

    /// The largest frame accepted at all.
    #[must_use]
    pub const fn max_frame(&self) -> usize {
        self.max_frame
    }
}

/// A part of the body of a streamed frame.
#[derive(Clone, Copy, PartialEq, Eq)]
pub struct Chunk<'a> {
    data: &'a [u8],
    remaining: u32,
}

impl<'a> Chunk<'a> {
    /// The bytes of this chunk. Never empty.
    #[must_use]
    pub const fn data(&self) -> &'a [u8] {
        self.data
    }

    /// The number of body bytes that follow this chunk.
    #[must_use]
    pub const fn remaining(&self) -> u32 {
        self.remaining
    }

    /// Whether this chunk completes the frame.
    #[must_use]
    pub const fn is_last(&self) -> bool {
        self.remaining == 0
    }
}

impl fmt::Debug for Chunk<'_> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Chunk")
            .field("data", &Redacted(self.data))
            .field("remaining", &self.remaining)
            .finish()
    }
}

/// What [`Framer::next`] found at the front of the buffer.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Step<'a> {
    /// A whole frame. It has been consumed from the buffer.
    Frame(Frame<'a>),
    /// The header of a frame too large to return whole. The header has been
    /// consumed. The body follows as one or more [`Step::StreamChunk`].
    StreamStart(FrameHeader),
    /// The next part of the body of a streamed frame. It has been consumed.
    StreamChunk(Chunk<'a>),
    /// Nothing can be returned yet and nothing was consumed. The buffer must
    /// hold at least this many bytes, counted from its current start, before
    /// the next call can make progress.
    NeedMore(usize),
}

/// Locates the frames of one direction of a connection.
///
/// The framer keeps no bytes. The caller owns the buffer and passes its
/// unread part to [`Framer::next`], which borrows frames from it.
///
/// ```
/// use pgsnare_proto::{Direction, Framer, Limits, Step};
///
/// # fn main() -> Result<(), pgsnare_proto::FrameError> {
/// let mut framer = Framer::new(Direction::FromServer, Limits::buffered_only(1024));
///
/// // ReadyForQuery, then the first three bytes of another frame.
/// let received = [b'Z', 0, 0, 0, 5, b'I', b'C', 0, 0];
/// let mut unread = &received[..];
///
/// let mut tags = Vec::new();
/// while let Step::Frame(frame) = framer.next(&mut unread)? {
///     tags.push(frame.tag());
/// }
/// assert_eq!(tags, [b'Z']);
/// // The incomplete frame stays in the buffer.
/// assert_eq!(unread, [b'C', 0, 0]);
/// # Ok(())
/// # }
/// ```
#[derive(Clone, Debug)]
pub struct Framer {
    direction: Direction,
    limits: Limits,
    /// Body bytes of the streamed frame that have not been returned yet.
    /// Zero between frames.
    stream_remaining: u32,
}

impl Framer {
    /// Creates a framer for one direction of a connection, positioned at a
    /// frame boundary.
    #[must_use]
    pub const fn new(direction: Direction, limits: Limits) -> Self {
        Self {
            direction,
            limits,
            stream_remaining: 0,
        }
    }

    /// The direction this framer reads.
    #[must_use]
    pub const fn direction(&self) -> Direction {
        self.direction
    }

    /// The limits in force.
    #[must_use]
    pub const fn limits(&self) -> Limits {
        self.limits
    }

    /// Replaces the limits. The new limits apply from the next frame header
    /// on. A frame that is already being streamed is streamed to its end.
    pub const fn set_limits(&mut self, limits: Limits) {
        self.limits = limits;
    }

    /// The number of body bytes of the current streamed frame that have not
    /// been returned yet. Zero when the framer is between frames.
    #[must_use]
    pub const fn stream_remaining(&self) -> u32 {
        self.stream_remaining
    }

    /// Whether the framer is between frames. When a connection ends, the
    /// stream was cut short unless this is true and the buffer is empty.
    #[must_use]
    pub const fn is_at_frame_boundary(&self) -> bool {
        self.stream_remaining == 0
    }

    /// Looks at the front of `buf` and returns what is there.
    ///
    /// On [`Step::Frame`], [`Step::StreamStart`] and [`Step::StreamChunk`],
    /// `buf` is advanced past the bytes returned. On [`Step::NeedMore`] and
    /// on an error, `buf` and the framer are left exactly as they were, so
    /// the call can be repeated once more bytes have arrived.
    ///
    /// # Errors
    ///
    /// Fails when the length field of the next header is below
    /// [`MIN_LENGTH`], above [`MAX_LENGTH`], or describes a frame larger
    /// than [`Limits::max_frame`].
    pub fn next<'a>(&mut self, buf: &mut &'a [u8]) -> Result<Step<'a>, FrameError> {
        let input = *buf;

        if self.stream_remaining > 0 {
            return Ok(self.next_chunk(input, buf));
        }

        let Some(header) = FrameHeader::parse(input)? else {
            return Ok(Step::NeedMore(HEADER_LEN));
        };
        let too_large = FrameError::FrameTooLarge {
            tag: header.tag,
            length: header.length,
        };
        let frame_len = header.frame_len_u64();
        if frame_len > u64::try_from(self.limits.max_frame).unwrap_or(u64::MAX) {
            return Err(too_large);
        }

        if frame_len > u64::try_from(self.limits.max_buffered).unwrap_or(u64::MAX) {
            // Too large to hold: hand out the header and stream the body.
            // `max_buffered` is at least the header size, so the body has at
            // least one byte.
            let Some(rest) = input.get(HEADER_LEN..) else {
                return Ok(Step::NeedMore(HEADER_LEN));
            };
            self.stream_remaining = header.body_len();
            *buf = rest;
            return Ok(Step::StreamStart(header));
        }

        // The frame is no larger than `max_buffered`, which is a `usize`.
        let frame_len = usize::try_from(frame_len).map_err(|_| too_large)?;
        let Some((bytes, rest)) = input.split_at_checked(frame_len) else {
            return Ok(Step::NeedMore(frame_len));
        };
        let Some(body) = bytes.get(HEADER_LEN..) else {
            return Ok(Step::NeedMore(frame_len));
        };
        *buf = rest;
        Ok(Step::Frame(Frame {
            direction: self.direction,
            tag: header.tag,
            bytes,
            body,
        }))
    }

    /// Returns the next part of the body being streamed.
    fn next_chunk<'a>(&mut self, input: &'a [u8], buf: &mut &'a [u8]) -> Step<'a> {
        let wanted = usize::try_from(self.stream_remaining).unwrap_or(usize::MAX);
        let len = wanted.min(input.len());
        let Some((data, rest)) = input.split_at_checked(len) else {
            return Step::NeedMore(1);
        };
        if data.is_empty() {
            return Step::NeedMore(1);
        }
        // `len` is at most `stream_remaining`, so it fits in a `u32`.
        let taken = u32::try_from(len).unwrap_or(u32::MAX);
        self.stream_remaining = self.stream_remaining.saturating_sub(taken);
        *buf = rest;
        Step::StreamChunk(Chunk {
            data,
            remaining: self.stream_remaining,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn frame_bytes(tag: u8, body: &[u8]) -> Vec<u8> {
        let mut bytes = vec![tag];
        bytes.extend_from_slice(&u32::try_from(body.len() + 4).unwrap().to_be_bytes());
        bytes.extend_from_slice(body);
        bytes
    }

    fn expect_frame<'a>(framer: &mut Framer, buf: &mut &'a [u8]) -> Frame<'a> {
        match framer.next(buf) {
            Ok(Step::Frame(frame)) => frame,
            other => panic!("expected a frame, got {other:?}"),
        }
    }

    #[test]
    fn header_needs_five_bytes() {
        assert_eq!(FrameHeader::parse(&[]), Ok(None));
        assert_eq!(FrameHeader::parse(&[b'Q', 0, 0, 0]), Ok(None));
        let header = FrameHeader::parse(&[b'Q', 0, 0, 0, 9, 0xaa])
            .unwrap()
            .unwrap();
        assert_eq!(header.tag(), b'Q');
        assert_eq!(header.length(), 9);
        assert_eq!(header.body_len(), 5);
        assert_eq!(header.frame_len(), 10);
        assert_eq!(header.to_bytes(), [b'Q', 0, 0, 0, 9]);
    }

    #[test]
    fn header_rejects_lengths_below_four() {
        for length in 0..4u32 {
            let mut bytes = vec![b'Z'];
            bytes.extend_from_slice(&length.to_be_bytes());
            assert_eq!(
                FrameHeader::parse(&bytes),
                Err(FrameError::LengthTooSmall { tag: b'Z', length })
            );
        }
    }

    #[test]
    fn header_rejects_lengths_postgresql_reads_as_negative() {
        for length in [0x8000_0000u32, 0xffff_ffff] {
            let mut bytes = vec![b'D'];
            bytes.extend_from_slice(&length.to_be_bytes());
            assert_eq!(
                FrameHeader::parse(&bytes),
                Err(FrameError::FrameTooLarge { tag: b'D', length })
            );
        }
        let mut bytes = vec![b'D'];
        bytes.extend_from_slice(&MAX_LENGTH.to_be_bytes());
        let header = FrameHeader::parse(&bytes).unwrap().unwrap();
        assert_eq!(header.frame_len(), 0x8000_0000);
        assert_eq!(header.body_len(), 0x7fff_fffb);
    }

    #[test]
    fn locates_consecutive_frames_without_copying() {
        let mut stream = frame_bytes(b'1', b"");
        stream.extend(frame_bytes(b'D', b"\x00\x01\x00\x00\x00\x01x"));
        stream.extend(frame_bytes(b'Z', b"I"));
        let mut framer = Framer::new(Direction::FromServer, Limits::buffered_only(64));
        let mut buf = &stream[..];

        let first = expect_frame(&mut framer, &mut buf);
        assert_eq!(first.tag(), b'1');
        assert_eq!(first.body(), b"");
        assert_eq!(first.wire_len(), 5);
        assert_eq!(first.direction(), Direction::FromServer);
        // The frame is a view into the stream, not a copy.
        assert!(core::ptr::eq(first.as_bytes().as_ptr(), stream.as_ptr()));

        let second = expect_frame(&mut framer, &mut buf);
        assert_eq!(second.tag(), b'D');
        assert_eq!(second.body(), b"\x00\x01\x00\x00\x00\x01x");
        assert_eq!(second.as_bytes(), &stream[5..17]);

        let third = expect_frame(&mut framer, &mut buf);
        assert_eq!(third.tag(), b'Z');
        assert_eq!(third.body(), b"I");

        assert!(buf.is_empty());
        assert_eq!(framer.next(&mut buf), Ok(Step::NeedMore(HEADER_LEN)));
        assert!(framer.is_at_frame_boundary());
    }

    #[test]
    fn need_more_consumes_nothing() {
        let stream = frame_bytes(b'Q', b"select 1\0");
        let mut framer = Framer::new(Direction::FromClient, Limits::buffered_only(64));
        for cut in 0..stream.len() {
            let mut buf = &stream[..cut];
            let expected = if cut < HEADER_LEN {
                HEADER_LEN
            } else {
                stream.len()
            };
            assert_eq!(framer.next(&mut buf), Ok(Step::NeedMore(expected)));
            assert_eq!(buf.len(), cut, "nothing may be consumed");
            assert!(framer.is_at_frame_boundary());
        }
        let mut buf = &stream[..];
        assert_eq!(expect_frame(&mut framer, &mut buf).body(), b"select 1\0");
    }

    #[test]
    fn errors_consume_nothing_and_repeat() {
        let stream = [b'Q', 0, 0, 0, 3, 1, 2, 3];
        let mut framer = Framer::new(Direction::FromClient, Limits::buffered_only(64));
        let mut buf = &stream[..];
        let error = FrameError::LengthTooSmall {
            tag: b'Q',
            length: 3,
        };
        assert_eq!(framer.next(&mut buf), Err(error));
        assert_eq!(buf.len(), stream.len());
        assert_eq!(framer.next(&mut buf), Err(error));
    }

    #[test]
    fn rejects_frames_above_the_maximum() {
        // A frame of exactly the maximum size passes, one byte more fails.
        let mut framer = Framer::new(Direction::FromClient, Limits::buffered_only(10));
        let fits = frame_bytes(b'Q', b"12345");
        let mut buf = &fits[..];
        assert_eq!(expect_frame(&mut framer, &mut buf).wire_len(), 10);

        let too_big = frame_bytes(b'Q', b"123456");
        let mut buf = &too_big[..];
        assert_eq!(
            framer.next(&mut buf),
            Err(FrameError::FrameTooLarge {
                tag: b'Q',
                length: 10
            })
        );
        // The verdict needs only the header.
        let mut buf = &too_big[..HEADER_LEN];
        assert!(framer.next(&mut buf).is_err());
    }

    #[test]
    fn unknown_type_bytes_are_framed_generically() {
        let mut framer = Framer::new(Direction::FromServer, Limits::buffered_only(64));
        for tag in [0x00, 0x01, b'?', 0x7f, 0x80, 0xff] {
            let stream = frame_bytes(tag, b"payload");
            let mut buf = &stream[..];
            let frame = expect_frame(&mut framer, &mut buf);
            assert_eq!(frame.tag(), tag);
            assert_eq!(frame.body(), b"payload");
            assert!(buf.is_empty());
        }
    }

    #[test]
    fn streams_a_frame_larger_than_the_buffer_limit() {
        let body: Vec<u8> = (0..=255u8).cycle().take(1000).collect();
        let mut stream = frame_bytes(b'd', &body);
        stream.extend(frame_bytes(b'c', b""));
        let mut framer = Framer::new(Direction::FromServer, Limits::new(100, 4096));

        // Feed the stream in pieces of 64 bytes, keeping what is not consumed.
        let mut pending: Vec<u8> = Vec::new();
        let mut header = None;
        let mut streamed = Vec::new();
        let mut finished = false;
        let mut tail_tags = Vec::new();
        for piece in stream.chunks(64) {
            pending.extend_from_slice(piece);
            let mut buf = &pending[..];
            loop {
                match framer.next(&mut buf).unwrap() {
                    Step::StreamStart(start) => {
                        assert!(header.is_none());
                        header = Some(start);
                        assert_eq!(framer.stream_remaining(), 1000);
                        assert!(!framer.is_at_frame_boundary());
                    }
                    Step::StreamChunk(chunk) => {
                        assert!(!chunk.data().is_empty());
                        assert!(!finished);
                        streamed.extend_from_slice(chunk.data());
                        assert_eq!(chunk.remaining(), framer.stream_remaining());
                        assert_eq!(
                            usize::try_from(chunk.remaining()).unwrap(),
                            1000 - streamed.len()
                        );
                        finished = chunk.is_last();
                    }
                    Step::Frame(frame) => {
                        assert!(finished, "the small frame follows the streamed one");
                        tail_tags.push(frame.tag());
                    }
                    Step::NeedMore(_) => break,
                }
            }
            let consumed = pending.len() - buf.len();
            pending.drain(..consumed);
        }

        let header = header.unwrap();
        assert_eq!(header.tag(), b'd');
        assert_eq!(header.body_len(), 1000);
        assert_eq!(header.to_bytes(), stream[..HEADER_LEN]);
        assert_eq!(streamed, body);
        assert!(finished);
        assert_eq!(tail_tags, [b'c']);
        assert!(pending.is_empty());
        assert!(framer.is_at_frame_boundary());
    }

    #[test]
    fn streaming_starts_with_only_the_header_available() {
        let mut framer = Framer::new(Direction::FromClient, Limits::new(16, 1 << 20));
        let header_bytes = [b'd', 0, 0, 0x10, 0x04];
        let mut buf = &header_bytes[..];
        let Ok(Step::StreamStart(header)) = framer.next(&mut buf) else {
            panic!("expected the start of a stream");
        };
        assert_eq!(header.body_len(), 4096);
        assert!(buf.is_empty());
        // No body bytes yet: one more byte is enough to make progress.
        assert_eq!(framer.next(&mut buf), Ok(Step::NeedMore(1)));
        assert_eq!(framer.stream_remaining(), 4096);
    }

    #[test]
    fn a_chunk_never_crosses_into_the_next_frame() {
        let mut stream = frame_bytes(b'd', &[7u8; 40]);
        stream.extend(frame_bytes(b'Z', b"I"));
        let mut framer = Framer::new(Direction::FromServer, Limits::new(16, 1024));
        let mut buf = &stream[..];
        assert!(matches!(framer.next(&mut buf), Ok(Step::StreamStart(_))));
        let Ok(Step::StreamChunk(chunk)) = framer.next(&mut buf) else {
            panic!("expected a chunk");
        };
        assert_eq!(chunk.data(), &[7u8; 40][..]);
        assert!(chunk.is_last());
        assert_eq!(expect_frame(&mut framer, &mut buf).tag(), b'Z');
        assert!(buf.is_empty());
    }

    #[test]
    fn an_empty_body_is_never_streamed() {
        // Even with a buffer limit of zero, which is raised to the header size.
        let limits = Limits::new(0, 1024);
        assert_eq!(limits.max_buffered(), HEADER_LEN);
        let mut framer = Framer::new(Direction::FromClient, limits);
        let stream = frame_bytes(b'S', b"");
        let mut buf = &stream[..];
        assert_eq!(expect_frame(&mut framer, &mut buf).tag(), b'S');

        let stream = frame_bytes(b'Q', b"\0");
        let mut buf = &stream[..];
        assert!(matches!(framer.next(&mut buf), Ok(Step::StreamStart(_))));
        let Ok(Step::StreamChunk(chunk)) = framer.next(&mut buf) else {
            panic!("expected a chunk");
        };
        assert_eq!(chunk.data(), b"\0");
        assert!(chunk.is_last());
    }

    #[test]
    fn a_maximum_below_the_header_size_refuses_everything() {
        let mut framer = Framer::new(Direction::FromClient, Limits::new(64, 4));
        let stream = frame_bytes(b'S', b"");
        let mut buf = &stream[..];
        assert_eq!(
            framer.next(&mut buf),
            Err(FrameError::FrameTooLarge {
                tag: b'S',
                length: 4
            })
        );
    }

    #[test]
    fn new_limits_apply_from_the_next_header() {
        let mut stream = frame_bytes(b'd', &[1u8; 30]);
        stream.extend(frame_bytes(b'd', &[2u8; 30]));
        let mut framer = Framer::new(Direction::FromServer, Limits::new(16, 1024));
        let mut buf = &stream[..];
        assert!(matches!(framer.next(&mut buf), Ok(Step::StreamStart(_))));

        // Changing limits mid-stream does not disturb the frame in progress.
        framer.set_limits(Limits::buffered_only(1024));
        assert_eq!(framer.limits(), Limits::new(1024, 1024));
        let Ok(Step::StreamChunk(chunk)) = framer.next(&mut buf) else {
            panic!("expected a chunk");
        };
        assert_eq!(chunk.data(), &[1u8; 30][..]);
        assert!(chunk.is_last());

        // The next frame is small enough for the new limits.
        assert_eq!(expect_frame(&mut framer, &mut buf).body(), &[2u8; 30][..]);
    }

    #[test]
    fn a_huge_declared_length_is_streamed_without_the_bytes_being_present() {
        // The largest length PostgreSQL accepts, with a generous maximum.
        let mut framer = Framer::new(Direction::FromServer, Limits::new(1024, usize::MAX));
        let mut header_bytes = vec![b'D'];
        header_bytes.extend_from_slice(&MAX_LENGTH.to_be_bytes());
        header_bytes.extend_from_slice(b"abc");
        let mut buf = &header_bytes[..];
        let Ok(Step::StreamStart(header)) = framer.next(&mut buf) else {
            panic!("expected the start of a stream");
        };
        assert_eq!(header.length(), MAX_LENGTH);
        let Ok(Step::StreamChunk(chunk)) = framer.next(&mut buf) else {
            panic!("expected a chunk");
        };
        assert_eq!(chunk.data(), b"abc");
        assert_eq!(chunk.remaining(), MAX_LENGTH - 4 - 3);
        assert!(!chunk.is_last());
    }

    #[test]
    fn debug_output_omits_the_body() {
        let stream = frame_bytes(b'Q', b"select 'SECRETMARKER'\0");
        let mut framer = Framer::new(Direction::FromClient, Limits::new(8, 1024));
        let mut buf = &stream[..];
        let start = framer.next(&mut buf).unwrap();
        let chunk = framer.next(&mut buf).unwrap();
        for step in [start, chunk] {
            assert!(!format!("{step:?}").contains("SECRETMARKER"));
        }

        let mut framer = Framer::new(Direction::FromClient, Limits::buffered_only(1024));
        let mut buf = &stream[..];
        let step = framer.next(&mut buf).unwrap();
        let text = format!("{step:?}");
        assert!(!text.contains("SECRETMARKER"));
        assert!(text.contains("<22 bytes>"), "{text}");
    }
}
