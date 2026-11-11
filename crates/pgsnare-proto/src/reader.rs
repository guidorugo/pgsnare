// SPDX-License-Identifier: Apache-2.0

//! A bounds-checked reader over the bytes of one message.

use core::fmt;

use crate::error::ParseError;

/// Reads fields from the front of a byte slice.
///
/// A reader is created from the body of one frame and holds nothing else, so
/// it cannot read past the end of that frame, however many bytes follow the
/// frame in the buffer it was found in. Every read returns the bytes asked
/// for or an error. A failed read consumes nothing.
#[derive(Clone, Copy)]
pub(crate) struct Reader<'a> {
    rest: &'a [u8],
}

impl<'a> Reader<'a> {
    pub(crate) const fn new(bytes: &'a [u8]) -> Self {
        Self { rest: bytes }
    }

    /// The number of bytes not read yet.
    pub(crate) const fn remaining(&self) -> usize {
        self.rest.len()
    }

    pub(crate) const fn is_empty(&self) -> bool {
        self.rest.is_empty()
    }

    /// Reads exactly `len` bytes.
    pub(crate) fn take(&mut self, len: usize) -> Result<&'a [u8], ParseError> {
        let (head, tail) = self
            .rest
            .split_at_checked(len)
            .ok_or(ParseError::Truncated)?;
        self.rest = tail;
        Ok(head)
    }

    /// Reads everything that is left.
    pub(crate) fn take_rest(&mut self) -> &'a [u8] {
        let rest = self.rest;
        self.rest = &[];
        rest
    }

    /// Reads a fixed number of bytes.
    pub(crate) fn array<const N: usize>(&mut self) -> Result<[u8; N], ParseError> {
        let (head, tail) = self
            .rest
            .split_first_chunk::<N>()
            .ok_or(ParseError::Truncated)?;
        self.rest = tail;
        Ok(*head)
    }

    pub(crate) fn u8(&mut self) -> Result<u8, ParseError> {
        self.array::<1>().map(|[byte]| byte)
    }

    pub(crate) fn u16(&mut self) -> Result<u16, ParseError> {
        self.array().map(u16::from_be_bytes)
    }

    pub(crate) fn i16(&mut self) -> Result<i16, ParseError> {
        self.array().map(i16::from_be_bytes)
    }

    pub(crate) fn u32(&mut self) -> Result<u32, ParseError> {
        self.array().map(u32::from_be_bytes)
    }

    pub(crate) fn i32(&mut self) -> Result<i32, ParseError> {
        self.array().map(i32::from_be_bytes)
    }

    /// Reads a string up to its terminating zero byte and consumes the
    /// terminator. The terminator is not part of the result.
    pub(crate) fn cstr(&mut self) -> Result<&'a [u8], ParseError> {
        let mut parts = self.rest.splitn(2, |&byte| byte == 0);
        let string = parts.next().ok_or(ParseError::UnterminatedString)?;
        // Without a zero byte there is no second part.
        let tail = parts.next().ok_or(ParseError::UnterminatedString)?;
        self.rest = tail;
        Ok(string)
    }

    /// Succeeds only when every byte has been read.
    pub(crate) fn finish(self) -> Result<(), ParseError> {
        if self.rest.is_empty() {
            Ok(())
        } else {
            Err(ParseError::TrailingBytes)
        }
    }

    /// The bytes read since `earlier`, a copy of this reader taken before
    /// those reads.
    pub(crate) fn consumed_since(&self, earlier: &Self) -> &'a [u8] {
        let len = earlier.rest.len().saturating_sub(self.rest.len());
        earlier.rest.get(..len).unwrap_or_default()
    }
}

/// Formats as the length of a byte string, never as its content.
///
/// The `Debug` implementations of this crate use it so that message content,
/// which may hold credentials or honeytoken values, cannot reach a log
/// through a debug print.
pub(crate) struct Redacted<'a>(pub(crate) &'a [u8]);

impl fmt::Debug for Redacted<'_> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "<{} bytes>", self.0.len())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn reads_integers_big_endian() {
        let mut reader = Reader::new(&[0x01, 0x02, 0x03, 0xff, 0xfe, 0x00, 0x00, 0x01, 0x00]);
        assert_eq!(reader.u8(), Ok(0x01));
        assert_eq!(reader.u16(), Ok(0x0203));
        assert_eq!(reader.i16(), Ok(-2));
        assert_eq!(reader.u32(), Ok(256));
        assert!(reader.is_empty());
        assert_eq!(reader.finish(), Ok(()));
    }

    #[test]
    fn negative_i32_is_read_as_negative() {
        let mut reader = Reader::new(&[0xff, 0xff, 0xff, 0xff]);
        assert_eq!(reader.i32(), Ok(-1));
    }

    #[test]
    fn short_reads_fail_and_consume_nothing() {
        let mut reader = Reader::new(&[0x01, 0x02, 0x03]);
        assert_eq!(reader.u32(), Err(ParseError::Truncated));
        assert_eq!(reader.take(4), Err(ParseError::Truncated));
        assert_eq!(reader.remaining(), 3);
        assert_eq!(reader.take(3), Ok(&[0x01, 0x02, 0x03][..]));
        assert_eq!(reader.u8(), Err(ParseError::Truncated));
    }

    #[test]
    fn take_of_zero_bytes_succeeds_at_the_end() {
        let mut reader = Reader::new(&[]);
        assert_eq!(reader.take(0), Ok(&[][..]));
        assert_eq!(reader.array::<0>(), Ok([]));
    }

    #[test]
    fn cstr_stops_at_the_first_zero_byte() {
        let mut reader = Reader::new(b"ab\0\0cd\0");
        assert_eq!(reader.cstr(), Ok(&b"ab"[..]));
        assert_eq!(reader.cstr(), Ok(&b""[..]));
        assert_eq!(reader.cstr(), Ok(&b"cd"[..]));
        assert_eq!(reader.cstr(), Err(ParseError::UnterminatedString));
        assert!(reader.is_empty());
    }

    #[test]
    fn unterminated_cstr_fails_and_consumes_nothing() {
        let mut reader = Reader::new(b"abc");
        assert_eq!(reader.cstr(), Err(ParseError::UnterminatedString));
        assert_eq!(reader.remaining(), 3);
    }

    #[test]
    fn finish_reports_trailing_bytes() {
        let mut reader = Reader::new(&[1, 2]);
        assert_eq!(reader.u8(), Ok(1));
        assert_eq!(reader.finish(), Err(ParseError::TrailingBytes));
    }

    #[test]
    fn consumed_since_returns_the_bytes_in_between() {
        let mut reader = Reader::new(b"abcdef");
        assert_eq!(reader.u8(), Ok(b'a'));
        let earlier = reader;
        assert_eq!(reader.take(3), Ok(&b"bcd"[..]));
        assert_eq!(reader.consumed_since(&earlier), b"bcd");
        assert_eq!(earlier.consumed_since(&earlier), b"");
        // Asking in the wrong order yields nothing rather than a panic.
        assert_eq!(earlier.consumed_since(&reader), b"");
    }

    #[test]
    fn take_rest_empties_the_reader() {
        let mut reader = Reader::new(b"xyz");
        assert_eq!(reader.take_rest(), b"xyz");
        assert_eq!(reader.take_rest(), b"");
        assert_eq!(reader.finish(), Ok(()));
    }

    #[test]
    fn redacted_prints_only_the_length() {
        assert_eq!(format!("{:?}", Redacted(b"secret")), "<6 bytes>");
    }
}
