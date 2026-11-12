// SPDX-License-Identifier: Apache-2.0

//! Parts shared by messages of both directions.

use core::fmt;

use crate::error::ParseError;
use crate::frame::Frame;
use crate::reader::{Reader, Redacted};

/// How one value is encoded: as text or in the binary form of its type.
///
/// The code is kept as it appeared on the wire. PostgreSQL defines only
/// [`FormatCode::TEXT`] and [`FormatCode::BINARY`].
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub struct FormatCode(pub i16);

impl FormatCode {
    /// The text format.
    pub const TEXT: Self = Self(0);

    /// The binary format.
    pub const BINARY: Self = Self(1);

    /// Whether this is the text format.
    #[must_use]
    pub const fn is_text(self) -> bool {
        self.0 == Self::TEXT.0
    }

    /// Whether this is the binary format.
    #[must_use]
    pub const fn is_binary(self) -> bool {
        self.0 == Self::BINARY.0
    }
}

/// A list of format codes, as sent in `Bind` and in the COPY responses.
#[derive(Clone, Copy, PartialEq, Eq)]
pub struct FormatCodes<'a> {
    codes: &'a [[u8; 2]],
}

impl<'a> FormatCodes<'a> {
    /// Reads a 16-bit count followed by that many codes.
    pub(crate) fn parse(reader: &mut Reader<'a>) -> Result<Self, ParseError> {
        let count = usize::from(reader.u16()?);
        // Checked against the frame before anything is read: a count the
        // frame cannot hold fails here.
        let len = count.checked_mul(2).ok_or(ParseError::CountExceedsFrame)?;
        let bytes = reader
            .take(len)
            .map_err(|_| ParseError::CountExceedsFrame)?;
        let (codes, _) = bytes.as_chunks::<2>();
        Ok(Self { codes })
    }

    /// The number of codes.
    #[must_use]
    pub const fn len(&self) -> usize {
        self.codes.len()
    }

    /// Whether the list is empty.
    #[must_use]
    pub const fn is_empty(&self) -> bool {
        self.codes.is_empty()
    }

    /// The code at `index`, as it was sent.
    #[must_use]
    pub fn get(&self, index: usize) -> Option<FormatCode> {
        self.codes.get(index).copied().map(decode_format)
    }

    /// The format that applies to the value at `index` under the rule of
    /// `Bind`: no codes means text for every value, one code applies to
    /// every value, and otherwise each value has its own code.
    ///
    /// Returns `None` when there are several codes and none at `index`.
    #[must_use]
    pub fn code_for(&self, index: usize) -> Option<FormatCode> {
        match self.codes {
            [] => Some(FormatCode::TEXT),
            [only] => Some(decode_format(*only)),
            codes => codes.get(index).copied().map(decode_format),
        }
    }

    /// Iterates over the codes in order.
    #[must_use]
    pub fn iter(&self) -> FormatCodeIter<'a> {
        FormatCodeIter {
            codes: self.codes.iter(),
        }
    }
}

impl<'a> IntoIterator for FormatCodes<'a> {
    type Item = FormatCode;
    type IntoIter = FormatCodeIter<'a>;

    fn into_iter(self) -> Self::IntoIter {
        self.iter()
    }
}

impl fmt::Debug for FormatCodes<'_> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_list()
            .entries(self.iter().map(|code| code.0))
            .finish()
    }
}

fn decode_format(bytes: [u8; 2]) -> FormatCode {
    FormatCode(i16::from_be_bytes(bytes))
}

/// An iterator over [`FormatCodes`].
#[derive(Clone, Debug)]
pub struct FormatCodeIter<'a> {
    codes: core::slice::Iter<'a, [u8; 2]>,
}

impl Iterator for FormatCodeIter<'_> {
    type Item = FormatCode;

    fn next(&mut self) -> Option<Self::Item> {
        self.codes.next().copied().map(decode_format)
    }

    fn size_hint(&self) -> (usize, Option<usize>) {
        self.codes.size_hint()
    }
}

impl ExactSizeIterator for FormatCodeIter<'_> {}

/// A list of values, each either NULL or a byte string: the columns of a
/// `DataRow` or the parameters of a `Bind`.
///
/// The list was checked in full when the message was parsed, so iterating
/// it cannot fail.
#[derive(Clone, Copy, PartialEq, Eq)]
pub struct Values<'a> {
    count: u16,
    /// The encoded values: for each, a length and then that many bytes.
    bytes: &'a [u8],
}

impl<'a> Values<'a> {
    /// Reads a 16-bit count followed by that many values.
    pub(crate) fn parse(reader: &mut Reader<'a>) -> Result<Self, ParseError> {
        let count = reader.u16()?;
        // Every value takes at least its four-byte length, so a count the
        // frame cannot hold fails here, before the loop.
        let min_len = usize::from(count)
            .checked_mul(4)
            .ok_or(ParseError::CountExceedsFrame)?;
        if min_len > reader.remaining() {
            return Err(ParseError::CountExceedsFrame);
        }
        let start = *reader;
        for _ in 0..count {
            read_value(reader)?;
        }
        Ok(Self {
            count,
            bytes: reader.consumed_since(&start),
        })
    }

    /// The number of values.
    #[must_use]
    pub fn len(&self) -> usize {
        usize::from(self.count)
    }

    /// Whether the list is empty.
    #[must_use]
    pub const fn is_empty(&self) -> bool {
        self.count == 0
    }

    /// Iterates over the values in order. `None` is the SQL NULL.
    #[must_use]
    pub const fn iter(&self) -> ValueIter<'a> {
        ValueIter {
            remaining: self.count,
            reader: Reader::new(self.bytes),
        }
    }
}

impl<'a> IntoIterator for Values<'a> {
    type Item = Option<&'a [u8]>;
    type IntoIter = ValueIter<'a>;

    fn into_iter(self) -> Self::IntoIter {
        self.iter()
    }
}

impl fmt::Debug for Values<'_> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Values")
            .field("count", &self.count)
            .field("encoded", &Redacted(self.bytes))
            .finish()
    }
}

/// Reads one value: a length, then that many bytes. A length of -1 is NULL.
fn read_value<'a>(reader: &mut Reader<'a>) -> Result<Option<&'a [u8]>, ParseError> {
    let len = reader.i32()?;
    if len == -1 {
        return Ok(None);
    }
    let len = usize::try_from(len).map_err(|_| ParseError::NegativeLength)?;
    reader.take(len).map(Some)
}

/// An iterator over [`Values`]. `None` is the SQL NULL.
#[derive(Clone)]
pub struct ValueIter<'a> {
    remaining: u16,
    reader: Reader<'a>,
}

impl<'a> Iterator for ValueIter<'a> {
    type Item = Option<&'a [u8]>;

    fn next(&mut self) -> Option<Self::Item> {
        self.remaining = self.remaining.checked_sub(1)?;
        read_value(&mut self.reader).ok()
    }

    fn size_hint(&self) -> (usize, Option<usize>) {
        let remaining = usize::from(self.remaining);
        (remaining, Some(remaining))
    }
}

impl ExactSizeIterator for ValueIter<'_> {}

impl fmt::Debug for ValueIter<'_> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("ValueIter")
            .field("remaining", &self.remaining)
            .finish_non_exhaustive()
    }
}

/// An iterator over consecutive zero-terminated strings.
#[derive(Clone)]
pub struct CStrings<'a> {
    reader: Reader<'a>,
}

impl<'a> CStrings<'a> {
    /// Iterates over a region already known to consist of terminated
    /// strings and nothing else.
    pub(crate) const fn new(region: &'a [u8]) -> Self {
        Self {
            reader: Reader::new(region),
        }
    }
}

impl<'a> Iterator for CStrings<'a> {
    type Item = &'a [u8];

    fn next(&mut self) -> Option<Self::Item> {
        if self.reader.is_empty() {
            return None;
        }
        self.reader.cstr().ok()
    }
}

impl fmt::Debug for CStrings<'_> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("CStrings").finish_non_exhaustive()
    }
}

/// `CopyData`: a piece of a COPY stream. Sent in both directions.
///
/// The body is opaque. Its division into rows is up to the sender, so one
/// row may span several messages and one message may hold several rows.
#[derive(Clone, Copy, PartialEq, Eq)]
pub struct CopyData<'a> {
    data: &'a [u8],
}

impl<'a> CopyData<'a> {
    /// The type byte, the same in both directions.
    pub const TAG: u8 = b'd';

    /// Reads a frame of either direction as `CopyData`.
    ///
    /// # Errors
    ///
    /// Fails when the frame has another type byte.
    pub fn from_frame(frame: Frame<'a>) -> Result<Self, ParseError> {
        if frame.tag() == Self::TAG {
            Ok(Self { data: frame.body() })
        } else {
            Err(frame.unexpected())
        }
    }

    /// The data carried by the message.
    #[must_use]
    pub const fn data(&self) -> &'a [u8] {
        self.data
    }
}

impl fmt::Debug for CopyData<'_> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("CopyData")
            .field("data", &Redacted(self.data))
            .finish()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn format_codes_parse_and_index() {
        let mut reader = Reader::new(&[0, 3, 0, 0, 0, 1, 0xff, 0xff, 0xaa]);
        let codes = FormatCodes::parse(&mut reader).unwrap();
        assert_eq!(reader.remaining(), 1, "only the codes are consumed");
        assert_eq!(codes.len(), 3);
        assert!(!codes.is_empty());
        assert_eq!(codes.get(0), Some(FormatCode::TEXT));
        assert_eq!(codes.get(1), Some(FormatCode::BINARY));
        assert_eq!(codes.get(2), Some(FormatCode(-1)));
        assert_eq!(codes.get(3), None);
        let collected: Vec<_> = codes.iter().collect();
        assert_eq!(
            collected,
            [FormatCode::TEXT, FormatCode::BINARY, FormatCode(-1)]
        );
        assert_eq!(codes.iter().len(), 3);
        assert_eq!(format!("{codes:?}"), "[0, 1, -1]");
        assert!(FormatCode(0).is_text());
        assert!(FormatCode(1).is_binary());
        assert!(!FormatCode(2).is_text() && !FormatCode(2).is_binary());
    }

    #[test]
    fn format_codes_count_is_checked_against_the_frame() {
        // Claims 65535 codes, holds one.
        let mut reader = Reader::new(&[0xff, 0xff, 0, 1]);
        assert_eq!(
            FormatCodes::parse(&mut reader),
            Err(ParseError::CountExceedsFrame)
        );
        // Half a code is missing.
        let mut reader = Reader::new(&[0, 2, 0, 1, 0]);
        assert_eq!(
            FormatCodes::parse(&mut reader),
            Err(ParseError::CountExceedsFrame)
        );
        // No count at all.
        let mut reader = Reader::new(&[0]);
        assert_eq!(FormatCodes::parse(&mut reader), Err(ParseError::Truncated));
    }

    #[test]
    fn code_for_follows_the_bind_rule() {
        let none = FormatCodes::parse(&mut Reader::new(&[0, 0])).unwrap();
        assert!(none.is_empty());
        assert_eq!(none.code_for(0), Some(FormatCode::TEXT));
        assert_eq!(none.code_for(999), Some(FormatCode::TEXT));

        let one = FormatCodes::parse(&mut Reader::new(&[0, 1, 0, 1])).unwrap();
        assert_eq!(one.code_for(0), Some(FormatCode::BINARY));
        assert_eq!(one.code_for(999), Some(FormatCode::BINARY));

        let two = FormatCodes::parse(&mut Reader::new(&[0, 2, 0, 1, 0, 0])).unwrap();
        assert_eq!(two.code_for(0), Some(FormatCode::BINARY));
        assert_eq!(two.code_for(1), Some(FormatCode::TEXT));
        assert_eq!(two.code_for(2), None);
    }

    #[test]
    fn values_parse_nulls_empty_and_data() {
        let bytes = [
            0, 4, // four values
            0xff, 0xff, 0xff, 0xff, // NULL
            0, 0, 0, 0, // empty
            0, 0, 0, 2, b'h', b'i', // "hi"
            0, 0, 0, 1, 0,    // one zero byte
            0x99, // not part of the list
        ];
        let mut reader = Reader::new(&bytes);
        let values = Values::parse(&mut reader).unwrap();
        assert_eq!(reader.remaining(), 1);
        assert_eq!(values.len(), 4);
        assert!(!values.is_empty());
        let collected: Vec<_> = values.iter().collect();
        assert_eq!(
            collected,
            [None, Some(&b""[..]), Some(&b"hi"[..]), Some(&[0u8][..])]
        );
        assert_eq!(values.iter().len(), 4);
        assert_eq!(values.into_iter().count(), 4);
    }

    #[test]
    fn values_count_is_checked_before_the_loop() {
        // Claims 65535 values in a region that could hold one.
        let mut reader = Reader::new(&[0xff, 0xff, 0, 0, 0, 0]);
        assert_eq!(
            Values::parse(&mut reader),
            Err(ParseError::CountExceedsFrame)
        );
    }

    #[test]
    fn values_reject_bad_lengths() {
        // A length that runs past the end.
        let mut reader = Reader::new(&[0, 1, 0, 0, 0, 5, b'a', b'b']);
        assert_eq!(Values::parse(&mut reader), Err(ParseError::Truncated));
        // A negative length other than -1.
        let mut reader = Reader::new(&[0, 1, 0xff, 0xff, 0xff, 0xfe]);
        assert_eq!(Values::parse(&mut reader), Err(ParseError::NegativeLength));
        // The most negative length.
        let mut reader = Reader::new(&[0, 1, 0x80, 0, 0, 0]);
        assert_eq!(Values::parse(&mut reader), Err(ParseError::NegativeLength));
        // The largest positive length.
        let mut reader = Reader::new(&[0, 1, 0x7f, 0xff, 0xff, 0xff]);
        assert_eq!(Values::parse(&mut reader), Err(ParseError::Truncated));
        // Enough room for the lengths, not for the second value.
        let mut reader = Reader::new(&[0, 2, 0, 0, 0, 0, 0, 0, 0, 1]);
        assert_eq!(Values::parse(&mut reader), Err(ParseError::Truncated));
    }

    #[test]
    fn empty_values_list() {
        let mut reader = Reader::new(&[0, 0]);
        let values = Values::parse(&mut reader).unwrap();
        assert!(values.is_empty());
        assert_eq!(values.iter().next(), None);
    }

    #[test]
    fn cstrings_iterates_a_region() {
        let strings: Vec<_> = CStrings::new(b"one\0\0three\0").collect();
        assert_eq!(strings, [&b"one"[..], &b""[..], &b"three"[..]]);
        assert_eq!(CStrings::new(b"").next(), None);
    }

    #[test]
    fn copy_data_is_read_in_both_directions() {
        use crate::frame::Direction;
        use crate::testutil::{frame, wire};

        let bytes = wire(b'd', b"1\talice\n2\tbob\n");
        for direction in [Direction::FromClient, Direction::FromServer] {
            let copy = CopyData::from_frame(frame(direction, &bytes)).unwrap();
            assert_eq!(copy.data(), b"1\talice\n2\tbob\n");
        }
        // An empty body is a valid, if useless, CopyData.
        let bytes = wire(b'd', b"");
        let copy = CopyData::from_frame(frame(Direction::FromServer, &bytes)).unwrap();
        assert_eq!(copy.data(), b"");

        let bytes = wire(b'c', b"");
        assert_eq!(
            CopyData::from_frame(frame(Direction::FromServer, &bytes)),
            Err(ParseError::UnexpectedMessage {
                direction: Direction::FromServer,
                tag: b'c'
            })
        );

        let bytes = wire(b'd', b"SECRETMARKER");
        let copy = CopyData::from_frame(frame(Direction::FromClient, &bytes)).unwrap();
        assert_eq!(format!("{copy:?}"), "CopyData { data: <12 bytes> }");
    }

    #[test]
    fn debug_output_omits_values() {
        let bytes = [0, 1, 0, 0, 0, 6, b'S', b'E', b'C', b'R', b'E', b'T'];
        let values = Values::parse(&mut Reader::new(&bytes)).unwrap();
        let text = format!("{values:?} {:?}", values.iter());
        assert!(!text.contains("SECRET"), "{text}");
        assert!(!text.contains("83"), "{text}");
    }
}
