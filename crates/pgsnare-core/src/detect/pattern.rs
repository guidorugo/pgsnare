// SPDX-License-Identifier: Apache-2.0

//! The byte patterns a token value is turned into.

use std::fmt;

/// The shortest value a token may have, in bytes.
///
/// Shorter values would match ordinary data by accident.
pub const MIN_VALUE_LEN: usize = 12;

/// The form in which a token value was found.
///
/// Every value is looked for in the first two forms. The others exist only
/// for the tokens and the values that ask for them.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
#[non_exhaustive]
pub enum PatternForm {
    /// The bytes of the value, exactly as configured.
    Raw,
    /// The value written as lowercase hexadecimal digits, two per byte. This
    /// is how PostgreSQL prints a `bytea` value in text format.
    Hex,
    /// The value with at least one ASCII letter in another case. An
    /// occurrence in exactly the configured case is reported as
    /// [`PatternForm::Raw`] instead.
    CaseInsensitive,
    /// The sixteen bytes a value that is a canonical UUID encodes. This is
    /// how PostgreSQL sends a `uuid` value in a binary result or a binary
    /// COPY. Only the values that are written as 8-4-4-4-12 hexadecimal
    /// digits have this form.
    UuidBinary,
}

impl PatternForm {
    /// A short, stable name for the form: `raw`, `hex`, `case-insensitive`
    /// or `uuid-binary`.
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Raw => "raw",
            Self::Hex => "hex",
            Self::CaseInsensitive => "case-insensitive",
            Self::UuidBinary => "uuid-binary",
        }
    }
}

impl fmt::Display for PatternForm {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

/// The sixteen bytes a value written as a canonical UUID encodes, or `None`
/// if the value is not written that way.
///
/// The value must be exactly 8-4-4-4-12 hexadecimal digits, separated by
/// hyphens, and nothing else: braces, a `urn:` prefix and any other
/// separator are not canonical, and get no pattern. The digits may be in
/// either letter case, and both cases give the same bytes.
pub fn uuid_bytes(value: &[u8]) -> Option<Vec<u8>> {
    if value.len() != 36 {
        return None;
    }
    let mut nibbles = Vec::with_capacity(32);
    for (index, &byte) in value.iter().enumerate() {
        if index == 8 || index == 13 || index == 18 || index == 23 {
            if byte != b'-' {
                return None;
            }
            continue;
        }
        nibbles.push(match byte {
            b'0' => 0,
            b'1' => 1,
            b'2' => 2,
            b'3' => 3,
            b'4' => 4,
            b'5' => 5,
            b'6' => 6,
            b'7' => 7,
            b'8' => 8,
            b'9' => 9,
            b'a' | b'A' => 10,
            b'b' | b'B' => 11,
            b'c' | b'C' => 12,
            b'd' | b'D' => 13,
            b'e' | b'E' => 14,
            b'f' | b'F' => 15,
            _ => return None,
        });
    }
    // The nibbles are thirty-two, so the pairing never leaves a remainder.
    let mut bytes = Vec::with_capacity(16);
    let mut index = 0usize;
    while let (Some(&high), Some(&low)) = (nibbles.get(index), nibbles.get(index.checked_add(1)?)) {
        bytes.push(high << 4 | low);
        index = index.checked_add(2)?;
    }
    Some(bytes)
}

/// Writes `bytes` as lowercase hexadecimal digits, two per byte.
pub(crate) fn hex_lower(bytes: &[u8]) -> Vec<u8> {
    let mut hex = Vec::with_capacity(bytes.len().saturating_mul(2));
    for &byte in bytes {
        hex.push(hex_digit(byte >> 4));
        hex.push(hex_digit(byte));
    }
    hex
}

/// The lowercase hexadecimal digit for the low four bits of `nibble`.
const fn hex_digit(nibble: u8) -> u8 {
    match nibble & 0x0f {
        0x0 => b'0',
        0x1 => b'1',
        0x2 => b'2',
        0x3 => b'3',
        0x4 => b'4',
        0x5 => b'5',
        0x6 => b'6',
        0x7 => b'7',
        0x8 => b'8',
        0x9 => b'9',
        0xa => b'a',
        0xb => b'b',
        0xc => b'c',
        0xd => b'd',
        0xe => b'e',
        _ => b'f',
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn hex_matches_the_standard_formatter_for_every_byte() {
        for byte in 0..=u8::MAX {
            assert_eq!(hex_lower(&[byte]), format!("{byte:02x}").into_bytes());
        }
    }

    #[test]
    fn hex_of_a_value_is_what_postgresql_prints_for_bytea() {
        // `SELECT 'svc.backup'::bytea` prints `\x7376632e6261636b7570`.
        assert_eq!(hex_lower(b"svc.backup"), b"7376632e6261636b7570");
        assert_eq!(hex_lower(b""), b"");
    }

    #[test]
    fn form_names_are_stable() {
        assert_eq!(PatternForm::Raw.to_string(), "raw");
        assert_eq!(PatternForm::Hex.to_string(), "hex");
        assert_eq!(PatternForm::CaseInsensitive.to_string(), "case-insensitive");
        assert_eq!(PatternForm::UuidBinary.to_string(), "uuid-binary");
    }

    #[test]
    fn a_canonical_uuid_value_gives_its_sixteen_bytes() {
        assert_eq!(
            uuid_bytes(b"f81d4fae-7dec-11d0-a765-00a0c91e6bf6"),
            Some(vec![
                0xf8, 0x1d, 0x4f, 0xae, 0x7d, 0xec, 0x11, 0xd0, 0xa7, 0x65, 0x00, 0xa0, 0xc9, 0x1e,
                0x6b, 0xf6
            ])
        );
        // Upper and lower case digits give the same bytes.
        assert_eq!(
            uuid_bytes(b"F81D4FAE-7DEC-11D0-A765-00A0C91E6BF6"),
            uuid_bytes(b"f81d4fae-7dec-11d0-a765-00a0c91e6bf6")
        );
        assert_eq!(
            uuid_bytes(b"f81D4faE-7dEC-11d0-a765-00A0C91e6Bf6"),
            uuid_bytes(b"f81d4fae-7dec-11d0-a765-00a0c91e6bf6")
        );
    }

    #[test]
    fn a_value_that_is_not_a_canonical_uuid_gives_no_bytes() {
        let not_uuids: &[&[u8]] = &[
            b"",
            b"f81d4fae-7dec-11d0-a765-00a0c91e6bf", // one digit short
            b"f81d4fae-7dec-11d0-a765-00a0c91e6bf60", // one digit over
            b"f81d4fae7dec11d0a76500a0c91e6bf6",    // no hyphens
            b"{f81d4fae-7dec-11d0-a765-00a0c91e6bf6}", // braces
            b"urn:uuid:f81d4fae-7dec-11d0-a7650012", // a prefix
            b"f81d4fae_7dec_11d0_a765_00a0c91e6bf6", // another separator
            b"f81d4fae-7dec-11d0-a765-00a0c91e6bf-", // a hyphen in the end
            b"f81d4fag-7dec-11d0-a765-00a0c91e6bf6", // not a hex digit
            b"f81d4fae-7dec-11d0-a765-00a0c91e6bfg", // not a hex digit, at the end
            b" 81d4fae-7dec-11d0-a765-00a0c91e6bf6", // a space
        ];
        for value in not_uuids {
            assert_eq!(uuid_bytes(value), None, "{value:?}");
        }
    }
}
