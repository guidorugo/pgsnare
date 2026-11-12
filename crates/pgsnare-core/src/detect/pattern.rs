// SPDX-License-Identifier: Apache-2.0

//! The byte patterns a token value is turned into.

use std::fmt;

/// The shortest value a token may have, in bytes.
///
/// Shorter values would match ordinary data by accident.
pub const MIN_VALUE_LEN: usize = 12;

/// The form in which a token value was found.
///
/// Every value is looked for in the first two forms. The third exists only
/// for tokens that ask for it.
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
}

impl PatternForm {
    /// A short, stable name for the form: `raw`, `hex` or
    /// `case-insensitive`.
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Raw => "raw",
            Self::Hex => "hex",
            Self::CaseInsensitive => "case-insensitive",
        }
    }
}

impl fmt::Display for PatternForm {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
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
    }
}
