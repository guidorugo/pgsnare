// SPDX-License-Identifier: Apache-2.0

//! Base64 in the three alphabets the bait formats use.
//!
//! All three split the input into groups of six bits, the first byte on
//! top, and fill the last group with zero bits. That is the encoding of
//! RFC 4648, and it is also what the reference implementation of bcrypt
//! does with an alphabet of its own. Encoding bytes this way always gives
//! the one spelling a strict decoder accepts: a decoder such as the
//! reference implementation of Argon2 refuses a last character with stray
//! bits in it.

use super::error::BaitError;

/// The alphabet of RFC 4648, section 4.
pub(super) const STANDARD: &[u8; 64] =
    b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";

/// The alphabet of RFC 4648, section 5, which is safe in URLs and file
/// names.
pub(super) const URL_SAFE: &[u8; 64] =
    b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_";

/// The alphabet of bcrypt, as in `Base64Code` of OpenBSD's `bcrypt.c`.
pub(super) const BCRYPT: &[u8; 64] =
    b"./ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789";

/// Whether the output is filled up to a multiple of four characters.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(super) enum Padding {
    /// No padding. bcrypt and the Argon2 format never pad.
    None,
    /// `=` characters, as RFC 4648 asks for by default.
    Equals,
}

/// The character for the low six bits of `group`.
fn symbol(alphabet: &[u8; 64], group: u32) -> Result<char, BaitError> {
    let index = usize::try_from(group & 0x3f).map_err(|_| BaitError::Defect)?;
    alphabet
        .get(index)
        .copied()
        .map(char::from)
        .ok_or(BaitError::Defect)
}

/// Appends `data` in Base64 to `out`.
pub(super) fn append_base64(
    data: &[u8],
    alphabet: &[u8; 64],
    padding: Padding,
    out: &mut String,
) -> Result<(), BaitError> {
    for chunk in data.chunks(3) {
        let (first, second, third) = match *chunk {
            [first] => (first, None, None),
            [first, second] => (first, Some(second), None),
            [first, second, third] => (first, Some(second), Some(third)),
            _ => return Err(BaitError::Defect),
        };
        // Up to three bytes as one number of 24 bits, the first byte on top.
        let group = (u32::from(first) << 16)
            | (u32::from(second.unwrap_or(0)) << 8)
            | u32::from(third.unwrap_or(0));

        out.push(symbol(alphabet, group >> 18)?);
        out.push(symbol(alphabet, group >> 12)?);
        match (second, padding) {
            (Some(_), _) => out.push(symbol(alphabet, group >> 6)?),
            (None, Padding::Equals) => out.push('='),
            (None, Padding::None) => {}
        }
        match (third, padding) {
            (Some(_), _) => out.push(symbol(alphabet, group)?),
            (None, Padding::Equals) => out.push('='),
            (None, Padding::None) => {}
        }
    }
    Ok(())
}

#[cfg(test)]
pub(super) mod testing {
    //! A decoder for tests, written without reference to the encoder: it
    //! looks every character up and collects bits.

    /// Decodes Base64 text. Returns `None` for a character outside the
    /// alphabet, for padding in the wrong place, for a length no encoder
    /// produces, and for a last character with stray bits.
    pub(crate) fn decode(text: &str, alphabet: &[u8; 64], padded: bool) -> Option<Vec<u8>> {
        let body = if padded {
            if !text.len().is_multiple_of(4) {
                return None;
            }
            let body = text.trim_end_matches('=');
            if text.len() - body.len() > 2 {
                return None;
            }
            body
        } else {
            text
        };
        if body.len() % 4 == 1 {
            return None;
        }

        let mut bits: u32 = 0;
        let mut bit_count = 0;
        let mut bytes = Vec::new();
        for character in body.bytes() {
            let value = alphabet.iter().position(|symbol| *symbol == character)?;
            bits = (bits << 6) | u32::try_from(value).ok()?;
            bit_count += 6;
            if bit_count >= 8 {
                bit_count -= 8;
                bytes.push(u8::try_from((bits >> bit_count) & 0xff).ok()?);
            }
        }
        // What is left over must be zero: anything else is a second
        // spelling of the same bytes.
        let stray = bits & ((1 << bit_count) - 1);
        (stray == 0).then_some(bytes)
    }
}

#[cfg(test)]
mod tests {
    use super::testing::decode;
    use super::*;

    fn encode(data: &[u8], alphabet: &[u8; 64], padding: Padding) -> String {
        let mut out = String::new();
        append_base64(data, alphabet, padding, &mut out).unwrap();
        out
    }

    #[test]
    fn the_alphabets_have_64_different_characters() {
        for alphabet in [STANDARD, URL_SAFE, BCRYPT] {
            let distinct: std::collections::BTreeSet<u8> = alphabet.iter().copied().collect();
            assert_eq!(distinct.len(), 64);
        }
    }

    #[test]
    fn the_standard_alphabet_gives_the_test_vectors_of_rfc_4648() {
        // RFC 4648, section 10.
        for (plain, encoded) in [
            ("", ""),
            ("f", "Zg=="),
            ("fo", "Zm8="),
            ("foo", "Zm9v"),
            ("foob", "Zm9vYg=="),
            ("fooba", "Zm9vYmE="),
            ("foobar", "Zm9vYmFy"),
        ] {
            assert_eq!(encode(plain.as_bytes(), STANDARD, Padding::Equals), encoded);
            assert_eq!(
                encode(plain.as_bytes(), STANDARD, Padding::None),
                encoded.trim_end_matches('=')
            );
        }
    }

    #[test]
    fn the_last_two_characters_differ_between_the_alphabets() {
        // Six bits of ones are the 64th character, and 111110 is the 63rd.
        assert_eq!(encode(&[0xfb, 0xff], STANDARD, Padding::None), "+/8");
        assert_eq!(encode(&[0xfb, 0xff], URL_SAFE, Padding::None), "-_8");
        assert_eq!(encode(&[0xff, 0xff, 0xff], STANDARD, Padding::None), "////");
        assert_eq!(encode(&[0xff, 0xff, 0xff], URL_SAFE, Padding::None), "____");
    }

    #[test]
    fn the_bcrypt_alphabet_gives_what_the_reference_implementation_gives() {
        // Worked by hand from `encode_base64` in OpenBSD's `bcrypt.c`,
        // which looks up `c1 >> 2`, then `(c1 & 0x03) << 4 | c2 >> 4`, then
        // `(c2 & 0x0f) << 2 | c3 >> 6`, then `c3 & 0x3f` in
        // "./ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789".
        assert_eq!(encode(&[0x00], BCRYPT, Padding::None), "..");
        assert_eq!(encode(&[0xff], BCRYPT, Padding::None), "9u");
        assert_eq!(encode(&[0xff, 0xff], BCRYPT, Padding::None), "996");
        assert_eq!(encode(&[0xff, 0xff, 0xff], BCRYPT, Padding::None), "9999");
        assert_eq!(encode(&[0x00, 0x00, 0x01], BCRYPT, Padding::None), ".../");
        // The groups 1, 2, 3 and 4, which are the second to fifth character.
        assert_eq!(encode(&[0x04, 0x20, 0xc4], BCRYPT, Padding::None), "/ABC");
    }

    #[test]
    fn the_output_has_the_length_the_formats_count_on() {
        for (bytes, unpadded, padded) in [(16, 22, 24), (23, 31, 32), (30, 40, 40), (32, 43, 44)] {
            let data = vec![0xa5u8; bytes];
            assert_eq!(encode(&data, STANDARD, Padding::None).len(), unpadded);
            assert_eq!(encode(&data, STANDARD, Padding::Equals).len(), padded);
        }
    }

    #[test]
    fn a_separate_decoder_gets_the_bytes_back() {
        let data: Vec<u8> = (0..=255u8).rev().collect();
        for length in 0..=data.len() {
            let data = &data[..length];
            for alphabet in [STANDARD, URL_SAFE, BCRYPT] {
                let unpadded = encode(data, alphabet, Padding::None);
                assert_eq!(decode(&unpadded, alphabet, false).as_deref(), Some(data));
                let padded = encode(data, alphabet, Padding::Equals);
                assert_eq!(decode(&padded, alphabet, true).as_deref(), Some(data));
            }
        }
    }

    #[test]
    fn the_decoder_of_the_tests_is_strict() {
        // If it were not, it could not show that the encoder is.
        assert_eq!(decode("Zg==", STANDARD, true).as_deref(), Some(&b"f"[..]));
        // The same byte with stray bits in the last character.
        assert_eq!(decode("Zh==", STANDARD, true), None);
        assert_eq!(decode("Zh", STANDARD, false), None);
        // Padding that is missing, misplaced or too long.
        assert_eq!(decode("Zg", STANDARD, true), None);
        assert_eq!(decode("Zg=", STANDARD, true), None);
        assert_eq!(decode("Z===", STANDARD, true), None);
        assert_eq!(decode("Zg==", STANDARD, false), None);
        // A character of another alphabet, and a length nothing encodes to.
        assert_eq!(decode("-_8", STANDARD, false), None);
        assert_eq!(decode("Zm9vY", STANDARD, false), None);
    }
}
