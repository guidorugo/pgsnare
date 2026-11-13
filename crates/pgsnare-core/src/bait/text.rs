// SPDX-License-Identifier: Apache-2.0

//! Bait that is plain random text: API keys and free-text markers.

use super::encode::{Padding, URL_SAFE, append_base64};
use super::entropy::Draw;
use super::error::BaitError;
use super::value::Bait;

/// The length of an API key.
pub(super) const API_KEY_LEN: usize = 40;

/// The length of a marker: four groups of four characters and three
/// hyphens.
pub(super) const MARKER_LEN: usize = 19;

/// The upper-case alphabet of Base32 in RFC 4648, section 6.
const BASE32_UPPER: &[u8; 32] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZ234567";

/// An API key: 40 letters, digits, `-` and `_`.
///
/// It is 30 random bytes in the URL-safe Base64 of RFC 4648. It carries no
/// prefix: the prefixes that keys carry in the wild each name a service,
/// and bait must not pass for the key of a service that exists.
pub(super) fn api_key(draw: &mut Draw<'_>) -> Result<Bait, BaitError> {
    let bytes: [u8; 30] = draw.bytes()?;
    let mut text = String::with_capacity(API_KEY_LEN);
    append_base64(&bytes, URL_SAFE, Padding::None, &mut text)?;
    if text.len() != API_KEY_LEN {
        return Err(BaitError::Defect);
    }
    Bait::new(text)
}

/// A marker for free text: four groups of four upper-case letters and
/// digits, such as `ABCD-EFGH-IJKL-MNOP`.
///
/// It reads like a reference number and can stand inside a sentence of a
/// note, a comment or a document. Matching looks for the value anywhere in
/// a message, so the text around it does not matter.
pub(super) fn marker(draw: &mut Draw<'_>) -> Result<Bait, BaitError> {
    let mut text = String::with_capacity(MARKER_LEN);
    for group in 0..4 {
        if group > 0 {
            text.push('-');
        }
        draw.append_base32(BASE32_UPPER, 4, &mut text)?;
    }
    if text.len() != MARKER_LEN {
        return Err(BaitError::Defect);
    }
    Bait::new(text)
}

#[cfg(test)]
mod tests {
    use super::super::encode::testing::decode;
    use super::super::entropy::testing::{Constant, Sequence};
    use super::*;

    fn with_sequence(seed: u64, generator: fn(&mut Draw<'_>) -> Result<Bait, BaitError>) -> String {
        let mut source = Sequence::new(seed);
        let mut draw = Draw::new(&mut source);
        generator(&mut draw).unwrap().expose().to_owned()
    }

    #[test]
    fn an_api_key_is_forty_url_safe_characters_from_thirty_bytes() {
        for seed in 0..500 {
            let key = with_sequence(seed, api_key);
            assert_eq!(key.len(), 40);
            assert!(
                key.bytes()
                    .all(|byte| byte.is_ascii_alphanumeric() || byte == b'-' || byte == b'_'),
                "{key}"
            );
            assert_eq!(
                decode(&key, URL_SAFE, false).map(|bytes| bytes.len()),
                Some(30)
            );
        }
    }

    #[test]
    fn an_api_key_carries_every_byte_it_was_given() {
        // The key is the encoding of exactly the bytes drawn: nothing is
        // dropped and nothing is fixed.
        let mut source = Sequence::new(11);
        let mut draw = Draw::new(&mut source);
        let key = api_key(&mut draw).unwrap();

        let mut expected = [0u8; 30];
        let mut source = Sequence::new(11);
        Draw::new(&mut source)
            .bytes::<30>()
            .map(|bytes| expected = bytes)
            .unwrap();
        assert_eq!(
            decode(key.expose(), URL_SAFE, false),
            Some(expected.to_vec())
        );
    }

    #[test]
    fn a_marker_is_four_groups_of_four() {
        for seed in 0..500 {
            let marker = with_sequence(seed, marker);
            assert_eq!(marker.len(), 19);
            let groups: Vec<&str> = marker.split('-').collect();
            assert_eq!(groups.len(), 4, "{marker}");
            for group in groups {
                assert_eq!(group.len(), 4, "{marker}");
                assert!(
                    group.bytes().all(|byte| BASE32_UPPER.contains(&byte)),
                    "{marker}"
                );
            }
        }
    }

    #[test]
    fn a_marker_from_known_bytes_is_what_the_format_says() {
        // Five bits of every byte choose a character: 0 is A and 31 is 7.
        let mut source = Constant(0);
        assert_eq!(
            marker(&mut Draw::new(&mut source)).unwrap().expose(),
            "AAAA-AAAA-AAAA-AAAA"
        );
        let mut source = Constant(0xff);
        assert_eq!(
            marker(&mut Draw::new(&mut source)).unwrap().expose(),
            "7777-7777-7777-7777"
        );
    }

    #[test]
    fn the_values_differ_from_one_to_the_next() {
        for generator in [api_key, marker] {
            let values: std::collections::HashSet<String> = (0..5000)
                .map(|seed| with_sequence(seed, generator))
                .collect();
            assert_eq!(values.len(), 5000);
        }
    }
}
