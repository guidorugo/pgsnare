// SPDX-License-Identifier: Apache-2.0

//! Text for events that comes from the network.

/// Appended to text that had to be cut.
pub const TRUNCATION_MARK: char = '\u{2026}';

/// A sensible limit for a name taken from the network, such as a database
/// user, a database or an application name.
pub const MAX_NAME_BYTES: usize = 256;

/// Turns bytes from the network into bounded text for an event.
///
/// Bytes that are not valid UTF-8 are replaced, and at most `max_bytes`
/// bytes of text are kept. When something had to be cut, the result ends
/// with [`TRUNCATION_MARK`]. The work done is bounded by `max_bytes`, not by
/// the length of the input.
///
/// This does not hide honeytoken values: redaction happens later, in one
/// place, for every event.
#[must_use]
pub fn text_from_wire(bytes: &[u8], max_bytes: usize) -> String {
    // Four extra bytes are enough to finish the character at the limit.
    let window_len = max_bytes.saturating_add(4);
    let input_was_cut = bytes.len() > window_len;
    let window = bytes.get(..window_len).unwrap_or(bytes);
    let text = String::from_utf8_lossy(window);

    if !input_was_cut && text.len() <= max_bytes {
        return text.into_owned();
    }

    let mut end = 0usize;
    for (start, character) in text.char_indices() {
        let next = start.saturating_add(character.len_utf8());
        if next > max_bytes {
            break;
        }
        end = next;
    }

    let mut out = String::with_capacity(end.saturating_add(TRUNCATION_MARK.len_utf8()));
    out.push_str(text.get(..end).unwrap_or_default());
    out.push(TRUNCATION_MARK);
    out
}

#[cfg(test)]
mod tests {
    use proptest::prelude::*;

    use super::*;

    #[test]
    fn short_text_is_kept_as_it_is() {
        assert_eq!(text_from_wire(b"", 8), "");
        assert_eq!(text_from_wire(b"app", 8), "app");
        assert_eq!(text_from_wire(b"exactly8", 8), "exactly8");
    }

    #[test]
    fn long_text_is_cut_and_marked() {
        assert_eq!(text_from_wire(b"exactly8+", 8), "exactly8\u{2026}");
        assert_eq!(text_from_wire(&[b'a'; 10_000], 3), "aaa\u{2026}");
        assert_eq!(text_from_wire(b"abc", 0), "\u{2026}");
    }

    #[test]
    fn a_character_is_never_split() {
        // Each of these characters takes two bytes.
        let text = "\u{e9}\u{e9}\u{e9}";
        assert_eq!(text_from_wire(text.as_bytes(), 6), text);
        assert_eq!(text_from_wire(text.as_bytes(), 5), "\u{e9}\u{e9}\u{2026}");
        assert_eq!(text_from_wire(text.as_bytes(), 4), "\u{e9}\u{e9}\u{2026}");
        assert_eq!(text_from_wire(text.as_bytes(), 1), "\u{2026}");
    }

    #[test]
    fn invalid_utf8_is_replaced() {
        assert_eq!(text_from_wire(b"a\xffb", 16), "a\u{fffd}b");
        // The replacement takes three bytes, so it may no longer fit.
        assert_eq!(text_from_wire(b"a\xffb", 3), "a\u{2026}");
    }

    proptest! {
        #[test]
        fn the_result_is_bounded_and_marked_when_cut(
            bytes in proptest::collection::vec(any::<u8>(), 0..600),
            max_bytes in 0usize..300,
        ) {
            let text = text_from_wire(&bytes, max_bytes);
            let mark = TRUNCATION_MARK.len_utf8();
            prop_assert!(text.len() <= max_bytes + mark);

            let whole = String::from_utf8_lossy(&bytes);
            if whole.len() <= max_bytes {
                prop_assert_eq!(text, whole);
            } else {
                prop_assert!(text.ends_with(TRUNCATION_MARK));
                let kept = &text[..text.len() - mark];
                prop_assert!(whole.starts_with(kept));
            }
        }
    }
}
