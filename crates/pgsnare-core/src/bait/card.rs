// SPDX-License-Identifier: Apache-2.0

//! Bait in the shape of a payment card number.
//!
//! A number is 16 digits: the digits `99`, 13 random digits, and the check
//! digit of the Luhn formula.
//!
//! No range of card numbers is known to be reserved for testing, so these
//! numbers are kept out of the ranges of the payment schemes instead. The
//! reasoning, what it rests on and what it costs are written down once, in
//! the documentation of [`Kind::CardNumber`](super::Kind::CardNumber).
//! Change the prefix here only together with that text.

use super::entropy::Draw;
use super::error::BaitError;
use super::value::Bait;

/// The digits every number begins with.
const PREFIX: [u8; 2] = [9, 9];

/// The number of random digits between the prefix and the check digit.
const RANDOM_DIGITS: usize = 13;

/// The length of a number: prefix, random digits and check digit.
pub(super) const CARD_NUMBER_LEN: usize = 16;

/// The check digit that the Luhn formula gives for `digits`, which are the
/// digits of a number without its last one.
///
/// Counting from the right, every second digit is doubled, starting with
/// the rightmost. A doubled digit above 9 has its own two digits added,
/// which is the same as taking 9 away. The check digit is what brings the
/// sum of all of them to a multiple of 10.
pub(super) fn luhn_check_digit(digits: &[u8]) -> Result<u8, BaitError> {
    let mut sum: u32 = 0;
    for (position, digit) in digits.iter().rev().enumerate() {
        if *digit > 9 {
            return Err(BaitError::Defect);
        }
        let digit = u32::from(*digit);
        let doubled = position.is_multiple_of(2);
        let value = match digit.checked_mul(2) {
            Some(twice) if doubled && twice > 9 => twice.checked_sub(9),
            Some(twice) if doubled => Some(twice),
            _ => Some(digit),
        };
        sum = value
            .and_then(|value| sum.checked_add(value))
            .ok_or(BaitError::Defect)?;
    }
    let remainder = sum.checked_rem(10).ok_or(BaitError::Defect)?;
    let check = 10u32
        .checked_sub(remainder)
        .and_then(|distance| distance.checked_rem(10))
        .ok_or(BaitError::Defect)?;
    u8::try_from(check).map_err(|_| BaitError::Defect)
}

/// A card number: see the documentation of this module.
pub(super) fn card_number(draw: &mut Draw<'_>) -> Result<Bait, BaitError> {
    let mut digits = Vec::with_capacity(CARD_NUMBER_LEN);
    digits.extend_from_slice(&PREFIX);
    draw.append_digits(RANDOM_DIGITS, &mut digits)?;
    digits.push(luhn_check_digit(&digits)?);

    let text = digits
        .iter()
        .map(|digit| char::from_digit(u32::from(*digit), 10))
        .collect::<Option<String>>()
        .ok_or(BaitError::Defect)?;
    if text.len() != CARD_NUMBER_LEN {
        return Err(BaitError::Defect);
    }
    Bait::new(text)
}

#[cfg(test)]
pub(super) mod testing {
    //! The Luhn formula once more, as a check of a whole number, written
    //! the way the formula is usually stated and not the way the generator
    //! computes a digit.

    /// Whether a number of decimal digits passes the Luhn check.
    pub(crate) fn passes_luhn(number: &str) -> bool {
        if number.is_empty() || !number.bytes().all(|byte| byte.is_ascii_digit()) {
            return false;
        }
        let mut sum = 0u32;
        // From the right: the check digit as it is, the next one doubled,
        // and so on in turn.
        for (position, byte) in number.bytes().rev().enumerate() {
            let digit = u32::from(byte - b'0');
            if position % 2 == 1 {
                let twice = digit * 2;
                sum += twice / 10 + twice % 10;
            } else {
                sum += digit;
            }
        }
        sum.is_multiple_of(10)
    }
}

#[cfg(test)]
mod tests {
    use super::super::entropy::testing::{Constant, Failing, Sequence};
    use super::testing::passes_luhn;
    use super::*;

    fn digits(text: &str) -> Vec<u8> {
        text.bytes().map(|byte| byte - b'0').collect()
    }

    fn number(seed: u64) -> String {
        let mut source = Sequence::new(seed);
        let mut draw = Draw::new(&mut source);
        card_number(&mut draw).unwrap().expose().to_owned()
    }

    #[test]
    fn the_check_digit_follows_the_luhn_formula() {
        // The worked example that is usually given for the formula: the
        // digits 7992739871 take the check digit 3.
        assert_eq!(luhn_check_digit(&digits("7992739871")), Ok(3));
        // Checked by hand. 1: doubled is 2, so the digit is 8.
        assert_eq!(luhn_check_digit(&digits("1")), Ok(8));
        // 0: the sum is 0 and so is the digit, not 10.
        assert_eq!(luhn_check_digit(&digits("0")), Ok(0));
        assert_eq!(luhn_check_digit(&digits("000000000000000")), Ok(0));
        // 5 doubled is 10, which counts as 1, so the digit is 9.
        assert_eq!(luhn_check_digit(&digits("5")), Ok(9));
        // 18: 8 doubled is 16, which counts as 7, plus 1 is 8: digit 2.
        assert_eq!(luhn_check_digit(&digits("18")), Ok(2));
        assert_eq!(luhn_check_digit(&[]), Ok(0));
    }

    #[test]
    fn the_checker_of_the_tests_agrees_with_published_examples() {
        // If the checker accepted everything, it could show nothing.
        assert!(passes_luhn("79927398713"));
        for wrong in [
            "79927398710",
            "79927398714",
            "79927398731",
            "",
            "7992739871x",
        ] {
            assert!(!passes_luhn(wrong), "{wrong}");
        }
        // Every other final digit fails.
        let passing: Vec<u8> = (0..=9)
            .filter(|digit| passes_luhn(&format!("7992739871{digit}")))
            .collect();
        assert_eq!(passing, [3]);
    }

    #[test]
    fn the_check_digit_makes_every_number_pass() {
        let mut source = Sequence::new(7);
        let mut draw = Draw::new(&mut source);
        for length in 1..40 {
            let mut number = Vec::new();
            draw.append_digits(length, &mut number).unwrap();
            number.push(luhn_check_digit(&number).unwrap());
            let text: String = number
                .iter()
                .map(|digit| char::from(b'0' + digit))
                .collect();
            assert!(passes_luhn(&text), "{text}");
        }
    }

    #[test]
    fn something_that_is_not_a_digit_is_a_defect() {
        assert_eq!(luhn_check_digit(&[1, 2, 10]), Err(BaitError::Defect));
        assert_eq!(luhn_check_digit(b"7"), Err(BaitError::Defect));
    }

    #[test]
    fn a_number_is_sixteen_digits_that_pass_the_luhn_check() {
        for seed in 0..2000 {
            let number = number(seed);
            assert_eq!(number.len(), 16, "{number}");
            assert!(number.bytes().all(|byte| byte.is_ascii_digit()), "{number}");
            assert!(passes_luhn(&number), "{number}");
        }
    }

    #[test]
    fn a_number_is_outside_the_ranges_of_the_payment_schemes() {
        for seed in 0..2000 {
            let number = number(seed);
            // The first digit is the industry. 2 to 6 are the ones that
            // include banking and finance.
            assert!(number.starts_with("99"), "{number}");
            assert!(!matches!(number.as_bytes()[0], b'2'..=b'6'), "{number}");
        }
    }

    #[test]
    fn the_thirteen_digits_in_the_middle_are_random() {
        let numbers: std::collections::HashSet<String> = (0..5000).map(number).collect();
        assert_eq!(numbers.len(), 5000);
        // Every digit turns up in every one of the thirteen places.
        for place in 2..15 {
            let seen: std::collections::BTreeSet<u8> = numbers
                .iter()
                .map(|number| number.as_bytes()[place])
                .collect();
            assert_eq!(seen.len(), 10, "place {place}");
        }
    }

    #[test]
    fn a_source_that_fails_gives_no_number() {
        let mut source = Failing;
        let mut draw = Draw::new(&mut source);
        assert!(matches!(card_number(&mut draw), Err(BaitError::Entropy(_))));

        // 0xff cannot be turned into a digit without favouring some digits.
        let mut source = Constant(0xff);
        let mut draw = Draw::new(&mut source);
        assert_eq!(card_number(&mut draw), Err(BaitError::UnusableEntropy));
    }

    #[test]
    fn a_number_from_known_digits_is_what_the_format_says() {
        // Every byte is 7, so every random digit is 7:
        // 99 7777777777777 and the check digit.
        let mut source = Constant(7);
        let mut draw = Draw::new(&mut source);
        let number = card_number(&mut draw).unwrap().expose().to_owned();
        assert_eq!(&number[..15], "997777777777777");
        assert!(passes_luhn(&number));
        // By hand, from the right of the fifteen digits: seven 7s are
        // doubled and count 5 each, six 7s count 7 each, the 9 next to them
        // counts 9, and the first 9 is doubled and counts 9 as well.
        // 35 + 42 + 9 + 9 = 95, so the digit is 5.
        assert_eq!(number, "9977777777777775");
    }
}
