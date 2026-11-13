// SPDX-License-Identifier: Apache-2.0

//! Bait in the shape of a stored password: bcrypt, Argon2id and
//! SCRAM-SHA-256.
//!
//! Each value has the format of its kind, down to the lengths and the
//! spelling a strict parser insists on. None is the hash of anything: the
//! parts that a real hash computes are random bytes here. A value is
//! therefore not a way to any password, and no password verifies against
//! it other than by chance.

use super::encode::{BCRYPT, Padding, STANDARD, append_base64};
use super::entropy::Draw;
use super::error::BaitError;
use super::value::Bait;

/// The length of a bcrypt hash in its text form.
pub(super) const BCRYPT_LEN: usize = 60;

/// The length of an Argon2id hash with the parameters used here.
pub(super) const ARGON2ID_LEN: usize = 97;

/// The length of a SCRAM-SHA-256 verifier with a salt of 16 bytes and four
/// digits of iterations.
pub(super) const SCRAM_SHA_256_LEN: usize = 133;

/// The text must have the length its format gives it.
fn finish(text: String, length: usize) -> Result<Bait, BaitError> {
    if text.len() == length {
        Bait::new(text)
    } else {
        Err(BaitError::Defect)
    }
}

/// A bcrypt hash: `$2b$12$`, then a salt of 22 characters and a hash of 31.
///
/// The format is the one of the reference implementation, OpenBSD's
/// `bcrypt.c`: version `2b`, the cost as two digits, 16 bytes of salt and
/// 23 bytes of hash, both in bcrypt's own Base64 without padding.
pub(super) fn bcrypt(draw: &mut Draw<'_>) -> Result<Bait, BaitError> {
    let salt: [u8; 16] = draw.bytes()?;
    let hash: [u8; 23] = draw.bytes()?;

    let mut text = String::with_capacity(BCRYPT_LEN);
    text.push_str("$2b$12$");
    append_base64(&salt, BCRYPT, Padding::None, &mut text)?;
    append_base64(&hash, BCRYPT, Padding::None, &mut text)?;
    finish(text, BCRYPT_LEN)
}

/// An Argon2id hash:
/// `$argon2id$v=19$m=65536,t=3,p=4$`, then a salt of 22 characters, `$` and
/// a hash of 43.
///
/// The format is the one of the reference implementation (`encoding.c`):
/// decimal numbers, and the salt and the hash in standard Base64 without
/// padding. The parameters are the second recommended option of RFC 9106,
/// section 4: 64 MiB of memory, three passes, four lanes, a salt of 16
/// bytes and a hash of 32.
pub(super) fn argon2id(draw: &mut Draw<'_>) -> Result<Bait, BaitError> {
    let salt: [u8; 16] = draw.bytes()?;
    let hash: [u8; 32] = draw.bytes()?;

    let mut text = String::with_capacity(ARGON2ID_LEN);
    text.push_str("$argon2id$v=19$m=65536,t=3,p=4$");
    append_base64(&salt, STANDARD, Padding::None, &mut text)?;
    text.push('$');
    append_base64(&hash, STANDARD, Padding::None, &mut text)?;
    finish(text, ARGON2ID_LEN)
}

/// A SCRAM-SHA-256 verifier as PostgreSQL stores one:
/// `SCRAM-SHA-256$4096:`, then the salt, `$`, the stored key, `:` and the
/// server key.
///
/// The format is the one of the `rolpassword` column of `pg_authid`, which
/// is that of RFC 5803: the three parts in standard Base64 with padding.
/// The salt has 16 bytes and the count of iterations is 4096, as when
/// PostgreSQL makes a verifier with its default settings. Both keys have
/// the 32 bytes of a SHA-256 digest, which PostgreSQL insists on.
pub(super) fn scram_sha_256(draw: &mut Draw<'_>) -> Result<Bait, BaitError> {
    let salt: [u8; 16] = draw.bytes()?;
    let stored_key: [u8; 32] = draw.bytes()?;
    let server_key: [u8; 32] = draw.bytes()?;

    let mut text = String::with_capacity(SCRAM_SHA_256_LEN);
    text.push_str("SCRAM-SHA-256$4096:");
    append_base64(&salt, STANDARD, Padding::Equals, &mut text)?;
    text.push('$');
    append_base64(&stored_key, STANDARD, Padding::Equals, &mut text)?;
    text.push(':');
    append_base64(&server_key, STANDARD, Padding::Equals, &mut text)?;
    finish(text, SCRAM_SHA_256_LEN)
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
    fn a_bcrypt_hash_has_the_parts_of_the_reference_implementation() {
        for seed in 0..200 {
            let text = with_sequence(seed, bcrypt);
            assert_eq!(text.len(), 60);
            let (head, rest) = text.split_at(7);
            assert_eq!(head, "$2b$12$");
            let (salt, hash) = rest.split_at(22);
            // 16 bytes and 23 bytes, in the one spelling a strict decoder
            // accepts.
            assert_eq!(
                decode(salt, BCRYPT, false).map(|bytes| bytes.len()),
                Some(16)
            );
            assert_eq!(
                decode(hash, BCRYPT, false).map(|bytes| bytes.len()),
                Some(23)
            );
            // The last character of each part carries only two and four
            // bits: OpenBSD writes `(c1 & 0x03) << 4` and `(c2 & 0x0f) << 2`.
            assert!(salt.ends_with(['.', 'O', 'e', 'u']), "{salt}");
        }
    }

    #[test]
    fn a_bcrypt_hash_from_known_bytes_is_what_the_format_says() {
        // 16 bytes of 0xff are 21 times '9' and then 'u'. 23 bytes of 0xff
        // are 30 times '9' and then '6'.
        let mut source = Constant(0xff);
        let mut draw = Draw::new(&mut source);
        let expected = format!("$2b$12${}u{}6", "9".repeat(21), "9".repeat(30));
        assert_eq!(bcrypt(&mut draw).unwrap().expose(), expected);
    }

    #[test]
    fn an_argon2id_hash_has_the_parts_of_the_reference_implementation() {
        for seed in 0..200 {
            let text = with_sequence(seed, argon2id);
            assert_eq!(text.len(), 97);
            let parts: Vec<&str> = text.split('$').collect();
            let [empty, kind, version, parameters, salt, hash] = parts.as_slice() else {
                panic!("expected six parts in {text}");
            };
            assert_eq!(*empty, "");
            assert_eq!(*kind, "argon2id");
            assert_eq!(*version, "v=19");
            assert_eq!(*parameters, "m=65536,t=3,p=4");
            assert_eq!(
                decode(salt, STANDARD, false).map(|bytes| bytes.len()),
                Some(16)
            );
            assert_eq!(
                decode(hash, STANDARD, false).map(|bytes| bytes.len()),
                Some(32)
            );
            // No padding: the two Base64 parts have no `=`.
            assert!(!salt.contains('=') && !hash.contains('='), "{text}");
        }
    }

    #[test]
    fn the_argon2id_parameters_are_ones_the_algorithm_accepts() {
        // Read back from a value, so that the test follows the text and not
        // a constant of its own.
        let text = with_sequence(0, argon2id);
        let parts: Vec<&str> = text.split('$').collect();
        let version: u64 = parts[2].strip_prefix("v=").unwrap().parse().unwrap();
        let numbers: Vec<u64> = parts[3]
            .split(',')
            .zip(["m=", "t=", "p="])
            .map(|(field, name)| field.strip_prefix(name).unwrap().parse().unwrap())
            .collect();
        let [memory, passes, lanes] = numbers[..] else {
            panic!("expected three parameters in {text}");
        };

        // RFC 9106, section 3.1: the version is 0x13, p is from 1 to
        // 2^24-1, m is from 8*p to 2^32-1 kibibytes, and t is at least 1.
        assert_eq!(version, 0x13);
        assert!((1..(1 << 24)).contains(&lanes));
        assert!(memory >= 8 * lanes && memory <= u64::from(u32::MAX));
        assert!(passes >= 1);
        // Section 4, the second recommended option.
        assert_eq!((passes, lanes, memory), (3, 4, 1 << 16));
    }

    #[test]
    fn a_scram_verifier_has_the_parts_postgresql_parses() {
        for seed in 0..200 {
            let text = with_sequence(seed, scram_sha_256);
            assert_eq!(text.len(), 133);
            // PostgreSQL splits at `$`, `:`, `$` and `:`, in that order.
            let (scheme, rest) = text.split_once('$').unwrap();
            let (iterations, rest) = rest.split_once(':').unwrap();
            let (salt, rest) = rest.split_once('$').unwrap();
            let (stored_key, server_key) = rest.split_once(':').unwrap();
            assert_eq!(scheme, "SCRAM-SHA-256");
            assert_eq!(iterations, "4096");
            assert_eq!(
                decode(salt, STANDARD, true).map(|bytes| bytes.len()),
                Some(16)
            );
            // Both keys must decode to the 32 bytes of a SHA-256 digest.
            assert_eq!(
                decode(stored_key, STANDARD, true).map(|bytes| bytes.len()),
                Some(32)
            );
            assert_eq!(
                decode(server_key, STANDARD, true).map(|bytes| bytes.len()),
                Some(32)
            );
            assert_ne!(stored_key, server_key);
        }
    }

    #[test]
    fn the_random_parts_differ_from_value_to_value() {
        for generator in [bcrypt, argon2id, scram_sha_256] {
            let values: std::collections::HashSet<String> = (0..2000)
                .map(|seed| with_sequence(seed, generator))
                .collect();
            assert_eq!(values.len(), 2000);
        }
    }

    #[test]
    fn a_text_of_the_wrong_length_is_a_defect() {
        assert_eq!(finish("x".repeat(59), BCRYPT_LEN), Err(BaitError::Defect));
        assert_eq!(finish("x".repeat(61), BCRYPT_LEN), Err(BaitError::Defect));
        assert!(finish("x".repeat(60), BCRYPT_LEN).is_ok());
    }
}
