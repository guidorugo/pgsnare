// SPDX-License-Identifier: Apache-2.0

//! Property tests for the bait generators, through their public interface.
//!
//! The randomness of a generator is whatever its caller hands in. Here that
//! is arbitrary bytes, including too few of them, so the properties hold
//! for every source and not only for a good one:
//!
//! - a generator returns a value of its format, or an error, and never
//!   panics;
//! - a value is accepted as a honeytoken by the matcher;
//! - a value depends on the bytes that were handed in and on nothing else.
//!
//! The formats are checked by code written here, which shares nothing with
//! the generators.

use pgsnare_core::bait::{self, BaitError, Domain, Entropy, EntropyError, Kind};
use pgsnare_core::detect::{MIN_VALUE_LEN, Matcher, TokenSpec};
use proptest::collection::vec;
use proptest::prelude::*;

/// Hands out the given bytes, fails when they run out, and remembers that
/// it failed.
struct Script {
    bytes: Vec<u8>,
    used: usize,
    failed: bool,
}

impl Script {
    fn new(bytes: &[u8]) -> Self {
        Self {
            bytes: bytes.to_vec(),
            used: 0,
            failed: false,
        }
    }
}

impl Entropy for Script {
    fn fill(&mut self, dest: &mut [u8]) -> Result<(), EntropyError> {
        let end = self.used + dest.len();
        let Some(bytes) = self.bytes.get(self.used..end) else {
            self.failed = true;
            // What a failed read leaves in the buffer must not be used.
            dest.fill(b'A');
            return Err(EntropyError::new());
        };
        dest.copy_from_slice(bytes);
        self.used = end;
        Ok(())
    }
}

/// Which kind to generate, without the domain an address needs.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Which {
    AccountName,
    Email,
    Bcrypt,
    Argon2id,
    ScramSha256,
    ApiKey,
    CardNumber,
    Marker,
}

const ALL: [Which; 8] = [
    Which::AccountName,
    Which::Email,
    Which::Bcrypt,
    Which::Argon2id,
    Which::ScramSha256,
    Which::ApiKey,
    Which::CardNumber,
    Which::Marker,
];

impl Which {
    fn kind(self, domain: &Domain) -> Kind<'_> {
        match self {
            Self::AccountName => Kind::AccountName,
            Self::Email => Kind::Email { domain },
            Self::Bcrypt => Kind::Bcrypt,
            Self::Argon2id => Kind::Argon2id,
            Self::ScramSha256 => Kind::ScramSha256,
            Self::ApiKey => Kind::ApiKey,
            Self::CardNumber => Kind::CardNumber,
            Self::Marker => Kind::Marker,
        }
    }
}

const STANDARD: &str = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
const BCRYPT: &str = "./ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789";

fn all_in(text: &str, alphabet: &str) -> bool {
    text.chars().all(|character| alphabet.contains(character))
}

/// Standard Base64 with padding, of a text that encodes `bytes` bytes.
fn is_padded_base64(text: &str, bytes: usize) -> bool {
    let body = text.trim_end_matches('=');
    let padding = text.len() - body.len();
    text.len() == bytes.div_ceil(3) * 4 && padding == (3 - bytes % 3) % 3 && all_in(body, STANDARD)
}

fn is_account_name(text: &str) -> bool {
    let parts: Vec<&str> = text.split('.').collect();
    let [prefix, role, suffix] = parts.as_slice() else {
        return false;
    };
    let word = |part: &str| !part.is_empty() && part.bytes().all(|byte| byte.is_ascii_lowercase());
    word(prefix)
        && word(role)
        && suffix.len() == 12
        && all_in(suffix, "abcdefghijklmnopqrstuvwxyz234567")
}

/// The Luhn check of a whole number, as the formula is usually stated.
fn passes_luhn(number: &str) -> bool {
    let mut sum = 0u32;
    for (position, byte) in number.bytes().rev().enumerate() {
        let digit = u32::from(byte - b'0');
        sum += if position % 2 == 1 {
            let twice = digit * 2;
            twice / 10 + twice % 10
        } else {
            digit
        };
    }
    sum.is_multiple_of(10)
}

/// Whether `text` has the format of its kind.
fn has_the_format(which: Which, text: &str, domain: &Domain) -> bool {
    match which {
        Which::AccountName => is_account_name(text),
        Which::Email => text
            .split_once('@')
            .is_some_and(|(local, host)| is_account_name(local) && host == domain.as_str()),
        Which::Bcrypt => {
            text.len() == 60
                && text
                    .strip_prefix("$2b$12$")
                    .is_some_and(|rest| all_in(rest, BCRYPT))
        }
        Which::Argon2id => text
            .strip_prefix("$argon2id$v=19$m=65536,t=3,p=4$")
            .and_then(|rest| rest.split_once('$'))
            .is_some_and(|(salt, hash)| {
                salt.len() == 22
                    && hash.len() == 43
                    && all_in(salt, STANDARD)
                    && all_in(hash, STANDARD)
            }),
        Which::ScramSha256 => text
            .strip_prefix("SCRAM-SHA-256$4096:")
            .and_then(|rest| rest.split_once('$'))
            .and_then(|(salt, keys)| Some((salt, keys.split_once(':')?)))
            .is_some_and(|(salt, (stored_key, server_key))| {
                is_padded_base64(salt, 16)
                    && is_padded_base64(stored_key, 32)
                    && is_padded_base64(server_key, 32)
            }),
        Which::ApiKey => {
            text.len() == 40
                && text
                    .bytes()
                    .all(|byte| byte.is_ascii_alphanumeric() || byte == b'-' || byte == b'_')
        }
        Which::CardNumber => {
            text.len() == 16
                && text.bytes().all(|byte| byte.is_ascii_digit())
                && text.starts_with("99")
                && passes_luhn(text)
        }
        Which::Marker => {
            let groups: Vec<&str> = text.split('-').collect();
            groups.len() == 4
                && groups.iter().all(|group| {
                    group.len() == 4 && all_in(group, "ABCDEFGHIJKLMNOPQRSTUVWXYZ234567")
                })
        }
    }
}

fn which() -> impl Strategy<Value = Which> {
    proptest::sample::select(ALL.as_slice())
}

/// A valid domain: one to four labels of letters, digits and hyphens.
fn domain() -> impl Strategy<Value = Domain> {
    vec("[a-zA-Z]([a-zA-Z0-9-]{0,12}[a-zA-Z0-9])?", 1..=4)
        .prop_map(|labels| Domain::new(&labels.join(".")).expect("the labels form a host name"))
}

proptest! {
    #![proptest_config(ProptestConfig::with_cases(2000))]

    /// Whatever bytes the source hands out, and however few: a value of
    /// the right format, or an error.
    #[test]
    fn a_generator_returns_a_value_of_its_format_or_an_error(
        which in which(),
        domain in domain(),
        bytes in vec(any::<u8>(), 0..400),
    ) {
        let mut source = Script::new(&bytes);
        let outcome = bait::generate(which.kind(&domain), &mut source);
        // An error for the source exactly when the source failed: a value
        // is never finished with something else after a failed read.
        prop_assert_eq!(matches!(outcome, Err(BaitError::Entropy(_))), source.failed);
        match outcome {
            Ok(value) => {
                let text = value.expose();
                prop_assert!(has_the_format(which, text, &domain), "{:?}", which);
                prop_assert!(text.is_ascii());
                prop_assert!(text.len() >= MIN_VALUE_LEN);
                // The matcher takes it as the value of a honeytoken.
                prop_assert!(Matcher::build(&[TokenSpec::new("bait", [&value])]).is_ok());
                // And its text stays out of debug output.
                prop_assert_eq!(format!("{value:?}"), "Bait(<redacted>)");
            }
            Err(BaitError::Entropy(_)) => {}
            Err(BaitError::UnusableEntropy) => {
                // Only a kind that turns bytes into decimal digits throws
                // bytes away, and only bytes of 250 and above.
                prop_assert_eq!(which, Which::CardNumber);
                prop_assert!(bytes.iter().filter(|byte| **byte >= 250).count() >= 128);
            }
            Err(other) => prop_assert!(false, "{:?}: {:?}", which, other),
        }
    }

    /// With enough bytes of any content that a sound source could give,
    /// there is always a value.
    #[test]
    fn enough_bytes_always_give_a_value(
        which in which(),
        domain in domain(),
        bytes in vec(0u8..250, 256),
    ) {
        let value = bait::generate(which.kind(&domain), &mut Script::new(&bytes));
        prop_assert!(value.is_ok(), "{:?}: {:?}", which, value);
    }

    /// The same bytes give the same value, and nothing else goes into it.
    #[test]
    fn a_value_is_made_of_the_bytes_handed_in_and_of_nothing_else(
        which in which(),
        domain in domain(),
        bytes in vec(any::<u8>(), 256),
    ) {
        let first = bait::generate(which.kind(&domain), &mut Script::new(&bytes));
        let again = bait::generate(which.kind(&domain), &mut Script::new(&bytes));
        prop_assert_eq!(first, again);
    }

    /// The address of an identity is its name at the domain that was given.
    #[test]
    fn an_identity_is_one_account(
        domain in domain(),
        bytes in vec(any::<u8>(), 64),
    ) {
        let identity = bait::identity(&domain, &mut Script::new(&bytes)).unwrap();
        prop_assert!(is_account_name(identity.name().expose()));
        prop_assert_eq!(
            identity.email().expose(),
            format!("{}@{}", identity.name().expose(), domain.as_str())
        );
        // The name alone is the token: the address sets it off as well.
        let matcher = Matcher::build(&[TokenSpec::new("account", [identity.name()])]).unwrap();
        prop_assert_eq!(matcher.scan(identity.email().expose().as_bytes()).count(), 1);
    }

    /// Any text is a domain or is refused, and a domain that is accepted
    /// is a lower-case host name.
    #[test]
    fn a_domain_is_checked_before_it_is_used(
        text in prop_oneof!["\\PC{0,40}", "[a-zA-Z0-9.-]{0,40}", "[a-z]{1,8}(\\.[a-z0-9-]{1,8}){0,3}"],
    ) {
        match Domain::new(&text) {
            Ok(domain) => {
                let name = domain.as_str();
                prop_assert!(name.len() <= Domain::MAX_LEN);
                prop_assert!(!name.is_empty());
                let plain = name.bytes().all(|byte| {
                    byte.is_ascii_lowercase() || byte.is_ascii_digit() || byte == b'-' || byte == b'.'
                });
                prop_assert!(plain);
                prop_assert_eq!(name, text.to_ascii_lowercase());
            }
            Err(error) => {
                // The error describes the rule and does not repeat the text.
                prop_assert!(error.to_string().starts_with("a mail domain is a host name"));
            }
        }
    }
}

#[test]
fn the_format_checks_of_this_file_can_fail() {
    // A check that accepts everything shows nothing, so each is given a
    // value of its kind with one thing wrong.
    let domain = Domain::new("mail.example").unwrap();
    let wrong = [
        (Which::AccountName, "svc.backup.k7q2m5xd3pz"),
        (Which::AccountName, "svc.backup.k7q2m5xd3pz1"),
        (Which::AccountName, "svc.k7q2m5xd3pza"),
        (Which::Email, "svc.backup.k7q2m5xd3pza@other.example"),
        (Which::Email, "svc.backup.k7q2m5xd3pza"),
        (
            Which::Bcrypt,
            "$2b$12$abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ+",
        ),
        (
            Which::Bcrypt,
            "$2b$12$abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ",
        ),
        (
            Which::Bcrypt,
            "$2x$12$abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0",
        ),
        (Which::CardNumber, "9900000000000000000"),
        (Which::CardNumber, "9900000000000001"),
        (Which::CardNumber, "4900000000000003"),
        (Which::Marker, "ABCD-EFGH-IJKL-MNO1"),
        (Which::Marker, "ABCD-EFGH-IJKL"),
        (Which::ApiKey, "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLM+"),
    ];
    for (which, text) in wrong {
        assert!(!has_the_format(which, text, &domain), "{which:?}: {text}");
    }
    let right = [
        (Which::AccountName, "svc.backup.k7q2m5xd3pza"),
        (Which::Email, "svc.backup.k7q2m5xd3pza@mail.example"),
        (
            Which::Bcrypt,
            "$2b$12$abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0",
        ),
        (Which::CardNumber, "9900000000000002"),
        (Which::Marker, "ABCD-EFGH-IJKL-MNOP"),
        (Which::ApiKey, "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLM-"),
    ];
    for (which, text) in right {
        assert!(has_the_format(which, text, &domain), "{which:?}: {text}");
    }
    assert!(is_padded_base64("Zm9vYg==", 4));
    assert!(!is_padded_base64("Zm9vYg", 4));
    assert!(!is_padded_base64("Zm9vYg==", 5));
}
