// SPDX-License-Identifier: Apache-2.0

//! Generators for believable bait values.
//!
//! A bait value is something made up that looks like what an intruder is
//! after: an account, a stored password, an API key, a card number, a
//! reference in a note. Planted in a database and configured as a
//! honeytoken, it gives the intruder away. Added to a result by the
//! `fake_data` response, it pollutes what was stolen.
//!
//! # The interface
//!
//! A generator takes a [`Kind`] and a source of randomness, and returns one
//! [`Bait`]:
//!
//! ```
//! use pgsnare_core::bait::{self, Entropy, EntropyError, Kind};
//!
//! // A test hands in a fixed sequence. The runtime hands in the secure
//! // random generator of the operating system.
//! struct Counting(u8);
//!
//! impl Entropy for Counting {
//!     fn fill(&mut self, dest: &mut [u8]) -> Result<(), EntropyError> {
//!         for byte in dest {
//!             *byte = self.0;
//!             self.0 = self.0.wrapping_add(1);
//!         }
//!         Ok(())
//!     }
//! }
//!
//! let marker = bait::generate(Kind::Marker, &mut Counting(0))?;
//! assert_eq!(marker.expose(), "ABCD-EFGH-IJKL-MNOP");
//! // A value does not show in debug output.
//! assert_eq!(format!("{marker:?}"), "Bait(<redacted>)");
//! # Ok::<(), bait::BaitError>(())
//! ```
//!
//! - [`generate`] makes one value of a kind.
//! - [`identity`] makes an account name and its email address, which
//!   belong together.
//!
//! A generator reads nothing and writes nothing, knows no clock and keeps
//! no state between calls. It does not wait for anything and it does not
//! panic. All of its randomness comes from the [`Entropy`] it is given:
//! when that fails, the generator returns the error and no value, and it
//! never makes up for missing randomness with something weaker.
//!
//! # What every value is
//!
//! Every value is ASCII, is at least 12 bytes long and is accepted as the
//! value of a honeytoken by [`Matcher::build`]. It is made of characters
//! that no text format escapes, so it is found wherever it is printed. See
//! [`Bait`].
//!
//! Every value is unique in the sense that matters for a honeytoken: it
//! carries so much randomness that neither real data nor another generated
//! value will repeat it by chance.
//!
//! | Kind | Value | Random bits |
//! |---|---|---|
//! | [`Kind::AccountName`] | `svc.backup.` and twelve characters: a prefix and a role from short lists of words, and a random end | 60, and the choice of words |
//! | [`Kind::Email`] | An account name, `@`, and the domain the caller gives | As the account name |
//! | [`Kind::Bcrypt`] | `$2b$12$` and 53 characters | 312 |
//! | [`Kind::Argon2id`] | `$argon2id$v=19$m=65536,t=3,p=4$`, 22 characters, `$` and 43 characters | 384 |
//! | [`Kind::ScramSha256`] | `SCRAM-SHA-256$4096:`, the salt, `$`, the stored key, `:` and the server key | 640 |
//! | [`Kind::ApiKey`] | 40 letters, digits, `-` and `_` | 240 |
//! | [`Kind::CardNumber`] | 16 digits that begin with `99` and end with a Luhn check digit | 43: thirteen decimal digits |
//! | [`Kind::Marker`] | Four groups of four upper-case letters and digits, such as `ABCD-EFGH-IJKL-MNOP` | 80 |
//!
//! A card number has the least randomness, because its format leaves room
//! for no more. Two of them are the same once in ten million million
//! pairs, so whoever makes many at a time compares them.
//!
//! # What the values are not
//!
//! - **A hash is not the hash of anything.** The three hash kinds have the
//!   exact format of their kind, and random bytes where a real hash holds
//!   what was computed. No password belongs to them.
//! - **A card number is not from a range reserved for testing.** No such
//!   range is known. The numbers are kept out of the ranges of the payment
//!   schemes instead: see [`Kind::CardNumber`] for the reasoning and for
//!   how far it could be verified.
//! - **No name of a person and no real domain is built in.** An account
//!   name is made of ordinary words, and an email address uses the domain
//!   the caller supplies.
//! - **An API key carries no prefix of a real service.**
//!
//! # Where the formats come from
//!
//! | Format | Source |
//! |---|---|
//! | bcrypt | The reference implementation: `bcrypt.c` of OpenBSD |
//! | Argon2id | The reference implementation: `encoding.c` of the Argon2 project. The parameters are the second recommended option of RFC 9106, section 4 |
//! | SCRAM-SHA-256 | The `rolpassword` column of `pg_authid` in the PostgreSQL documentation, which follows RFC 5803, and `parse_scram_secret` of the PostgreSQL source |
//! | Card number | ISO/IEC 7812-1 for the first digit and the Luhn formula |
//! | Base64 | RFC 4648 |
//!
//! [`Matcher::build`]: crate::detect::Matcher::build

mod card;
mod encode;
mod entropy;
mod error;
mod hash;
mod identity;
mod text;
mod value;

pub use entropy::{Entropy, EntropyError};
pub use error::BaitError;
pub use identity::{Domain, Identity, InvalidDomain};
pub use value::Bait;

use entropy::Draw;

/// What kind of bait to generate.
///
/// The table in the [documentation of this module](self) shows what each
/// kind gives.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
#[non_exhaustive]
pub enum Kind<'a> {
    /// The name of a made-up service account.
    AccountName,
    /// The email address of a made-up service account.
    Email {
        /// The domain of the address. The caller supplies it: no domain is
        /// built in.
        domain: &'a Domain,
    },
    /// A stored password in the format of bcrypt.
    Bcrypt,
    /// A stored password in the format of Argon2id.
    Argon2id,
    /// A stored password in the format PostgreSQL uses for SCRAM-SHA-256.
    ScramSha256,
    /// An API key.
    ApiKey,
    /// A number with the length and the check digit of a payment card
    /// number: the digits `99`, thirteen random digits, and the check digit
    /// of the Luhn formula.
    ///
    /// # Why these numbers
    ///
    /// A bait number must not be the number of somebody's card. **No range
    /// of card numbers is known to be reserved for testing**, so the
    /// numbers are kept out of the ranges of the payment schemes instead.
    ///
    /// - The numbering is ISO/IEC 7812-1. The first digit of a number
    ///   names an industry. The digits `2` to `6` are the ones that include
    ///   banking and finance, and that is where the payment schemes have
    ///   their ranges. The digit `9` is "for assignment by national
    ///   standards bodies".
    /// - The numbers that payment processors publish for testing are
    ///   single numbers inside the ranges of the schemes, each for the test
    ///   environment of one processor. A random number from such a range,
    ///   with a valid check digit, can be the number of a card.
    /// - What follows a `9` is, by accounts of the standard, the
    ///   three-digit numeric country code of the body that assigns the
    ///   rest. The codes from 900 to 999 are left for users to define and
    ///   stand for no country. A number that begins with `99` should
    ///   therefore belong to no numbering system at all.
    ///
    /// This is a choice and not a reservation, and its last step rests on
    /// a clause of the standard that was not read when this was written.
    /// It has a price as well: whoever looks at the first digit can tell
    /// that the number is not a payment card.
    CardNumber,
    /// A marker to put into free text.
    Marker,
}

impl Kind<'_> {
    /// A short, stable name for the kind, such as `api-key`.
    #[must_use]
    pub const fn name(&self) -> &'static str {
        match self {
            Self::AccountName => "account-name",
            Self::Email { .. } => "email",
            Self::Bcrypt => "bcrypt",
            Self::Argon2id => "argon2id",
            Self::ScramSha256 => "scram-sha-256",
            Self::ApiKey => "api-key",
            Self::CardNumber => "card-number",
            Self::Marker => "marker",
        }
    }
}

/// Generates one bait value of a kind.
///
/// All randomness of the value is taken from `entropy`. The function does
/// not wait, does not panic and keeps no state.
///
/// # Errors
///
/// - [`BaitError::Entropy`] if `entropy` fails. No value is returned then,
///   and nothing weaker takes its place.
/// - [`BaitError::UnusableEntropy`] if `entropy` keeps returning bytes that
///   cannot be used, which a sound source does not do.
pub fn generate(kind: Kind<'_>, entropy: &mut dyn Entropy) -> Result<Bait, BaitError> {
    let mut draw = Draw::new(entropy);
    match kind {
        Kind::AccountName => identity::account_name(&mut draw),
        Kind::Email { domain } => identity::email(domain, &mut draw),
        Kind::Bcrypt => hash::bcrypt(&mut draw),
        Kind::Argon2id => hash::argon2id(&mut draw),
        Kind::ScramSha256 => hash::scram_sha_256(&mut draw),
        Kind::ApiKey => text::api_key(&mut draw),
        Kind::CardNumber => card::card_number(&mut draw),
        Kind::Marker => text::marker(&mut draw),
    }
}

/// Generates a made-up account: a name, and an email address at `domain`
/// that begins with that name.
///
/// See [`Identity`] for how to configure the pair as a honeytoken.
///
/// # Errors
///
/// As [`generate`].
pub fn identity(domain: &Domain, entropy: &mut dyn Entropy) -> Result<Identity, BaitError> {
    identity::identity(domain, &mut Draw::new(entropy))
}

#[cfg(test)]
mod tests {
    use std::collections::HashSet;

    use super::entropy::testing::{Constant, Failing, Sequence};
    use super::*;
    use crate::detect::{Matcher, TokenSpec};

    /// Every kind, with `domain` for the one that needs it.
    fn kinds(domain: &Domain) -> [Kind<'_>; 8] {
        [
            Kind::AccountName,
            Kind::Email { domain },
            Kind::Bcrypt,
            Kind::Argon2id,
            Kind::ScramSha256,
            Kind::ApiKey,
            Kind::CardNumber,
            Kind::Marker,
        ]
    }

    fn domain() -> Domain {
        Domain::new("mail.example").unwrap()
    }

    #[test]
    fn the_names_of_the_kinds_are_stable_and_different() {
        let domain = domain();
        let names: Vec<&str> = kinds(&domain).iter().map(Kind::name).collect();
        assert_eq!(
            names,
            [
                "account-name",
                "email",
                "bcrypt",
                "argon2id",
                "scram-sha-256",
                "api-key",
                "card-number",
                "marker"
            ]
        );
    }

    #[test]
    fn every_kind_gives_the_value_of_its_generator() {
        let domain = domain();
        let lengths = [
            None,
            None,
            Some(hash::BCRYPT_LEN),
            Some(hash::ARGON2ID_LEN),
            Some(hash::SCRAM_SHA_256_LEN),
            Some(text::API_KEY_LEN),
            Some(card::CARD_NUMBER_LEN),
            Some(text::MARKER_LEN),
        ];
        let starts = [
            "",
            "",
            "$2b$12$",
            "$argon2id$v=19$m=65536,t=3,p=4$",
            "SCRAM-SHA-256$4096:",
            "",
            "99",
            "",
        ];
        for ((kind, length), start) in kinds(&domain).into_iter().zip(lengths).zip(starts) {
            let value = generate(kind, &mut Sequence::new(1)).unwrap();
            if let Some(length) = length {
                assert_eq!(value.expose().len(), length, "{}", kind.name());
            }
            assert!(value.expose().starts_with(start), "{}", kind.name());
        }
        let email = generate(Kind::Email { domain: &domain }, &mut Sequence::new(1)).unwrap();
        assert!(email.expose().ends_with("@mail.example"));
    }

    #[test]
    fn every_value_is_ascii_and_long_enough_for_a_honeytoken() {
        let domain = domain();
        for kind in kinds(&domain) {
            for seed in 0..300 {
                let value = generate(kind, &mut Sequence::new(seed)).unwrap();
                let text = value.expose();
                assert!(text.is_ascii(), "{}", kind.name());
                assert!(
                    text.len() >= crate::detect::MIN_VALUE_LEN,
                    "{}",
                    kind.name()
                );
                assert!(
                    text.bytes().all(|byte| byte.is_ascii_graphic()),
                    "{}",
                    kind.name()
                );
            }
        }
    }

    #[test]
    fn every_value_is_accepted_as_a_honeytoken_on_its_own() {
        let domain = domain();
        for kind in kinds(&domain) {
            for seed in 0..50 {
                let value = generate(kind, &mut Sequence::new(seed)).unwrap();
                let token = TokenSpec::new(kind.name(), [&value]);
                let matcher = Matcher::build(&[token]).unwrap();
                // And it is found in a message that holds it.
                let message = format!("{{\"column\": \"{}\"}}", value.expose());
                let hits: Vec<_> = matcher
                    .scan(message.as_bytes())
                    .collect::<Result<_, _>>()
                    .unwrap();
                assert_eq!(hits.len(), 1, "{}", kind.name());
            }
        }
    }

    #[test]
    fn values_of_every_kind_are_accepted_together_in_one_token_list() {
        // No value is the same as another, and none contains another, in
        // any of the forms the matcher looks for. Half of the tokens ignore
        // letter case, which makes the rule stricter. An address shares a
        // list with any value but its own account name, which the next
        // test shows.
        let domain = domain();
        let mut tokens = Vec::new();
        let mut seed = 0;
        for kind in kinds(&domain) {
            for number in 0..40 {
                seed += 1;
                let value = generate(kind, &mut Sequence::new(seed)).unwrap();
                tokens.push(
                    TokenSpec::new(format!("{}-{number}", kind.name()), [&value])
                        .case_insensitive(number % 2 == 0),
                );
            }
        }
        let matcher = Matcher::build(&tokens).unwrap();
        assert_eq!(matcher.token_count(), 8 * 40);
    }

    #[test]
    fn the_name_of_an_identity_answers_for_its_address() {
        let domain = domain();
        let identity = identity(&domain, &mut Sequence::new(9)).unwrap();

        // The name alone is a valid token, and it is found in the address.
        let name_only = [TokenSpec::new("account", [identity.name()])];
        let matcher = Matcher::build(&name_only).unwrap();
        for column in [identity.name(), identity.email()] {
            let hits: Vec<_> = matcher
                .scan(column.expose().as_bytes())
                .collect::<Result<_, _>>()
                .unwrap();
            assert_eq!(hits.len(), 1);
        }

        // Both together are refused: the address contains the name.
        let both = [TokenSpec::new(
            "account",
            [identity.name(), identity.email()],
        )];
        assert!(Matcher::build(&both).is_err());
    }

    #[test]
    fn many_values_of_a_kind_are_all_different() {
        let domain = domain();
        for kind in kinds(&domain) {
            let mut source = Sequence::new(0xfeed);
            let values: HashSet<String> = (0..10_000)
                .map(|_| generate(kind, &mut source).unwrap().expose().to_owned())
                .collect();
            assert_eq!(values.len(), 10_000, "{}", kind.name());
        }
    }

    #[test]
    fn the_value_follows_the_randomness_it_is_given() {
        let domain = domain();
        for kind in kinds(&domain) {
            let first = generate(kind, &mut Sequence::new(1)).unwrap();
            let again = generate(kind, &mut Sequence::new(1)).unwrap();
            let other = generate(kind, &mut Sequence::new(2)).unwrap();
            // The same randomness gives the same value: nothing else goes
            // into it, no clock and no counter.
            assert_eq!(first, again, "{}", kind.name());
            assert_ne!(first, other, "{}", kind.name());
        }
    }

    #[test]
    fn a_source_that_fails_gives_an_error_and_no_value() {
        let domain = domain();
        for kind in kinds(&domain) {
            assert_eq!(
                generate(kind, &mut Failing),
                Err(BaitError::Entropy(EntropyError::from_os_error(5))),
                "{}",
                kind.name()
            );
        }
        assert!(matches!(
            identity(&domain, &mut Failing),
            Err(BaitError::Entropy(_))
        ));
    }

    #[test]
    fn a_source_that_fails_part_of_the_way_gives_no_value_either() {
        // A source with some bytes and then none: the value must not be
        // finished with what is at hand.
        struct Short(usize);
        impl Entropy for Short {
            fn fill(&mut self, dest: &mut [u8]) -> Result<(), EntropyError> {
                if self.0 == 0 {
                    return Err(EntropyError::new());
                }
                self.0 -= 1;
                dest.fill(0x21);
                Ok(())
            }
        }
        // A SCRAM verifier needs 80 bytes, which is more than one read.
        assert!(generate(Kind::ScramSha256, &mut Short(2)).is_ok());
        assert_eq!(
            generate(Kind::ScramSha256, &mut Short(1)),
            Err(BaitError::Entropy(EntropyError::new()))
        );
    }

    #[test]
    fn a_source_of_one_repeated_byte_never_makes_a_generator_panic_or_hang() {
        let domain = domain();
        for byte in 0..=u8::MAX {
            for kind in kinds(&domain) {
                match generate(kind, &mut Constant(byte)) {
                    Ok(value) => assert!(value.expose().len() >= 12),
                    // Only the kinds that need a number below a bound that
                    // does not divide 256 can meet a byte they cannot use.
                    Err(BaitError::UnusableEntropy) => {
                        assert!(matches!(kind, Kind::CardNumber), "{}", kind.name());
                        assert!(byte >= 250);
                    }
                    Err(other) => panic!("{}: {other:?}", kind.name()),
                }
            }
        }
    }
}
