// SPDX-License-Identifier: Apache-2.0

//! Bait in the shape of a user: an account name and an email address.
//!
//! The account is a made-up service account, such as
//! `svc.backup.k7q2m5xd3pza`: a prefix and a role from two short lists of
//! ordinary words, and twelve random characters. An account that looks
//! privileged and that nothing ever uses is the classic honeytoken. The
//! lists hold no name of a person, and no mail domain is built in: the
//! domain of an address comes from the caller.

use core::fmt;
use core::str::FromStr;

use super::entropy::Draw;
use super::error::BaitError;
use super::value::Bait;

/// What an account name begins with.
const PREFIXES: [&str; 8] = ["svc", "app", "sys", "adm", "ops", "srv", "bot", "job"];

/// What the account is for, by its name.
const ROLES: [&str; 32] = [
    "backup",
    "billing",
    "deploy",
    "reports",
    "audit",
    "export",
    "archive",
    "sync",
    "payroll",
    "finance",
    "support",
    "migrate",
    "monitor",
    "etl",
    "legacy",
    "import",
    "ledger",
    "invoice",
    "replica",
    "restore",
    "cron",
    "batch",
    "notify",
    "search",
    "metrics",
    "admin",
    "dba",
    "integration",
    "analytics",
    "crm",
    "erp",
    "warehouse",
];

/// The lower-case alphabet of Base32: the letters, and the digits 2 to 7.
const BASE32_LOWER: &[u8; 32] = b"abcdefghijklmnopqrstuvwxyz234567";

/// The number of random characters at the end of an account name. Each
/// carries five random bits.
const SUFFIX_LEN: usize = 12;

/// The longest account name: the longest prefix and role, the suffix and
/// two dots. A test holds it to the lists.
const ACCOUNT_NAME_MAX_LEN: usize = 28;

// The part of an address before the `@` is at most 64 bytes: RFC 5321,
// section 4.5.3.1.1.
const _: () = assert!(ACCOUNT_NAME_MAX_LEN <= 64);

/// The longest email address a mail system carries, in bytes: the path of
/// RFC 5321, section 4.5.3.1.3, is 256 bytes with its two angle brackets.
const EMAIL_MAX_LEN: usize = 254;

/// The domain of the email addresses to generate, such as `mail.example`.
///
/// The caller supplies it: no domain is built in, because an address at a
/// domain that belongs to somebody else is that somebody's address.
///
/// A domain is a host name: labels of ASCII letters, digits and `-`,
/// separated by dots. A label has 1 to 63 characters and neither begins
/// nor ends with `-`, and the last label is not a number. The whole name
/// has at most [`Domain::MAX_LEN`] bytes. Upper-case letters are folded to
/// lower case, which names the same domain.
///
/// ```
/// use pgsnare_core::bait::Domain;
///
/// let domain: Domain = "Mail.Example".parse()?;
/// assert_eq!(domain.as_str(), "mail.example");
/// assert!("mail..example".parse::<Domain>().is_err());
/// assert!("192.0.2.1".parse::<Domain>().is_err());
/// # Ok::<(), pgsnare_core::bait::InvalidDomain>(())
/// ```
#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub struct Domain(String);

/// The text is not a domain an email address can be generated at.
///
/// The error says what a domain looks like and does not repeat the text.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct InvalidDomain;

impl fmt::Display for InvalidDomain {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(
            "a mail domain is a host name such as mail.example: labels of ASCII letters, \
             digits and '-', separated by dots, at most 63 characters each and 225 bytes in \
             all, and the last label is not a number",
        )
    }
}

impl core::error::Error for InvalidDomain {}

impl Domain {
    /// The longest domain, in bytes. With a longer one, an address would
    /// pass the 254 bytes a mail system carries.
    pub const MAX_LEN: usize = 225;

    /// Checks the text and wraps it, in lower case.
    ///
    /// # Errors
    ///
    /// Returns [`InvalidDomain`] unless the text is a host name as
    /// described for [`Domain`].
    pub fn new(text: &str) -> Result<Self, InvalidDomain> {
        let label_is_valid = |label: &str| {
            (1..=63).contains(&label.len())
                && !label.starts_with('-')
                && !label.ends_with('-')
                && label
                    .bytes()
                    .all(|byte| byte.is_ascii_alphanumeric() || byte == b'-')
        };
        let last_is_a_number = text
            .rsplit('.')
            .next()
            .is_some_and(|label| label.bytes().all(|byte| byte.is_ascii_digit()));
        let valid = !text.is_empty()
            && text.len() <= Self::MAX_LEN
            && text.split('.').all(label_is_valid)
            && !last_is_a_number;
        if valid {
            Ok(Self(text.to_ascii_lowercase()))
        } else {
            Err(InvalidDomain)
        }
    }

    /// The domain as text, in lower case.
    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl FromStr for Domain {
    type Err = InvalidDomain;

    fn from_str(text: &str) -> Result<Self, InvalidDomain> {
        Self::new(text)
    }
}

impl fmt::Display for Domain {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.0)
    }
}

/// A made-up account: its name, and its email address.
///
/// The address is the name, `@` and the domain, so the two belong to one
/// account when they are read side by side.
///
/// # Configuring it as a honeytoken
///
/// List the **name** as the value of the token, and not the address. Data
/// that holds the address holds the name too, so one value answers for
/// both columns. Listing both is refused: a token list in which one value
/// contains another is not valid, see the rules of
/// [`Matcher::build`](crate::detect::Matcher::build).
#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub struct Identity {
    name: Bait,
    email: Bait,
}

impl Identity {
    /// The account name, such as `svc.backup.k7q2m5xd3pza`.
    #[must_use]
    pub const fn name(&self) -> &Bait {
        &self.name
    }

    /// The email address: the name, `@` and the domain.
    #[must_use]
    pub const fn email(&self) -> &Bait {
        &self.email
    }

    /// The name and the address, in that order.
    #[must_use]
    pub fn into_parts(self) -> (Bait, Bait) {
        (self.name, self.email)
    }
}

/// The text of a new account name.
fn account_name_text(draw: &mut Draw<'_>) -> Result<String, BaitError> {
    let mut text = String::with_capacity(ACCOUNT_NAME_MAX_LEN);
    text.push_str(draw.pick(&PREFIXES)?);
    text.push('.');
    text.push_str(draw.pick(&ROLES)?);
    text.push('.');
    draw.append_base32(BASE32_LOWER, SUFFIX_LEN, &mut text)?;
    if text.len() > ACCOUNT_NAME_MAX_LEN {
        return Err(BaitError::Defect);
    }
    Ok(text)
}

/// The address of an account at a domain.
fn address(name: &str, domain: &Domain) -> Result<Bait, BaitError> {
    let mut text = String::with_capacity(
        name.len()
            .saturating_add(1)
            .saturating_add(domain.as_str().len()),
    );
    text.push_str(name);
    text.push('@');
    text.push_str(domain.as_str());
    if text.len() > EMAIL_MAX_LEN {
        return Err(BaitError::Defect);
    }
    Bait::new(text)
}

/// An account name: a prefix, a role and twelve random characters.
pub(super) fn account_name(draw: &mut Draw<'_>) -> Result<Bait, BaitError> {
    Bait::new(account_name_text(draw)?)
}

/// An email address of a new account at `domain`.
pub(super) fn email(domain: &Domain, draw: &mut Draw<'_>) -> Result<Bait, BaitError> {
    address(&account_name_text(draw)?, domain)
}

/// A new account at `domain`: its name and its address.
pub(super) fn identity(domain: &Domain, draw: &mut Draw<'_>) -> Result<Identity, BaitError> {
    let name = account_name_text(draw)?;
    let email = address(&name, domain)?;
    Ok(Identity {
        name: Bait::new(name)?,
        email,
    })
}

#[cfg(test)]
mod tests {
    use std::collections::{BTreeSet, HashSet};

    use super::super::entropy::testing::{Constant, Sequence};
    use super::*;

    fn domain(text: &str) -> Domain {
        Domain::new(text).unwrap()
    }

    #[test]
    fn a_domain_is_a_host_name() {
        for text in [
            "example",
            "mail.example",
            "corp.example.com",
            "a.b",
            "xn--bcher-kva.example",
            "mail-1.example",
            "1mail.example",
            "example.test",
        ] {
            assert_eq!(domain(text).as_str(), text);
        }
        for text in [
            "",
            ".",
            ".example",
            "example.",
            "mail..example",
            "-mail.example",
            "mail-.example",
            "mail_1.example",
            "mail example",
            "mail@example",
            "m\u{e4}il.example",
            "192.0.2.1",
            "mail.123",
            "[2001:db8::1]",
            "mail.example\n",
            "mail.example\0",
            "mail.example/path",
            "mail.example:25",
            "\"mail\".example",
        ] {
            assert_eq!(Domain::new(text), Err(InvalidDomain), "{text:?}");
            assert_eq!(text.parse::<Domain>(), Err(InvalidDomain), "{text:?}");
        }
    }

    #[test]
    fn a_domain_is_kept_in_lower_case() {
        assert_eq!(domain("Mail.EXAMPLE").as_str(), "mail.example");
        assert_eq!(domain("Mail.EXAMPLE"), domain("mail.example"));
        assert_eq!(domain("Mail.EXAMPLE").to_string(), "mail.example");
    }

    #[test]
    fn a_label_and_a_domain_have_a_longest_length() {
        let label = "a".repeat(63);
        assert!(Domain::new(&format!("{label}.example")).is_ok());
        assert!(Domain::new(&format!("{label}a.example")).is_err());

        // Labels of 63 with dots between them, up to the limit exactly.
        let mut longest = [label.as_str(); 3].join(".");
        longest.push('.');
        longest.push_str(&"b".repeat(Domain::MAX_LEN - longest.len()));
        assert_eq!(longest.len(), Domain::MAX_LEN);
        assert!(Domain::new(&longest).is_ok());
        let longer = format!("{longest}b");
        assert!(Domain::new(&longer).is_err());
    }

    #[test]
    fn the_error_does_not_repeat_the_text() {
        let error = Domain::new("not a domain!").unwrap_err().to_string();
        assert!(!error.contains("not a domain"), "{error}");
        assert!(error.starts_with("a mail domain is a host name"), "{error}");
        // The limit in the message is the limit.
        assert!(
            error.contains(&format!("{} bytes", Domain::MAX_LEN)),
            "{error}"
        );
    }

    #[test]
    fn the_word_lists_are_plain_lower_case_words() {
        for word in PREFIXES.iter().chain(ROLES.iter()) {
            assert!(!word.is_empty());
            assert!(word.bytes().all(|byte| byte.is_ascii_lowercase()), "{word}");
        }
        assert_eq!(
            PREFIXES.iter().collect::<BTreeSet<_>>().len(),
            PREFIXES.len()
        );
        assert_eq!(ROLES.iter().collect::<BTreeSet<_>>().len(), ROLES.len());
    }

    #[test]
    fn the_longest_name_and_the_longest_domain_give_an_address_that_fits() {
        let longest_word = |list: &[&str]| list.iter().map(|word| word.len()).max().unwrap();
        assert_eq!(
            longest_word(&PREFIXES) + 1 + longest_word(&ROLES) + 1 + SUFFIX_LEN,
            ACCOUNT_NAME_MAX_LEN
        );
        assert_eq!(ACCOUNT_NAME_MAX_LEN + 1 + Domain::MAX_LEN, EMAIL_MAX_LEN);

        let longest = domain(
            &[
                "d".repeat(63),
                "d".repeat(63),
                "d".repeat(63),
                "d".repeat(33),
            ]
            .join("."),
        );
        assert_eq!(longest.as_str().len(), Domain::MAX_LEN);
        let name = "n".repeat(ACCOUNT_NAME_MAX_LEN);
        assert_eq!(
            address(&name, &longest).unwrap().expose().len(),
            EMAIL_MAX_LEN
        );
        // One byte more cannot come from a generator. If it did, it would
        // be refused.
        assert_eq!(
            address(&format!("{name}n"), &longest),
            Err(BaitError::Defect)
        );
    }

    #[test]
    fn an_account_name_is_a_prefix_a_role_and_twelve_random_characters() {
        let mut prefixes = BTreeSet::new();
        let mut roles = BTreeSet::new();
        for seed in 0..2000 {
            let mut source = Sequence::new(seed);
            let name = account_name(&mut Draw::new(&mut source)).unwrap();
            let name = name.expose();
            let parts: Vec<&str> = name.split('.').collect();
            let [prefix, role, suffix] = parts.as_slice() else {
                panic!("expected three parts in {name}");
            };
            assert!(PREFIXES.contains(prefix), "{name}");
            assert!(ROLES.contains(role), "{name}");
            assert_eq!(suffix.len(), 12, "{name}");
            assert!(
                suffix.bytes().all(|byte| BASE32_LOWER.contains(&byte)),
                "{name}"
            );
            assert!((20..=ACCOUNT_NAME_MAX_LEN).contains(&name.len()), "{name}");
            prefixes.insert((*prefix).to_owned());
            roles.insert((*role).to_owned());
        }
        // Every word is used.
        assert_eq!(prefixes.len(), PREFIXES.len());
        assert_eq!(roles.len(), ROLES.len());
    }

    #[test]
    fn an_account_name_from_known_bytes_is_what_the_format_says() {
        // Every byte is 0: the first prefix, the first role, and twelve
        // times the first character.
        let mut source = Constant(0);
        assert_eq!(
            account_name(&mut Draw::new(&mut source)).unwrap().expose(),
            "svc.backup.aaaaaaaaaaaa"
        );
        // Every byte is 0xff: the last of each. 255 is 7 below 8, 31 below
        // 32, and its low five bits are 31.
        let mut source = Constant(0xff);
        assert_eq!(
            account_name(&mut Draw::new(&mut source)).unwrap().expose(),
            "job.warehouse.777777777777"
        );
    }

    #[test]
    fn an_email_address_is_an_account_at_the_domain_that_was_given() {
        let domain = domain("mail.example");
        for seed in 0..500 {
            let mut source = Sequence::new(seed);
            let email = email(&domain, &mut Draw::new(&mut source)).unwrap();
            let (local, host) = email.expose().split_once('@').unwrap();
            assert_eq!(host, "mail.example");
            assert!(!local.contains('@'));

            // The part before the `@` is what the name generator gives for
            // the same randomness.
            let mut source = Sequence::new(seed);
            let name = account_name(&mut Draw::new(&mut source)).unwrap();
            assert_eq!(local, name.expose());
        }
    }

    #[test]
    fn no_domain_is_built_in() {
        // Whatever domain is given is the only one that ever appears.
        for text in ["corp.example", "example.org", "a.test"] {
            let domain = domain(text);
            let mut source = Sequence::new(1);
            let identity = identity(&domain, &mut Draw::new(&mut source)).unwrap();
            assert!(identity.email().expose().ends_with(&format!("@{text}")));
            assert!(!identity.name().expose().contains('@'));
        }
    }

    #[test]
    fn the_address_of_an_identity_is_its_name_at_the_domain() {
        let domain = domain("corp.example");
        let mut source = Sequence::new(42);
        let identity = identity(&domain, &mut Draw::new(&mut source)).unwrap();
        assert_eq!(
            identity.email().expose(),
            format!("{}@corp.example", identity.name().expose())
        );
        // Nothing of either shows in debug output.
        assert_eq!(
            format!("{identity:?}"),
            "Identity { name: Bait(<redacted>), email: Bait(<redacted>) }"
        );
        let (name, email) = identity.clone().into_parts();
        assert_eq!(&name, identity.name());
        assert_eq!(&email, identity.email());
    }

    #[test]
    fn the_names_differ_from_one_to_the_next() {
        let domain = domain("mail.example");
        let mut names = HashSet::new();
        let mut emails = HashSet::new();
        for seed in 0..5000 {
            let mut source = Sequence::new(seed);
            let identity = identity(&domain, &mut Draw::new(&mut source)).unwrap();
            names.insert(identity.name().expose().to_owned());
            emails.insert(identity.email().expose().to_owned());
        }
        assert_eq!(names.len(), 5000);
        assert_eq!(emails.len(), 5000);
    }
}
