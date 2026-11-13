// SPDX-License-Identifier: Apache-2.0

//! `pgsnare token generate`: print the SQL that plants new honeytokens and
//! the configuration that matches them. It connects to nothing.
//!
//! # What is printed
//!
//! The output is one SQL script, in plain ASCII:
//!
//! 1. an `INSERT` with a row for every honeytoken, and
//! 2. a token file with an entry for every honeytoken, inside an SQL
//!    comment.
//!
//! The command writes that to standard output and does nothing else. It
//! opens no connection and no file. The operator reviews the statement,
//! runs it, and gives the token file to pgsnare.
//!
//! # Randomness
//!
//! Every value comes from the bait generators of `pgsnare-core`, which take
//! all their randomness from a source they are handed. The command always
//! hands them [`OsEntropy`], the secure random generator of the operating
//! system. No option, no environment variable and no setting of the build
//! changes that. [`generate`] takes the source as an argument so that a
//! test can hand in a fixed one. Nothing on the command line leads there.
//!
//! # Quoting
//!
//! A table or column name is whatever the operator passes, so everything
//! that is printed is quoted for the place it is printed in:
//!
//! - An identifier is written between double quotes, with a double quote
//!   in it doubled. A name with characters outside ASCII is written in the
//!   `U&"..."` form, with each such character as its code point, so the
//!   script has no byte above 127 and reads the same in every client
//!   encoding.
//! - A value is written between single quotes, with a single quote in it
//!   doubled. A value with a backslash is written in the `E'...'` form
//!   with the backslash doubled, which is right whatever
//!   `standard_conforming_strings` is set to. This is the rule of
//!   `PQescapeLiteral` in libpq.
//! - Text in the token file is a double-quoted YAML scalar. Besides what
//!   YAML asks for, every `*` is written as an escape, so nothing in the
//!   file can end the SQL comment around it.
//! - A name with a NUL or another control character is refused: the first
//!   cannot be written in SQL at all, and the others have no place in the
//!   name of a table.
//!
//! The whole output can therefore be given to `psql` as it is. The
//! statement runs, and the rest is a comment.

use std::fmt;
use std::io::Write;

use clap::ValueEnum;
use pgsnare_core::bait::{self, Bait, BaitError, Domain, Entropy, EntropyError};
use pgsnare_core::detect::{BuildError, Matcher, TokenSpec};
use pgsnare_core::policy::TokenId;

use super::{FAILURE, SUCCESS};

/// The most honeytokens one run generates.
pub const MAX_COUNT: u32 = 1000;

/// The longest name of a table or a column, in bytes. The configuration
/// accepts no longer text in the scope of a token.
pub const MAX_NAME_BYTES: usize = 256;

/// How often a set of values is generated again when two of them clash.
/// With the randomness the values carry, once is already unheard of.
const ATTEMPTS: u32 = 4;

/// The kinds of honeytoken the command generates.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, ValueEnum)]
pub enum Kind {
    /// A made-up service account: a name and an email address. Needs
    /// --domain.
    Identity,
    /// A stored password in the format of bcrypt. It is the hash of
    /// nothing.
    Bcrypt,
    /// A stored password in the format of Argon2id. It is the hash of
    /// nothing.
    Argon2id,
    /// A SCRAM-SHA-256 verifier as PostgreSQL stores one. It belongs to no
    /// password.
    #[value(name = "scram-sha-256")]
    ScramSha256,
    /// An API key: 40 random characters, the key of no service.
    ApiKey,
    /// A number with the length and the check digit of a payment card
    /// number, from outside the ranges of the payment schemes.
    Card,
    /// A marker to put into free text, such as a note.
    Marker,
}

impl Kind {
    /// The name of the kind on the command line.
    #[must_use]
    pub const fn name(self) -> &'static str {
        match self {
            Self::Identity => "identity",
            Self::Bcrypt => "bcrypt",
            Self::Argon2id => "argon2id",
            Self::ScramSha256 => "scram-sha-256",
            Self::ApiKey => "api-key",
            Self::Card => "card",
            Self::Marker => "marker",
        }
    }

    /// The columns of the statement when the operator names none.
    #[must_use]
    pub const fn default_columns(self) -> &'static [&'static str] {
        match self {
            Self::Identity => &["name", "email"],
            Self::Bcrypt | Self::Argon2id | Self::ScramSha256 => &["password_hash"],
            Self::ApiKey => &["api_key"],
            Self::Card => &["card_number"],
            Self::Marker => &["note"],
        }
    }

    /// What the operator should know about the values, as lines of an SQL
    /// comment.
    const fn note(self) -> &'static [&'static str] {
        match self {
            Self::Identity => &[
                "Each row is a made-up service account. Its email address is its",
                "name at the domain you gave.",
            ],
            Self::Bcrypt => &[
                "Each value has the format of a bcrypt hash and is the hash of",
                "nothing: no password belongs to it.",
            ],
            Self::Argon2id => &[
                "Each value has the format of an Argon2id hash and is the hash of",
                "nothing: no password belongs to it.",
            ],
            Self::ScramSha256 => &[
                "Each value has the format of a SCRAM-SHA-256 verifier of PostgreSQL",
                "and belongs to no password.",
            ],
            Self::ApiKey => &["Each value is 40 random characters and the key of no service."],
            Self::Card => &[
                "Each number passes the Luhn check and begins with 99, which is",
                "outside the ranges of the payment schemes. It is not the number of",
                "a card, and a reader who looks at the first digit can tell. Keep it",
                "in a text column: a number column is sent in another form in binary",
                "results, and the value is missed there.",
            ],
            Self::Marker => &[
                "Each value is a marker for free text. It is found anywhere in a",
                "message, so it can stand inside a sentence of your own.",
            ],
        }
    }
}

/// The arguments of `pgsnare token generate`.
#[derive(Debug, clap::Args)]
#[command(
    long_about = "Generate honeytokens: the SQL to plant them and the matching configuration.\n\n\
        The output is an SQL script: an INSERT with one row for each honeytoken, and a token \
        file for pgsnare inside an SQL comment. Nothing else happens. pgsnare connects to no \
        database and writes no file. Review the statement, adapt it to your table and run it \
        yourself.\n\n\
        Every value is new and random, from the secure random generator of the operating \
        system. Running the command again gives other values.",
    after_help = "Examples:\n  \
        pgsnare token generate --kind identity --table public.users --domain mail.example\n  \
        pgsnare token generate --kind api-key --table public.api_keys --column key --count 3\n  \
        pgsnare token generate --kind bcrypt --table '\"Shop\".\"Customer Logins\"' --id shop-logins"
)]
pub struct Args {
    /// The kind of honeytoken to generate.
    #[arg(long, value_enum, value_name = "KIND")]
    pub kind: Kind,

    /// The table the honeytokens are planted in, with its schema if you
    /// like: public.users. A name is taken exactly as written and is
    /// case-sensitive. Put double quotes around a part that contains a
    /// dot: '"my.schema".users'.
    #[arg(long, value_name = "TABLE")]
    pub table: String,

    /// The column a value goes into. The kind identity takes two, the name
    /// first and the email address second. Without it the columns are
    /// name and email for identity, password_hash for the three hash
    /// kinds, api_key, card_number and note.
    #[arg(long = "column", value_name = "COLUMN")]
    pub columns: Vec<String>,

    /// The domain of the email addresses, such as mail.example. The kind
    /// identity needs it, and no domain is built in. Use a domain of your
    /// own that receives no mail.
    #[arg(long, value_name = "DOMAIN")]
    pub domain: Option<String>,

    /// How many honeytokens to generate, 1000 at most.
    #[arg(long, value_name = "N", default_value_t = 1, value_parser = clap::value_parser!(u32).range(1..=i64::from(MAX_COUNT)))]
    pub count: u32,

    /// The id of the honeytoken in the configuration, which is what events
    /// show. With more than one honeytoken, each id is this and a number.
    /// Without it, the id is the kind and a few random characters.
    #[arg(long, value_name = "ID")]
    pub id: Option<String>,
}

/// Why the command printed nothing.
#[derive(Clone, Debug, PartialEq, Eq)]
#[non_exhaustive]
pub enum Error {
    /// `--table` or `--column` cannot be used as a name.
    Name {
        /// The option the name was given with.
        option: &'static str,
        /// What is wrong with it.
        problem: NameProblem,
    },
    /// `--column` was given a number of times that the kind cannot use.
    Columns {
        /// The kind.
        kind: Kind,
        /// How many columns the kind fills.
        expected: usize,
    },
    /// The kind needs `--domain` and none was given.
    DomainMissing,
    /// `--domain` was given for a kind that makes no email address.
    DomainUnused,
    /// `--domain` is not a domain.
    Domain(bait::InvalidDomain),
    /// `--id` is not an identifier, or is too long for the numbers that
    /// are added to it.
    Id,
    /// `--count` is outside 1 to [`MAX_COUNT`].
    Count,
    /// A value could not be generated.
    Bait(BaitError),
    /// The generated values would not be accepted together as honeytokens,
    /// several times in a row.
    Clash,
    /// The command broke its own rules. This points at a defect.
    Defect,
}

impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Name { option, problem } => write!(f, "{option}: {problem}"),
            Self::Columns { kind, expected: 1 } => write!(
                f,
                "--column: the kind {} fills one column, so give --column once or not at all",
                kind.name()
            ),
            Self::Columns { kind, expected } => write!(
                f,
                "--column: the kind {} fills {expected} columns, so give --column {expected} \
                 times or not at all",
                kind.name()
            ),
            Self::DomainMissing => f.write_str(
                "--domain: the kind identity needs the domain of its email addresses, such as \
                 --domain mail.example; no domain is built in",
            ),
            Self::DomainUnused => {
                f.write_str("--domain: only the kind identity makes email addresses")
            }
            Self::Domain(error) => write!(f, "--domain: {error}"),
            Self::Id => f.write_str(
                "--id: an id is 1 to 64 ASCII letters, digits, '.', '_' and '-', starting with \
                 a letter or a digit; with more than one honeytoken it must leave room for a \
                 hyphen and a number",
            ),
            Self::Count => write!(f, "--count: must be between 1 and {MAX_COUNT}"),
            Self::Bait(error) => write!(f, "no value could be generated: {error}"),
            Self::Clash => f.write_str(
                "the generated values clashed with each other several times in a row, which \
                 does not happen with a sound source of randomness; nothing was printed",
            ),
            Self::Defect => f.write_str("the command broke its own rules; nothing was printed"),
        }
    }
}

impl std::error::Error for Error {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::Domain(error) => Some(error),
            Self::Bait(error) => Some(error),
            _ => None,
        }
    }
}

impl From<BaitError> for Error {
    fn from(error: BaitError) -> Self {
        Self::Bait(error)
    }
}

/// What is wrong with the name of a table or a column.
///
/// The message says what a name looks like and does not repeat the name.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[non_exhaustive]
pub enum NameProblem {
    /// The name, or a part of it, is empty.
    Empty,
    /// The name is longer than [`MAX_NAME_BYTES`].
    TooLong,
    /// The name contains a NUL or another control character.
    ControlCharacter,
    /// A double quote stands inside a part that did not begin with one.
    StrayQuote,
    /// A part begins with a double quote and never ends.
    UnterminatedQuote,
    /// Something other than a dot follows the closing quote of a part.
    TextAfterQuote,
    /// The name has more parts than a name of its sort can have.
    TooManyParts,
}

impl fmt::Display for NameProblem {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            Self::Empty => "the name, or a part of it between two dots, is empty",
            Self::TooLong => "the name is longer than 256 bytes",
            Self::ControlCharacter => {
                "the name contains a control character, which cannot be written in a statement"
            }
            Self::StrayQuote => {
                "a double quote may only begin and end a part of the name; inside a quoted \
                 part, write it twice"
            }
            Self::UnterminatedQuote => {
                "a part of the name begins with a double quote and has no end"
            }
            Self::TextAfterQuote => {
                "after the closing double quote of a part, only a dot may follow"
            }
            Self::TooManyParts => {
                "the name has too many parts: a table is named as table, schema.table or \
                 database.schema.table, and a column has one part; put double quotes around \
                 a part that contains a dot"
            }
        })
    }
}

/// Takes a name apart as PostgreSQL does: parts separated by dots, where a
/// part between double quotes may contain dots, and a double quote inside
/// such a part is written twice.
///
/// A part outside quotes is taken exactly as written. Unlike PostgreSQL,
/// its letters are not folded to lower case: every part is quoted in the
/// output, so the name printed is the name given.
fn parse_name(text: &str, max_parts: usize) -> Result<Vec<String>, NameProblem> {
    /// Where the scan is within a part.
    enum At {
        /// Before the first character of a part.
        Start,
        /// Inside a part without quotes.
        Plain,
        /// Inside a part between quotes.
        Quoted,
        /// After the closing quote of a part.
        Closed,
    }

    if text.is_empty() {
        return Err(NameProblem::Empty);
    }
    if text.len() > MAX_NAME_BYTES {
        return Err(NameProblem::TooLong);
    }
    if text.chars().any(char::is_control) {
        return Err(NameProblem::ControlCharacter);
    }

    let mut parts = Vec::new();
    let mut part = String::new();
    let mut at = At::Start;
    let mut characters = text.chars().peekable();
    while let Some(character) = characters.next() {
        match (&at, character) {
            (At::Start, '"') => at = At::Quoted,
            (At::Start | At::Plain, '.') => {
                if part.is_empty() {
                    return Err(NameProblem::Empty);
                }
                parts.push(std::mem::take(&mut part));
                at = At::Start;
            }
            (At::Plain, '"') => return Err(NameProblem::StrayQuote),
            (At::Start | At::Plain, other) => {
                part.push(other);
                at = At::Plain;
            }
            (At::Quoted, '"') => {
                if characters.peek() == Some(&'"') {
                    characters.next();
                    part.push('"');
                } else {
                    at = At::Closed;
                }
            }
            (At::Quoted, other) => part.push(other),
            (At::Closed, '.') => {
                if part.is_empty() {
                    return Err(NameProblem::Empty);
                }
                parts.push(std::mem::take(&mut part));
                at = At::Start;
            }
            (At::Closed, _) => return Err(NameProblem::TextAfterQuote),
        }
    }
    match at {
        At::Quoted => return Err(NameProblem::UnterminatedQuote),
        // The name ends with a dot, or a quoted part is empty.
        At::Start | At::Closed | At::Plain if part.is_empty() => return Err(NameProblem::Empty),
        At::Start | At::Closed | At::Plain => parts.push(part),
    }
    if parts.len() > max_parts {
        return Err(NameProblem::TooManyParts);
    }
    Ok(parts)
}

/// Whether a character is written as it is: printable ASCII.
const fn is_printable_ascii(character: char) -> bool {
    matches!(character, ' '..='~')
}

/// Appends an identifier in the form PostgreSQL reads back as exactly
/// `name`, in ASCII.
fn push_identifier(out: &mut String, name: &str) {
    if name.chars().all(is_printable_ascii) {
        out.push('"');
        for character in name.chars() {
            if character == '"' {
                out.push('"');
            }
            out.push(character);
        }
        out.push('"');
        return;
    }
    // The form with Unicode escapes. Its escape character is the
    // backslash, which is therefore written twice.
    out.push_str("U&\"");
    for character in name.chars() {
        match character {
            '"' => out.push_str("\"\""),
            '\\' => out.push_str("\\\\"),
            plain if is_printable_ascii(plain) => out.push(plain),
            other => {
                let code = u32::from(other);
                if code <= 0xffff {
                    out.push_str(&format!("\\{code:04X}"));
                } else {
                    out.push_str(&format!("\\+{code:06X}"));
                }
            }
        }
    }
    out.push('"');
}

/// Appends a string constant that PostgreSQL reads back as exactly `text`.
///
/// # Errors
///
/// Refuses text with anything but printable ASCII. A generated value has
/// none of that, so this points at a defect.
fn push_literal(out: &mut String, text: &str) -> Result<(), Error> {
    if !text.chars().all(is_printable_ascii) {
        return Err(Error::Defect);
    }
    // With a backslash, the escape form is the only one that means the
    // same under both settings of `standard_conforming_strings`.
    let escape = text.contains('\\');
    if escape {
        out.push('E');
    }
    out.push('\'');
    for character in text.chars() {
        match character {
            '\'' => out.push_str("''"),
            '\\' if escape => out.push_str("\\\\"),
            other => out.push(other),
        }
    }
    out.push('\'');
    Ok(())
}

/// Appends a double-quoted YAML scalar that reads back as exactly `text`,
/// in ASCII and without a `*`.
fn push_yaml_text(out: &mut String, text: &str) {
    out.push('"');
    for character in text.chars() {
        match character {
            '"' => out.push_str("\\\""),
            '\\' => out.push_str("\\\\"),
            // Never written as it is: the file stands inside an SQL comment,
            // which only `*` and `/` together can open or close.
            '*' => out.push_str("\\x2A"),
            plain if is_printable_ascii(plain) => out.push(plain),
            other => {
                let code = u32::from(other);
                if code <= 0xff {
                    out.push_str(&format!("\\x{code:02X}"));
                } else if code <= 0xffff {
                    out.push_str(&format!("\\u{code:04X}"));
                } else {
                    out.push_str(&format!("\\U{code:08X}"));
                }
            }
        }
    }
    out.push('"');
}

/// The secure random generator of the operating system.
///
/// This is the source of randomness of every value the command prints. It
/// asks the operating system for every byte, through the `getrandom`
/// crate, and keeps no generator of its own. When the operating system
/// cannot give random bytes, [`Entropy::fill`] returns the error, and
/// nothing weaker is used in their place.
///
/// # Waiting
///
/// On Linux the operating system makes a caller wait only while its
/// generator has not been seeded, early in the start of the machine.
/// [`OsEntropy::new`] reads once, so that wait, if there is one, happens
/// when the source is made. After that a read does not wait: the source
/// asks for 256 bytes at a time at most, which the system call always
/// returns at once and in full.
#[derive(Clone, Copy, Debug)]
pub struct OsEntropy(());

impl OsEntropy {
    /// The most bytes asked of the operating system in one call.
    const CHUNK: usize = 256;

    /// Makes the source, and reads from it once to see that it works.
    ///
    /// # Errors
    ///
    /// Returns the error of the operating system if it cannot give random
    /// bytes.
    pub fn new() -> Result<Self, EntropyError> {
        let mut source = Self(());
        source.fill(&mut [0u8; 1])?;
        Ok(source)
    }
}

impl Entropy for OsEntropy {
    fn fill(&mut self, dest: &mut [u8]) -> Result<(), EntropyError> {
        for chunk in dest.chunks_mut(Self::CHUNK) {
            getrandom::fill(chunk).map_err(|error| match error.raw_os_error() {
                Some(number) => EntropyError::from_os_error(number),
                None => EntropyError::new(),
            })?;
        }
        Ok(())
    }
}

/// One generated honeytoken.
struct Token {
    id: String,
    /// What goes into the columns of the row, in their order.
    row: Vec<Bait>,
    /// How many of the first entries of `row` are the values of the token
    /// in the configuration.
    listed: usize,
}

impl Token {
    fn values(&self) -> &[Bait] {
        self.row.get(..self.listed).unwrap_or(&self.row)
    }
}

/// The lower-case alphabet of Base32, for the random part of an id.
const ID_ALPHABET: &[u8; 32] = b"abcdefghijklmnopqrstuvwxyz234567";

/// The id of the tokens of this run: the one the operator gave, or the
/// kind and six random characters.
fn base_id(args: &Args, entropy: &mut dyn Entropy) -> Result<String, Error> {
    if let Some(id) = &args.id {
        return Ok(id.clone());
    }
    let mut random = [0u8; 6];
    entropy
        .fill(&mut random)
        .map_err(|error| Error::Bait(BaitError::Entropy(error)))?;
    let mut id = String::from(args.kind.name());
    id.push('-');
    for byte in random {
        let symbol = ID_ALPHABET
            .get(usize::from(byte & 0x1f))
            .ok_or(Error::Defect)?;
        id.push(char::from(*symbol));
    }
    Ok(id)
}

/// The ids of `count` tokens: the base alone for one token, and the base
/// with a number for more.
fn ids(base: &str, count: u32) -> Result<Vec<String>, Error> {
    let ids: Vec<String> = if count == 1 {
        vec![base.to_owned()]
    } else {
        (1..=count)
            .map(|number| format!("{base}-{number}"))
            .collect()
    };
    if ids.iter().all(|id| TokenId::new(id).is_ok()) {
        Ok(ids)
    } else {
        Err(Error::Id)
    }
}

/// Generates the values of every token.
fn tokens(
    kind: Kind,
    domain: Option<&Domain>,
    ids: &[String],
    entropy: &mut dyn Entropy,
) -> Result<Vec<Token>, Error> {
    let mut tokens = Vec::with_capacity(ids.len());
    for id in ids {
        let (row, listed) = match kind {
            Kind::Identity => {
                let domain = domain.ok_or(Error::DomainMissing)?;
                let (name, email) = bait::identity(domain, entropy)?.into_parts();
                // The name alone is the value of the token: the address
                // contains it, and a list with both would be refused.
                (vec![name, email], 1)
            }
            Kind::Bcrypt => (vec![bait::generate(bait::Kind::Bcrypt, entropy)?], 1),
            Kind::Argon2id => (vec![bait::generate(bait::Kind::Argon2id, entropy)?], 1),
            Kind::ScramSha256 => (vec![bait::generate(bait::Kind::ScramSha256, entropy)?], 1),
            Kind::ApiKey => (vec![bait::generate(bait::Kind::ApiKey, entropy)?], 1),
            Kind::Card => (vec![bait::generate(bait::Kind::CardNumber, entropy)?], 1),
            Kind::Marker => (vec![bait::generate(bait::Kind::Marker, entropy)?], 1),
        };
        tokens.push(Token {
            id: id.clone(),
            row,
            listed,
        });
    }
    Ok(tokens)
}

/// Whether the matcher accepts the tokens together: no value twice, and
/// none inside another.
fn accepted_together(tokens: &[Token]) -> Result<bool, Error> {
    let specs: Vec<TokenSpec> = tokens
        .iter()
        .map(|token| TokenSpec::new(token.id.as_str(), token.values()))
        .collect();
    match Matcher::build(&specs) {
        Ok(_) => Ok(true),
        Err(BuildError::Invalid(_)) => Ok(false),
        Err(_) => Err(Error::Defect),
    }
}

/// Writes the script: the statement, and the token file in a comment.
fn render(
    kind: Kind,
    table: &[String],
    table_as_given: &str,
    columns: &[String],
    tokens: &[Token],
) -> Result<String, Error> {
    let mut out = String::new();
    let count = tokens.len();
    let honeytokens = if count == 1 {
        "honeytoken"
    } else {
        "honeytokens"
    };

    out.push_str(&format!(
        "-- pgsnare token generate: {count} {honeytokens} of the kind {}.\n\
         -- This is an SQL script. The configuration for pgsnare is in the comment\n\
         -- at its end.\n\
         --\n\
         -- 1. Plant the rows. Review this statement, adapt it to your table and\n\
         --    run it yourself: pgsnare has connected to nothing. Run it directly\n\
         --    against the database, or before pgsnare is given the values: a\n\
         --    value that a client sends through pgsnare is a hit as well.\n",
        kind.name()
    ));
    for line in kind.note() {
        out.push_str("--    ");
        out.push_str(line);
        out.push('\n');
    }

    out.push_str("INSERT INTO ");
    for (position, part) in table.iter().enumerate() {
        if position > 0 {
            out.push('.');
        }
        push_identifier(&mut out, part);
    }
    out.push_str(" (");
    for (position, column) in columns.iter().enumerate() {
        if position > 0 {
            out.push_str(", ");
        }
        push_identifier(&mut out, column);
    }
    out.push_str(") VALUES");
    for (position, token) in tokens.iter().enumerate() {
        if token.row.len() != columns.len() {
            return Err(Error::Defect);
        }
        out.push_str(if position > 0 { ",\n    (" } else { "\n    (" });
        for (place, value) in token.row.iter().enumerate() {
            if place > 0 {
                out.push_str(", ");
            }
            push_literal(&mut out, value.expose())?;
        }
        out.push(')');
    }
    out.push_str(";\n\n");

    out.push_str(
        "/*\n\
         # 2. Tell pgsnare. What stands between the two comment marks is a token\n\
         #    file: save it as a file that `token_files` names, or add its entries\n\
         #    to the `tokens` of the configuration. Keep it as secret as a password:\n\
         #    whoever knows a value can avoid it.\n",
    );
    if kind == Kind::Identity {
        out.push_str(
            "#    The value of a token is the account name. The email address\n\
             #    contains it and sets off the same token.\n",
        );
    }
    out.push_str("tokens:\n");
    let Some(first_column) = columns.first() else {
        return Err(Error::Defect);
    };
    for token in tokens {
        out.push_str("  - id: ");
        push_yaml_text(&mut out, &token.id);
        out.push_str("\n    values: [");
        for (place, value) in token.values().iter().enumerate() {
            if place > 0 {
                out.push_str(", ");
            }
            push_yaml_text(&mut out, value.expose());
        }
        out.push_str("]\n    scope: { table: ");
        push_yaml_text(&mut out, table_as_given);
        out.push_str(", column: ");
        push_yaml_text(&mut out, first_column);
        out.push_str(" }\n");
    }
    out.push_str("*/\n");

    // The promise of this module, checked on what is about to be printed.
    let plain = out
        .chars()
        .all(|character| character == '\n' || is_printable_ascii(character));
    if plain { Ok(out) } else { Err(Error::Defect) }
}

/// Generates the honeytokens and returns everything the command prints.
///
/// All randomness is taken from `entropy`. The command hands in
/// [`OsEntropy`] and nothing else; a test hands in a fixed source.
///
/// # Errors
///
/// Returns what is wrong with the arguments, or why no value could be
/// generated. Nothing is returned in part.
pub fn generate(args: &Args, entropy: &mut dyn Entropy) -> Result<String, Error> {
    if !(1..=MAX_COUNT).contains(&args.count) {
        return Err(Error::Count);
    }
    let name_error = |option| move |problem| Error::Name { option, problem };
    let table = parse_name(&args.table, 3).map_err(name_error("--table"))?;

    let expected = args.kind.default_columns().len();
    let columns: Vec<String> = if args.columns.is_empty() {
        args.kind
            .default_columns()
            .iter()
            .map(|column| (*column).to_owned())
            .collect()
    } else if args.columns.len() == expected {
        let mut columns = Vec::with_capacity(expected);
        for column in &args.columns {
            let mut parts = parse_name(column, 1).map_err(name_error("--column"))?;
            columns.push(parts.pop().ok_or(Error::Defect)?);
        }
        columns
    } else {
        return Err(Error::Columns {
            kind: args.kind,
            expected,
        });
    };

    let domain = match (args.kind, &args.domain) {
        (Kind::Identity, Some(domain)) => Some(Domain::new(domain).map_err(Error::Domain)?),
        (Kind::Identity, None) => return Err(Error::DomainMissing),
        (_, Some(_)) => return Err(Error::DomainUnused),
        (_, None) => None,
    };
    if let Some(id) = &args.id
        && TokenId::new(id).is_err()
    {
        return Err(Error::Id);
    }

    let ids = ids(&base_id(args, entropy)?, args.count)?;
    for _ in 0..ATTEMPTS {
        let tokens = tokens(args.kind, domain.as_ref(), &ids, entropy)?;
        if accepted_together(&tokens)? {
            return render(args.kind, &table, &args.table, &columns, &tokens);
        }
    }
    Err(Error::Clash)
}

/// Runs the command and returns its exit status.
#[must_use]
pub fn run(args: &Args) -> u8 {
    let failed = |error: &dyn fmt::Display| {
        eprintln!("pgsnare token generate: {error}");
        FAILURE
    };
    let mut entropy = match OsEntropy::new() {
        Ok(entropy) => entropy,
        Err(error) => return failed(&error),
    };
    // Everything is generated and checked before the first byte is
    // written, so the output is whole or absent.
    let script = match generate(args, &mut entropy) {
        Ok(script) => script,
        Err(error) => return failed(&error),
    };
    let mut stdout = std::io::stdout().lock();
    match stdout
        .write_all(script.as_bytes())
        .and_then(|()| stdout.flush())
    {
        Ok(()) => SUCCESS,
        Err(error) => failed(&format_args!(
            "the output could not be written: {}",
            error.kind()
        )),
    }
}

#[cfg(test)]
mod tests;
