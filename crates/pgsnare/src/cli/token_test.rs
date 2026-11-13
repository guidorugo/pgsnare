// SPDX-License-Identifier: Apache-2.0

//! `pgsnare token test`: check whether a value matches a honeytoken of a
//! configuration.
//!
//! # Where the value comes from
//!
//! The value is read from standard input and is not an argument, so that it
//! does not end up in the shell history or the process list, where other
//! users of the machine can read it.
//!
//! Standard input must be a file or a pipe. A terminal is refused: a value
//! typed there is shown on the screen and stays in the scrollback.
//!
//! # What is printed
//!
//! The id of every honeytoken the value matches, or that none matches. The
//! value itself is never printed, in no message and whatever goes wrong,
//! and neither is a value of the configuration.
//!
//! # What "matches" means
//!
//! The input is scanned as traffic is: a honeytoken is found anywhere in
//! it, as it is, in hexadecimal, and in another letter case if the token
//! ignores case. The input may therefore be a whole row as well as a single
//! value.

use std::ffi::OsString;
use std::io::{IsTerminal, Read, Write};
use std::path::PathBuf;

use pgsnare_core::detect::{BuildError, PatternForm, ScanError};

use crate::config::Config;

use super::config_check::{disable_core_dumps, load_for};
use super::{FAILURE, SUCCESS, USAGE};

/// The most bytes that are read from standard input: 1 MiB.
pub const MAX_INPUT_BYTES: u64 = 1024 * 1024;

/// The arguments of `pgsnare token test`.
#[derive(Debug, clap::Args)]
#[command(
    after_long_help = "The value is read from standard input. It is not an argument, because an\n\
        argument ends up in the history of the shell and in the process list, where\n\
        other users of the machine can read it. For the same reason, do not put the\n\
        value into the command line of echo or printf from an interactive shell.\n\n\
        Standard input must be a file or a pipe. A terminal is refused: what is typed\n\
        there is shown on the screen. One line break at the end is not counted as part\n\
        of the value.\n\n\
        The input is scanned as traffic is: a honeytoken is found anywhere in it, as\n\
        it is, in hexadecimal, and in another letter case if the token ignores case.\n\n\
        The exit status is 0 if a honeytoken matches and 1 for anything else. When no\n\
        test could be made, nothing is written to standard output.\n\n\
        Examples:\n  \
        pgsnare token test --config /etc/pgsnare/pgsnare.yaml < value.txt\n  \
        read -rs VALUE && printf '%s' \"$VALUE\" | pgsnare token test -c /etc/pgsnare/pgsnare.yaml"
)]
pub struct Args {
    /// The configuration file. Its token files are read as well.
    #[arg(short, long, value_name = "FILE")]
    pub config: PathBuf,

    /// Not a way to give the value. Whatever else stands on the command
    /// line is collected here, so that the command can refuse it with a
    /// message that does not repeat it. Left to the parser, a value given
    /// as an argument would be printed back in the complaint about it.
    #[arg(hide = true, allow_hyphen_values = true)]
    pub not_taken: Vec<OsString>,
}

/// One way in which the input matches a honeytoken.
#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub struct Found {
    /// The position of the token in the configuration, counted from zero.
    pub token_index: usize,
    /// The id of the token.
    pub token: String,
    /// Which of the values of the token matches, counted from zero.
    pub value_index: usize,
    /// The form in which the value is in the input.
    pub form: PatternForm,
}

/// Why the input could not be tested.
#[derive(Clone, Debug, PartialEq, Eq)]
#[non_exhaustive]
pub enum Error {
    /// The honeytokens of the configuration could not be compiled.
    Matcher(BuildError),
    /// The search could not be carried out.
    Scan(ScanError),
}

impl std::fmt::Display for Error {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Matcher(error) => write!(f, "{error}"),
            Self::Scan(error) => write!(f, "{error}"),
        }
    }
}

impl std::error::Error for Error {}

/// Looks for the honeytokens of a configuration in `input`, the way
/// traffic is scanned.
///
/// Every way in which a token matches is returned once, in the order of
/// the configuration. The result holds ids and positions and never a
/// value.
///
/// # Errors
///
/// Returns an error if the tokens cannot be compiled or the search fails.
/// A configuration that was loaded gives neither.
pub fn find(config: &Config, input: &[u8]) -> Result<Vec<Found>, Error> {
    let matcher = config.matcher().map_err(Error::Matcher)?;
    let mut found = Vec::new();
    for hit in matcher.scan(input) {
        let hit = hit.map_err(Error::Scan)?;
        found.push(Found {
            token_index: hit.token_index(),
            token: hit.token_id().as_str().to_owned(),
            value_index: hit.value_index(),
            form: hit.form(),
        });
    }
    found.sort();
    found.dedup();
    Ok(found)
}

/// The value in what was read: everything but one line break at its end.
#[must_use]
pub fn value_of(input: &[u8]) -> &[u8] {
    let input = input.strip_suffix(b"\n").unwrap_or(input);
    input.strip_suffix(b"\r").unwrap_or(input)
}

/// What the command prints for a result.
#[must_use]
pub fn report(found: &[Found]) -> String {
    if found.is_empty() {
        return "no honeytoken matches\n".to_owned();
    }
    let mut out = String::new();
    for one in found {
        out.push_str(&format!(
            "matches honeytoken {}: values[{}], {}\n",
            one.token,
            one.value_index,
            match one.form {
                PatternForm::Raw => "as it is",
                PatternForm::Hex => "in hexadecimal",
                PatternForm::CaseInsensitive => "in another letter case",
                _ => "in another form",
            }
        ));
    }
    out
}

/// Runs the command and returns its exit status: 0 if a honeytoken
/// matches, and 1 for anything else.
#[must_use]
pub fn run(args: &Args) -> u8 {
    let failed = |message: &dyn std::fmt::Display| {
        eprintln!("pgsnare token test: {message}");
        FAILURE
    };
    if !args.not_taken.is_empty() {
        // The argument may be the value itself, so it is not repeated.
        eprintln!(
            "pgsnare token test: the command takes no argument but --config. The value is \
             read from standard input, so that it does not end up in the shell history and \
             the process list."
        );
        return USAGE;
    }
    // Before the first secret is read: the token files hold some, and so
    // does standard input.
    disable_core_dumps();

    let stdin = std::io::stdin();
    if stdin.is_terminal() {
        return failed(
            &"standard input is a terminal, and a value typed there is shown on the screen. \
              Give the value through a file or a pipe, for example: \
              pgsnare token test --config FILE < value.txt",
        );
    }
    let loaded = match load_for("token test", &args.config) {
        Ok(loaded) => loaded,
        Err(status) => return status,
    };

    // One byte more than the limit is enough to know the input is too long.
    let mut input = Vec::new();
    if let Err(error) = stdin
        .lock()
        .take(MAX_INPUT_BYTES.saturating_add(1))
        .read_to_end(&mut input)
    {
        return failed(&format_args!(
            "standard input could not be read: {}",
            error.kind()
        ));
    }
    if u64::try_from(input.len()).unwrap_or(u64::MAX) > MAX_INPUT_BYTES {
        return failed(&"the input is longer than 1MiB");
    }
    let value = value_of(&input);
    if value.is_empty() {
        return failed(&"no value was given on standard input");
    }

    let found = match find(&loaded.config, value) {
        Ok(found) => found,
        Err(error) => return failed(&error),
    };
    let mut stdout = std::io::stdout().lock();
    if let Err(error) = stdout
        .write_all(report(&found).as_bytes())
        .and_then(|()| stdout.flush())
    {
        return failed(&format_args!(
            "the output could not be written: {}",
            error.kind()
        ));
    }
    if found.is_empty() { FAILURE } else { SUCCESS }
}

#[cfg(test)]
mod tests {
    use super::*;

    const CONFIG: &str = "\
listeners:
  - name: main
    listen: 0.0.0.0:5432
    upstream: db.example.com:5432
    client_tls: { mode: disable }
    upstream_tls: { mode: verify-full }
events:
  sinks:
    - type: stdout
tokens:
  - id: users-admin-backup
    values: [\"svc.backup.aaaaaaaaaaaa\"]
  - id: billing-canary
    values: [\"Canary.Invoice.000417\", \"ABCD-EFGH-IJKL-MNOP\"]
    case_insensitive: true
";

    fn found(input: &[u8]) -> Vec<(String, usize, PatternForm)> {
        find(&Config::from_yaml(CONFIG).unwrap(), input)
            .unwrap()
            .into_iter()
            .map(|one| (one.token, one.value_index, one.form))
            .collect()
    }

    fn hit(token: &str, value_index: usize, form: PatternForm) -> (String, usize, PatternForm) {
        (token.to_owned(), value_index, form)
    }

    #[test]
    fn a_value_of_a_token_matches_that_token() {
        assert_eq!(
            found(b"svc.backup.aaaaaaaaaaaa"),
            [hit("users-admin-backup", 0, PatternForm::Raw)]
        );
        assert_eq!(
            found(b"ABCD-EFGH-IJKL-MNOP"),
            [hit("billing-canary", 1, PatternForm::Raw)]
        );
    }

    #[test]
    fn a_value_of_no_token_matches_nothing() {
        assert!(found(b"svc.backup.aaaaaaaaaaab").is_empty());
        assert!(found(b"svc.backup.aaaaaaaaaaa").is_empty());
        assert!(found(b"short").is_empty());
        assert!(found(b"").is_empty());
        // The first token does not ignore case.
        assert!(found(b"SVC.BACKUP.AAAAAAAAAAAA").is_empty());
    }

    #[test]
    fn a_value_is_found_the_way_traffic_is_scanned() {
        // Inside a larger text, such as a row.
        assert_eq!(
            found(b"1042,svc.backup.aaaaaaaaaaaa@mail.example,2026-01-31"),
            [hit("users-admin-backup", 0, PatternForm::Raw)]
        );
        // In hexadecimal, as a bytea column is printed.
        let hex: String = b"svc.backup.aaaaaaaaaaaa"
            .iter()
            .map(|byte| format!("{byte:02x}"))
            .collect();
        assert_eq!(
            found(hex.as_bytes()),
            [hit("users-admin-backup", 0, PatternForm::Hex)]
        );
        // In another letter case, for the token that ignores it.
        assert_eq!(
            found(b"CANARY.INVOICE.000417"),
            [hit("billing-canary", 0, PatternForm::CaseInsensitive)]
        );
        // Bytes that are not text are scanned like any others.
        assert_eq!(
            found(b"\xff\x00svc.backup.aaaaaaaaaaaa\xfe"),
            [hit("users-admin-backup", 0, PatternForm::Raw)]
        );
    }

    #[test]
    fn every_token_in_the_input_is_named_once_and_in_the_order_of_the_configuration() {
        assert_eq!(
            found(b"abcd-efgh-ijkl-mnop svc.backup.aaaaaaaaaaaa svc.backup.aaaaaaaaaaaa ABCD-EFGH-IJKL-MNOP"),
            [
                hit("users-admin-backup", 0, PatternForm::Raw),
                hit("billing-canary", 1, PatternForm::Raw),
                hit("billing-canary", 1, PatternForm::CaseInsensitive),
            ]
        );
    }

    #[test]
    fn one_line_break_at_the_end_is_not_part_of_the_value() {
        assert_eq!(value_of(b"value\n"), b"value");
        assert_eq!(value_of(b"value\r\n"), b"value");
        assert_eq!(value_of(b"value"), b"value");
        assert_eq!(value_of(b"value\n\n"), b"value\n");
        assert_eq!(value_of(b"va\nlue\n"), b"va\nlue");
        assert_eq!(value_of(b" value \n"), b" value ");
        assert_eq!(value_of(b"\n"), b"");
        assert_eq!(value_of(b""), b"");
    }

    #[test]
    fn the_report_names_tokens_and_never_a_value() {
        assert_eq!(report(&[]), "no honeytoken matches\n");
        let config = Config::from_yaml(CONFIG).unwrap();
        // The first value as it is, the second in another letter case, and
        // the third in hexadecimal.
        let input =
            b"svc.backup.aaaaaaaaaaaa canary.invoice.000417 414243442d454647482d494a4b4c2d4d4e4f50";
        let text = report(&find(&config, input).unwrap());
        assert_eq!(
            text,
            "matches honeytoken users-admin-backup: values[0], as it is\n\
             matches honeytoken billing-canary: values[0], in another letter case\n\
             matches honeytoken billing-canary: values[1], in hexadecimal\n"
        );
        for secret in [
            "svc.backup",
            "aaaaaa",
            "nvoice",
            "000417",
            "ABCD",
            "MNOP",
            "4142",
        ] {
            assert!(!text.contains(secret), "{text}");
        }
    }

    #[test]
    fn the_errors_have_fixed_messages() {
        assert_eq!(
            Error::Matcher(BuildError::TooLarge).to_string(),
            "the honeytoken values are too many or too long to compile"
        );
    }
}
