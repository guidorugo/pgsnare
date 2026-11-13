// SPDX-License-Identifier: Apache-2.0

//! `pgsnare config check`: check a configuration and report every problem.
//!
//! # The same code as `pgsnare run`
//!
//! The check does what `pgsnare run` does before it opens a listener, with
//! the same code and in the same order:
//!
//! 1. It loads the configuration and its token files with the loader that
//!    `run` uses. The loader refuses unknown fields, honeytokens that are
//!    not valid and token files that are missing.
//! 2. It checks the access rights of the files that hold secrets: the rule
//!    is the one of `run`, in [`permissions`], and the files are the ones
//!    `run` checks, from [`Loaded::secret_files`].
//! 3. It builds the policy.
//! 4. It reads the certificates and the keys of every listener, with the
//!    functions `run` reads them with.
//!
//! A configuration that passes therefore starts, and one that fails does
//! not, as far as that can be known without connecting to anything. The
//! check opens no listener and no connection, so it cannot know whether an
//! address is free or a database answers.
//!
//! One difference is deliberate. `run` stops at the first step that fails,
//! and the check goes on where it can, so that one run reports everything.
//!
//! # Warnings
//!
//! Settings that are valid and give up some protection are reported as
//! warnings: see [`Config::warnings`](crate::config::Config::warnings).
//! Warnings alone leave the exit status at 0.
//!
//! # What is printed
//!
//! A line for every error and every warning, and a last line that says
//! whether pgsnare would start. A message is made of fixed text, file
//! names and places in the schema. It holds no text from the files, so a
//! honeytoken value cannot show up in the output of a check.

use std::fmt::Write as _;
use std::io::Write as _;
use std::path::{Path, PathBuf};

use pgsnare_core::extension::ProtocolModule;
use pgsnare_core::session::postgres::Postgres;

use crate::config::{self, LoadError, Loaded};
use crate::runtime::permissions;
use crate::tls::{BackendLeg, ClientLeg, TlsError};

use super::{FAILURE, SUCCESS};

/// The arguments of `pgsnare config check`.
#[derive(Debug, clap::Args)]
#[command(
    after_long_help = "The check loads the configuration and its token files, looks at the access\n\
        rights of the files that hold secrets, and reads the certificates and keys, with\n\
        the code that `pgsnare run` uses. It reports every problem it finds, and warns\n\
        about settings that are valid and give up some protection.\n\n\
        Nothing is connected to and no listener is opened. Whether an address is free\n\
        and whether a database answers is therefore not checked.\n\n\
        The exit status is 0 if pgsnare would start with this configuration, also when\n\
        there are warnings, and 1 if it would not.\n\n\
        Example:\n  pgsnare config check --config /etc/pgsnare/pgsnare.yaml"
)]
pub struct Args {
    /// The configuration file to check.
    #[arg(short, long, value_name = "FILE")]
    pub config: PathBuf,

    /// Report a file that holds secrets and can be read by other users as
    /// a warning and not as an error. `pgsnare run` starts with such files
    /// when it is given the same option.
    #[arg(long)]
    pub allow_insecure_file_permissions: bool,
}

/// What a configuration holds.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Summary {
    /// The number of listeners.
    pub listeners: usize,
    /// The number of honeytokens.
    pub tokens: usize,
    /// The number of values of all honeytokens together.
    pub values: usize,
    /// The number of sinks.
    pub sinks: usize,
}

/// What a check found.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct Report {
    /// Why pgsnare would not start with this configuration.
    pub errors: Vec<String>,
    /// Settings that are valid and give up some protection.
    pub warnings: Vec<String>,
    /// What else the reader should know. A note is neither an error nor a
    /// warning and changes nothing about the outcome.
    pub notes: Vec<String>,
    /// What the configuration holds. `None` if it could not be loaded, and
    /// then nothing after loading was checked.
    pub summary: Option<Summary>,
}

/// `1 word` or `n words`.
fn counted(count: usize, word: &str) -> String {
    if count == 1 {
        format!("1 {word}")
    } else {
        format!("{count} {word}s")
    }
}

impl Report {
    /// Whether pgsnare would start with this configuration.
    #[must_use]
    pub fn passed(&self) -> bool {
        self.errors.is_empty()
    }

    /// The report as the command prints it: a line for every error, every
    /// warning and every note, and a last line with the outcome for `file`.
    #[must_use]
    pub fn render(&self, file: &Path) -> String {
        let mut out = String::new();
        // Writing to a string cannot fail.
        for error in &self.errors {
            let _ = writeln!(out, "error: {error}");
        }
        for warning in &self.warnings {
            let _ = writeln!(out, "warning: {warning}");
        }
        for note in &self.notes {
            let _ = writeln!(out, "note: {note}");
        }
        let warnings = if self.warnings.is_empty() {
            "no warnings".to_owned()
        } else {
            counted(self.warnings.len(), "warning")
        };
        match (&self.summary, self.passed()) {
            (Some(summary), true) => {
                let _ = writeln!(
                    out,
                    "ok: {}: pgsnare would start with {}, {} with {}, {} and {warnings}",
                    file.display(),
                    counted(summary.listeners, "listener"),
                    counted(summary.tokens, "honeytoken"),
                    counted(summary.values, "value"),
                    counted(summary.sinks, "sink"),
                );
            }
            _ => {
                let _ = writeln!(
                    out,
                    "failed: {}: pgsnare would not start: {} and {warnings}",
                    file.display(),
                    counted(self.errors.len(), "error"),
                );
            }
        }
        out
    }
}

/// The note of a check that could not load the configuration.
const NOT_LOADED: &str = "the configuration could not be loaded, so the files it names and its \
                          TLS settings were not checked";

/// The note of a check that found no honeytokens.
const NO_TOKENS: &str = "the configuration has no honeytokens, so pgsnare would detect nothing";

/// The note of a check that found files open to other users.
const OPEN_FILES: &str = "files that hold secrets are open to other users: restrict the access \
                          to them; pgsnare run refuses to start unless it is given \
                          --allow-insecure-file-permissions";

/// Checks a configuration the way `pgsnare run` would use it, and returns
/// everything that was found.
///
/// Nothing is connected to and no listener is opened.
#[must_use]
pub fn check(args: &Args) -> Report {
    let mut report = Report::default();

    // 1. The loader of `run`.
    let loaded = match config::load(&args.config) {
        Ok(loaded) => loaded,
        Err(error) => {
            match error {
                LoadError::Invalid(error) => report
                    .errors
                    .extend(error.problems().iter().map(ToString::to_string)),
                other => report.errors.push(other.to_string()),
            }
            report.notes.push(NOT_LOADED.to_owned());
            return report;
        }
    };
    let config = &loaded.config;
    report.summary = Some(Summary {
        listeners: config.listeners.len(),
        tokens: config.tokens.len(),
        values: config.tokens.iter().map(|token| token.values.len()).sum(),
        sinks: config.events.sinks.len(),
    });

    // 2. The access rights of the files that hold secrets.
    let unreadable = check_permissions(&loaded, args.allow_insecure_file_permissions, &mut report);

    // 3. The policy.
    if let Err(error) = config.policy(1) {
        report.errors.push(error.to_string());
    }

    // 4. The certificates and keys, read as `run` reads them.
    let alpn = Postgres::new().alpn_protocol();
    for listener in &config.listeners {
        let name = listener.name.as_str();
        let mut failed = |error: TlsError| {
            // A file that could not even be examined has its error already.
            let reported =
                matches!(&error, TlsError::Read { file, .. } if unreadable.contains(file));
            if !reported {
                report.errors.push(format!("listener {name}: {error}"));
            }
        };
        if let Err(error) = ClientLeg::from_config(&listener.client_tls, alpn) {
            failed(error);
        }
        if let Err(error) =
            BackendLeg::from_config(&listener.upstream_tls, &listener.upstream, alpn)
        {
            failed(error);
        }
    }

    report
        .warnings
        .extend(config.warnings().iter().map(ToString::to_string));
    if config.tokens.is_empty() {
        report.notes.push(NO_TOKENS.to_owned());
    }
    report
}

/// Applies the rule of `run` to the files `run` applies it to, and returns
/// the files that could not be examined at all.
///
/// A file that is open to other users is an error, or a warning when the
/// operator allows such files, as `run` starts with them then. A file that
/// cannot be examined is an error either way: `run` cannot read it.
fn check_permissions(loaded: &Loaded, allow: bool, report: &mut Report) -> Vec<PathBuf> {
    let mut unreadable = Vec::new();
    let mut open = false;
    for refused in permissions::check_all(loaded.secret_files()) {
        if matches!(refused.problem, permissions::Problem::Unreadable(_)) {
            report.errors.push(refused.to_string());
            unreadable.push(refused.file);
        } else if allow {
            report.warnings.push(format!(
                "{refused}; pgsnare run starts all the same when it is given \
                 --allow-insecure-file-permissions"
            ));
        } else {
            report.errors.push(refused.to_string());
            open = true;
        }
    }
    if open {
        report.notes.push(OPEN_FILES.to_owned());
    }
    unreadable
}

/// Switches core dumps off for this process.
///
/// A command that loads a configuration holds honeytoken values in memory,
/// and a core dump would write them to disk.
pub(super) fn disable_core_dumps() {
    use rustix::process::{Resource, Rlimit, setrlimit};

    let none = Rlimit {
        current: Some(0),
        maximum: Some(0),
    };
    if setrlimit(Resource::Core, none).is_err() {
        eprintln!("pgsnare: warning: core dumps could not be switched off");
    }
}

/// Loads a configuration for a command that only reads it. When that
/// fails, the reason goes to standard error, and the exit status of the
/// command is returned.
pub(super) fn load_for(command: &str, file: &Path) -> Result<Loaded, u8> {
    config::load(file).map_err(|error| {
        eprintln!("pgsnare {command}: {error}");
        FAILURE
    })
}

/// Runs the command and returns its exit status: 0 if pgsnare would start
/// with the configuration, and 1 if it would not.
#[must_use]
pub fn run(args: &Args) -> u8 {
    // Before the first secret is read: the token files hold some.
    disable_core_dumps();
    let report = check(args);
    let text = report.render(&args.config);
    let mut stdout = std::io::stdout().lock();
    if let Err(error) = stdout
        .write_all(text.as_bytes())
        .and_then(|()| stdout.flush())
    {
        eprintln!(
            "pgsnare config check: the report could not be written: {}",
            error.kind()
        );
        return FAILURE;
    }
    if report.passed() { SUCCESS } else { FAILURE }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn summary() -> Summary {
        Summary {
            listeners: 2,
            tokens: 3,
            values: 4,
            sinks: 1,
        }
    }

    #[test]
    fn a_report_without_errors_passes_and_says_what_was_checked() {
        let report = Report {
            summary: Some(summary()),
            ..Report::default()
        };
        assert!(report.passed());
        assert_eq!(
            report.render(Path::new("/etc/pgsnare/pgsnare.yaml")),
            "ok: /etc/pgsnare/pgsnare.yaml: pgsnare would start with 2 listeners, 3 honeytokens \
             with 4 values, 1 sink and no warnings\n"
        );
    }

    #[test]
    fn warnings_do_not_fail_a_report() {
        let report = Report {
            warnings: vec!["inspection.on_error: fail_open".to_owned()],
            summary: Some(Summary {
                listeners: 1,
                tokens: 1,
                values: 1,
                sinks: 2,
            }),
            ..Report::default()
        };
        assert!(report.passed());
        assert_eq!(
            report.render(Path::new("pgsnare.yaml")),
            "warning: inspection.on_error: fail_open\n\
             ok: pgsnare.yaml: pgsnare would start with 1 listener, 1 honeytoken with 1 value, \
             2 sinks and 1 warning\n"
        );
    }

    #[test]
    fn an_error_fails_a_report_and_errors_come_before_warnings() {
        let report = Report {
            errors: vec!["first".to_owned(), "second".to_owned()],
            warnings: vec!["third".to_owned(), "fourth".to_owned()],
            notes: vec!["fifth".to_owned()],
            summary: Some(summary()),
        };
        assert!(!report.passed());
        assert_eq!(
            report.render(Path::new("pgsnare.yaml")),
            "error: first\nerror: second\nwarning: third\nwarning: fourth\nnote: fifth\n\
             failed: pgsnare.yaml: pgsnare would not start: 2 errors and 2 warnings\n"
        );
        // A note alone neither fails a report nor counts as a warning.
        let report = Report {
            notes: vec!["only a note".to_owned()],
            summary: Some(summary()),
            ..Report::default()
        };
        assert!(report.passed());
        assert!(
            report
                .render(Path::new("pgsnare.yaml"))
                .ends_with("1 sink and no warnings\n")
        );
    }

    #[test]
    fn a_configuration_that_could_not_be_loaded_says_what_was_left_out() {
        // Written as text that is not a configuration, and checked.
        let file = std::env::temp_dir().join(format!(
            "pgsnare-config-check-test-{}.yaml",
            std::process::id()
        ));
        std::fs::write(&file, "listeners: 5\n").unwrap();
        let report = check(&Args {
            config: file.clone(),
            allow_insecure_file_permissions: false,
        });
        std::fs::remove_file(&file).unwrap();

        assert!(!report.passed());
        assert_eq!(report.summary, None);
        assert_eq!(report.notes, [NOT_LOADED]);
        assert_eq!(
            report.render(Path::new("pgsnare.yaml")),
            format!(
                "error: {}: line 1, column 12: expected a list\n\
                 note: the configuration could not be loaded, so the files it names and its \
                 TLS settings were not checked\n\
                 failed: pgsnare.yaml: pgsnare would not start: 1 error and no warnings\n",
                file.display()
            )
        );
    }

    #[test]
    fn a_file_that_does_not_exist_fails_the_check() {
        let args = Args {
            config: PathBuf::from("/nonexistent/pgsnare.yaml"),
            allow_insecure_file_permissions: false,
        };
        let report = check(&args);
        assert!(!report.passed());
        assert_eq!(report.summary, None);
        assert_eq!(report.errors.len(), 1);
        assert!(
            report.errors[0].starts_with("/nonexistent/pgsnare.yaml: cannot read the file"),
            "{:?}",
            report.errors
        );
        assert_eq!(run(&args), FAILURE);
    }
}
