// SPDX-License-Identifier: Apache-2.0

//! The command line.
//!
//! Each subcommand lives in a file of its own, with its arguments and its
//! `run` function, so that work on one command does not touch another:
//!
//! | Command | File |
//! |---|---|
//! | `pgsnare run` | `run.rs` |
//! | `pgsnare config check` | `config_check.rs` |
//! | `pgsnare token generate` | `token_generate.rs` |
//! | `pgsnare token list` | `token_list.rs` |
//! | `pgsnare token test` | `token_test.rs` |
//! | `pgsnare healthcheck` | `healthcheck.rs` |
//!
//! A command that is not built yet says so and fails. It never reports
//! success without having done what was asked.

use std::ffi::OsString;
use std::process::ExitCode;

use clap::{Parser, Subcommand};

pub mod config_check;
pub mod healthcheck;
pub mod run;
pub mod token_generate;
pub mod token_list;
pub mod token_test;

/// The exit status of a command that did what was asked.
pub const SUCCESS: u8 = 0;

/// The exit status of a command that failed, of a check that found
/// problems, and of a health check that found the proxy unhealthy.
pub const FAILURE: u8 = 1;

/// The exit status for a command line that could not be understood.
pub const USAGE: u8 = 2;

/// The `pgsnare` command line.
#[derive(Debug, Parser)]
#[command(
    name = "pgsnare",
    version,
    about = "A PostgreSQL proxy that detects data theft with honeytokens.",
    propagate_version = true,
    subcommand_required = true,
    arg_required_else_help = true
)]
pub struct Cli {
    /// What to do.
    #[command(subcommand)]
    pub command: Command,
}

/// The top-level commands.
#[derive(Debug, Subcommand)]
pub enum Command {
    /// Run the proxy.
    Run(run::Args),
    /// Work with a configuration.
    #[command(subcommand)]
    Config(ConfigCommand),
    /// Work with honeytokens.
    #[command(subcommand)]
    Token(TokenCommand),
    /// Ask a running proxy whether it is healthy.
    Healthcheck(healthcheck::Args),
}

/// The `pgsnare config` commands.
#[derive(Debug, Subcommand)]
pub enum ConfigCommand {
    /// Check a configuration and report every problem.
    Check(config_check::Args),
}

/// The `pgsnare token` commands.
#[derive(Debug, Subcommand)]
pub enum TokenCommand {
    /// Generate honeytokens: the SQL to plant them and the matching
    /// configuration.
    Generate(token_generate::Args),
    /// List the honeytokens of a configuration, without their values.
    List(token_list::Args),
    /// Check whether a value matches a honeytoken of a configuration.
    Test(token_test::Args),
}

impl Command {
    /// Runs the command and returns its exit status.
    #[must_use]
    pub fn run(self) -> u8 {
        match self {
            Self::Run(args) => run::run(&args),
            Self::Config(ConfigCommand::Check(args)) => config_check::run(&args),
            Self::Token(TokenCommand::Generate(args)) => token_generate::run(&args),
            Self::Token(TokenCommand::List(args)) => token_list::run(&args),
            Self::Token(TokenCommand::Test(args)) => token_test::run(&args),
            Self::Healthcheck(args) => healthcheck::run(&args),
        }
    }
}

/// Runs the command line of this process.
#[must_use]
pub fn main() -> ExitCode {
    ExitCode::from(run_from(std::env::args_os()))
}

/// Runs a command line and returns its exit status. The first argument is
/// the name of the program.
///
/// Help and version requests print to standard output and succeed. A
/// command line that cannot be understood prints to standard error.
pub fn run_from<I, T>(arguments: I) -> u8
where
    I: IntoIterator<Item = T>,
    T: Into<OsString> + Clone,
{
    match Cli::try_parse_from(arguments) {
        Ok(cli) => cli.command.run(),
        Err(error) => {
            // Printing can fail when the output is closed. There is nobody
            // left to tell, and the exit status still says what happened.
            let _ = error.print();
            if error.use_stderr() { USAGE } else { SUCCESS }
        }
    }
}

/// Reports that a command is not built yet. It never returns success.
fn not_implemented(command: &str) -> u8 {
    eprintln!("pgsnare {command}: not implemented yet");
    FAILURE
}

#[cfg(test)]
mod tests {
    use std::path::Path;

    use clap::CommandFactory;

    use super::*;

    fn parse(arguments: &[&str]) -> Result<Command, clap::Error> {
        Cli::try_parse_from(std::iter::once("pgsnare").chain(arguments.iter().copied()))
            .map(|cli| cli.command)
    }

    #[test]
    fn the_command_line_is_well_formed() {
        Cli::command().debug_assert();
    }

    #[test]
    fn every_subcommand_exists() {
        let cli = Cli::command();
        let names = |command: &clap::Command| -> Vec<String> {
            command
                .get_subcommands()
                .map(|sub| sub.get_name().to_owned())
                .filter(|name| name != "help")
                .collect()
        };
        assert_eq!(names(&cli), ["run", "config", "token", "healthcheck"]);
        let sub = |name: &str| cli.find_subcommand(name).unwrap();
        assert_eq!(names(sub("config")), ["check"]);
        assert_eq!(names(sub("token")), ["generate", "list", "test"]);
    }

    #[test]
    fn run_takes_a_configuration_file() {
        let Command::Run(args) = parse(&["run", "--config", "/etc/pgsnare/pgsnare.yaml"]).unwrap()
        else {
            panic!("expected run");
        };
        assert_eq!(args.config, Path::new("/etc/pgsnare/pgsnare.yaml"));

        let Command::Run(args) = parse(&["run", "-c", "pgsnare.yaml"]).unwrap() else {
            panic!("expected run");
        };
        assert_eq!(args.config, Path::new("pgsnare.yaml"));
        assert!(parse(&["run"]).is_err());
    }

    #[test]
    fn config_check_takes_a_configuration_file() {
        let Command::Config(ConfigCommand::Check(args)) =
            parse(&["config", "check", "-c", "pgsnare.yaml"]).unwrap()
        else {
            panic!("expected config check");
        };
        assert_eq!(args.config, Path::new("pgsnare.yaml"));
        assert!(!args.allow_insecure_file_permissions);
        assert!(parse(&["config", "check"]).is_err());
        assert!(parse(&["config"]).is_err());

        // The option of `run` that lets files through means the same here.
        let Command::Config(ConfigCommand::Check(args)) = parse(&[
            "config",
            "check",
            "--config",
            "pgsnare.yaml",
            "--allow-insecure-file-permissions",
        ])
        .unwrap() else {
            panic!("expected config check");
        };
        assert!(args.allow_insecure_file_permissions);
    }

    #[test]
    fn token_generate_takes_a_kind_a_table_and_a_count() {
        let generate = |arguments: &[&str]| {
            let all: Vec<&str> = ["token", "generate"]
                .into_iter()
                .chain(arguments.iter().copied())
                .collect();
            match parse(&all) {
                Ok(Command::Token(TokenCommand::Generate(args))) => Ok(args),
                Ok(other) => panic!("expected token generate, got {other:?}"),
                Err(error) => Err(error),
            }
        };

        let args = generate(&["--kind", "marker", "--table", "notes"]).unwrap();
        assert_eq!(args.kind, token_generate::Kind::Marker);
        assert_eq!(args.table, "notes");
        assert!(args.columns.is_empty());
        assert_eq!(args.domain, None);
        assert_eq!(args.count, 1);
        assert_eq!(args.id, None);

        let args = generate(&[
            "--kind",
            "api-key",
            "--table",
            "public.api_keys",
            "--count",
            "5",
        ])
        .unwrap();
        assert_eq!(args.kind, token_generate::Kind::ApiKey);
        assert_eq!(args.table, "public.api_keys");
        assert_eq!(args.count, 5);

        let args = generate(&[
            "--kind",
            "identity",
            "--table",
            "public.users",
            "--column",
            "login",
            "--column",
            "mail",
            "--domain",
            "mail.example",
            "--id",
            "users-admin",
        ])
        .unwrap();
        assert_eq!(args.kind, token_generate::Kind::Identity);
        assert_eq!(args.columns, ["login", "mail"]);
        assert_eq!(args.domain.as_deref(), Some("mail.example"));
        assert_eq!(args.id.as_deref(), Some("users-admin"));

        // Every kind is chosen by the name it prints.
        for kind in <token_generate::Kind as clap::ValueEnum>::value_variants() {
            let args = generate(&["--kind", kind.name(), "--table", "t"]).unwrap();
            assert_eq!(args.kind, *kind);
        }
        assert_eq!(
            <token_generate::Kind as clap::ValueEnum>::value_variants().len(),
            7
        );

        // The kind and the table are required, and the count has bounds.
        assert!(generate(&[]).is_err());
        assert!(generate(&["--kind", "marker"]).is_err());
        assert!(generate(&["--table", "notes"]).is_err());
        assert!(generate(&["--kind", "no-such-kind", "--table", "t"]).is_err());
        for count in ["0", "1001", "-1", "many"] {
            let arguments = ["--kind", "marker", "--table", "t", "--count", count];
            assert!(generate(&arguments).is_err(), "{count}");
        }
        assert_eq!(
            generate(&["--kind", "marker", "--table", "t", "--count", "1000"])
                .unwrap()
                .count,
            token_generate::MAX_COUNT
        );
        // There is no option that makes the values predictable.
        for option in ["--seed", "--random-seed", "--deterministic", "--rng"] {
            let arguments = ["--kind", "marker", "--table", "t", option, "1"];
            assert!(generate(&arguments).is_err(), "{option}");
        }
    }

    #[test]
    fn token_list_and_token_test_take_a_configuration_file() {
        let Command::Token(TokenCommand::List(args)) =
            parse(&["token", "list", "-c", "pgsnare.yaml"]).unwrap()
        else {
            panic!("expected token list");
        };
        assert_eq!(args.config, Path::new("pgsnare.yaml"));

        let Command::Token(TokenCommand::Test(args)) =
            parse(&["token", "test", "--config", "pgsnare.yaml"]).unwrap()
        else {
            panic!("expected token test");
        };
        assert_eq!(args.config, Path::new("pgsnare.yaml"));

        assert!(args.not_taken.is_empty());

        // The value to test is read from standard input. It is not an
        // argument, so it cannot end up in the process list or the shell
        // history. Something given as one is collected, so that the command
        // can refuse it without printing it back, and it is refused.
        for arguments in [
            &["token", "test", "-c", "pgsnare.yaml", "some-value"][..],
            &[
                "token",
                "test",
                "-c",
                "pgsnare.yaml",
                "--value",
                "some-value",
            ],
            &["token", "test", "-c", "pgsnare.yaml", "--value=some-value"],
        ] {
            let Command::Token(TokenCommand::Test(args)) = parse(arguments).unwrap() else {
                panic!("expected token test");
            };
            assert!(!args.not_taken.is_empty(), "{arguments:?}");
            let all = std::iter::once("pgsnare").chain(arguments.iter().copied());
            assert_eq!(run_from(all), USAGE, "{arguments:?}");
        }
        // With the value in front, everything after it is collected too,
        // and the parser misses --config. Its complaint does not repeat
        // the value either.
        let front = ["token", "test", "some-value", "-c", "pgsnare.yaml"];
        let error = parse(&front).unwrap_err();
        assert!(!error.to_string().contains("some-value"), "{error}");
        assert_eq!(run_from(std::iter::once("pgsnare").chain(front)), USAGE);
        assert!(parse(&["token", "list"]).is_err());
        assert!(parse(&["token"]).is_err());
    }

    #[test]
    fn healthcheck_needs_no_arguments() {
        let Command::Healthcheck(args) = parse(&["healthcheck"]).unwrap() else {
            panic!("expected healthcheck");
        };
        assert_eq!(args.config, None);

        let Command::Healthcheck(args) = parse(&["healthcheck", "-c", "pgsnare.yaml"]).unwrap()
        else {
            panic!("expected healthcheck");
        };
        assert_eq!(args.config.as_deref(), Some(Path::new("pgsnare.yaml")));
    }

    #[test]
    fn a_command_that_is_not_built_yet_fails() {
        let arguments = ["pgsnare", "healthcheck"];
        assert_eq!(run_from(arguments), FAILURE, "{arguments:?}");
    }

    #[test]
    fn help_and_version_succeed_and_mistakes_are_usage_errors() {
        assert_eq!(run_from(["pgsnare", "--help"]), SUCCESS);
        assert_eq!(run_from(["pgsnare", "--version"]), SUCCESS);
        assert_eq!(run_from(["pgsnare", "token", "--help"]), SUCCESS);
        assert_eq!(run_from(["pgsnare", "run", "--version"]), SUCCESS);

        assert_eq!(run_from(["pgsnare", "frobnicate"]), USAGE);
        assert_eq!(run_from(["pgsnare", "run"]), USAGE);
        assert_eq!(run_from(["pgsnare", "run", "--no-such-option"]), USAGE);
        // With no command at all, the help is shown as an error.
        assert_eq!(run_from(["pgsnare"]), USAGE);
    }
}
