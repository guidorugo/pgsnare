// SPDX-License-Identifier: Apache-2.0

//! Comparing output with the files in `expected/`, and running the binary.

use std::path::{Path, PathBuf};
use std::process::{Command, Output, Stdio};

/// The directory of the expected files.
fn directory() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR")).join("tests/cli/expected")
}

/// Compares `actual` with the expected file `name`.
///
/// With `UPDATE_EXPECTED` in the environment, the file is rewritten
/// instead, and the test passes.
#[track_caller]
pub fn check(name: &str, actual: &str) {
    let path = directory().join(name);
    if std::env::var_os("UPDATE_EXPECTED").is_some() {
        std::fs::create_dir_all(directory()).expect("the directory of the expected files");
        std::fs::write(&path, actual).expect("an expected file can be written");
        return;
    }
    let expected = std::fs::read_to_string(&path).unwrap_or_else(|error| {
        panic!(
            "the expected file {name} cannot be read ({}); run the tests with UPDATE_EXPECTED=1 \
             to write it, and review it",
            error.kind()
        )
    });
    if expected == actual {
        return;
    }
    let line = expected
        .lines()
        .zip(actual.lines())
        .position(|(expected, actual)| expected != actual)
        .unwrap_or_else(|| expected.lines().count().min(actual.lines().count()));
    panic!(
        "the output differs from {name}, first at line {}.\n\
         --- expected ---\n{expected}\n--- actual ---\n{actual}\n\
         If the change is intended, run the tests with UPDATE_EXPECTED=1 and review the file.",
        line + 1
    );
}

/// What a run of the `pgsnare` binary gave.
pub struct Run {
    pub status: i32,
    pub stdout: String,
    pub stderr: String,
}

impl Run {
    fn from(output: Output) -> Self {
        Self {
            status: output.status.code().expect("the command ended by itself"),
            stdout: String::from_utf8(output.stdout).expect("standard output is UTF-8"),
            stderr: String::from_utf8(output.stderr).expect("standard error is UTF-8"),
        }
    }
}

/// The environment variable the configurations of these tests name for
/// the signing key of a webhook.
pub const SIGNING_KEY_VARIABLE: &str = "PGSNARE_WEBHOOK_SECRET";

/// A signing key that is made for this run of the tests and is long enough
/// to cause no warning. Nothing is ever signed with it.
pub fn signing_key() -> String {
    format!("made-for-this-run-of-the-tests-{:010}", std::process::id())
}

/// A command line for the binary under test. Its environment holds one
/// variable and nothing else: [`SIGNING_KEY_VARIABLE`], because a webhook
/// sink cannot be built without its signing key.
pub fn pgsnare(arguments: &[&str]) -> Command {
    let mut command = Command::new(env!("CARGO_BIN_EXE_pgsnare"));
    command
        .args(arguments)
        .env_clear()
        .env(SIGNING_KEY_VARIABLE, signing_key())
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped());
    command
}

/// Runs the binary with these arguments, nothing on standard input and the
/// environment of [`pgsnare`].
pub fn run(arguments: &[&str]) -> Run {
    Run::from(
        pgsnare(arguments)
            .output()
            .expect("the pgsnare binary can be run"),
    )
}

/// Runs a prepared command line.
pub fn run_command(mut command: Command) -> Run {
    Run::from(command.output().expect("the pgsnare binary can be run"))
}

/// Waits for a command that was started, and returns what it gave.
pub fn finish(child: std::process::Child) -> Run {
    Run::from(
        child
            .wait_with_output()
            .expect("the pgsnare binary can be waited for"),
    )
}
