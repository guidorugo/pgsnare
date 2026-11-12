// SPDX-License-Identifier: Apache-2.0

//! `pgsnare token test`: check whether a value matches a honeytoken of a
//! configuration.
//!
//! The value is read from standard input and is not an argument, so that it
//! does not end up in the shell history or the process list.

use std::path::PathBuf;

/// The arguments of `pgsnare token test`.
#[derive(Debug, clap::Args)]
pub struct Args {
    /// The configuration file.
    #[arg(short, long, value_name = "FILE")]
    pub config: PathBuf,
}

/// Runs the command and returns its exit status.
#[must_use]
pub fn run(_args: &Args) -> u8 {
    super::not_implemented("token test")
}
