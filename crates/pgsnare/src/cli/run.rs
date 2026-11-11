// SPDX-License-Identifier: Apache-2.0

//! `pgsnare run`: start the proxy.

use std::path::PathBuf;

/// The arguments of `pgsnare run`.
#[derive(Debug, clap::Args)]
pub struct Args {
    /// The configuration file.
    #[arg(short, long, value_name = "FILE")]
    pub config: PathBuf,
}

/// Runs the command and returns its exit status.
#[must_use]
pub fn run(_args: &Args) -> u8 {
    super::not_implemented("run")
}
