// SPDX-License-Identifier: Apache-2.0

//! `pgsnare healthcheck`: ask the admin listener of a running proxy whether
//! it is healthy.
//!
//! The exit status is 0 for healthy and 1 for anything else, which is what a
//! container health check and a Kubernetes exec probe expect.

use std::path::PathBuf;

/// The arguments of `pgsnare healthcheck`.
#[derive(Debug, clap::Args)]
pub struct Args {
    /// The configuration file, to find the admin listener. Without it the
    /// default address is asked.
    #[arg(short, long, value_name = "FILE")]
    pub config: Option<PathBuf>,
}

/// Runs the command and returns its exit status. Until the check is built
/// the answer is "not healthy".
#[must_use]
pub fn run(_args: &Args) -> u8 {
    super::not_implemented("healthcheck")
}
