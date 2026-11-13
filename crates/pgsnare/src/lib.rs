// SPDX-License-Identifier: Apache-2.0

//! The pgsnare runtime as a library: listeners, TLS, configuration and
//! reload, sinks, the admin and metrics listeners, and the command line.
//!
//! The `pgsnare` binary is a thin wrapper around [`main`]. Another build can
//! assemble its own proxy from the same parts with the [`builder`].

#![forbid(unsafe_code)]

use std::process::ExitCode;

pub mod admin;
pub mod builder;
pub mod cli;
pub mod config;
mod http;
pub mod redact;
pub mod reload;
pub mod runtime;
pub mod sinks;
pub mod tls;

/// Entry point of the `pgsnare` binary: runs the command line of this
/// process.
#[must_use]
pub fn main() -> ExitCode {
    cli::main()
}
