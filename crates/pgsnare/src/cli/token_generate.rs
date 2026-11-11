// SPDX-License-Identifier: Apache-2.0

//! `pgsnare token generate`: print the SQL that plants new honeytokens and
//! the configuration that matches them. It connects to nothing.

/// The arguments of `pgsnare token generate`.
#[derive(Debug, clap::Args)]
pub struct Args {
    /// The kind of honeytoken to generate.
    #[arg(long, value_name = "KIND")]
    pub kind: String,
    /// The table the honeytokens are meant for.
    #[arg(long, value_name = "TABLE")]
    pub table: Option<String>,
    /// How many honeytokens to generate.
    #[arg(long, value_name = "N", default_value_t = 1, value_parser = clap::value_parser!(u32).range(1..))]
    pub count: u32,
}

/// Runs the command and returns its exit status.
#[must_use]
pub fn run(_args: &Args) -> u8 {
    super::not_implemented("token generate")
}
