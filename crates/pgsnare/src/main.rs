// SPDX-License-Identifier: Apache-2.0

//! The `pgsnare` binary: a thin wrapper around the runtime library.

#![forbid(unsafe_code)]

use std::process::ExitCode;

fn main() -> ExitCode {
    pgsnare::main()
}
