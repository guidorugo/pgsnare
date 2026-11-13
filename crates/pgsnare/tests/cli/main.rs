// SPDX-License-Identifier: Apache-2.0

//! What the commands print, compared with expected output that is kept
//! next to this file, in `expected/`.
//!
//! When the output of a command changes on purpose, run the tests once
//! with `UPDATE_EXPECTED=1` in the environment. That rewrites the expected
//! files, and the change then shows up in review as a difference to them.
//!
//! The values `token generate` prints are random, so its expected output
//! is taken from [`pgsnare::cli::token_generate::generate`] with a fixed
//! source of randomness. That function is the only way to fix the
//! randomness, and nothing on the command line leads to it. The command
//! itself is run as well, to see that its values do differ from run to
//! run.

mod expected;
mod sql;
mod token_generate;
