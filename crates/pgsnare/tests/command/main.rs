// SPDX-License-Identifier: Apache-2.0

//! The `pgsnare` command, tested as the process it ships as: the binary of
//! this build is started with a configuration file, and the tests look at
//! what it writes and at how it ends.
//!
//! Everything the process talks to is a few lines of test code on the
//! loopback interface of this machine. Keys and certificates are made when
//! a test runs and are gone when it ends.

mod health;
mod stdout;
mod support;
