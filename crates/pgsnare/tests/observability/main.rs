// SPDX-License-Identifier: Apache-2.0

//! Events, sinks and observability, tested from the outside.
//!
//! Some tests run a proxy inside the test, on a free port of this machine,
//! with a protocol that raises the events a test asks for. Others start
//! the `pgsnare` binary of this build as the process it ships as, with a
//! configuration file, and look at what it writes and at how it ends. The
//! sinks, receivers and databases they talk to are a few lines of test
//! code. Keys and certificates are made when a test runs and are gone when
//! it ends.
//!
//! The tests are one program, so that what they share is compiled once and
//! every part of it is used.

mod events;
mod health;
mod leak;
mod listener_fault;
mod process;
mod receiver;
mod stdout;
mod support;
mod webhook;
