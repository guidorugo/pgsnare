// SPDX-License-Identifier: Apache-2.0

//! The runtime, tested from the outside: a proxy on a free port of this
//! machine, between clients and databases that are a few lines of test
//! code.
//!
//! The tests are one program, so that what they share is compiled once and
//! every part of it is used.

mod relay;
mod scan;
mod support;
mod tls;
