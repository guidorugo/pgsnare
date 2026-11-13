// SPDX-License-Identifier: Apache-2.0

//! Events, sinks and observability, tested from the outside: a proxy on a
//! free port of this machine whose protocol raises the events a test asks
//! for, and sinks and receivers that are a few lines of test code.
//!
//! The tests are one program, so that what they share is compiled once and
//! every part of it is used.

mod events;
mod listener_fault;
mod support;
