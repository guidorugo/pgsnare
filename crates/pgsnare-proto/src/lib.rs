// SPDX-License-Identifier: Apache-2.0

//! The PostgreSQL wire format as pgsnare needs it: framing, typed views of
//! the messages it must understand, and encoders for the few messages it
//! injects.
//!
//! This crate performs no I/O. Every read of untrusted bytes is
//! bounds-checked and returns an error instead of panicking.

#![forbid(unsafe_code)]
#![cfg_attr(
    not(test),
    deny(
        clippy::unwrap_used,
        clippy::expect_used,
        clippy::panic,
        clippy::indexing_slicing,
        clippy::arithmetic_side_effects
    )
)]
