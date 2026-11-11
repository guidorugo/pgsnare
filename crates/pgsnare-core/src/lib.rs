// SPDX-License-Identifier: Apache-2.0

//! The core of pgsnare: session logic, detection, policy, actions, optional
//! SQL rules, the event schema and bait generators.
//!
//! This crate performs no I/O. It takes bytes in and returns bytes out plus
//! effects for the runtime to carry out. It never touches a socket or a
//! clock.

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

pub mod actions;
pub mod bait;
pub mod detect;
pub mod event;
pub mod policy;
#[cfg(feature = "rules")]
pub mod rules;
pub mod session;
