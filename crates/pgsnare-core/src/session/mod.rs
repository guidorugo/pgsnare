// SPDX-License-Identifier: Apache-2.0

//! The session state machine and what it exchanges with the runtime.
//!
//! The session logic takes bytes in and returns bytes out plus [`Effect`]s
//! for the runtime to carry out. It never touches a socket or a clock, so it
//! can be tested and fuzzed with any interleaving of client and server
//! bytes.
//!
//! # The boundary
//!
//! The types of this module are what crosses the boundary between the
//! session logic and the runtime. They know nothing about any particular
//! database protocol.
//!
//! - The runtime hands the session logic the bytes it read from either
//!   connection, and a [`Report`] when something else happened.
//! - The session logic answers with an [`Output`]: bytes for each
//!   connection and a list of [`Effect`]s.
//!
//! # The state machine
//!
//! The state machine itself belongs to a protocol module. The one that
//! ships with pgsnare is [`postgres`]. Everything that is specific to
//! PostgreSQL lives there, and nothing outside it uses the wire-protocol
//! crate.

mod effect;
mod origin;
pub mod postgres;
mod report;

#[cfg(feature = "rules")]
pub use effect::StatementText;
pub use effect::{Effect, Output};
pub use origin::{Direction, Leg, SessionOrigin, TlsPolicy};
pub use report::Report;
