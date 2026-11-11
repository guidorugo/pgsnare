// SPDX-License-Identifier: Apache-2.0

//! The session state machine and the effects it returns to the runtime.
//!
//! The session logic takes bytes in and returns bytes out plus [`Effect`]s
//! for the runtime to carry out. It never touches a socket or a clock, so it
//! can be tested and fuzzed with any interleaving of client and server
//! bytes.
//!
//! This module holds the types at that boundary. The state machine itself
//! is added by the relay.

mod effect;
mod origin;

pub use effect::{Effect, Output};
pub use origin::{Direction, Leg, SessionOrigin};
