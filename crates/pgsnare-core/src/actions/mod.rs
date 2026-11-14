// SPDX-License-Identifier: Apache-2.0

//! Responses to a hit: kill, tarpit and fake data.
//!
//! Each response is a pure function that appends to an [`Output`] what the
//! session sends and the effects the runtime carries out. The inspector
//! decides when a response applies.
//!
//! [`Output`]: crate::session::Output

mod fake_data;
mod kill;
mod tarpit;

pub use fake_data::FakeRows;
pub use kill::kill;
pub use tarpit::{Tarpit, TarpitPlace, TarpitPlaces};
