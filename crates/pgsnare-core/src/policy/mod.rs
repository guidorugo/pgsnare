// SPDX-License-Identifier: Apache-2.0

//! The immutable policy snapshot.
//!
//! A [`PolicySnapshot`] holds what the session logic needs to judge a
//! message: the tokens and what to do when one is hit, who is exempt, the
//! limits of inspection and the settings of each response. It contains no
//! PostgreSQL-specific type and does no I/O.
//!
//! The session logic gets the current snapshot from a [`PolicySource`], one
//! per message. The runtime builds snapshots from configuration and swaps
//! them on reload.
//!
//! The compiled matcher and the SQL rules join the snapshot with the tasks
//! that build them.

mod action;
mod cidr;
mod id;
mod settings;
mod snapshot;
mod token;

pub use action::{Action, ActionSet, Escalation};
pub use cidr::{InvalidCidr, IpCidr};
pub use id::{InvalidId, MAX_ID_BYTES, RuleId, TokenId};
pub use settings::{
    ActionSettings, FakeDataSettings, Inspection, InvalidSqlState, KillSettings, OnError,
    QueryRedaction, SqlState, TarpitSettings,
};
pub use snapshot::{FixedPolicy, PolicyError, PolicySnapshot, PolicySnapshotBuilder, PolicySource};
pub use token::{Exemption, Scope, TokenPolicy};
