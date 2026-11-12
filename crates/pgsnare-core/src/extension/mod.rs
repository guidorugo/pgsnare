// SPDX-License-Identifier: Apache-2.0

//! The three interfaces through which pgsnare can be extended.
//!
//! - A [`LoginStrategy`] decides how a client is authenticated to the
//!   database. pgsnare ships one, [`Relay`], which passes the login through
//!   untouched and never learns a password.
//! - An [`EventSink`] delivers events somewhere: a webhook, a file, a log.
//! - A [`ProtocolModule`] holds everything that is specific to one database
//!   protocol. pgsnare ships one, for PostgreSQL. Detection, policy and
//!   events know nothing about any particular protocol.
//!
//! A proxy is assembled from implementations of these by the builder in the
//! `pgsnare` crate. Another build can supply its own implementations without
//! changing or forking this crate.
//!
//! # Extensions are compiled in
//!
//! An extension is ordinary Rust code that is linked into the binary. There
//! is no plugin loading at run time, no dynamic library and no scripting, so
//! an extension point adds nothing to the attack surface of a running proxy.
//!
//! # Stability
//!
//! Nothing is released yet. These interfaces will change while the relay and
//! the sinks are being built.

mod login;
mod protocol;
mod sink;

pub use login::{LoginDecision, LoginError, LoginExchange, LoginStrategy, Relay};
pub use protocol::{ProtocolModule, ProtocolSession, SessionError};
pub use sink::{EventSink, SinkError, SinkFuture};
