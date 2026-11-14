// SPDX-License-Identifier: Apache-2.0

//! `kill`: the session ends the way a session an administrator terminates
//! ends.
//!
//! The client is told with an `ErrorResponse` of severity `FATAL`, the
//! SQLSTATE and the message of the policy, in the order the database
//! itself uses for a terminated session; the fields that name a source
//! file and line of the server are left out, as in every error the
//! session writes itself. The query that runs on
//! the database is cancelled with the key the server gave the session,
//! and both connections are closed. Nothing waits before the error, and
//! nothing in it names pgsnare.
//!
//! The error is sent only when the client is at the end of a message: a
//! client that has received part of a message cannot read an error in its
//! place. It then loses its connection without one, as when a server
//! dies.

use pgsnare_proto::backend::error_field;
use pgsnare_proto::encode;

use crate::policy::KillSettings;
use crate::session::{Effect, Leg, Output};

/// Ends a session.
///
/// Appends the error for the client when `client_can_be_told`, a cancel
/// request when the server gave the session a key (`cancel_request`), and
/// the effects that close both connections. The caller holds back the
/// message that caused it and everything after it.
pub fn kill(
    settings: &KillSettings,
    client_can_be_told: bool,
    cancel_request: Option<&[u8]>,
    out: &mut Output,
) {
    if client_can_be_told {
        // The settings are checked when they are loaded, so the error can
        // always be written. Should it fail, nothing was written and the
        // client loses the connection without it.
        let _ = encode::error_response(
            &[
                (error_field::SEVERITY, b"FATAL"),
                (error_field::SEVERITY_NONLOCALIZED, b"FATAL"),
                (error_field::SQLSTATE, settings.sqlstate.as_bytes()),
                (error_field::MESSAGE, settings.message.as_bytes()),
            ],
            &mut out.to_client,
        );
    }
    if let Some(request) = cancel_request {
        out.effects.push(Effect::Cancel {
            request: request.to_vec(),
        });
    }
    out.effects.push(Effect::Close(Leg::Client));
    out.effects.push(Effect::Close(Leg::Backend));
}
