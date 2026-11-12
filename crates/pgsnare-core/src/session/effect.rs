// SPDX-License-Identifier: Apache-2.0

//! What the session logic hands back to the runtime.

use core::time::Duration;

use crate::event::EventBody;

use super::Leg;

/// Something the session logic asks the runtime to do.
///
/// The session logic decides and the runtime acts: only the runtime owns
/// sockets and timers.
#[derive(Clone, Debug, PartialEq)]
#[non_exhaustive]
pub enum Effect {
    /// Close one connection, after the bytes queued for it have been sent.
    Close(Leg),
    /// Send this cancel request to the database on a new connection.
    ///
    /// The bytes are the complete request, built by the protocol module from
    /// the key the server issued to this session.
    Cancel {
        /// The request to send, verbatim.
        request: Vec<u8>,
    },
    /// Wait this long before sending the queued bytes to the client.
    Delay(Duration),
    /// Hand this event to the dispatcher, without waiting for it.
    Emit(Box<EventBody>),
}

/// Everything one step of the session logic produced.
///
/// The runtime sends the bytes and then carries out the effects, in order.
#[derive(Clone, Debug, Default, PartialEq)]
pub struct Output {
    /// Bytes to send to the client.
    pub to_client: Vec<u8>,
    /// Bytes to send to the database.
    pub to_server: Vec<u8>,
    /// What else the runtime must do.
    pub effects: Vec<Effect>,
}

impl Output {
    /// An empty output.
    #[must_use]
    pub const fn new() -> Self {
        Self {
            to_client: Vec::new(),
            to_server: Vec::new(),
            effects: Vec::new(),
        }
    }

    /// Whether this step produced nothing at all.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.to_client.is_empty() && self.to_server.is_empty() && self.effects.is_empty()
    }

    /// Empties the output and keeps its buffers, so it can be reused for the
    /// next step without allocating again.
    pub fn clear(&mut self) {
        self.to_client.clear();
        self.to_server.clear();
        self.effects.clear();
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_new_output_is_empty_and_clear_empties_it() {
        let mut out = Output::new();
        assert!(out.is_empty());

        out.to_client.extend_from_slice(b"abc");
        out.effects.push(Effect::Close(Leg::Client));
        out.effects.push(Effect::Delay(Duration::from_millis(5)));
        assert!(!out.is_empty());

        out.clear();
        assert!(out.is_empty());
        assert_eq!(out, Output::default());
    }
}
