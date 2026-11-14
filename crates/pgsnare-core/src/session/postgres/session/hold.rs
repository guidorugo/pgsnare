// SPDX-License-Identifier: Apache-2.0

//! Holding a message of the client until the inspector has decided.
//!
//! An inspector that answers [`Verdict::Hold`] for a message of the client
//! has asked the runtime for something it needs to decide. Until the
//! answer is there:
//!
//! - the message is kept, and none of it is passed on;
//! - nothing the client sent after it is looked at: those bytes wait
//!   behind it, in the order they arrived, and are handled when the
//!   message is let go, as if they had arrived then;
//! - messages of the server pass as before.
//!
//! # Bounds
//!
//! One message is held at a time, and it is one the session held whole
//! anyway. Behind it wait at most [`MAX_BEHIND`] bytes: a client that
//! sends more, to a runtime that keeps reading it, loses the session. The
//! runtime that ships with pgsnare does not read a client whose statement
//! is held, so that what waits is the rest of one read.
//!
//! Letting a message go costs what the messages handled then are long.
//! The bytes that wait are never copied again, however often the session
//! holds a message among them.
//!
//! # When something goes wrong
//!
//! A session that holds a statement never becomes a tunnel, whatever
//! `on_error` says: the statement would reach the database unjudged. It
//! ends.

use std::sync::Arc;

use pgsnare_proto::Frame;

use crate::extension::SessionError;
use crate::policy::PolicySnapshot;
use crate::rules::{Analysis, ParseFailure};
use crate::session::{Direction, Output};

use super::{Fault, Phase, PostgresSession, Verdict, context};

/// The most bytes of a client that wait behind a held message.
pub(in crate::session::postgres) const MAX_BEHIND: usize = 1024 * 1024;

/// A held message of the client and what waits behind it.
pub(super) struct Parked {
    /// The message, as it arrived.
    message: Vec<u8>,
    /// What the client sent after it.
    behind: Vec<u8>,
    /// How many bytes at the front of `behind` have been handled already.
    handled: usize,
}

impl Parked {
    /// The bytes that are held and have not been handled.
    pub(super) fn bytes(&self) -> usize {
        self.message
            .len()
            .saturating_add(self.behind.len().saturating_sub(self.handled))
    }
}

impl PostgresSession {
    /// Holds a whole message of the client.
    pub(super) fn park(&mut self, from: Direction, frame: Frame<'_>) -> Result<(), Fault> {
        if from != Direction::FromClient || self.parked.is_some() {
            return Err(Fault::new("a message was held that cannot be"));
        }
        self.parked = Some(Parked {
            message: frame.as_bytes().to_vec(),
            behind: Vec::new(),
            handled: 0,
        });
        Ok(())
    }

    /// Takes bytes of the client that arrive while a message is held.
    pub(super) fn queue_behind(&mut self, input: &[u8]) -> Result<(), SessionError> {
        let Some(parked) = self.parked.as_mut() else {
            self.close();
            return Err(SessionError::new(
                "bytes of the client were left without a message that holds them",
            ));
        };
        // What has been handled is given up once it is half of what is
        // kept, so that this costs no more than handling it did.
        if parked.handled > 0 && parked.handled >= parked.behind.len() / 2 {
            let handled = parked.handled.min(parked.behind.len());
            parked.behind.drain(..handled);
            parked.handled = 0;
        }
        let waiting = parked.behind.len().saturating_sub(parked.handled);
        if input.len() > MAX_BEHIND.saturating_sub(waiting) {
            self.close();
            return Err(SessionError::new(
                "too many bytes from the client behind a held statement",
            ));
        }
        parked.behind.extend_from_slice(input);
        Ok(())
    }

    /// Keeps the last `unhandled` bytes of `input` behind the message that
    /// was held while `input` was handled.
    pub(super) fn keep_unhandled(
        &mut self,
        input: &[u8],
        unhandled: usize,
    ) -> Result<(), SessionError> {
        if unhandled == 0 {
            return Ok(());
        }
        let rest = input
            .get(input.len().saturating_sub(unhandled)..)
            .unwrap_or_default();
        self.queue_behind(rest)
    }

    /// The answer of the runtime to a request of the inspector: asks the
    /// inspector what becomes of the held message, and then handles what
    /// waited behind it.
    pub(super) fn analysed(
        &mut self,
        id: u64,
        outcome: Result<Arc<Analysis>, ParseFailure>,
        policy: &PolicySnapshot,
        out: &mut Output,
    ) -> Result<(), SessionError> {
        if self.parked.is_none() {
            return Ok(());
        }
        let context = context(
            &self.origin,
            &self.identity,
            self.cancel_request.as_deref(),
            policy,
            self.from_client.in_copy,
            self.phase == Phase::Established,
        );
        let verdict = match self.inspector.analysed(id, outcome, &context, out) {
            // Not the answer that is waited for.
            Ok(None) => return Ok(()),
            Ok(Some(Verdict::Hold)) | Err(_) => {
                self.close();
                return Err(SessionError::new(
                    "a held statement could not be decided about",
                ));
            }
            Ok(Some(verdict)) => verdict,
        };
        let Some(parked) = self.parked.take() else {
            return Ok(());
        };
        match verdict {
            Verdict::Forward => out.to_server.extend_from_slice(&parked.message),
            Verdict::End => {
                self.close();
                return Ok(());
            }
            Verdict::Withhold | Verdict::Hold => {}
        }

        // What waited behind the message, as if it arrived now. Should a
        // message among it be held, the rest goes on waiting where it is.
        let Parked {
            behind, handled, ..
        } = parked;
        let waiting = behind.get(handled..).unwrap_or_default();
        let unhandled = self.pump_some(Direction::FromClient, waiting, policy, out)?;
        if unhandled == 0 {
            return Ok(());
        }
        let Some(parked) = self.parked.as_mut() else {
            self.close();
            return Err(SessionError::new(
                "bytes of the client were left without a message that holds them",
            ));
        };
        parked.handled = behind.len().saturating_sub(unhandled);
        parked.behind = behind;
        Ok(())
    }
}
