// SPDX-License-Identifier: Apache-2.0

//! What the runtime tells the session logic, apart from the bytes it read.

#[cfg(feature = "rules")]
use std::sync::Arc;

#[cfg(feature = "rules")]
use crate::rules::{Analysis, ParseFailure};

/// Something the runtime did or learned that the session logic must know.
///
/// The session logic asks for work through [`Effect`]s and the runtime
/// reports how it went. The runtime also reports what the session logic
/// cannot see for itself, such as the proxy shutting down.
///
/// [`Effect`]: super::Effect
#[derive(Clone, Debug, PartialEq, Eq)]
#[non_exhaustive]
pub enum Report {
    /// The handshake asked for with [`Effect::AcceptTls`] has succeeded.
    /// The client leg is encrypted from here on.
    ///
    /// [`Effect::AcceptTls`]: super::Effect::AcceptTls
    ClientTlsEstablished,
    /// The connection asked for with [`Effect::ConnectBackend`] is open.
    ///
    /// [`Effect::ConnectBackend`]: super::Effect::ConnectBackend
    BackendConnected {
        /// Whether the backend leg is encrypted.
        tls: bool,
    },
    /// The connection asked for with [`Effect::ConnectBackend`] could not
    /// be opened.
    ///
    /// [`Effect::ConnectBackend`]: super::Effect::ConnectBackend
    BackendUnavailable,
    /// The proxy is stopping and this session has run out of time. The
    /// runtime closes both connections once the bytes queued in answer to
    /// this report have been sent.
    ShuttingDown,
    /// The session has been tarpitted for as long as
    /// [`Effect::Tarpit`] allowed. It is killed.
    ///
    /// [`Effect::Tarpit`]: super::Effect::Tarpit
    TarpitOver,
    /// The answer to [`Effect::Analyse`]: the analysis of the statement,
    /// or the reason there is none. An answer the session does not wait
    /// for, such as one that comes after another answer under the same
    /// `id`, changes nothing.
    ///
    /// [`Effect::Analyse`]: super::Effect::Analyse
    #[cfg(feature = "rules")]
    Analysed {
        /// The `id` of the request.
        id: u64,
        /// The analysis, shared with whoever else holds it, or why there
        /// is none.
        outcome: Result<Arc<Analysis>, ParseFailure>,
    },
}
