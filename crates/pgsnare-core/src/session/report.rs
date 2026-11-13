// SPDX-License-Identifier: Apache-2.0

//! What the runtime tells the session logic, apart from the bytes it read.

/// Something the runtime did or learned that the session logic must know.
///
/// The session logic asks for work through [`Effect`]s and the runtime
/// reports how it went. The runtime also reports what the session logic
/// cannot see for itself, such as the proxy shutting down.
///
/// [`Effect`]: super::Effect
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
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
}
