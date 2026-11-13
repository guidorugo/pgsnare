// SPDX-License-Identifier: Apache-2.0

//! Connections from pgsnare to the database.
//!
//! Two things connect: a session, when its client begins to log in, and a
//! cancel request, which travels on a connection of its own. Both go
//! through [`connect`], so both use TLS in the same way.
//!
//! # TLS
//!
//! A protocol module may say that TLS is asked for in the clear before the
//! handshake (`ProtocolModule::backend_tls_request`). The database answers
//! with one byte. Exactly that one byte is read before the handshake
//! begins. Whatever arrives after it is read by the TLS library, as part of
//! the handshake, so nothing that was sent in the clear can ever be taken
//! for something the database said inside TLS.
//!
//! A connection over a Unix socket is never encrypted: the runtime has no
//! TLS for it. A leg that must use TLS and a Unix socket therefore do not
//! go together. `Runtime::bind` refuses a listener that asks for both, and
//! `Connector::connect` refuses a second time, so that no path leads to a
//! plaintext connection where the settings ask for an encrypted one.

use std::fmt;
use std::io;
use std::path::PathBuf;
use std::sync::atomic::{AtomicBool, Ordering};

use pgsnare_core::extension::TlsRequest;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpSocket, TcpStream, UnixStream, lookup_host};

use crate::tls::{self, BackendLeg, BackendTlsUse};

use super::stream::BackendStream;

/// Where the database is.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Upstream {
    /// A TCP connection to a host and a port.
    Tcp {
        /// A host name or an IP address.
        host: String,
        /// The port.
        port: u16,
    },
    /// A Unix socket. A connection over it is never encrypted.
    Unix(PathBuf),
}

impl fmt::Display for Upstream {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Tcp { host, port } if host.contains(':') => write!(f, "[{host}]:{port}"),
            Self::Tcp { host, port } => write!(f, "{host}:{port}"),
            Self::Unix(path) => write!(f, "unix:{}", path.display()),
        }
    }
}

impl From<&crate::config::Endpoint> for Upstream {
    fn from(endpoint: &crate::config::Endpoint) -> Self {
        match endpoint {
            crate::config::Endpoint::Tcp { host, port } => Self::Tcp {
                host: host.as_str().to_owned(),
                port: *port,
            },
            crate::config::Endpoint::Unix { path } => Self::Unix(path.clone()),
        }
    }
}

/// Why no connection to the database could be opened. Every reason is a
/// fixed text, fit for a log.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) struct ConnectError(pub(crate) &'static str);

impl fmt::Display for ConnectError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.0)
    }
}

/// What is needed to open a connection to the database of one listener.
pub(crate) struct Connector {
    pub(crate) upstream: Upstream,
    pub(crate) tls: BackendLeg,
    pub(crate) tls_request: Option<TlsRequest>,
    /// The certificate pgsnare presents on the client leg, to compare the
    /// one of the database with.
    pub(crate) client_certificate: Option<Vec<u8>>,
    /// Whether a difference between the two has been logged already.
    pub(crate) mismatch_logged: AtomicBool,
    /// The name of the listener, for the log.
    pub(crate) listener: String,
}

/// A connection to the database, and whether it is encrypted.
pub(crate) struct Connected {
    pub(crate) stream: BackendStream,
    pub(crate) tls: bool,
}

/// What is said of settings that require TLS to a database reached over a
/// Unix socket.
pub(crate) const TLS_OVER_UNIX_SOCKET: &str = "the settings require TLS to the database, and a connection over a Unix socket is never \
     encrypted";

/// Whether these settings ask for what the runtime cannot give: a
/// connection that must be encrypted, over a Unix socket.
pub(crate) fn requires_tls_over_unix_socket(upstream: &Upstream, tls: &BackendLeg) -> bool {
    matches!(upstream, Upstream::Unix(_)) && tls.usage() == BackendTlsUse::Always
}

impl Connector {
    /// Opens a connection to the database, with TLS as configured.
    ///
    /// The caller bounds the time this may take.
    pub(crate) async fn connect(&self) -> Result<Connected, ConnectError> {
        // Before anything is opened: see the module documentation.
        if requires_tls_over_unix_socket(&self.upstream, &self.tls) {
            return Err(ConnectError(TLS_OVER_UNIX_SOCKET));
        }
        let (host, port) = match &self.upstream {
            Upstream::Unix(path) => {
                let stream = UnixStream::connect(path)
                    .await
                    .map_err(|error| ConnectError(io_reason(&error)))?;
                return Ok(Connected {
                    stream: BackendStream::Unix(stream),
                    tls: false,
                });
            }
            Upstream::Tcp { host, port } => (host.as_str(), *port),
        };
        let mut stream = connect_tcp(host, port).await?;

        if self.tls.usage() == BackendTlsUse::Never {
            return Ok(Connected {
                stream: BackendStream::Tcp(stream),
                tls: false,
            });
        }
        let (Some(connector), Some(server_name)) = (self.tls.connector(), self.tls.server_name())
        else {
            return Err(ConnectError("TLS is configured without its settings"));
        };

        if let Some(request) = self.tls_request {
            stream
                .write_all(request.request)
                .await
                .map_err(|error| ConnectError(io_reason(&error)))?;
            // One byte, and not one more: see the module documentation.
            let mut answer = [0u8; 1];
            stream
                .read_exact(&mut answer)
                .await
                .map_err(|error| ConnectError(io_reason(&error)))?;
            let [answer] = answer;
            if answer == request.refused {
                if self.tls.usage() == BackendTlsUse::IfOffered {
                    return Ok(Connected {
                        stream: BackendStream::Tcp(stream),
                        tls: false,
                    });
                }
                return Err(ConnectError("the database does not offer TLS"));
            }
            if answer != request.accepted {
                return Err(ConnectError(
                    "the database gave no valid answer to the request for TLS",
                ));
            }
        }

        let stream = connector
            .connect(server_name.clone(), stream)
            .await
            .map_err(|error| ConnectError(tls::describe(&error)))?;
        self.compare_certificates(stream.get_ref().1.peer_certificates());
        Ok(Connected {
            stream: BackendStream::Tls(Box::new(stream)),
            tls: true,
        })
    }

    /// Compares the certificate the database presented with the one
    /// pgsnare presents to clients, by their encoded form, and says so
    /// once when they differ.
    ///
    /// Returns whether they are the same, or `None` when there is nothing
    /// to compare.
    fn compare_certificates(
        &self,
        presented: Option<&[rustls::pki_types::CertificateDer<'static>]>,
    ) -> Option<bool> {
        let ours = self.client_certificate.as_deref()?;
        let theirs = presented?.first()?;
        let same = theirs.as_ref() == ours;
        if !same && !self.mismatch_logged.swap(true, Ordering::Relaxed) {
            tracing::warn!(
                listener = %self.listener,
                "{}",
                CERTIFICATE_MISMATCH
            );
        }
        Some(same)
    }

    /// Connects to the database once, only to learn which certificate it
    /// presents, and compares it with the one of the client leg.
    ///
    /// Returns `None` when there is nothing to compare: one of the legs has
    /// no TLS, or the database could not be reached.
    pub(crate) async fn probe_certificate(&self) -> Option<bool> {
        self.client_certificate.as_ref()?;
        if self.tls.usage() == BackendTlsUse::Never {
            return None;
        }
        match self.connect().await {
            Ok(Connected {
                stream: BackendStream::Tls(mut stream),
                ..
            }) => {
                let same = stream
                    .get_ref()
                    .1
                    .peer_certificates()
                    .and_then(<[_]>::first)
                    .zip(self.client_certificate.as_deref())
                    .map(|(theirs, ours)| theirs.as_ref() == ours);
                // The database sees a client that leaves before it sends a
                // startup message, which it expects of health checks.
                let _ = stream.shutdown().await;
                same
            }
            Ok(_) => None,
            Err(error) => {
                tracing::warn!(
                    listener = %self.listener,
                    reason = error.0,
                    "the certificate of the database could not be compared with the one of \
                     the client leg, because the database could not be reached"
                );
                None
            }
        }
    }

    /// Sends a cancel request to the database on a connection of its own
    /// and waits for the database to close it, which is how the database
    /// says that it has dealt with the request.
    ///
    /// The caller bounds the time this may take.
    pub(crate) async fn cancel(&self, request: &[u8]) -> Result<(), ConnectError> {
        let Connected { mut stream, .. } = self.connect().await?;
        stream
            .write_all(request)
            .await
            .map_err(|error| ConnectError(io_reason(&error)))?;
        stream
            .flush()
            .await
            .map_err(|error| ConnectError(io_reason(&error)))?;
        // The database sends nothing. Whatever does arrive is dropped.
        let mut sink = [0u8; 64];
        loop {
            match stream.read(&mut sink).await {
                Ok(0) | Err(_) => break,
                Ok(_) => {}
            }
        }
        Ok(())
    }
}

/// What the log says when the two legs present different certificates.
/// It names no protocol: channel binding is what ties a login to the
/// certificate the client saw, whatever the protocol calls it.
pub(crate) const CERTIFICATE_MISMATCH: &str = "the certificate of the client leg is not the one the database presents: a login that \
     uses channel binding will fail through this listener";

/// Opens a TCP connection to the first address of `host` that answers.
async fn connect_tcp(host: &str, port: u16) -> Result<TcpStream, ConnectError> {
    let addresses = lookup_host((host, port))
        .await
        .map_err(|_| ConnectError("the name of the database could not be resolved"))?;
    let mut last = ConnectError("the name of the database has no address");
    for address in addresses {
        let socket = if address.is_ipv4() {
            TcpSocket::new_v4()
        } else {
            TcpSocket::new_v6()
        };
        let attempt = async {
            let socket = socket?;
            // A connection that has gone away is noticed even when nothing
            // is being sent, and nothing waits to be sent in larger pieces.
            socket.set_keepalive(true)?;
            socket.set_nodelay(true)?;
            socket.connect(address).await
        };
        match attempt.await {
            Ok(stream) => return Ok(stream),
            Err(error) => last = ConnectError(io_reason(&error)),
        }
    }
    Err(last)
}

/// A fixed text for an I/O error.
pub(crate) fn io_reason(error: &io::Error) -> &'static str {
    match error.kind() {
        io::ErrorKind::ConnectionRefused => "the connection was refused",
        io::ErrorKind::ConnectionReset | io::ErrorKind::ConnectionAborted => {
            "the connection was reset"
        }
        io::ErrorKind::UnexpectedEof => "the connection was closed",
        io::ErrorKind::TimedOut => "the connection timed out",
        io::ErrorKind::NotFound => "the socket does not exist",
        io::ErrorKind::PermissionDenied => "permission was denied",
        io::ErrorKind::BrokenPipe => "the connection was closed by the other side",
        io::ErrorKind::HostUnreachable | io::ErrorKind::NetworkUnreachable => {
            "the host cannot be reached"
        }
        _ => "an input or output error",
    }
}

#[cfg(test)]
mod tests {
    use std::sync::atomic::AtomicU32;
    use std::time::Duration;

    use tokio::net::UnixListener;

    use super::*;
    use crate::config::Config;

    /// A directory that is removed again when the test ends.
    struct TempDir(PathBuf);

    impl TempDir {
        fn new() -> Self {
            static NEXT: AtomicU32 = AtomicU32::new(0);
            let path = std::env::temp_dir().join(format!(
                "pgsnare-backend-test-{}-{}",
                std::process::id(),
                NEXT.fetch_add(1, Ordering::Relaxed)
            ));
            std::fs::create_dir_all(&path).unwrap();
            Self(path)
        }
    }

    impl Drop for TempDir {
        fn drop(&mut self) {
            let _ = std::fs::remove_dir_all(&self.0);
        }
    }

    /// The backend leg a configuration gives for this mode. Its database is
    /// reached over TCP: a configuration that asks for TLS over a Unix
    /// socket is not accepted in the first place, so only code that puts
    /// the settings together by itself can pair such a leg with a socket.
    fn leg(mode: &str) -> BackendLeg {
        let config = Config::from_yaml(&format!(
            "listeners:\n  - name: test\n    listen: 127.0.0.1:5432\n    upstream: db.example.com:5432\n    \
             client_tls: {{ mode: disable }}\n    upstream_tls: {{ mode: {mode} }}\nevents:\n  sinks:\n    \
             - type: stdout\n"
        ))
        .unwrap();
        let listener = &config.listeners[0];
        BackendLeg::from_config(&listener.upstream_tls, &listener.upstream, None).unwrap()
    }

    fn connector(upstream: Upstream, tls: BackendLeg) -> Connector {
        Connector {
            upstream,
            tls,
            tls_request: None,
            client_certificate: None,
            mismatch_logged: AtomicBool::new(false),
            listener: "test".to_owned(),
        }
    }

    #[tokio::test]
    async fn a_unix_socket_is_not_used_where_tls_is_required() {
        let dir = TempDir::new();
        let path = dir.0.join("socket");
        let socket = UnixListener::bind(&path).unwrap();
        let upstream = || Upstream::Unix(path.clone());

        // TLS that must be used: no connection, and not even an attempt.
        let leg_that_must = leg("require");
        assert_eq!(leg_that_must.usage(), BackendTlsUse::Always);
        assert!(requires_tls_over_unix_socket(&upstream(), &leg_that_must));
        let refused = connector(upstream(), leg_that_must).connect().await;
        assert_eq!(refused.err(), Some(ConnectError(TLS_OVER_UNIX_SOCKET)));
        let waited = tokio::time::timeout(Duration::from_millis(200), socket.accept()).await;
        assert!(waited.is_err(), "nothing has connected to the socket");

        // Where the mode allows plaintext, the socket is used, in plaintext.
        for (mode, usage) in [
            ("disable", BackendTlsUse::Never),
            ("prefer", BackendTlsUse::IfOffered),
        ] {
            let leg_that_may = leg(mode);
            assert_eq!(leg_that_may.usage(), usage);
            assert!(!requires_tls_over_unix_socket(&upstream(), &leg_that_may));
            let connected = connector(upstream(), leg_that_may).connect().await;
            assert!(
                matches!(connected, Ok(Connected { tls: false, .. })),
                "{mode}"
            );
            socket.accept().await.unwrap();
        }

        // Over TCP, nothing is refused on these grounds.
        let tcp = Upstream::Tcp {
            host: "db.example.com".to_owned(),
            port: 5432,
        };
        assert!(!requires_tls_over_unix_socket(&tcp, &leg("require")));
    }
}
