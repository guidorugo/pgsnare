// SPDX-License-Identifier: Apache-2.0

//! The connections of a session, whatever they are made of.
//!
//! The client leg is a TCP connection, with or without TLS. The backend leg
//! is a TCP connection, with or without TLS, or a Unix socket. The session
//! driver reads and writes them through these two types and does not care
//! which it has.

use std::io;
use std::pin::Pin;
use std::task::{Context, Poll};

use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};
use tokio::net::{TcpStream, UnixStream};
use tokio_rustls::{client, server};

/// A connection that first yields bytes that were read from it earlier.
///
/// A client may open its connection with a TLS handshake. The session logic
/// has read the beginning of that handshake by the time it knows what it
/// is, and hands those bytes back. They are replayed here, ahead of
/// whatever the socket delivers next, so the TLS library sees the handshake
/// from its first byte.
#[derive(Debug)]
pub(crate) struct Rewind<S> {
    replay: Vec<u8>,
    offset: usize,
    inner: S,
}

impl<S> Rewind<S> {
    pub(crate) const fn new(inner: S, replay: Vec<u8>) -> Self {
        Self {
            replay,
            offset: 0,
            inner,
        }
    }
}

impl<S: AsyncRead + Unpin> AsyncRead for Rewind<S> {
    fn poll_read(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        let this = self.get_mut();
        let pending = this.replay.get(this.offset..).unwrap_or_default();
        if pending.is_empty() {
            return Pin::new(&mut this.inner).poll_read(cx, buf);
        }
        let (now, _) = pending.split_at(pending.len().min(buf.remaining()));
        buf.put_slice(now);
        this.offset = this.offset.saturating_add(now.len());
        if this.offset >= this.replay.len() {
            // Replayed in full: the bytes are not kept any longer.
            this.replay = Vec::new();
            this.offset = 0;
        }
        Poll::Ready(Ok(()))
    }
}

impl<S: AsyncWrite + Unpin> AsyncWrite for Rewind<S> {
    fn poll_write(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<io::Result<usize>> {
        Pin::new(&mut self.get_mut().inner).poll_write(cx, buf)
    }

    fn poll_flush(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut self.get_mut().inner).poll_flush(cx)
    }

    fn poll_shutdown(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut self.get_mut().inner).poll_shutdown(cx)
    }
}

/// The connection between an application and pgsnare.
#[derive(Debug)]
pub(crate) enum ClientStream {
    Plain(TcpStream),
    Tls(Box<server::TlsStream<Rewind<TcpStream>>>),
}

/// The connection between pgsnare and the database.
#[derive(Debug)]
pub(crate) enum BackendStream {
    Tcp(TcpStream),
    Unix(UnixStream),
    Tls(Box<client::TlsStream<TcpStream>>),
}

impl BackendStream {
    /// Whether the connection is encrypted. An encrypted connection keeps
    /// what is written to it until it is flushed.
    pub(crate) const fn is_tls(&self) -> bool {
        matches!(self, Self::Tls(_))
    }
}

/// Passes the four operations of a stream on to whichever connection an
/// enum holds.
macro_rules! delegate_io {
    ($name:ident { $($variant:ident),+ }) => {
        impl AsyncRead for $name {
            fn poll_read(
                self: Pin<&mut Self>,
                cx: &mut Context<'_>,
                buf: &mut ReadBuf<'_>,
            ) -> Poll<io::Result<()>> {
                match self.get_mut() {
                    $(Self::$variant(stream) => Pin::new(stream).poll_read(cx, buf),)+
                }
            }
        }

        impl AsyncWrite for $name {
            fn poll_write(
                self: Pin<&mut Self>,
                cx: &mut Context<'_>,
                buf: &[u8],
            ) -> Poll<io::Result<usize>> {
                match self.get_mut() {
                    $(Self::$variant(stream) => Pin::new(stream).poll_write(cx, buf),)+
                }
            }

            fn poll_flush(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
                match self.get_mut() {
                    $(Self::$variant(stream) => Pin::new(stream).poll_flush(cx),)+
                }
            }

            fn poll_shutdown(
                self: Pin<&mut Self>,
                cx: &mut Context<'_>,
            ) -> Poll<io::Result<()>> {
                match self.get_mut() {
                    $(Self::$variant(stream) => Pin::new(stream).poll_shutdown(cx),)+
                }
            }
        }
    };
}

delegate_io!(ClientStream { Plain, Tls });
delegate_io!(BackendStream { Tcp, Unix, Tls });

#[cfg(test)]
mod tests {
    use tokio::io::{AsyncReadExt, AsyncWriteExt};

    use super::*;

    #[tokio::test]
    async fn replayed_bytes_come_first_and_are_then_let_go() {
        let (near, mut far) = tokio::io::duplex(64);
        let mut rewind = Rewind::new(near, b"hello ".to_vec());
        far.write_all(b"world").await.unwrap();
        drop(far);

        // A buffer smaller than what is replayed.
        let mut small = [0u8; 4];
        assert_eq!(rewind.read(&mut small).await.unwrap(), 4);
        assert_eq!(&small, b"hell");
        assert_eq!(rewind.replay.len(), 6);

        let mut rest = Vec::new();
        rewind.read_to_end(&mut rest).await.unwrap();
        assert_eq!(rest, b"o world");
        assert!(rewind.replay.is_empty());
        assert_eq!(rewind.replay.capacity(), 0);
    }

    #[tokio::test]
    async fn nothing_to_replay_reads_straight_through_and_writes_pass() {
        let (near, mut far) = tokio::io::duplex(64);
        let mut rewind = Rewind::new(near, Vec::new());
        rewind.write_all(b"ping").await.unwrap();
        rewind.flush().await.unwrap();
        let mut got = [0u8; 4];
        far.read_exact(&mut got).await.unwrap();
        assert_eq!(&got, b"ping");

        far.write_all(b"pong").await.unwrap();
        rewind.read_exact(&mut got).await.unwrap();
        assert_eq!(&got, b"pong");
        rewind.shutdown().await.unwrap();
        assert_eq!(far.read(&mut got).await.unwrap(), 0);
    }
}
