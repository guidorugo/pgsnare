// SPDX-License-Identifier: Apache-2.0

//! HTTP/1.1, for the little of it pgsnare speaks.
//!
//! pgsnare is an HTTP client in two places, the webhook sink and
//! `pgsnare healthcheck`, and an HTTP server in two, the listeners for
//! health and for metrics. All four leave the protocol to the HTTP library:
//! nothing in pgsnare parses a request or a response by hand.
//!
//! This module holds what the four share:
//!
//! - [`Io`] lets the library read from and write to a connection of the
//!   runtime.
//! - [`Body`] is a body that is there in full when it is sent.
//! - [`exchange`] sends one request on one connection and reads the status
//!   of the answer, within limits.
//! - [`connect`] opens a TCP connection to the first address of a host that
//!   answers.
//!
//! # Limits
//!
//! Whatever answers a request is not trusted to stop sending. The head of
//! an answer is read up to [`MAX_HEAD_BYTES`], and of its body at most
//! [`MAX_DRAINED_BYTES`] are read and thrown away. No redirect is ever
//! followed: an answer is a status, and what to make of it is up to the
//! caller. How long any of it may take is the caller's limit too.

use std::convert::Infallible;
use std::future::poll_fn;
use std::io;
use std::pin::Pin;
use std::task::{Context, Poll, ready};

use hyper::body::{Body as HttpBody, Bytes, Frame, SizeHint};
use hyper::rt::ReadBufCursor;
use hyper::{Request, StatusCode};
use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};
use tokio::net::{TcpSocket, TcpStream, lookup_host};

/// The most bytes the head of an answer may have: its status line and its
/// headers.
pub(crate) const MAX_HEAD_BYTES: usize = 16 * 1024;

/// The most headers an answer may have.
pub(crate) const MAX_HEADERS: usize = 64;

/// How much of the body of an answer is read before the connection is
/// dropped. Nothing in a body is ever used.
pub(crate) const MAX_DRAINED_BYTES: usize = 64 * 1024;

/// How much is read from a connection at once.
const READ_CHUNK: usize = 4096;

/// A connection of the runtime, as the HTTP library wants one.
pub(crate) struct Io<T>(pub(crate) T);

impl<T: AsyncRead + Unpin> hyper::rt::Read for Io<T> {
    fn poll_read(
        mut self: Pin<&mut Self>,
        context: &mut Context<'_>,
        mut buffer: ReadBufCursor<'_>,
    ) -> Poll<io::Result<()>> {
        // Read into a buffer of our own and copy from there. That is one
        // copy more than strictly needed, and it is what keeps this free
        // of unsafe code.
        let mut chunk = [0u8; READ_CHUNK];
        let room = buffer.remaining().min(READ_CHUNK);
        let mut read = ReadBuf::new(chunk.get_mut(..room).unwrap_or_default());
        ready!(Pin::new(&mut self.0).poll_read(context, &mut read))?;
        buffer.put_slice(read.filled());
        Poll::Ready(Ok(()))
    }
}

impl<T: AsyncWrite + Unpin> hyper::rt::Write for Io<T> {
    fn poll_write(
        mut self: Pin<&mut Self>,
        context: &mut Context<'_>,
        bytes: &[u8],
    ) -> Poll<io::Result<usize>> {
        Pin::new(&mut self.0).poll_write(context, bytes)
    }

    fn poll_flush(mut self: Pin<&mut Self>, context: &mut Context<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut self.0).poll_flush(context)
    }

    fn poll_shutdown(mut self: Pin<&mut Self>, context: &mut Context<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut self.0).poll_shutdown(context)
    }
}

/// A body that is there in full: nothing, which is the default, or one
/// piece.
#[derive(Debug, Default)]
pub(crate) struct Body(Option<Bytes>);

impl Body {
    /// A body with these bytes.
    pub(crate) fn new(bytes: impl Into<Bytes>) -> Self {
        Self(Some(bytes.into()))
    }
}

impl HttpBody for Body {
    type Data = Bytes;
    type Error = Infallible;

    fn poll_frame(
        mut self: Pin<&mut Self>,
        _context: &mut Context<'_>,
    ) -> Poll<Option<Result<Frame<Bytes>, Infallible>>> {
        let piece = self.0.take().filter(|bytes| !bytes.is_empty());
        Poll::Ready(piece.map(|bytes| Ok(Frame::data(bytes))))
    }

    fn is_end_stream(&self) -> bool {
        self.0.as_ref().is_none_or(Bytes::is_empty)
    }

    fn size_hint(&self) -> SizeHint {
        let length = self.0.as_ref().map_or(0, Bytes::len);
        SizeHint::with_exact(u64::try_from(length).unwrap_or(u64::MAX))
    }
}

/// Sends one request over a connection and returns the status of the
/// answer. The connection is used for nothing else and is dropped
/// afterwards.
///
/// The caller bounds the time this may take.
///
/// # Errors
///
/// Returns what went wrong, as a fixed text. Nothing the other side sent
/// is part of it.
pub(crate) async fn exchange<T>(
    stream: T,
    request: Request<Body>,
) -> Result<StatusCode, &'static str>
where
    T: AsyncRead + AsyncWrite + Unpin,
{
    let mut builder = hyper::client::conn::http1::Builder::new();
    builder
        .max_buf_size(MAX_HEAD_BYTES)
        .max_headers(MAX_HEADERS);
    let (mut sender, connection) = builder
        .handshake::<_, Body>(Io(stream))
        .await
        .map_err(|_| "the connection could not be used")?;
    tokio::pin!(connection);

    let answer = async {
        let response = sender.send_request(request).await.map_err(|error| {
            if error.is_parse_too_large() {
                "the head of the answer is too large"
            } else if error.is_parse() {
                "the answer is not valid HTTP"
            } else if error.is_incomplete_message() {
                "the connection was closed before the answer was complete"
            } else {
                "the request could not be sent, or no answer came"
            }
        })?;
        let status = response.status();

        // What follows the head is of no use. A little of it is read, so
        // that an answer of ordinary size ends the exchange cleanly, and
        // then the connection is dropped whatever else may come.
        let mut body = response.into_body();
        let mut room = MAX_DRAINED_BYTES;
        while let Some(Ok(frame)) = poll_fn(|context| Pin::new(&mut body).poll_frame(context)).await
        {
            let length = frame.data_ref().map_or(0, Bytes::len);
            match room.checked_sub(length) {
                Some(left) if left > 0 => room = left,
                _ => break,
            }
        }
        Ok(status)
    };

    // The connection has to be driven for the request to make progress.
    tokio::pin!(answer);
    tokio::select! {
        biased;
        answer = &mut answer => return answer,
        _ = &mut connection => {}
    }
    // The connection has ended, as it does when the other side closes it
    // behind its answer. What it delivered before that is still to be
    // taken, and with nothing more to come this does not wait.
    answer.await
}

/// Opens a TCP connection to the first address of `host` that answers.
///
/// The caller bounds the time this may take.
///
/// # Errors
///
/// Returns what went wrong, as a fixed text.
pub(crate) async fn connect(host: &str, port: u16) -> Result<TcpStream, &'static str> {
    let addresses = lookup_host((host, port))
        .await
        .map_err(|_| "the name of the host could not be resolved")?;
    let mut last = "the name of the host has no address";
    for address in addresses {
        let attempt = async {
            let socket = if address.is_ipv4() {
                TcpSocket::new_v4()?
            } else {
                TcpSocket::new_v6()?
            };
            socket.set_nodelay(true)?;
            socket.connect(address).await
        };
        match attempt.await {
            Ok(stream) => return Ok(stream),
            Err(error) => last = io_reason(&error),
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
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    use tokio::net::TcpListener;

    use super::*;

    /// A server that reads one request and answers with these bytes.
    async fn answering(
        answer: &'static [u8],
    ) -> (std::net::SocketAddr, tokio::task::JoinHandle<Vec<u8>>) {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let address = listener.local_addr().unwrap();
        let task = tokio::spawn(async move {
            let (mut stream, _) = listener.accept().await.unwrap();
            let mut request = Vec::new();
            let mut buffer = [0u8; 1024];
            while !request.windows(4).any(|window| window == b"\r\n\r\n") {
                let count = stream.read(&mut buffer).await.unwrap();
                if count == 0 {
                    break;
                }
                request.extend_from_slice(&buffer[..count]);
            }
            let _ = stream.write_all(answer).await;
            let _ = stream.shutdown().await;
            request
        });
        (address, task)
    }

    fn get(path: &str) -> Request<Body> {
        Request::builder()
            .method("GET")
            .uri(path)
            .header("host", "localhost")
            .body(Body::default())
            .unwrap()
    }

    async fn ask(answer: &'static [u8]) -> (Result<StatusCode, &'static str>, String) {
        let (address, server) = answering(answer).await;
        let stream = connect("127.0.0.1", address.port()).await.unwrap();
        let status = exchange(stream, get("/healthz")).await;
        let request = String::from_utf8(server.await.unwrap()).unwrap();
        (status, request)
    }

    #[tokio::test]
    async fn a_request_is_sent_and_the_status_of_the_answer_comes_back() {
        let (status, request) = ask(b"HTTP/1.1 200 OK\r\ncontent-length: 3\r\n\r\nok\n").await;
        assert_eq!(status, Ok(StatusCode::OK));
        assert!(
            request.starts_with("GET /healthz HTTP/1.1\r\n"),
            "{request}"
        );
        assert!(request.contains("host: localhost\r\n"), "{request}");

        let (status, _) =
            ask(b"HTTP/1.1 503 Service Unavailable\r\ncontent-length: 0\r\n\r\n").await;
        assert_eq!(status, Ok(StatusCode::SERVICE_UNAVAILABLE));
    }

    #[tokio::test]
    async fn a_redirect_is_an_answer_like_any_other_and_is_not_followed() {
        let (status, _) = ask(
            b"HTTP/1.1 302 Found\r\nlocation: http://192.0.2.1/elsewhere\r\ncontent-length: 0\r\n\r\n",
        )
        .await;
        assert_eq!(status, Ok(StatusCode::FOUND));
    }

    #[tokio::test]
    async fn what_is_not_an_answer_is_an_error_that_repeats_nothing() {
        let (status, _) = ask(b"SSH-2.0-OpenSSH_9.9 secret-banner\r\n").await;
        assert_eq!(status, Err("the answer is not valid HTTP"));

        let (status, _) = ask(b"").await;
        assert!(status.is_err());
        let (status, _) = ask(b"HTTP/1.1 200 OK\r\ncontent-le").await;
        assert!(status.is_err());
    }

    #[tokio::test]
    async fn a_head_that_is_too_large_is_refused() {
        static HUGE: std::sync::LazyLock<Vec<u8>> = std::sync::LazyLock::new(|| {
            let mut answer = b"HTTP/1.1 200 OK\r\n".to_vec();
            answer.extend_from_slice(b"x-padding: ");
            answer.extend(std::iter::repeat_n(b'a', 4 * MAX_HEAD_BYTES));
            answer.extend_from_slice(b"\r\ncontent-length: 0\r\n\r\n");
            answer
        });
        let (status, _) = ask(&HUGE).await;
        assert_eq!(status, Err("the head of the answer is too large"));

        static MANY: std::sync::LazyLock<Vec<u8>> = std::sync::LazyLock::new(|| {
            let mut answer = b"HTTP/1.1 200 OK\r\n".to_vec();
            for number in 0..=MAX_HEADERS {
                answer.extend_from_slice(format!("x-header-{number}: 1\r\n").as_bytes());
            }
            answer.extend_from_slice(b"content-length: 0\r\n\r\n");
            answer
        });
        let (status, _) = ask(&MANY).await;
        assert!(status.is_err(), "{status:?}");
    }

    #[tokio::test]
    async fn a_body_that_never_ends_does_not_keep_the_exchange_going() {
        // A server that answers and then sends without end.
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let address = listener.local_addr().unwrap();
        let server = tokio::spawn(async move {
            let (mut stream, _) = listener.accept().await.unwrap();
            let mut buffer = [0u8; 1024];
            let _ = stream.read(&mut buffer).await;
            let _ = stream
                .write_all(b"HTTP/1.1 200 OK\r\ntransfer-encoding: chunked\r\n\r\n")
                .await;
            let chunk = [b"1000\r\n".as_slice(), &[b'x'; 4096], b"\r\n"].concat();
            let mut sent = 0usize;
            while stream.write_all(&chunk).await.is_ok() {
                sent += 4096;
            }
            sent
        });

        let stream = connect("127.0.0.1", address.port()).await.unwrap();
        let status = tokio::time::timeout(
            std::time::Duration::from_secs(10),
            exchange(stream, get("/")),
        )
        .await
        .expect("the exchange ends by itself");
        assert_eq!(status, Ok(StatusCode::OK));
        // The server could not go on for long after the client was gone.
        let sent = server.await.unwrap();
        assert!(sent < 64 * 1024 * 1024, "{sent}");
    }

    #[tokio::test]
    async fn a_body_is_sent_with_its_length() {
        let (address, server) = answering(b"HTTP/1.1 204 No Content\r\n\r\n").await;
        let stream = connect("127.0.0.1", address.port()).await.unwrap();
        let request = Request::builder()
            .method("POST")
            .uri("/hook?source=pgsnare")
            .header("host", "alerts.example.com")
            .body(Body::new(b"{\"kind\":\"token_hit\"}".to_vec()))
            .unwrap();
        assert_eq!(exchange(stream, request).await, Ok(StatusCode::NO_CONTENT));
        // The test server stops reading at the end of the head, so only
        // the head is looked at here.
        let request = String::from_utf8_lossy(&server.await.unwrap()).into_owned();
        assert!(
            request.starts_with("POST /hook?source=pgsnare HTTP/1.1\r\n"),
            "{request}"
        );
        assert!(request.contains("content-length: 20\r\n"), "{request}");
    }

    #[tokio::test]
    async fn a_host_that_does_not_answer_is_a_fixed_text() {
        // A port nothing listens on.
        let port = std::net::TcpListener::bind("127.0.0.1:0")
            .unwrap()
            .local_addr()
            .unwrap()
            .port();
        assert_eq!(
            connect("127.0.0.1", port).await.err(),
            Some("the connection was refused")
        );
        // A name that cannot exist: the top-level domain is reserved.
        assert_eq!(
            connect("nothing.invalid", 80).await.err(),
            Some("the name of the host could not be resolved")
        );
    }

    #[test]
    fn a_body_knows_its_length_and_its_end() {
        let empty = Body::default();
        assert!(empty.is_end_stream());
        assert_eq!(empty.size_hint().exact(), Some(0));
        assert!(Body::new(Vec::new()).is_end_stream());

        let body = Body::new(b"abc".to_vec());
        assert!(!body.is_end_stream());
        assert_eq!(body.size_hint().exact(), Some(3));
    }
}
