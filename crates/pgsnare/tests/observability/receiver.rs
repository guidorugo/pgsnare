// SPDX-License-Identifier: Apache-2.0

//! A webhook receiver that is a few lines of test code, and the checks a
//! receiver makes on a request.
//!
//! The receiver reads HTTP by hand, which is fine for a test and lets it
//! misbehave in every way a test needs: answer late, never, with a
//! redirect, without end, or with something that is not HTTP at all.
//!
//! [`Verifier`] is written from the documentation of the webhook sink and
//! from nothing else. It is what shows that a receiver can tell a forged
//! and a repeated request from a real one.

use std::collections::{HashSet, VecDeque};
use std::net::SocketAddr;
use std::sync::{Arc, Mutex};
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use aws_lc_rs::hmac;
use rustls::ServerConfig;
use rustls::pki_types::pem::PemObject;
use rustls::pki_types::{CertificateDer, PrivateKeyDer};
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};
use tokio::net::TcpListener;
use tokio::task::JoinHandle;
use tokio_rustls::TlsAcceptor;

use crate::support::Identity;

/// What the receiver does with one request.
#[derive(Clone, Debug)]
pub enum Answer {
    /// Answer with this status.
    Status(u16),
    /// Answer with a redirect to this URL.
    Redirect(String),
    /// Read the request and never answer.
    Hang,
    /// Answer with status 200 and a body that never ends.
    Endless,
    /// Answer with something that is not HTTP.
    Garbage,
}

/// A request as the receiver read it.
#[derive(Clone, Debug)]
pub struct Received {
    /// When the last byte of it had arrived.
    pub at: SystemTime,
    /// The first line, such as `POST /hook HTTP/1.1`.
    pub request_line: String,
    /// The headers, with their names in lower case.
    pub headers: Vec<(String, String)>,
    pub body: Vec<u8>,
}

impl Received {
    pub fn header(&self, name: &str) -> Option<&str> {
        self.headers
            .iter()
            .find(|(header, _)| header == name)
            .map(|(_, value)| value.as_str())
    }
}

/// A receiver on a free port of this machine.
pub struct Receiver {
    pub address: SocketAddr,
    received: Arc<Mutex<Vec<Received>>>,
    task: JoinHandle<()>,
}

struct Script {
    next: Mutex<VecDeque<Answer>>,
    then: Answer,
}

impl Receiver {
    /// A receiver that speaks plain HTTP. It gives the answers of `script`
    /// in turn, and `then` for ever after.
    pub async fn plain(script: &[Answer], then: Answer) -> Self {
        Self::start(None, script, then).await
    }

    /// A receiver that speaks HTTPS and presents this certificate.
    pub async fn tls(identity: &Identity, script: &[Answer], then: Answer) -> Self {
        let chain = vec![CertificateDer::from_pem_slice(identity.cert_pem.as_bytes()).unwrap()];
        let key = PrivateKeyDer::from_pem_slice(identity.key_pem.as_bytes()).unwrap();
        let config = ServerConfig::builder_with_provider(pgsnare::tls::provider())
            .with_safe_default_protocol_versions()
            .unwrap()
            .with_no_client_auth()
            .with_single_cert(chain, key)
            .unwrap();
        Self::start(Some(TlsAcceptor::from(Arc::new(config))), script, then).await
    }

    async fn start(tls: Option<TlsAcceptor>, script: &[Answer], then: Answer) -> Self {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let address = listener.local_addr().unwrap();
        let received: Arc<Mutex<Vec<Received>>> = Arc::default();
        let script = Arc::new(Script {
            next: Mutex::new(script.iter().cloned().collect()),
            then,
        });
        let requests = Arc::clone(&received);
        let task = tokio::spawn(async move {
            loop {
                let Ok((stream, _)) = listener.accept().await else {
                    return;
                };
                let (requests, script, tls) = (requests.clone(), script.clone(), tls.clone());
                tokio::spawn(async move {
                    match tls {
                        Some(acceptor) => {
                            // A client that does not trust the certificate
                            // ends the handshake, and sends no request.
                            if let Ok(stream) = acceptor.accept(stream).await {
                                serve(stream, &requests, &script).await;
                            }
                        }
                        None => serve(stream, &requests, &script).await,
                    }
                });
            }
        });
        Self {
            address,
            received,
            task,
        }
    }

    /// Every request that arrived so far, in order.
    pub fn received(&self) -> Vec<Received> {
        self.received.lock().unwrap().clone()
    }

    pub fn count(&self) -> usize {
        self.received.lock().unwrap().len()
    }
}

impl Drop for Receiver {
    fn drop(&mut self) {
        self.task.abort();
    }
}

async fn serve(
    mut stream: impl AsyncRead + AsyncWrite + Unpin,
    requests: &Mutex<Vec<Received>>,
    script: &Script,
) {
    let Some(request) = read_request(&mut stream).await else {
        return;
    };
    requests.lock().unwrap().push(request);
    let answer = script
        .next
        .lock()
        .unwrap()
        .pop_front()
        .unwrap_or_else(|| script.then.clone());
    match answer {
        Answer::Status(code) => {
            let head = format!(
                "HTTP/1.1 {code} Answer\r\ncontent-length: 3\r\nconnection: close\r\n\r\nok\n"
            );
            let _ = stream.write_all(head.as_bytes()).await;
        }
        Answer::Redirect(location) => {
            let head = format!(
                "HTTP/1.1 302 Found\r\nlocation: {location}\r\ncontent-length: 0\r\nconnection: close\r\n\r\n"
            );
            let _ = stream.write_all(head.as_bytes()).await;
        }
        Answer::Hang => std::future::pending().await,
        Answer::Endless => {
            let _ = stream
                .write_all(b"HTTP/1.1 200 OK\r\ntransfer-encoding: chunked\r\n\r\n")
                .await;
            let chunk = [b"1000\r\n".as_slice(), &[b'x'; 4096], b"\r\n"].concat();
            while stream.write_all(&chunk).await.is_ok() {}
        }
        Answer::Garbage => {
            let _ = stream.write_all(b"\x00\x01 this is not HTTP\r\n\r\n").await;
        }
    }
    let _ = stream.shutdown().await;
}

/// Reads one request: its head, and as many bytes of body as it says.
async fn read_request(stream: &mut (impl AsyncRead + Unpin)) -> Option<Received> {
    let mut bytes = Vec::new();
    let mut buffer = [0u8; 4096];
    let head_end = loop {
        if let Some(end) = bytes.windows(4).position(|window| window == b"\r\n\r\n") {
            break end;
        }
        let count = stream.read(&mut buffer).await.ok()?;
        if count == 0 || bytes.len() > 1024 * 1024 {
            return None;
        }
        bytes.extend_from_slice(&buffer[..count]);
    };
    let head = String::from_utf8(bytes[..head_end].to_vec()).ok()?;
    let mut lines = head.split("\r\n");
    let request_line = lines.next()?.to_owned();
    let headers: Vec<(String, String)> = lines
        .filter_map(|line| line.split_once(':'))
        .map(|(name, value)| (name.to_ascii_lowercase(), value.trim().to_owned()))
        .collect();
    let length: usize = headers
        .iter()
        .find(|(name, _)| name == "content-length")
        .and_then(|(_, value)| value.parse().ok())
        .unwrap_or(0);

    let mut body = bytes[head_end + 4..].to_vec();
    while body.len() < length {
        let count = stream.read(&mut buffer).await.ok()?;
        if count == 0 {
            return None;
        }
        body.extend_from_slice(&buffer[..count]);
    }
    Some(Received {
        at: SystemTime::now(),
        request_line,
        headers,
        body,
    })
}

// ---------------------------------------------------------------------------
// What a receiver checks
// ---------------------------------------------------------------------------

/// Why a receiver refuses a request.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Refused {
    /// A header is missing, or is not what the scheme says it is.
    Malformed,
    /// The timestamp is further from the receiver's clock than it
    /// tolerates.
    TooOld,
    /// The signature is not the one of this timestamp and body under the
    /// shared key.
    Forged,
    /// The receiver has accepted this event before.
    Repeated,
}

/// A receiver that follows the documentation of the webhook sink, step by
/// step.
pub struct Verifier {
    key: hmac::Key,
    tolerance: Duration,
    accepted: HashSet<String>,
}

impl Verifier {
    pub fn new(key: &[u8], tolerance: Duration) -> Self {
        Self {
            key: hmac::Key::new(hmac::HMAC_SHA256, key),
            tolerance,
            accepted: HashSet::new(),
        }
    }

    /// Checks a request that arrived at `now`, in seconds since 1970.
    pub fn check(
        &mut self,
        timestamp: Option<&str>,
        signature: Option<&str>,
        body: &[u8],
        now: u64,
    ) -> Result<(), Refused> {
        // 1. Both headers, in the form the scheme gives them.
        let (Some(timestamp), Some(signature)) = (timestamp, signature) else {
            return Err(Refused::Malformed);
        };
        let digits = !timestamp.is_empty()
            && timestamp.len() <= 20
            && timestamp.bytes().all(|byte| byte.is_ascii_digit())
            && (timestamp == "0" || !timestamp.starts_with('0'));
        let sent: u64 = timestamp.parse().map_err(|_| Refused::Malformed)?;
        let tag = signature
            .strip_prefix("v1=")
            .filter(|hex| hex.len() == 64)
            .and_then(unhex)
            .ok_or(Refused::Malformed)?;
        if !digits {
            return Err(Refused::Malformed);
        }

        // 2. Not older, and not newer, than the receiver tolerates.
        if now.abs_diff(sent) > self.tolerance.as_secs() {
            return Err(Refused::TooOld);
        }

        // 3. The HMAC over the timestamp, a full stop and the body, compared
        //    in constant time.
        let mut signed = timestamp.as_bytes().to_vec();
        signed.push(b'.');
        signed.extend_from_slice(body);
        hmac::verify(&self.key, &signed, &tag).map_err(|_| Refused::Forged)?;

        // 4. Not an event that was accepted before. The identifier is the
        //    one in the body, which the signature covers.
        let event: serde_json::Value =
            serde_json::from_slice(body).map_err(|_| Refused::Malformed)?;
        let id = event["event_id"].as_str().ok_or(Refused::Malformed)?;
        if !self.accepted.insert(id.to_owned()) {
            return Err(Refused::Repeated);
        }
        Ok(())
    }

    /// Checks a request the test receiver read, at the time it arrived.
    pub fn check_received(&mut self, request: &Received) -> Result<(), Refused> {
        self.check(
            request.header("x-pgsnare-timestamp"),
            request.header("x-pgsnare-signature"),
            &request.body,
            unix_seconds(request.at),
        )
    }
}

pub fn unix_seconds(time: SystemTime) -> u64 {
    time.duration_since(UNIX_EPOCH).unwrap().as_secs()
}

/// Lowercase hexadecimal digits as bytes.
fn unhex(text: &str) -> Option<Vec<u8>> {
    if !text
        .bytes()
        .all(|byte| matches!(byte, b'0'..=b'9' | b'a'..=b'f'))
    {
        return None;
    }
    (0..text.len())
        .step_by(2)
        .map(|at| u8::from_str_radix(text.get(at..at + 2)?, 16).ok())
        .collect()
}
