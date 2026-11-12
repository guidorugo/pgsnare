// SPDX-License-Identifier: Apache-2.0

//! What the tests of the runtime share: a proxy on a free port, a database
//! made of a few lines, a client that speaks just enough of the protocol,
//! and certificates that exist only while a test runs.

#![allow(dead_code)]

use std::future::Future;
use std::io;
use std::net::SocketAddr;
use std::path::{Path, PathBuf};
use std::pin::Pin;
use std::sync::atomic::{AtomicU32, Ordering};
use std::sync::{Arc, Mutex};
use std::time::Duration;

use pgsnare::builder::{Proxy, ProxyBuilder};
use pgsnare::config::Config;
use pgsnare::runtime::{ListenerSettings, Runtime, Settings, Status, Upstream};
use pgsnare::tls::{BackendLeg, ClientLeg};
use pgsnare_core::event::Event;
use pgsnare_core::extension::{EventSink, ProtocolModule, Relay, SinkFuture};
use pgsnare_core::policy::{FixedPolicy, Inspection, OnError, PolicySnapshot};
use pgsnare_core::session::postgres::Postgres;
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};
use tokio::sync::oneshot;
use tokio::task::JoinHandle;

/// How long a test waits for something that must happen.
pub const PATIENCE: Duration = Duration::from_secs(10);

/// How long a test waits to see that something does not happen.
pub const A_WHILE: Duration = Duration::from_millis(300);

// ---------------------------------------------------------------------------
// Messages
// ---------------------------------------------------------------------------

pub const SSL_REQUEST: [u8; 8] = [0, 0, 0, 8, 0x04, 0xd2, 0x16, 0x2f];
pub const GSSENC_REQUEST: [u8; 8] = [0, 0, 0, 8, 0x04, 0xd2, 0x16, 0x30];

/// A message with a type byte, as it goes on the wire.
pub fn frame(tag: u8, body: &[u8]) -> Vec<u8> {
    let mut bytes = vec![tag];
    bytes.extend_from_slice(&u32::try_from(body.len() + 4).unwrap().to_be_bytes());
    bytes.extend_from_slice(body);
    bytes
}

/// A startup message for protocol 3.0 with a user and a database.
pub fn startup_message() -> Vec<u8> {
    let mut body = 196_608u32.to_be_bytes().to_vec();
    body.extend_from_slice(b"user\0app\0database\0shop\0\0");
    let mut bytes = u32::try_from(body.len() + 4)
        .unwrap()
        .to_be_bytes()
        .to_vec();
    bytes.extend_from_slice(&body);
    bytes
}

pub fn query(sql: &str) -> Vec<u8> {
    let mut body = sql.as_bytes().to_vec();
    body.push(0);
    frame(b'Q', &body)
}

pub fn cancel_request(process_id: i32, key: &[u8]) -> Vec<u8> {
    let mut bytes = u32::try_from(12 + key.len())
        .unwrap()
        .to_be_bytes()
        .to_vec();
    bytes.extend_from_slice(&80_877_102u32.to_be_bytes());
    bytes.extend_from_slice(&process_id.to_be_bytes());
    bytes.extend_from_slice(key);
    bytes
}

/// What the test database sends a client it has let in.
pub fn welcome() -> Vec<u8> {
    let mut bytes = frame(b'R', &0u32.to_be_bytes());
    bytes.extend_from_slice(&frame(b'S', b"server_version\x0018.6\0"));
    let mut key = 4242i32.to_be_bytes().to_vec();
    key.extend_from_slice(&[1, 2, 3, 4]);
    bytes.extend_from_slice(&frame(b'K', &key));
    bytes.extend_from_slice(&frame(b'Z', b"I"));
    bytes
}

/// The answer of the test database to a query: the query text as the only
/// column of one row.
pub fn answer(sql: &[u8]) -> Vec<u8> {
    let mut row = vec![0, 1];
    row.extend_from_slice(&u32::try_from(sql.len()).unwrap().to_be_bytes());
    row.extend_from_slice(sql);
    let mut bytes = frame(b'D', &row);
    bytes.extend_from_slice(&frame(b'C', b"SELECT 1\0"));
    bytes.extend_from_slice(&frame(b'Z', b"I"));
    bytes
}

/// Reads one startup-phase packet: a length and that many bytes.
pub async fn read_packet(stream: &mut (impl AsyncRead + Unpin)) -> io::Result<Vec<u8>> {
    let mut length = [0u8; 4];
    stream.read_exact(&mut length).await?;
    let total = usize::try_from(u32::from_be_bytes(length)).unwrap();
    let mut packet = length.to_vec();
    packet.resize(total.max(4), 0);
    stream.read_exact(&mut packet[4..]).await?;
    Ok(packet)
}

/// Reads one message with a type byte.
pub async fn read_frame(stream: &mut (impl AsyncRead + Unpin)) -> io::Result<Vec<u8>> {
    let mut header = [0u8; 5];
    stream.read_exact(&mut header).await?;
    let length = usize::try_from(u32::from_be_bytes(header[1..].try_into().unwrap())).unwrap();
    let mut frame = header.to_vec();
    frame.resize(1 + length.max(4), 0);
    stream.read_exact(&mut frame[5..]).await?;
    Ok(frame)
}

/// Reads messages up to and including `ReadyForQuery`, and returns them
/// all, joined.
pub async fn read_until_ready(stream: &mut (impl AsyncRead + Unpin)) -> io::Result<Vec<u8>> {
    let mut all = Vec::new();
    loop {
        let frame = read_frame(stream).await?;
        let done = frame[0] == b'Z';
        all.extend_from_slice(&frame);
        if done {
            return Ok(all);
        }
    }
}

/// Reads until the other side closes, and returns what came.
pub async fn read_to_end(stream: &mut (impl AsyncRead + Unpin)) -> Vec<u8> {
    let mut all = Vec::new();
    let _ = tokio::time::timeout(PATIENCE, stream.read_to_end(&mut all))
        .await
        .expect("the connection is closed in time");
    all
}

/// Waits for something that must happen within [`PATIENCE`].
pub async fn soon<T>(work: impl Future<Output = T>) -> T {
    tokio::time::timeout(PATIENCE, work)
        .await
        .expect("this happens in time")
}

/// Waits until a condition holds, checking it every few milliseconds.
pub async fn until(mut condition: impl FnMut() -> bool) {
    soon(async {
        while !condition() {
            tokio::time::sleep(Duration::from_millis(5)).await;
        }
    })
    .await;
}

/// The severity, the code and the message of an `ErrorResponse`.
pub fn error_fields(frame: &[u8]) -> Vec<(u8, String)> {
    assert_eq!(frame[0], b'E', "an ErrorResponse");
    frame[5..]
        .split(|byte| *byte == 0)
        .filter(|field| !field.is_empty())
        .map(|field| (field[0], String::from_utf8_lossy(&field[1..]).into_owned()))
        .collect()
}

// ---------------------------------------------------------------------------
// A database
// ---------------------------------------------------------------------------

/// One connection to the test database, as the code of a test sees it.
pub type Served = Pin<Box<dyn Future<Output = ()> + Send>>;

/// A database made of whatever a test needs it to do with each connection.
pub struct Database {
    pub address: SocketAddr,
    /// How many connections it has accepted.
    pub connections: Arc<AtomicU32>,
    task: JoinHandle<()>,
}

impl Database {
    /// Serves every connection with `serve`.
    pub async fn new<F>(serve: F) -> Self
    where
        F: Fn(TcpStream) -> Served + Send + Sync + 'static,
    {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let address = listener.local_addr().unwrap();
        let connections = Arc::new(AtomicU32::new(0));
        let counter = Arc::clone(&connections);
        let task = tokio::spawn(async move {
            loop {
                let Ok((stream, _)) = listener.accept().await else {
                    return;
                };
                counter.fetch_add(1, Ordering::SeqCst);
                tokio::spawn(serve(stream));
            }
        });
        Self {
            address,
            connections,
            task,
        }
    }

    /// A database that lets every client in and answers each query with
    /// the text of the query.
    pub async fn echo() -> Self {
        Self::new(|mut stream| {
            Box::pin(async move {
                let _ = serve_session(&mut stream).await;
            })
        })
        .await
    }

    pub fn upstream(&self) -> Upstream {
        Upstream::Tcp {
            host: self.address.ip().to_string(),
            port: self.address.port(),
        }
    }

    pub fn connection_count(&self) -> u32 {
        self.connections.load(Ordering::SeqCst)
    }
}

impl Drop for Database {
    fn drop(&mut self) {
        self.task.abort();
    }
}

/// Lets a client in and answers its queries until it leaves.
pub async fn serve_session(stream: &mut (impl AsyncRead + AsyncWrite + Unpin)) -> io::Result<()> {
    read_packet(stream).await?;
    stream.write_all(&welcome()).await?;
    stream.flush().await?;
    serve_queries(stream).await
}

/// Answers each query with the text of the query, until the client leaves.
pub async fn serve_queries(stream: &mut (impl AsyncRead + AsyncWrite + Unpin)) -> io::Result<()> {
    loop {
        let frame = read_frame(stream).await?;
        match frame[0] {
            b'X' => return Ok(()),
            b'Q' => {
                let sql = &frame[5..frame.len() - 1];
                stream.write_all(&answer(sql)).await?;
                stream.flush().await?;
            }
            _ => {}
        }
    }
}

// ---------------------------------------------------------------------------
// A proxy
// ---------------------------------------------------------------------------

/// Keeps the events it is given.
#[derive(Default)]
pub struct Memory {
    pub events: Mutex<Vec<Event>>,
}

impl EventSink for Memory {
    fn name(&self) -> &str {
        "memory"
    }

    fn deliver<'a>(&'a self, event: &'a Event) -> SinkFuture<'a> {
        Box::pin(async move {
            self.events.lock().unwrap().push(event.clone());
            Ok(())
        })
    }
}

/// A proxy that runs for as long as a test holds it.
pub struct Running {
    pub address: SocketAddr,
    pub status: Arc<Status>,
    pub events: Arc<Memory>,
    stop: Option<oneshot::Sender<()>>,
    task: Option<JoinHandle<()>>,
}

pub fn policy(on_error: OnError, max_buffered_frame: usize) -> PolicySnapshot {
    PolicySnapshot::builder()
        .inspection(Inspection::new(on_error, max_buffered_frame))
        .build()
        .unwrap()
}

pub struct ProxyOptions {
    pub module: Arc<dyn ProtocolModule>,
    pub policy: PolicySnapshot,
    pub grace_period: Duration,
}

impl Default for ProxyOptions {
    fn default() -> Self {
        Self {
            module: Arc::new(Postgres::new()),
            policy: policy(OnError::FailClosed, 1024 * 1024),
            grace_period: Duration::from_secs(5),
        }
    }
}

pub fn proxy_of(module: Arc<dyn ProtocolModule>, events: &Arc<Memory>) -> Proxy {
    ProxyBuilder::new()
        .protocol_module(module)
        .login_strategy(Arc::new(Relay))
        .event_sink(Arc::clone(events) as Arc<dyn EventSink>)
        .build()
        .unwrap()
}

impl Running {
    /// Starts a proxy with one listener on a free port of this machine.
    pub async fn start(listener: ListenerSettings) -> Self {
        Self::start_with(listener, ProxyOptions::default()).await
    }

    pub async fn start_with(listener: ListenerSettings, options: ProxyOptions) -> Self {
        let events = Arc::new(Memory::default());
        let proxy = proxy_of(options.module, &events);
        let runtime = Runtime::new(
            proxy,
            Arc::new(FixedPolicy::new(options.policy)),
            Settings::new(vec![listener]).with_grace_period(options.grace_period),
        );
        let bound = runtime.bind().unwrap();
        let address = bound.local_addrs()[0];
        let status = bound.status();
        let (stop, stopped) = oneshot::channel::<()>();
        let task = tokio::spawn(bound.serve(async move {
            let _ = stopped.await;
        }));
        let running = Self {
            address,
            status: Arc::clone(&status),
            events,
            stop: Some(stop),
            task: Some(task),
        };
        until(|| status.is_ready()).await;
        running
    }

    /// A listener for this machine that relays to `upstream`.
    pub fn listener(upstream: Upstream) -> ListenerSettings {
        ListenerSettings::new("test", "127.0.0.1:0".parse().unwrap(), upstream)
    }

    pub async fn connect(&self) -> TcpStream {
        TcpStream::connect(self.address).await.unwrap()
    }

    /// Connects and logs in, and returns the connection with everything
    /// the database sent on the way.
    pub async fn log_in(&self) -> (TcpStream, Vec<u8>) {
        let mut client = self.connect().await;
        client.write_all(&startup_message()).await.unwrap();
        let greeting = soon(read_until_ready(&mut client)).await.unwrap();
        (client, greeting)
    }

    /// Asks the proxy to stop, as a signal does. Returns at once.
    pub fn stop(&mut self) {
        if let Some(stop) = self.stop.take() {
            let _ = stop.send(());
        }
    }

    /// Waits until the proxy has stopped.
    pub async fn stopped(&mut self) {
        if let Some(task) = self.task.take() {
            soon(task).await.unwrap();
        }
    }
}

impl Drop for Running {
    fn drop(&mut self) {
        if let Some(task) = self.task.take() {
            task.abort();
        }
    }
}

// ---------------------------------------------------------------------------
// Certificates
// ---------------------------------------------------------------------------

/// A directory that is removed again when the test ends.
pub struct TempDir(pub PathBuf);

impl TempDir {
    pub fn new() -> Self {
        static NEXT: AtomicU32 = AtomicU32::new(0);
        let path = std::env::temp_dir().join(format!(
            "pgsnare-runtime-test-{}-{}",
            std::process::id(),
            NEXT.fetch_add(1, Ordering::Relaxed)
        ));
        std::fs::create_dir_all(&path).unwrap();
        Self(path)
    }

    /// Writes a file that only its owner can read.
    pub fn write(&self, name: &str, content: &str) -> PathBuf {
        use std::os::unix::fs::PermissionsExt;

        let path = self.0.join(name);
        std::fs::write(&path, content).unwrap();
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o600)).unwrap();
        path
    }
}

impl Drop for TempDir {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.0);
    }
}

/// A certificate authority that exists for one test.
pub struct Authority {
    issuer: rcgen::CertifiedIssuer<'static, rcgen::KeyPair>,
}

/// A certificate and its key, in PEM and as files.
pub struct Identity {
    pub cert_pem: String,
    pub key_pem: String,
    pub cert_file: PathBuf,
    pub key_file: PathBuf,
}

impl Authority {
    pub fn new(name: &str) -> Self {
        let mut params = rcgen::CertificateParams::new(Vec::<String>::new()).unwrap();
        params.is_ca = rcgen::IsCa::Ca(rcgen::BasicConstraints::Unconstrained);
        params.key_usages = vec![
            rcgen::KeyUsagePurpose::KeyCertSign,
            rcgen::KeyUsagePurpose::CrlSign,
        ];
        params
            .distinguished_name
            .push(rcgen::DnType::CommonName, name);
        let key = rcgen::KeyPair::generate().unwrap();
        Self {
            issuer: rcgen::CertifiedIssuer::self_signed(params, key).unwrap(),
        }
    }

    pub fn pem(&self) -> String {
        self.issuer.pem()
    }

    /// Writes the certificate of the authority to a file.
    pub fn file(&self, dir: &TempDir, name: &str) -> PathBuf {
        dir.write(name, &self.pem())
    }

    /// A certificate for a server with these names, and its key, written
    /// to `dir`.
    pub fn issue(&self, dir: &TempDir, file: &str, names: &[&str]) -> Identity {
        let names: Vec<String> = names.iter().map(|name| (*name).to_owned()).collect();
        let mut params = rcgen::CertificateParams::new(names).unwrap();
        params.extended_key_usages = vec![rcgen::ExtendedKeyUsagePurpose::ServerAuth];
        params
            .distinguished_name
            .push(rcgen::DnType::CommonName, file);
        let key = rcgen::KeyPair::generate().unwrap();
        let certificate = params.signed_by(&key, &self.issuer).unwrap();
        let (cert_pem, key_pem) = (certificate.pem(), key.serialize_pem());
        Identity {
            cert_file: dir.write(&format!("{file}.crt"), &cert_pem),
            key_file: dir.write(&format!("{file}.key"), &key_pem),
            cert_pem,
            key_pem,
        }
    }
}

/// The TLS settings of a listener, read from the configuration text a
/// test gives for its two legs.
pub fn tls_legs(
    client_tls: &str,
    upstream: &Upstream,
    upstream_tls: &str,
) -> (ClientLeg, BackendLeg) {
    let config = Config::from_yaml(&format!(
        "listeners:\n  - name: test\n    listen: 127.0.0.1:5432\n    upstream: {upstream}\n    \
         client_tls: {client_tls}\n    upstream_tls: {upstream_tls}\nevents:\n  sinks:\n    - type: stdout\n"
    ))
    .unwrap();
    let listener = &config.listeners[0];
    let alpn = Postgres::new().alpn_protocol();
    (
        ClientLeg::from_config(&listener.client_tls, alpn).unwrap(),
        BackendLeg::from_config(&listener.upstream_tls, &listener.upstream, alpn).unwrap(),
    )
}

/// A path as it is written in a configuration.
pub fn yaml_path(path: &Path) -> String {
    format!("\"{}\"", path.display())
}
