// SPDX-License-Identifier: Apache-2.0

//! What the tests of this program share: a proxy on a free port of this
//! machine, a protocol that raises the events a test asks for, and sinks
//! and receivers that keep what reaches them.

use std::future::Future;
use std::net::SocketAddr;
use std::sync::{Arc, Mutex};
use std::time::Duration;

use pgsnare::builder::ProxyBuilder;
use pgsnare::runtime::{ListenerSettings, Runtime, Settings, Status, Stopped, Upstream};
use pgsnare::sinks::SinkOptions;
use pgsnare_core::event::{Event, EventBody, EventKind};
use pgsnare_core::extension::{
    EventSink, LoginStrategy, ProtocolModule, ProtocolSession, Relay, SessionError, SinkFuture,
};
use pgsnare_core::policy::{ActionSet, FixedPolicy, PolicySnapshot, TokenId};
use pgsnare_core::session::{Direction, Effect, Output, Report, SessionOrigin};
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;
use tokio::sync::oneshot;
use tokio::task::JoinHandle;

/// How long a test waits for something that must happen.
pub const PATIENCE: Duration = Duration::from_secs(20);

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

/// Reads until the other side closes, and returns what came.
pub async fn read_to_end(stream: &mut (impl AsyncRead + Unpin)) -> Vec<u8> {
    let mut all = Vec::new();
    let _ = soon(stream.read_to_end(&mut all)).await;
    all
}

/// Sends something and expects an answer.
pub async fn exchange(client: &mut TcpStream, send: &[u8], expect: &[u8]) {
    client.write_all(send).await.unwrap();
    let mut reply = vec![0u8; expect.len()];
    soon(client.read_exact(&mut reply)).await.unwrap();
    assert_eq!(reply, expect);
}

// ---------------------------------------------------------------------------
// A protocol that raises events on request
// ---------------------------------------------------------------------------

/// A protocol without a database. What a client sends comes back to it,
/// except for the commands that make the session raise an event:
///
/// | The client sends | The session |
/// |---|---|
/// | `user NAME` | Takes NAME for the database user of its later events |
/// | `app NAME` | Takes NAME for the application name of its later events |
/// | `hit TOKEN` | Raises a `token_hit` for the token with the id TOKEN |
/// | `bypass` | Raises an `inspection_bypassed` |
///
/// Each command is answered with `ok`. A session that is told to end says
/// `closing time`.
pub struct Spoken;

struct SpokenSession {
    origin: SessionOrigin,
    db_user: Option<String>,
    application_name: Option<String>,
}

impl ProtocolModule for Spoken {
    fn name(&self) -> &'static str {
        "spoken"
    }

    fn start_session(
        &self,
        origin: SessionOrigin,
        _login: Arc<dyn LoginStrategy>,
    ) -> Box<dyn ProtocolSession> {
        Box::new(SpokenSession {
            origin,
            db_user: None,
            application_name: None,
        })
    }
}

impl SpokenSession {
    fn raise(&self, kind: EventKind, token: Option<&str>, out: &mut Output) {
        let mut body = EventBody::new(kind, &self.origin);
        body.token_id = token.map(|id| TokenId::new(id).expect("a valid token id"));
        if token.is_some() {
            body.action_taken = ActionSet::ALERT;
        }
        body.direction = Some(Direction::FromServer);
        body.db_user.clone_from(&self.db_user);
        body.application_name.clone_from(&self.application_name);
        out.effects.push(Effect::Emit(Box::new(body)));
    }
}

impl ProtocolSession for SpokenSession {
    fn on_bytes(
        &mut self,
        _from: Direction,
        input: &[u8],
        _policy: &PolicySnapshot,
        out: &mut Output,
    ) -> Result<(), SessionError> {
        let text = String::from_utf8_lossy(input);
        let (command, argument) = text.split_once(' ').unwrap_or((&text, ""));
        match command {
            "user" => self.db_user = Some(argument.to_owned()),
            "app" => self.application_name = Some(argument.to_owned()),
            "hit" => self.raise(EventKind::TokenHit, Some(argument), out),
            "bypass" => self.raise(EventKind::InspectionBypassed, None, out),
            _ => {
                out.to_client.extend_from_slice(input);
                return Ok(());
            }
        }
        out.to_client.extend_from_slice(b"ok");
        Ok(())
    }

    fn on_report(
        &mut self,
        report: Report,
        _policy: &PolicySnapshot,
        out: &mut Output,
    ) -> Result<(), SessionError> {
        if report == Report::ShuttingDown {
            out.to_client.extend_from_slice(b"closing time");
        }
        Ok(())
    }
}

/// Sends a command of the [`Spoken`] protocol and waits for its `ok`.
pub async fn say(client: &mut TcpStream, command: &str) {
    exchange(client, command.as_bytes(), b"ok").await;
}

// ---------------------------------------------------------------------------
// A sink that keeps what it is given
// ---------------------------------------------------------------------------

/// Keeps the events it is given.
#[derive(Default)]
pub struct Memory {
    pub events: Mutex<Vec<Event>>,
}

impl Memory {
    pub fn count(&self) -> usize {
        self.events.lock().unwrap().len()
    }

    pub fn events(&self) -> Vec<Event> {
        self.events.lock().unwrap().clone()
    }
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

// ---------------------------------------------------------------------------
// A proxy
// ---------------------------------------------------------------------------

/// A proxy that speaks [`Spoken`] and runs for as long as a test holds it.
pub struct Running {
    pub address: SocketAddr,
    pub status: Arc<Status>,
    stop: Option<oneshot::Sender<()>>,
    task: Option<JoinHandle<Stopped>>,
}

/// What a test may want to be different about its proxy.
pub struct Options {
    pub sinks: Vec<(Arc<dyn EventSink>, SinkOptions)>,
    pub max_connections: usize,
    /// Changes the settings of the runtime before it is started.
    pub settings: Box<dyn FnOnce(Settings) -> Settings>,
}

impl Default for Options {
    fn default() -> Self {
        Self {
            sinks: vec![(Arc::new(Memory::default()), SinkOptions::default())],
            max_connections: 100,
            settings: Box::new(|settings| settings),
        }
    }
}

impl Options {
    /// A proxy with these sinks and the defaults for everything else.
    pub fn with_sinks(sinks: Vec<(Arc<dyn EventSink>, SinkOptions)>) -> Self {
        Self {
            sinks,
            ..Self::default()
        }
    }
}

impl Running {
    pub async fn start(options: Options) -> Self {
        let mut builder = ProxyBuilder::new()
            .protocol_module(Arc::new(Spoken))
            .login_strategy(Arc::new(Relay));
        for (sink, sink_options) in options.sinks {
            builder = builder.event_sink_with(sink, sink_options);
        }
        let proxy = builder.build().unwrap();

        // The protocol of these tests never asks for a database.
        let nowhere = Upstream::Tcp {
            host: "127.0.0.1".to_owned(),
            port: 1,
        };
        let listener = ListenerSettings::new("test", "127.0.0.1:0".parse().unwrap(), nowhere)
            .with_max_connections(options.max_connections);
        let settings = (options.settings)(
            Settings::new(vec![listener]).with_grace_period(Duration::from_millis(300)),
        );
        let policy = PolicySnapshot::builder().build().unwrap();
        let bound = Runtime::new(proxy, Arc::new(FixedPolicy::new(policy)), settings)
            .bind()
            .unwrap();
        let address = bound.local_addrs()[0];
        let status = bound.status();
        let (stop, stopped) = oneshot::channel::<()>();
        let task = tokio::spawn(bound.run(async move {
            let _ = stopped.await;
        }));
        let running = Self {
            address,
            status: Arc::clone(&status),
            stop: Some(stop),
            task: Some(task),
        };
        until(|| status.is_ready()).await;
        running
    }

    pub async fn connect(&self) -> TcpStream {
        TcpStream::connect(self.address).await.unwrap()
    }

    /// Asks the proxy to stop, as a signal does. Returns at once.
    pub fn stop(&mut self) {
        if let Some(stop) = self.stop.take() {
            let _ = stop.send(());
        }
    }

    /// Waits until the proxy has stopped, and says why it did.
    pub async fn stopped(&mut self) -> Stopped {
        let task = self.task.take().expect("the proxy is waited for once");
        soon(task).await.unwrap()
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

/// A certificate authority that exists for one test.
pub struct Authority {
    issuer: rcgen::CertifiedIssuer<'static, rcgen::KeyPair>,
}

/// A certificate and its key, in PEM. Both are made when a test runs and
/// are gone when it ends.
pub struct Identity {
    pub cert_pem: String,
    pub key_pem: String,
    /// The key as the bytes its file encodes.
    pub key_der: Vec<u8>,
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

    /// The authorities a client trusts when it trusts this one alone.
    pub fn roots(&self) -> rustls::RootCertStore {
        use rustls::pki_types::pem::PemObject;

        let mut roots = rustls::RootCertStore::empty();
        roots
            .add(rustls::pki_types::CertificateDer::from_pem_slice(self.pem().as_bytes()).unwrap())
            .unwrap();
        roots
    }

    /// A certificate for a server with these names, and its key.
    pub fn issue(&self, names: &[&str]) -> Identity {
        let names: Vec<String> = names.iter().map(|name| (*name).to_owned()).collect();
        let mut params = rcgen::CertificateParams::new(names).unwrap();
        params.extended_key_usages = vec![rcgen::ExtendedKeyUsagePurpose::ServerAuth];
        params
            .distinguished_name
            .push(rcgen::DnType::CommonName, "a test receiver");
        let key = rcgen::KeyPair::generate().unwrap();
        let certificate = params.signed_by(&key, &self.issuer).unwrap();
        Identity {
            cert_pem: certificate.pem(),
            key_pem: key.serialize_pem(),
            key_der: key.serialize_der(),
        }
    }
}
