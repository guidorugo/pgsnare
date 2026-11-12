// SPDX-License-Identifier: Apache-2.0

//! TLS on both legs of the runtime.
//!
//! The certificates are made while the tests run and exist only in a
//! temporary directory. The clients and the databases are a few lines of
//! test code with a TLS library, so that they can do what a well-behaved
//! peer would not: speak before the handshake, leave out the ALPN
//! extension, or present the wrong certificate.

mod support;

use std::io::Write;
use std::sync::{Arc, Mutex};

use pgsnare::runtime::{ListenerSettings, Upstream};
use pgsnare::tls::{self, BackendLeg, BackendTlsUse, ClientLeg, TlsError};
use pgsnare_core::session::TlsPolicy;
use rustls::pki_types::pem::PemObject;
use rustls::pki_types::{CertificateDer, PrivateKeyDer, ServerName};
use rustls::{ClientConfig, RootCertStore, ServerConfig};
use support::{
    Authority, Database, Identity, Running, SSL_REQUEST, TempDir, answer, error_fields, query,
    read_packet, read_to_end, read_until_ready, serve_session, soon, startup_message, tls_legs,
    until, welcome, yaml_path,
};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;
use tokio_rustls::{TlsAcceptor, TlsConnector};

const ALPN: &[u8] = b"postgresql";

// ---------------------------------------------------------------------------
// A client and a database that speak TLS
// ---------------------------------------------------------------------------

fn roots(authority: &Authority) -> RootCertStore {
    let mut store = RootCertStore::empty();
    for certificate in CertificateDer::pem_slice_iter(authority.pem().as_bytes()) {
        store.add(certificate.unwrap()).unwrap();
    }
    store
}

/// A TLS client that trusts `authority`. `alpn` is what it offers in the
/// ALPN extension, and nothing when that is empty.
fn client_config(
    authority: &Authority,
    versions: &[&'static rustls::SupportedProtocolVersion],
    alpn: &[&[u8]],
) -> Arc<ClientConfig> {
    let mut config = ClientConfig::builder_with_provider(tls::provider())
        .with_protocol_versions(versions)
        .unwrap()
        .with_root_certificates(roots(authority))
        .with_no_client_auth();
    config.alpn_protocols = alpn.iter().map(|name| name.to_vec()).collect();
    Arc::new(config)
}

fn both_versions() -> &'static [&'static rustls::SupportedProtocolVersion] {
    static VERSIONS: [&rustls::SupportedProtocolVersion; 2] =
        [&rustls::version::TLS13, &rustls::version::TLS12];
    &VERSIONS
}

fn only_tls12() -> &'static [&'static rustls::SupportedProtocolVersion] {
    static VERSIONS: [&rustls::SupportedProtocolVersion; 1] = [&rustls::version::TLS12];
    &VERSIONS
}

fn server_config(identity: &Identity) -> Arc<ServerConfig> {
    let chain: Vec<CertificateDer<'static>> =
        CertificateDer::pem_slice_iter(identity.cert_pem.as_bytes())
            .map(Result::unwrap)
            .collect();
    let key = PrivateKeyDer::from_pem_slice(identity.key_pem.as_bytes()).unwrap();
    let mut config = ServerConfig::builder_with_provider(tls::provider())
        .with_safe_default_protocol_versions()
        .unwrap()
        .with_no_client_auth()
        .with_single_cert(chain, key)
        .unwrap();
    config.alpn_protocols = vec![ALPN.to_vec()];
    Arc::new(config)
}

/// A database that answers a request for TLS with `S`, runs the handshake
/// with `identity`, and then behaves like the echo database.
async fn tls_database(identity: &Identity) -> Database {
    let acceptor = TlsAcceptor::from(server_config(identity));
    Database::new(move |mut stream| {
        let acceptor = acceptor.clone();
        Box::pin(async move {
            let Ok(request) = read_packet(&mut stream).await else {
                return;
            };
            assert_eq!(request, SSL_REQUEST);
            if stream.write_all(b"S").await.is_err() {
                return;
            }
            let Ok(mut stream) = acceptor.accept(stream).await else {
                return;
            };
            let _ = serve_session(&mut stream).await;
        })
    })
    .await
}

/// Asks for TLS as libpq does, runs the handshake, and returns the
/// encrypted connection.
async fn start_tls(
    mut stream: TcpStream,
    config: Arc<ClientConfig>,
    name: &str,
) -> std::io::Result<tokio_rustls::client::TlsStream<TcpStream>> {
    stream.write_all(&SSL_REQUEST).await?;
    let mut answer_byte = [0u8; 1];
    stream.read_exact(&mut answer_byte).await?;
    assert_eq!(&answer_byte, b"S");
    TlsConnector::from(config)
        .connect(ServerName::try_from(name.to_owned()).unwrap(), stream)
        .await
}

/// A listener with TLS as the two fragments of configuration say.
fn listener(upstream: Upstream, client_tls: &str, upstream_tls: &str) -> ListenerSettings {
    let (client, backend) = tls_legs(client_tls, &upstream, upstream_tls);
    Running::listener(upstream).with_tls(client, backend)
}

fn client_tls(mode: &str, identity: &Identity) -> String {
    format!(
        "{{ mode: {mode}, cert: {}, key: {} }}",
        yaml_path(&identity.cert_file),
        yaml_path(&identity.key_file)
    )
}

/// What the tests need of a certificate authority and a directory.
struct Pki {
    dir: TempDir,
    authority: Authority,
}

impl Pki {
    fn new() -> Self {
        Self {
            dir: TempDir::new(),
            authority: Authority::new("tests"),
        }
    }

    fn issue(&self, name: &str) -> Identity {
        self.authority.issue(&self.dir, name, &[name, "127.0.0.1"])
    }

    fn verified(&self) -> String {
        format!(
            "{{ mode: verify-full, ca: {} }}",
            yaml_path(&self.authority.file(&self.dir, "ca.crt"))
        )
    }
}

/// Logs in over a connection that is already encrypted and runs a query.
async fn log_in_and_query(
    stream: &mut (impl tokio::io::AsyncRead + tokio::io::AsyncWrite + Unpin),
) {
    stream.write_all(&startup_message()).await.unwrap();
    assert_eq!(soon(read_until_ready(stream)).await.unwrap(), welcome());
    stream.write_all(&query("SELECT 1")).await.unwrap();
    assert_eq!(
        soon(read_until_ready(stream)).await.unwrap(),
        answer(b"SELECT 1")
    );
}

// ---------------------------------------------------------------------------
// The client leg
// ---------------------------------------------------------------------------

#[tokio::test]
async fn a_client_that_asks_for_tls_gets_a_handshake_and_is_relayed() {
    let pki = Pki::new();
    let identity = pki.issue("proxy.example.com");
    let database = Database::echo().await;
    let proxy = Running::start(listener(
        database.upstream(),
        &client_tls("require", &identity),
        "{ mode: disable }",
    ))
    .await;

    // With the ALPN extension, as libpq sends it since version 17, and
    // without, as older clients do.
    for alpn in [&[ALPN][..], &[]] {
        let config = client_config(&pki.authority, both_versions(), alpn);
        let mut client = start_tls(proxy.connect().await, config, "proxy.example.com")
            .await
            .unwrap();
        // The certificate the client was shown is the one configured.
        let shown = client.get_ref().1.peer_certificates().unwrap()[0].clone();
        let configured = CertificateDer::from_pem_slice(identity.cert_pem.as_bytes()).unwrap();
        assert_eq!(shown, configured);
        log_in_and_query(&mut client).await;
    }
    assert_eq!(proxy.status.counters().logins_finished, 2);
}

#[tokio::test]
async fn tls_1_2_is_accepted_and_a_listener_can_ask_for_more() {
    let pki = Pki::new();
    let identity = pki.issue("proxy.example.com");
    let database = Database::echo().await;

    let proxy = Running::start(listener(
        database.upstream(),
        &client_tls("require", &identity),
        "{ mode: disable }",
    ))
    .await;
    let config = client_config(&pki.authority, only_tls12(), &[ALPN]);
    let mut client = start_tls(proxy.connect().await, config, "proxy.example.com")
        .await
        .unwrap();
    assert_eq!(
        client.get_ref().1.protocol_version(),
        Some(rustls::ProtocolVersion::TLSv1_2)
    );
    log_in_and_query(&mut client).await;

    // Raised to TLS 1.3, the same client is refused in the handshake.
    let strict = format!(
        "{{ mode: require, cert: {}, key: {}, min_version: tls1.3 }}",
        yaml_path(&identity.cert_file),
        yaml_path(&identity.key_file)
    );
    let proxy = Running::start(listener(database.upstream(), &strict, "{ mode: disable }")).await;
    let config = client_config(&pki.authority, only_tls12(), &[ALPN]);
    assert!(
        start_tls(proxy.connect().await, config, "proxy.example.com")
            .await
            .is_err()
    );
    let config = client_config(&pki.authority, both_versions(), &[ALPN]);
    let client = start_tls(proxy.connect().await, config, "proxy.example.com")
        .await
        .unwrap();
    assert_eq!(
        client.get_ref().1.protocol_version(),
        Some(rustls::ProtocolVersion::TLSv1_3)
    );
}

#[tokio::test]
async fn nothing_older_than_tls_1_2_is_ever_accepted() {
    let pki = Pki::new();
    let identity = pki.issue("proxy.example.com");
    let database = Database::echo().await;
    let proxy = Running::start(listener(
        database.upstream(),
        &client_tls("require", &identity),
        "{ mode: disable }",
    ))
    .await;

    // The first flight of a client that offers TLS 1.1 at most: a
    // ClientHello with version 3.2 and one cipher suite. The second one
    // also names signature algorithms, which a server looks at before it
    // looks at the version.
    let signature_algorithms: &[u8] = &[0, 10, 0, 13, 0, 6, 0, 4, 4, 3, 8, 4];
    for (extensions, alert) in [(&[][..], None), (signature_algorithms, Some(70))] {
        let mut hello = vec![0x03, 0x02];
        hello.extend_from_slice(&[0x5a; 32]);
        hello.push(0);
        hello.extend_from_slice(&[0, 2, 0x00, 0x2f]);
        hello.extend_from_slice(&[1, 0]);
        hello.extend_from_slice(extensions);
        let mut handshake = vec![0x01, 0, 0, u8::try_from(hello.len()).unwrap()];
        handshake.extend_from_slice(&hello);
        let mut record = vec![0x16, 0x03, 0x01, 0, u8::try_from(handshake.len()).unwrap()];
        record.extend_from_slice(&handshake);

        let mut client = proxy.connect().await;
        client.write_all(&SSL_REQUEST).await.unwrap();
        let mut answer_byte = [0u8; 1];
        soon(client.read_exact(&mut answer_byte)).await.unwrap();
        assert_eq!(&answer_byte, b"S");
        client.write_all(&record).await.unwrap();

        // The answer is a fatal alert and the end of the connection.
        let reply = read_to_end(&mut client).await;
        assert_eq!(reply.len(), 7, "one alert record");
        assert_eq!(reply[0], 0x15, "an alert record");
        assert_eq!(reply[5], 2, "fatal");
        if let Some(alert) = alert {
            assert_eq!(reply[6], alert, "protocol_version");
        }
    }
    assert_eq!(database.connection_count(), 0);
}

#[tokio::test]
async fn plaintext_that_follows_a_request_for_tls_is_refused_on_the_client_leg() {
    let pki = Pki::new();
    let identity = pki.issue("proxy.example.com");
    let database = Database::echo().await;
    let proxy = Running::start(listener(
        database.upstream(),
        &client_tls("require", &identity),
        "{ mode: disable }",
    ))
    .await;

    // The request and a startup message in one piece, the way someone on
    // the path would put a message of his own in front of the handshake.
    let mut injected = SSL_REQUEST.to_vec();
    injected.extend_from_slice(&startup_message());
    let mut client = proxy.connect().await;
    client.write_all(&injected).await.unwrap();

    // No `S`, no handshake, no answer to the startup message: the
    // connection is closed, and the database never hears of it.
    assert!(read_to_end(&mut client).await.is_empty());
    until(|| proxy.status.counters().sessions_failed == 1).await;
    assert_eq!(database.connection_count(), 0);

    // Sent after the `S`, plaintext is read by the handshake, which fails.
    let mut client = proxy.connect().await;
    client.write_all(&SSL_REQUEST).await.unwrap();
    let mut answer_byte = [0u8; 1];
    soon(client.read_exact(&mut answer_byte)).await.unwrap();
    assert_eq!(&answer_byte, b"S");
    client.write_all(&startup_message()).await.unwrap();
    let reply = read_to_end(&mut client).await;
    assert!(reply.is_empty() || reply[0] == 0x15, "an alert at most");
    assert_eq!(database.connection_count(), 0);
}

#[tokio::test]
async fn a_connection_that_opens_with_a_handshake_must_name_the_protocol() {
    let pki = Pki::new();
    let identity = pki.issue("proxy.example.com");
    let database = Database::echo().await;
    let proxy = Running::start(listener(
        database.upstream(),
        &client_tls("require", &identity),
        "{ mode: disable }",
    ))
    .await;
    let name = || ServerName::try_from("proxy.example.com").unwrap();

    // With the ALPN name of the protocol: served.
    let config = client_config(&pki.authority, both_versions(), &[ALPN]);
    let mut client = TlsConnector::from(config)
        .connect(name(), proxy.connect().await)
        .await
        .unwrap();
    assert_eq!(client.get_ref().1.alpn_protocol(), Some(ALPN));
    log_in_and_query(&mut client).await;

    // Without the ALPN extension: the handshake completes, since nothing
    // in it is wrong, and the connection is closed before a single byte
    // of the session is read.
    let config = client_config(&pki.authority, both_versions(), &[]);
    let mut client = TlsConnector::from(config)
        .connect(name(), proxy.connect().await)
        .await
        .unwrap();
    let _ = client.write_all(&startup_message()).await;
    let mut reply = Vec::new();
    let _ = soon(client.read_to_end(&mut reply)).await;
    assert!(reply.is_empty());

    // With the name of another protocol: refused. A client that speaks
    // TLS 1.2 is told why with an alert. A client that speaks TLS 1.3
    // finds the connection closed in the middle of the handshake.
    for versions in [only_tls12(), both_versions()] {
        let config = client_config(&pki.authority, versions, &[b"h2"]);
        let refused = TlsConnector::from(config)
            .connect(name(), proxy.connect().await)
            .await
            .unwrap_err();
        let expected = if versions.len() == 1 {
            "the peer refused the handshake"
        } else {
            "the connection was closed during the handshake"
        };
        assert_eq!(tls::describe(&refused), expected, "{refused:?}");
    }
    // The same holds after a request for TLS.
    let config = client_config(&pki.authority, both_versions(), &[b"h2"]);
    assert!(
        start_tls(proxy.connect().await, config, "proxy.example.com")
            .await
            .is_err()
    );

    assert_eq!(database.connection_count(), 1);
}

#[tokio::test]
async fn a_listener_can_offer_tls_without_requiring_it() {
    let pki = Pki::new();
    let identity = pki.issue("proxy.example.com");
    let database = Database::echo().await;
    let proxy = Running::start(listener(
        database.upstream(),
        &client_tls("prefer", &identity),
        "{ mode: disable }",
    ))
    .await;

    let config = client_config(&pki.authority, both_versions(), &[ALPN]);
    let mut encrypted = start_tls(proxy.connect().await, config, "proxy.example.com")
        .await
        .unwrap();
    log_in_and_query(&mut encrypted).await;
    let mut plain = proxy.connect().await;
    log_in_and_query(&mut plain).await;

    // Where TLS is required, a plaintext client is told so in the words
    // of PostgreSQL and the database is not contacted.
    let proxy = Running::start(listener(
        database.upstream(),
        &client_tls("require", &identity),
        "{ mode: disable }",
    ))
    .await;
    let mut plain = proxy.connect().await;
    plain.write_all(&startup_message()).await.unwrap();
    let fields = error_fields(&read_to_end(&mut plain).await);
    assert_eq!(fields[2], (b'C', "28000".to_owned()));
    assert_eq!(
        fields[3].1,
        "no pg_hba.conf entry for host \"127.0.0.1\", user \"app\", database \"shop\", \
         no encryption"
    );
    assert_eq!(database.connection_count(), 2);
}

// ---------------------------------------------------------------------------
// The backend leg
// ---------------------------------------------------------------------------

#[tokio::test]
async fn the_backend_leg_uses_tls_and_verifies_the_certificate() {
    let pki = Pki::new();
    let database = tls_database(&pki.issue("127.0.0.1")).await;
    let proxy = Running::start(listener(
        database.upstream(),
        "{ mode: disable }",
        &pki.verified(),
    ))
    .await;

    let (mut client, greeting) = proxy.log_in().await;
    assert_eq!(greeting, welcome());
    client.write_all(&query("SELECT 1")).await.unwrap();
    assert_eq!(
        soon(read_until_ready(&mut client)).await.unwrap(),
        answer(b"SELECT 1")
    );
}

/// Starts a proxy in front of `database` with these TLS settings for the
/// backend leg, tries to log in, and returns the code of the error the
/// client was sent.
async fn refused_login(database: &Database, upstream_tls: &str) -> String {
    let proxy = Running::start(listener(
        database.upstream(),
        "{ mode: disable }",
        upstream_tls,
    ))
    .await;
    let mut client = proxy.connect().await;
    client.write_all(&startup_message()).await.unwrap();
    let reply = read_to_end(&mut client).await;
    assert_eq!(proxy.status.counters().backend_failures, 1);
    assert_eq!(proxy.status.counters().logins_finished, 0);
    error_fields(&reply)[2].1.clone()
}

#[tokio::test]
async fn a_certificate_that_does_not_verify_stops_the_login() {
    let pki = Pki::new();

    // A certificate for another name.
    let database = tls_database(
        &pki.authority
            .issue(&pki.dir, "other", &["other.example.com"]),
    )
    .await;
    assert_eq!(refused_login(&database, &pki.verified()).await, "57P03");

    // A certificate from an authority that is not the configured one.
    let stranger = Authority::new("stranger");
    let database = tls_database(&stranger.issue(&pki.dir, "stranger", &["127.0.0.1"])).await;
    assert_eq!(refused_login(&database, &pki.verified()).await, "57P03");

    // The right certificate, and a name configured that it does not carry.
    let database = tls_database(&pki.issue("127.0.0.1")).await;
    let renamed = format!(
        "{{ mode: verify-full, ca: {}, server_name: db.example.com }}",
        yaml_path(&pki.authority.file(&pki.dir, "ca.crt"))
    );
    assert_eq!(refused_login(&database, &renamed).await, "57P03");

    // The same three databases are accepted when verification is off,
    // which takes a mode that says so.
    for mode in ["require", "prefer"] {
        let database = tls_database(&stranger.issue(&pki.dir, "any", &["other.example.com"])).await;
        let proxy = Running::start(listener(
            database.upstream(),
            "{ mode: disable }",
            &format!("{{ mode: {mode} }}"),
        ))
        .await;
        let (_client, greeting) = proxy.log_in().await;
        assert_eq!(greeting, welcome());
    }
}

#[tokio::test]
async fn a_database_without_tls_is_used_only_where_the_mode_allows_plaintext() {
    // A database that declines TLS and goes on in plaintext.
    let database = Database::new(|mut stream| {
        Box::pin(async move {
            let Ok(request) = read_packet(&mut stream).await else {
                return;
            };
            assert_eq!(request, SSL_REQUEST);
            if stream.write_all(b"N").await.is_err() {
                return;
            }
            let _ = serve_session(&mut stream).await;
        })
    })
    .await;
    let pki = Pki::new();

    assert_eq!(refused_login(&database, "{ mode: require }").await, "57P03");
    assert_eq!(refused_login(&database, &pki.verified()).await, "57P03");

    let proxy = Running::start(listener(
        database.upstream(),
        "{ mode: disable }",
        "{ mode: prefer }",
    ))
    .await;
    let (_client, greeting) = proxy.log_in().await;
    assert_eq!(greeting, welcome());
}

#[tokio::test]
async fn plaintext_that_follows_the_answer_to_a_request_for_tls_is_refused_on_the_backend_leg() {
    // Someone on the path answers the request for TLS with `S` and adds a
    // message of his own, in the clear, before any handshake: here, the
    // news that the login succeeded.
    let injected: Arc<Mutex<bool>> = Arc::default();
    let done = Arc::clone(&injected);
    let database = Database::new(move |mut stream| {
        let done = Arc::clone(&done);
        Box::pin(async move {
            if read_packet(&mut stream).await.is_err() {
                return;
            }
            let mut reply = b"S".to_vec();
            reply.extend_from_slice(&welcome());
            let _ = stream.write_all(&reply).await;
            *done.lock().unwrap() = true;
            // Whatever pgsnare sends next is drained.
            let mut sink = [0u8; 1024];
            while matches!(stream.read(&mut sink).await, Ok(count) if count > 0) {}
        })
    })
    .await;

    for mode in ["require", "prefer"] {
        let proxy = Running::start(listener(
            database.upstream(),
            "{ mode: disable }",
            &format!("{{ mode: {mode} }}"),
        ))
        .await;
        let mut client = proxy.connect().await;
        client.write_all(&startup_message()).await.unwrap();
        let reply = read_to_end(&mut client).await;
        assert!(*injected.lock().unwrap());
        // The client is told that the database cannot be reached. It is
        // not shown a single byte of what was injected.
        assert_eq!(error_fields(&reply)[2].1, "57P03");
        assert_eq!(reply.iter().filter(|byte| **byte == b'Z').count(), 0);
        assert_eq!(proxy.status.counters().logins_finished, 0);
        assert_eq!(proxy.status.counters().backend_failures, 1);
    }
}

#[tokio::test]
async fn an_answer_that_is_neither_yes_nor_no_stops_the_login() {
    // An old server answers a request it does not know with an error.
    let database = Database::new(|mut stream| {
        Box::pin(async move {
            if read_packet(&mut stream).await.is_ok() {
                let _ = stream.write_all(b"E").await;
            }
        })
    })
    .await;
    assert_eq!(refused_login(&database, "{ mode: prefer }").await, "57P03");
    assert_eq!(refused_login(&database, "{ mode: require }").await, "57P03");
}

// ---------------------------------------------------------------------------
// Both legs
// ---------------------------------------------------------------------------

/// A writer that keeps what is logged, for a test to read.
#[derive(Clone, Default)]
struct Captured(Arc<Mutex<Vec<u8>>>);

impl Captured {
    fn text(&self) -> String {
        String::from_utf8_lossy(&self.0.lock().unwrap()).into_owned()
    }
}

impl Write for Captured {
    fn write(&mut self, bytes: &[u8]) -> std::io::Result<usize> {
        self.0.lock().unwrap().extend_from_slice(bytes);
        Ok(bytes.len())
    }

    fn flush(&mut self) -> std::io::Result<()> {
        Ok(())
    }
}

impl<'a> tracing_subscriber::fmt::MakeWriter<'a> for Captured {
    type Writer = Self;

    fn make_writer(&'a self) -> Self {
        self.clone()
    }
}

const MISMATCH: &str = "the certificate of the client leg is not the one the database presents";

#[tokio::test]
async fn a_client_leg_certificate_that_differs_from_the_one_of_the_database_is_warned_about() {
    let log = Captured::default();
    let subscriber = tracing_subscriber::fmt()
        .with_writer(log.clone())
        .with_ansi(false)
        .finish();
    let _guard = tracing::subscriber::set_default(subscriber);

    let pki = Pki::new();
    let of_database = pki.issue("127.0.0.1");
    let of_proxy = pki.issue("proxy.example.com");
    let database = tls_database(&of_database).await;
    let build = |identity: &Identity| {
        let listener = listener(
            database.upstream(),
            &client_tls("require", identity),
            &pki.verified(),
        );
        let events = Arc::new(support::Memory::default());
        let module = Arc::new(pgsnare_core::session::postgres::Postgres::new());
        pgsnare::runtime::Runtime::new(
            support::proxy_of(module, &events),
            Arc::new(pgsnare_core::policy::FixedPolicy::new(support::policy(
                pgsnare_core::policy::OnError::FailClosed,
                1024 * 1024,
            ))),
            pgsnare::runtime::Settings::new(vec![listener]),
        )
        .bind()
        .unwrap()
    };

    // The shared certificate: nothing to say.
    let bound = build(&of_database);
    let same = bound
        .compare_certificates(std::time::Duration::from_secs(5))
        .await;
    assert_eq!(same, [Some(true)]);
    assert!(!log.text().contains(MISMATCH), "{}", log.text());

    // A certificate of its own: a warning that names the listener.
    let bound = build(&of_proxy);
    let same = bound
        .compare_certificates(std::time::Duration::from_secs(5))
        .await;
    assert_eq!(same, [Some(false)]);
    let text = log.text();
    assert!(text.contains(MISMATCH), "{text}");
    assert!(text.contains("WARN"), "{text}");
    assert!(text.contains("listener=test"), "{text}");
    // Said once for a listener, however many connections follow.
    assert_eq!(text.matches(MISMATCH).count(), 1);
    bound
        .compare_certificates(std::time::Duration::from_secs(5))
        .await;
    assert_eq!(log.text().matches(MISMATCH).count(), 1);
}

#[tokio::test]
async fn there_is_nothing_to_compare_without_tls_on_both_legs_or_without_a_database() {
    let pki = Pki::new();
    let identity = pki.issue("proxy.example.com");
    let database = Database::echo().await;
    let events = Arc::new(support::Memory::default());
    let build = |listener: ListenerSettings| {
        let module = Arc::new(pgsnare_core::session::postgres::Postgres::new());
        pgsnare::runtime::Runtime::new(
            support::proxy_of(module, &events),
            Arc::new(pgsnare_core::policy::FixedPolicy::new(support::policy(
                pgsnare_core::policy::OnError::FailClosed,
                1024 * 1024,
            ))),
            pgsnare::runtime::Settings::new(vec![listener]),
        )
        .bind()
        .unwrap()
    };
    let patience = std::time::Duration::from_secs(5);

    // TLS on the client leg only.
    let bound = build(listener(
        database.upstream(),
        &client_tls("require", &identity),
        "{ mode: disable }",
    ));
    assert_eq!(bound.compare_certificates(patience).await, [None]);
    // TLS on the backend leg only.
    let bound = build(listener(
        database.upstream(),
        "{ mode: disable }",
        "{ mode: require }",
    ));
    assert_eq!(bound.compare_certificates(patience).await, [None]);
    assert_eq!(database.connection_count(), 0);

    // TLS on both, and a database that is not there: the proxy starts all
    // the same.
    let nowhere = Upstream::Tcp {
        host: "127.0.0.1".to_owned(),
        port: 1,
    };
    let bound = build(listener(
        nowhere,
        &client_tls("require", &identity),
        "{ mode: require }",
    ));
    assert_eq!(bound.compare_certificates(patience).await, [None]);
}

#[tokio::test]
async fn tls_on_both_legs_relays_a_session() {
    let pki = Pki::new();
    let identity = pki.issue("127.0.0.1");
    let database = tls_database(&identity).await;
    // The shared certificate: the proxy presents the one of the database.
    let proxy = Running::start(listener(
        database.upstream(),
        &client_tls("require", &identity),
        &pki.verified(),
    ))
    .await;

    let config = client_config(&pki.authority, both_versions(), &[ALPN]);
    let mut client = start_tls(proxy.connect().await, config, "127.0.0.1")
        .await
        .unwrap();
    log_in_and_query(&mut client).await;

    // A megabyte in each direction, through two layers of encryption.
    let sql = "y".repeat(1024 * 1024);
    client.write_all(&query(&sql)).await.unwrap();
    let reply = soon(read_until_ready(&mut client)).await.unwrap();
    assert!(reply == answer(sql.as_bytes()));
}

// ---------------------------------------------------------------------------
// Settings
// ---------------------------------------------------------------------------

#[test]
fn the_settings_of_a_listener_say_what_each_leg_does() {
    let pki = Pki::new();
    let identity = pki.issue("proxy.example.com");
    let upstream = Upstream::Tcp {
        host: "db.example.com".to_owned(),
        port: 5432,
    };

    let (client, backend) = tls_legs("{ mode: disable }", &upstream, "{ mode: disable }");
    assert_eq!(client.policy(), TlsPolicy::Disabled);
    assert!(client.acceptor().is_none());
    assert!(client.certificate().is_none());
    assert_eq!(backend.usage(), BackendTlsUse::Never);
    assert!(!backend.verifies());
    assert!(backend.connector().is_none());

    let (client, backend) = tls_legs(
        &client_tls("prefer", &identity),
        &upstream,
        "{ mode: prefer }",
    );
    assert_eq!(client.policy(), TlsPolicy::Optional);
    assert_eq!(backend.usage(), BackendTlsUse::IfOffered);
    assert!(!backend.verifies());

    let (client, backend) = tls_legs(
        &client_tls("require", &identity),
        &upstream,
        "{ mode: require }",
    );
    assert_eq!(client.policy(), TlsPolicy::Required);
    assert_eq!(backend.usage(), BackendTlsUse::Always);
    assert!(!backend.verifies());
    // The certificate is known in its encoded form, for the comparison.
    let configured = CertificateDer::from_pem_slice(identity.cert_pem.as_bytes()).unwrap();
    assert_eq!(client.certificate(), Some(configured.as_ref()));

    let (_, backend) = tls_legs("{ mode: disable }", &upstream, &pki.verified());
    assert_eq!(backend.usage(), BackendTlsUse::Always);
    assert!(backend.verifies());
    // The name to verify is the host of the database, unless one is set.
    assert_eq!(
        backend.server_name(),
        Some(&ServerName::try_from("db.example.com").unwrap())
    );
    let renamed = format!(
        "{{ mode: verify-full, ca: {}, server_name: other.example.com }}",
        yaml_path(&pki.authority.file(&pki.dir, "ca.crt"))
    );
    let (_, backend) = tls_legs("{ mode: disable }", &upstream, &renamed);
    assert_eq!(
        backend.server_name(),
        Some(&ServerName::try_from("other.example.com").unwrap())
    );

    // Nothing of a key or a certificate shows up in debug output.
    assert_eq!(
        format!("{client:?} {backend:?}"),
        "ClientLeg { policy: Required, .. } BackendLeg { usage: Always, verifies: true, .. }"
    );
}

/// The client and upstream TLS settings of a configuration text.
fn settings(
    client_tls: &str,
    upstream_tls: &str,
) -> (
    pgsnare::config::ClientTls,
    pgsnare::config::UpstreamTls,
    pgsnare::config::Endpoint,
) {
    let config = pgsnare::config::Config::from_yaml(&format!(
        "listeners:\n  - name: test\n    listen: 127.0.0.1:5432\n    upstream: db.example.com:5432\n    \
         client_tls: {client_tls}\n    upstream_tls: {upstream_tls}\nevents:\n  sinks:\n    - type: stdout\n"
    ))
    .unwrap();
    let listener = config.listeners.into_iter().next().unwrap();
    (
        listener.client_tls,
        listener.upstream_tls,
        listener.upstream,
    )
}

#[test]
fn files_that_cannot_be_used_are_named_and_their_content_is_not() {
    let pki = Pki::new();
    let identity = pki.issue("proxy.example.com");
    let other = pki.issue("other.example.com");
    let cert = yaml_path(&identity.cert_file);
    let key = yaml_path(&identity.key_file);

    let client_error = |client_tls: &str| {
        let (client, _, _) = settings(client_tls, "{ mode: disable }");
        ClientLeg::from_config(&client, Some(ALPN)).unwrap_err()
    };

    // A file that is not there.
    let missing = yaml_path(&pki.dir.0.join("missing.pem"));
    let error = client_error(&format!("{{ mode: require, cert: {missing}, key: {key} }}"));
    assert!(matches!(error, TlsError::Read { .. }), "{error}");
    assert!(
        error
            .to_string()
            .ends_with("missing.pem\": cannot read the file: entity not found")
            || error.to_string().contains("cannot read the file"),
        "{error}"
    );

    // The key where the certificate should be, and the other way round.
    let error = client_error(&format!("{{ mode: require, cert: {key}, key: {key} }}"));
    assert!(matches!(error, TlsError::NoCertificate { .. }), "{error}");
    let error = client_error(&format!("{{ mode: require, cert: {cert}, key: {cert} }}"));
    assert!(matches!(error, TlsError::NoPrivateKey { .. }), "{error}");

    // A key that belongs to another certificate.
    let other_key = yaml_path(&other.key_file);
    let error = client_error(&format!(
        "{{ mode: require, cert: {cert}, key: {other_key} }}"
    ));
    assert!(matches!(error, TlsError::KeyMismatch { .. }), "{error}");

    // A file that is not PEM at all. The secret in it is not repeated.
    let garbage = pki.dir.write(
        "garbage.key",
        "-----BEGIN PRIVATE KEY-----\nnot base64: hunter2!\n-----END PRIVATE KEY-----\n",
    );
    let error = client_error(&format!(
        "{{ mode: require, cert: {cert}, key: {} }}",
        yaml_path(&garbage)
    ));
    assert!(matches!(error, TlsError::NotPem { .. }), "{error}");
    assert!(!error.to_string().contains("hunter2"));
    assert!(!format!("{error:?}").contains("hunter2"));

    // An authority file without a certificate.
    let (_, upstream_tls, endpoint) = settings(
        "{ mode: disable }",
        &format!("{{ mode: verify-full, ca: {key} }}"),
    );
    let error = BackendLeg::from_config(&upstream_tls, &endpoint, Some(ALPN)).unwrap_err();
    assert!(matches!(error, TlsError::NoCertificate { .. }), "{error}");
}
