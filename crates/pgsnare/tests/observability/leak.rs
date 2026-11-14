// SPDX-License-Identifier: Apache-2.0

//! The leak test: nothing that goes into pgsnare as a secret comes out of
//! it anywhere.
//!
//! # How it works
//!
//! 1. **Secrets are made**, new for every run: honeytoken values, a
//!    password, a bind parameter, signing keys, a private key and a URL
//!    that is a secret. See [`Secrets`].
//! 2. **A `pgsnare` process is started** with all of them loaded and with
//!    every way out it has: each kind of sink, the log, the metrics and
//!    the health endpoints.
//! 3. **Traffic that carries the secrets goes through it**, in the places
//!    where they could be picked up: a honeytoken as a user name, as an
//!    application name and in a statement, a password in a login and in a
//!    statement, a parameter in a `Bind` message.
//! 4. **Everything that came out is collected**: see [`Output`].
//! 5. **Every output is searched for every secret, in every form** a
//!    careless line of code could have written it in: see [`forms`] and
//!    [`Search`].
//!
//! # A pass has to mean something
//!
//! - The search is shown to find what it looks for: every secret is
//!   planted in a text, in every form, whole and in part, and the search
//!   must report each of them.
//! - Every secret is shown to have been where it could leak from: the
//!   database of the test received each of them through the proxy, the
//!   receivers verified signatures made with the keys, and a session ran
//!   over TLS with the private key.
//! - Every output is shown to have been written to.
//!
//! # Adding to it
//!
//! A new kind of secret is one more entry in [`Secrets::new`]. A new way
//! out is one more entry in the list of outputs at the end of the test. A
//! new form is one more entry in [`forms`].

use std::collections::BTreeSet;
use std::sync::{Arc, Mutex};
use std::time::Duration;

use aho_corasick::AhoCorasick;
use aws_lc_rs::rand::{SecureRandom, SystemRandom};
use rustix::process::Signal;
use rustls::ClientConfig;
use rustls::pki_types::ServerName;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream, UdpSocket};
use tokio_rustls::TlsConnector;

use crate::process::{
    BROKEN, Database, Pgsnare, TempDir, bind, free_port, query, read_until_ready, start_session,
};
use crate::receiver::{Answer, Receiver, Verifier};
use crate::support::{Authority, soon, until};

/// How many bytes of a secret, as it is, are enough to count as a leak.
/// Shorter pieces turn up by chance.
const PIECE: usize = 12;

// ---------------------------------------------------------------------------
// What goes in
// ---------------------------------------------------------------------------

/// What kind of secret something is.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord)]
enum Kind {
    TokenValue,
    Password,
    BindParameter,
    SigningKey,
    PrivateKey,
    SecretUrl,
}

/// One secret that went in.
#[derive(Clone, Debug)]
struct Secret {
    kind: Kind,
    /// What it is, for the report of a leak.
    name: &'static str,
    bytes: Vec<u8>,
    /// The outputs that hold it by design. The receiver of a webhook, for
    /// one, cannot be kept from knowing its own URL.
    expected_in: &'static [&'static str],
}

impl Secret {
    fn text(&self) -> &str {
        std::str::from_utf8(&self.bytes).expect("this secret is text")
    }
}

/// Random bytes from the generator of the cryptographic library.
fn random_bytes(length: usize) -> Vec<u8> {
    let mut bytes = vec![0u8; length];
    SystemRandom::new().fill(&mut bytes).unwrap();
    bytes
}

/// Random text of letters and digits.
fn random_text(length: usize) -> String {
    const ALPHABET: &[u8] = b"abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789";
    random_bytes(length)
        .into_iter()
        .map(|byte| char::from(ALPHABET[usize::from(byte) % ALPHABET.len()]))
        .collect()
}

/// Everything secret of one run.
struct Secrets {
    /// A honeytoken value that a client uses as its user name.
    token_user: Secret,
    /// One with the characters JSON escapes, used in a statement.
    token_quoted: Secret,
    /// One whose letter case is ignored, used in another case.
    token_folded: Secret,
    /// One that a client sends in hexadecimal.
    token_hex: Secret,
    /// One that sits where a long application name is cut.
    token_cut: Secret,
    /// The password of a login.
    password: Secret,
    /// A password in the text of a statement.
    statement_password: Secret,
    /// A parameter of a `Bind` message.
    bind_parameter: Secret,
    /// The signing key of a webhook, from a file. It is not text.
    key_in_file: Secret,
    /// The signing key of another webhook, from the environment.
    key_in_environment: Secret,
    /// The private key of the listener, as the bytes TLS works with.
    private_key: Secret,
    /// The same key as the lines of its file.
    private_key_lines: Vec<Secret>,
    /// The part of a webhook URL that is a secret.
    url_path: Secret,
}

impl Secrets {
    fn new(private_key_der: &[u8], private_key_pem: &str) -> Self {
        let secret = |kind, name, bytes: Vec<u8>| Secret {
            kind,
            name,
            bytes,
            expected_in: &[],
        };
        let token = |name, value: String| secret(Kind::TokenValue, name, value.into_bytes());
        // A signing key that is not text, and that does not end in a line
        // break, which the reader of the file would take off.
        let mut key = random_bytes(48);
        key[47] |= 0x80;
        Self {
            token_user: token(
                "the honeytoken used as a user name",
                // No part of a secret that is the same in every run is as
                // long as a piece the search looks for.
                format!("svc.{}@m.example", random_text(20).to_lowercase()),
            ),
            token_quoted: token(
                "the honeytoken with a quote and a backslash",
                format!("q\"{}\\{}", random_text(12), random_text(12)),
            ),
            token_folded: token(
                "the honeytoken whose letter case is ignored",
                format!("Canary.{}", random_text(20)),
            ),
            token_hex: token("the honeytoken sent in hexadecimal", random_text(24)),
            token_cut: token("the honeytoken where a name is cut", random_text(40)),
            password: secret(
                Kind::Password,
                "the password of the login",
                random_text(24).into_bytes(),
            ),
            statement_password: secret(
                Kind::Password,
                "the password in a statement",
                random_text(24).into_bytes(),
            ),
            bind_parameter: secret(
                Kind::BindParameter,
                "the bind parameter",
                random_text(24).into_bytes(),
            ),
            key_in_file: secret(Kind::SigningKey, "the signing key from a file", key),
            key_in_environment: secret(
                Kind::SigningKey,
                "the signing key from the environment",
                random_text(40).into_bytes(),
            ),
            private_key: secret(
                Kind::PrivateKey,
                "the private key of the listener",
                private_key_der.to_vec(),
            ),
            private_key_lines: private_key_pem
                .lines()
                .filter(|line| !line.starts_with("-----") && line.len() >= PIECE)
                .map(|line| {
                    secret(
                        Kind::PrivateKey,
                        "a line of the private key file",
                        line.as_bytes().to_vec(),
                    )
                })
                .collect(),
            url_path: Secret {
                kind: Kind::SecretUrl,
                name: "the secret path of a webhook URL",
                bytes: format!("/hooks/{}", random_text(32)).into_bytes(),
                expected_in: &["the requests to the first webhook receiver"],
            },
        }
    }

    /// Every secret, each an entry of its own.
    fn all(&self) -> Vec<Secret> {
        let mut all = vec![
            self.token_user.clone(),
            self.token_quoted.clone(),
            self.token_folded.clone(),
            self.token_hex.clone(),
            self.token_cut.clone(),
            self.password.clone(),
            self.statement_password.clone(),
            self.bind_parameter.clone(),
            self.key_in_file.clone(),
            self.key_in_environment.clone(),
            self.private_key.clone(),
            self.url_path.clone(),
        ];
        all.extend(self.private_key_lines.iter().cloned());
        all
    }
}

// ---------------------------------------------------------------------------
// The search
// ---------------------------------------------------------------------------

fn hex(bytes: &[u8], upper: bool) -> Vec<u8> {
    bytes
        .iter()
        .flat_map(|byte| {
            let text = if upper {
                format!("{byte:02X}")
            } else {
                format!("{byte:02x}")
            };
            text.into_bytes()
        })
        .collect()
}

/// Base64 without padding, with the usual alphabet or the one for URLs.
fn base64(bytes: &[u8], url_safe: bool) -> Vec<u8> {
    let alphabet: &[u8; 64] = if url_safe {
        b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_"
    } else {
        b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/"
    };
    let mut text = Vec::new();
    for chunk in bytes.chunks(3) {
        let group = [
            chunk[0],
            chunk.get(1).copied().unwrap_or(0),
            chunk.get(2).copied().unwrap_or(0),
        ];
        let sextets = [
            group[0] >> 2,
            (group[0] & 0x03) << 4 | group[1] >> 4,
            (group[1] & 0x0f) << 2 | group[2] >> 6,
            group[2] & 0x3f,
        ];
        for sextet in &sextets[..=chunk.len()] {
            text.push(alphabet[usize::from(*sextet)]);
        }
    }
    text
}

/// A form a secret could have been written in: what the form is called,
/// the secret in that form, and how many bytes of it are enough to count
/// as a leak.
struct Form {
    name: String,
    bytes: Vec<u8>,
    piece: usize,
}

/// Every form a secret is looked for in: as it is, and the ways a line of
/// code that should not exist could have written it.
fn forms(secret: &[u8]) -> Vec<Form> {
    let form = |name: &str, bytes: Vec<u8>, piece: usize| Form {
        name: name.to_owned(),
        bytes,
        piece,
    };
    let mut forms = vec![form("as it is", secret.to_vec(), PIECE)];

    if let Ok(text) = std::str::from_utf8(secret) {
        // The way a JSON encoder writes a text, which is also the way a
        // label of a metric is escaped, and close to how Rust shows a text
        // for debugging.
        let quoted = serde_json::to_string(text).unwrap();
        let escaped = quoted.as_bytes()[1..quoted.len() - 1].to_vec();
        if escaped != secret {
            forms.push(form("escaped as in JSON", escaped, PIECE));
        }
        for (name, changed) in [
            ("in upper case", text.to_ascii_uppercase()),
            ("in lower case", text.to_ascii_lowercase()),
        ] {
            if changed != text {
                forms.push(form(name, changed.into_bytes(), PIECE));
            }
        }
    }

    forms.push(form("in hexadecimal", hex(secret, false), 2 * PIECE));
    forms.push(form(
        "in upper-case hexadecimal",
        hex(secret, true),
        2 * PIECE,
    ));
    // The way Rust shows bytes for debugging: [115, 118, 99, ...].
    let numbers: Vec<String> = secret.iter().map(u8::to_string).collect();
    forms.push(form(
        "as a list of numbers",
        numbers.join(", ").into_bytes(),
        2 * PIECE,
    ));

    // Base64 turns three bytes into four characters, so what a secret looks
    // like depends on where it starts in what was encoded. Each of the three
    // places is tried. The characters at both ends depend on the neighbours
    // of the secret and are left out.
    for url_safe in [false, true] {
        for before in 0..3usize {
            let mut padded = vec![0u8; before];
            padded.extend_from_slice(secret);
            let encoded = base64(&padded, url_safe);
            let start = if before == 0 { 0 } else { 4 };
            let end = encoded.len().saturating_sub(4);
            if end > start + 16 {
                let name = format!(
                    "in {}base64, {before} bytes into a group",
                    if url_safe { "URL-safe " } else { "" }
                );
                forms.push(form(&name, encoded[start..end].to_vec(), 16));
            }
        }
    }
    forms
}

/// A leak: which secret, in which form, in which output.
#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord)]
struct Leak {
    kind: Kind,
    secret: &'static str,
    form: String,
    output: String,
}

/// Something that came out of pgsnare.
#[derive(Clone, Debug)]
struct Output {
    name: &'static str,
    bytes: Vec<u8>,
}

/// The search for a set of secrets, compiled once.
struct Search<'a> {
    secrets: &'a [Secret],
    /// Every piece of every form of every secret, to be looked for in one
    /// pass over an output.
    pieces: AhoCorasick,
    /// For each piece: the secret it belongs to, and the name of its form.
    origin: Vec<(usize, String)>,
}

impl<'a> Search<'a> {
    fn new(secrets: &'a [Secret]) -> Self {
        let mut pieces: Vec<Vec<u8>> = Vec::new();
        let mut origin: Vec<(usize, String)> = Vec::new();
        for (index, secret) in secrets.iter().enumerate() {
            for form in forms(&secret.bytes) {
                let piece = form.piece.min(form.bytes.len());
                for window in form.bytes.windows(piece) {
                    pieces.push(window.to_vec());
                    origin.push((index, form.name.clone()));
                }
            }
        }
        Self {
            secrets,
            pieces: AhoCorasick::new(&pieces).expect("the pieces can be compiled"),
            origin,
        }
    }

    /// Searches every output for every secret in every form, and returns
    /// what it found.
    fn leaks(&self, outputs: &[Output]) -> Vec<Leak> {
        let mut found = BTreeSet::new();
        for output in outputs {
            for hit in self.pieces.find_overlapping_iter(&output.bytes) {
                let (index, form) = &self.origin[hit.pattern().as_usize()];
                let secret = &self.secrets[*index];
                if secret.expected_in.contains(&output.name) {
                    continue;
                }
                found.insert(Leak {
                    kind: secret.kind,
                    secret: secret.name,
                    form: form.clone(),
                    output: output.name.to_owned(),
                });
            }
        }
        found.into_iter().collect()
    }
}

/// The search must find what it looks for. Every secret is planted in an
/// output of its own, in every form, once whole and once as the smallest
/// piece that counts, and each must be reported for the right secret.
fn the_search_finds_what_is_planted(search: &Search<'_>) {
    let around = |planted: &[u8]| {
        let mut bytes = b"{\"level\":\"info\",\"message\":\"listening\",\"reason\":\"".to_vec();
        bytes.extend_from_slice(planted);
        bytes.extend_from_slice(b"\"}\n");
        bytes
    };
    let clean = Output {
        name: "a clean output",
        bytes: around(b"nothing to see here"),
    };
    assert_eq!(search.leaks(&[clean]), [], "a clean output is clean");

    let mut kinds = BTreeSet::new();
    for secret in search.secrets {
        for form in forms(&secret.bytes) {
            let piece = form.piece.min(form.bytes.len());
            let middle = (form.bytes.len() - piece) / 2;
            for planted in [&form.bytes[..], &form.bytes[middle..middle + piece]] {
                let output = Output {
                    name: "an output with a planted secret",
                    bytes: around(planted),
                };
                let found = search.leaks(&[output]);
                assert!(
                    found
                        .iter()
                        .any(|leak| leak.secret == secret.name && leak.kind == secret.kind),
                    "{} planted {} was not found",
                    secret.name,
                    form.name
                );
            }
        }
        // And a secret that is where it is expected is not a leak there.
        for expected in secret.expected_in {
            let output = Output {
                name: expected,
                bytes: around(&secret.bytes),
            };
            let found = search.leaks(&[output]);
            assert!(
                !found.iter().any(|leak| leak.secret == secret.name),
                "{found:?}"
            );
        }
        kinds.insert(secret.kind);
    }
    assert_eq!(
        kinds.into_iter().collect::<Vec<_>>(),
        [
            Kind::TokenValue,
            Kind::Password,
            Kind::BindParameter,
            Kind::SigningKey,
            Kind::PrivateKey,
            Kind::SecretUrl
        ],
        "every kind of secret is among the secrets"
    );
}

// ---------------------------------------------------------------------------
// The test
// ---------------------------------------------------------------------------

/// A text as it stands between double quotes in YAML.
fn yaml_quoted(text: &str) -> String {
    format!("\"{}\"", text.replace('\\', "\\\\").replace('"', "\\\""))
}

/// A server that keeps every byte it is sent, over TCP.
async fn collecting_tcp() -> (u16, Arc<Mutex<Vec<u8>>>) {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let port = listener.local_addr().unwrap().port();
    let all: Arc<Mutex<Vec<u8>>> = Arc::default();
    let kept = Arc::clone(&all);
    tokio::spawn(async move {
        loop {
            let Ok((mut stream, _)) = listener.accept().await else {
                return;
            };
            let kept = Arc::clone(&kept);
            tokio::spawn(async move {
                let mut buffer = [0u8; 4096];
                while let Ok(count) = stream.read(&mut buffer).await {
                    if count == 0 {
                        break;
                    }
                    kept.lock().unwrap().extend_from_slice(&buffer[..count]);
                }
            });
        }
    });
    (port, all)
}

/// The same for datagrams.
async fn collecting_udp() -> (u16, Arc<Mutex<Vec<u8>>>) {
    let socket = UdpSocket::bind("127.0.0.1:0").await.unwrap();
    let port = socket.local_addr().unwrap().port();
    let all: Arc<Mutex<Vec<u8>>> = Arc::default();
    let kept = Arc::clone(&all);
    tokio::spawn(async move {
        let mut buffer = vec![0u8; 65536];
        while let Ok(count) = socket.recv(&mut buffer).await {
            let mut kept = kept.lock().unwrap();
            kept.extend_from_slice(&buffer[..count]);
            kept.push(b'\n');
        }
    });
    (port, all)
}

/// Sends a `GET` and returns everything that comes back, head and body.
async fn raw_get(port: u16, path: &str) -> Vec<u8> {
    let mut stream = TcpStream::connect(("127.0.0.1", port)).await.unwrap();
    stream
        .write_all(format!("GET {path} HTTP/1.1\r\nhost: localhost\r\n\r\n").as_bytes())
        .await
        .unwrap();
    let mut answer = Vec::new();
    soon(stream.read_to_end(&mut answer)).await.unwrap();
    answer
}

/// Everything the receivers of a webhook were sent: heads and bodies.
fn requests_of(receiver: &Receiver) -> Vec<u8> {
    let mut all = Vec::new();
    for request in receiver.received() {
        all.extend_from_slice(request.request_line.as_bytes());
        all.push(b'\n');
        for (name, value) in &request.headers {
            all.extend_from_slice(format!("{name}: {value}\n").as_bytes());
        }
        all.extend_from_slice(&request.body);
        all.push(b'\n');
    }
    all
}

/// Whether `haystack` contains `needle`.
fn contains(haystack: &[u8], needle: &[u8]) -> bool {
    haystack
        .windows(needle.len())
        .any(|window| window == needle)
}

#[tokio::test]
async fn nothing_that_went_in_as_a_secret_comes_out_anywhere() {
    // ------------------------------------------------------------------
    // What goes in
    // ------------------------------------------------------------------
    let authority = Authority::new("the authority of the leak test");
    let listener_identity = authority.issue(&["localhost"]);
    let secrets = Secrets::new(&listener_identity.key_der, &listener_identity.key_pem);
    let all_secrets = secrets.all();
    let search = Search::new(&all_secrets);
    the_search_finds_what_is_planted(&search);

    // ------------------------------------------------------------------
    // What pgsnare talks to
    // ------------------------------------------------------------------
    let database = Database::asking_for_a_password().await;
    // The first receiver refuses once, so that a failed delivery and its
    // retry are part of what is written.
    let receiver_identity = authority.issue(&["localhost"]);
    let first_receiver = Receiver::tls(
        &receiver_identity,
        &[Answer::Status(503)],
        Answer::Status(200),
    )
    .await;
    let second_receiver = Receiver::tls(&receiver_identity, &[], Answer::Status(200)).await;
    let (syslog_udp, syslog_datagrams) = collecting_udp().await;
    let (syslog_tcp, syslog_stream) = collecting_tcp().await;

    // ------------------------------------------------------------------
    // The files of the process
    // ------------------------------------------------------------------
    let dir = TempDir::new();
    let (port, admin, metrics) = (free_port(), free_port(), free_port());
    let authority_file = dir.write("ca.crt", authority.pem().as_bytes());
    let certificate = dir.write("server.crt", listener_identity.cert_pem.as_bytes());
    let private_key = dir.write("server.key", listener_identity.key_pem.as_bytes());
    let signing_key = dir.write("webhook.key", &secrets.key_in_file.bytes);
    let secret_url = format!(
        "https://localhost:{}{}",
        first_receiver.address.port(),
        secrets.url_path.text()
    );
    let url_file = dir.write("webhook.url", format!("{secret_url}\n").as_bytes());
    let events_file = dir.path("events.jsonl");
    std::fs::create_dir_all(dir.path("tokens")).unwrap();
    dir.write(
        "tokens/more.yaml",
        format!(
            "tokens:\n  - id: leak-hex\n    values: [{}]\n  - id: leak-cut\n    values: [{}]\n",
            yaml_quoted(secrets.token_hex.text()),
            yaml_quoted(secrets.token_cut.text()),
        )
        .as_bytes(),
    );
    let config = dir.write(
        "pgsnare.yaml",
        format!(
            "listeners:\n  - name: main\n    listen: 127.0.0.1:{port}\n    upstream: {database}\n    \
             client_tls: {{ mode: prefer, cert: {certificate}, key: {private_key} }}\n    \
             upstream_tls: {{ mode: disable }}\n\
             inspection:\n  on_error: fail_open\n\
             token_files:\n  - tokens/*.yaml\n\
             tokens:\n  - id: leak-user\n    values: [{user}]\n  - id: leak-quoted\n    values: [{quoted}]\n\
             \x20 - id: leak-folded\n    values: [{folded}]\n    case_insensitive: true\n\
             events:\n  query_redaction: full\n  labels: {{ environment: leak-test }}\n  \
             labels_from_env: [POD_NAME]\n  sinks:\n    \
             - {{ type: webhook, url_file: {url_file}, hmac_secret_file: {signing_key} }}\n    \
             - {{ type: webhook, url: \"https://localhost:{second}/second\", hmac_secret_env: PGSNARE_LEAK_TEST_KEY }}\n    \
             - {{ type: stdout }}\n    \
             - {{ type: file, path: {events_file} }}\n    \
             - {{ type: syslog, address: \"127.0.0.1:{syslog_udp}\", transport: udp }}\n    \
             - {{ type: syslog, address: \"127.0.0.1:{syslog_tcp}\", transport: tcp }}\n\
             admin:\n  listen: 127.0.0.1:{admin}\nmetrics:\n  listen: 127.0.0.1:{metrics}\n\
             shutdown:\n  grace_period: 1s\n",
            database = database.address,
            certificate = certificate.display(),
            private_key = private_key.display(),
            user = yaml_quoted(secrets.token_user.text()),
            quoted = yaml_quoted(secrets.token_quoted.text()),
            folded = yaml_quoted(secrets.token_folded.text()),
            url_file = url_file.display(),
            signing_key = signing_key.display(),
            second = second_receiver.address.port(),
            events_file = events_file.display(),
        )
        .as_bytes(),
    );

    // ------------------------------------------------------------------
    // The process, and the traffic through it
    // ------------------------------------------------------------------
    let environment = [
        // The system's certificate store, for the receivers of the test.
        ("SSL_CERT_FILE", authority_file.to_str().unwrap()),
        ("POD_NAME", "pgsnare-0"),
        ("PGSNARE_LEAK_TEST_KEY", secrets.key_in_environment.text()),
    ];
    let mut pgsnare = Pgsnare::run(&config, &environment);
    pgsnare.listening(port).await;

    // A session that logs in under a honeytoken, with a password, and
    // names itself with another honeytoken in another letter case.
    let mut first = TcpStream::connect(("127.0.0.1", port)).await.unwrap();
    start_session(
        &mut first,
        secrets.token_user.text(),
        "shop",
        &secrets.token_folded.text().to_uppercase(),
        Some(secrets.password.text()),
    )
    .await;
    // Statements with a honeytoken, with one in hexadecimal and with a
    // password, and a parameter of a prepared statement.
    let statement = format!(
        "SELECT '{}', '\\x{}'; ALTER ROLE app PASSWORD '{}'",
        secrets.token_quoted.text(),
        String::from_utf8(hex(&secrets.token_hex.bytes, false)).unwrap(),
        secrets.statement_password.text()
    );
    first.write_all(&query(&statement)).await.unwrap();
    soon(read_until_ready(&mut first)).await.unwrap();
    first
        .write_all(&bind(&secrets.bind_parameter.bytes))
        .await
        .unwrap();
    // Then a message that cannot be followed, which is what raises an
    // event today. The event names the user and the application.
    first.write_all(&BROKEN).await.unwrap();

    // A session over TLS, which is what the private key is for. Its
    // application name is cut in the middle of a honeytoken, twenty bytes
    // into the value.
    let mut tls = TcpStream::connect(("127.0.0.1", port)).await.unwrap();
    tls.write_all(&[0, 0, 0, 8, 0x04, 0xd2, 0x16, 0x2f])
        .await
        .unwrap();
    let mut answer = [0u8; 1];
    soon(tls.read_exact(&mut answer)).await.unwrap();
    assert_eq!(&answer, b"S", "the listener offers TLS");
    let client = ClientConfig::builder_with_provider(pgsnare::tls::provider())
        .with_safe_default_protocol_versions()
        .unwrap()
        .with_root_certificates(authority.roots())
        .with_no_client_auth();
    let mut tls = soon(
        TlsConnector::from(Arc::new(client))
            .connect(ServerName::try_from("localhost").unwrap(), tls),
    )
    .await
    .unwrap();
    let long_name = format!("{}{}", "a".repeat(236), secrets.token_cut.text());
    start_session(
        &mut tls,
        &String::from_utf8(hex(&secrets.token_hex.bytes, false)).unwrap(),
        "shop",
        &long_name,
        Some(secrets.password.text()),
    )
    .await;
    tls.write_all(&BROKEN).await.unwrap();
    tls.flush().await.unwrap();

    // A client that never gets as far as a login, for the lines the log
    // has about that.
    let mut lost = TcpStream::connect(("127.0.0.1", port)).await.unwrap();
    lost.write_all(b"\x00\x00\x00\x08garbage that is no startup packet")
        .await
        .unwrap();
    let mut nothing = Vec::new();
    let _ = soon(lost.read_to_end(&mut nothing)).await;

    // ------------------------------------------------------------------
    // Everything that comes out
    // ------------------------------------------------------------------
    // The two events of the messages that could not be followed, and the
    // hits the honeytokens in this traffic raised, to six sinks. How many
    // events the hits make depends on how they are folded, so the counts
    // are the least there can be.
    until(|| pgsnare.stdout.lines().len() >= 2).await;
    until(|| {
        pgsnare
            .stdout
            .lines()
            .iter()
            .any(|line| line.contains("\"kind\":\"token_hit\""))
    })
    .await;
    until(|| first_receiver.count() >= 3 && second_receiver.count() >= 2).await;
    until(|| std::fs::read_to_string(&events_file).is_ok_and(|text| text.lines().count() >= 2))
        .await;
    until(|| {
        syslog_datagrams
            .lock()
            .unwrap()
            .iter()
            .filter(|byte| **byte == b'\n')
            .count()
            >= 2
    })
    .await;
    until(|| contains(&syslog_stream.lock().unwrap(), b"\"tls\":true")).await;

    let metrics_answer = raw_get(metrics, "/metrics").await;
    let healthz = raw_get(admin, "/healthz").await;
    let readyz = raw_get(admin, "/readyz").await;
    let mut checks = Vec::new();
    for arguments in [
        &["healthcheck", "--config", config.to_str().unwrap()][..],
        &[
            "healthcheck",
            "--ready",
            "--config",
            config.to_str().unwrap(),
        ],
    ] {
        let mut check = Pgsnare::start(arguments, &[]);
        assert!(check.ended().await.success());
        checks.extend(check.stdout.bytes());
        checks.extend(check.stderr.bytes());
    }

    drop((first, tls));
    pgsnare.signal(Signal::TERM);
    let status = pgsnare.ended().await;
    assert!(status.success(), "{status}: {}", pgsnare.stderr.text());

    // The check of a proxy that is gone says why it failed.
    let mut check = Pgsnare::start(&["healthcheck", "--config", config.to_str().unwrap()], &[]);
    assert_eq!(check.ended().await.code(), Some(1));
    checks.extend(check.stdout.bytes());
    checks.extend(check.stderr.bytes());

    // A start that is refused, because one honeytoken value contains
    // another: the reason must name the tokens and show no value.
    let refused_config = dir.write(
        "refused.yaml",
        format!(
            "listeners:\n  - name: main\n    listen: 127.0.0.1:{port}\n    upstream: {}\n    \
             client_tls: {{ mode: disable }}\n    upstream_tls: {{ mode: disable }}\n\
             tokens:\n  - id: inner\n    values: [{}]\n  - id: outer\n    values: [{}]\n\
             events:\n  sinks:\n    - type: stdout\n",
            database.address,
            yaml_quoted(secrets.token_user.text()),
            yaml_quoted(&format!("x-{}-x", secrets.token_user.text())),
        )
        .as_bytes(),
    );
    let mut refused = Pgsnare::run(&refused_config, &[]);
    assert_eq!(refused.ended().await.code(), Some(1));
    let mut refused_output = refused.stdout.bytes();
    refused_output.extend(refused.stderr.bytes());

    let outputs = [
        Output {
            name: "standard output, where the stdout sink writes",
            bytes: pgsnare.stdout.bytes(),
        },
        Output {
            name: "standard error, where the log goes",
            bytes: pgsnare.stderr.bytes(),
        },
        Output {
            name: "the file of the file sink",
            bytes: std::fs::read(&events_file).unwrap(),
        },
        Output {
            name: "the datagrams of the syslog sink",
            bytes: syslog_datagrams.lock().unwrap().clone(),
        },
        Output {
            name: "the stream of the syslog sink",
            bytes: syslog_stream.lock().unwrap().clone(),
        },
        Output {
            name: "the requests to the first webhook receiver",
            bytes: requests_of(&first_receiver),
        },
        Output {
            name: "the requests to the second webhook receiver",
            bytes: requests_of(&second_receiver),
        },
        Output {
            name: "the answer of the metrics endpoint",
            bytes: metrics_answer,
        },
        Output {
            name: "the answer of /healthz",
            bytes: healthz,
        },
        Output {
            name: "the answer of /readyz",
            bytes: readyz,
        },
        Output {
            name: "the output of pgsnare healthcheck",
            bytes: checks,
        },
        Output {
            name: "the output of a start that was refused",
            bytes: refused_output,
        },
    ];

    // ------------------------------------------------------------------
    // The secrets were where they could have leaked from
    // ------------------------------------------------------------------
    // Every output was written to.
    for output in &outputs {
        assert!(!output.bytes.is_empty(), "{} is empty", output.name);
    }
    // The database got every secret a client sent, through the proxy.
    let reached_database = database.received();
    for secret in [
        &secrets.token_user,
        &secrets.token_quoted,
        &secrets.token_cut,
        &secrets.password,
        &secrets.statement_password,
        &secrets.bind_parameter,
    ] {
        assert!(
            contains(&reached_database, &secret.bytes),
            "{} did not reach the database",
            secret.name
        );
    }
    assert!(contains(
        &reached_database,
        secrets.token_folded.text().to_uppercase().as_bytes()
    ));
    assert!(contains(
        &reached_database,
        &hex(&secrets.token_hex.bytes, false)
    ));
    // Both signing keys were used: a receiver that holds the key accepts
    // what was sent with it.
    for (receiver, key) in [
        (&first_receiver, &secrets.key_in_file),
        (&second_receiver, &secrets.key_in_environment),
    ] {
        let mut verifier = Verifier::new(&key.bytes, Duration::from_secs(300));
        assert_eq!(verifier.check_received(&receiver.received()[0]), Ok(()));
    }
    // The secret URL was used: the first receiver was asked at its path.
    assert!(
        first_receiver.received()[0]
            .request_line
            .contains(secrets.url_path.text())
    );
    // The log has the lines of a delivery that failed and of a client
    // that was turned away.
    let log = pgsnare.stderr.text();
    assert!(log.contains("will be tried again"), "{log}");
    assert!(log.contains("could not be followed"), "{log}");
    assert!(
        String::from_utf8_lossy(&outputs[11].bytes).contains("pgsnare cannot go on"),
        "the refused start says so"
    );

    // ------------------------------------------------------------------
    // And none of them came out
    // ------------------------------------------------------------------
    let found = search.leaks(&outputs);
    assert!(
        found.is_empty(),
        "secrets came out of pgsnare:\n{}",
        found
            .iter()
            .map(|leak| format!(
                "  {:?}: {} {}, in {}",
                leak.kind, leak.secret, leak.form, leak.output
            ))
            .collect::<Vec<_>>()
            .join("\n")
    );

    // ------------------------------------------------------------------
    // And what stands in their place says that something was taken out
    // ------------------------------------------------------------------
    // The events are about those sessions, with the values taken out.
    let events = pgsnare.stdout.text();
    assert!(events.contains("\"db_user\":\"[redacted]\""), "{events}");
    assert!(
        events.contains("\"application_name\":\"[redacted]\""),
        "{events}"
    );
    assert!(
        events.contains(&format!("{}[redacted]\u{2026}\"", "a".repeat(236))),
        "{events}"
    );
    assert!(events.contains("\"tls\":true"), "{events}");
}
