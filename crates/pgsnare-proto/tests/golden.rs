// SPDX-License-Identifier: Apache-2.0

//! Golden-byte tests: the crate reads traffic captured from real PostgreSQL
//! servers.
//!
//! The fixtures in `tests/fixtures/` hold, for PostgreSQL 15 to 18 and for
//! protocol 3.0 and 3.2, what a client and a server sent each other in a
//! set of scenarios. `tests/fixtures/README.md` describes them and how they
//! were captured. Every value in them is synthetic.
//!
//! The tests do not depend on the values that change from one capture to
//! the next: salts, nonces, cancel keys and process ids.

use std::collections::BTreeSet;
use std::fs;
use std::path::PathBuf;

use pgsnare_proto::backend::{self, Authentication, CopyKind, TransactionStatus, error_field};
use pgsnare_proto::frontend::{self, Target};
use pgsnare_proto::startup::{self, Classification, StartupMessage, StartupPacket};
use pgsnare_proto::{Direction, FormatCode, Frame, Framer, Limits, ProtocolVersion, Step, encode};

/// One directory of fixtures: a server version and the protocol version
/// the client asked for.
struct Capture {
    dir: &'static str,
    server_major: u32,
    protocol: ProtocolVersion,
}

const CAPTURES: [Capture; 5] = [
    Capture {
        dir: "pg15-3.0",
        server_major: 15,
        protocol: ProtocolVersion::V3_0,
    },
    Capture {
        dir: "pg16-3.0",
        server_major: 16,
        protocol: ProtocolVersion::V3_0,
    },
    Capture {
        dir: "pg17-3.0",
        server_major: 17,
        protocol: ProtocolVersion::V3_0,
    },
    Capture {
        dir: "pg18-3.0",
        server_major: 18,
        protocol: ProtocolVersion::V3_0,
    },
    Capture {
        dir: "pg18-3.2",
        server_major: 18,
        protocol: ProtocolVersion::V3_2,
    },
];

impl Capture {
    /// The length of the cancel key the server issues: 4 bytes in protocol
    /// 3.0, and 32 bytes from PostgreSQL 18 in protocol 3.2.
    fn key_len(&self) -> usize {
        if self.protocol == ProtocolVersion::V3_2 {
            32
        } else {
            4
        }
    }

    fn path(&self, file: &str) -> PathBuf {
        fixtures_dir().join(self.dir).join(file)
    }

    fn has(&self, file: &str) -> bool {
        self.path(file).exists()
    }

    fn read(&self, file: &str) -> Vec<u8> {
        let path = self.path(file);
        fs::read(&path).unwrap_or_else(|error| panic!("{}/{file}: {error}", self.dir))
    }

    fn client(&self, scenario: &str) -> Vec<u8> {
        self.read(&format!("{scenario}.client.bin"))
    }

    fn server(&self, scenario: &str) -> Vec<u8> {
        self.read(&format!("{scenario}.server.bin"))
    }
}

fn fixtures_dir() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("tests/fixtures")
}

fn text(bytes: &[u8]) -> &str {
    std::str::from_utf8(bytes).expect("the fixtures hold text in UTF-8")
}

/// Splits a stream into frames. The stream must consist of whole frames
/// and nothing else.
fn frames(direction: Direction, stream: &[u8]) -> Vec<Frame<'_>> {
    let mut framer = Framer::new(direction, Limits::buffered_only(1 << 20));
    let mut unread = stream;
    let mut found = Vec::new();
    loop {
        match framer.next(&mut unread) {
            Ok(Step::Frame(frame)) => found.push(frame),
            Ok(Step::NeedMore(_)) if unread.is_empty() => return found,
            other => panic!(
                "not a sequence of whole frames: {other:?} with {} bytes unread",
                unread.len()
            ),
        }
    }
}

/// What a client sent on one connection: the startup-phase packets, then
/// frames.
struct ClientSide<'a> {
    packets: Vec<StartupPacket<'a>>,
    frames: Vec<Frame<'a>>,
}

impl<'a> ClientSide<'a> {
    fn read(stream: &'a [u8]) -> Self {
        let mut rest = stream;
        let mut packets = Vec::new();
        loop {
            let packet = match StartupPacket::parse(rest) {
                Ok(Some(packet)) => packet,
                other => panic!("expected a startup-phase packet, got {other:?}"),
            };
            rest = &rest[packet.wire_len()..];
            packets.push(packet);
            // A request for encryption is followed by another packet.
            if !matches!(
                packet,
                StartupPacket::SslRequest | StartupPacket::GssEncRequest
            ) {
                break;
            }
        }
        let frames = frames(Direction::FromClient, rest);
        Self { packets, frames }
    }

    fn startup(&self) -> StartupMessage<'a> {
        match self.packets.last() {
            Some(StartupPacket::StartupMessage(message)) => *message,
            other => panic!("expected a startup message, got {other:?}"),
        }
    }

    fn asked_for_encryption(&self) -> bool {
        matches!(self.packets.first(), Some(StartupPacket::SslRequest))
    }

    fn messages(&self) -> Vec<frontend::Message<'a>> {
        self.frames
            .iter()
            .map(|frame| {
                frontend::Message::from_frame(*frame).expect("a real client message parses")
            })
            .collect()
    }
}

/// The frames a server sent on one connection. When the client had asked
/// for encryption, the stream starts with the one-byte answer.
fn server_frames(stream: &[u8], asked_for_encryption: bool) -> Vec<Frame<'_>> {
    let stream = if asked_for_encryption {
        let (answer, rest) = stream.split_first().expect("the server answered");
        assert_eq!(*answer, startup::ENCRYPTION_REFUSED);
        rest
    } else {
        stream
    };
    frames(Direction::FromServer, stream)
}

fn server_messages(stream: &[u8]) -> Vec<backend::Message<'_>> {
    server_frames(stream, false)
        .into_iter()
        .map(|frame| backend::Message::from_frame(frame).expect("a real server message parses"))
        .collect()
}

fn backend_kind(message: &backend::Message<'_>) -> &'static str {
    use backend::Message;
    match message {
        Message::Authentication(Authentication::Ok) => "AuthenticationOk",
        Message::Authentication(Authentication::CleartextPassword) => {
            "AuthenticationCleartextPassword"
        }
        Message::Authentication(Authentication::Md5Password { .. }) => "AuthenticationMD5Password",
        Message::Authentication(Authentication::Sasl(_)) => "AuthenticationSASL",
        Message::Authentication(Authentication::SaslContinue { .. }) => {
            "AuthenticationSASLContinue"
        }
        Message::Authentication(Authentication::SaslFinal { .. }) => "AuthenticationSASLFinal",
        Message::Authentication(_) => "Authentication (other)",
        Message::BackendKeyData(_) => "BackendKeyData",
        Message::ParameterStatus(_) => "ParameterStatus",
        Message::NegotiateProtocolVersion(_) => "NegotiateProtocolVersion",
        Message::RowDescription(_) => "RowDescription",
        Message::DataRow(_) => "DataRow",
        Message::CommandComplete(_) => "CommandComplete",
        Message::ReadyForQuery(_) => "ReadyForQuery",
        Message::ErrorResponse(_) => "ErrorResponse",
        Message::NoticeResponse(_) => "NoticeResponse",
        Message::NotificationResponse(_) => "NotificationResponse",
        Message::CopyResponse(copy) => match copy.kind() {
            CopyKind::In => "CopyInResponse",
            CopyKind::Out => "CopyOutResponse",
            CopyKind::Both => "CopyBothResponse",
        },
        Message::CopyData(_) => "CopyData from the server",
        Message::Other(_) => "other server message",
    }
}

fn frontend_kind(message: &frontend::Message<'_>) -> &'static str {
    use frontend::Message;
    match message {
        Message::Query(_) => "Query",
        Message::Parse(_) => "Parse",
        Message::Bind(_) => "Bind",
        Message::Describe(_) => "Describe",
        Message::Execute(_) => "Execute",
        Message::Close(_) => "Close",
        Message::CopyData(_) => "CopyData from the client",
        Message::Other(_) => "other client message",
    }
}

/// The scenarios of a capture directory: the names of its client streams.
fn scenarios(capture: &Capture) -> Vec<String> {
    let mut names: Vec<String> = fs::read_dir(fixtures_dir().join(capture.dir))
        .unwrap_or_else(|error| panic!("{}: {error}", capture.dir))
        .map(|entry| entry.unwrap().file_name().into_string().unwrap())
        .filter_map(|name| name.strip_suffix(".client.bin").map(str::to_owned))
        .collect();
    names.sort();
    names
}

/// Every stream of every capture is framed without a byte left over, and
/// every frame is read by its view without an error. Together the
/// captures show every view real traffic, except those noted at the end.
#[test]
fn every_capture_is_read_in_full() {
    let mut seen = BTreeSet::new();
    let mut streams = 0;

    for capture in &CAPTURES {
        assert!(capture.has("MANIFEST.txt"), "{}", capture.dir);
        let scenarios = scenarios(capture);
        assert!(scenarios.len() >= 10, "{}: {scenarios:?}", capture.dir);

        for scenario in &scenarios {
            let client_bytes = capture.client(scenario);
            let server_bytes = capture.server(scenario);
            streams += 2;

            if startup::classify(&client_bytes) == Ok(Classification::DirectTls) {
                seen.insert("direct TLS");
                continue;
            }

            let client = ClientSide::read(&client_bytes);
            for packet in &client.packets {
                seen.insert(match packet {
                    StartupPacket::SslRequest => "SSLRequest",
                    StartupPacket::GssEncRequest => "GSSENCRequest",
                    StartupPacket::CancelRequest(_) => "CancelRequest",
                    StartupPacket::StartupMessage(_) => "StartupMessage",
                });
            }
            for message in client.messages() {
                seen.insert(frontend_kind(&message));
            }

            let asked = client.asked_for_encryption();
            for frame in server_frames(&server_bytes, asked) {
                let message = backend::Message::from_frame(frame).unwrap_or_else(|error| {
                    panic!("{}/{scenario}: {error} in {frame:?}", capture.dir)
                });
                seen.insert(backend_kind(&message));
            }
        }
    }

    assert_eq!(streams, 124, "a fixture was added or removed");
    let expected = [
        "AuthenticationCleartextPassword",
        "AuthenticationMD5Password",
        "AuthenticationOk",
        "AuthenticationSASL",
        "AuthenticationSASLContinue",
        "AuthenticationSASLFinal",
        "BackendKeyData",
        "Bind",
        "CancelRequest",
        "Close",
        "CommandComplete",
        "CopyBothResponse",
        "CopyData from the client",
        "CopyData from the server",
        "CopyInResponse",
        "CopyOutResponse",
        "DataRow",
        "Describe",
        "ErrorResponse",
        "Execute",
        "NegotiateProtocolVersion",
        "NoticeResponse",
        "NotificationResponse",
        "ParameterStatus",
        "Parse",
        "Query",
        "ReadyForQuery",
        "RowDescription",
        "SSLRequest",
        "StartupMessage",
        "direct TLS",
        "other client message",
        "other server message",
    ];
    // Not captured, and covered by unit tests and fuzzing only:
    // GSSENCRequest and the Kerberos, GSSAPI and SSPI authentication
    // messages, which need a Kerberos setup to occur.
    assert_eq!(seen.into_iter().collect::<Vec<_>>(), expected);
}

/// A frame as the framer reported it, with a streamed body joined.
fn collect(
    direction: Direction,
    limits: Limits,
    stream: &[u8],
    piece_len: usize,
) -> Vec<(u8, Vec<u8>)> {
    let mut framer = Framer::new(direction, limits);
    let mut pending: Vec<u8> = Vec::new();
    let mut found: Vec<(u8, Vec<u8>)> = Vec::new();
    for piece in stream.chunks(piece_len) {
        pending.extend_from_slice(piece);
        let mut unread = &pending[..];
        loop {
            match framer
                .next(&mut unread)
                .expect("captured streams are well-formed")
            {
                Step::Frame(frame) => found.push((frame.tag(), frame.body().to_vec())),
                Step::StreamStart(header) => found.push((header.tag(), Vec::new())),
                Step::StreamChunk(chunk) => {
                    found.last_mut().unwrap().1.extend_from_slice(chunk.data());
                }
                Step::NeedMore(_) => break,
            }
        }
        let consumed = pending.len() - unread.len();
        pending.drain(..consumed);
    }
    assert!(pending.is_empty(), "bytes left over");
    assert!(framer.is_at_frame_boundary());
    found
}

/// Real streams yield the same frames whether they arrive at once, one
/// byte at a time, or with every frame above a few bytes streamed.
#[test]
fn captured_streams_frame_the_same_in_pieces() {
    for capture in &CAPTURES {
        for scenario in scenarios(capture) {
            let client_bytes = capture.client(&scenario);
            let server_bytes = capture.server(&scenario);
            if startup::classify(&client_bytes) == Ok(Classification::DirectTls) {
                continue;
            }
            let client = ClientSide::read(&client_bytes);
            let startup_len: usize = client.packets.iter().map(StartupPacket::wire_len).sum();
            let answer_len = usize::from(client.asked_for_encryption());

            for (direction, stream) in [
                (Direction::FromClient, &client_bytes[startup_len..]),
                (Direction::FromServer, &server_bytes[answer_len..]),
            ] {
                let whole = Limits::buffered_only(1 << 20);
                let at_once = collect(direction, whole, stream, stream.len().max(1));
                assert_eq!(collect(direction, whole, stream, 1), at_once);
                assert_eq!(collect(direction, whole, stream, 7), at_once);
                let streamed = Limits::new(16, 1 << 20);
                assert_eq!(collect(direction, streamed, stream, 1), at_once);
                assert_eq!(collect(direction, streamed, stream, 1000), at_once);
            }
        }
    }
}

/// The encoders reproduce what real servers and clients sent, byte for
/// byte.
#[test]
fn captured_messages_encode_back_to_the_same_bytes() {
    let mut encoded_kinds = BTreeSet::new();
    for capture in &CAPTURES {
        for scenario in scenarios(capture) {
            let client_bytes = capture.client(&scenario);
            let server_bytes = capture.server(&scenario);
            if startup::classify(&client_bytes) == Ok(Classification::DirectTls) {
                continue;
            }

            let client = ClientSide::read(&client_bytes);
            for packet in &client.packets {
                let mut out = Vec::new();
                let original = match packet {
                    StartupPacket::SslRequest => {
                        encode::ssl_request(&mut out).unwrap();
                        encoded_kinds.insert("SSLRequest");
                        &client_bytes[..8]
                    }
                    StartupPacket::CancelRequest(request) => {
                        encode::cancel_request(
                            request.process_id(),
                            request.secret_key(),
                            &mut out,
                        )
                        .unwrap();
                        encoded_kinds.insert("CancelRequest");
                        request.as_bytes()
                    }
                    StartupPacket::StartupMessage(message) => {
                        let parameters: Vec<(&[u8], &[u8])> = message
                            .parameters()
                            .map(|parameter| (parameter.name(), parameter.value()))
                            .collect();
                        encode::startup_message(message.version(), &parameters, &mut out).unwrap();
                        encoded_kinds.insert("StartupMessage");
                        message.as_bytes()
                    }
                    StartupPacket::GssEncRequest => continue,
                };
                assert_eq!(out, original, "{}/{scenario}", capture.dir);
            }

            for frame in server_frames(&server_bytes, client.asked_for_encryption()) {
                let mut out = Vec::new();
                match backend::Message::from_frame(frame).unwrap() {
                    backend::Message::Authentication(Authentication::Sasl(mechanisms)) => {
                        let names: Vec<&[u8]> = mechanisms.iter().collect();
                        encode::authentication_sasl(&names, &mut out).unwrap();
                        encoded_kinds.insert("AuthenticationSASL");
                    }
                    backend::Message::NegotiateProtocolVersion(negotiate) => {
                        let options: Vec<&[u8]> = negotiate.options().collect();
                        encode::negotiate_protocol_version(negotiate.version(), &options, &mut out)
                            .unwrap();
                        encoded_kinds.insert("NegotiateProtocolVersion");
                    }
                    backend::Message::DataRow(row) => {
                        let columns: Vec<Option<&[u8]>> = row.iter().collect();
                        encode::data_row(&columns, &mut out).unwrap();
                        encoded_kinds.insert("DataRow");
                    }
                    backend::Message::CommandComplete(complete) => {
                        encode::command_complete(complete.tag(), &mut out).unwrap();
                        if let Some((command, rows)) = complete.split_rows() {
                            let mut with_rows = Vec::new();
                            encode::command_complete_with_rows(command, rows, &mut with_rows)
                                .unwrap();
                            assert_eq!(with_rows, frame.as_bytes());
                            encoded_kinds.insert("CommandComplete with a row count");
                        }
                        encoded_kinds.insert("CommandComplete");
                    }
                    backend::Message::ErrorResponse(error) => {
                        let fields: Vec<(u8, &[u8])> = error
                            .fields()
                            .iter()
                            .map(|field| (field.code(), field.value()))
                            .collect();
                        encode::error_response(&fields, &mut out).unwrap();
                        encoded_kinds.insert("ErrorResponse");
                    }
                    _ => continue,
                }
                assert_eq!(out, frame.as_bytes(), "{}/{scenario}", capture.dir);
            }
        }
    }
    let expected = [
        "AuthenticationSASL",
        "CancelRequest",
        "CommandComplete",
        "CommandComplete with a row count",
        "DataRow",
        "ErrorResponse",
        "NegotiateProtocolVersion",
        "SSLRequest",
        "StartupMessage",
    ];
    assert_eq!(encoded_kinds.into_iter().collect::<Vec<_>>(), expected);
}

#[test]
fn startup_messages() {
    for capture in &CAPTURES {
        let bytes = capture.client("simple");
        let client = ClientSide::read(&bytes);
        assert_eq!(client.packets.len(), 1);
        let startup = client.startup();
        assert_eq!(startup.version(), capture.protocol, "{}", capture.dir);
        assert_eq!(startup.as_bytes().len(), 61);
        let parameters: Vec<(&str, &str)> = startup
            .parameters()
            .map(|parameter| (text(parameter.name()), text(parameter.value())))
            .collect();
        assert_eq!(
            parameters,
            [
                ("user", "app_scram"),
                ("database", "appdb"),
                ("application_name", "psql"),
            ]
        );
        assert_eq!(startup.get(b"user"), Some(&b"app_scram"[..]));
        assert_eq!(startup.get(b"options"), None);
        assert!(
            startup
                .parameters()
                .all(|parameter| !parameter.is_protocol_option())
        );

        // A replication connection says so in a parameter.
        let bytes = capture.client("replication");
        let startup = ClientSide::read(&bytes).startup();
        assert_eq!(startup.get(b"replication"), Some(&b"database"[..]));
        assert_eq!(startup.get(b"user"), Some(&b"app_repl"[..]));
    }
}

#[test]
fn scram_login_and_session_setup() {
    for capture in &CAPTURES {
        let bytes = capture.server("simple");
        let messages = server_messages(&bytes);
        let mut messages = messages.iter();

        let Some(backend::Message::Authentication(Authentication::Sasl(mechanisms))) =
            messages.next()
        else {
            panic!("{}: expected AuthenticationSASL first", capture.dir);
        };
        // Without TLS the server offers no channel binding.
        assert_eq!(
            mechanisms.iter().collect::<Vec<_>>(),
            [&b"SCRAM-SHA-256"[..]]
        );
        assert!(mechanisms.contains(b"SCRAM-SHA-256"));
        assert!(!mechanisms.contains(b"SCRAM-SHA-256-PLUS"));

        let Some(backend::Message::Authentication(Authentication::SaslContinue { data })) =
            messages.next()
        else {
            panic!("{}: expected AuthenticationSASLContinue", capture.dir);
        };
        assert!(data.starts_with(b"r="));
        let Some(backend::Message::Authentication(Authentication::SaslFinal { data })) =
            messages.next()
        else {
            panic!("{}: expected AuthenticationSASLFinal", capture.dir);
        };
        assert!(data.starts_with(b"v="));
        assert_eq!(
            messages.next(),
            Some(&backend::Message::Authentication(Authentication::Ok))
        );

        // The parameters the server reports, up to BackendKeyData.
        let mut parameters = Vec::new();
        let key_data = loop {
            match messages.next() {
                Some(backend::Message::ParameterStatus(status)) => {
                    parameters.push((text(status.name()), text(status.value())));
                }
                Some(backend::Message::BackendKeyData(key_data)) => break key_data,
                other => panic!("{}: unexpected {other:?}", capture.dir),
            }
        };
        assert!(parameters.len() >= 13, "{parameters:?}");
        let value_of = |name: &str| {
            parameters
                .iter()
                .find(|(parameter, _)| *parameter == name)
                .map(|(_, value)| *value)
        };
        let version = value_of("server_version").expect("server_version is reported");
        assert!(
            version.starts_with(&format!("{}.", capture.server_major)),
            "{}: {version}",
            capture.dir
        );
        assert_eq!(value_of("client_encoding"), Some("UTF8"));
        assert_eq!(value_of("session_authorization"), Some("app_scram"));
        assert_eq!(value_of("application_name"), Some("psql"));
        assert_eq!(value_of("standard_conforming_strings"), Some("on"));

        // The cancel key is read by its length: 4 bytes in protocol 3.0,
        // 32 bytes from PostgreSQL 18 in protocol 3.2.
        assert_eq!(
            key_data.secret_key().len(),
            capture.key_len(),
            "{}",
            capture.dir
        );
        assert!(key_data.process_id() > 0);

        let Some(backend::Message::ReadyForQuery(ready)) = messages.next() else {
            panic!("{}: expected ReadyForQuery", capture.dir);
        };
        assert_eq!(ready.status(), TransactionStatus::Idle);
    }
}

#[test]
fn simple_query_results() {
    for capture in &CAPTURES {
        // What the client asked.
        let client_bytes = capture.client("simple");
        let client = ClientSide::read(&client_bytes);
        let queries: Vec<&str> = client
            .messages()
            .iter()
            .filter_map(|message| match message {
                frontend::Message::Query(query) => Some(text(query.sql())),
                _ => None,
            })
            .collect();
        assert_eq!(queries.len(), 21);
        assert_eq!(
            queries[0],
            "SELECT 1 AS one, 'text' AS t, NULL::int AS n, ''::text AS empty;"
        );
        // Two statements in one Query message.
        assert_eq!(queries[3], "SELECT 1 AS first ; SELECT 2 AS second;");
        assert_eq!(
            client.frames.last().map(Frame::tag),
            Some(frontend::tag::TERMINATE)
        );

        // What the server answered, from the first ReadyForQuery on.
        let server_bytes = capture.server("simple");
        let messages = server_messages(&server_bytes);
        let login_end = messages
            .iter()
            .position(|message| matches!(message, backend::Message::ReadyForQuery(_)))
            .unwrap();
        let process_id = messages
            .iter()
            .find_map(|message| match message {
                backend::Message::BackendKeyData(key_data) => Some(key_data.process_id()),
                _ => None,
            })
            .unwrap();
        let results = &messages[login_end + 1..];

        // The first result: one row of four columns.
        let backend::Message::RowDescription(description) = &results[0] else {
            panic!("{}: expected RowDescription", capture.dir);
        };
        let fields: Vec<_> = description.iter().collect();
        assert_eq!(description.len(), 4);
        assert_eq!(
            fields
                .iter()
                .map(|field| text(field.name()))
                .collect::<Vec<_>>(),
            ["one", "t", "n", "empty"]
        );
        // int4, text, int4, text: computed columns of no table, in text.
        assert_eq!(
            fields
                .iter()
                .map(|field| field.type_oid())
                .collect::<Vec<_>>(),
            [23, 25, 23, 25]
        );
        assert_eq!(
            fields
                .iter()
                .map(|field| field.type_size())
                .collect::<Vec<_>>(),
            [4, -1, 4, -1]
        );
        for field in &fields {
            assert_eq!(field.table_oid(), 0);
            assert_eq!(field.column_id(), 0);
            assert_eq!(field.type_modifier(), -1);
            assert_eq!(field.format(), FormatCode::TEXT);
        }
        let backend::Message::DataRow(row) = &results[1] else {
            panic!("{}: expected DataRow", capture.dir);
        };
        assert_eq!(
            row.iter().collect::<Vec<_>>(),
            [Some(&b"1"[..]), Some(&b"text"[..]), None, Some(&b""[..])]
        );
        let backend::Message::CommandComplete(complete) = &results[2] else {
            panic!("{}: expected CommandComplete", capture.dir);
        };
        assert_eq!(complete.tag(), b"SELECT 1");
        assert_eq!(complete.rows(), Some(1));

        // The second result: three rows of a real table.
        let backend::Message::RowDescription(description) = &results[4] else {
            panic!("{}: expected RowDescription", capture.dir);
        };
        let fields: Vec<_> = description.iter().collect();
        assert_eq!(
            fields
                .iter()
                .map(|field| text(field.name()))
                .collect::<Vec<_>>(),
            ["id", "email", "note"]
        );
        assert!(fields.iter().all(|field| field.table_oid() != 0));
        assert_eq!(
            fields
                .iter()
                .map(|field| field.column_id())
                .collect::<Vec<_>>(),
            [1, 2, 3]
        );
        let rows: Vec<Vec<Option<&str>>> = results[5..8]
            .iter()
            .map(|message| match message {
                backend::Message::DataRow(row) => {
                    row.iter().map(|column| column.map(text)).collect()
                }
                other => panic!("{}: expected DataRow, got {other:?}", capture.dir),
            })
            .collect();
        assert_eq!(
            rows,
            [
                [Some("1"), Some("alice@example.com"), Some("first contact")],
                [Some("2"), Some("bob@example.com"), None],
                [Some("3"), Some("carol@example.com"), Some("")],
            ]
        );

        // A row with one wide column.
        let wide = results
            .iter()
            .find_map(|message| match message {
                backend::Message::DataRow(row) if row.iter().next().flatten()?.len() > 100 => {
                    Some(*row)
                }
                _ => None,
            })
            .unwrap();
        assert_eq!(wide.len(), 1);
        assert_eq!(wide.iter().next(), Some(Some(&[b'x'; 1500][..])));

        // Every command tag, in order.
        let completions: Vec<_> = results
            .iter()
            .filter_map(|message| match message {
                backend::Message::CommandComplete(complete) => Some(*complete),
                _ => None,
            })
            .collect();
        assert_eq!(
            completions
                .iter()
                .map(|complete| text(complete.tag()))
                .collect::<Vec<_>>(),
            [
                "SELECT 1",
                "SELECT 3",
                "SELECT 1",
                "SELECT 1",
                "SELECT 1",
                "CREATE TABLE",
                "BEGIN",
                "INSERT 0 3",
                "UPDATE 2",
                "DELETE 1",
                "SELECT 1",
                "COMMIT",
                "BEGIN",
                "ROLLBACK",
                "DO",
                "SET",
                "LISTEN",
                "NOTIFY",
                "DROP TABLE",
            ]
        );
        assert_eq!(
            completions
                .iter()
                .map(|complete| complete.split_rows())
                .collect::<Vec<_>>(),
            [
                Some((&b"SELECT"[..], 1)),
                Some((&b"SELECT"[..], 3)),
                Some((&b"SELECT"[..], 1)),
                Some((&b"SELECT"[..], 1)),
                Some((&b"SELECT"[..], 1)),
                None,
                None,
                Some((&b"INSERT 0"[..], 3)),
                Some((&b"UPDATE"[..], 2)),
                Some((&b"DELETE"[..], 1)),
                Some((&b"SELECT"[..], 1)),
                None,
                None,
                None,
                None,
                None,
                None,
                None,
                None,
            ]
        );

        // The transaction state after every query.
        use TransactionStatus::{Failed, Idle, InTransaction};
        let states: Vec<_> = results
            .iter()
            .filter_map(|message| match message {
                backend::Message::ReadyForQuery(ready) => Some(ready.status()),
                _ => None,
            })
            .collect();
        assert_eq!(
            states,
            [
                Idle,
                Idle,
                Idle,
                Idle,
                Idle,
                InTransaction,
                InTransaction,
                InTransaction,
                InTransaction,
                InTransaction,
                Idle,
                InTransaction,
                Failed,
                Failed,
                Idle,
                Idle,
                Idle,
                Idle,
                Idle,
                Idle,
                Idle,
            ]
        );

        // The errors: division by zero, a statement in a failed
        // transaction, and a syntax error with its position.
        let errors: Vec<_> = results
            .iter()
            .filter_map(|message| match message {
                backend::Message::ErrorResponse(error) => Some(error.fields()),
                _ => None,
            })
            .collect();
        assert_eq!(
            errors
                .iter()
                .map(|fields| fields.sqlstate().map(text))
                .collect::<Vec<_>>(),
            [Some("22012"), Some("25P02"), Some("42601")]
        );
        for fields in &errors {
            assert_eq!(fields.severity(), Some(&b"ERROR"[..]));
            assert_eq!(
                fields.get(error_field::SEVERITY_NONLOCALIZED),
                Some(&b"ERROR"[..])
            );
            assert!(fields.get(error_field::FILE).is_some());
            assert!(fields.get(error_field::LINE).is_some());
            assert!(fields.get(error_field::ROUTINE).is_some());
        }
        assert_eq!(errors[0].message(), Some(&b"division by zero"[..]));
        assert_eq!(errors[0].get(error_field::POSITION), None);
        assert_eq!(errors[2].get(error_field::POSITION), Some(&b"1"[..]));

        // The notice raised by the DO block.
        let notice = results
            .iter()
            .find_map(|message| match message {
                backend::Message::NoticeResponse(notice) => Some(notice.fields()),
                _ => None,
            })
            .unwrap();
        assert_eq!(notice.severity(), Some(&b"NOTICE"[..]));
        assert_eq!(notice.sqlstate(), Some(&b"00000"[..]));
        assert_eq!(notice.message(), Some(&b"synthetic notice"[..]));
        assert!(notice.get(error_field::WHERE).is_some());

        // SET makes the server report the new value.
        let reported = results
            .iter()
            .find_map(|message| match message {
                backend::Message::ParameterStatus(status) => Some(*status),
                _ => None,
            })
            .unwrap();
        assert_eq!(reported.name(), b"application_name");
        assert_eq!(reported.value(), b"fixture");

        // The session notified itself.
        let notification = results
            .iter()
            .find_map(|message| match message {
                backend::Message::NotificationResponse(notification) => Some(*notification),
                _ => None,
            })
            .unwrap();
        assert_eq!(notification.channel(), b"fixture_channel");
        assert_eq!(notification.payload(), b"synthetic payload");
        assert_eq!(notification.process_id(), process_id);
    }
}

#[test]
fn extended_query_messages() {
    for capture in &CAPTURES {
        let client_bytes = capture.client("extended");
        let client = ClientSide::read(&client_bytes);
        let messages = client.messages();

        let parses: Vec<_> = messages
            .iter()
            .filter_map(|message| match message {
                frontend::Message::Parse(parse) => Some(*parse),
                _ => None,
            })
            .collect();
        assert_eq!(parses.len(), 8);
        assert_eq!(parses[0].statement(), b"");
        assert_eq!(parses[0].sql(), b"SELECT $1::int + $2::int AS sum ");
        assert!(parses[0].parameter_types().is_empty());
        assert_eq!(parses[1].statement(), b"by_id");
        assert_eq!(
            parses[1].sql(),
            b"SELECT id, email FROM contacts WHERE id = $1 "
        );

        let binds: Vec<_> = messages
            .iter()
            .filter_map(|message| match message {
                frontend::Message::Bind(bind) => Some(*bind),
                _ => None,
            })
            .collect();
        assert_eq!(binds.len(), 8);
        // The unnamed statement with two text parameters.
        assert_eq!(binds[0].portal(), b"");
        assert_eq!(binds[0].statement(), b"");
        assert!(binds[0].parameter_formats().is_empty());
        assert_eq!(
            binds[0].parameter_formats().code_for(1),
            Some(FormatCode::TEXT)
        );
        assert_eq!(
            binds[0].parameters().iter().collect::<Vec<_>>(),
            [Some(&b"40"[..]), Some(&b"2"[..])]
        );
        assert_eq!(
            binds[0].result_formats().iter().collect::<Vec<_>>(),
            [FormatCode::TEXT]
        );
        // The named statement, bound twice.
        assert_eq!(binds[1].statement(), b"by_id");
        assert_eq!(
            binds[1].parameters().iter().collect::<Vec<_>>(),
            [Some(&b"1"[..])]
        );
        assert_eq!(binds[2].statement(), b"by_id");
        assert_eq!(
            binds[2].parameters().iter().collect::<Vec<_>>(),
            [Some(&b"2"[..])]
        );
        // Three parameters.
        assert_eq!(
            binds[4].parameters().iter().collect::<Vec<_>>(),
            [
                Some(&b"4"[..]),
                Some(&b"dave@example.com"[..]),
                Some(&b"added by the fixture"[..])
            ]
        );

        let describes: Vec<_> = messages
            .iter()
            .filter_map(|message| match message {
                frontend::Message::Describe(describe) => Some((describe.target(), describe.name())),
                _ => None,
            })
            .collect();
        assert_eq!(describes.len(), 9);
        assert_eq!(
            describes
                .iter()
                .filter(|(target, _)| *target == Target::Portal)
                .count(),
            8
        );
        // `\gdesc` describes the unnamed statement.
        assert!(describes.contains(&(Target::Statement, &b""[..])));

        let executes: Vec<_> = messages
            .iter()
            .filter_map(|message| match message {
                frontend::Message::Execute(execute) => Some((execute.portal(), execute.max_rows())),
                _ => None,
            })
            .collect();
        assert_eq!(executes, [(&b""[..], 0); 8]);

        let closes: Vec<_> = messages
            .iter()
            .filter_map(|message| match message {
                frontend::Message::Close(close) => Some((close.target(), close.name())),
                _ => None,
            })
            .collect();
        assert_eq!(closes, [(Target::Statement, &b"by_id"[..])]);

        // Sync has no view and passes as a frame.
        assert!(messages.iter().any(|message| matches!(
            message,
            frontend::Message::Other(frame) if frame.tag() == frontend::tag::SYNC
        )));

        // The server side.
        let server_bytes = capture.server("extended");
        let messages = server_messages(&server_bytes);
        let count_of = |tag: u8| {
            messages
                .iter()
                .filter(
                    |message| matches!(message, backend::Message::Other(frame) if frame.tag() == tag),
                )
                .count()
        };
        assert_eq!(count_of(backend::tag::PARSE_COMPLETE), 8);
        assert!(count_of(backend::tag::BIND_COMPLETE) >= 7);
        assert_eq!(count_of(backend::tag::CLOSE_COMPLETE), 1);
        assert_eq!(count_of(backend::tag::PARAMETER_DESCRIPTION), 1);
        assert_eq!(count_of(backend::tag::NO_DATA), 1);

        let first_row = messages
            .iter()
            .find_map(|message| match message {
                backend::Message::DataRow(row) => Some(row.iter().collect::<Vec<_>>()),
                _ => None,
            })
            .unwrap();
        assert_eq!(first_row, [Some(&b"42"[..])]);
        assert!(messages.iter().any(|message| matches!(
            message,
            backend::Message::CommandComplete(complete) if complete.tag() == b"INSERT 0 1"
        )));
        assert!(messages.iter().any(|message| matches!(
            message,
            backend::Message::ErrorResponse(error)
                if error.fields().sqlstate() == Some(&b"22012"[..])
        )));
    }
}

#[test]
fn copy_in_both_directions() {
    for capture in &CAPTURES {
        let server_bytes = capture.server("copy");
        let messages = server_messages(&server_bytes);

        let responses: Vec<_> = messages
            .iter()
            .filter_map(|message| match message {
                backend::Message::CopyResponse(copy) => Some(*copy),
                _ => None,
            })
            .collect();
        assert_eq!(
            responses.iter().map(|copy| copy.kind()).collect::<Vec<_>>(),
            [
                CopyKind::Out,
                CopyKind::Out,
                CopyKind::Out,
                CopyKind::In,
                CopyKind::In
            ]
        );
        // Text and CSV are both the text format. Only the third is binary.
        assert_eq!(
            responses
                .iter()
                .map(|copy| copy.overall_format())
                .collect::<Vec<_>>(),
            [
                FormatCode::TEXT,
                FormatCode::TEXT,
                FormatCode::BINARY,
                FormatCode::TEXT,
                FormatCode::TEXT
            ]
        );
        assert_eq!(
            responses
                .iter()
                .map(|copy| copy.column_formats().len())
                .collect::<Vec<_>>(),
            [3, 3, 3, 2, 2]
        );
        assert!(
            responses[0]
                .column_formats()
                .iter()
                .all(FormatCode::is_text)
        );
        assert!(
            responses[2]
                .column_formats()
                .iter()
                .all(FormatCode::is_binary)
        );

        let data: Vec<&[u8]> = messages
            .iter()
            .filter_map(|message| match message {
                backend::Message::CopyData(copy) => Some(copy.data()),
                _ => None,
            })
            .collect();
        assert_eq!(data[0], b"1\talice@example.com\tfirst contact\n");
        assert_eq!(data[1], b"2\tbob@example.com\t\\N\n");
        assert_eq!(data[2], b"3\tcarol@example.com\t\n");
        assert_eq!(data[3], b"id,email,note\n");
        // The binary form starts with its signature.
        assert!(data[7].starts_with(b"PGCOPY\n\xff\r\n\0"));
        assert_eq!(data.len(), 11);

        let tags: Vec<&str> = messages
            .iter()
            .filter_map(|message| match message {
                backend::Message::CommandComplete(complete) => Some(text(complete.tag())),
                _ => None,
            })
            .collect();
        assert_eq!(
            tags,
            [
                "COPY 3",
                "COPY 3",
                "COPY 3",
                "CREATE TABLE",
                "COPY 2",
                "SELECT 1"
            ]
        );
        // The second COPY FROM carries a value the server rejects.
        assert!(messages.iter().any(|message| matches!(
            message,
            backend::Message::ErrorResponse(error)
                if error.fields().sqlstate() == Some(&b"22P02"[..])
        )));

        // What the client sent as COPY data.
        let client_bytes = capture.client("copy");
        let client = ClientSide::read(&client_bytes);
        let sent: Vec<&[u8]> = client
            .messages()
            .iter()
            .filter_map(|message| match message {
                frontend::Message::CopyData(copy) => Some(copy.data()),
                _ => None,
            })
            .collect();
        assert_eq!(
            sent,
            [
                &b"1\tone\n2\ttwo\n"[..],
                &b"3,three\nnot-a-number,four\n"[..]
            ]
        );
        let copy_done = client
            .frames
            .iter()
            .filter(|frame| frame.tag() == frontend::tag::COPY_DONE)
            .count();
        assert_eq!(copy_done, 2);
    }
}

#[test]
fn replication_stream_in_copy_both_mode() {
    for capture in &CAPTURES {
        let server_bytes = capture.server("replication");
        let messages = server_messages(&server_bytes);

        let both = messages
            .iter()
            .find_map(|message| match message {
                backend::Message::CopyResponse(copy) => Some(*copy),
                _ => None,
            })
            .unwrap();
        assert_eq!(both.kind(), CopyKind::Both);
        assert_eq!(both.overall_format(), FormatCode::TEXT);
        assert!(both.column_formats().is_empty());

        // The stream: keepalives (k) and WAL data (w).
        let stream: Vec<&[u8]> = messages
            .iter()
            .filter_map(|message| match message {
                backend::Message::CopyData(copy) => Some(copy.data()),
                _ => None,
            })
            .collect();
        assert!(
            stream
                .iter()
                .all(|data| matches!(data.first(), Some(b'k' | b'w')))
        );
        assert!(stream.iter().any(|data| data.first() == Some(&b'k')));
        let decoded: Vec<&[u8]> = stream
            .iter()
            .filter(|data| data.first() == Some(&b'w'))
            // The header of a WAL data message is 25 bytes.
            .map(|data| &data[25..])
            .collect();
        assert!(decoded.iter().any(|change| {
            change.starts_with(b"table public.contacts: INSERT:")
                && change
                    .windows(22)
                    .any(|window| window == b"replicated@example.com")
        }));
        assert!(decoded.iter().any(|change| change.starts_with(b"COMMIT")));

        let tags: Vec<&str> = messages
            .iter()
            .filter_map(|message| match message {
                backend::Message::CommandComplete(complete) => Some(text(complete.tag())),
                _ => None,
            })
            .collect();
        assert!(tags.ends_with(&["COPY 0", "START_REPLICATION"]), "{tags:?}");

        // The client reports its position (r) and ends the stream.
        let client_bytes = capture.client("replication");
        let client = ClientSide::read(&client_bytes);
        let status_updates: Vec<&[u8]> = client
            .messages()
            .iter()
            .filter_map(|message| match message {
                frontend::Message::CopyData(copy) => Some(copy.data()),
                _ => None,
            })
            .collect();
        assert!(!status_updates.is_empty());
        assert!(
            status_updates
                .iter()
                .all(|data| data.first() == Some(&b'r'))
        );
        assert!(
            client
                .frames
                .iter()
                .any(|frame| frame.tag() == frontend::tag::COPY_DONE)
        );
    }
}

#[test]
fn md5_cleartext_and_failed_logins() {
    for capture in &CAPTURES {
        let bytes = capture.server("auth-md5");
        let messages = server_messages(&bytes);
        let backend::Message::Authentication(Authentication::Md5Password { .. }) = &messages[0]
        else {
            panic!("{}: expected AuthenticationMD5Password", capture.dir);
        };
        assert_eq!(
            messages[1],
            backend::Message::Authentication(Authentication::Ok)
        );
        // The answer is "md5" and 32 hexadecimal digits.
        let bytes = capture.client("auth-md5");
        let client = ClientSide::read(&bytes);
        assert_eq!(
            client.frames[0].tag(),
            frontend::tag::AUTHENTICATION_RESPONSE
        );
        assert_eq!(client.frames[0].body().len(), 36);
        assert!(client.frames[0].body().starts_with(b"md5"));

        let bytes = capture.server("auth-cleartext");
        let messages = server_messages(&bytes);
        assert_eq!(
            messages[0],
            backend::Message::Authentication(Authentication::CleartextPassword)
        );
        assert_eq!(
            messages[1],
            backend::Message::Authentication(Authentication::Ok)
        );

        // A wrong password ends in a fatal error instead of
        // AuthenticationOk.
        let bytes = capture.server("auth-failed");
        let messages = server_messages(&bytes);
        assert!(!messages.contains(&backend::Message::Authentication(Authentication::Ok)));
        let Some(backend::Message::ErrorResponse(error)) = messages.last() else {
            panic!("{}: expected an ErrorResponse last", capture.dir);
        };
        assert_eq!(error.fields().severity(), Some(&b"FATAL"[..]));
        assert_eq!(error.fields().sqlstate(), Some(&b"28P01"[..]));
        assert_eq!(
            error.fields().message(),
            Some(&b"password authentication failed for user \"app_scram\""[..])
        );
    }
}

#[test]
fn ssl_request_declined() {
    for capture in &CAPTURES {
        let client_bytes = capture.client("ssl-refused");
        assert_eq!(
            startup::classify(&client_bytes),
            Ok(Classification::Packet(StartupPacket::SslRequest))
        );
        let client = ClientSide::read(&client_bytes);
        assert_eq!(client.packets.len(), 2);
        assert_eq!(client.packets[0], StartupPacket::SslRequest);
        assert_eq!(client.packets[0].wire_len(), 8);
        assert_eq!(client.startup().version(), capture.protocol);

        // One byte declines, then the session continues in the clear.
        let server_bytes = capture.server("ssl-refused");
        assert_eq!(server_bytes[0], startup::ENCRYPTION_REFUSED);
        let frames = server_frames(&server_bytes, true);
        assert_eq!(frames[0].tag(), backend::tag::AUTHENTICATION);
    }
}

#[test]
fn cancel_request_carries_the_key_the_server_issued() {
    for capture in &CAPTURES {
        // The session that is cancelled.
        let server_bytes = capture.server("cancel");
        let messages = server_messages(&server_bytes);
        let key_data = messages
            .iter()
            .find_map(|message| match message {
                backend::Message::BackendKeyData(key_data) => Some(*key_data),
                _ => None,
            })
            .unwrap();
        assert!(messages.iter().any(|message| matches!(
            message,
            backend::Message::ErrorResponse(error)
                if error.fields().sqlstate() == Some(&b"57014"[..])
        )));

        // The second connection, which only carries the request.
        let request_bytes = capture.client("cancel.2");
        let Ok(Classification::Packet(StartupPacket::CancelRequest(request))) =
            startup::classify(&request_bytes)
        else {
            panic!("{}: expected a CancelRequest", capture.dir);
        };
        assert_eq!(request.as_bytes(), request_bytes);
        assert_eq!(request.process_id(), key_data.process_id());
        assert_eq!(request.secret_key(), key_data.secret_key());
        assert_eq!(request.secret_key().len(), capture.key_len());
        assert_eq!(request_bytes.len(), 12 + capture.key_len());
        // The server closes without an answer.
        assert!(capture.server("cancel.2").is_empty());
    }
}

#[test]
fn negotiate_protocol_version() {
    for capture in &CAPTURES {
        // libpq 18 asks a server older than 18 for protocol 3.2.
        if capture.has("negotiate.server.bin") {
            assert!(capture.server_major < 18);
            let client_bytes = capture.client("negotiate");
            let client = ClientSide::read(&client_bytes);
            assert_eq!(client.startup().version(), ProtocolVersion::V3_2);

            let server_bytes = capture.server("negotiate");
            let messages = server_messages(&server_bytes);
            let backend::Message::NegotiateProtocolVersion(negotiate) = &messages[0] else {
                panic!("{}: expected NegotiateProtocolVersion first", capture.dir);
            };
            // The server sends a complete version number, not a minor
            // version.
            assert_eq!(negotiate.version(), ProtocolVersion::V3_0);
            assert_eq!(negotiate.option_count(), 0);
            assert_eq!(negotiate.options().count(), 0);
            // The session goes on with 3.0 and its four-byte key.
            let key_data = messages
                .iter()
                .find_map(|message| match message {
                    backend::Message::BackendKeyData(key_data) => Some(*key_data),
                    _ => None,
                })
                .unwrap();
            assert_eq!(key_data.secret_key().len(), 4);
        } else {
            assert_eq!(capture.server_major, 18);
        }

        // A hand-written startup message asks for protocol 3.99 with an
        // option no server knows.
        if capture.has("crafted-negotiate.server.bin") {
            let client_bytes = capture.client("crafted-negotiate");
            let client = ClientSide::read(&client_bytes);
            let startup = client.startup();
            assert_eq!(startup.version(), ProtocolVersion::new(3, 99));
            let options: Vec<&[u8]> = startup
                .parameters()
                .filter(|parameter| parameter.is_protocol_option())
                .map(|parameter| parameter.name())
                .collect();
            assert_eq!(options, [&b"_pq_.fixture_option"[..]]);

            let server_bytes = capture.server("crafted-negotiate");
            let messages = server_messages(&server_bytes);
            let backend::Message::NegotiateProtocolVersion(negotiate) = &messages[0] else {
                panic!("{}: expected NegotiateProtocolVersion first", capture.dir);
            };
            let newest = if capture.server_major >= 18 {
                ProtocolVersion::V3_2
            } else {
                ProtocolVersion::V3_0
            };
            assert_eq!(negotiate.version(), newest, "{}", capture.dir);
            assert_eq!(negotiate.option_count(), 1);
            assert_eq!(negotiate.options().collect::<Vec<_>>(), options);
            assert_eq!(
                messages[1],
                backend::Message::Authentication(Authentication::CleartextPassword)
            );
        } else {
            assert_eq!(capture.protocol, ProtocolVersion::V3_2);
        }
    }
}

#[test]
fn binary_parameters_and_results() {
    for capture in &CAPTURES {
        if !capture.has("crafted-binary.client.bin") {
            assert_eq!(capture.protocol, ProtocolVersion::V3_2);
            continue;
        }
        // A hand-written Bind that the server accepted.
        let client_bytes = capture.client("crafted-binary");
        let client = ClientSide::read(&client_bytes);
        let bind = client
            .messages()
            .iter()
            .find_map(|message| match message {
                frontend::Message::Bind(bind) => Some(*bind),
                _ => None,
            })
            .unwrap();
        assert_eq!(
            bind.parameter_formats().iter().collect::<Vec<_>>(),
            [FormatCode::BINARY, FormatCode::TEXT, FormatCode::TEXT]
        );
        assert_eq!(
            bind.parameters().iter().collect::<Vec<_>>(),
            [Some(&[0, 0, 0, 41][..]), Some(&b"synthetic"[..]), None]
        );
        assert_eq!(
            bind.result_formats().iter().collect::<Vec<_>>(),
            [FormatCode::BINARY]
        );
        assert_eq!(bind.result_formats().code_for(3), Some(FormatCode::BINARY));

        // The server describes and sends every column in binary.
        let server_bytes = capture.server("crafted-binary");
        let messages = server_messages(&server_bytes);
        let description = messages
            .iter()
            .find_map(|message| match message {
                backend::Message::RowDescription(description) => Some(*description),
                _ => None,
            })
            .unwrap();
        let fields: Vec<_> = description.iter().collect();
        assert_eq!(
            fields
                .iter()
                .map(|field| text(field.name()))
                .collect::<Vec<_>>(),
            ["n", "t", "missing", "flag"]
        );
        // int4, text, int8, bool.
        assert_eq!(
            fields
                .iter()
                .map(|field| field.type_oid())
                .collect::<Vec<_>>(),
            [23, 25, 20, 16]
        );
        assert!(fields.iter().all(|field| field.format().is_binary()));

        let row = messages
            .iter()
            .find_map(|message| match message {
                backend::Message::DataRow(row) => Some(row.iter().collect::<Vec<_>>()),
                _ => None,
            })
            .unwrap();
        assert_eq!(
            row,
            [
                Some(&[0, 0, 0, 42][..]),
                Some(&b"synthetic"[..]),
                None,
                Some(&[1][..])
            ]
        );
    }
}

#[test]
fn direct_tls_handshake() {
    let capture = &CAPTURES[3];
    assert_eq!(capture.dir, "pg18-3.0");
    let bytes = capture.client("direct-tls");
    assert_eq!(bytes[0], startup::TLS_HANDSHAKE_RECORD);
    assert_eq!(startup::classify(&bytes), Ok(Classification::DirectTls));
    // Decided on the first byte.
    assert_eq!(
        startup::classify(&bytes[..1]),
        Ok(Classification::DirectTls)
    );
    // The handshake names the protocol, as direct TLS requires, and the
    // host the client connected to.
    let contains = |needle: &[u8]| bytes.windows(needle.len()).any(|window| window == needle);
    assert!(contains(b"postgresql"));
    assert!(contains(b"db.example.com"));
    // Read as a startup packet, the same bytes are refused.
    assert!(StartupPacket::parse(&bytes).is_err());
    // The server had no TLS and closed without an answer.
    assert!(capture.server("direct-tls").is_empty());
}
