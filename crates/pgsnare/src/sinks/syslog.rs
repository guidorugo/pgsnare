// SPDX-License-Identifier: Apache-2.0

//! The `syslog` sink: each event as one message in the format of RFC 5424.
//!
//! # The message
//!
//! ```text
//! <129>1 2026-11-11T17:06:31.123456Z proxy-1 pgsnare 1 token_hit - {"schema_version":1,...}
//! ```
//!
//! | Part | Content |
//! |---|---|
//! | `PRI` | The facility of the configuration times eight, plus the severity of the event |
//! | `VERSION` | `1` |
//! | `TIMESTAMP` | The time the event was raised, in UTC with microseconds |
//! | `HOSTNAME` | The name of the machine as the system reports it, or `-` |
//! | `APP-NAME` | `pgsnare` |
//! | `PROCID` | The process id |
//! | `MSGID` | The kind of the event, such as `token_hit` |
//! | `STRUCTURED-DATA` | `-` |
//! | `MSG` | The event as JSON, as every other sink writes it, in ASCII |
//!
//! The severity follows the kind of the event:
//!
//! | Kind | Severity |
//! |---|---|
//! | `token_hit` | 1, alert |
//! | `rule_hit`, `inspection_bypassed` | 4, warning |
//! | Every other kind | 5, notice |
//!
//! # An event cannot forge a record
//!
//! Nothing of an event goes into the header of a message or into its
//! structured data: the header is made of the facility, the time, the name
//! of the machine, fixed words and the kind of the event, and there is no
//! structured data, so there is nothing in either that would need the
//! escaping RFC 5424 has for them.
//!
//! Everything of an event is in `MSG`, as JSON. The JSON encoder escapes
//! every control character, and this sink also writes every character
//! outside ASCII, and the one control character JSON leaves alone, as a
//! `\u` escape. The message is therefore printable ASCII from its first
//! byte to its last. No text of an event, such as a user name with a line
//! break in it, can end a record and begin another, whatever a receiver
//! splits records at. Because the message is ASCII it also needs no byte
//! order mark, which RFC 5424 asks for in front of UTF-8.
//!
//! # Transport
//!
//! - **UDP**, and a datagram socket of the system such as `/dev/log`: one
//!   message is one datagram, as RFC 5426 says. An event that does not fit
//!   into a datagram is dropped.
//! - **TCP**, and a stream socket of the system: each message is preceded
//!   by its length in bytes and a space, the octet counting of RFC 6587.
//!   A receiver then never has to look for the end of a message. The
//!   connection is kept between events and opened again when it fails.
//!
//! A message is not encrypted on its way, and a syslog server sends no
//! answer: an event that was written to a connection the server has just
//! closed is lost without the sink knowing. Where that matters, the
//! webhook sink is the one that gets an answer.

use std::fmt::{self, Write as _};
use std::path::PathBuf;

use pgsnare_core::event::{Event, EventKind};
use pgsnare_core::extension::{EventSink, SinkError, SinkFuture};
use tokio::io::AsyncWriteExt;
use tokio::net::{TcpStream, UdpSocket, UnixDatagram, UnixStream};
use tokio::sync::Mutex;

use crate::config::{Endpoint, SyslogFacility, SyslogTransport};
use crate::http;

/// The longest name of a machine RFC 5424 has room for.
const MAX_HOSTNAME_BYTES: usize = 255;

/// Where the messages go.
#[derive(Clone, Debug, PartialEq, Eq)]
enum Target {
    Udp { host: String, port: u16 },
    Tcp { host: String, port: u16 },
    UnixDatagram(PathBuf),
    UnixStream(PathBuf),
}

/// The socket to the server, once there is one.
enum Connection {
    Udp(UdpSocket),
    Tcp(TcpStream),
    UnixDatagram(UnixDatagram),
    UnixStream(UnixStream),
}

/// Sends each event to a syslog server as one message of RFC 5424.
///
/// See the [module documentation](self) for the message and for how it is
/// sent.
pub struct SyslogSink {
    name: String,
    target: Target,
    facility: u8,
    hostname: String,
    process_id: u32,
    /// The socket, kept between events. It is taken out for the time of a
    /// write, so that a write that is given up half way leaves no socket
    /// behind that is in the middle of a message.
    connection: Mutex<Option<Connection>>,
}

impl SyslogSink {
    /// A sink that sends to `address` over `transport`, with messages
    /// filed under `facility`.
    ///
    /// `name` is what logs and metrics call the sink. Nothing is opened
    /// before the first event: a syslog server that is not up yet does not
    /// keep the proxy from starting.
    #[must_use]
    pub fn new(
        name: impl Into<String>,
        address: &Endpoint,
        transport: SyslogTransport,
        facility: SyslogFacility,
    ) -> Self {
        let stream = matches!(transport, SyslogTransport::Tcp);
        let target = match (address, stream) {
            (Endpoint::Unix { path }, true) => Target::UnixStream(path.clone()),
            (Endpoint::Unix { path }, false) => Target::UnixDatagram(path.clone()),
            (Endpoint::Tcp { host, port }, true) => Target::Tcp {
                host: host.as_str().to_owned(),
                port: *port,
            },
            (Endpoint::Tcp { host, port }, false) => Target::Udp {
                host: host.as_str().to_owned(),
                port: *port,
            },
        };
        Self {
            name: name.into(),
            target,
            facility: facility.code(),
            hostname: hostname(),
            process_id: std::process::id(),
            connection: Mutex::new(None),
        }
    }

    /// The message for an event, without what the transport adds.
    fn message(&self, event: &Event) -> Result<String, SinkError> {
        let json = serde_json::to_string(event)
            .map_err(|_| SinkError::permanent("the event could not be written as JSON"))?;
        let priority = u16::from(self.facility) * 8 + u16::from(severity(event.body.kind));
        let mut message = String::with_capacity(json.len() + 128);
        // Writing to a `String` cannot fail.
        let _ = write!(
            message,
            "<{priority}>1 {} {} pgsnare {} {} - ",
            event.timestamp,
            self.hostname,
            self.process_id,
            message_id(event.body.kind),
        );
        push_ascii(&mut message, &json);
        Ok(message)
    }

    async fn connect(&self) -> Result<Connection, SinkError> {
        let failed = |error: std::io::Error| SinkError::retryable(http::io_reason(&error));
        match &self.target {
            Target::Tcp { host, port } => http::connect(host, *port)
                .await
                .map(Connection::Tcp)
                .map_err(SinkError::retryable),
            Target::UnixStream(path) => UnixStream::connect(path)
                .await
                .map(Connection::UnixStream)
                .map_err(failed),
            Target::UnixDatagram(path) => {
                let socket = UnixDatagram::unbound().map_err(failed)?;
                socket.connect(path).map_err(failed)?;
                Ok(Connection::UnixDatagram(socket))
            }
            Target::Udp { host, port } => {
                let addresses = tokio::net::lookup_host((host.as_str(), *port))
                    .await
                    .map_err(|_| {
                        SinkError::retryable("the name of the syslog server could not be resolved")
                    })?;
                let mut last = SinkError::retryable("the name of the syslog server has no address");
                for address in addresses {
                    let local = if address.is_ipv4() {
                        "0.0.0.0:0"
                    } else {
                        "[::]:0"
                    };
                    let attempt = async {
                        let socket = UdpSocket::bind(local).await?;
                        socket.connect(address).await?;
                        Ok(socket)
                    };
                    match attempt.await {
                        Ok(socket) => return Ok(Connection::Udp(socket)),
                        Err(error) => last = failed(error),
                    }
                }
                Err(last)
            }
        }
    }

    async fn send(&self, message: String) -> Result<(), SinkError> {
        let mut kept = self.connection.lock().await;
        let mut connection = match kept.take() {
            // A server that closed the connection since the last event is
            // not written to: what would be written would be lost.
            Some(connection) if connection.is_open() => connection,
            _ => self.connect().await?,
        };
        connection.write(message.as_bytes()).await?;
        *kept = Some(connection);
        Ok(())
    }
}

impl Connection {
    /// Whether the other side is still there, as far as that can be told
    /// without sending anything.
    fn is_open(&self) -> bool {
        let mut nothing = [0u8; 64];
        let read = match self {
            Self::Tcp(stream) => stream.try_read(&mut nothing),
            Self::UnixStream(stream) => stream.try_read(&mut nothing),
            Self::Udp(_) | Self::UnixDatagram(_) => return true,
        };
        match read {
            // The end of the stream: the server has closed it.
            Ok(0) => false,
            // A syslog server sends nothing. If one does, that is no reason
            // to leave.
            Ok(_) => true,
            Err(error) => error.kind() == std::io::ErrorKind::WouldBlock,
        }
    }

    async fn write(&mut self, message: &[u8]) -> Result<(), SinkError> {
        let failed = |error: std::io::Error| match error.raw_os_error() {
            Some(code) if code == rustix::io::Errno::MSGSIZE.raw_os_error() => {
                SinkError::permanent("the event is too large for one datagram")
            }
            _ => SinkError::retryable(http::io_reason(&error)),
        };
        match self {
            Self::Udp(socket) => socket.send(message).await.map(|_| ()).map_err(failed),
            Self::UnixDatagram(socket) => socket.send(message).await.map(|_| ()).map_err(failed),
            Self::Tcp(stream) => write_framed(stream, message).await.map_err(failed),
            Self::UnixStream(stream) => write_framed(stream, message).await.map_err(failed),
        }
    }
}

/// Writes a message with its length in front, in one piece.
async fn write_framed(
    stream: &mut (impl AsyncWriteExt + Unpin),
    message: &[u8],
) -> std::io::Result<()> {
    let mut frame = format!("{} ", message.len()).into_bytes();
    frame.extend_from_slice(message);
    stream.write_all(&frame).await?;
    stream.flush().await
}

/// How urgent an event is, in the numbers of syslog.
const fn severity(kind: EventKind) -> u8 {
    match kind {
        // Alert: somebody is reading what nobody should.
        EventKind::TokenHit => 1,
        // Warning.
        EventKind::RuleHit | EventKind::InspectionBypassed => 4,
        // Notice.
        _ => 5,
    }
}

/// The kind of an event as a `MSGID`: a fixed word of printable ASCII.
const fn message_id(kind: EventKind) -> &'static str {
    match kind {
        EventKind::TokenHit => "token_hit",
        EventKind::RuleHit => "rule_hit",
        EventKind::ParseFailure => "parse_failure",
        EventKind::SessionActivity => "session_activity",
        EventKind::InspectionBypassed => "inspection_bypassed",
        _ => "event",
    }
}

/// The name of this machine as a `HOSTNAME`: printable ASCII without
/// spaces, or `-` when the system has no such name.
fn hostname() -> String {
    let name = rustix::system::uname();
    sanitize_hostname(name.nodename().to_bytes())
}

fn sanitize_hostname(name: &[u8]) -> String {
    let name: String = name
        .iter()
        .take(MAX_HOSTNAME_BYTES)
        .map(|byte| char::from(*byte))
        .collect();
    if name.is_empty() || !name.bytes().all(|byte| byte.is_ascii_graphic()) {
        return "-".to_owned();
    }
    name
}

/// Appends JSON to a message as ASCII: what is not printable ASCII becomes
/// a `\u` escape. In JSON such characters stand inside strings only, where
/// the escape means the same as the character.
fn push_ascii(message: &mut String, json: &str) {
    for character in json.chars() {
        if character.is_ascii() && !character.is_ascii_control() {
            message.push(character);
        } else {
            let mut units = [0u16; 2];
            for unit in character.encode_utf16(&mut units) {
                // Writing to a `String` cannot fail.
                let _ = write!(message, "\\u{unit:04x}");
            }
        }
    }
}

impl fmt::Debug for SyslogSink {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("SyslogSink")
            .field("name", &self.name)
            .field("target", &self.target)
            .field("facility", &self.facility)
            .finish_non_exhaustive()
    }
}

impl EventSink for SyslogSink {
    fn name(&self) -> &str {
        &self.name
    }

    fn deliver<'a>(&'a self, event: &'a Event) -> SinkFuture<'a> {
        Box::pin(async move { self.send(self.message(event)?).await })
    }
}

#[cfg(test)]
mod tests {
    use std::sync::atomic::{AtomicU32, Ordering};
    use std::time::Duration;

    use tokio::io::AsyncReadExt;
    use tokio::net::{TcpListener, UnixListener};

    use super::super::lines::tests::event;
    use super::*;

    fn endpoint(text: &str) -> Endpoint {
        text.parse().unwrap()
    }

    fn sink(address: &str, transport: SyslogTransport) -> SyslogSink {
        SyslogSink::new(
            "syslog-0",
            &endpoint(address),
            transport,
            SyslogFacility::Local0,
        )
    }

    /// The parts of a message of RFC 5424, split as a receiver splits them.
    struct Parsed<'a> {
        priority: u16,
        timestamp: &'a str,
        hostname: &'a str,
        app_name: &'a str,
        process_id: &'a str,
        message_id: &'a str,
        structured_data: &'a str,
        message: &'a str,
    }

    fn parse(text: &str) -> Parsed<'_> {
        let rest = text.strip_prefix('<').expect("a priority");
        let (priority, rest) = rest.split_once('>').expect("the end of the priority");
        let mut parts = rest.splitn(8, ' ');
        let mut next = || parts.next().expect("eight parts");
        assert_eq!(next(), "1", "the version");
        Parsed {
            priority: priority.parse().unwrap(),
            timestamp: next(),
            hostname: next(),
            app_name: next(),
            process_id: next(),
            message_id: next(),
            structured_data: next(),
            message: next(),
        }
    }

    #[test]
    fn a_message_has_the_parts_of_rfc_5424() {
        let sink = sink("syslog.example.com:514", SyslogTransport::Udp);
        let event = event("app");
        let text = sink.message(&event).unwrap();
        let parsed = parse(&text);

        // local0 is facility 16, and an event of this kind is a warning.
        assert_eq!(parsed.priority, 16 * 8 + 4);
        assert_eq!(parsed.timestamp, "2026-11-11T17:06:31.123456Z");
        assert_eq!(parsed.hostname, sink.hostname);
        assert!(!parsed.hostname.is_empty());
        assert!(parsed.hostname.bytes().all(|byte| byte.is_ascii_graphic()));
        assert_eq!(parsed.app_name, "pgsnare");
        assert_eq!(parsed.process_id, std::process::id().to_string());
        assert_eq!(parsed.message_id, "inspection_bypassed");
        assert_eq!(parsed.structured_data, "-");
        // The message is the event, as every sink writes it.
        assert_eq!(parsed.message, serde_json::to_string(&event).unwrap());
        let back: Event = serde_json::from_str(parsed.message).unwrap();
        assert_eq!(back, event);
    }

    #[test]
    fn the_priority_follows_the_facility_and_the_kind_of_the_event() {
        let kinds = [
            (EventKind::TokenHit, 1, "token_hit"),
            (EventKind::RuleHit, 4, "rule_hit"),
            (EventKind::InspectionBypassed, 4, "inspection_bypassed"),
            (EventKind::ParseFailure, 5, "parse_failure"),
            (EventKind::SessionActivity, 5, "session_activity"),
        ];
        for (facility, code) in [
            (SyslogFacility::User, 1),
            (SyslogFacility::Auth, 4),
            (SyslogFacility::Authpriv, 10),
            (SyslogFacility::Local0, 16),
            (SyslogFacility::Local7, 23),
        ] {
            let sink = SyslogSink::new(
                "syslog-0",
                &endpoint("syslog.example.com:514"),
                SyslogTransport::Udp,
                facility,
            );
            for (kind, severity, name) in kinds {
                let mut event = event("app");
                event.body.kind = kind;
                let text = sink.message(&event).unwrap();
                let parsed = parse(&text);
                assert_eq!(
                    parsed.priority,
                    code * 8 + severity,
                    "{facility:?} {kind:?}"
                );
                assert_eq!(parsed.message_id, name);
            }
        }
    }

    #[test]
    fn no_text_of_an_event_can_end_a_record_or_begin_another() {
        let sink = sink("syslog.example.com:514", SyslogTransport::Tcp);
        // A user name that tries: a line break and a whole second record,
        // the characters structured data is made of, a byte order mark,
        // other line separators, a control character JSON leaves alone,
        // and characters outside ASCII.
        let hostile = "app\n<8>1 2026-01-01T00:00:00Z host su 1 ID47 [x@1 a=\"]\\\"] forged\r\n\
                       \u{feff}\u{85}\u{2028}\u{2029}\u{7f}\u{0}caf\u{e9} \u{1f980}";
        let event = event(hostile);
        let text = sink.message(&event).unwrap();

        // Printable ASCII from the first byte to the last, on one line.
        assert!(
            text.bytes()
                .all(|byte| byte == b' ' || byte.is_ascii_graphic()),
            "{text}"
        );
        // One record, with one header, and the name is back as it was.
        let parsed = parse(&text);
        assert_eq!(parsed.message_id, "inspection_bypassed");
        assert_eq!(parsed.structured_data, "-");
        let back: Event = serde_json::from_str(parsed.message).unwrap();
        assert_eq!(back.body.db_user.as_deref(), Some(hostile));
        assert_eq!(back, event);
        // What is outside ASCII is written as escapes, a pair of them for
        // a character beyond the basic plane.
        assert!(
            parsed.message.contains("caf\\u00e9 \\ud83e\\udd80"),
            "{text}"
        );
        assert!(parsed.message.contains("\\u007f\\u0000"), "{text}");
        assert!(
            parsed.message.contains("\\ufeff\\u0085\\u2028\\u2029"),
            "{text}"
        );
    }

    #[test]
    fn the_name_of_the_machine_is_printable_or_left_out() {
        assert_eq!(
            sanitize_hostname(b"proxy-1.example.com"),
            "proxy-1.example.com"
        );
        assert_eq!(sanitize_hostname(b""), "-");
        assert_eq!(sanitize_hostname(b"two words"), "-");
        assert_eq!(sanitize_hostname(b"line\nbreak"), "-");
        assert_eq!(sanitize_hostname("caf\u{e9}".as_bytes()), "-");
        assert_eq!(sanitize_hostname(&[b'h'; 300]).len(), MAX_HOSTNAME_BYTES);
    }

    #[test]
    fn the_address_and_the_transport_say_which_socket_is_used() {
        let target = |address: &str, transport| sink(address, transport).target;
        assert_eq!(
            target("syslog.example.com:514", SyslogTransport::Udp),
            Target::Udp {
                host: "syslog.example.com".to_owned(),
                port: 514
            }
        );
        assert_eq!(
            target("[2001:db8::20]:6514", SyslogTransport::Tcp),
            Target::Tcp {
                host: "2001:db8::20".to_owned(),
                port: 6514
            }
        );
        assert_eq!(
            target("unix:/dev/log", SyslogTransport::Udp),
            Target::UnixDatagram(PathBuf::from("/dev/log"))
        );
        assert_eq!(
            target("unix:/dev/log", SyslogTransport::Tcp),
            Target::UnixStream(PathBuf::from("/dev/log"))
        );
        let shown = format!("{:?}", sink("unix:/dev/log", SyslogTransport::Udp));
        assert!(shown.contains("syslog-0"), "{shown}");
    }

    #[tokio::test]
    async fn over_udp_one_event_is_one_datagram() {
        let server = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let address = server.local_addr().unwrap();
        let sink = sink(&address.to_string(), SyslogTransport::Udp);

        let first = event("first");
        let second = event("two\nlines");
        sink.deliver(&first).await.unwrap();
        sink.deliver(&second).await.unwrap();

        let mut buffer = vec![0u8; 65536];
        for event in [&first, &second] {
            let count = tokio::time::timeout(Duration::from_secs(5), server.recv(&mut buffer))
                .await
                .unwrap()
                .unwrap();
            let text = std::str::from_utf8(&buffer[..count]).unwrap();
            assert_eq!(text, sink.message(event).unwrap());
            let back: Event = serde_json::from_str(parse(text).message).unwrap();
            assert_eq!(&back, event);
        }
    }

    /// Reads one message that has its length in front.
    async fn read_framed(stream: &mut (impl AsyncReadExt + Unpin)) -> String {
        let mut length = String::new();
        loop {
            let byte = stream.read_u8().await.unwrap();
            if byte == b' ' {
                break;
            }
            assert!(byte.is_ascii_digit(), "a length is made of digits");
            length.push(char::from(byte));
        }
        let mut message = vec![0u8; length.parse().unwrap()];
        stream.read_exact(&mut message).await.unwrap();
        String::from_utf8(message).unwrap()
    }

    #[tokio::test]
    async fn over_tcp_each_message_has_its_length_in_front_and_the_connection_is_kept() {
        let server = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let address = server.local_addr().unwrap();
        let sink = sink(&address.to_string(), SyslogTransport::Tcp);

        let events = [event("first"), event("two\nlines"), event("third")];
        sink.deliver(&events[0]).await.unwrap();
        let (mut stream, _) = server.accept().await.unwrap();
        sink.deliver(&events[1]).await.unwrap();
        sink.deliver(&events[2]).await.unwrap();

        // Three messages on one connection, each exactly as long as it
        // says, with nothing in between.
        for event in &events {
            assert_eq!(read_framed(&mut stream).await, sink.message(event).unwrap());
        }
        let waiting = tokio::time::timeout(Duration::from_millis(100), server.accept()).await;
        assert!(waiting.is_err(), "no second connection was opened");

        // The server closes the connection. The next event goes over a new
        // one.
        drop(stream);
        tokio::time::sleep(Duration::from_millis(100)).await;
        sink.deliver(&events[0]).await.unwrap();
        let (mut stream, _) = tokio::time::timeout(Duration::from_secs(5), server.accept())
            .await
            .unwrap()
            .unwrap();
        assert_eq!(
            read_framed(&mut stream).await,
            sink.message(&events[0]).unwrap()
        );
    }

    #[tokio::test]
    async fn a_server_that_is_not_there_is_a_failure_that_may_pass() {
        // A port nothing listens on.
        let port = std::net::TcpListener::bind("127.0.0.1:0")
            .unwrap()
            .local_addr()
            .unwrap()
            .port();
        let sink = sink(&format!("127.0.0.1:{port}"), SyslogTransport::Tcp);
        let error = sink.deliver(&event("app")).await.unwrap_err();
        assert!(error.is_retryable());
        assert_eq!(error.message(), "the connection was refused");

        // Once the server is there, the same sink delivers.
        let server = TcpListener::bind(("127.0.0.1", port)).await.unwrap();
        sink.deliver(&event("app")).await.unwrap();
        let (mut stream, _) = server.accept().await.unwrap();
        assert!(read_framed(&mut stream).await.starts_with("<132>1 "));
    }

    /// A directory that is removed again when the test ends.
    struct TempDir(PathBuf);

    impl TempDir {
        fn new() -> Self {
            static NEXT: AtomicU32 = AtomicU32::new(0);
            let path = std::env::temp_dir().join(format!(
                "pgsnare-syslog-test-{}-{}",
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

    #[tokio::test]
    async fn a_socket_of_the_system_takes_datagrams_or_a_stream() {
        let dir = TempDir::new();
        let event = event("app");

        let path = dir.0.join("datagrams");
        let server = UnixDatagram::bind(&path).unwrap();
        let sink_for = |path: &std::path::Path, transport| {
            sink(&format!("unix:{}", path.display()), transport)
        };
        let datagrams = sink_for(&path, SyslogTransport::Udp);
        datagrams.deliver(&event).await.unwrap();
        let mut buffer = vec![0u8; 65536];
        let count = tokio::time::timeout(Duration::from_secs(5), server.recv(&mut buffer))
            .await
            .unwrap()
            .unwrap();
        assert_eq!(
            std::str::from_utf8(&buffer[..count]).unwrap(),
            datagrams.message(&event).unwrap()
        );

        let path = dir.0.join("stream");
        let server = UnixListener::bind(&path).unwrap();
        let stream_sink = sink_for(&path, SyslogTransport::Tcp);
        stream_sink.deliver(&event).await.unwrap();
        let (mut stream, _) = server.accept().await.unwrap();
        assert_eq!(
            read_framed(&mut stream).await,
            stream_sink.message(&event).unwrap()
        );

        // A socket that is not there.
        let missing = sink_for(&dir.0.join("missing"), SyslogTransport::Udp);
        let error = missing.deliver(&event).await.unwrap_err();
        assert!(error.is_retryable());
        assert_eq!(error.message(), "the socket does not exist");
    }

    #[tokio::test]
    async fn an_event_that_is_too_large_for_a_datagram_is_dropped_for_good() {
        let server = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let sink = sink(
            &server.local_addr().unwrap().to_string(),
            SyslogTransport::Udp,
        );
        let large = event(&"x".repeat(70_000));
        let error = sink.deliver(&large).await.unwrap_err();
        assert!(!error.is_retryable());
        assert_eq!(error.message(), "the event is too large for one datagram");
        // The sink still works for an event that fits.
        sink.deliver(&event("app")).await.unwrap();
    }
}
