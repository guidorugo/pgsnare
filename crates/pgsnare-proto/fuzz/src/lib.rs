// SPDX-License-Identifier: Apache-2.0

//! The shared code of the fuzz targets of `pgsnare-proto`.
//!
//! The functions here do more than wait for a panic. They check what the
//! crate promises, so the fuzzer reports any input that breaks a promise:
//!
//! - framing a stream gives the same result however the stream is cut
//! - a view agrees with the dispatching `Message` type and with itself
//! - what a view accepts re-encodes to the identical bytes
//! - bytes that follow a frame or a packet never change how it is read
//! - the startup parser accepts nothing PostgreSQL would reject
//!
//! # Running
//!
//! From the root of the repository:
//!
//! ```sh
//! make fuzz FUZZ_CRATE=pgsnare-proto FUZZ_SECONDS=60
//! ```
//!
//! The targets are `framer_client`, `framer_server`, `startup`,
//! `frontend_views` and `backend_views`. `FUZZ_TARGET` selects one.
//!
//! The first three start from the traffic captured from PostgreSQL 18:
//! their directories under `seeds/` are links to
//! `../tests/fixtures/pg18-3.0`, so the seeds are the golden-byte fixtures
//! themselves and cannot drift from them.

use pgsnare_proto::backend::{self, Authentication};
use pgsnare_proto::startup::{self, Classification, StartupPacket};
use pgsnare_proto::{
    CopyData, Direction, Frame, FrameError, Framer, HEADER_LEN, Limits, ParseError, StartupError,
    Step, encode, frontend,
};

// ---------------------------------------------------------------------------
// Framing
// ---------------------------------------------------------------------------

/// A frame as the framer reported it, with the chunks of a streamed body
/// joined.
#[derive(Debug, PartialEq, Eq)]
enum Found {
    Whole {
        tag: u8,
        body: Vec<u8>,
    },
    Streamed {
        tag: u8,
        body_len: u32,
        body: Vec<u8>,
    },
}

/// Everything a framer reported for one stream.
#[derive(Debug, PartialEq, Eq)]
struct Outcome {
    found: Vec<Found>,
    error: Option<FrameError>,
    leftover: Vec<u8>,
    stream_remaining: u32,
}

/// Fuzzes the framer of one direction.
///
/// The last three bytes of the input choose the limits and the size of the
/// pieces the stream is delivered in. Everything before them is the stream,
/// so a captured stream is a usable seed as it is.
///
/// A client stream may begin with its startup-phase packets, as a captured
/// one does. They are not frames, and they are skipped the way a session
/// reads them before it starts framing.
pub fn fuzz_framer(direction: Direction, data: &[u8]) {
    let Some((stream, &[buffered, maximum, piece])) = data.split_last_chunk::<3>() else {
        return;
    };
    let stream = match direction {
        Direction::FromClient => after_startup_phase(stream),
        Direction::FromServer => stream,
    };
    let max_buffered = usize::from(buffered) * 4;
    let max_frame = if maximum == 0 {
        usize::MAX
    } else {
        usize::from(maximum) * 64
    };
    let limits = Limits::new(max_buffered, max_frame);

    let at_once = run_framer(direction, limits, stream, stream.len().max(1), true);
    let in_pieces = run_framer(
        direction,
        limits,
        stream,
        usize::from(piece % 32) + 1,
        false,
    );
    assert_eq!(
        at_once, in_pieces,
        "the result depends on how the stream was cut"
    );
}

/// The part of a client stream that follows its startup-phase packets: a
/// request for encryption, if there is one, and the packet after it. A
/// stream that does not begin with such packets is returned whole.
fn after_startup_phase(stream: &[u8]) -> &[u8] {
    let mut rest = stream;
    while let Ok(Some(packet)) = StartupPacket::parse(rest) {
        rest = &rest[packet.wire_len()..];
        if !matches!(
            packet,
            StartupPacket::SslRequest | StartupPacket::GssEncRequest
        ) {
            break;
        }
    }
    rest
}

/// Feeds `stream` to a framer in pieces of `piece_len` bytes, the way a
/// connection delivers it.
fn run_framer(
    direction: Direction,
    limits: Limits,
    stream: &[u8],
    piece_len: usize,
    check_views: bool,
) -> Outcome {
    let mut framer = Framer::new(direction, limits);
    let mut pending: Vec<u8> = Vec::new();
    let mut found = Vec::new();
    let mut error = None;

    for piece in stream.chunks(piece_len) {
        pending.extend_from_slice(piece);
        let mut unread = &pending[..];
        loop {
            let before = unread.len();
            match framer.next(&mut unread) {
                Ok(Step::Frame(frame)) => {
                    assert_eq!(frame.direction(), direction);
                    assert_eq!(frame.wire_len(), before - unread.len());
                    assert_eq!(frame.as_bytes().len(), frame.body().len() + HEADER_LEN);
                    assert!(frame.wire_len() <= limits.max_buffered());
                    assert!(framer.is_at_frame_boundary());
                    if check_views {
                        check_frame(frame);
                    }
                    found.push(Found::Whole {
                        tag: frame.tag(),
                        body: frame.body().to_vec(),
                    });
                }
                Ok(Step::StreamStart(header)) => {
                    assert_eq!(before - unread.len(), HEADER_LEN);
                    assert!(header.frame_len() > limits.max_buffered());
                    assert!(header.frame_len() <= limits.max_frame());
                    assert!(header.body_len() > 0);
                    assert_eq!(framer.stream_remaining(), header.body_len());
                    found.push(Found::Streamed {
                        tag: header.tag(),
                        body_len: header.body_len(),
                        body: Vec::new(),
                    });
                }
                Ok(Step::StreamChunk(chunk)) => {
                    assert!(!chunk.data().is_empty());
                    assert_eq!(chunk.data().len(), before - unread.len());
                    assert_eq!(chunk.remaining(), framer.stream_remaining());
                    assert_eq!(chunk.is_last(), framer.is_at_frame_boundary());
                    let Some(Found::Streamed { body, .. }) = found.last_mut() else {
                        panic!("a chunk without the start of a stream");
                    };
                    body.extend_from_slice(chunk.data());
                }
                Ok(Step::NeedMore(needed)) => {
                    assert_eq!(unread.len(), before, "NeedMore consumed bytes");
                    assert!(needed > before, "the hint asks for no more than is there");
                    break;
                }
                Err(first) => {
                    assert_eq!(unread.len(), before, "an error consumed bytes");
                    assert_eq!(
                        framer.next(&mut unread),
                        Err(first),
                        "an error did not repeat"
                    );
                    error = Some(first);
                    break;
                }
            }
        }
        let consumed = pending.len() - unread.len();
        pending.drain(..consumed);
        if error.is_some() {
            pending.clear();
            break;
        }
    }

    Outcome {
        found,
        error,
        leftover: pending,
        stream_remaining: framer.stream_remaining(),
    }
}

/// Frames `bytes`, which must begin with one whole frame.
fn first_frame(direction: Direction, bytes: &[u8]) -> Frame<'_> {
    let mut framer = Framer::new(direction, Limits::buffered_only(usize::MAX));
    let mut unread = bytes;
    match framer.next(&mut unread) {
        Ok(Step::Frame(frame)) => frame,
        other => panic!("expected a frame, got {other:?}"),
    }
}

// ---------------------------------------------------------------------------
// Views
// ---------------------------------------------------------------------------

/// Fuzzes the views of one direction with a single message: the first byte
/// of the input is the type byte and the rest is the body.
pub fn fuzz_views(direction: Direction, data: &[u8]) {
    let Some((&tag, body)) = data.split_first() else {
        return;
    };
    let Ok(length) = u32::try_from(body.len() + 4) else {
        return;
    };
    let mut bytes = Vec::with_capacity(HEADER_LEN + 2 * body.len());
    bytes.push(tag);
    bytes.extend_from_slice(&length.to_be_bytes());
    bytes.extend_from_slice(body);
    let frame_len = bytes.len();
    // The buffer goes on after the frame. What follows must never matter.
    bytes.extend_from_slice(body);

    let frame = first_frame(direction, &bytes);
    assert_eq!(frame.wire_len(), frame_len);
    check_frame(frame);

    let alone = first_frame(direction, &bytes[..frame_len]);
    match direction {
        Direction::FromServer => assert_eq!(
            backend::Message::from_frame(frame),
            backend::Message::from_frame(alone),
            "bytes after the frame changed how it was read"
        ),
        Direction::FromClient => assert_eq!(
            frontend::Message::from_frame(frame),
            frontend::Message::from_frame(alone),
            "bytes after the frame changed how it was read"
        ),
    }
}

/// Runs every check on one frame.
fn check_frame(frame: Frame<'_>) {
    match frame.direction() {
        Direction::FromServer => check_backend(frame),
        Direction::FromClient => check_frontend(frame),
    }
    check_copy_data(frame);
}

/// Checks that the view `$view` agrees with the result of the dispatching
/// `Message` type: the same value or the same error for its own type byte,
/// and a refusal for every other.
macro_rules! check_view {
    ($frame:expr, $dispatched:expr, $view:ty, $variant:path) => {{
        let single = <$view>::from_frame($frame);
        if $frame.tag() == <$view>::TAG {
            match &$dispatched {
                Ok($variant(expected)) => assert_eq!(single.as_ref(), Ok(expected)),
                Err(error) => assert_eq!(single.as_ref().err(), Some(error)),
                Ok(other) => panic!("type byte dispatched to {other:?}"),
            }
        } else {
            assert_unexpected(single.map(drop), $frame);
        }
    }};
}

fn assert_unexpected(result: Result<(), ParseError>, frame: Frame<'_>) {
    assert_eq!(
        result,
        Err(ParseError::UnexpectedMessage {
            direction: frame.direction(),
            tag: frame.tag(),
        })
    );
}

fn check_backend(frame: Frame<'_>) {
    use backend::Message;

    let dispatched = Message::from_frame(frame);
    check_view!(
        frame,
        dispatched,
        backend::Authentication,
        Message::Authentication
    );
    check_view!(
        frame,
        dispatched,
        backend::BackendKeyData,
        Message::BackendKeyData
    );
    check_view!(
        frame,
        dispatched,
        backend::ParameterStatus,
        Message::ParameterStatus
    );
    check_view!(
        frame,
        dispatched,
        backend::NegotiateProtocolVersion,
        Message::NegotiateProtocolVersion
    );
    check_view!(
        frame,
        dispatched,
        backend::RowDescription,
        Message::RowDescription
    );
    check_view!(frame, dispatched, backend::DataRow, Message::DataRow);
    check_view!(
        frame,
        dispatched,
        backend::CommandComplete,
        Message::CommandComplete
    );
    check_view!(
        frame,
        dispatched,
        backend::ReadyForQuery,
        Message::ReadyForQuery
    );
    check_view!(
        frame,
        dispatched,
        backend::ErrorResponse,
        Message::ErrorResponse
    );
    check_view!(
        frame,
        dispatched,
        backend::NoticeResponse,
        Message::NoticeResponse
    );
    check_view!(
        frame,
        dispatched,
        backend::NotificationResponse,
        Message::NotificationResponse
    );

    // The three COPY responses share one view.
    let copy = backend::CopyResponse::from_frame(frame);
    if matches!(frame.tag(), b'G' | b'H' | b'W') {
        match &dispatched {
            Ok(Message::CopyResponse(expected)) => assert_eq!(copy.as_ref(), Ok(expected)),
            Err(error) => assert_eq!(copy.as_ref().err(), Some(error)),
            Ok(other) => panic!("type byte dispatched to {other:?}"),
        }
    } else {
        assert_unexpected(copy.map(drop), frame);
    }

    // No view for client messages accepts a frame from the server.
    assert_unexpected(frontend::Message::from_frame(frame).map(drop), frame);

    let Ok(message) = dispatched else {
        return;
    };
    let _ = format!("{message:?}");
    exercise_backend(&message);
    if let Some(encoded) = reencode_backend(&message) {
        assert_eq!(
            encoded,
            frame.as_bytes(),
            "an accepted message has a second encoding"
        );
    }
}

fn check_frontend(frame: Frame<'_>) {
    use frontend::Message;

    let dispatched = Message::from_frame(frame);
    check_view!(frame, dispatched, frontend::Query, Message::Query);
    check_view!(frame, dispatched, frontend::Parse, Message::Parse);
    check_view!(frame, dispatched, frontend::Bind, Message::Bind);
    check_view!(frame, dispatched, frontend::Describe, Message::Describe);
    check_view!(frame, dispatched, frontend::Execute, Message::Execute);
    check_view!(frame, dispatched, frontend::Close, Message::Close);

    // No view for server messages accepts a frame from the client.
    assert_unexpected(backend::Message::from_frame(frame).map(drop), frame);

    let Ok(message) = dispatched else {
        return;
    };
    let _ = format!("{message:?}");
    exercise_frontend(&message);
}

/// `CopyData` is the one view that accepts both directions.
fn check_copy_data(frame: Frame<'_>) {
    let copy = CopyData::from_frame(frame);
    if frame.tag() == CopyData::TAG {
        assert_eq!(copy.map(|copy| copy.data()), Ok(frame.body()));
    } else {
        assert_unexpected(copy.map(drop), frame);
    }
}

/// Reads every part of a parsed backend message and checks that what the
/// view hands out agrees with what it announced.
fn exercise_backend(message: &backend::Message<'_>) {
    use backend::Message;
    match message {
        Message::Authentication(authentication) => {
            let _ = authentication.code();
            if let Authentication::Sasl(mechanisms) = authentication {
                for name in mechanisms.iter() {
                    assert!(!name.is_empty());
                    assert!(!name.contains(&0));
                    assert!(mechanisms.contains(name));
                }
            }
        }
        Message::BackendKeyData(key_data) => {
            let _ = key_data.process_id();
            assert!((4..=256).contains(&key_data.secret_key().len()));
        }
        Message::ParameterStatus(status) => {
            assert!(!status.name().contains(&0));
            assert!(!status.value().contains(&0));
        }
        Message::NegotiateProtocolVersion(negotiate) => {
            let _ = negotiate.version();
            assert_eq!(negotiate.options().count(), negotiate.option_count());
        }
        Message::RowDescription(description) => {
            assert_eq!(description.iter().count(), description.len());
            assert_eq!(description.iter().len(), description.len());
            for field in description.iter() {
                assert!(!field.name().contains(&0));
                let _ = (
                    field.table_oid(),
                    field.column_id(),
                    field.type_oid(),
                    field.type_size(),
                    field.type_modifier(),
                    field.format(),
                );
            }
        }
        Message::DataRow(row) => {
            assert_eq!(row.iter().count(), row.len());
            assert_eq!(row.columns().iter().len(), row.len());
        }
        Message::CommandComplete(complete) => {
            assert!(!complete.tag().contains(&0));
            assert_eq!(complete.rows(), complete.split_rows().map(|(_, rows)| rows));
        }
        Message::ReadyForQuery(ready) => {
            let _ = ready.status().to_byte();
        }
        Message::ErrorResponse(error) => exercise_error_fields(error.fields()),
        Message::NoticeResponse(notice) => exercise_error_fields(notice.fields()),
        Message::NotificationResponse(notification) => {
            let _ = notification.process_id();
            assert!(!notification.channel().contains(&0));
            assert!(!notification.payload().contains(&0));
        }
        Message::CopyResponse(copy) => {
            let _ = (copy.kind(), copy.overall_format());
            assert_eq!(
                copy.column_formats().iter().count(),
                copy.column_formats().len()
            );
        }
        Message::CopyData(copy) => {
            let _ = copy.data();
        }
        Message::Other(frame) => {
            let _ = frame.body();
        }
    }
}

fn exercise_error_fields(fields: backend::ErrorFields<'_>) {
    for field in fields.iter() {
        assert_ne!(field.code(), 0);
        assert!(!field.value().contains(&0));
        assert!(fields.get(field.code()).is_some());
    }
    let _ = (fields.severity(), fields.sqlstate(), fields.message());
    assert_eq!(fields.get(0), None);
}

/// Reads every part of a parsed frontend message.
fn exercise_frontend(message: &frontend::Message<'_>) {
    use frontend::Message;
    match message {
        Message::Query(query) => assert!(!query.sql().contains(&0)),
        Message::Parse(parse) => {
            assert!(!parse.statement().contains(&0));
            assert!(!parse.sql().contains(&0));
            let types = parse.parameter_types();
            assert_eq!(types.iter().count(), types.len());
            assert_eq!(types.get(types.len()), None);
        }
        Message::Bind(bind) => {
            assert!(!bind.portal().contains(&0));
            assert!(!bind.statement().contains(&0));
            assert_eq!(bind.parameters().iter().count(), bind.parameters().len());
            assert_eq!(
                bind.parameter_formats().iter().count(),
                bind.parameter_formats().len()
            );
            assert_eq!(
                bind.result_formats().iter().count(),
                bind.result_formats().len()
            );
            for index in 0..bind.parameters().len() {
                let _ = bind.parameter_formats().code_for(index);
            }
        }
        Message::Describe(describe) => {
            let _ = describe.target();
            assert!(!describe.name().contains(&0));
        }
        Message::Execute(execute) => {
            let _ = execute.max_rows();
            assert!(!execute.portal().contains(&0));
        }
        Message::Close(close) => {
            let _ = close.target();
            assert!(!close.name().contains(&0));
        }
        Message::CopyData(copy) => {
            let _ = copy.data();
        }
        Message::Other(frame) => {
            let _ = frame.body();
        }
    }
}

/// Encodes a parsed backend message again, where the crate has an encoder.
fn reencode_backend(message: &backend::Message<'_>) -> Option<Vec<u8>> {
    use backend::Message;
    let mut out = Vec::new();
    let result = match message {
        Message::Authentication(Authentication::Sasl(mechanisms)) => {
            let names: Vec<&[u8]> = mechanisms.iter().collect();
            encode::authentication_sasl(&names, &mut out)
        }
        Message::NegotiateProtocolVersion(negotiate) => {
            let options: Vec<&[u8]> = negotiate.options().collect();
            encode::negotiate_protocol_version(negotiate.version(), &options, &mut out)
        }
        Message::DataRow(row) => {
            let columns: Vec<Option<&[u8]>> = row.iter().collect();
            encode::data_row(&columns, &mut out)
        }
        Message::CommandComplete(complete) => {
            if let Some((command, rows)) = complete.split_rows() {
                let mut with_rows = Vec::new();
                encode::command_complete_with_rows(command, rows, &mut with_rows)
                    .expect("a tag that was read can be written");
                let mut plain = Vec::new();
                encode::command_complete(complete.tag(), &mut plain)
                    .expect("a tag that was read can be written");
                assert_eq!(with_rows, plain, "the two encoders disagree");
            }
            encode::command_complete(complete.tag(), &mut out)
        }
        Message::ErrorResponse(error) => {
            let fields: Vec<(u8, &[u8])> = error
                .fields()
                .iter()
                .map(|field| (field.code(), field.value()))
                .collect();
            encode::error_response(&fields, &mut out)
        }
        _ => return None,
    };
    result.expect("what a view read can be encoded");
    Some(out)
}

// ---------------------------------------------------------------------------
// Startup phase
// ---------------------------------------------------------------------------

/// Fuzzes the classifier of the first bytes of a connection and the views
/// of the startup-phase packets.
pub fn fuzz_startup(data: &[u8]) {
    let classified = startup::classify(data);
    let parsed = StartupPacket::parse(data);

    // A TLS handshake is decided on the first byte. Anything else is
    // whatever the packet parser says.
    if data.first() == Some(&startup::TLS_HANDSHAKE_RECORD) {
        assert_eq!(classified, Ok(Classification::DirectTls));
    } else {
        let expected = parsed.map(|packet| match packet {
            Some(packet) => Classification::Packet(packet),
            None => Classification::Incomplete,
        });
        assert_eq!(classified, expected);
    }

    // A verdict reached on a prefix is final.
    for end in [0, 1, 3, 4, 7, 8, 11, 12, 13, data.len().saturating_sub(1)] {
        let Some(prefix) = data.get(..end) else {
            continue;
        };
        match StartupPacket::parse(prefix) {
            Ok(None) => {}
            earlier => assert_eq!(earlier, parsed, "more bytes changed the verdict"),
        }
    }

    match parsed {
        Ok(Some(packet)) => check_startup_packet(data, packet),
        Ok(None) => {}
        Err(StartupError::MalformedParameters) => {
            // PostgreSQL accepts one form this crate refuses: a parameter
            // list whose last byte is not zero.
            if let Some(packet) = declared_packet(data)
                && postgres_startup_parameters(&packet[4..]).is_some()
            {
                assert_ne!(packet.last(), Some(&0));
            }
        }
        Err(_) => {}
    }
}

fn check_startup_packet(data: &[u8], packet: StartupPacket<'_>) {
    let len = packet.wire_len();
    assert!((8..=10_004).contains(&len));
    let bytes = &data[..len];
    // The packet is read from its own bytes only.
    assert_eq!(StartupPacket::parse(bytes), Ok(Some(packet)));
    let _ = format!("{packet:?}");

    let mut encoded = Vec::new();
    match packet {
        StartupPacket::SslRequest => {
            encode::ssl_request(&mut encoded).expect("a fixed packet can be written");
        }
        StartupPacket::GssEncRequest => {
            encoded.extend_from_slice(&[0, 0, 0, 8, 0x04, 0xd2, 0x16, 0x30]);
        }
        StartupPacket::CancelRequest(request) => {
            assert_eq!(request.as_bytes(), bytes);
            assert!((1..=256).contains(&request.secret_key().len()));
            encode::cancel_request(request.process_id(), request.secret_key(), &mut encoded)
                .expect("a request that was read can be written");
        }
        StartupPacket::StartupMessage(message) => {
            assert_eq!(message.as_bytes(), bytes);
            assert_eq!(message.version().major(), 3);
            let parameters: Vec<(&[u8], &[u8])> = message
                .parameters()
                .map(|parameter| (parameter.name(), parameter.value()))
                .collect();
            for (name, value) in &parameters {
                assert!(!name.is_empty());
                assert!(!name.contains(&0) && !value.contains(&0));
                assert!(message.get(name).is_some());
            }
            // PostgreSQL reads the same packet into the same pairs.
            let reference = postgres_startup_parameters(&bytes[4..])
                .expect("PostgreSQL rejects a packet this crate accepts");
            let ours: Vec<(Vec<u8>, Vec<u8>)> = parameters
                .iter()
                .map(|(name, value)| (name.to_vec(), value.to_vec()))
                .collect();
            assert_eq!(ours, reference);

            encode::startup_message(message.version(), &parameters, &mut encoded)
                .expect("a message that was read can be written");
        }
    }
    assert_eq!(encoded, bytes, "an accepted packet has a second encoding");
}

/// The bytes of the packet that the length field at the front of `data`
/// announces, if `data` holds all of them.
fn declared_packet(data: &[u8]) -> Option<&[u8]> {
    let length = u32::from_be_bytes(*data.first_chunk::<4>()?);
    data.get(..usize::try_from(length).ok()?)
}

/// The parameter loop of PostgreSQL's `ProcessStartupPacket`, ported line
/// by line. `body` is a startup packet without its length field.
///
/// Returns the name and value pairs, or `None` where PostgreSQL reports
/// "invalid startup packet layout: expected terminator as last byte".
fn postgres_startup_parameters(body: &[u8]) -> Option<Vec<(Vec<u8>, Vec<u8>)>> {
    let len = body.len();
    // PostgreSQL appends a zero byte, so that every string in the packet is
    // terminated.
    let mut buf = body.to_vec();
    buf.push(0);
    let strlen = |from: usize| buf[from..].iter().position(|&byte| byte == 0).unwrap_or(0);

    let mut offset = 4; // sizeof(ProtocolVersion)
    let mut pairs = Vec::new();
    while offset < len {
        if buf[offset] == 0 {
            break; // found packet terminator
        }
        let name_len = strlen(offset);
        let valoffset = offset + name_len + 1;
        if valoffset >= len {
            break; // missing value, will complain below
        }
        let value_len = strlen(valoffset);
        pairs.push((
            buf[offset..offset + name_len].to_vec(),
            buf[valoffset..valoffset + value_len].to_vec(),
        ));
        offset = valoffset + value_len + 1;
    }
    if offset + 1 != len {
        return None;
    }
    Some(pairs)
}
