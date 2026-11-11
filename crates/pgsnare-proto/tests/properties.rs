// SPDX-License-Identifier: Apache-2.0

//! Property tests for the framer, the startup phase, the views and the
//! encoders.

use pgsnare_proto::backend::{self, Authentication};
use pgsnare_proto::startup::{self, Classification, StartupPacket};
use pgsnare_proto::{
    Direction, EncodeError, Frame, FrameError, Framer, HEADER_LEN, Limits, ProtocolVersion,
    StartupError, Step, encode, frontend,
};
use proptest::prelude::*;
use proptest::sample::Index;

// ---------------------------------------------------------------------------
// Framing
// ---------------------------------------------------------------------------

/// A frame as the framer reported it, with the chunks of a streamed body
/// joined, so that results can be compared whatever the chunk boundaries.
#[derive(Clone, Debug, PartialEq, Eq)]
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
    /// The error that ended the stream, if any.
    error: Option<FrameError>,
    /// The bytes still unconsumed when the stream ended without an error.
    leftover: Vec<u8>,
    /// The body bytes of a streamed frame still missing at the end.
    stream_remaining: u32,
}

/// Turns arbitrary indexes into sorted cut positions inside `len` bytes.
fn cut_positions(cuts: &[Index], len: usize) -> Vec<usize> {
    let mut positions: Vec<usize> = cuts.iter().map(|cut| cut.index(len + 1)).collect();
    positions.sort_unstable();
    positions
}

/// Feeds `stream` to a framer in the pieces given by `cuts`, the way a
/// connection delivers it: each piece is appended to what the framer left
/// unconsumed the last time.
fn run_framer(direction: Direction, limits: Limits, stream: &[u8], cuts: &[usize]) -> Outcome {
    let mut framer = Framer::new(direction, limits);
    let mut pending: Vec<u8> = Vec::new();
    let mut found = Vec::new();
    let mut error = None;

    let mut start = 0;
    let ends = cuts.iter().copied().chain([stream.len()]);
    for end in ends {
        pending.extend_from_slice(&stream[start..end]);
        start = end;

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
                    assert_eq!(unread.len(), before, "NeedMore must consume nothing");
                    assert!(needed > before, "the hint must ask for more than is there");
                    break;
                }
                Err(first) => {
                    assert_eq!(unread.len(), before, "an error must consume nothing");
                    assert_eq!(framer.next(&mut unread), Err(first), "an error must repeat");
                    error = Some(first);
                    break;
                }
            }
        }
        let consumed = pending.len() - unread.len();
        pending.drain(..consumed);
        if error.is_some() {
            // Nothing after a framing error can be trusted.
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

/// The wire bytes of a frame.
fn wire(tag: u8, body: &[u8]) -> Vec<u8> {
    let mut bytes = vec![tag];
    bytes.extend_from_slice(&u32::try_from(body.len() + 4).unwrap().to_be_bytes());
    bytes.extend_from_slice(body);
    bytes
}

/// What a framer must report for a stream made of exactly these frames.
fn expected_outcome(frames: &[(u8, Vec<u8>)], limits: Limits) -> Outcome {
    let mut found = Vec::new();
    let mut error = None;
    for (tag, body) in frames {
        let frame_len = body.len() + HEADER_LEN;
        let length = u32::try_from(body.len() + 4).unwrap();
        if frame_len > limits.max_frame() {
            error = Some(FrameError::FrameTooLarge { tag: *tag, length });
            break;
        }
        found.push(if frame_len <= limits.max_buffered() {
            Found::Whole {
                tag: *tag,
                body: body.clone(),
            }
        } else {
            Found::Streamed {
                tag: *tag,
                body_len: length - 4,
                body: body.clone(),
            }
        });
    }
    Outcome {
        found,
        error,
        leftover: Vec::new(),
        stream_remaining: 0,
    }
}

fn direction() -> impl Strategy<Value = Direction> {
    prop_oneof![Just(Direction::FromClient), Just(Direction::FromServer)]
}

/// Frames of any type byte, with bodies from empty to a few hundred bytes.
fn frames() -> impl Strategy<Value = Vec<(u8, Vec<u8>)>> {
    prop::collection::vec(
        (any::<u8>(), prop::collection::vec(any::<u8>(), 0..300)),
        0..10,
    )
}

/// Limits small enough that the generated frames are sometimes returned
/// whole, sometimes streamed and sometimes refused.
fn small_limits() -> impl Strategy<Value = Limits> {
    prop_oneof![
        // Everything fits.
        Just(Limits::buffered_only(1 << 20)),
        // Large frames are streamed.
        (0usize..200).prop_map(|buffered| Limits::new(buffered, 1 << 20)),
        // Large frames are streamed, larger ones refused.
        (0usize..200, 0usize..400).prop_map(|(buffered, max)| Limits::new(buffered, max)),
    ]
}

fn cuts() -> impl Strategy<Value = Vec<Index>> {
    prop::collection::vec(any::<Index>(), 0..12)
}

proptest! {
    /// A stream of well-formed frames yields exactly those frames, whole or
    /// streamed as the limits say, however the stream is cut into pieces.
    #[test]
    fn framed_stream_yields_its_frames_under_any_split(
        direction in direction(),
        frames in frames(),
        limits in small_limits(),
        cuts in cuts(),
    ) {
        let stream: Vec<u8> = frames.iter().flat_map(|(tag, body)| wire(*tag, body)).collect();
        let positions = cut_positions(&cuts, stream.len());
        let expected = expected_outcome(&frames, limits);

        let split = run_framer(direction, limits, &stream, &positions);
        prop_assert_eq!(&split, &expected);
        let unsplit = run_framer(direction, limits, &stream, &[]);
        prop_assert_eq!(&unsplit, &expected);
    }

    /// The same holds when the stream is fed one byte at a time.
    #[test]
    fn framed_stream_yields_its_frames_byte_by_byte(
        direction in direction(),
        frames in frames(),
        limits in small_limits(),
    ) {
        let stream: Vec<u8> = frames.iter().flat_map(|(tag, body)| wire(*tag, body)).collect();
        let every_position: Vec<usize> = (0..=stream.len()).collect();
        let split = run_framer(direction, limits, &stream, &every_position);
        prop_assert_eq!(split, expected_outcome(&frames, limits));
    }

    /// Arbitrary bytes, which are rarely well-formed, give the same frames,
    /// the same error and the same unconsumed rest however they are cut.
    #[test]
    fn arbitrary_bytes_frame_the_same_under_any_split(
        direction in direction(),
        stream in prop::collection::vec(any::<u8>(), 0..600),
        limits in prop_oneof![
            small_limits(),
            (0usize..64).prop_map(|buffered| Limits::new(buffered, usize::MAX)),
        ],
        cuts in cuts(),
    ) {
        let positions = cut_positions(&cuts, stream.len());
        let split = run_framer(direction, limits, &stream, &positions);
        let unsplit = run_framer(direction, limits, &stream, &[]);
        prop_assert_eq!(split, unsplit);
    }

    /// A well-formed stream cut short or damaged in one place still frames
    /// the same under any split.
    #[test]
    fn damaged_stream_frames_the_same_under_any_split(
        direction in direction(),
        frames in frames(),
        limits in small_limits(),
        truncate_at in any::<Index>(),
        damage in prop::option::of((any::<Index>(), any::<u8>())),
        cuts in cuts(),
    ) {
        let mut stream: Vec<u8> = frames.iter().flat_map(|(tag, body)| wire(*tag, body)).collect();
        stream.truncate(truncate_at.index(stream.len() + 1));
        if let (Some((position, value)), false) = (damage, stream.is_empty()) {
            let position = position.index(stream.len());
            stream[position] = value;
        }
        let positions = cut_positions(&cuts, stream.len());
        let split = run_framer(direction, limits, &stream, &positions);
        let unsplit = run_framer(direction, limits, &stream, &[]);
        prop_assert_eq!(split, unsplit);
    }

    /// The framer accepts every length from 4 up to the maximum and refuses
    /// every other length, for every type byte.
    #[test]
    fn length_field_is_validated(tag in any::<u8>(), length in any::<u32>(), max in 0usize..100_000) {
        let mut header = vec![tag];
        header.extend_from_slice(&length.to_be_bytes());
        let mut framer = Framer::new(Direction::FromServer, Limits::new(16, max));
        let mut unread = &header[..];
        let result = framer.next(&mut unread);

        let frame_len = u64::from(length) + 1;
        if length < 4 {
            prop_assert_eq!(result, Err(FrameError::LengthTooSmall { tag, length }));
        } else if length > 0x7fff_ffff || frame_len > max as u64 {
            prop_assert_eq!(result, Err(FrameError::FrameTooLarge { tag, length }));
        } else {
            prop_assert!(matches!(
                result,
                Ok(Step::Frame(_) | Step::StreamStart(_) | Step::NeedMore(_))
            ));
        }
    }
}

// ---------------------------------------------------------------------------
// Views
// ---------------------------------------------------------------------------

/// Frames `bytes`, which must hold at least one whole frame, and returns
/// the first.
fn first_frame(direction: Direction, bytes: &[u8]) -> Frame<'_> {
    let mut framer = Framer::new(direction, Limits::buffered_only(usize::MAX));
    let mut unread = bytes;
    match framer.next(&mut unread) {
        Ok(Step::Frame(frame)) => frame,
        other => panic!("expected a frame, got {other:?}"),
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

/// Encodes a parsed backend message again, where an encoder exists.
fn reencode_backend(message: &backend::Message<'_>) -> Option<Vec<u8>> {
    use backend::Message;
    let mut out = Vec::new();
    match message {
        Message::Authentication(Authentication::Sasl(mechanisms)) => {
            let names: Vec<&[u8]> = mechanisms.iter().collect();
            encode::authentication_sasl(&names, &mut out).unwrap();
        }
        Message::NegotiateProtocolVersion(negotiate) => {
            let options: Vec<&[u8]> = negotiate.options().collect();
            encode::negotiate_protocol_version(negotiate.version(), &options, &mut out).unwrap();
        }
        Message::DataRow(row) => {
            let columns: Vec<Option<&[u8]>> = row.iter().collect();
            encode::data_row(&columns, &mut out).unwrap();
        }
        Message::CommandComplete(complete) => {
            encode::command_complete(complete.tag(), &mut out).unwrap();
            if let Some((command, rows)) = complete.split_rows() {
                let mut with_rows = Vec::new();
                encode::command_complete_with_rows(command, rows, &mut with_rows).unwrap();
                assert_eq!(with_rows, out, "both encoders must agree");
            }
        }
        Message::ErrorResponse(error) => {
            let fields: Vec<(u8, &[u8])> = error
                .fields()
                .iter()
                .map(|field| (field.code(), field.value()))
                .collect();
            encode::error_response(&fields, &mut out).unwrap();
        }
        _ => return None,
    }
    Some(out)
}

/// A body that is sometimes well-formed for some message: a run of short
/// strings, counts and lengths rather than uniform noise.
fn structured_body() -> impl Strategy<Value = Vec<u8>> {
    let piece = prop_oneof![
        4 => prop::collection::vec(prop_oneof![Just(0u8), Just(1), Just(2), Just(0xff)], 1..5),
        3 => "[a-zA-Z0-9_. -]{0,8}".prop_map(|text| {
            let mut bytes = text.into_bytes();
            bytes.push(0);
            bytes
        }),
        1 => prop::collection::vec(any::<u8>(), 0..6),
        1 => prop::sample::select(vec![
            b"S".to_vec(), b"P".to_vec(), b"I".to_vec(), b"T".to_vec(), b"E".to_vec(),
            vec![0, 0, 0, 10], vec![0, 0, 0, 5], vec![0, 3, 0, 0], vec![0, 3, 0, 2],
        ]),
    ];
    prop::collection::vec(piece, 0..10).prop_map(|pieces| pieces.concat())
}

/// The type bytes that have a view in either direction, and a few that do
/// not.
fn tag() -> impl Strategy<Value = u8> {
    prop_oneof![
        8 => prop::sample::select(b"RKSvTDCZENAGHWdQPBXcf12".to_vec()),
        1 => any::<u8>(),
    ]
}

proptest! {
    /// No body makes a view panic. A body a view accepts is consistent with
    /// what the view announces, and encodes back to the identical bytes.
    #[test]
    fn backend_views_accept_or_reject_any_body(
        tag in tag(),
        body in prop_oneof![structured_body(), prop::collection::vec(any::<u8>(), 0..64)],
    ) {
        let bytes = wire(tag, &body);
        let frame = first_frame(Direction::FromServer, &bytes);
        if let Ok(message) = backend::Message::from_frame(frame) {
            exercise_backend(&message);
            // Debug output is always available and never the content.
            let _ = format!("{message:?}");
            if let Some(encoded) = reencode_backend(&message) {
                prop_assert_eq!(&encoded, &bytes);
            }
        }
        // A frame of the other direction is never accepted.
        let wrong = first_frame(Direction::FromClient, &bytes);
        prop_assert!(backend::Message::from_frame(wrong).is_err());
    }

    /// The same for the views of client messages.
    #[test]
    fn frontend_views_accept_or_reject_any_body(
        tag in tag(),
        body in prop_oneof![structured_body(), prop::collection::vec(any::<u8>(), 0..64)],
    ) {
        let bytes = wire(tag, &body);
        let frame = first_frame(Direction::FromClient, &bytes);
        if let Ok(message) = frontend::Message::from_frame(frame) {
            exercise_frontend(&message);
            let _ = format!("{message:?}");
        }
        let wrong = first_frame(Direction::FromServer, &bytes);
        prop_assert!(frontend::Message::from_frame(wrong).is_err());
    }

    /// A view reads its frame and nothing else: the bytes that follow the
    /// frame in the buffer never change the result.
    #[test]
    fn views_ignore_what_follows_the_frame(
        tag in tag(),
        body in prop_oneof![structured_body(), prop::collection::vec(any::<u8>(), 0..64)],
        following in prop_oneof![structured_body(), prop::collection::vec(any::<u8>(), 0..64)],
    ) {
        let alone = wire(tag, &body);
        let mut followed = alone.clone();
        followed.extend_from_slice(&following);

        let backend_alone = backend::Message::from_frame(first_frame(Direction::FromServer, &alone));
        let backend_followed =
            backend::Message::from_frame(first_frame(Direction::FromServer, &followed));
        prop_assert_eq!(backend_alone, backend_followed);

        let frontend_alone =
            frontend::Message::from_frame(first_frame(Direction::FromClient, &alone));
        let frontend_followed =
            frontend::Message::from_frame(first_frame(Direction::FromClient, &followed));
        prop_assert_eq!(frontend_alone, frontend_followed);
    }
}

// ---------------------------------------------------------------------------
// Encoders
// ---------------------------------------------------------------------------

/// A byte string without a zero byte.
fn text(max_len: usize) -> impl Strategy<Value = Vec<u8>> {
    prop::collection::vec(1u8..=255, 0..=max_len)
}

/// A byte string without a zero byte and with at least one byte.
fn name(max_len: usize) -> impl Strategy<Value = Vec<u8>> {
    prop::collection::vec(1u8..=255, 1..=max_len)
}

proptest! {
    #[test]
    fn error_response_round_trips(
        fields in prop::collection::vec((1u8..=255, text(40)), 0..12),
    ) {
        let borrowed: Vec<(u8, &[u8])> =
            fields.iter().map(|(code, value)| (*code, value.as_slice())).collect();
        let mut bytes = Vec::new();
        encode::error_response(&borrowed, &mut bytes).unwrap();

        let frame = first_frame(Direction::FromServer, &bytes);
        prop_assert_eq!(frame.wire_len(), bytes.len());
        let parsed = backend::ErrorResponse::from_frame(frame).unwrap();
        let read: Vec<(u8, &[u8])> = parsed
            .fields()
            .iter()
            .map(|field| (field.code(), field.value()))
            .collect();
        prop_assert_eq!(read, borrowed);
    }

    #[test]
    fn data_row_round_trips(
        columns in prop::collection::vec(
            prop::option::of(prop::collection::vec(any::<u8>(), 0..40)),
            0..20,
        ),
    ) {
        let borrowed: Vec<Option<&[u8]>> = columns.iter().map(Option::as_deref).collect();
        let mut bytes = Vec::new();
        encode::data_row(&borrowed, &mut bytes).unwrap();

        let frame = first_frame(Direction::FromServer, &bytes);
        prop_assert_eq!(frame.wire_len(), bytes.len());
        let parsed = backend::DataRow::from_frame(frame).unwrap();
        prop_assert_eq!(parsed.len(), borrowed.len());
        prop_assert_eq!(parsed.iter().collect::<Vec<_>>(), borrowed);
    }

    #[test]
    fn command_complete_round_trips(tag in text(60)) {
        let mut bytes = Vec::new();
        encode::command_complete(&tag, &mut bytes).unwrap();
        let frame = first_frame(Direction::FromServer, &bytes);
        prop_assert_eq!(frame.wire_len(), bytes.len());
        let parsed = backend::CommandComplete::from_frame(frame).unwrap();
        prop_assert_eq!(parsed.tag(), tag.as_slice());
    }

    #[test]
    fn command_complete_with_rows_round_trips(command in name(30), rows in any::<u64>()) {
        let mut bytes = Vec::new();
        encode::command_complete_with_rows(&command, rows, &mut bytes).unwrap();
        let frame = first_frame(Direction::FromServer, &bytes);
        prop_assert_eq!(frame.wire_len(), bytes.len());
        let parsed = backend::CommandComplete::from_frame(frame).unwrap();
        prop_assert_eq!(parsed.split_rows(), Some((command.as_slice(), rows)));
        prop_assert_eq!(parsed.rows(), Some(rows));
    }

    #[test]
    fn negotiate_protocol_version_round_trips(
        version in any::<u32>(),
        options in prop::collection::vec(text(30), 0..8),
    ) {
        let version = ProtocolVersion::from_u32(version);
        let borrowed: Vec<&[u8]> = options.iter().map(Vec::as_slice).collect();
        let mut bytes = Vec::new();
        encode::negotiate_protocol_version(version, &borrowed, &mut bytes).unwrap();

        let frame = first_frame(Direction::FromServer, &bytes);
        prop_assert_eq!(frame.wire_len(), bytes.len());
        let parsed = backend::NegotiateProtocolVersion::from_frame(frame).unwrap();
        prop_assert_eq!(parsed.version(), version);
        prop_assert_eq!(parsed.option_count(), borrowed.len());
        prop_assert_eq!(parsed.options().collect::<Vec<_>>(), borrowed);
    }

    #[test]
    fn authentication_sasl_round_trips(mechanisms in prop::collection::vec(name(30), 0..6)) {
        let borrowed: Vec<&[u8]> = mechanisms.iter().map(Vec::as_slice).collect();
        let mut bytes = Vec::new();
        encode::authentication_sasl(&borrowed, &mut bytes).unwrap();

        let frame = first_frame(Direction::FromServer, &bytes);
        prop_assert_eq!(frame.wire_len(), bytes.len());
        let Ok(Authentication::Sasl(parsed)) = Authentication::from_frame(frame) else {
            return Err(TestCaseError::fail("expected AuthenticationSASL"));
        };
        prop_assert_eq!(parsed.iter().collect::<Vec<_>>(), borrowed);
    }

    #[test]
    fn startup_message_round_trips(
        minor in any::<u16>(),
        parameters in prop::collection::vec((name(20), text(40)), 0..10),
    ) {
        let version = ProtocolVersion::new(3, minor);
        let borrowed: Vec<(&[u8], &[u8])> = parameters
            .iter()
            .map(|(name, value)| (name.as_slice(), value.as_slice()))
            .collect();
        let mut bytes = Vec::new();
        encode::startup_message(version, &borrowed, &mut bytes).unwrap();

        let Ok(Classification::Packet(StartupPacket::StartupMessage(parsed))) =
            startup::classify(&bytes)
        else {
            return Err(TestCaseError::fail("expected a startup message"));
        };
        prop_assert_eq!(parsed.as_bytes(), bytes.as_slice());
        prop_assert_eq!(parsed.version(), version);
        let read: Vec<(&[u8], &[u8])> = parsed
            .parameters()
            .map(|parameter| (parameter.name(), parameter.value()))
            .collect();
        prop_assert_eq!(&read, &borrowed);
        // A lookup returns the last value given for a name.
        for (name, _) in &borrowed {
            let last = borrowed.iter().rev().find(|(other, _)| other == name).map(|(_, value)| *value);
            prop_assert_eq!(parsed.get(name), last);
        }
    }

    #[test]
    fn cancel_request_round_trips(
        process_id in any::<i32>(),
        key in prop::collection::vec(any::<u8>(), 1..=256),
    ) {
        let mut bytes = Vec::new();
        encode::cancel_request(process_id, &key, &mut bytes).unwrap();
        prop_assert_eq!(bytes.len(), 12 + key.len());

        let Ok(Classification::Packet(StartupPacket::CancelRequest(parsed))) =
            startup::classify(&bytes)
        else {
            return Err(TestCaseError::fail("expected a cancel request"));
        };
        prop_assert_eq!(parsed.process_id(), process_id);
        prop_assert_eq!(parsed.secret_key(), key.as_slice());
        prop_assert_eq!(parsed.as_bytes(), bytes.as_slice());
    }

    /// An encoder refuses a string with a zero byte and writes nothing.
    #[test]
    fn encoders_refuse_embedded_zero_bytes(prefix in text(10), suffix in text(10)) {
        let mut poisoned = prefix.clone();
        poisoned.push(0);
        poisoned.extend_from_slice(&suffix);
        let mut out = Vec::new();

        prop_assert_eq!(
            encode::error_response(&[(b'M', &poisoned)], &mut out),
            Err(EncodeError::NulInString)
        );
        prop_assert_eq!(
            encode::command_complete(&poisoned, &mut out),
            Err(EncodeError::NulInString)
        );
        prop_assert_eq!(
            encode::command_complete_with_rows(&poisoned, 1, &mut out),
            Err(EncodeError::NulInString)
        );
        prop_assert_eq!(
            encode::negotiate_protocol_version(ProtocolVersion::V3_0, &[&poisoned], &mut out),
            Err(EncodeError::NulInString)
        );
        if !prefix.is_empty() {
            prop_assert_eq!(
                encode::authentication_sasl(&[&poisoned], &mut out),
                Err(EncodeError::NulInString)
            );
            prop_assert_eq!(
                encode::startup_message(ProtocolVersion::V3_0, &[(&poisoned, b"v")], &mut out),
                Err(EncodeError::NulInString)
            );
        }
        prop_assert_eq!(
            encode::startup_message(ProtocolVersion::V3_0, &[(b"n", &poisoned)], &mut out),
            Err(EncodeError::NulInString)
        );
        prop_assert!(out.is_empty());
    }
}

#[test]
fn ssl_request_round_trips() {
    let mut bytes = Vec::new();
    encode::ssl_request(&mut bytes).unwrap();
    assert_eq!(
        startup::classify(&bytes),
        Ok(Classification::Packet(StartupPacket::SslRequest))
    );
}

// ---------------------------------------------------------------------------
// Startup phase
// ---------------------------------------------------------------------------

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
    let strlen = |from: usize| buf[from..].iter().position(|&byte| byte == 0).unwrap();

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
    if offset != len - 1 {
        return None;
    }
    Some(pairs)
}

/// The bytes after the version of a startup packet: often a well-formed
/// parameter list, often nearly one.
fn parameter_region() -> impl Strategy<Value = Vec<u8>> {
    prop::collection::vec(
        prop_oneof![3 => Just(0u8), 5 => b'a'..=b'c', 1 => any::<u8>()],
        0..24,
    )
}

fn startup_packet(version: ProtocolVersion, region: &[u8]) -> Vec<u8> {
    let mut bytes = u32::try_from(region.len() + 8)
        .unwrap()
        .to_be_bytes()
        .to_vec();
    bytes.extend_from_slice(&version.to_u32().to_be_bytes());
    bytes.extend_from_slice(region);
    bytes
}

proptest! {
    /// The startup parser never accepts a packet PostgreSQL rejects, and
    /// reads the packets it accepts into the same pairs as PostgreSQL. The
    /// one packet form PostgreSQL accepts and this crate does not is a
    /// parameter list whose last byte is not zero.
    #[test]
    fn startup_parameters_agree_with_postgresql(minor in 0u16..4, region in parameter_region()) {
        let bytes = startup_packet(ProtocolVersion::new(3, minor), &region);
        let reference = postgres_startup_parameters(&bytes[4..]);

        match StartupPacket::parse(&bytes) {
            Ok(Some(StartupPacket::StartupMessage(message))) => {
                let ours: Vec<(Vec<u8>, Vec<u8>)> = message
                    .parameters()
                    .map(|parameter| (parameter.name().to_vec(), parameter.value().to_vec()))
                    .collect();
                prop_assert_eq!(Some(ours), reference);
                for parameter in message.parameters() {
                    prop_assert!(!parameter.name().is_empty());
                }
            }
            Err(StartupError::MalformedParameters) => {
                if reference.is_some() {
                    prop_assert_ne!(bytes.last().copied(), Some(0));
                }
            }
            other => return Err(TestCaseError::fail(format!("unexpected result {other:?}"))),
        }
    }

    /// Classification depends only on the bytes of the packet: a verdict
    /// reached on a prefix is never changed by the bytes that follow, and
    /// arbitrary input never panics.
    #[test]
    fn classification_is_stable_as_bytes_arrive(
        bytes in prop_oneof![
            prop::collection::vec(any::<u8>(), 0..64),
            // A plausible length and code in front of arbitrary bytes.
            (
                0u32..40,
                prop::sample::select(vec![
                    196_608u32, 196_610, 80_877_102, 80_877_103, 80_877_104, 131_072, 0,
                ]),
                parameter_region(),
            )
                .prop_map(|(length, code, rest)| {
                    let mut bytes = length.to_be_bytes().to_vec();
                    bytes.extend_from_slice(&code.to_be_bytes());
                    bytes.extend_from_slice(&rest);
                    bytes
                }),
        ],
    ) {
        let mut verdict: Option<Result<Classification<'_>, StartupError>> = None;
        for end in 0..=bytes.len() {
            let now = startup::classify(&bytes[..end]);
            match (&verdict, &now) {
                // Still undecided.
                (None, Ok(Classification::Incomplete)) => {}
                (None, _) => verdict = Some(now),
                // Once decided, the verdict stays.
                (Some(earlier), _) => prop_assert_eq!(earlier, &now),
            }
            if let Ok(Classification::Packet(packet)) = now {
                prop_assert!(packet.wire_len() <= end);
                prop_assert!((8..=10_004).contains(&packet.wire_len()));
                let _ = format!("{packet:?}");
            }
        }
    }

    /// A startup-phase packet is read from its own bytes only.
    #[test]
    fn startup_packets_ignore_what_follows(
        region in parameter_region(),
        following in parameter_region(),
    ) {
        let alone = startup_packet(ProtocolVersion::V3_0, &region);
        let mut followed = alone.clone();
        followed.extend_from_slice(&following);
        prop_assert_eq!(StartupPacket::parse(&alone), StartupPacket::parse(&followed));
    }
}
