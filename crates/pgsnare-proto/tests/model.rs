// SPDX-License-Identifier: Apache-2.0

//! Model-based tests of the views.
//!
//! Every message has a model here: its fields as plain owned values, with a
//! reference encoder written independently of the crate. Two properties tie
//! the views to the models:
//!
//! - A view reads an encoded model back as the same values.
//! - If a view accepts some bytes, encoding what it read gives back exactly
//!   those bytes. A view therefore accepts one byte string per message and
//!   nothing else: no trailing bytes, no missing terminator, no second way
//!   to write the same thing.
//!
//! The second property is checked on encoded models that were damaged in
//! one place, which is where a lenient parser would show.

use pgsnare_proto::backend::{self, Authentication, CopyKind};
use pgsnare_proto::frontend::{self, Target};
use pgsnare_proto::startup::StartupPacket;
use pgsnare_proto::{Direction, Frame, Framer, Limits, ProtocolVersion, Step, encode};
use proptest::prelude::*;
use proptest::sample::Index;

/// The wire bytes of a frame.
fn wire(tag: u8, body: &[u8]) -> Vec<u8> {
    let mut bytes = vec![tag];
    bytes.extend_from_slice(&u32::try_from(body.len() + 4).unwrap().to_be_bytes());
    bytes.extend_from_slice(body);
    bytes
}

/// Frames `bytes`, which must hold exactly one frame.
fn only_frame(direction: Direction, bytes: &[u8]) -> Frame<'_> {
    let mut framer = Framer::new(direction, Limits::buffered_only(usize::MAX));
    let mut unread = bytes;
    match framer.next(&mut unread) {
        Ok(Step::Frame(frame)) if unread.is_empty() => frame,
        other => panic!("expected exactly one frame, got {other:?}"),
    }
}

fn put_cstr(out: &mut Vec<u8>, string: &[u8]) {
    out.extend_from_slice(string);
    out.push(0);
}

fn put_values(out: &mut Vec<u8>, values: &[Option<Vec<u8>>]) {
    out.extend_from_slice(&u16::try_from(values.len()).unwrap().to_be_bytes());
    for value in values {
        match value {
            None => out.extend_from_slice(&(-1i32).to_be_bytes()),
            Some(value) => {
                out.extend_from_slice(&i32::try_from(value.len()).unwrap().to_be_bytes());
                out.extend_from_slice(value);
            }
        }
    }
}

fn put_formats(out: &mut Vec<u8>, formats: &[i16]) {
    out.extend_from_slice(&u16::try_from(formats.len()).unwrap().to_be_bytes());
    for format in formats {
        out.extend_from_slice(&format.to_be_bytes());
    }
}

// ---------------------------------------------------------------------------
// Models of the messages a server sends
// ---------------------------------------------------------------------------

#[derive(Clone, Debug, PartialEq, Eq)]
struct Field {
    name: Vec<u8>,
    table_oid: u32,
    column_id: i16,
    type_oid: u32,
    type_size: i16,
    type_modifier: i32,
    format: i16,
}

#[derive(Clone, Debug, PartialEq, Eq)]
enum ServerModel {
    /// The authentication messages that consist of their code alone.
    AuthenticationFixed {
        code: u32,
    },
    AuthenticationMd5 {
        salt: [u8; 4],
    },
    AuthenticationSasl {
        mechanisms: Vec<Vec<u8>>,
    },
    /// The authentication messages that carry opaque data after the code,
    /// and those with a code the crate does not know.
    AuthenticationData {
        code: u32,
        data: Vec<u8>,
    },
    BackendKeyData {
        process_id: i32,
        key: Vec<u8>,
    },
    ParameterStatus {
        name: Vec<u8>,
        value: Vec<u8>,
    },
    NegotiateProtocolVersion {
        version: u32,
        options: Vec<Vec<u8>>,
    },
    RowDescription {
        fields: Vec<Field>,
    },
    DataRow {
        columns: Vec<Option<Vec<u8>>>,
    },
    CommandComplete {
        tag: Vec<u8>,
    },
    ReadyForQuery {
        status: u8,
    },
    ErrorResponse {
        fields: Vec<(u8, Vec<u8>)>,
    },
    NoticeResponse {
        fields: Vec<(u8, Vec<u8>)>,
    },
    NotificationResponse {
        process_id: i32,
        channel: Vec<u8>,
        payload: Vec<u8>,
    },
    CopyResponse {
        tag: u8,
        overall_format: u8,
        column_formats: Vec<i16>,
    },
    CopyData {
        data: Vec<u8>,
    },
}

impl ServerModel {
    /// The reference encoding of the message.
    fn encode(&self) -> Vec<u8> {
        let mut body = Vec::new();
        let tag = match self {
            Self::AuthenticationFixed { code } => {
                body.extend_from_slice(&code.to_be_bytes());
                b'R'
            }
            Self::AuthenticationMd5 { salt } => {
                body.extend_from_slice(&5u32.to_be_bytes());
                body.extend_from_slice(salt);
                b'R'
            }
            Self::AuthenticationSasl { mechanisms } => {
                body.extend_from_slice(&10u32.to_be_bytes());
                for mechanism in mechanisms {
                    put_cstr(&mut body, mechanism);
                }
                body.push(0);
                b'R'
            }
            Self::AuthenticationData { code, data } => {
                body.extend_from_slice(&code.to_be_bytes());
                body.extend_from_slice(data);
                b'R'
            }
            Self::BackendKeyData { process_id, key } => {
                body.extend_from_slice(&process_id.to_be_bytes());
                body.extend_from_slice(key);
                b'K'
            }
            Self::ParameterStatus { name, value } => {
                put_cstr(&mut body, name);
                put_cstr(&mut body, value);
                b'S'
            }
            Self::NegotiateProtocolVersion { version, options } => {
                body.extend_from_slice(&version.to_be_bytes());
                body.extend_from_slice(&i32::try_from(options.len()).unwrap().to_be_bytes());
                for option in options {
                    put_cstr(&mut body, option);
                }
                b'v'
            }
            Self::RowDescription { fields } => {
                body.extend_from_slice(&u16::try_from(fields.len()).unwrap().to_be_bytes());
                for field in fields {
                    put_cstr(&mut body, &field.name);
                    body.extend_from_slice(&field.table_oid.to_be_bytes());
                    body.extend_from_slice(&field.column_id.to_be_bytes());
                    body.extend_from_slice(&field.type_oid.to_be_bytes());
                    body.extend_from_slice(&field.type_size.to_be_bytes());
                    body.extend_from_slice(&field.type_modifier.to_be_bytes());
                    body.extend_from_slice(&field.format.to_be_bytes());
                }
                b'T'
            }
            Self::DataRow { columns } => {
                put_values(&mut body, columns);
                b'D'
            }
            Self::CommandComplete { tag } => {
                put_cstr(&mut body, tag);
                b'C'
            }
            Self::ReadyForQuery { status } => {
                body.push(*status);
                b'Z'
            }
            Self::ErrorResponse { fields } | Self::NoticeResponse { fields } => {
                for (code, value) in fields {
                    body.push(*code);
                    put_cstr(&mut body, value);
                }
                body.push(0);
                if matches!(self, Self::ErrorResponse { .. }) {
                    b'E'
                } else {
                    b'N'
                }
            }
            Self::NotificationResponse {
                process_id,
                channel,
                payload,
            } => {
                body.extend_from_slice(&process_id.to_be_bytes());
                put_cstr(&mut body, channel);
                put_cstr(&mut body, payload);
                b'A'
            }
            Self::CopyResponse {
                tag,
                overall_format,
                column_formats,
            } => {
                body.push(*overall_format);
                put_formats(&mut body, column_formats);
                *tag
            }
            Self::CopyData { data } => {
                body.extend_from_slice(data);
                b'd'
            }
        };
        wire(tag, &body)
    }

    /// The model of what a view read. `None` for a message without a view.
    fn read(message: &backend::Message<'_>) -> Option<Self> {
        use backend::Message;
        Some(match message {
            Message::Authentication(authentication) => match authentication {
                Authentication::Ok
                | Authentication::KerberosV5
                | Authentication::CleartextPassword
                | Authentication::Gss
                | Authentication::Sspi => Self::AuthenticationFixed {
                    code: authentication.code(),
                },
                Authentication::Md5Password { salt } => Self::AuthenticationMd5 { salt: *salt },
                Authentication::Sasl(mechanisms) => Self::AuthenticationSasl {
                    mechanisms: mechanisms.iter().map(<[u8]>::to_vec).collect(),
                },
                Authentication::GssContinue { data }
                | Authentication::SaslContinue { data }
                | Authentication::SaslFinal { data }
                | Authentication::Other { data, .. } => Self::AuthenticationData {
                    code: authentication.code(),
                    data: data.to_vec(),
                },
            },
            Message::BackendKeyData(key_data) => Self::BackendKeyData {
                process_id: key_data.process_id(),
                key: key_data.secret_key().to_vec(),
            },
            Message::ParameterStatus(status) => Self::ParameterStatus {
                name: status.name().to_vec(),
                value: status.value().to_vec(),
            },
            Message::NegotiateProtocolVersion(negotiate) => Self::NegotiateProtocolVersion {
                version: negotiate.version().to_u32(),
                options: negotiate.options().map(<[u8]>::to_vec).collect(),
            },
            Message::RowDescription(description) => Self::RowDescription {
                fields: description
                    .iter()
                    .map(|field| Field {
                        name: field.name().to_vec(),
                        table_oid: field.table_oid(),
                        column_id: field.column_id(),
                        type_oid: field.type_oid(),
                        type_size: field.type_size(),
                        type_modifier: field.type_modifier(),
                        format: field.format().0,
                    })
                    .collect(),
            },
            Message::DataRow(row) => Self::DataRow {
                columns: row
                    .iter()
                    .map(|column| column.map(<[u8]>::to_vec))
                    .collect(),
            },
            Message::CommandComplete(complete) => Self::CommandComplete {
                tag: complete.tag().to_vec(),
            },
            Message::ReadyForQuery(ready) => Self::ReadyForQuery {
                status: ready.status().to_byte(),
            },
            Message::ErrorResponse(error) => Self::ErrorResponse {
                fields: read_error_fields(error.fields()),
            },
            Message::NoticeResponse(notice) => Self::NoticeResponse {
                fields: read_error_fields(notice.fields()),
            },
            Message::NotificationResponse(notification) => Self::NotificationResponse {
                process_id: notification.process_id(),
                channel: notification.channel().to_vec(),
                payload: notification.payload().to_vec(),
            },
            Message::CopyResponse(copy) => Self::CopyResponse {
                tag: match copy.kind() {
                    CopyKind::In => b'G',
                    CopyKind::Out => b'H',
                    CopyKind::Both => b'W',
                },
                overall_format: u8::try_from(copy.overall_format().0).unwrap(),
                column_formats: copy.column_formats().iter().map(|code| code.0).collect(),
            },
            Message::CopyData(copy) => Self::CopyData {
                data: copy.data().to_vec(),
            },
            Message::Other(_) => return None,
        })
    }
}

fn read_error_fields(fields: backend::ErrorFields<'_>) -> Vec<(u8, Vec<u8>)> {
    fields
        .iter()
        .map(|field| (field.code(), field.value().to_vec()))
        .collect()
}

/// Any bytes.
fn bytes(max_len: usize) -> impl Strategy<Value = Vec<u8>> {
    prop::collection::vec(any::<u8>(), 0..=max_len)
}

/// Bytes without a zero byte: the content of a string.
fn text(max_len: usize) -> impl Strategy<Value = Vec<u8>> {
    prop::collection::vec(1u8..=255, 0..=max_len)
}

/// A string with at least one byte.
fn name(max_len: usize) -> impl Strategy<Value = Vec<u8>> {
    prop::collection::vec(1u8..=255, 1..=max_len)
}

fn values() -> impl Strategy<Value = Vec<Option<Vec<u8>>>> {
    prop::collection::vec(prop::option::of(bytes(12)), 0..6)
}

fn formats() -> impl Strategy<Value = Vec<i16>> {
    prop::collection::vec(prop_oneof![Just(0i16), Just(1), any::<i16>()], 0..5)
}

fn error_fields() -> impl Strategy<Value = Vec<(u8, Vec<u8>)>> {
    prop::collection::vec((1u8..=255, text(12)), 0..6)
}

fn field() -> impl Strategy<Value = Field> {
    (
        text(10),
        any::<u32>(),
        any::<i16>(),
        any::<u32>(),
        any::<i16>(),
        any::<i32>(),
        any::<i16>(),
    )
        .prop_map(
            |(name, table_oid, column_id, type_oid, type_size, type_modifier, format)| Field {
                name,
                table_oid,
                column_id,
                type_oid,
                type_size,
                type_modifier,
                format,
            },
        )
}

fn backend_model() -> impl Strategy<Value = ServerModel> {
    prop_oneof![
        prop::sample::select(vec![0u32, 2, 3, 7, 9])
            .prop_map(|code| ServerModel::AuthenticationFixed { code }),
        any::<[u8; 4]>().prop_map(|salt| ServerModel::AuthenticationMd5 { salt }),
        prop::collection::vec(name(12), 0..4)
            .prop_map(|mechanisms| ServerModel::AuthenticationSasl { mechanisms }),
        (
            prop_oneof![
                Just(8u32),
                Just(11),
                Just(12),
                Just(1),
                Just(4),
                Just(6),
                13u32..
            ],
            bytes(16)
        )
            .prop_map(|(code, data)| ServerModel::AuthenticationData { code, data }),
        (
            any::<i32>(),
            prop_oneof![4usize..=40, Just(255usize), Just(256usize)]
        )
            .prop_flat_map(|(process_id, key_len)| {
                prop::collection::vec(any::<u8>(), key_len)
                    .prop_map(move |key| ServerModel::BackendKeyData { process_id, key })
            }),
        (text(12), text(12)).prop_map(|(name, value)| ServerModel::ParameterStatus { name, value }),
        (any::<u32>(), prop::collection::vec(text(10), 0..4)).prop_map(|(version, options)| {
            ServerModel::NegotiateProtocolVersion { version, options }
        }),
        prop::collection::vec(field(), 0..4)
            .prop_map(|fields| ServerModel::RowDescription { fields }),
        values().prop_map(|columns| ServerModel::DataRow { columns }),
        text(16).prop_map(|tag| ServerModel::CommandComplete { tag }),
        prop::sample::select(b"ITE".to_vec())
            .prop_map(|status| ServerModel::ReadyForQuery { status }),
        error_fields().prop_map(|fields| ServerModel::ErrorResponse { fields }),
        error_fields().prop_map(|fields| ServerModel::NoticeResponse { fields }),
        (any::<i32>(), text(10), text(16)).prop_map(|(process_id, channel, payload)| {
            ServerModel::NotificationResponse {
                process_id,
                channel,
                payload,
            }
        }),
        (
            prop::sample::select(b"GHW".to_vec()),
            any::<u8>(),
            formats()
        )
            .prop_map(
                |(tag, overall_format, column_formats)| ServerModel::CopyResponse {
                    tag,
                    overall_format,
                    column_formats,
                }
            ),
        bytes(24).prop_map(|data| ServerModel::CopyData { data }),
    ]
}

// ---------------------------------------------------------------------------
// Models of the messages a client sends
// ---------------------------------------------------------------------------

#[derive(Clone, Debug, PartialEq, Eq)]
enum ClientModel {
    Query {
        sql: Vec<u8>,
    },
    Parse {
        statement: Vec<u8>,
        sql: Vec<u8>,
        parameter_types: Vec<u32>,
    },
    Bind {
        portal: Vec<u8>,
        statement: Vec<u8>,
        parameter_formats: Vec<i16>,
        parameters: Vec<Option<Vec<u8>>>,
        result_formats: Vec<i16>,
    },
    Describe {
        target: u8,
        name: Vec<u8>,
    },
    Execute {
        portal: Vec<u8>,
        max_rows: i32,
    },
    Close {
        target: u8,
        name: Vec<u8>,
    },
    CopyData {
        data: Vec<u8>,
    },
}

impl ClientModel {
    /// The reference encoding of the message.
    fn encode(&self) -> Vec<u8> {
        let mut body = Vec::new();
        let tag = match self {
            Self::Query { sql } => {
                put_cstr(&mut body, sql);
                b'Q'
            }
            Self::Parse {
                statement,
                sql,
                parameter_types,
            } => {
                put_cstr(&mut body, statement);
                put_cstr(&mut body, sql);
                body.extend_from_slice(
                    &u16::try_from(parameter_types.len()).unwrap().to_be_bytes(),
                );
                for oid in parameter_types {
                    body.extend_from_slice(&oid.to_be_bytes());
                }
                b'P'
            }
            Self::Bind {
                portal,
                statement,
                parameter_formats,
                parameters,
                result_formats,
            } => {
                put_cstr(&mut body, portal);
                put_cstr(&mut body, statement);
                put_formats(&mut body, parameter_formats);
                put_values(&mut body, parameters);
                put_formats(&mut body, result_formats);
                b'B'
            }
            Self::Describe { target, name } | Self::Close { target, name } => {
                body.push(*target);
                put_cstr(&mut body, name);
                if matches!(self, Self::Describe { .. }) {
                    b'D'
                } else {
                    b'C'
                }
            }
            Self::Execute { portal, max_rows } => {
                put_cstr(&mut body, portal);
                body.extend_from_slice(&max_rows.to_be_bytes());
                b'E'
            }
            Self::CopyData { data } => {
                body.extend_from_slice(data);
                b'd'
            }
        };
        wire(tag, &body)
    }

    /// The model of what a view read. `None` for a message without a view.
    fn read(message: &frontend::Message<'_>) -> Option<Self> {
        use frontend::Message;
        Some(match message {
            Message::Query(query) => Self::Query {
                sql: query.sql().to_vec(),
            },
            Message::Parse(parse) => Self::Parse {
                statement: parse.statement().to_vec(),
                sql: parse.sql().to_vec(),
                parameter_types: parse.parameter_types().iter().collect(),
            },
            Message::Bind(bind) => Self::Bind {
                portal: bind.portal().to_vec(),
                statement: bind.statement().to_vec(),
                parameter_formats: bind.parameter_formats().iter().map(|code| code.0).collect(),
                parameters: bind
                    .parameters()
                    .iter()
                    .map(|value| value.map(<[u8]>::to_vec))
                    .collect(),
                result_formats: bind.result_formats().iter().map(|code| code.0).collect(),
            },
            Message::Describe(describe) => Self::Describe {
                target: describe.target().to_byte(),
                name: describe.name().to_vec(),
            },
            Message::Execute(execute) => Self::Execute {
                portal: execute.portal().to_vec(),
                max_rows: execute.max_rows(),
            },
            Message::Close(close) => Self::Close {
                target: close.target().to_byte(),
                name: close.name().to_vec(),
            },
            Message::CopyData(copy) => Self::CopyData {
                data: copy.data().to_vec(),
            },
            Message::Other(_) => return None,
        })
    }
}

fn target() -> impl Strategy<Value = u8> {
    prop::sample::select(vec![Target::Statement.to_byte(), Target::Portal.to_byte()])
}

fn frontend_model() -> impl Strategy<Value = ClientModel> {
    prop_oneof![
        text(24).prop_map(|sql| ClientModel::Query { sql }),
        (text(8), text(16), prop::collection::vec(any::<u32>(), 0..5)).prop_map(
            |(statement, sql, parameter_types)| ClientModel::Parse {
                statement,
                sql,
                parameter_types,
            }
        ),
        (text(8), text(8), formats(), values(), formats()).prop_map(
            |(portal, statement, parameter_formats, parameters, result_formats)| {
                ClientModel::Bind {
                    portal,
                    statement,
                    parameter_formats,
                    parameters,
                    result_formats,
                }
            }
        ),
        (target(), text(8)).prop_map(|(target, name)| ClientModel::Describe { target, name }),
        (text(8), any::<i32>())
            .prop_map(|(portal, max_rows)| ClientModel::Execute { portal, max_rows }),
        (target(), text(8)).prop_map(|(target, name)| ClientModel::Close { target, name }),
        bytes(24).prop_map(|data| ClientModel::CopyData { data }),
    ]
}

// ---------------------------------------------------------------------------
// Damage
// ---------------------------------------------------------------------------

/// One change to the body or the type byte of a frame.
#[derive(Clone, Debug)]
enum Damage {
    Replace { at: Index, value: u8 },
    Insert { at: Index, value: u8 },
    Remove { at: Index },
    Append { extra: Vec<u8> },
    Truncate { at: Index },
    Retag { tag: u8 },
}

fn damage() -> impl Strategy<Value = Damage> {
    let small = prop_oneof![Just(0u8), Just(1), Just(0xff), any::<u8>()];
    prop_oneof![
        (any::<Index>(), small.clone()).prop_map(|(at, value)| Damage::Replace { at, value }),
        (any::<Index>(), small).prop_map(|(at, value)| Damage::Insert { at, value }),
        any::<Index>().prop_map(|at| Damage::Remove { at }),
        prop::collection::vec(prop_oneof![Just(0u8), any::<u8>()], 1..6)
            .prop_map(|extra| Damage::Append { extra }),
        any::<Index>().prop_map(|at| Damage::Truncate { at }),
        prop::sample::select(b"RKSvTDCZENAGHWdQPBcfX".to_vec())
            .prop_map(|tag| Damage::Retag { tag }),
    ]
}

/// Applies `damage` to a well-formed frame and returns a frame that is
/// well-formed again as far as framing goes: its length field matches its
/// new body.
fn damaged(frame: &[u8], damage: &Damage) -> Vec<u8> {
    let mut tag = frame[0];
    let mut body = frame[5..].to_vec();
    match damage {
        Damage::Replace { at, value } => {
            if !body.is_empty() {
                let at = at.index(body.len());
                body[at] = *value;
            }
        }
        Damage::Insert { at, value } => body.insert(at.index(body.len() + 1), *value),
        Damage::Remove { at } => {
            if !body.is_empty() {
                body.remove(at.index(body.len()));
            }
        }
        Damage::Append { extra } => body.extend_from_slice(extra),
        Damage::Truncate { at } => body.truncate(at.index(body.len() + 1)),
        Damage::Retag { tag: new } => tag = *new,
    }
    wire(tag, &body)
}

proptest! {
    #![proptest_config(ProptestConfig::with_cases(1024))]

    /// A view reads an encoded message back as the values it was made of.
    #[test]
    fn backend_views_read_what_was_encoded(model in backend_model()) {
        let bytes = model.encode();
        let message = backend::Message::from_frame(only_frame(Direction::FromServer, &bytes));
        prop_assert!(message.is_ok(), "{:?} for {:?}", message, model);
        prop_assert_eq!(ServerModel::read(&message.unwrap()), Some(model));
    }

    /// Whatever a view accepts has exactly one encoding: the bytes it was
    /// read from.
    #[test]
    fn backend_views_accept_only_the_canonical_form(
        model in backend_model(),
        damage in damage(),
    ) {
        let bytes = damaged(&model.encode(), &damage);
        let frame = only_frame(Direction::FromServer, &bytes);
        if let Ok(message) = backend::Message::from_frame(frame)
            && let Some(read) = ServerModel::read(&message)
        {
            prop_assert_eq!(read.encode(), bytes);
        }
    }

    /// The same two properties for the messages a client sends.
    #[test]
    fn frontend_views_read_what_was_encoded(model in frontend_model()) {
        let bytes = model.encode();
        let message = frontend::Message::from_frame(only_frame(Direction::FromClient, &bytes));
        prop_assert!(message.is_ok(), "{:?} for {:?}", message, model);
        prop_assert_eq!(ClientModel::read(&message.unwrap()), Some(model));
    }

    #[test]
    fn frontend_views_accept_only_the_canonical_form(
        model in frontend_model(),
        damage in damage(),
    ) {
        let bytes = damaged(&model.encode(), &damage);
        let frame = only_frame(Direction::FromClient, &bytes);
        if let Ok(message) = frontend::Message::from_frame(frame)
            && let Some(read) = ClientModel::read(&message)
        {
            prop_assert_eq!(read.encode(), bytes);
        }
    }

    /// The crate's own encoders write the reference encoding.
    #[test]
    fn encoders_agree_with_the_reference_encoding(model in backend_model()) {
        let mut encoded = Vec::new();
        match &model {
            ServerModel::AuthenticationSasl { mechanisms } => {
                let names: Vec<&[u8]> = mechanisms.iter().map(Vec::as_slice).collect();
                encode::authentication_sasl(&names, &mut encoded).unwrap();
            }
            ServerModel::NegotiateProtocolVersion { version, options } => {
                let names: Vec<&[u8]> = options.iter().map(Vec::as_slice).collect();
                encode::negotiate_protocol_version(
                    ProtocolVersion::from_u32(*version),
                    &names,
                    &mut encoded,
                )
                .unwrap();
            }
            ServerModel::DataRow { columns } => {
                let columns: Vec<Option<&[u8]>> = columns.iter().map(Option::as_deref).collect();
                encode::data_row(&columns, &mut encoded).unwrap();
            }
            ServerModel::CommandComplete { tag } => {
                encode::command_complete(tag, &mut encoded).unwrap();
            }
            ServerModel::ErrorResponse { fields } => {
                let fields: Vec<(u8, &[u8])> =
                    fields.iter().map(|(code, value)| (*code, value.as_slice())).collect();
                encode::error_response(&fields, &mut encoded).unwrap();
            }
            _ => return Ok(()),
        }
        prop_assert_eq!(encoded, model.encode());
    }

    /// A startup-phase packet that is accepted has exactly one encoding too.
    #[test]
    fn startup_packets_accept_only_the_canonical_form(
        packet in prop_oneof![
            (0u16..4, prop::collection::vec((name(6), text(6)), 0..4)).prop_map(
                |(minor, parameters)| {
                    let parameters: Vec<(&[u8], &[u8])> = parameters
                        .iter()
                        .map(|(name, value)| (name.as_slice(), value.as_slice()))
                        .collect();
                    let mut bytes = Vec::new();
                    encode::startup_message(ProtocolVersion::new(3, minor), &parameters, &mut bytes)
                        .unwrap();
                    bytes
                }
            ),
            (any::<i32>(), prop::collection::vec(any::<u8>(), 1..=40)).prop_map(|(process_id, key)| {
                let mut bytes = Vec::new();
                encode::cancel_request(process_id, &key, &mut bytes).unwrap();
                bytes
            }),
            Just(vec![0, 0, 0, 8, 0x04, 0xd2, 0x16, 0x2f]),
            Just(vec![0, 0, 0, 8, 0x04, 0xd2, 0x16, 0x30]),
        ],
        damage in damage(),
    ) {
        // Damage everything after the length field, then write a length
        // that matches again.
        let mut body = packet[4..].to_vec();
        match &damage {
            Damage::Replace { at, value } => {
                let at = at.index(body.len());
                body[at] = *value;
            }
            Damage::Insert { at, value } => body.insert(at.index(body.len() + 1), *value),
            Damage::Remove { at } => {
                body.remove(at.index(body.len()));
            }
            Damage::Append { extra } => body.extend_from_slice(extra),
            Damage::Truncate { at } => body.truncate(at.index(body.len() + 1)),
            Damage::Retag { .. } => {}
        }
        let mut bytes = u32::try_from(body.len() + 4).unwrap().to_be_bytes().to_vec();
        bytes.extend_from_slice(&body);

        let mut encoded = Vec::new();
        match StartupPacket::parse(&bytes) {
            Ok(Some(StartupPacket::StartupMessage(message))) => {
                let parameters: Vec<(&[u8], &[u8])> = message
                    .parameters()
                    .map(|parameter| (parameter.name(), parameter.value()))
                    .collect();
                encode::startup_message(message.version(), &parameters, &mut encoded).unwrap();
            }
            Ok(Some(StartupPacket::CancelRequest(request))) => {
                encode::cancel_request(request.process_id(), request.secret_key(), &mut encoded)
                    .unwrap();
            }
            Ok(Some(StartupPacket::SslRequest)) => encode::ssl_request(&mut encoded).unwrap(),
            Ok(Some(StartupPacket::GssEncRequest)) => {
                encoded.extend_from_slice(&[0, 0, 0, 8, 0x04, 0xd2, 0x16, 0x30]);
            }
            // The length is consistent, so the packet is complete.
            Ok(None) => prop_assert!(bytes.len() < 8, "a complete packet reported incomplete"),
            Err(_) => return Ok(()),
        }
        if !encoded.is_empty() {
            prop_assert_eq!(encoded, bytes);
        }
    }
}
