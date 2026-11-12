// SPDX-License-Identifier: Apache-2.0

//! Encoders for the messages pgsnare writes itself.
//!
//! pgsnare forwards the bytes it received. It builds a message of its own
//! only in a few cases: the error that ends a killed session, fake rows and
//! the corrected row count that follows them, a rewritten SASL mechanism
//! list, a capped startup message with the `NegotiateProtocolVersion` that
//! tells the client about it, and the requests it sends on the backend leg.
//!
//! Every encoder checks its whole input first and writes nothing unless the
//! complete message can be written. What an encoder writes, the matching
//! view of this crate reads back unchanged, so pgsnare cannot emit a
//! message it would itself reject.

use bytes::BufMut;

use crate::backend;
use crate::error::EncodeError;
use crate::frame::{HEADER_LEN, MAX_LENGTH};
use crate::startup::{
    CANCEL_REQUEST_CODE, MAX_CANCEL_KEY_LEN, MAX_STARTUP_PACKET_LEN, MIN_CANCEL_KEY_LEN,
    SSL_REQUEST_CODE,
};
use crate::version::ProtocolVersion;

/// Receives the parts of a message body.
///
/// Each encoder describes the layout of its message once, as a function
/// that sends the parts to a sink. The function runs twice: first into a
/// [`Counter`], which validates the input and measures the body, then into
/// a [`Writer`]. The size announced in the header and the bytes written
/// therefore come from the same code and cannot disagree.
trait Sink {
    fn put(&mut self, bytes: &[u8]) -> Result<(), EncodeError>;
}

/// Measures a body without writing it.
struct Counter(usize);

impl Sink for Counter {
    fn put(&mut self, bytes: &[u8]) -> Result<(), EncodeError> {
        self.0 = self
            .0
            .checked_add(bytes.len())
            .ok_or(EncodeError::TooLong)?;
        Ok(())
    }
}

/// Writes a body to the output buffer.
struct Writer<'o, B>(&'o mut B);

impl<B: BufMut> Sink for Writer<'_, B> {
    fn put(&mut self, bytes: &[u8]) -> Result<(), EncodeError> {
        self.0.put_slice(bytes);
        Ok(())
    }
}

/// Sends a string and its terminator.
fn put_cstr(sink: &mut dyn Sink, string: &[u8]) -> Result<(), EncodeError> {
    if string.contains(&0) {
        return Err(EncodeError::NulInString);
    }
    sink.put(string)?;
    sink.put(&[0])
}

/// Sends a string that must not be empty, and its terminator.
fn put_name(sink: &mut dyn Sink, name: &[u8]) -> Result<(), EncodeError> {
    if name.is_empty() {
        return Err(EncodeError::EmptyName);
    }
    put_cstr(sink, name)
}

/// Measures the body that `layout` describes. Fails when the input is not
/// valid for the message.
fn measure(
    layout: &dyn Fn(&mut dyn Sink) -> Result<(), EncodeError>,
) -> Result<usize, EncodeError> {
    let mut counter = Counter(0);
    layout(&mut counter)?;
    Ok(counter.0)
}

/// Writes a frame: the type byte, the length and the body that `layout`
/// describes.
fn write_frame<B: BufMut>(
    out: &mut B,
    tag: u8,
    layout: &dyn Fn(&mut dyn Sink) -> Result<(), EncodeError>,
) -> Result<(), EncodeError> {
    let body_len = measure(layout)?;
    let length = body_len
        .checked_add(4)
        .and_then(|length| u32::try_from(length).ok())
        .filter(|length| *length <= MAX_LENGTH)
        .ok_or(EncodeError::TooLong)?;
    let frame_len = body_len
        .checked_add(HEADER_LEN)
        .ok_or(EncodeError::TooLong)?;
    if out.remaining_mut() < frame_len {
        return Err(EncodeError::BufferFull);
    }
    out.put_u8(tag);
    out.put_u32(length);
    layout(&mut Writer(out))
}

/// Writes a startup-phase packet: the length and the body that `layout`
/// describes. There is no type byte.
fn write_packet<B: BufMut>(
    out: &mut B,
    layout: &dyn Fn(&mut dyn Sink) -> Result<(), EncodeError>,
) -> Result<(), EncodeError> {
    let packet_len = measure(layout)?
        .checked_add(4)
        .filter(|len| *len <= MAX_STARTUP_PACKET_LEN)
        .ok_or(EncodeError::TooLong)?;
    let length = u32::try_from(packet_len).map_err(|_| EncodeError::TooLong)?;
    if out.remaining_mut() < packet_len {
        return Err(EncodeError::BufferFull);
    }
    out.put_u32(length);
    layout(&mut Writer(out))
}

/// Writes an `ErrorResponse` with the given fields, in the given order.
///
/// Each field is a code from [`backend::error_field`] and a value. A client
/// expects at least the severity, the SQLSTATE code and the message.
///
/// # Errors
///
/// Fails when a code is zero, when a value contains a zero byte, when the
/// message would exceed the protocol's size limit, or when `out` cannot
/// take it. Nothing is written on failure.
pub fn error_response(fields: &[(u8, &[u8])], out: &mut impl BufMut) -> Result<(), EncodeError> {
    write_frame(out, backend::tag::ERROR_RESPONSE, &|sink| {
        for &(code, value) in fields {
            if code == 0 {
                return Err(EncodeError::InvalidFieldCode);
            }
            sink.put(&[code])?;
            put_cstr(sink, value)?;
        }
        sink.put(&[0])
    })
}

/// Writes a `DataRow` with the given column values. `None` is the SQL NULL.
///
/// # Errors
///
/// Fails when there are more than 65535 columns, when the message would
/// exceed the protocol's size limit, or when `out` cannot take it. Nothing
/// is written on failure.
pub fn data_row(columns: &[Option<&[u8]>], out: &mut impl BufMut) -> Result<(), EncodeError> {
    let count = u16::try_from(columns.len()).map_err(|_| EncodeError::TooManyItems)?;
    write_frame(out, backend::tag::DATA_ROW, &|sink| {
        sink.put(&count.to_be_bytes())?;
        for column in columns {
            match column {
                None => sink.put(&(-1i32).to_be_bytes())?,
                Some(value) => {
                    let len = i32::try_from(value.len()).map_err(|_| EncodeError::TooLong)?;
                    sink.put(&len.to_be_bytes())?;
                    sink.put(value)?;
                }
            }
        }
        Ok(())
    })
}

/// Writes a `CommandComplete` with the given command tag.
///
/// # Errors
///
/// Fails when the tag contains a zero byte, when the message would exceed
/// the protocol's size limit, or when `out` cannot take it. Nothing is
/// written on failure.
pub fn command_complete(tag: &[u8], out: &mut impl BufMut) -> Result<(), EncodeError> {
    write_frame(out, backend::tag::COMMAND_COMPLETE, &|sink| {
        put_cstr(sink, tag)
    })
}

/// Writes a `CommandComplete` whose tag is `command`, a space and `rows`:
/// the command `SELECT` and 5 rows give `SELECT 5`.
///
/// This is the counterpart of
/// [`CommandComplete::split_rows`](backend::CommandComplete::split_rows) and
/// serves to correct the row count of a result that rows were added to.
///
/// # Errors
///
/// Fails when the command is empty or contains a zero byte, when the
/// message would exceed the protocol's size limit, or when `out` cannot
/// take it. Nothing is written on failure.
pub fn command_complete_with_rows(
    command: &[u8],
    rows: u64,
    out: &mut impl BufMut,
) -> Result<(), EncodeError> {
    let digits = rows.to_string();
    write_frame(out, backend::tag::COMMAND_COMPLETE, &|sink| {
        if command.is_empty() {
            return Err(EncodeError::EmptyName);
        }
        if command.contains(&0) {
            return Err(EncodeError::NulInString);
        }
        sink.put(command)?;
        sink.put(b" ")?;
        sink.put(digits.as_bytes())?;
        sink.put(&[0])
    })
}

/// Writes a `NegotiateProtocolVersion`: the newest protocol version on
/// offer and the names of the protocol options that were not accepted.
///
/// The version is written as a complete version number, the way servers
/// send it. See
/// [`NegotiateProtocolVersion::version`](backend::NegotiateProtocolVersion::version).
///
/// # Errors
///
/// Fails when a name contains a zero byte, when there are more names than
/// the count field can express, when the message would exceed the
/// protocol's size limit, or when `out` cannot take it. Nothing is written
/// on failure.
pub fn negotiate_protocol_version(
    version: ProtocolVersion,
    options: &[&[u8]],
    out: &mut impl BufMut,
) -> Result<(), EncodeError> {
    let count = i32::try_from(options.len()).map_err(|_| EncodeError::TooManyItems)?;
    write_frame(out, backend::tag::NEGOTIATE_PROTOCOL_VERSION, &|sink| {
        sink.put(&version.to_u32().to_be_bytes())?;
        sink.put(&count.to_be_bytes())?;
        for option in options {
            put_cstr(sink, option)?;
        }
        Ok(())
    })
}

/// Writes an `AuthenticationSASL` that offers the given mechanisms, in the
/// given order.
///
/// # Errors
///
/// Fails when a mechanism name is empty or contains a zero byte, when the
/// message would exceed the protocol's size limit, or when `out` cannot
/// take it. Nothing is written on failure.
pub fn authentication_sasl(mechanisms: &[&[u8]], out: &mut impl BufMut) -> Result<(), EncodeError> {
    write_frame(out, backend::tag::AUTHENTICATION, &|sink| {
        sink.put(&backend::Authentication::CODE_SASL.to_be_bytes())?;
        for mechanism in mechanisms {
            // An empty name would end the list early.
            put_name(sink, mechanism)?;
        }
        sink.put(&[0])
    })
}

/// Writes a `StartupMessage` with the given protocol version and
/// parameters, in the given order.
///
/// # Errors
///
/// Fails when the major version is not 3, when a parameter name is empty,
/// when a name or a value contains a zero byte, when the packet would
/// exceed PostgreSQL's limit for startup packets, or when `out` cannot take
/// it. Nothing is written on failure.
pub fn startup_message(
    version: ProtocolVersion,
    parameters: &[(&[u8], &[u8])],
    out: &mut impl BufMut,
) -> Result<(), EncodeError> {
    if version.major() != 3 {
        return Err(EncodeError::UnsupportedVersion(version));
    }
    write_packet(out, &|sink| {
        sink.put(&version.to_u32().to_be_bytes())?;
        for &(name, value) in parameters {
            // An empty name would end the list early.
            put_name(sink, name)?;
            put_cstr(sink, value)?;
        }
        sink.put(&[0])
    })
}

/// Writes a `CancelRequest` for the backend with the given process id and
/// secret key.
///
/// # Errors
///
/// Fails when the key is not 1 to 256 bytes long, or when `out` cannot
/// take the packet. Nothing is written on failure.
pub fn cancel_request(
    process_id: i32,
    secret_key: &[u8],
    out: &mut impl BufMut,
) -> Result<(), EncodeError> {
    if secret_key.len() < MIN_CANCEL_KEY_LEN || secret_key.len() > MAX_CANCEL_KEY_LEN {
        return Err(EncodeError::InvalidKeyLength);
    }
    write_packet(out, &|sink| {
        sink.put(&CANCEL_REQUEST_CODE.to_be_bytes())?;
        sink.put(&process_id.to_be_bytes())?;
        sink.put(secret_key)
    })
}

/// Writes an `SSLRequest`.
///
/// # Errors
///
/// Fails when `out` cannot take the packet. Nothing is written on failure.
pub fn ssl_request(out: &mut impl BufMut) -> Result<(), EncodeError> {
    write_packet(out, &|sink| sink.put(&SSL_REQUEST_CODE.to_be_bytes()))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::backend::{
        Authentication, CommandComplete, DataRow, ErrorResponse, NegotiateProtocolVersion,
        error_field,
    };
    use crate::frame::Direction;
    use crate::startup::{MAX_STARTUP_PACKET_BODY, StartupPacket};
    use crate::testutil::frame;

    /// Runs an encoder into a growable buffer.
    fn encoded(
        encode: impl Fn(&mut Vec<u8>) -> Result<(), EncodeError>,
    ) -> Result<Vec<u8>, EncodeError> {
        let mut out = Vec::new();
        encode(&mut out)?;
        Ok(out)
    }

    /// Checks how an encoder treats the output buffer: it appends, it fits
    /// a buffer of exactly the right size, and it leaves a buffer that is
    /// one byte too small untouched.
    fn check_buffer_handling(
        expected: &[u8],
        encode: impl Fn(&mut dyn BufMut) -> Result<(), EncodeError>,
    ) {
        // Appends after existing content.
        let mut out = b"existing".to_vec();
        encode(&mut out).unwrap();
        assert_eq!(&out[..8], b"existing");
        assert_eq!(&out[8..], expected);

        // Exactly enough room. A fixed slice panics on any byte too many.
        let mut storage = vec![0xeeu8; expected.len()];
        let mut slice = &mut storage[..];
        encode(&mut slice).unwrap();
        assert_eq!(slice.len(), 0, "every byte of the buffer is used");
        assert_eq!(storage, expected);

        // One byte short: an error, and nothing written.
        if !expected.is_empty() {
            let mut storage = vec![0xeeu8; expected.len() - 1];
            let mut slice = &mut storage[..];
            assert_eq!(encode(&mut slice), Err(EncodeError::BufferFull));
            assert_eq!(slice.len(), expected.len() - 1);
            assert!(storage.iter().all(|&byte| byte == 0xee));
        }
    }

    #[test]
    fn error_response_bytes() {
        let fields: [(u8, &[u8]); 4] = [
            (error_field::SEVERITY, b"FATAL"),
            (error_field::SEVERITY_NONLOCALIZED, b"FATAL"),
            (error_field::SQLSTATE, b"57P01"),
            (
                error_field::MESSAGE,
                b"terminating connection due to administrator command",
            ),
        ];
        let bytes = encoded(|out| error_response(&fields, out)).unwrap();
        let expected = b"E\0\0\0\x4fSFATAL\0VFATAL\0C57P01\0\
            Mterminating connection due to administrator command\0\0";
        assert_eq!(bytes, expected);
        check_buffer_handling(expected, |mut out| error_response(&fields, &mut out));

        let parsed = ErrorResponse::from_frame(frame(Direction::FromServer, &bytes)).unwrap();
        let read: Vec<_> = parsed
            .fields()
            .iter()
            .map(|field| (field.code(), field.value()))
            .collect();
        assert_eq!(read, fields);
    }

    #[test]
    fn error_response_rejects_bad_fields() {
        assert_eq!(
            encoded(|out| error_response(&[(0, b"x")], out)),
            Err(EncodeError::InvalidFieldCode)
        );
        assert_eq!(
            encoded(|out| error_response(&[(b'M', b"a\0b")], out)),
            Err(EncodeError::NulInString)
        );
        // No fields at all is a valid, if useless, message.
        assert_eq!(
            encoded(|out| error_response(&[], out)).unwrap(),
            b"E\0\0\0\x05\0"
        );
    }

    #[test]
    fn a_failed_encoder_writes_nothing() {
        // The second field is invalid. The first must not be written.
        let mut out = b"keep".to_vec();
        let fields: [(u8, &[u8]); 2] = [(b'S', b"ERROR"), (b'M', b"bad\0value")];
        assert_eq!(
            error_response(&fields, &mut out),
            Err(EncodeError::NulInString)
        );
        assert_eq!(out, b"keep");

        let columns = [Some(&b"fine"[..]), None];
        let mut storage = [0xeeu8; 4];
        let mut slice = &mut storage[..];
        assert_eq!(data_row(&columns, &mut slice), Err(EncodeError::BufferFull));
        assert_eq!(storage, [0xee; 4]);
    }

    #[test]
    fn data_row_bytes() {
        let columns = [Some(&b"42"[..]), None, Some(&b""[..])];
        let bytes = encoded(|out| data_row(&columns, out)).unwrap();
        let expected = b"D\0\0\0\x14\0\x03\0\0\0\x0242\xff\xff\xff\xff\0\0\0\0";
        assert_eq!(bytes, expected);
        check_buffer_handling(expected, |mut out| data_row(&columns, &mut out));

        let parsed = DataRow::from_frame(frame(Direction::FromServer, &bytes)).unwrap();
        assert_eq!(parsed.iter().collect::<Vec<_>>(), columns);

        assert_eq!(
            encoded(|out| data_row(&[], out)).unwrap(),
            b"D\0\0\0\x06\0\0"
        );
    }

    #[test]
    fn data_row_column_count_limit() {
        let most = vec![None; usize::from(u16::MAX)];
        let bytes = encoded(|out| data_row(&most, out)).unwrap();
        let parsed = DataRow::from_frame(frame(Direction::FromServer, &bytes)).unwrap();
        assert_eq!(parsed.len(), 65_535);

        let too_many = vec![None; usize::from(u16::MAX) + 1];
        assert_eq!(
            encoded(|out| data_row(&too_many, out)),
            Err(EncodeError::TooManyItems)
        );
    }

    #[test]
    fn command_complete_bytes() {
        let bytes = encoded(|out| command_complete(b"SELECT 5", out)).unwrap();
        let expected = b"C\0\0\0\x0dSELECT 5\0";
        assert_eq!(bytes, expected);
        check_buffer_handling(expected, |mut out| command_complete(b"SELECT 5", &mut out));
        assert_eq!(
            encoded(|out| command_complete(b"SEL\0ECT", out)),
            Err(EncodeError::NulInString)
        );
    }

    #[test]
    fn command_complete_with_a_new_row_count() {
        // Rewrite the row count of a tag taken from the server.
        let original = encoded(|out| command_complete(b"INSERT 0 3", out)).unwrap();
        let parsed = CommandComplete::from_frame(frame(Direction::FromServer, &original)).unwrap();
        let (command, rows) = parsed.split_rows().unwrap();
        let bytes = encoded(|out| command_complete_with_rows(command, rows + 500, out)).unwrap();
        assert_eq!(bytes, b"C\0\0\0\x11INSERT 0 503\0");
        check_buffer_handling(&bytes, |mut out| {
            command_complete_with_rows(command, rows + 500, &mut out)
        });

        for rows in [0, 1, 9, 10, u64::MAX] {
            let bytes = encoded(|out| command_complete_with_rows(b"SELECT", rows, out)).unwrap();
            let parsed = CommandComplete::from_frame(frame(Direction::FromServer, &bytes)).unwrap();
            assert_eq!(parsed.split_rows(), Some((&b"SELECT"[..], rows)));
        }

        assert_eq!(
            encoded(|out| command_complete_with_rows(b"", 1, out)),
            Err(EncodeError::EmptyName)
        );
        assert_eq!(
            encoded(|out| command_complete_with_rows(b"SEL\0ECT", 1, out)),
            Err(EncodeError::NulInString)
        );
    }

    #[test]
    fn negotiate_protocol_version_bytes() {
        let options: [&[u8]; 2] = [b"_pq_.first", b"_pq_.second"];
        let bytes = encoded(|out| negotiate_protocol_version(ProtocolVersion::V3_2, &options, out))
            .unwrap();
        let expected = b"v\0\0\0\x23\0\x03\0\x02\0\0\0\x02_pq_.first\0_pq_.second\0";
        assert_eq!(bytes, expected);
        check_buffer_handling(expected, |mut out| {
            negotiate_protocol_version(ProtocolVersion::V3_2, &options, &mut out)
        });

        let parsed =
            NegotiateProtocolVersion::from_frame(frame(Direction::FromServer, &bytes)).unwrap();
        assert_eq!(parsed.version(), ProtocolVersion::V3_2);
        assert_eq!(parsed.options().collect::<Vec<_>>(), options);

        assert_eq!(
            encoded(|out| negotiate_protocol_version(ProtocolVersion::V3_0, &[], out)).unwrap(),
            b"v\0\0\0\x0c\0\x03\0\0\0\0\0\0"
        );
        assert_eq!(
            encoded(|out| negotiate_protocol_version(ProtocolVersion::V3_0, &[b"a\0b"], out)),
            Err(EncodeError::NulInString)
        );
    }

    #[test]
    fn authentication_sasl_bytes() {
        let mechanisms: [&[u8]; 1] = [b"SCRAM-SHA-256"];
        let bytes = encoded(|out| authentication_sasl(&mechanisms, out)).unwrap();
        let expected = b"R\0\0\0\x17\0\0\0\x0aSCRAM-SHA-256\0\0";
        assert_eq!(bytes, expected);
        check_buffer_handling(expected, |mut out| {
            authentication_sasl(&mechanisms, &mut out)
        });

        let Ok(Authentication::Sasl(parsed)) =
            Authentication::from_frame(frame(Direction::FromServer, &bytes))
        else {
            panic!("expected AuthenticationSASL");
        };
        assert_eq!(parsed.iter().collect::<Vec<_>>(), mechanisms);
    }

    #[test]
    fn authentication_sasl_rewrites_a_mechanism_list() {
        // What a server offers over TLS, without the channel-binding
        // variant.
        let offered = b"R\0\0\0\x2a\0\0\0\x0aSCRAM-SHA-256-PLUS\0SCRAM-SHA-256\0\0";
        let Ok(Authentication::Sasl(mechanisms)) =
            Authentication::from_frame(frame(Direction::FromServer, offered))
        else {
            panic!("expected AuthenticationSASL");
        };
        let kept: Vec<&[u8]> = mechanisms
            .iter()
            .filter(|name| *name != b"SCRAM-SHA-256-PLUS")
            .collect();
        let bytes = encoded(|out| authentication_sasl(&kept, out)).unwrap();
        assert_eq!(bytes, b"R\0\0\0\x17\0\0\0\x0aSCRAM-SHA-256\0\0");
    }

    #[test]
    fn authentication_sasl_rejects_bad_names() {
        assert_eq!(
            encoded(|out| authentication_sasl(&[b"SCRAM-SHA-256", b""], out)),
            Err(EncodeError::EmptyName)
        );
        assert_eq!(
            encoded(|out| authentication_sasl(&[b"SCRAM\0SHA"], out)),
            Err(EncodeError::NulInString)
        );
        // An empty list is a valid message.
        assert_eq!(
            encoded(|out| authentication_sasl(&[], out)).unwrap(),
            b"R\0\0\0\x09\0\0\0\x0a\0"
        );
    }

    #[test]
    fn startup_message_bytes() {
        let parameters: [(&[u8], &[u8]); 2] = [(b"user", b"alice"), (b"database", b"appdb")];
        let bytes =
            encoded(|out| startup_message(ProtocolVersion::V3_2, &parameters, out)).unwrap();
        let expected = b"\0\0\0\x23\0\x03\0\x02user\0alice\0database\0appdb\0\0";
        assert_eq!(bytes, expected);
        check_buffer_handling(expected, |mut out| {
            startup_message(ProtocolVersion::V3_2, &parameters, &mut out)
        });

        let Ok(Some(StartupPacket::StartupMessage(parsed))) = StartupPacket::parse(&bytes) else {
            panic!("expected a startup message");
        };
        assert_eq!(parsed.version(), ProtocolVersion::V3_2);
        let read: Vec<_> = parsed
            .parameters()
            .map(|parameter| (parameter.name(), parameter.value()))
            .collect();
        assert_eq!(read, parameters);
    }

    #[test]
    fn startup_message_rewrites_version_and_options() {
        // A client asks for a version and an option pgsnare does not know.
        let received = encoded(|out| {
            startup_message(
                ProtocolVersion::new(3, 7),
                &[(b"user", b"alice"), (b"_pq_.future", b"on")],
                out,
            )
        })
        .unwrap();
        let Ok(Some(StartupPacket::StartupMessage(message))) = StartupPacket::parse(&received)
        else {
            panic!("expected a startup message");
        };
        // Forward it capped at 3.2, without the protocol options.
        let kept: Vec<(&[u8], &[u8])> = message
            .parameters()
            .filter(|parameter| !parameter.is_protocol_option())
            .map(|parameter| (parameter.name(), parameter.value()))
            .collect();
        let version = message.version().min(ProtocolVersion::V3_2);
        let forwarded = encoded(|out| startup_message(version, &kept, out)).unwrap();
        assert_eq!(forwarded, b"\0\0\0\x14\0\x03\0\x02user\0alice\0\0");
    }

    #[test]
    fn startup_message_rejects_bad_input() {
        for version in [
            ProtocolVersion::new(2, 0),
            ProtocolVersion::new(4, 0),
            ProtocolVersion::from_u32(SSL_REQUEST_CODE),
            ProtocolVersion::from_u32(CANCEL_REQUEST_CODE),
        ] {
            assert_eq!(
                encoded(|out| startup_message(version, &[], out)),
                Err(EncodeError::UnsupportedVersion(version))
            );
        }
        let v = ProtocolVersion::V3_0;
        assert_eq!(
            encoded(|out| startup_message(v, &[(b"", b"x")], out)),
            Err(EncodeError::EmptyName)
        );
        assert_eq!(
            encoded(|out| startup_message(v, &[(b"us\0er", b"x")], out)),
            Err(EncodeError::NulInString)
        );
        assert_eq!(
            encoded(|out| startup_message(v, &[(b"user", b"x\0y")], out)),
            Err(EncodeError::NulInString)
        );
        // No parameters: the version and the terminator.
        assert_eq!(
            encoded(|out| startup_message(v, &[], out)).unwrap(),
            b"\0\0\0\x09\0\x03\0\0\0"
        );
    }

    #[test]
    fn startup_message_respects_the_packet_limit() {
        // The body is the version (4), "user\0" (5), the value and its
        // terminator, and the final terminator.
        let fits = vec![b'a'; MAX_STARTUP_PACKET_BODY - 4 - 5 - 2];
        let bytes = encoded(|out| startup_message(ProtocolVersion::V3_0, &[(b"user", &fits)], out))
            .unwrap();
        assert_eq!(bytes.len(), MAX_STARTUP_PACKET_LEN);
        assert!(matches!(
            StartupPacket::parse(&bytes),
            Ok(Some(StartupPacket::StartupMessage(_)))
        ));

        let too_long = vec![b'a'; MAX_STARTUP_PACKET_BODY - 4 - 5 - 1];
        assert_eq!(
            encoded(|out| startup_message(ProtocolVersion::V3_0, &[(b"user", &too_long)], out)),
            Err(EncodeError::TooLong)
        );
    }

    #[test]
    fn cancel_request_bytes() {
        let bytes = encoded(|out| cancel_request(12_345, &[1, 2, 3, 4], out)).unwrap();
        let expected = [
            0, 0, 0, 16, 0x04, 0xd2, 0x16, 0x2e, 0, 0, 0x30, 0x39, 1, 2, 3, 4,
        ];
        assert_eq!(bytes, expected);
        check_buffer_handling(&expected, |mut out| {
            cancel_request(12_345, &[1, 2, 3, 4], &mut out)
        });

        for key_len in [1usize, 4, 32, 256] {
            let key = vec![0x5a; key_len];
            let bytes = encoded(|out| cancel_request(-7, &key, out)).unwrap();
            let Ok(Some(StartupPacket::CancelRequest(parsed))) = StartupPacket::parse(&bytes)
            else {
                panic!("expected a cancel request");
            };
            assert_eq!(parsed.process_id(), -7);
            assert_eq!(parsed.secret_key(), key);
        }
        for key_len in [0usize, 257] {
            let key = vec![0x5a; key_len];
            assert_eq!(
                encoded(|out| cancel_request(1, &key, out)),
                Err(EncodeError::InvalidKeyLength)
            );
        }
    }

    #[test]
    fn ssl_request_bytes() {
        let bytes = encoded(ssl_request).unwrap();
        let expected = [0, 0, 0, 8, 0x04, 0xd2, 0x16, 0x2f];
        assert_eq!(bytes, expected);
        check_buffer_handling(&expected, |mut out| ssl_request(&mut out));
        assert_eq!(
            StartupPacket::parse(&bytes),
            Ok(Some(StartupPacket::SslRequest))
        );
    }

    #[test]
    fn encoders_write_into_bytes_mut() {
        let mut out = bytes::BytesMut::new();
        command_complete(b"SELECT 1", &mut out).unwrap();
        data_row(&[Some(b"x")], &mut out).unwrap();
        assert_eq!(
            &out[..],
            b"C\0\0\0\x0dSELECT 1\0D\0\0\0\x0b\0\x01\0\0\0\x01x"
        );
    }
}
