// SPDX-License-Identifier: Apache-2.0

//! The startup phase: the first packets of a connection.
//!
//! Until a session is established, packets have no type byte. A packet is a
//! four-byte big-endian length that counts itself, a four-byte code, and a
//! body. The code is a protocol version, which makes the packet a
//! `StartupMessage`, or one of three request codes: `SSLRequest`,
//! `GSSENCRequest` and `CancelRequest`.
//!
//! A client may also skip the request and open the connection with a TLS
//! handshake. [`classify`] tells these five cases apart.
//!
//! The parser accepts nothing PostgreSQL would reject, so that what pgsnare
//! forwards is understood by the server exactly as pgsnare understood it.

use core::fmt;

use crate::error::StartupError;
use crate::reader::{Reader, Redacted};
use crate::version::ProtocolVersion;

/// The code of an `SSLRequest`.
pub const SSL_REQUEST_CODE: u32 = 80_877_103;

/// The code of a `GSSENCRequest`.
pub const GSSENC_REQUEST_CODE: u32 = 80_877_104;

/// The code of a `CancelRequest`.
pub const CANCEL_REQUEST_CODE: u32 = 80_877_102;

/// The smallest startup-phase packet: a length and a code.
pub const MIN_STARTUP_PACKET_LEN: usize = 8;

/// PostgreSQL's limit on a startup packet, `MAX_STARTUP_PACKET_LENGTH`. It
/// counts the bytes after the length field.
pub const MAX_STARTUP_PACKET_BODY: usize = 10_000;

/// The largest startup-phase packet on the wire, its length field included.
pub const MAX_STARTUP_PACKET_LEN: usize = MAX_STARTUP_PACKET_BODY + 4;

/// The longest cancel key the protocol allows.
pub const MAX_CANCEL_KEY_LEN: usize = 256;

/// The shortest cancel key a server accepts in a `CancelRequest`.
pub const MIN_CANCEL_KEY_LEN: usize = 1;

/// The size of a `CancelRequest` without its key: length, code and process
/// id.
const CANCEL_REQUEST_FIXED_LEN: usize = 12;

/// The first byte of a TLS record that carries a handshake message. A
/// startup-phase packet cannot begin with it: read as the first byte of a
/// length, it would announce a packet of hundreds of megabytes.
pub const TLS_HANDSHAKE_RECORD: u8 = 0x16;

/// The byte a server answers an `SSLRequest` with when it will use TLS.
pub const SSL_ACCEPTED: u8 = b'S';

/// The byte a server answers a `GSSENCRequest` with when it will use GSSAPI
/// encryption.
pub const GSSENC_ACCEPTED: u8 = b'G';

/// The byte a server answers an `SSLRequest` or a `GSSENCRequest` with when
/// it declines.
pub const ENCRYPTION_REFUSED: u8 = b'N';

/// The prefix of the names of protocol options in a `StartupMessage`.
pub const PROTOCOL_OPTION_PREFIX: &[u8] = b"_pq_.";

/// What the first bytes of a connection are.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Classification<'a> {
    /// A TLS handshake: the client uses direct TLS, without an `SSLRequest`.
    /// None of the bytes belong to a packet. All of them are for the TLS
    /// layer.
    DirectTls,
    /// A complete startup-phase packet at the front of the buffer.
    Packet(StartupPacket<'a>),
    /// Too few bytes to tell. More must arrive.
    Incomplete,
}

/// Classifies the first bytes of a new connection.
///
/// The decision between a TLS handshake and a packet is made on the first
/// byte alone, as PostgreSQL makes it. Use this only for the very first
/// bytes of a connection. A packet that follows an `SSLRequest` or a
/// `GSSENCRequest` cannot be a TLS handshake and is read with
/// [`StartupPacket::parse`].
///
/// # Errors
///
/// Fails as [`StartupPacket::parse`] does.
pub fn classify(buf: &[u8]) -> Result<Classification<'_>, StartupError> {
    match buf.first() {
        None => Ok(Classification::Incomplete),
        Some(&TLS_HANDSHAKE_RECORD) => Ok(Classification::DirectTls),
        Some(_) => Ok(match StartupPacket::parse(buf)? {
            Some(packet) => Classification::Packet(packet),
            None => Classification::Incomplete,
        }),
    }
}

/// A packet of the startup phase.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum StartupPacket<'a> {
    /// `SSLRequest`: the client asks to switch to TLS.
    ///
    /// The server answers with one byte and the TLS handshake follows. Any
    /// byte that arrived after this packet and before the handshake was
    /// sent in the clear and must be refused, because an attacker in the
    /// path may have injected it. Compare the size of the buffer with
    /// [`StartupPacket::wire_len`] to detect that.
    SslRequest,
    /// `GSSENCRequest`: the client asks to switch to GSSAPI encryption. The
    /// same rule about bytes that follow applies.
    GssEncRequest,
    /// `CancelRequest`: the client asks to cancel a query on another
    /// connection.
    CancelRequest(CancelRequest<'a>),
    /// `StartupMessage`: the client starts a session.
    StartupMessage(StartupMessage<'a>),
}

impl<'a> StartupPacket<'a> {
    /// Reads one startup-phase packet from the front of `buf`.
    ///
    /// Returns `Ok(None)` when `buf` does not yet hold the whole packet.
    /// Nothing is consumed: the packet occupies the first
    /// [`StartupPacket::wire_len`] bytes of `buf`.
    ///
    /// A packet is refused as soon as the bytes available show it to be
    /// invalid, without waiting for the rest of it.
    ///
    /// # Errors
    ///
    /// - [`StartupError::InvalidLength`]: the length is below
    ///   [`MIN_STARTUP_PACKET_LEN`] or above [`MAX_STARTUP_PACKET_LEN`].
    /// - [`StartupError::InvalidRequestLength`]: an `SSLRequest` or a
    ///   `GSSENCRequest` is not exactly eight bytes long.
    /// - [`StartupError::InvalidCancelRequestLength`]: a `CancelRequest`
    ///   has no room for a key of [`MIN_CANCEL_KEY_LEN`] to
    ///   [`MAX_CANCEL_KEY_LEN`] bytes.
    /// - [`StartupError::UnsupportedVersion`]: the code is neither a
    ///   request code nor a version of protocol 3.
    /// - [`StartupError::MalformedParameters`]: the parameters of a
    ///   `StartupMessage` are not pairs of terminated strings followed by
    ///   one zero byte that is the last byte of the packet.
    pub fn parse(buf: &'a [u8]) -> Result<Option<Self>, StartupError> {
        let Some((length_bytes, after_length)) = buf.split_first_chunk::<4>() else {
            return Ok(None);
        };
        let length = u32::from_be_bytes(*length_bytes);
        let packet_len = match usize::try_from(length) {
            Ok(len) if (MIN_STARTUP_PACKET_LEN..=MAX_STARTUP_PACKET_LEN).contains(&len) => len,
            _ => return Err(StartupError::InvalidLength { length }),
        };

        let Some((code_bytes, _)) = after_length.split_first_chunk::<4>() else {
            return Ok(None);
        };
        let code = u32::from_be_bytes(*code_bytes);

        // What the first eight bytes can decide is decided before waiting
        // for the rest of the packet.
        match code {
            SSL_REQUEST_CODE | GSSENC_REQUEST_CODE => {
                if packet_len != MIN_STARTUP_PACKET_LEN {
                    return Err(StartupError::InvalidRequestLength { length });
                }
            }
            CANCEL_REQUEST_CODE => {
                let key_len = packet_len.saturating_sub(CANCEL_REQUEST_FIXED_LEN);
                if !(MIN_CANCEL_KEY_LEN..=MAX_CANCEL_KEY_LEN).contains(&key_len) {
                    return Err(StartupError::InvalidCancelRequestLength { length });
                }
            }
            _ => {
                let version = ProtocolVersion::from_u32(code);
                if version.major() != 3 {
                    return Err(StartupError::UnsupportedVersion(version));
                }
            }
        }

        let Some(bytes) = buf.get(..packet_len) else {
            return Ok(None);
        };
        let Some(body) = bytes.get(MIN_STARTUP_PACKET_LEN..) else {
            return Ok(None);
        };

        Ok(Some(match code {
            SSL_REQUEST_CODE => Self::SslRequest,
            GSSENC_REQUEST_CODE => Self::GssEncRequest,
            CANCEL_REQUEST_CODE => {
                let mut reader = Reader::new(body);
                let invalid = StartupError::InvalidCancelRequestLength { length };
                let process_id = reader.i32().map_err(|_| invalid)?;
                Self::CancelRequest(CancelRequest {
                    bytes,
                    process_id,
                    secret_key: reader.take_rest(),
                })
            }
            _ => Self::StartupMessage(StartupMessage {
                bytes,
                version: ProtocolVersion::from_u32(code),
                parameters: check_parameters(body)?,
            }),
        }))
    }

    /// The size of the packet on the wire, its length field included.
    #[must_use]
    pub const fn wire_len(&self) -> usize {
        match self {
            Self::SslRequest | Self::GssEncRequest => MIN_STARTUP_PACKET_LEN,
            Self::CancelRequest(request) => request.bytes.len(),
            Self::StartupMessage(message) => message.bytes.len(),
        }
    }
}

/// Checks the parameter list of a `StartupMessage` and returns the pairs
/// without the zero byte that ends the list.
///
/// The accepted form is exactly: any number of pairs of a non-empty
/// terminated name and a terminated value, then one zero byte, then the end
/// of the packet. PostgreSQL parses the same form into the same pairs. It
/// additionally accepts a packet whose last byte is not zero, which is not
/// accepted here.
fn check_parameters(body: &[u8]) -> Result<&[u8], StartupError> {
    let start = Reader::new(body);
    let mut reader = start;
    loop {
        let before = reader;
        let name = reader
            .cstr()
            .map_err(|_| StartupError::MalformedParameters)?;
        if name.is_empty() {
            // The terminator of the list must be the last byte.
            reader
                .finish()
                .map_err(|_| StartupError::MalformedParameters)?;
            return Ok(before.consumed_since(&start));
        }
        reader
            .cstr()
            .map_err(|_| StartupError::MalformedParameters)?;
    }
}

/// `StartupMessage`: the protocol version a client asks for and the
/// parameters of the session it wants.
#[derive(Clone, Copy, PartialEq, Eq)]
pub struct StartupMessage<'a> {
    bytes: &'a [u8],
    version: ProtocolVersion,
    /// The pairs, each string with its terminator, without the zero byte
    /// that ends the list.
    parameters: &'a [u8],
}

impl<'a> StartupMessage<'a> {
    /// The protocol version the client asks for. Its major version is 3.
    #[must_use]
    pub const fn version(&self) -> ProtocolVersion {
        self.version
    }

    /// Iterates over the parameters in the order sent.
    #[must_use]
    pub const fn parameters(&self) -> Parameters<'a> {
        Parameters {
            reader: Reader::new(self.parameters),
        }
    }

    /// The value of the parameter with exactly this name.
    ///
    /// If the name occurs more than once, the last value is returned, which
    /// is the one the server uses.
    #[must_use]
    pub fn get(&self, name: &[u8]) -> Option<&'a [u8]> {
        self.parameters()
            .filter(|parameter| parameter.name == name)
            .last()
            .map(|parameter| parameter.value)
    }

    /// The whole packet as it appeared on the wire.
    #[must_use]
    pub const fn as_bytes(&self) -> &'a [u8] {
        self.bytes
    }
}

impl fmt::Debug for StartupMessage<'_> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("StartupMessage")
            .field("version", &self.version)
            .field("parameter_count", &self.parameters().count())
            .field("parameters", &Redacted(self.parameters))
            .finish()
    }
}

/// One parameter of a `StartupMessage`.
#[derive(Clone, Copy, PartialEq, Eq)]
pub struct Parameter<'a> {
    name: &'a [u8],
    value: &'a [u8],
}

impl<'a> Parameter<'a> {
    /// The name. Never empty.
    #[must_use]
    pub const fn name(&self) -> &'a [u8] {
        self.name
    }

    /// The value.
    #[must_use]
    pub const fn value(&self) -> &'a [u8] {
        self.value
    }

    /// Whether this is a protocol option: a parameter whose name starts
    /// with `_pq_.`. Such parameters extend the protocol itself, and a
    /// server lists the ones it does not know in `NegotiateProtocolVersion`.
    #[must_use]
    pub fn is_protocol_option(&self) -> bool {
        self.name.starts_with(PROTOCOL_OPTION_PREFIX)
    }
}

impl fmt::Debug for Parameter<'_> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Parameter")
            .field("name", &Redacted(self.name))
            .field("value", &Redacted(self.value))
            .finish()
    }
}

/// An iterator over the parameters of a [`StartupMessage`].
#[derive(Clone)]
pub struct Parameters<'a> {
    reader: Reader<'a>,
}

impl<'a> Iterator for Parameters<'a> {
    type Item = Parameter<'a>;

    fn next(&mut self) -> Option<Self::Item> {
        if self.reader.is_empty() {
            return None;
        }
        let name = self.reader.cstr().ok()?;
        let value = self.reader.cstr().ok()?;
        Some(Parameter { name, value })
    }
}

impl fmt::Debug for Parameters<'_> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Parameters").finish_non_exhaustive()
    }
}

/// `CancelRequest`: a request to cancel the query running on another
/// connection, identified by the process id and secret key that connection
/// received in `BackendKeyData`.
///
/// The key is everything after the process id, so its length is read from
/// the packet: 4 bytes in protocol 3.0 and up to 256 bytes in protocol 3.2.
#[derive(Clone, Copy, PartialEq, Eq)]
pub struct CancelRequest<'a> {
    bytes: &'a [u8],
    process_id: i32,
    secret_key: &'a [u8],
}

impl<'a> CancelRequest<'a> {
    /// The process id of the backend to cancel.
    #[must_use]
    pub const fn process_id(&self) -> i32 {
        self.process_id
    }

    /// The secret key, 1 to 256 bytes long.
    #[must_use]
    pub const fn secret_key(&self) -> &'a [u8] {
        self.secret_key
    }

    /// The whole packet as it appeared on the wire.
    #[must_use]
    pub const fn as_bytes(&self) -> &'a [u8] {
        self.bytes
    }
}

impl fmt::Debug for CancelRequest<'_> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("CancelRequest")
            .field("process_id", &self.process_id)
            .field("secret_key", &Redacted(self.secret_key))
            .finish()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn packet(code: u32, body: &[u8]) -> Vec<u8> {
        let mut bytes = u32::try_from(body.len() + 8)
            .unwrap()
            .to_be_bytes()
            .to_vec();
        bytes.extend_from_slice(&code.to_be_bytes());
        bytes.extend_from_slice(body);
        bytes
    }

    fn startup(version: ProtocolVersion, parameters: &[u8]) -> Vec<u8> {
        packet(version.to_u32(), parameters)
    }

    fn expect_startup(bytes: &[u8]) -> StartupMessage<'_> {
        match StartupPacket::parse(bytes) {
            Ok(Some(StartupPacket::StartupMessage(message))) => message,
            other => panic!("expected a startup message, got {other:?}"),
        }
    }

    fn pairs<'a>(message: &StartupMessage<'a>) -> Vec<(&'a [u8], &'a [u8])> {
        message
            .parameters()
            .map(|parameter| (parameter.name(), parameter.value()))
            .collect()
    }

    #[test]
    fn request_codes_match_postgresql() {
        assert_eq!(SSL_REQUEST_CODE, ProtocolVersion::new(1234, 5679).to_u32());
        assert_eq!(
            GSSENC_REQUEST_CODE,
            ProtocolVersion::new(1234, 5680).to_u32()
        );
        assert_eq!(
            CANCEL_REQUEST_CODE,
            ProtocolVersion::new(1234, 5678).to_u32()
        );
        assert_eq!(MAX_STARTUP_PACKET_LEN, 10_004);
    }

    #[test]
    fn empty_input_is_incomplete() {
        assert_eq!(classify(&[]), Ok(Classification::Incomplete));
        assert_eq!(StartupPacket::parse(&[]), Ok(None));
    }

    #[test]
    fn a_tls_handshake_is_recognised_from_its_first_byte() {
        assert_eq!(classify(&[0x16]), Ok(Classification::DirectTls));
        // The start of a TLS 1.3 ClientHello record.
        assert_eq!(
            classify(&[0x16, 0x03, 0x01, 0x02, 0x00, 0x01, 0x00, 0x01, 0xfc]),
            Ok(Classification::DirectTls)
        );
    }

    #[test]
    fn a_tls_handshake_byte_is_not_special_after_the_first_packet() {
        // Read as a packet, the same bytes announce an impossible length.
        assert_eq!(
            StartupPacket::parse(&[0x16, 0x03, 0x01, 0x02]),
            Err(StartupError::InvalidLength {
                length: 0x1603_0102
            })
        );
    }

    #[test]
    fn other_tls_record_types_are_not_direct_tls() {
        // An alert record (0x15) is not a handshake.
        assert_eq!(
            classify(&[0x15, 0x03, 0x01, 0x00]),
            Err(StartupError::InvalidLength {
                length: 0x1503_0100
            })
        );
    }

    #[test]
    fn classifies_ssl_request() {
        let bytes = packet(SSL_REQUEST_CODE, b"");
        assert_eq!(bytes, [0, 0, 0, 8, 0x04, 0xd2, 0x16, 0x2f]);
        let Ok(Classification::Packet(found)) = classify(&bytes) else {
            panic!("expected a packet");
        };
        assert_eq!(found, StartupPacket::SslRequest);
        assert_eq!(found.wire_len(), 8);
    }

    #[test]
    fn classifies_gssenc_request() {
        let bytes = packet(GSSENC_REQUEST_CODE, b"");
        assert_eq!(bytes, [0, 0, 0, 8, 0x04, 0xd2, 0x16, 0x30]);
        assert_eq!(
            classify(&bytes),
            Ok(Classification::Packet(StartupPacket::GssEncRequest))
        );
    }

    #[test]
    fn bytes_after_a_request_are_visible_to_the_caller() {
        // Plaintext sent right behind an SSLRequest must be refused by the
        // caller. The packet length tells it where the packet ends.
        let mut bytes = packet(SSL_REQUEST_CODE, b"");
        bytes.extend_from_slice(b"Q\0\0\0\x0dselect 1\0");
        let found = StartupPacket::parse(&bytes).unwrap().unwrap();
        assert_eq!(found, StartupPacket::SslRequest);
        assert!(bytes.len() > found.wire_len());
    }

    #[test]
    fn encryption_requests_must_be_eight_bytes() {
        for code in [SSL_REQUEST_CODE, GSSENC_REQUEST_CODE] {
            let bytes = packet(code, b"\0\0\0\0");
            assert_eq!(
                StartupPacket::parse(&bytes),
                Err(StartupError::InvalidRequestLength { length: 12 })
            );
            // Decided from the first eight bytes.
            assert_eq!(
                StartupPacket::parse(&bytes[..8]),
                Err(StartupError::InvalidRequestLength { length: 12 })
            );
        }
    }

    #[test]
    fn classifies_cancel_request_with_a_four_byte_key() {
        let bytes = packet(CANCEL_REQUEST_CODE, &[0, 0, 0x30, 0x39, 1, 2, 3, 4]);
        assert_eq!(bytes.len(), 16);
        let Ok(Some(StartupPacket::CancelRequest(request))) = StartupPacket::parse(&bytes) else {
            panic!("expected a cancel request");
        };
        assert_eq!(request.process_id(), 12345);
        assert_eq!(request.secret_key(), [1, 2, 3, 4]);
        assert_eq!(request.as_bytes(), bytes);
        assert_eq!(StartupPacket::CancelRequest(request).wire_len(), 16);
    }

    #[test]
    fn accepts_cancel_keys_of_1_to_256_bytes() {
        for key_len in [1usize, 2, 3, 4, 5, 31, 32, 33, 255, 256] {
            let mut body = vec![0xff, 0xff, 0xff, 0xff];
            body.extend(core::iter::repeat_n(0xab, key_len));
            let bytes = packet(CANCEL_REQUEST_CODE, &body);
            let Ok(Some(StartupPacket::CancelRequest(request))) = StartupPacket::parse(&bytes)
            else {
                panic!("key of {key_len} bytes must be accepted");
            };
            assert_eq!(request.process_id(), -1);
            assert_eq!(request.secret_key().len(), key_len);
            assert_eq!(request.as_bytes().len(), 12 + key_len);
        }
    }

    #[test]
    fn rejects_cancel_requests_without_a_valid_key() {
        // No process id, half a process id, no key, and a key of 257 bytes.
        for body_len in [0usize, 2, 4, 4 + 257, 4 + 1000] {
            let bytes = packet(CANCEL_REQUEST_CODE, &vec![0u8; body_len]);
            let length = u32::try_from(bytes.len()).unwrap();
            assert_eq!(
                StartupPacket::parse(&bytes),
                Err(StartupError::InvalidCancelRequestLength { length }),
                "body of {body_len} bytes"
            );
            // Decided from the first eight bytes.
            assert_eq!(
                StartupPacket::parse(&bytes[..8]),
                Err(StartupError::InvalidCancelRequestLength { length })
            );
        }
    }

    #[test]
    fn parses_version_and_parameters() {
        let bytes = startup(
            ProtocolVersion::V3_0,
            b"user\0alice\0database\0appdb\0application_name\0psql\0\0",
        );
        let Ok(Classification::Packet(StartupPacket::StartupMessage(message))) = classify(&bytes)
        else {
            panic!("expected a startup message");
        };
        assert_eq!(message.version(), ProtocolVersion::V3_0);
        assert_eq!(
            pairs(&message),
            [
                (&b"user"[..], &b"alice"[..]),
                (&b"database"[..], &b"appdb"[..]),
                (&b"application_name"[..], &b"psql"[..]),
            ]
        );
        assert_eq!(message.get(b"user"), Some(&b"alice"[..]));
        assert_eq!(message.get(b"database"), Some(&b"appdb"[..]));
        assert_eq!(message.get(b"options"), None);
        assert_eq!(message.get(b"use"), None);
        assert_eq!(message.as_bytes(), bytes);
        assert_eq!(
            StartupPacket::StartupMessage(message).wire_len(),
            bytes.len()
        );
    }

    #[test]
    fn parses_protocol_3_2_and_protocol_options() {
        let bytes = startup(
            ProtocolVersion::V3_2,
            b"user\0bob\0_pq_.example\x001\0_pq_\0x\0_pq_.\0\0\0",
        );
        let message = expect_startup(&bytes);
        assert_eq!(message.version(), ProtocolVersion::V3_2);
        assert_eq!(message.version().minor(), 2);
        let options: Vec<_> = message
            .parameters()
            .filter(Parameter::is_protocol_option)
            .map(|parameter| parameter.name())
            .collect();
        // "_pq_" without the dot is an ordinary parameter. "_pq_." alone is
        // a protocol option with an empty rest, as it is to the server.
        assert_eq!(options, [&b"_pq_.example"[..], &b"_pq_."[..]]);
        assert_eq!(message.get(b"_pq_.example"), Some(&b"1"[..]));
        assert_eq!(message.get(b"_pq_."), Some(&b""[..]));
    }

    #[test]
    fn a_future_minor_version_is_parsed_and_reported() {
        let bytes = startup(ProtocolVersion::new(3, 9999), b"user\0u\0\0");
        let message = expect_startup(&bytes);
        assert_eq!(message.version().major(), 3);
        assert_eq!(message.version().minor(), 9999);
        assert!(message.version() > ProtocolVersion::V3_2);
    }

    #[test]
    fn a_repeated_parameter_resolves_to_its_last_value() {
        let bytes = startup(ProtocolVersion::V3_0, b"user\0first\0user\0second\0\0");
        let message = expect_startup(&bytes);
        assert_eq!(message.parameters().count(), 2);
        assert_eq!(message.get(b"user"), Some(&b"second"[..]));
    }

    #[test]
    fn a_startup_message_without_parameters_is_valid() {
        let bytes = startup(ProtocolVersion::V3_0, b"\0");
        let message = expect_startup(&bytes);
        assert_eq!(message.parameters().count(), 0);
        assert_eq!(message.get(b"user"), None);
    }

    #[test]
    fn values_may_be_empty_but_names_may_not() {
        let bytes = startup(ProtocolVersion::V3_0, b"options\0\0user\0u\0\0");
        let message = expect_startup(&bytes);
        assert_eq!(
            pairs(&message),
            [(&b"options"[..], &b""[..]), (&b"user"[..], &b"u"[..])]
        );
    }

    #[test]
    fn rejects_malformed_parameter_lists() {
        let cases: [&[u8]; 9] = [
            // No terminator at all.
            b"",
            // A name without a value.
            b"user\0",
            // A value that is not terminated.
            b"user\0alice",
            // A pair without the final terminator.
            b"user\0alice\0",
            // An empty value followed by nothing: the list is not ended.
            b"user\0\0",
            // Bytes after the terminator.
            b"user\0alice\0\0x",
            b"user\0alice\0\0\0",
            // A terminator first, then more.
            b"\0user\0alice\0\0",
            // A last byte that is not zero. PostgreSQL lets this one pass.
            b"user\0alice\0x",
        ];
        for parameters in cases {
            let bytes = startup(ProtocolVersion::V3_0, parameters);
            assert_eq!(
                StartupPacket::parse(&bytes),
                Err(StartupError::MalformedParameters),
                "{parameters:?}"
            );
        }
    }

    #[test]
    fn rejects_other_major_versions() {
        for (major, minor) in [(2u16, 0u16), (0, 0), (4, 0), (1234, 5677), (1234, 5681)] {
            let version = ProtocolVersion::new(major, minor);
            let bytes = startup(version, b"user\0u\0\0");
            assert_eq!(
                StartupPacket::parse(&bytes),
                Err(StartupError::UnsupportedVersion(version))
            );
            // Decided from the first eight bytes.
            assert_eq!(
                StartupPacket::parse(&bytes[..8]),
                Err(StartupError::UnsupportedVersion(version))
            );
        }
    }

    #[test]
    fn enforces_the_startup_packet_limit() {
        // PostgreSQL accepts at most 10000 bytes after the length field.
        let mut parameters = b"user\0".to_vec();
        parameters.resize(MAX_STARTUP_PACKET_BODY - 4 - 2, b'a');
        parameters.extend_from_slice(b"\0\0");
        let bytes = startup(ProtocolVersion::V3_0, &parameters);
        assert_eq!(bytes.len(), MAX_STARTUP_PACKET_LEN);
        let message = expect_startup(&bytes);
        assert_eq!(message.get(b"user").map(<[u8]>::len), Some(9_989));

        // One byte more is refused, from the length field alone.
        let mut parameters = b"user\0".to_vec();
        parameters.resize(MAX_STARTUP_PACKET_BODY - 4 - 1, b'a');
        parameters.extend_from_slice(b"\0\0");
        let bytes = startup(ProtocolVersion::V3_0, &parameters);
        assert_eq!(bytes.len(), MAX_STARTUP_PACKET_LEN + 1);
        let error = StartupError::InvalidLength { length: 10_005 };
        assert_eq!(StartupPacket::parse(&bytes), Err(error));
        assert_eq!(StartupPacket::parse(&bytes[..4]), Err(error));
        assert_eq!(classify(&bytes[..4]), Err(error));
    }

    #[test]
    fn rejects_lengths_below_eight_and_absurd_lengths() {
        for length in [0u32, 1, 4, 7, 10_005, 0x7fff_ffff, 0x8000_0000, u32::MAX] {
            let mut bytes = length.to_be_bytes().to_vec();
            bytes.extend_from_slice(&ProtocolVersion::V3_0.to_u32().to_be_bytes());
            assert_eq!(
                StartupPacket::parse(&bytes),
                Err(StartupError::InvalidLength { length }),
            );
        }
    }

    #[test]
    fn incomplete_packets_report_incomplete_at_every_cut() {
        let bytes = startup(ProtocolVersion::V3_0, b"user\0alice\0\0");
        for cut in 0..bytes.len() {
            assert_eq!(StartupPacket::parse(&bytes[..cut]), Ok(None), "cut {cut}");
            assert_eq!(classify(&bytes[..cut]), Ok(Classification::Incomplete));
        }
        assert!(matches!(
            classify(&bytes),
            Ok(Classification::Packet(StartupPacket::StartupMessage(_)))
        ));
    }

    #[test]
    fn a_packet_never_reads_past_its_own_length() {
        // The buffer continues with bytes that would complete the parameter
        // list. They are outside the packet and must not be used.
        let mut bytes = startup(ProtocolVersion::V3_0, b"user\0alice");
        bytes.extend_from_slice(b"\0\0");
        assert_eq!(
            StartupPacket::parse(&bytes),
            Err(StartupError::MalformedParameters)
        );

        // A well-formed packet followed by more bytes ends where it says.
        let mut bytes = startup(ProtocolVersion::V3_0, b"user\0alice\0\0");
        let packet_len = bytes.len();
        bytes.extend_from_slice(b"database\0other\0\0");
        let message = expect_startup(&bytes);
        assert_eq!(message.as_bytes().len(), packet_len);
        assert_eq!(message.get(b"database"), None);
    }

    #[test]
    fn debug_output_omits_content() {
        let bytes = startup(ProtocolVersion::V3_0, b"user\0SECRETMARKER\0\0");
        let found = StartupPacket::parse(&bytes).unwrap().unwrap();
        let text = format!("{found:?}");
        assert!(!text.contains("SECRETMARKER"), "{text}");
        let StartupPacket::StartupMessage(message) = found else {
            panic!("expected a startup message");
        };
        for parameter in message.parameters() {
            let text = format!("{parameter:?} {:?}", message.parameters());
            assert!(!text.contains("SECRETMARKER"), "{text}");
            assert!(!text.contains("user"), "{text}");
        }

        let bytes = packet(CANCEL_REQUEST_CODE, b"\0\0\0\x01KEYMATERIAL");
        let text = format!("{:?}", StartupPacket::parse(&bytes).unwrap().unwrap());
        assert!(!text.contains("KEYMATERIAL"), "{text}");
        assert!(text.contains("<11 bytes>"), "{text}");
    }
}
