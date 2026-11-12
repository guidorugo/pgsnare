// SPDX-License-Identifier: Apache-2.0

//! Views of the messages the server sends.
//!
//! Each view is built by its `from_frame` function, which takes a [`Frame`],
//! checks that it is the right message and validates the whole body. A view
//! then hands out borrowed fields without further checks. Nothing is copied.

use core::fmt;

use crate::error::ParseError;
use crate::frame::{Direction, Frame};
use crate::message::{CStrings, CopyData, FormatCode, FormatCodes, ValueIter, Values};
use crate::reader::{Reader, Redacted};
use crate::startup::MAX_CANCEL_KEY_LEN;
use crate::version::ProtocolVersion;

/// The type bytes of the messages a server sends.
pub mod tag {
    /// Every authentication request and `AuthenticationOk`.
    pub const AUTHENTICATION: u8 = b'R';
    /// `BackendKeyData`.
    pub const BACKEND_KEY_DATA: u8 = b'K';
    /// `BindComplete`.
    pub const BIND_COMPLETE: u8 = b'2';
    /// `CloseComplete`.
    pub const CLOSE_COMPLETE: u8 = b'3';
    /// `CommandComplete`.
    pub const COMMAND_COMPLETE: u8 = b'C';
    /// `CopyBothResponse`.
    pub const COPY_BOTH_RESPONSE: u8 = b'W';
    /// `CopyData`.
    pub const COPY_DATA: u8 = b'd';
    /// `CopyDone`.
    pub const COPY_DONE: u8 = b'c';
    /// `CopyInResponse`.
    pub const COPY_IN_RESPONSE: u8 = b'G';
    /// `CopyOutResponse`.
    pub const COPY_OUT_RESPONSE: u8 = b'H';
    /// `DataRow`.
    pub const DATA_ROW: u8 = b'D';
    /// `EmptyQueryResponse`.
    pub const EMPTY_QUERY_RESPONSE: u8 = b'I';
    /// `ErrorResponse`.
    pub const ERROR_RESPONSE: u8 = b'E';
    /// `FunctionCallResponse`.
    pub const FUNCTION_CALL_RESPONSE: u8 = b'V';
    /// `NegotiateProtocolVersion`.
    pub const NEGOTIATE_PROTOCOL_VERSION: u8 = b'v';
    /// `NoData`.
    pub const NO_DATA: u8 = b'n';
    /// `NoticeResponse`.
    pub const NOTICE_RESPONSE: u8 = b'N';
    /// `NotificationResponse`.
    pub const NOTIFICATION_RESPONSE: u8 = b'A';
    /// `ParameterDescription`.
    pub const PARAMETER_DESCRIPTION: u8 = b't';
    /// `ParameterStatus`.
    pub const PARAMETER_STATUS: u8 = b'S';
    /// `ParseComplete`.
    pub const PARSE_COMPLETE: u8 = b'1';
    /// `PortalSuspended`.
    pub const PORTAL_SUSPENDED: u8 = b's';
    /// `ReadyForQuery`.
    pub const READY_FOR_QUERY: u8 = b'Z';
    /// `RowDescription`.
    pub const ROW_DESCRIPTION: u8 = b'T';
}

/// The codes that identify the fields of an `ErrorResponse` or a
/// `NoticeResponse`.
pub mod error_field {
    /// Severity, possibly translated.
    pub const SEVERITY: u8 = b'S';
    /// Severity, never translated. Sent by PostgreSQL 9.6 and later.
    pub const SEVERITY_NONLOCALIZED: u8 = b'V';
    /// The SQLSTATE code.
    pub const SQLSTATE: u8 = b'C';
    /// The primary message.
    pub const MESSAGE: u8 = b'M';
    /// Detail.
    pub const DETAIL: u8 = b'D';
    /// Hint.
    pub const HINT: u8 = b'H';
    /// Cursor position in the query.
    pub const POSITION: u8 = b'P';
    /// Cursor position in an internally generated query.
    pub const INTERNAL_POSITION: u8 = b'p';
    /// The text of the internally generated query.
    pub const INTERNAL_QUERY: u8 = b'q';
    /// The context in which the error occurred.
    pub const WHERE: u8 = b'W';
    /// Schema name.
    pub const SCHEMA: u8 = b's';
    /// Table name.
    pub const TABLE: u8 = b't';
    /// Column name.
    pub const COLUMN: u8 = b'c';
    /// Data type name.
    pub const DATA_TYPE: u8 = b'd';
    /// Constraint name.
    pub const CONSTRAINT: u8 = b'n';
    /// Source file that reported the error.
    pub const FILE: u8 = b'F';
    /// Source line that reported the error.
    pub const LINE: u8 = b'L';
    /// Source routine that reported the error.
    pub const ROUTINE: u8 = b'R';
}

/// The shortest cancel key a server may issue in `BackendKeyData`.
pub const MIN_BACKEND_KEY_LEN: usize = 4;

/// An authentication request, or the final `AuthenticationOk`.
///
/// All of them share one type byte and are told apart by a 32-bit code at
/// the start of the body.
#[derive(Clone, Copy, PartialEq, Eq)]
pub enum Authentication<'a> {
    /// `AuthenticationOk`: the login succeeded.
    Ok,
    /// `AuthenticationKerberosV5`.
    KerberosV5,
    /// `AuthenticationCleartextPassword`.
    CleartextPassword,
    /// `AuthenticationMD5Password`, with the salt to hash the password with.
    Md5Password {
        /// The salt.
        salt: [u8; 4],
    },
    /// `AuthenticationGSS`.
    Gss,
    /// `AuthenticationGSSContinue`, with GSSAPI or SSPI data.
    GssContinue {
        /// The authentication data.
        data: &'a [u8],
    },
    /// `AuthenticationSSPI`.
    Sspi,
    /// `AuthenticationSASL`, with the mechanisms the server offers.
    Sasl(SaslMechanisms<'a>),
    /// `AuthenticationSASLContinue`, with a SASL challenge.
    SaslContinue {
        /// The mechanism-specific data.
        data: &'a [u8],
    },
    /// `AuthenticationSASLFinal`, with the outcome of the SASL exchange.
    SaslFinal {
        /// The mechanism-specific data.
        data: &'a [u8],
    },
    /// An authentication message with a code this crate does not know.
    Other {
        /// The code that identifies the kind of message.
        code: u32,
        /// Everything after the code.
        data: &'a [u8],
    },
}

impl<'a> Authentication<'a> {
    /// The type byte.
    pub const TAG: u8 = tag::AUTHENTICATION;

    /// The code of `AuthenticationOk`.
    pub const CODE_OK: u32 = 0;
    /// The code of `AuthenticationKerberosV5`.
    pub const CODE_KERBEROS_V5: u32 = 2;
    /// The code of `AuthenticationCleartextPassword`.
    pub const CODE_CLEARTEXT_PASSWORD: u32 = 3;
    /// The code of `AuthenticationMD5Password`.
    pub const CODE_MD5_PASSWORD: u32 = 5;
    /// The code of `AuthenticationGSS`.
    pub const CODE_GSS: u32 = 7;
    /// The code of `AuthenticationGSSContinue`.
    pub const CODE_GSS_CONTINUE: u32 = 8;
    /// The code of `AuthenticationSSPI`.
    pub const CODE_SSPI: u32 = 9;
    /// The code of `AuthenticationSASL`.
    pub const CODE_SASL: u32 = 10;
    /// The code of `AuthenticationSASLContinue`.
    pub const CODE_SASL_CONTINUE: u32 = 11;
    /// The code of `AuthenticationSASLFinal`.
    pub const CODE_SASL_FINAL: u32 = 12;

    /// Reads an authentication message.
    ///
    /// # Errors
    ///
    /// Fails when the frame is not an authentication message from the
    /// server, or when its body does not have the layout its code requires.
    /// Messages of a fixed size must have exactly that size.
    pub fn from_frame(frame: Frame<'a>) -> Result<Self, ParseError> {
        let mut reader = Reader::new(frame.body_of(Direction::FromServer, Self::TAG)?);
        let code = reader.u32()?;
        let message = match code {
            Self::CODE_OK => Self::Ok,
            Self::CODE_KERBEROS_V5 => Self::KerberosV5,
            Self::CODE_CLEARTEXT_PASSWORD => Self::CleartextPassword,
            Self::CODE_MD5_PASSWORD => Self::Md5Password {
                salt: reader.array()?,
            },
            Self::CODE_GSS => Self::Gss,
            Self::CODE_GSS_CONTINUE => Self::GssContinue {
                data: reader.take_rest(),
            },
            Self::CODE_SSPI => Self::Sspi,
            Self::CODE_SASL => Self::Sasl(SaslMechanisms::parse(&mut reader)?),
            Self::CODE_SASL_CONTINUE => Self::SaslContinue {
                data: reader.take_rest(),
            },
            Self::CODE_SASL_FINAL => Self::SaslFinal {
                data: reader.take_rest(),
            },
            _ => Self::Other {
                code,
                data: reader.take_rest(),
            },
        };
        reader.finish()?;
        Ok(message)
    }

    /// The code that identifies the kind of authentication message.
    #[must_use]
    pub const fn code(&self) -> u32 {
        match self {
            Self::Ok => Self::CODE_OK,
            Self::KerberosV5 => Self::CODE_KERBEROS_V5,
            Self::CleartextPassword => Self::CODE_CLEARTEXT_PASSWORD,
            Self::Md5Password { .. } => Self::CODE_MD5_PASSWORD,
            Self::Gss => Self::CODE_GSS,
            Self::GssContinue { .. } => Self::CODE_GSS_CONTINUE,
            Self::Sspi => Self::CODE_SSPI,
            Self::Sasl(_) => Self::CODE_SASL,
            Self::SaslContinue { .. } => Self::CODE_SASL_CONTINUE,
            Self::SaslFinal { .. } => Self::CODE_SASL_FINAL,
            Self::Other { code, .. } => *code,
        }
    }
}

impl fmt::Debug for Authentication<'_> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Ok => f.write_str("Ok"),
            Self::KerberosV5 => f.write_str("KerberosV5"),
            Self::CleartextPassword => f.write_str("CleartextPassword"),
            Self::Md5Password { salt } => f
                .debug_struct("Md5Password")
                .field("salt", &Redacted(salt))
                .finish(),
            Self::Gss => f.write_str("Gss"),
            Self::GssContinue { data } => f
                .debug_struct("GssContinue")
                .field("data", &Redacted(data))
                .finish(),
            Self::Sspi => f.write_str("Sspi"),
            Self::Sasl(mechanisms) => f.debug_tuple("Sasl").field(mechanisms).finish(),
            Self::SaslContinue { data } => f
                .debug_struct("SaslContinue")
                .field("data", &Redacted(data))
                .finish(),
            Self::SaslFinal { data } => f
                .debug_struct("SaslFinal")
                .field("data", &Redacted(data))
                .finish(),
            Self::Other { code, data } => f
                .debug_struct("Other")
                .field("code", code)
                .field("data", &Redacted(data))
                .finish(),
        }
    }
}

/// The SASL mechanisms a server offers in `AuthenticationSASL`, in the
/// server's order of preference.
#[derive(Clone, Copy, PartialEq, Eq)]
pub struct SaslMechanisms<'a> {
    /// The names, each with its terminator, without the final terminator.
    names: &'a [u8],
}

impl<'a> SaslMechanisms<'a> {
    /// Reads names up to the empty name that ends the list.
    fn parse(reader: &mut Reader<'a>) -> Result<Self, ParseError> {
        let start = *reader;
        loop {
            let before = *reader;
            if reader.cstr()?.is_empty() {
                return Ok(Self {
                    names: before.consumed_since(&start),
                });
            }
        }
    }

    /// Iterates over the mechanism names in the order sent.
    #[must_use]
    pub const fn iter(&self) -> CStrings<'a> {
        CStrings::new(self.names)
    }

    /// Whether the server offers the mechanism with exactly this name.
    #[must_use]
    pub fn contains(&self, name: &[u8]) -> bool {
        self.iter().any(|offered| offered == name)
    }
}

impl<'a> IntoIterator for SaslMechanisms<'a> {
    type Item = &'a [u8];
    type IntoIter = CStrings<'a>;

    fn into_iter(self) -> Self::IntoIter {
        self.iter()
    }
}

impl fmt::Debug for SaslMechanisms<'_> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("SaslMechanisms")
            .field("count", &self.iter().count())
            .finish()
    }
}

/// `BackendKeyData`: the process id and the secret key a client needs to
/// cancel a query.
///
/// The key is everything after the process id, so its length is read from
/// the frame: 4 bytes in protocol 3.0 and up to 256 bytes in protocol 3.2.
#[derive(Clone, Copy, PartialEq, Eq)]
pub struct BackendKeyData<'a> {
    process_id: i32,
    secret_key: &'a [u8],
}

impl<'a> BackendKeyData<'a> {
    /// The type byte.
    pub const TAG: u8 = tag::BACKEND_KEY_DATA;

    /// Reads a `BackendKeyData` message.
    ///
    /// # Errors
    ///
    /// Fails when the frame is not `BackendKeyData` from the server, or when
    /// the key is not between [`MIN_BACKEND_KEY_LEN`] and
    /// [`MAX_CANCEL_KEY_LEN`] bytes long.
    pub fn from_frame(frame: Frame<'a>) -> Result<Self, ParseError> {
        let mut reader = Reader::new(frame.body_of(Direction::FromServer, Self::TAG)?);
        let process_id = reader.i32()?;
        let secret_key = reader.take_rest();
        if secret_key.len() < MIN_BACKEND_KEY_LEN || secret_key.len() > MAX_CANCEL_KEY_LEN {
            return Err(ParseError::InvalidKeyLength);
        }
        Ok(Self {
            process_id,
            secret_key,
        })
    }

    /// The process id of the backend.
    #[must_use]
    pub const fn process_id(&self) -> i32 {
        self.process_id
    }

    /// The secret key, 4 to 256 bytes long.
    #[must_use]
    pub const fn secret_key(&self) -> &'a [u8] {
        self.secret_key
    }
}

impl fmt::Debug for BackendKeyData<'_> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("BackendKeyData")
            .field("process_id", &self.process_id)
            .field("secret_key", &Redacted(self.secret_key))
            .finish()
    }
}

/// `ParameterStatus`: the current value of a run-time parameter.
#[derive(Clone, Copy, PartialEq, Eq)]
pub struct ParameterStatus<'a> {
    name: &'a [u8],
    value: &'a [u8],
}

impl<'a> ParameterStatus<'a> {
    /// The type byte.
    pub const TAG: u8 = tag::PARAMETER_STATUS;

    /// Reads a `ParameterStatus` message.
    ///
    /// # Errors
    ///
    /// Fails when the frame is not `ParameterStatus` from the server, or
    /// when the body is not exactly two terminated strings.
    pub fn from_frame(frame: Frame<'a>) -> Result<Self, ParseError> {
        let mut reader = Reader::new(frame.body_of(Direction::FromServer, Self::TAG)?);
        let name = reader.cstr()?;
        let value = reader.cstr()?;
        reader.finish()?;
        Ok(Self { name, value })
    }

    /// The name of the parameter.
    #[must_use]
    pub const fn name(&self) -> &'a [u8] {
        self.name
    }

    /// The value of the parameter.
    #[must_use]
    pub const fn value(&self) -> &'a [u8] {
        self.value
    }
}

impl fmt::Debug for ParameterStatus<'_> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("ParameterStatus")
            .field("name", &Redacted(self.name))
            .field("value", &Redacted(self.value))
            .finish()
    }
}

/// `NegotiateProtocolVersion`: the server does not support the minor version
/// or some protocol options the client asked for.
#[derive(Clone, Copy, PartialEq, Eq)]
pub struct NegotiateProtocolVersion<'a> {
    version: ProtocolVersion,
    count: usize,
    /// The option names, each with its terminator.
    options: &'a [u8],
}

impl<'a> NegotiateProtocolVersion<'a> {
    /// The type byte.
    pub const TAG: u8 = tag::NEGOTIATE_PROTOCOL_VERSION;

    /// Reads a `NegotiateProtocolVersion` message.
    ///
    /// # Errors
    ///
    /// Fails when the frame is not `NegotiateProtocolVersion` from the
    /// server, when the option count is negative or more than the frame can
    /// hold, or when the body is not exactly that many terminated strings.
    pub fn from_frame(frame: Frame<'a>) -> Result<Self, ParseError> {
        let mut reader = Reader::new(frame.body_of(Direction::FromServer, Self::TAG)?);
        let version = ProtocolVersion::from_u32(reader.u32()?);
        let count = usize::try_from(reader.i32()?).map_err(|_| ParseError::NegativeLength)?;
        // Every name takes at least its terminator.
        if count > reader.remaining() {
            return Err(ParseError::CountExceedsFrame);
        }
        let options = reader.take_rest();
        let mut check = Reader::new(options);
        for _ in 0..count {
            check.cstr()?;
        }
        check.finish()?;
        Ok(Self {
            version,
            count,
            options,
        })
    }

    /// The newest protocol version the server supports.
    ///
    /// The protocol documentation describes this field as a minor version,
    /// but servers send the complete version number, so that is how it is
    /// read here: protocol 3.0 arrives as 196608.
    #[must_use]
    pub const fn version(&self) -> ProtocolVersion {
        self.version
    }

    /// The number of protocol options the server did not recognise.
    #[must_use]
    pub const fn option_count(&self) -> usize {
        self.count
    }

    /// Iterates over the names of the protocol options the server did not
    /// recognise.
    #[must_use]
    pub const fn options(&self) -> CStrings<'a> {
        CStrings::new(self.options)
    }
}

impl fmt::Debug for NegotiateProtocolVersion<'_> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("NegotiateProtocolVersion")
            .field("version", &self.version)
            .field("option_count", &self.count)
            .finish()
    }
}

/// The bytes one field of a `RowDescription` takes at least: the terminator
/// of its name and 18 bytes of fixed-size fields.
const MIN_FIELD_DESCRIPTION_LEN: usize = 19;

/// `RowDescription`: the columns of the rows that follow.
#[derive(Clone, Copy, PartialEq, Eq)]
pub struct RowDescription<'a> {
    count: u16,
    /// The encoded field descriptions.
    fields: &'a [u8],
}

impl<'a> RowDescription<'a> {
    /// The type byte.
    pub const TAG: u8 = tag::ROW_DESCRIPTION;

    /// Reads a `RowDescription` message.
    ///
    /// # Errors
    ///
    /// Fails when the frame is not `RowDescription` from the server, when
    /// the field count is more than the frame can hold, or when the body is
    /// not exactly that many field descriptions.
    pub fn from_frame(frame: Frame<'a>) -> Result<Self, ParseError> {
        let mut reader = Reader::new(frame.body_of(Direction::FromServer, Self::TAG)?);
        let count = reader.u16()?;
        let min_len = usize::from(count)
            .checked_mul(MIN_FIELD_DESCRIPTION_LEN)
            .ok_or(ParseError::CountExceedsFrame)?;
        if min_len > reader.remaining() {
            return Err(ParseError::CountExceedsFrame);
        }
        let fields = reader.take_rest();
        let mut check = Reader::new(fields);
        for _ in 0..count {
            read_field_description(&mut check)?;
        }
        check.finish()?;
        Ok(Self { count, fields })
    }

    /// The number of fields.
    #[must_use]
    pub fn len(&self) -> usize {
        usize::from(self.count)
    }

    /// Whether the row has no fields.
    #[must_use]
    pub const fn is_empty(&self) -> bool {
        self.count == 0
    }

    /// Iterates over the field descriptions in column order.
    #[must_use]
    pub const fn iter(&self) -> FieldDescriptions<'a> {
        FieldDescriptions {
            remaining: self.count,
            reader: Reader::new(self.fields),
        }
    }
}

impl<'a> IntoIterator for RowDescription<'a> {
    type Item = FieldDescription<'a>;
    type IntoIter = FieldDescriptions<'a>;

    fn into_iter(self) -> Self::IntoIter {
        self.iter()
    }
}

impl fmt::Debug for RowDescription<'_> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("RowDescription")
            .field("count", &self.count)
            .finish()
    }
}

/// One column of a `RowDescription`.
#[derive(Clone, Copy, PartialEq, Eq)]
pub struct FieldDescription<'a> {
    name: &'a [u8],
    table_oid: u32,
    column_id: i16,
    type_oid: u32,
    type_size: i16,
    type_modifier: i32,
    format: FormatCode,
}

impl<'a> FieldDescription<'a> {
    /// The column name.
    #[must_use]
    pub const fn name(&self) -> &'a [u8] {
        self.name
    }

    /// The object id of the table the column comes from, or zero.
    #[must_use]
    pub const fn table_oid(&self) -> u32 {
        self.table_oid
    }

    /// The attribute number of the column in its table, or zero.
    #[must_use]
    pub const fn column_id(&self) -> i16 {
        self.column_id
    }

    /// The object id of the data type.
    #[must_use]
    pub const fn type_oid(&self) -> u32 {
        self.type_oid
    }

    /// The size of the data type. Negative for types of variable width.
    #[must_use]
    pub const fn type_size(&self) -> i16 {
        self.type_size
    }

    /// The type modifier.
    #[must_use]
    pub const fn type_modifier(&self) -> i32 {
        self.type_modifier
    }

    /// The format the column's values are sent in.
    #[must_use]
    pub const fn format(&self) -> FormatCode {
        self.format
    }
}

impl fmt::Debug for FieldDescription<'_> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("FieldDescription")
            .field("name", &Redacted(self.name))
            .field("table_oid", &self.table_oid)
            .field("column_id", &self.column_id)
            .field("type_oid", &self.type_oid)
            .field("type_size", &self.type_size)
            .field("type_modifier", &self.type_modifier)
            .field("format", &self.format)
            .finish()
    }
}

fn read_field_description<'a>(reader: &mut Reader<'a>) -> Result<FieldDescription<'a>, ParseError> {
    Ok(FieldDescription {
        name: reader.cstr()?,
        table_oid: reader.u32()?,
        column_id: reader.i16()?,
        type_oid: reader.u32()?,
        type_size: reader.i16()?,
        type_modifier: reader.i32()?,
        format: FormatCode(reader.i16()?),
    })
}

/// An iterator over the fields of a [`RowDescription`].
#[derive(Clone)]
pub struct FieldDescriptions<'a> {
    remaining: u16,
    reader: Reader<'a>,
}

impl<'a> Iterator for FieldDescriptions<'a> {
    type Item = FieldDescription<'a>;

    fn next(&mut self) -> Option<Self::Item> {
        self.remaining = self.remaining.checked_sub(1)?;
        read_field_description(&mut self.reader).ok()
    }

    fn size_hint(&self) -> (usize, Option<usize>) {
        let remaining = usize::from(self.remaining);
        (remaining, Some(remaining))
    }
}

impl ExactSizeIterator for FieldDescriptions<'_> {}

impl fmt::Debug for FieldDescriptions<'_> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("FieldDescriptions")
            .field("remaining", &self.remaining)
            .finish_non_exhaustive()
    }
}

/// `DataRow`: one row of a result.
#[derive(Clone, Copy, PartialEq, Eq)]
pub struct DataRow<'a> {
    columns: Values<'a>,
}

impl<'a> DataRow<'a> {
    /// The type byte.
    pub const TAG: u8 = tag::DATA_ROW;

    /// Reads a `DataRow` message.
    ///
    /// # Errors
    ///
    /// Fails when the frame is not `DataRow` from the server, when the
    /// column count is more than the frame can hold, when a column length is
    /// negative without being the NULL marker or runs past the frame, or
    /// when bytes remain after the last column.
    pub fn from_frame(frame: Frame<'a>) -> Result<Self, ParseError> {
        let mut reader = Reader::new(frame.body_of(Direction::FromServer, Self::TAG)?);
        let columns = Values::parse(&mut reader)?;
        reader.finish()?;
        Ok(Self { columns })
    }

    /// The column values.
    #[must_use]
    pub const fn columns(&self) -> Values<'a> {
        self.columns
    }

    /// The number of columns.
    #[must_use]
    pub fn len(&self) -> usize {
        self.columns.len()
    }

    /// Whether the row has no columns.
    #[must_use]
    pub const fn is_empty(&self) -> bool {
        self.columns.is_empty()
    }

    /// Iterates over the column values in order. `None` is the SQL NULL.
    #[must_use]
    pub const fn iter(&self) -> ValueIter<'a> {
        self.columns.iter()
    }
}

impl<'a> IntoIterator for DataRow<'a> {
    type Item = Option<&'a [u8]>;
    type IntoIter = ValueIter<'a>;

    fn into_iter(self) -> Self::IntoIter {
        self.iter()
    }
}

impl fmt::Debug for DataRow<'_> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("DataRow")
            .field("columns", &self.columns)
            .finish()
    }
}

/// `CommandComplete`: a command finished, with its command tag.
#[derive(Clone, Copy, PartialEq, Eq)]
pub struct CommandComplete<'a> {
    tag: &'a [u8],
}

impl<'a> CommandComplete<'a> {
    /// The type byte.
    pub const TAG: u8 = tag::COMMAND_COMPLETE;

    /// Reads a `CommandComplete` message.
    ///
    /// # Errors
    ///
    /// Fails when the frame is not `CommandComplete` from the server, or
    /// when the body is not exactly one terminated string.
    pub fn from_frame(frame: Frame<'a>) -> Result<Self, ParseError> {
        let mut reader = Reader::new(frame.body_of(Direction::FromServer, Self::TAG)?);
        let tag = reader.cstr()?;
        reader.finish()?;
        Ok(Self { tag })
    }

    /// The command tag, such as `SELECT 3` or `INSERT 0 1`.
    #[must_use]
    pub const fn tag(&self) -> &'a [u8] {
        self.tag
    }

    /// The row count at the end of the tag, for commands that report one.
    #[must_use]
    pub fn rows(&self) -> Option<u64> {
        self.split_rows().map(|(_, rows)| rows)
    }

    /// Splits the tag into the part before the row count and the row count:
    /// `INSERT 0 1` gives `INSERT 0` and 1.
    ///
    /// Returns `None` unless the tag is a command, a space and a decimal
    /// number written the way the server writes it: digits only, without a
    /// sign or leading zeros, and within 64 bits.
    #[must_use]
    pub fn split_rows(&self) -> Option<(&'a [u8], u64)> {
        let space = self.tag.iter().rposition(|&byte| byte == b' ')?;
        let (command, rest) = self.tag.split_at_checked(space)?;
        if command.is_empty() {
            return None;
        }
        let (_, digits) = rest.split_first()?;
        Some((command, parse_row_count(digits)?))
    }
}

impl fmt::Debug for CommandComplete<'_> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("CommandComplete")
            .field("tag", &Redacted(self.tag))
            .finish()
    }
}

/// Parses a row count in the form the server prints it.
fn parse_row_count(digits: &[u8]) -> Option<u64> {
    match digits {
        [] | [b'0', _, ..] => return None,
        _ => {}
    }
    let mut value: u64 = 0;
    for &digit in digits {
        if !digit.is_ascii_digit() {
            return None;
        }
        let digit = u64::from(digit.checked_sub(b'0')?);
        value = value.checked_mul(10)?.checked_add(digit)?;
    }
    Some(value)
}

/// The transaction state a server reports in `ReadyForQuery`.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum TransactionStatus {
    /// Not in a transaction block.
    Idle,
    /// In a transaction block.
    InTransaction,
    /// In a failed transaction block. Queries are rejected until it ends.
    Failed,
}

impl TransactionStatus {
    /// Interprets the status byte of `ReadyForQuery`.
    #[must_use]
    pub const fn from_byte(byte: u8) -> Option<Self> {
        match byte {
            b'I' => Some(Self::Idle),
            b'T' => Some(Self::InTransaction),
            b'E' => Some(Self::Failed),
            _ => None,
        }
    }

    /// The status byte as sent on the wire.
    #[must_use]
    pub const fn to_byte(self) -> u8 {
        match self {
            Self::Idle => b'I',
            Self::InTransaction => b'T',
            Self::Failed => b'E',
        }
    }
}

/// `ReadyForQuery`: the server is ready for the next command.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct ReadyForQuery {
    status: TransactionStatus,
}

impl ReadyForQuery {
    /// The type byte.
    pub const TAG: u8 = tag::READY_FOR_QUERY;

    /// Reads a `ReadyForQuery` message.
    ///
    /// # Errors
    ///
    /// Fails when the frame is not `ReadyForQuery` from the server, when the
    /// body is not exactly one byte, or when that byte is not a transaction
    /// status the protocol defines.
    pub fn from_frame(frame: Frame<'_>) -> Result<Self, ParseError> {
        let mut reader = Reader::new(frame.body_of(Direction::FromServer, Self::TAG)?);
        let status = TransactionStatus::from_byte(reader.u8()?).ok_or(ParseError::InvalidValue)?;
        reader.finish()?;
        Ok(Self { status })
    }

    /// The transaction state of the session.
    #[must_use]
    pub const fn status(&self) -> TransactionStatus {
        self.status
    }
}

/// The fields of an `ErrorResponse` or a `NoticeResponse`.
///
/// Each field is a one-byte code and a string. The codes are listed in
/// [`error_field`]. Codes this crate does not know are kept, as the
/// protocol requires.
#[derive(Clone, Copy, PartialEq, Eq)]
pub struct ErrorFields<'a> {
    /// The encoded fields, without the zero byte that ends the list.
    fields: &'a [u8],
}

impl<'a> ErrorFields<'a> {
    /// Reads fields up to the zero byte that ends the list, which must be
    /// the last byte of the body.
    fn parse(body: &'a [u8]) -> Result<Self, ParseError> {
        let start = Reader::new(body);
        let mut reader = start;
        loop {
            let before = reader;
            if reader.u8()? == 0 {
                reader.finish()?;
                return Ok(Self {
                    fields: before.consumed_since(&start),
                });
            }
            reader.cstr()?;
        }
    }

    /// Iterates over the fields in the order sent.
    #[must_use]
    pub const fn iter(&self) -> ErrorFieldIter<'a> {
        ErrorFieldIter {
            reader: Reader::new(self.fields),
        }
    }

    /// The value of the field with the given code.
    ///
    /// A well-formed message has each code at most once. If a code is
    /// repeated, the last value is returned, which is the one libpq reports.
    #[must_use]
    pub fn get(&self, code: u8) -> Option<&'a [u8]> {
        self.iter()
            .filter(|field| field.code == code)
            .last()
            .map(|field| field.value)
    }

    /// The severity that is never translated, such as `ERROR` or `FATAL`,
    /// or the possibly translated one when the server sent no other.
    #[must_use]
    pub fn severity(&self) -> Option<&'a [u8]> {
        self.get(error_field::SEVERITY_NONLOCALIZED)
            .or_else(|| self.get(error_field::SEVERITY))
    }

    /// The SQLSTATE code.
    #[must_use]
    pub fn sqlstate(&self) -> Option<&'a [u8]> {
        self.get(error_field::SQLSTATE)
    }

    /// The primary message.
    #[must_use]
    pub fn message(&self) -> Option<&'a [u8]> {
        self.get(error_field::MESSAGE)
    }
}

impl<'a> IntoIterator for ErrorFields<'a> {
    type Item = ErrorField<'a>;
    type IntoIter = ErrorFieldIter<'a>;

    fn into_iter(self) -> Self::IntoIter {
        self.iter()
    }
}

impl fmt::Debug for ErrorFields<'_> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("ErrorFields")
            .field("count", &self.iter().count())
            .finish()
    }
}

/// One field of an `ErrorResponse` or a `NoticeResponse`.
#[derive(Clone, Copy, PartialEq, Eq)]
pub struct ErrorField<'a> {
    code: u8,
    value: &'a [u8],
}

impl<'a> ErrorField<'a> {
    /// The code that identifies the field. Never zero.
    #[must_use]
    pub const fn code(&self) -> u8 {
        self.code
    }

    /// The value of the field.
    #[must_use]
    pub const fn value(&self) -> &'a [u8] {
        self.value
    }
}

impl fmt::Debug for ErrorField<'_> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("ErrorField")
            .field("code", &self.code)
            .field("value", &Redacted(self.value))
            .finish()
    }
}

/// An iterator over [`ErrorFields`].
#[derive(Clone)]
pub struct ErrorFieldIter<'a> {
    reader: Reader<'a>,
}

impl<'a> Iterator for ErrorFieldIter<'a> {
    type Item = ErrorField<'a>;

    fn next(&mut self) -> Option<Self::Item> {
        let code = self.reader.u8().ok()?;
        let value = self.reader.cstr().ok()?;
        Some(ErrorField { code, value })
    }
}

impl fmt::Debug for ErrorFieldIter<'_> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("ErrorFieldIter").finish_non_exhaustive()
    }
}

/// `ErrorResponse`: a command or the connection failed.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct ErrorResponse<'a> {
    fields: ErrorFields<'a>,
}

impl<'a> ErrorResponse<'a> {
    /// The type byte.
    pub const TAG: u8 = tag::ERROR_RESPONSE;

    /// Reads an `ErrorResponse` message.
    ///
    /// # Errors
    ///
    /// Fails when the frame is not `ErrorResponse` from the server, or when
    /// the body is not a list of fields ended by one zero byte at the very
    /// end.
    pub fn from_frame(frame: Frame<'a>) -> Result<Self, ParseError> {
        let body = frame.body_of(Direction::FromServer, Self::TAG)?;
        Ok(Self {
            fields: ErrorFields::parse(body)?,
        })
    }

    /// The fields of the error.
    #[must_use]
    pub const fn fields(&self) -> ErrorFields<'a> {
        self.fields
    }
}

/// `NoticeResponse`: a warning or an informational message.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct NoticeResponse<'a> {
    fields: ErrorFields<'a>,
}

impl<'a> NoticeResponse<'a> {
    /// The type byte.
    pub const TAG: u8 = tag::NOTICE_RESPONSE;

    /// Reads a `NoticeResponse` message.
    ///
    /// # Errors
    ///
    /// Fails when the frame is not `NoticeResponse` from the server, or when
    /// the body is not a list of fields ended by one zero byte at the very
    /// end.
    pub fn from_frame(frame: Frame<'a>) -> Result<Self, ParseError> {
        let body = frame.body_of(Direction::FromServer, Self::TAG)?;
        Ok(Self {
            fields: ErrorFields::parse(body)?,
        })
    }

    /// The fields of the notice.
    #[must_use]
    pub const fn fields(&self) -> ErrorFields<'a> {
        self.fields
    }
}

/// `NotificationResponse`: a `NOTIFY` reached a channel the session listens
/// on.
#[derive(Clone, Copy, PartialEq, Eq)]
pub struct NotificationResponse<'a> {
    process_id: i32,
    channel: &'a [u8],
    payload: &'a [u8],
}

impl<'a> NotificationResponse<'a> {
    /// The type byte.
    pub const TAG: u8 = tag::NOTIFICATION_RESPONSE;

    /// Reads a `NotificationResponse` message.
    ///
    /// # Errors
    ///
    /// Fails when the frame is not `NotificationResponse` from the server,
    /// or when the body is not exactly a process id and two terminated
    /// strings.
    pub fn from_frame(frame: Frame<'a>) -> Result<Self, ParseError> {
        let mut reader = Reader::new(frame.body_of(Direction::FromServer, Self::TAG)?);
        let process_id = reader.i32()?;
        let channel = reader.cstr()?;
        let payload = reader.cstr()?;
        reader.finish()?;
        Ok(Self {
            process_id,
            channel,
            payload,
        })
    }

    /// The process id of the backend that sent the notification.
    #[must_use]
    pub const fn process_id(&self) -> i32 {
        self.process_id
    }

    /// The name of the channel.
    #[must_use]
    pub const fn channel(&self) -> &'a [u8] {
        self.channel
    }

    /// The payload passed to `NOTIFY`.
    #[must_use]
    pub const fn payload(&self) -> &'a [u8] {
        self.payload
    }
}

impl fmt::Debug for NotificationResponse<'_> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("NotificationResponse")
            .field("process_id", &self.process_id)
            .field("channel", &Redacted(self.channel))
            .field("payload", &Redacted(self.payload))
            .finish()
    }
}

/// Which way COPY data flows after a COPY response.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum CopyKind {
    /// `CopyInResponse`: the client sends data.
    In,
    /// `CopyOutResponse`: the server sends data.
    Out,
    /// `CopyBothResponse`: both sides send data, as in streaming
    /// replication.
    Both,
}

/// `CopyInResponse`, `CopyOutResponse` or `CopyBothResponse`: the server
/// starts a COPY. The three messages share one layout.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct CopyResponse<'a> {
    kind: CopyKind,
    overall_format: FormatCode,
    column_formats: FormatCodes<'a>,
}

impl<'a> CopyResponse<'a> {
    /// Reads any of the three COPY responses.
    ///
    /// # Errors
    ///
    /// Fails when the frame is not a COPY response from the server, when
    /// the column count is more than the frame can hold, or when the body is
    /// not exactly a format byte, a count and that many format codes.
    pub fn from_frame(frame: Frame<'a>) -> Result<Self, ParseError> {
        let kind = match (frame.direction(), frame.tag()) {
            (Direction::FromServer, tag::COPY_IN_RESPONSE) => CopyKind::In,
            (Direction::FromServer, tag::COPY_OUT_RESPONSE) => CopyKind::Out,
            (Direction::FromServer, tag::COPY_BOTH_RESPONSE) => CopyKind::Both,
            _ => return Err(frame.unexpected()),
        };
        let mut reader = Reader::new(frame.body());
        let overall_format = FormatCode(i16::from(reader.u8()?));
        let column_formats = FormatCodes::parse(&mut reader)?;
        reader.finish()?;
        Ok(Self {
            kind,
            overall_format,
            column_formats,
        })
    }

    /// Which of the three responses this is.
    #[must_use]
    pub const fn kind(&self) -> CopyKind {
        self.kind
    }

    /// The format of the COPY as a whole: text or binary.
    #[must_use]
    pub const fn overall_format(&self) -> FormatCode {
        self.overall_format
    }

    /// The format of each column.
    #[must_use]
    pub const fn column_formats(&self) -> FormatCodes<'a> {
        self.column_formats
    }
}

/// Any message from the server, parsed into the view this crate has for it.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Message<'a> {
    /// An authentication request or `AuthenticationOk`.
    Authentication(Authentication<'a>),
    /// `BackendKeyData`.
    BackendKeyData(BackendKeyData<'a>),
    /// `ParameterStatus`.
    ParameterStatus(ParameterStatus<'a>),
    /// `NegotiateProtocolVersion`.
    NegotiateProtocolVersion(NegotiateProtocolVersion<'a>),
    /// `RowDescription`.
    RowDescription(RowDescription<'a>),
    /// `DataRow`.
    DataRow(DataRow<'a>),
    /// `CommandComplete`.
    CommandComplete(CommandComplete<'a>),
    /// `ReadyForQuery`.
    ReadyForQuery(ReadyForQuery),
    /// `ErrorResponse`.
    ErrorResponse(ErrorResponse<'a>),
    /// `NoticeResponse`.
    NoticeResponse(NoticeResponse<'a>),
    /// `NotificationResponse`.
    NotificationResponse(NotificationResponse<'a>),
    /// `CopyInResponse`, `CopyOutResponse` or `CopyBothResponse`.
    CopyResponse(CopyResponse<'a>),
    /// `CopyData`.
    CopyData(CopyData<'a>),
    /// A message this crate has no view for. Its body was not examined.
    Other(Frame<'a>),
}

impl<'a> Message<'a> {
    /// Reads a frame from the server as the view that matches its type
    /// byte. A type byte without a view gives [`Message::Other`].
    ///
    /// # Errors
    ///
    /// Fails when the frame was not sent by the server, or when the view
    /// for its type byte rejects the body.
    pub fn from_frame(frame: Frame<'a>) -> Result<Self, ParseError> {
        if frame.direction() != Direction::FromServer {
            return Err(frame.unexpected());
        }
        Ok(match frame.tag() {
            tag::AUTHENTICATION => Self::Authentication(Authentication::from_frame(frame)?),
            tag::BACKEND_KEY_DATA => Self::BackendKeyData(BackendKeyData::from_frame(frame)?),
            tag::PARAMETER_STATUS => Self::ParameterStatus(ParameterStatus::from_frame(frame)?),
            tag::NEGOTIATE_PROTOCOL_VERSION => {
                Self::NegotiateProtocolVersion(NegotiateProtocolVersion::from_frame(frame)?)
            }
            tag::ROW_DESCRIPTION => Self::RowDescription(RowDescription::from_frame(frame)?),
            tag::DATA_ROW => Self::DataRow(DataRow::from_frame(frame)?),
            tag::COMMAND_COMPLETE => Self::CommandComplete(CommandComplete::from_frame(frame)?),
            tag::READY_FOR_QUERY => Self::ReadyForQuery(ReadyForQuery::from_frame(frame)?),
            tag::ERROR_RESPONSE => Self::ErrorResponse(ErrorResponse::from_frame(frame)?),
            tag::NOTICE_RESPONSE => Self::NoticeResponse(NoticeResponse::from_frame(frame)?),
            tag::NOTIFICATION_RESPONSE => {
                Self::NotificationResponse(NotificationResponse::from_frame(frame)?)
            }
            tag::COPY_IN_RESPONSE | tag::COPY_OUT_RESPONSE | tag::COPY_BOTH_RESPONSE => {
                Self::CopyResponse(CopyResponse::from_frame(frame)?)
            }
            tag::COPY_DATA => Self::CopyData(CopyData::from_frame(frame)?),
            _ => Self::Other(frame),
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::frame::{Framer, Limits, Step};
    use crate::testutil::{frame, wire};

    fn server(bytes: &[u8]) -> Frame<'_> {
        frame(Direction::FromServer, bytes)
    }

    /// Asserts that `parse` rejects every proper prefix of `body`.
    fn assert_prefixes_fail(tag: u8, body: &[u8], parse: impl Fn(Frame<'_>) -> bool) {
        for cut in 0..body.len() {
            let bytes = wire(tag, &body[..cut]);
            assert!(
                !parse(server(&bytes)),
                "a body cut to {cut} of {} bytes must be rejected",
                body.len()
            );
        }
        let bytes = wire(tag, body);
        assert!(parse(server(&bytes)), "the whole body must be accepted");
    }

    fn auth(body: &[u8]) -> Result<Authentication<'_>, ParseError> {
        // Leaked so the result can borrow from it in a one-line test.
        let bytes: &'static [u8] = Vec::leak(wire(b'R', body));
        Authentication::from_frame(server(bytes))
    }

    #[test]
    fn authentication_fixed_size_kinds() {
        assert_eq!(auth(&[0, 0, 0, 0]), Ok(Authentication::Ok));
        assert_eq!(auth(&[0, 0, 0, 2]), Ok(Authentication::KerberosV5));
        assert_eq!(auth(&[0, 0, 0, 3]), Ok(Authentication::CleartextPassword));
        assert_eq!(auth(&[0, 0, 0, 7]), Ok(Authentication::Gss));
        assert_eq!(auth(&[0, 0, 0, 9]), Ok(Authentication::Sspi));
        assert_eq!(
            auth(&[0, 0, 0, 5, 1, 2, 3, 4]),
            Ok(Authentication::Md5Password { salt: [1, 2, 3, 4] })
        );
        for code in [0u8, 2, 3, 7, 9] {
            assert_eq!(auth(&[0, 0, 0, code]).unwrap().code(), u32::from(code));
            // A message of fixed size must have exactly that size.
            assert_eq!(auth(&[0, 0, 0, code, 0]), Err(ParseError::TrailingBytes));
        }
        assert_eq!(auth(&[0, 0, 0, 5, 1, 2, 3]), Err(ParseError::Truncated));
        assert_eq!(
            auth(&[0, 0, 0, 5, 1, 2, 3, 4, 5]),
            Err(ParseError::TrailingBytes)
        );
        assert_eq!(auth(&[]), Err(ParseError::Truncated));
        assert_eq!(auth(&[0, 0, 0]), Err(ParseError::Truncated));
    }

    #[test]
    fn authentication_sasl_mechanism_list() {
        let message = auth(b"\0\0\0\x0aSCRAM-SHA-256-PLUS\0SCRAM-SHA-256\0\0").unwrap();
        let Authentication::Sasl(mechanisms) = message else {
            panic!("expected AuthenticationSASL");
        };
        assert_eq!(message.code(), 10);
        let names: Vec<_> = mechanisms.iter().collect();
        assert_eq!(names, [&b"SCRAM-SHA-256-PLUS"[..], &b"SCRAM-SHA-256"[..]]);
        assert!(mechanisms.contains(b"SCRAM-SHA-256"));
        assert!(mechanisms.contains(b"SCRAM-SHA-256-PLUS"));
        assert!(!mechanisms.contains(b"SCRAM-SHA-25"));
        assert!(!mechanisms.contains(b""));
        assert_eq!(mechanisms.into_iter().count(), 2);
    }

    #[test]
    fn authentication_sasl_edge_cases() {
        // An empty list is well-formed.
        let Ok(Authentication::Sasl(mechanisms)) = auth(b"\0\0\0\x0a\0") else {
            panic!("expected AuthenticationSASL");
        };
        assert_eq!(mechanisms.iter().count(), 0);

        // No terminator for the list.
        assert_eq!(
            auth(b"\0\0\0\x0aSCRAM-SHA-256\0"),
            Err(ParseError::UnterminatedString)
        );
        // No terminator for the name.
        assert_eq!(
            auth(b"\0\0\0\x0aSCRAM-SHA-256"),
            Err(ParseError::UnterminatedString)
        );
        // Nothing after the code.
        assert_eq!(auth(b"\0\0\0\x0a"), Err(ParseError::UnterminatedString));
        // Bytes after the end of the list would be read by libpq as the
        // start of the next message. They are refused.
        assert_eq!(
            auth(b"\0\0\0\x0aSCRAM-SHA-256\0\0R"),
            Err(ParseError::TrailingBytes)
        );
        assert_eq!(
            auth(b"\0\0\0\x0aSCRAM-SHA-256\0\0\0"),
            Err(ParseError::TrailingBytes)
        );
    }

    #[test]
    fn authentication_kinds_with_data() {
        assert_eq!(
            auth(b"\0\0\0\x0br=nonce,s=salt,i=4096"),
            Ok(Authentication::SaslContinue {
                data: b"r=nonce,s=salt,i=4096"
            })
        );
        assert_eq!(
            auth(b"\0\0\0\x0cv=signature"),
            Ok(Authentication::SaslFinal {
                data: b"v=signature"
            })
        );
        assert_eq!(
            auth(b"\0\0\0\x08\x01\x02"),
            Ok(Authentication::GssContinue { data: &[1, 2] })
        );
        // Data may be empty.
        assert_eq!(
            auth(b"\0\0\0\x0b"),
            Ok(Authentication::SaslContinue { data: b"" })
        );
        assert_eq!(auth(b"\0\0\0\x0b").unwrap().code(), 11);
        assert_eq!(auth(b"\0\0\0\x0c").unwrap().code(), 12);
        assert_eq!(auth(b"\0\0\0\x08").unwrap().code(), 8);
    }

    #[test]
    fn authentication_with_an_unknown_code_is_kept() {
        let message = auth(b"\0\0\0\x63future").unwrap();
        assert_eq!(
            message,
            Authentication::Other {
                code: 99,
                data: b"future"
            }
        );
        assert_eq!(message.code(), 99);
        // Codes PostgreSQL once used and no longer sends are unknown too.
        assert_eq!(auth(&[0, 0, 0, 6]).unwrap().code(), 6);
        assert_eq!(auth(&[0xff, 0xff, 0xff, 0xff]).unwrap().code(), u32::MAX);
    }

    #[test]
    fn views_check_direction_and_type() {
        let bytes = wire(b'R', &[0, 0, 0, 0]);
        let from_client = frame(Direction::FromClient, &bytes);
        assert_eq!(
            Authentication::from_frame(from_client),
            Err(ParseError::UnexpectedMessage {
                direction: Direction::FromClient,
                tag: b'R'
            })
        );
        assert_eq!(
            Message::from_frame(from_client),
            Err(ParseError::UnexpectedMessage {
                direction: Direction::FromClient,
                tag: b'R'
            })
        );

        // A well-formed frame of another type is refused by every view.
        let from_server = server(&bytes);
        let unexpected = Err(ParseError::UnexpectedMessage {
            direction: Direction::FromServer,
            tag: b'R',
        });
        assert_eq!(
            BackendKeyData::from_frame(from_server).map(drop),
            unexpected
        );
        assert_eq!(
            ParameterStatus::from_frame(from_server).map(drop),
            unexpected
        );
        assert_eq!(
            NegotiateProtocolVersion::from_frame(from_server).map(drop),
            unexpected
        );
        assert_eq!(
            RowDescription::from_frame(from_server).map(drop),
            unexpected
        );
        assert_eq!(DataRow::from_frame(from_server).map(drop), unexpected);
        assert_eq!(
            CommandComplete::from_frame(from_server).map(drop),
            unexpected
        );
        assert_eq!(ReadyForQuery::from_frame(from_server).map(drop), unexpected);
        assert_eq!(ErrorResponse::from_frame(from_server).map(drop), unexpected);
        assert_eq!(
            NoticeResponse::from_frame(from_server).map(drop),
            unexpected
        );
        assert_eq!(
            NotificationResponse::from_frame(from_server).map(drop),
            unexpected
        );
        assert_eq!(CopyResponse::from_frame(from_server).map(drop), unexpected);

        // The COPY responses exist only from the server.
        let bytes = wire(b'H', &[0, 0, 0]);
        assert!(CopyResponse::from_frame(server(&bytes)).is_ok());
        assert_eq!(
            CopyResponse::from_frame(frame(Direction::FromClient, &bytes)).map(drop),
            Err(ParseError::UnexpectedMessage {
                direction: Direction::FromClient,
                tag: b'H'
            })
        );
    }

    #[test]
    fn backend_key_data_reads_the_key_by_length() {
        // Protocol 3.0: a four-byte key.
        let bytes = wire(b'K', &[0, 0, 0x04, 0xd2, 0xde, 0xad, 0xbe, 0xef]);
        let key_data = BackendKeyData::from_frame(server(&bytes)).unwrap();
        assert_eq!(key_data.process_id(), 1234);
        assert_eq!(key_data.secret_key(), [0xde, 0xad, 0xbe, 0xef]);

        // Protocol 3.2: PostgreSQL 18 sends 32 bytes, up to 256 are allowed.
        for key_len in [5usize, 32, 255, 256] {
            let mut body = vec![0, 0, 0, 1];
            body.extend((0..key_len).map(|index| u8::try_from(index % 251).unwrap()));
            let bytes = wire(b'K', &body);
            let key_data = BackendKeyData::from_frame(server(&bytes)).unwrap();
            assert_eq!(key_data.secret_key(), &body[4..]);
        }
    }

    #[test]
    fn backend_key_data_rejects_keys_out_of_range() {
        for key_len in [0usize, 1, 3, 257, 1000] {
            let mut body = vec![0, 0, 0, 1];
            body.extend(core::iter::repeat_n(7u8, key_len));
            let bytes = wire(b'K', &body);
            assert_eq!(
                BackendKeyData::from_frame(server(&bytes)),
                Err(ParseError::InvalidKeyLength),
                "key of {key_len} bytes"
            );
        }
        let bytes = wire(b'K', &[0, 0, 0]);
        assert_eq!(
            BackendKeyData::from_frame(server(&bytes)),
            Err(ParseError::Truncated)
        );
        // A negative process id is passed through as it is.
        let bytes = wire(b'K', &[0xff, 0xff, 0xff, 0xfe, 1, 2, 3, 4]);
        assert_eq!(
            BackendKeyData::from_frame(server(&bytes))
                .unwrap()
                .process_id(),
            -2
        );
    }

    #[test]
    fn parameter_status() {
        let body = b"server_version\x0018.0\0";
        let bytes = wire(b'S', body);
        let status = ParameterStatus::from_frame(server(&bytes)).unwrap();
        assert_eq!(status.name(), b"server_version");
        assert_eq!(status.value(), b"18.0");
        assert_prefixes_fail(b'S', body, |frame| {
            ParameterStatus::from_frame(frame).is_ok()
        });

        let bytes = wire(b'S', b"a\0b\0c");
        assert_eq!(
            ParameterStatus::from_frame(server(&bytes)),
            Err(ParseError::TrailingBytes)
        );
        // Both strings may be empty.
        let bytes = wire(b'S', b"\0\0");
        let status = ParameterStatus::from_frame(server(&bytes)).unwrap();
        assert_eq!((status.name(), status.value()), (&b""[..], &b""[..]));
    }

    #[test]
    fn negotiate_protocol_version() {
        // What a server that only speaks 3.0 answers to a 3.2 request.
        let body = [0, 3, 0, 0, 0, 0, 0, 0];
        let bytes = wire(b'v', &body);
        let negotiate = NegotiateProtocolVersion::from_frame(server(&bytes)).unwrap();
        assert_eq!(negotiate.version(), ProtocolVersion::V3_0);
        assert_eq!(negotiate.option_count(), 0);
        assert_eq!(negotiate.options().count(), 0);

        let body = b"\0\x03\0\x02\0\0\0\x02_pq_.first\0_pq_.second\0";
        let bytes = wire(b'v', body);
        let negotiate = NegotiateProtocolVersion::from_frame(server(&bytes)).unwrap();
        assert_eq!(negotiate.version(), ProtocolVersion::V3_2);
        assert_eq!(negotiate.option_count(), 2);
        let options: Vec<_> = negotiate.options().collect();
        assert_eq!(options, [&b"_pq_.first"[..], &b"_pq_.second"[..]]);
        assert_prefixes_fail(b'v', body, |frame| {
            NegotiateProtocolVersion::from_frame(frame).is_ok()
        });
    }

    #[test]
    fn negotiate_protocol_version_checks_the_count() {
        let parse = |body: &[u8]| {
            let bytes = wire(b'v', body);
            NegotiateProtocolVersion::from_frame(server(&bytes)).map(drop)
        };
        // A negative count.
        assert_eq!(
            parse(b"\0\x03\0\0\xff\xff\xff\xff"),
            Err(ParseError::NegativeLength)
        );
        // A count the frame cannot hold: checked before any loop.
        assert_eq!(
            parse(b"\0\x03\0\0\x7f\xff\xff\xffa\0"),
            Err(ParseError::CountExceedsFrame)
        );
        assert_eq!(
            parse(b"\0\x03\0\0\0\0\0\x01"),
            Err(ParseError::CountExceedsFrame)
        );
        // Fewer names than counted.
        assert_eq!(
            parse(b"\0\x03\0\0\0\0\0\x02ab\0"),
            Err(ParseError::UnterminatedString)
        );
        // More names than counted.
        assert_eq!(
            parse(b"\0\x03\0\0\0\0\0\x01a\0b\0"),
            Err(ParseError::TrailingBytes)
        );
        // An empty name is a string like any other.
        assert_eq!(parse(b"\0\x03\0\0\0\0\0\x01\0"), Ok(()));
    }

    fn row_description_body() -> Vec<u8> {
        let mut body = vec![0, 2];
        body.extend_from_slice(b"id\0");
        body.extend_from_slice(&16_384u32.to_be_bytes()); // table
        body.extend_from_slice(&1i16.to_be_bytes()); // column
        body.extend_from_slice(&23u32.to_be_bytes()); // int4
        body.extend_from_slice(&4i16.to_be_bytes());
        body.extend_from_slice(&(-1i32).to_be_bytes());
        body.extend_from_slice(&0i16.to_be_bytes());
        body.extend_from_slice(b"email\0");
        body.extend_from_slice(&0u32.to_be_bytes());
        body.extend_from_slice(&0i16.to_be_bytes());
        body.extend_from_slice(&25u32.to_be_bytes()); // text
        body.extend_from_slice(&(-1i16).to_be_bytes());
        body.extend_from_slice(&(-1i32).to_be_bytes());
        body.extend_from_slice(&1i16.to_be_bytes());
        body
    }

    #[test]
    fn row_description_fields() {
        let body = row_description_body();
        let bytes = wire(b'T', &body);
        let description = RowDescription::from_frame(server(&bytes)).unwrap();
        assert_eq!(description.len(), 2);
        assert!(!description.is_empty());
        assert_eq!(description.iter().len(), 2);
        let fields: Vec<_> = description.into_iter().collect();
        assert_eq!(fields.len(), 2);

        assert_eq!(fields[0].name(), b"id");
        assert_eq!(fields[0].table_oid(), 16_384);
        assert_eq!(fields[0].column_id(), 1);
        assert_eq!(fields[0].type_oid(), 23);
        assert_eq!(fields[0].type_size(), 4);
        assert_eq!(fields[0].type_modifier(), -1);
        assert_eq!(fields[0].format(), FormatCode::TEXT);

        assert_eq!(fields[1].name(), b"email");
        assert_eq!(fields[1].table_oid(), 0);
        assert_eq!(fields[1].column_id(), 0);
        assert_eq!(fields[1].type_oid(), 25);
        assert_eq!(fields[1].type_size(), -1);
        assert_eq!(fields[1].format(), FormatCode::BINARY);

        assert_prefixes_fail(b'T', &body, |frame| {
            RowDescription::from_frame(frame).is_ok()
        });
    }

    #[test]
    fn row_description_checks_the_count() {
        let parse = |body: &[u8]| {
            let bytes = wire(b'T', body);
            RowDescription::from_frame(server(&bytes)).map(drop)
        };
        // No fields.
        assert_eq!(parse(&[0, 0]), Ok(()));
        assert_eq!(parse(&[0, 0, 0]), Err(ParseError::TrailingBytes));
        // A count the frame cannot hold fails before the loop.
        assert_eq!(parse(&[0xff, 0xff]), Err(ParseError::CountExceedsFrame));
        let mut body = row_description_body();
        body[1] = 3;
        assert_eq!(parse(&body), Err(ParseError::CountExceedsFrame));
        // One field fewer than present.
        body[1] = 1;
        assert_eq!(parse(&body), Err(ParseError::TrailingBytes));
        // A name that never ends: the fixed part is then missing.
        let mut body = vec![0, 1];
        body.extend_from_slice(&[b'x'; 30]);
        assert_eq!(parse(&body), Err(ParseError::UnterminatedString));
        assert_eq!(parse(&[]), Err(ParseError::Truncated));
    }

    #[test]
    fn data_row_columns() {
        let body = b"\0\x03\0\0\0\x05alice\xff\xff\xff\xff\0\0\0\0";
        let bytes = wire(b'D', body);
        let row = DataRow::from_frame(server(&bytes)).unwrap();
        assert_eq!(row.len(), 3);
        assert!(!row.is_empty());
        let columns: Vec<_> = row.iter().collect();
        assert_eq!(columns, [Some(&b"alice"[..]), None, Some(&b""[..])]);
        assert_eq!(row.columns().len(), 3);
        assert_eq!(row.into_iter().len(), 3);
        assert_prefixes_fail(b'D', body, |frame| DataRow::from_frame(frame).is_ok());
    }

    #[test]
    fn data_row_rejects_malformed_bodies() {
        let parse = |body: &[u8]| {
            let bytes = wire(b'D', body);
            DataRow::from_frame(server(&bytes)).map(drop)
        };
        assert_eq!(parse(&[0, 0]), Ok(()));
        assert_eq!(parse(&[]), Err(ParseError::Truncated));
        assert_eq!(parse(&[0]), Err(ParseError::Truncated));
        assert_eq!(parse(&[0, 0, 0]), Err(ParseError::TrailingBytes));
        assert_eq!(parse(&[0xff, 0xff]), Err(ParseError::CountExceedsFrame));
        assert_eq!(parse(b"\0\x01\0\0\0\x05abcd"), Err(ParseError::Truncated));
        assert_eq!(
            parse(b"\0\x01\0\0\0\x03abcd"),
            Err(ParseError::TrailingBytes)
        );
        assert_eq!(
            parse(b"\0\x01\xff\xff\xff\xfe"),
            Err(ParseError::NegativeLength)
        );
        assert_eq!(parse(b"\0\x01\x80\0\0\0"), Err(ParseError::NegativeLength));
    }

    #[test]
    fn a_view_never_reads_past_its_frame() {
        // The frame says two columns and holds one. The buffer goes on with
        // bytes that would be a valid second column.
        let mut buffer = wire(b'D', b"\0\x02\0\0\0\x01a");
        let frame_len = buffer.len();
        buffer.extend_from_slice(b"\0\0\0\x01b");
        buffer.extend_from_slice(&wire(b'Z', b"I"));

        let mut framer = Framer::new(Direction::FromServer, Limits::buffered_only(1024));
        let mut unread = &buffer[..];
        let Ok(Step::Frame(first)) = framer.next(&mut unread) else {
            panic!("expected a frame");
        };
        assert_eq!(first.wire_len(), frame_len);
        assert_eq!(
            DataRow::from_frame(first),
            Err(ParseError::CountExceedsFrame)
        );

        // The same with a column length that points past the frame.
        let mut buffer = wire(b'D', b"\0\x01\0\0\0\x05ab");
        buffer.extend_from_slice(b"cde");
        let mut unread = &buffer[..];
        let Ok(Step::Frame(first)) = framer.next(&mut unread) else {
            panic!("expected a frame");
        };
        assert_eq!(DataRow::from_frame(first), Err(ParseError::Truncated));

        // And with a string whose terminator lies outside the frame.
        let mut buffer = wire(b'C', b"SELECT 1");
        buffer.push(0);
        let mut unread = &buffer[..];
        let Ok(Step::Frame(first)) = framer.next(&mut unread) else {
            panic!("expected a frame");
        };
        assert_eq!(
            CommandComplete::from_frame(first),
            Err(ParseError::UnterminatedString)
        );
    }

    #[test]
    fn command_complete_tag_and_row_count() {
        let parse = |tag: &[u8]| {
            let mut body = tag.to_vec();
            body.push(0);
            let bytes: &'static [u8] = Vec::leak(wire(b'C', &body));
            CommandComplete::from_frame(server(bytes)).unwrap()
        };
        let complete = parse(b"SELECT 5");
        assert_eq!(complete.tag(), b"SELECT 5");
        assert_eq!(complete.rows(), Some(5));
        assert_eq!(complete.split_rows(), Some((&b"SELECT"[..], 5)));

        assert_eq!(
            parse(b"INSERT 0 1").split_rows(),
            Some((&b"INSERT 0"[..], 1))
        );
        assert_eq!(parse(b"UPDATE 0").rows(), Some(0));
        assert_eq!(parse(b"COPY 1000000").rows(), Some(1_000_000));
        assert_eq!(parse(b"SELECT 18446744073709551615").rows(), Some(u64::MAX));

        // Tags without a row count.
        for tag in [
            &b"BEGIN"[..],
            b"CREATE TABLE",
            b"SET",
            b"",
            b" ",
            b"SELECT ",
            b" 5",
            b"5",
            // Not the form the server writes.
            b"SELECT -1",
            b"SELECT +1",
            b"SELECT 05",
            b"SELECT 00",
            b"SELECT 1 ",
            b"SELECT 1x",
            b"SELECT 0x10",
            // One more than fits in 64 bits.
            b"SELECT 18446744073709551616",
            b"SELECT 99999999999999999999999999",
        ] {
            assert_eq!(parse(tag).rows(), None, "{:?}", core::str::from_utf8(tag));
            assert_eq!(parse(tag).tag(), tag);
        }
    }

    #[test]
    fn command_complete_rejects_malformed_bodies() {
        let parse = |body: &[u8]| {
            let bytes = wire(b'C', body);
            CommandComplete::from_frame(server(&bytes)).map(drop)
        };
        assert_eq!(parse(b"SELECT 1"), Err(ParseError::UnterminatedString));
        assert_eq!(parse(b""), Err(ParseError::UnterminatedString));
        assert_eq!(parse(b"SELECT 1\0\0"), Err(ParseError::TrailingBytes));
        assert_eq!(parse(b"SELECT 1\0x"), Err(ParseError::TrailingBytes));
    }

    #[test]
    fn ready_for_query_status() {
        let parse = |body: &[u8]| {
            let bytes = wire(b'Z', body);
            ReadyForQuery::from_frame(server(&bytes)).map(|ready| ready.status())
        };
        assert_eq!(parse(b"I"), Ok(TransactionStatus::Idle));
        assert_eq!(parse(b"T"), Ok(TransactionStatus::InTransaction));
        assert_eq!(parse(b"E"), Ok(TransactionStatus::Failed));
        assert_eq!(parse(b"i"), Err(ParseError::InvalidValue));
        assert_eq!(parse(b"\0"), Err(ParseError::InvalidValue));
        assert_eq!(parse(b""), Err(ParseError::Truncated));
        assert_eq!(parse(b"II"), Err(ParseError::TrailingBytes));
        for status in [
            TransactionStatus::Idle,
            TransactionStatus::InTransaction,
            TransactionStatus::Failed,
        ] {
            assert_eq!(TransactionStatus::from_byte(status.to_byte()), Some(status));
        }
    }

    const ERROR_BODY: &[u8] =
        b"SFEHLER\0VERROR\0C42601\0Msyntax error at or near \"selec\"\0P1\0Fscan.l\0L1244\0Rscanner_yyerror\0\0";

    #[test]
    fn error_response_fields() {
        let bytes = wire(b'E', ERROR_BODY);
        let error = ErrorResponse::from_frame(server(&bytes)).unwrap();
        let fields = error.fields();
        let codes: Vec<u8> = fields.iter().map(|field| field.code()).collect();
        assert_eq!(codes, b"SVCMPFLR");
        assert_eq!(fields.get(error_field::SEVERITY), Some(&b"FEHLER"[..]));
        assert_eq!(fields.severity(), Some(&b"ERROR"[..]));
        assert_eq!(fields.sqlstate(), Some(&b"42601"[..]));
        assert_eq!(
            fields.message(),
            Some(&b"syntax error at or near \"selec\""[..])
        );
        assert_eq!(fields.get(error_field::POSITION), Some(&b"1"[..]));
        assert_eq!(fields.get(error_field::FILE), Some(&b"scan.l"[..]));
        assert_eq!(fields.get(error_field::LINE), Some(&b"1244"[..]));
        assert_eq!(
            fields.get(error_field::ROUTINE),
            Some(&b"scanner_yyerror"[..])
        );
        assert_eq!(fields.get(error_field::DETAIL), None);
        assert_eq!(fields.get(0), None);
        let last = fields.into_iter().last().unwrap();
        assert_eq!((last.code(), last.value()), (b'R', &b"scanner_yyerror"[..]));

        assert_prefixes_fail(b'E', ERROR_BODY, |frame| {
            ErrorResponse::from_frame(frame).is_ok()
        });
    }

    #[test]
    fn notice_response_shares_the_layout() {
        let bytes = wire(b'N', ERROR_BODY);
        let notice = NoticeResponse::from_frame(server(&bytes)).unwrap();
        assert_eq!(notice.fields().sqlstate(), Some(&b"42601"[..]));
        assert_eq!(notice.fields().iter().count(), 8);
        // The two views do not accept each other's type byte.
        assert!(ErrorResponse::from_frame(server(&bytes)).is_err());
        let bytes = wire(b'E', ERROR_BODY);
        assert!(NoticeResponse::from_frame(server(&bytes)).is_err());
    }

    #[test]
    fn error_fields_edge_cases() {
        let parse = |body: &[u8]| {
            let bytes: &'static [u8] = Vec::leak(wire(b'E', body));
            ErrorResponse::from_frame(server(bytes)).map(|error| error.fields())
        };
        // Only the terminator: no fields.
        assert_eq!(parse(b"\0").unwrap().iter().count(), 0);
        assert_eq!(parse(b"\0").unwrap().severity(), None);
        // An old server sends only the translated severity.
        assert_eq!(
            parse(b"SFATAL\0\0").unwrap().severity(),
            Some(&b"FATAL"[..])
        );
        // A repeated code resolves to its last value, as in libpq.
        assert_eq!(
            parse(b"Mfirst\0Msecond\0\0").unwrap().message(),
            Some(&b"second"[..])
        );
        // An empty value and an unknown code are kept.
        let fields = parse(b"M\0\xf0future\0\0").unwrap();
        assert_eq!(fields.message(), Some(&b""[..]));
        assert_eq!(fields.get(0xf0), Some(&b"future"[..]));

        assert_eq!(parse(b"").map(drop), Err(ParseError::Truncated));
        assert_eq!(parse(b"Mtext\0").map(drop), Err(ParseError::Truncated));
        assert_eq!(
            parse(b"Mtext").map(drop),
            Err(ParseError::UnterminatedString)
        );
        assert_eq!(
            parse(b"Mtext\0\0\0").map(drop),
            Err(ParseError::TrailingBytes)
        );
        assert_eq!(
            parse(b"\0Mtext\0\0").map(drop),
            Err(ParseError::TrailingBytes)
        );
    }

    #[test]
    fn notification_response() {
        let body = b"\0\0\x30\x39jobs\0payload text\0";
        let bytes = wire(b'A', body);
        let notification = NotificationResponse::from_frame(server(&bytes)).unwrap();
        assert_eq!(notification.process_id(), 12_345);
        assert_eq!(notification.channel(), b"jobs");
        assert_eq!(notification.payload(), b"payload text");
        assert_prefixes_fail(b'A', body, |frame| {
            NotificationResponse::from_frame(frame).is_ok()
        });
        let bytes = wire(b'A', b"\0\0\0\x01c\0p\0x");
        assert_eq!(
            NotificationResponse::from_frame(server(&bytes)),
            Err(ParseError::TrailingBytes)
        );
    }

    #[test]
    fn copy_responses() {
        for (tag, kind) in [
            (b'G', CopyKind::In),
            (b'H', CopyKind::Out),
            (b'W', CopyKind::Both),
        ] {
            let body = [1, 0, 3, 0, 1, 0, 1, 0, 1];
            let bytes = wire(tag, &body);
            let copy = CopyResponse::from_frame(server(&bytes)).unwrap();
            assert_eq!(copy.kind(), kind);
            assert_eq!(copy.overall_format(), FormatCode::BINARY);
            assert_eq!(copy.column_formats().len(), 3);
            assert!(copy.column_formats().iter().all(FormatCode::is_binary));
            assert_prefixes_fail(tag, &body, |frame| CopyResponse::from_frame(frame).is_ok());
        }

        let parse = |body: &[u8]| {
            let bytes = wire(b'H', body);
            CopyResponse::from_frame(server(&bytes)).map(drop)
        };
        // A text COPY of no columns, as START_REPLICATION answers.
        assert_eq!(parse(&[0, 0, 0]), Ok(()));
        assert_eq!(parse(&[0, 0, 0, 0]), Err(ParseError::TrailingBytes));
        assert_eq!(parse(&[0, 0xff, 0xff]), Err(ParseError::CountExceedsFrame));
        assert_eq!(parse(&[0, 0, 2, 0, 0]), Err(ParseError::CountExceedsFrame));
        assert_eq!(parse(&[]), Err(ParseError::Truncated));
        assert_eq!(parse(&[0, 0]), Err(ParseError::Truncated));
    }

    #[test]
    fn message_dispatches_on_the_type_byte() {
        let cases: [(u8, &[u8]); 15] = [
            (b'R', &[0, 0, 0, 0]),
            (b'K', &[0, 0, 0, 1, 1, 2, 3, 4]),
            (b'S', b"a\0b\0"),
            (b'v', &[0, 3, 0, 0, 0, 0, 0, 0]),
            (b'T', &[0, 0]),
            (b'D', &[0, 0]),
            (b'C', b"SELECT 0\0"),
            (b'Z', b"I"),
            (b'E', b"\0"),
            (b'N', b"\0"),
            (b'A', b"\0\0\0\x01c\0p\0"),
            (b'G', &[0, 0, 0]),
            (b'H', &[0, 0, 0]),
            (b'W', &[0, 0, 0]),
            (b'd', b"row\n"),
        ];
        for (tag, body) in cases {
            let bytes = wire(tag, body);
            let message = Message::from_frame(server(&bytes)).unwrap();
            let matches = matches!(
                (tag, message),
                (b'R', Message::Authentication(_))
                    | (b'K', Message::BackendKeyData(_))
                    | (b'S', Message::ParameterStatus(_))
                    | (b'v', Message::NegotiateProtocolVersion(_))
                    | (b'T', Message::RowDescription(_))
                    | (b'D', Message::DataRow(_))
                    | (b'C', Message::CommandComplete(_))
                    | (b'Z', Message::ReadyForQuery(_))
                    | (b'E', Message::ErrorResponse(_))
                    | (b'N', Message::NoticeResponse(_))
                    | (b'A', Message::NotificationResponse(_))
                    | (b'G' | b'H' | b'W', Message::CopyResponse(_))
                    | (b'd', Message::CopyData(_))
            );
            assert!(matches, "type {:?} gave {message:?}", char::from(tag));
        }

        // Messages without a view, and unknown type bytes, pass as frames.
        for tag in [
            b'1', b'2', b'3', b'n', b's', b't', b'I', b'c', b'V', b'?', 0, 0xff,
        ] {
            let bytes = wire(tag, b"anything");
            let Ok(Message::Other(other)) = Message::from_frame(server(&bytes)) else {
                panic!("type {tag:#04x} must be passed through");
            };
            assert_eq!(other.tag(), tag);
            assert_eq!(other.as_bytes(), bytes);
        }

        // A malformed body of a known type is an error, not `Other`.
        let bytes = wire(b'Z', b"");
        assert_eq!(
            Message::from_frame(server(&bytes)),
            Err(ParseError::Truncated)
        );
    }

    #[test]
    fn debug_output_omits_content() {
        const MARKER: &str = "SECRETMARKER";
        let m = MARKER.as_bytes();
        let with = |prefix: &[u8], suffix: &[u8]| [prefix, m, suffix].concat();

        let mut row_description = vec![0, 1];
        row_description.extend_from_slice(m);
        row_description.extend_from_slice(&[0; 19]);

        let bodies: Vec<(u8, Vec<u8>)> = vec![
            (b'R', with(b"\0\0\0\x0a", b"\0\0")),
            (b'R', with(b"\0\0\0\x0b", b"")),
            (b'R', with(b"\0\0\0\x0c", b"")),
            (b'R', with(b"\0\0\0\x08", b"")),
            (b'R', with(b"\0\0\0\x63", b"")),
            (b'K', with(b"\0\0\0\x01", b"")),
            (b'S', with(b"", b"\0value\0")),
            (b'S', with(b"name\0", b"\0")),
            (b'v', with(b"\0\x03\0\0\0\0\0\x01", b"\0")),
            (b'T', row_description),
            (b'D', with(b"\0\x01\0\0\0\x0c", b"")),
            (b'C', with(b"", b"\0")),
            (b'E', with(b"M", b"\0\0")),
            (b'N', with(b"M", b"\0\0")),
            (b'A', with(b"\0\0\0\x01", b"\0payload\0")),
            (b'A', with(b"\0\0\0\x01channel\0", b"\0")),
            (b'd', with(b"", b"\n")),
            (b'?', with(b"", b"")),
        ];
        for (tag, body) in bodies {
            let bytes = wire(tag, &body);
            let message = Message::from_frame(server(&bytes)).unwrap();
            let text = format!("{message:?}");
            assert!(!text.contains(MARKER), "{text}");
            // Not as a list of byte values either.
            assert!(!text.contains("83, 69, 67"), "{text}");
        }

        // The parts handed out by the views are redacted as well.
        let bytes = wire(b'E', &with(b"M", b"\0\0"));
        let error = ErrorResponse::from_frame(server(&bytes)).unwrap();
        let field = error.fields().iter().next().unwrap();
        let text = format!("{field:?} {:?}", error.fields().iter());
        assert!(!text.contains(MARKER), "{text}");

        let mut body = vec![0, 1];
        body.extend_from_slice(m);
        body.extend_from_slice(&[0; 19]);
        let bytes = wire(b'T', &body);
        let description = RowDescription::from_frame(server(&bytes)).unwrap();
        let field = description.iter().next().unwrap();
        let text = format!("{field:?} {:?}", description.iter());
        assert!(!text.contains(MARKER), "{text}");

        let bytes = wire(b'R', &with(b"\0\0\0\x0a", b"\0\0"));
        let Ok(Authentication::Sasl(mechanisms)) = Authentication::from_frame(server(&bytes))
        else {
            panic!("expected AuthenticationSASL");
        };
        let text = format!("{mechanisms:?} {:?}", mechanisms.iter());
        assert!(!text.contains(MARKER), "{text}");

        // The MD5 salt is not printed.
        let bytes = wire(b'R', &[0, 0, 0, 5, 0xaa, 0xbb, 0xcc, 0xdd]);
        let text = format!("{:?}", Authentication::from_frame(server(&bytes)).unwrap());
        assert_eq!(text, "Md5Password { salt: <4 bytes> }");
    }
}
