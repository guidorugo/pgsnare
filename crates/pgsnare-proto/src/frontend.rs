// SPDX-License-Identifier: Apache-2.0

//! Views of the messages the client sends after the startup phase.
//!
//! Each view is built by its `from_frame` function, which takes a [`Frame`],
//! checks that it is the right message and validates the whole body, the way
//! the server does: every string terminated inside the message, every count
//! backed by the bytes that follow it, and nothing left over at the end.

use core::fmt;

use crate::error::ParseError;
use crate::frame::{Direction, Frame};
use crate::message::{CopyData, FormatCodes, Values};
use crate::reader::{Reader, Redacted};

/// The type bytes of the messages a client sends.
pub mod tag {
    /// `Bind`.
    pub const BIND: u8 = b'B';
    /// `Close`.
    pub const CLOSE: u8 = b'C';
    /// `CopyData`.
    pub const COPY_DATA: u8 = b'd';
    /// `CopyDone`.
    pub const COPY_DONE: u8 = b'c';
    /// `CopyFail`.
    pub const COPY_FAIL: u8 = b'f';
    /// `Describe`.
    pub const DESCRIBE: u8 = b'D';
    /// `Execute`.
    pub const EXECUTE: u8 = b'E';
    /// `Flush`.
    pub const FLUSH: u8 = b'H';
    /// `FunctionCall`.
    pub const FUNCTION_CALL: u8 = b'F';
    /// `Parse`.
    pub const PARSE: u8 = b'P';
    /// `PasswordMessage`, `SASLInitialResponse`, `SASLResponse` and
    /// `GSSResponse`, which share one type byte.
    pub const AUTHENTICATION_RESPONSE: u8 = b'p';
    /// `Query`.
    pub const QUERY: u8 = b'Q';
    /// `Sync`.
    pub const SYNC: u8 = b'S';
    /// `Terminate`.
    pub const TERMINATE: u8 = b'X';
}

/// `Query`: one or more SQL statements to run with the simple query
/// protocol.
#[derive(Clone, Copy, PartialEq, Eq)]
pub struct Query<'a> {
    sql: &'a [u8],
}

impl<'a> Query<'a> {
    /// The type byte.
    pub const TAG: u8 = tag::QUERY;

    /// Reads a `Query` message.
    ///
    /// # Errors
    ///
    /// Fails when the frame is not `Query` from the client, or when the
    /// body is not exactly one terminated string.
    pub fn from_frame(frame: Frame<'a>) -> Result<Self, ParseError> {
        let mut reader = Reader::new(frame.body_of(Direction::FromClient, Self::TAG)?);
        let sql = reader.cstr()?;
        reader.finish()?;
        Ok(Self { sql })
    }

    /// The query text, without its terminator.
    #[must_use]
    pub const fn sql(&self) -> &'a [u8] {
        self.sql
    }
}

impl fmt::Debug for Query<'_> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Query")
            .field("sql", &Redacted(self.sql))
            .finish()
    }
}

/// `Parse`: prepare a statement.
#[derive(Clone, Copy, PartialEq, Eq)]
pub struct Parse<'a> {
    statement: &'a [u8],
    sql: &'a [u8],
    parameter_types: ParameterTypes<'a>,
}

impl<'a> Parse<'a> {
    /// The type byte.
    pub const TAG: u8 = tag::PARSE;

    /// Reads a `Parse` message.
    ///
    /// # Errors
    ///
    /// Fails when the frame is not `Parse` from the client, when the count
    /// of parameter types is more than the frame can hold, or when the body
    /// is not exactly two terminated strings, a count and that many type
    /// ids.
    pub fn from_frame(frame: Frame<'a>) -> Result<Self, ParseError> {
        let mut reader = Reader::new(frame.body_of(Direction::FromClient, Self::TAG)?);
        let statement = reader.cstr()?;
        let sql = reader.cstr()?;
        let parameter_types = ParameterTypes::parse(&mut reader)?;
        reader.finish()?;
        Ok(Self {
            statement,
            sql,
            parameter_types,
        })
    }

    /// The name of the prepared statement. Empty for the unnamed statement.
    #[must_use]
    pub const fn statement(&self) -> &'a [u8] {
        self.statement
    }

    /// The query text, without its terminator.
    #[must_use]
    pub const fn sql(&self) -> &'a [u8] {
        self.sql
    }

    /// The parameter types the client fixes in advance.
    #[must_use]
    pub const fn parameter_types(&self) -> ParameterTypes<'a> {
        self.parameter_types
    }
}

impl fmt::Debug for Parse<'_> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Parse")
            .field("statement", &Redacted(self.statement))
            .field("sql", &Redacted(self.sql))
            .field("parameter_types", &self.parameter_types.len())
            .finish()
    }
}

/// The object ids of the parameter types given in a `Parse` message. Zero
/// leaves a type for the server to infer.
#[derive(Clone, Copy, PartialEq, Eq)]
pub struct ParameterTypes<'a> {
    oids: &'a [[u8; 4]],
}

impl<'a> ParameterTypes<'a> {
    /// Reads a 16-bit count followed by that many type ids.
    fn parse(reader: &mut Reader<'a>) -> Result<Self, ParseError> {
        let count = usize::from(reader.u16()?);
        // Checked against the frame before anything is read.
        let len = count.checked_mul(4).ok_or(ParseError::CountExceedsFrame)?;
        let bytes = reader
            .take(len)
            .map_err(|_| ParseError::CountExceedsFrame)?;
        let (oids, _) = bytes.as_chunks::<4>();
        Ok(Self { oids })
    }

    /// The number of type ids.
    #[must_use]
    pub const fn len(&self) -> usize {
        self.oids.len()
    }

    /// Whether the client gave no types.
    #[must_use]
    pub const fn is_empty(&self) -> bool {
        self.oids.is_empty()
    }

    /// The type id at `index`.
    #[must_use]
    pub fn get(&self, index: usize) -> Option<u32> {
        self.oids.get(index).copied().map(u32::from_be_bytes)
    }

    /// Iterates over the type ids in parameter order.
    pub fn iter(&self) -> impl ExactSizeIterator<Item = u32> + use<'a> {
        self.oids.iter().copied().map(u32::from_be_bytes)
    }
}

impl fmt::Debug for ParameterTypes<'_> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_list().entries(self.iter()).finish()
    }
}

/// `Bind`: create a portal from a prepared statement and parameter values.
///
/// The view checks the layout only. The server additionally requires the
/// number of parameter formats to be zero, one or the number of parameters.
/// A `Bind` that breaks that rule parses here, and the server answers it
/// with an error.
#[derive(Clone, Copy, PartialEq, Eq)]
pub struct Bind<'a> {
    portal: &'a [u8],
    statement: &'a [u8],
    parameter_formats: FormatCodes<'a>,
    parameters: Values<'a>,
    result_formats: FormatCodes<'a>,
}

impl<'a> Bind<'a> {
    /// The type byte.
    pub const TAG: u8 = tag::BIND;

    /// Reads a `Bind` message.
    ///
    /// # Errors
    ///
    /// Fails when the frame is not `Bind` from the client, when a count is
    /// more than the frame can hold, when a parameter length is negative
    /// without being the NULL marker or runs past the frame, or when bytes
    /// remain after the result formats.
    pub fn from_frame(frame: Frame<'a>) -> Result<Self, ParseError> {
        let mut reader = Reader::new(frame.body_of(Direction::FromClient, Self::TAG)?);
        let portal = reader.cstr()?;
        let statement = reader.cstr()?;
        let parameter_formats = FormatCodes::parse(&mut reader)?;
        let parameters = Values::parse(&mut reader)?;
        let result_formats = FormatCodes::parse(&mut reader)?;
        reader.finish()?;
        Ok(Self {
            portal,
            statement,
            parameter_formats,
            parameters,
            result_formats,
        })
    }

    /// The name of the portal to create. Empty for the unnamed portal.
    #[must_use]
    pub const fn portal(&self) -> &'a [u8] {
        self.portal
    }

    /// The name of the prepared statement. Empty for the unnamed statement.
    #[must_use]
    pub const fn statement(&self) -> &'a [u8] {
        self.statement
    }

    /// The formats of the parameter values. See [`FormatCodes::code_for`]
    /// for how they map to parameters.
    #[must_use]
    pub const fn parameter_formats(&self) -> FormatCodes<'a> {
        self.parameter_formats
    }

    /// The parameter values.
    #[must_use]
    pub const fn parameters(&self) -> Values<'a> {
        self.parameters
    }

    /// The formats the client wants result columns in. See
    /// [`FormatCodes::code_for`] for how they map to columns.
    #[must_use]
    pub const fn result_formats(&self) -> FormatCodes<'a> {
        self.result_formats
    }
}

impl fmt::Debug for Bind<'_> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Bind")
            .field("portal", &Redacted(self.portal))
            .field("statement", &Redacted(self.statement))
            .field("parameter_formats", &self.parameter_formats)
            .field("parameters", &self.parameters)
            .field("result_formats", &self.result_formats)
            .finish()
    }
}

/// What a `Describe` or a `Close` refers to.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum Target {
    /// A prepared statement.
    Statement,
    /// A portal.
    Portal,
}

impl Target {
    /// Interprets the byte that selects the target.
    #[must_use]
    pub const fn from_byte(byte: u8) -> Option<Self> {
        match byte {
            b'S' => Some(Self::Statement),
            b'P' => Some(Self::Portal),
            _ => None,
        }
    }

    /// The byte as sent on the wire.
    #[must_use]
    pub const fn to_byte(self) -> u8 {
        match self {
            Self::Statement => b'S',
            Self::Portal => b'P',
        }
    }
}

/// Reads the body shared by `Describe` and `Close`: a target byte and a
/// name.
fn parse_target_and_name(body: &[u8]) -> Result<(Target, &[u8]), ParseError> {
    let mut reader = Reader::new(body);
    let target = Target::from_byte(reader.u8()?).ok_or(ParseError::InvalidValue)?;
    let name = reader.cstr()?;
    reader.finish()?;
    Ok((target, name))
}

/// `Describe`: ask for the description of a prepared statement or a portal.
#[derive(Clone, Copy, PartialEq, Eq)]
pub struct Describe<'a> {
    target: Target,
    name: &'a [u8],
}

impl<'a> Describe<'a> {
    /// The type byte.
    pub const TAG: u8 = tag::DESCRIBE;

    /// Reads a `Describe` message.
    ///
    /// # Errors
    ///
    /// Fails when the frame is not `Describe` from the client, when the
    /// target byte is neither `S` nor `P`, or when the body is not exactly
    /// that byte and one terminated string.
    pub fn from_frame(frame: Frame<'a>) -> Result<Self, ParseError> {
        let body = frame.body_of(Direction::FromClient, Self::TAG)?;
        let (target, name) = parse_target_and_name(body)?;
        Ok(Self { target, name })
    }

    /// Whether a statement or a portal is described.
    #[must_use]
    pub const fn target(&self) -> Target {
        self.target
    }

    /// The name of the statement or portal. Empty for the unnamed one.
    #[must_use]
    pub const fn name(&self) -> &'a [u8] {
        self.name
    }
}

impl fmt::Debug for Describe<'_> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Describe")
            .field("target", &self.target)
            .field("name", &Redacted(self.name))
            .finish()
    }
}

/// `Close`: close a prepared statement or a portal.
#[derive(Clone, Copy, PartialEq, Eq)]
pub struct Close<'a> {
    target: Target,
    name: &'a [u8],
}

impl<'a> Close<'a> {
    /// The type byte.
    pub const TAG: u8 = tag::CLOSE;

    /// Reads a `Close` message.
    ///
    /// # Errors
    ///
    /// Fails when the frame is not `Close` from the client, when the target
    /// byte is neither `S` nor `P`, or when the body is not exactly that
    /// byte and one terminated string.
    pub fn from_frame(frame: Frame<'a>) -> Result<Self, ParseError> {
        let body = frame.body_of(Direction::FromClient, Self::TAG)?;
        let (target, name) = parse_target_and_name(body)?;
        Ok(Self { target, name })
    }

    /// Whether a statement or a portal is closed.
    #[must_use]
    pub const fn target(&self) -> Target {
        self.target
    }

    /// The name of the statement or portal. Empty for the unnamed one.
    #[must_use]
    pub const fn name(&self) -> &'a [u8] {
        self.name
    }
}

impl fmt::Debug for Close<'_> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Close")
            .field("target", &self.target)
            .field("name", &Redacted(self.name))
            .finish()
    }
}

/// `Execute`: run a portal.
#[derive(Clone, Copy, PartialEq, Eq)]
pub struct Execute<'a> {
    portal: &'a [u8],
    max_rows: i32,
}

impl<'a> Execute<'a> {
    /// The type byte.
    pub const TAG: u8 = tag::EXECUTE;

    /// Reads an `Execute` message.
    ///
    /// # Errors
    ///
    /// Fails when the frame is not `Execute` from the client, or when the
    /// body is not exactly one terminated string and a 32-bit row limit.
    pub fn from_frame(frame: Frame<'a>) -> Result<Self, ParseError> {
        let mut reader = Reader::new(frame.body_of(Direction::FromClient, Self::TAG)?);
        let portal = reader.cstr()?;
        let max_rows = reader.i32()?;
        reader.finish()?;
        Ok(Self { portal, max_rows })
    }

    /// The name of the portal to run. Empty for the unnamed portal.
    #[must_use]
    pub const fn portal(&self) -> &'a [u8] {
        self.portal
    }

    /// The largest number of rows to return. Zero or less means no limit,
    /// as the server reads it.
    #[must_use]
    pub const fn max_rows(&self) -> i32 {
        self.max_rows
    }
}

impl fmt::Debug for Execute<'_> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Execute")
            .field("portal", &Redacted(self.portal))
            .field("max_rows", &self.max_rows)
            .finish()
    }
}

/// Any message from the client, parsed into the view this crate has for it.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Message<'a> {
    /// `Query`.
    Query(Query<'a>),
    /// `Parse`.
    Parse(Parse<'a>),
    /// `Bind`.
    Bind(Bind<'a>),
    /// `Describe`.
    Describe(Describe<'a>),
    /// `Execute`.
    Execute(Execute<'a>),
    /// `Close`.
    Close(Close<'a>),
    /// `CopyData`.
    CopyData(CopyData<'a>),
    /// A message this crate has no view for. Its body was not examined.
    Other(Frame<'a>),
}

impl<'a> Message<'a> {
    /// Reads a frame from the client as the view that matches its type
    /// byte. A type byte without a view gives [`Message::Other`].
    ///
    /// # Errors
    ///
    /// Fails when the frame was not sent by the client, or when the view
    /// for its type byte rejects the body.
    pub fn from_frame(frame: Frame<'a>) -> Result<Self, ParseError> {
        if frame.direction() != Direction::FromClient {
            return Err(frame.unexpected());
        }
        Ok(match frame.tag() {
            tag::QUERY => Self::Query(Query::from_frame(frame)?),
            tag::PARSE => Self::Parse(Parse::from_frame(frame)?),
            tag::BIND => Self::Bind(Bind::from_frame(frame)?),
            tag::DESCRIBE => Self::Describe(Describe::from_frame(frame)?),
            tag::EXECUTE => Self::Execute(Execute::from_frame(frame)?),
            tag::CLOSE => Self::Close(Close::from_frame(frame)?),
            tag::COPY_DATA => Self::CopyData(CopyData::from_frame(frame)?),
            _ => Self::Other(frame),
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::message::FormatCode;
    use crate::testutil::{frame, wire};

    fn client(bytes: &[u8]) -> Frame<'_> {
        frame(Direction::FromClient, bytes)
    }

    /// Asserts that `parse` rejects every proper prefix of `body`.
    fn assert_prefixes_fail(tag: u8, body: &[u8], parse: impl Fn(Frame<'_>) -> bool) {
        for cut in 0..body.len() {
            let bytes = wire(tag, &body[..cut]);
            assert!(
                !parse(client(&bytes)),
                "a body cut to {cut} of {} bytes must be rejected",
                body.len()
            );
        }
        let bytes = wire(tag, body);
        assert!(parse(client(&bytes)), "the whole body must be accepted");
    }

    #[test]
    fn query() {
        let body = b"select * from users\0";
        let bytes = wire(b'Q', body);
        let query = Query::from_frame(client(&bytes)).unwrap();
        assert_eq!(query.sql(), b"select * from users");
        assert_prefixes_fail(b'Q', body, |frame| Query::from_frame(frame).is_ok());

        let parse = |body: &[u8]| {
            let bytes = wire(b'Q', body);
            Query::from_frame(client(&bytes)).map(drop)
        };
        // The empty query string.
        assert_eq!(parse(b"\0"), Ok(()));
        assert_eq!(parse(b""), Err(ParseError::UnterminatedString));
        assert_eq!(parse(b"select 1"), Err(ParseError::UnterminatedString));
        // The server refuses anything after the terminator, so does the view.
        assert_eq!(
            parse(b"select 1\0select 2\0"),
            Err(ParseError::TrailingBytes)
        );
        assert_eq!(parse(b"select 1\0\0"), Err(ParseError::TrailingBytes));
    }

    #[test]
    fn parse_with_parameter_types() {
        let body = b"stmt1\0select $1, $2\0\0\x02\0\0\0\x17\0\0\0\0";
        let bytes = wire(b'P', body);
        let parse = Parse::from_frame(client(&bytes)).unwrap();
        assert_eq!(parse.statement(), b"stmt1");
        assert_eq!(parse.sql(), b"select $1, $2");
        let types = parse.parameter_types();
        assert_eq!(types.len(), 2);
        assert!(!types.is_empty());
        assert_eq!(types.get(0), Some(23));
        assert_eq!(types.get(1), Some(0));
        assert_eq!(types.get(2), None);
        assert_eq!(types.iter().collect::<Vec<_>>(), [23, 0]);
        assert_eq!(types.iter().len(), 2);
        assert_prefixes_fail(b'P', body, |frame| Parse::from_frame(frame).is_ok());
    }

    #[test]
    fn parse_edge_cases() {
        let parse = |body: &[u8]| {
            let bytes = wire(b'P', body);
            Parse::from_frame(client(&bytes)).map(drop)
        };
        // The unnamed statement, an empty query, no types.
        assert_eq!(parse(b"\0\0\0\0"), Ok(()));
        // A count the frame cannot hold fails before anything is read.
        assert_eq!(parse(b"\0\0\xff\xff"), Err(ParseError::CountExceedsFrame));
        assert_eq!(
            parse(b"\0\0\0\x02\0\0\0\x17"),
            Err(ParseError::CountExceedsFrame)
        );
        // Three of the four bytes of a type id.
        assert_eq!(
            parse(b"\0\0\0\x01\0\0\0"),
            Err(ParseError::CountExceedsFrame)
        );
        assert_eq!(
            parse(b"\0\0\0\x01\0\0\0\x17\0"),
            Err(ParseError::TrailingBytes)
        );
        assert_eq!(parse(b"s\0q"), Err(ParseError::UnterminatedString));
        assert_eq!(parse(b"s\0q\0"), Err(ParseError::Truncated));
        assert_eq!(parse(b"s\0q\0\0"), Err(ParseError::Truncated));
    }

    /// A `Bind` to the portal "p" of the statement "s": two parameter
    /// formats, the parameters "hi" and NULL, one result format.
    const BIND_BODY: &[u8] =
        b"p\0s\0\0\x02\0\0\0\x01\0\x02\0\0\0\x02hi\xff\xff\xff\xff\0\x01\0\x01";

    #[test]
    fn bind_fields() {
        let bytes = wire(b'B', BIND_BODY);
        let bind = Bind::from_frame(client(&bytes)).unwrap();
        assert_eq!(bind.portal(), b"p");
        assert_eq!(bind.statement(), b"s");
        assert_eq!(
            bind.parameter_formats().iter().collect::<Vec<_>>(),
            [FormatCode::TEXT, FormatCode::BINARY]
        );
        assert_eq!(
            bind.parameters().iter().collect::<Vec<_>>(),
            [Some(&b"hi"[..]), None]
        );
        assert_eq!(
            bind.result_formats().iter().collect::<Vec<_>>(),
            [FormatCode::BINARY]
        );
        assert_eq!(bind.result_formats().code_for(7), Some(FormatCode::BINARY));
        assert_prefixes_fail(b'B', BIND_BODY, |frame| Bind::from_frame(frame).is_ok());
    }

    #[test]
    fn bind_edge_cases() {
        let parse = |body: &[u8]| {
            let bytes = wire(b'B', body);
            Bind::from_frame(client(&bytes)).map(drop)
        };
        // Unnamed portal and statement, nothing else.
        assert_eq!(parse(b"\0\0\0\0\0\0\0\0"), Ok(()));
        assert_eq!(parse(b"\0\0\0\0\0\0\0\0\0"), Err(ParseError::TrailingBytes));
        // Each of the three counts is checked against the frame.
        assert_eq!(
            parse(b"\0\0\xff\xff\0\0\0\0"),
            Err(ParseError::CountExceedsFrame)
        );
        assert_eq!(
            parse(b"\0\0\0\0\xff\xff\0\0"),
            Err(ParseError::CountExceedsFrame)
        );
        assert_eq!(
            parse(b"\0\0\0\0\0\0\xff\xff"),
            Err(ParseError::CountExceedsFrame)
        );
        // A parameter that runs past the frame, and a negative length.
        assert_eq!(
            parse(b"\0\0\0\0\0\x01\0\0\0\x09ab\0\0"),
            Err(ParseError::Truncated)
        );
        assert_eq!(
            parse(b"\0\0\0\0\0\x01\xff\xff\xff\xf0\0\0"),
            Err(ParseError::NegativeLength)
        );
        // The number of formats need not match the number of parameters:
        // that rule is the server's to enforce, and it answers with an error.
        assert_eq!(parse(b"\0\0\0\x02\0\0\0\x01\0\x01\0\0\0\x01x\0\0"), Ok(()));
    }

    #[test]
    fn describe_and_close() {
        for (body, target, name) in [
            (&b"Sstmt\0"[..], Target::Statement, &b"stmt"[..]),
            (b"Pportal\0", Target::Portal, b"portal"),
            (b"S\0", Target::Statement, b""),
            (b"P\0", Target::Portal, b""),
        ] {
            let bytes = wire(b'D', body);
            let describe = Describe::from_frame(client(&bytes)).unwrap();
            assert_eq!((describe.target(), describe.name()), (target, name));
            assert_prefixes_fail(b'D', body, |frame| Describe::from_frame(frame).is_ok());

            let bytes = wire(b'C', body);
            let close = Close::from_frame(client(&bytes)).unwrap();
            assert_eq!((close.target(), close.name()), (target, name));
            assert_prefixes_fail(b'C', body, |frame| Close::from_frame(frame).is_ok());
        }

        for tag in *b"DC" {
            let parse = |body: &[u8]| {
                let bytes = wire(tag, body);
                if tag == b'D' {
                    Describe::from_frame(client(&bytes)).map(drop)
                } else {
                    Close::from_frame(client(&bytes)).map(drop)
                }
            };
            // The server answers other target bytes with an error.
            assert_eq!(parse(b"Xname\0"), Err(ParseError::InvalidValue));
            assert_eq!(parse(b"sname\0"), Err(ParseError::InvalidValue));
            assert_eq!(parse(b"\0\0"), Err(ParseError::InvalidValue));
            assert_eq!(parse(b""), Err(ParseError::Truncated));
            assert_eq!(parse(b"S"), Err(ParseError::UnterminatedString));
            assert_eq!(parse(b"Sname\0x"), Err(ParseError::TrailingBytes));
        }
        assert_eq!(
            Target::from_byte(Target::Statement.to_byte()),
            Some(Target::Statement)
        );
        assert_eq!(
            Target::from_byte(Target::Portal.to_byte()),
            Some(Target::Portal)
        );
    }

    #[test]
    fn execute() {
        let body = b"portal\0\0\0\0\x64";
        let bytes = wire(b'E', body);
        let execute = Execute::from_frame(client(&bytes)).unwrap();
        assert_eq!(execute.portal(), b"portal");
        assert_eq!(execute.max_rows(), 100);
        assert_prefixes_fail(b'E', body, |frame| Execute::from_frame(frame).is_ok());

        let bytes = wire(b'E', b"\0\0\0\0\0");
        let execute = Execute::from_frame(client(&bytes)).unwrap();
        assert_eq!((execute.portal(), execute.max_rows()), (&b""[..], 0));
        let bytes = wire(b'E', b"\0\xff\xff\xff\xff");
        assert_eq!(Execute::from_frame(client(&bytes)).unwrap().max_rows(), -1);
        let bytes = wire(b'E', b"\0\0\0\0\0\0");
        assert_eq!(
            Execute::from_frame(client(&bytes)),
            Err(ParseError::TrailingBytes)
        );
    }

    #[test]
    fn views_check_direction_and_type() {
        // `D` from the server is DataRow, not Describe.
        let bytes = wire(b'D', b"Sstmt\0");
        let from_server = frame(Direction::FromServer, &bytes);
        let unexpected = Err(ParseError::UnexpectedMessage {
            direction: Direction::FromServer,
            tag: b'D',
        });
        assert_eq!(Describe::from_frame(from_server).map(drop), unexpected);
        assert_eq!(Message::from_frame(from_server).map(drop), unexpected);

        let from_client = client(&bytes);
        let unexpected = Err(ParseError::UnexpectedMessage {
            direction: Direction::FromClient,
            tag: b'D',
        });
        assert_eq!(Query::from_frame(from_client).map(drop), unexpected);
        assert_eq!(Parse::from_frame(from_client).map(drop), unexpected);
        assert_eq!(Bind::from_frame(from_client).map(drop), unexpected);
        assert_eq!(Execute::from_frame(from_client).map(drop), unexpected);
        assert_eq!(Close::from_frame(from_client).map(drop), unexpected);
    }

    #[test]
    fn message_dispatches_on_the_type_byte() {
        let cases: [(u8, &[u8]); 7] = [
            (b'Q', b"select 1\0"),
            (b'P', b"\0\0\0\0"),
            (b'B', b"\0\0\0\0\0\0\0\0"),
            (b'D', b"S\0"),
            (b'E', b"\0\0\0\0\0"),
            (b'C', b"P\0"),
            (b'd', b"1\talice\n"),
        ];
        for (tag, body) in cases {
            let bytes = wire(tag, body);
            let message = Message::from_frame(client(&bytes)).unwrap();
            let matches = matches!(
                (tag, message),
                (b'Q', Message::Query(_))
                    | (b'P', Message::Parse(_))
                    | (b'B', Message::Bind(_))
                    | (b'D', Message::Describe(_))
                    | (b'E', Message::Execute(_))
                    | (b'C', Message::Close(_))
                    | (b'd', Message::CopyData(_))
            );
            assert!(matches, "type {:?} gave {message:?}", char::from(tag));
        }

        // Messages without a view, and unknown type bytes, pass as frames.
        for tag in [b'S', b'H', b'X', b'c', b'f', b'F', b'p', b'?', 0, 0xff] {
            let bytes = wire(tag, b"anything");
            let Ok(Message::Other(other)) = Message::from_frame(client(&bytes)) else {
                panic!("type {tag:#04x} must be passed through");
            };
            assert_eq!(other.tag(), tag);
            assert_eq!(other.as_bytes(), bytes);
        }

        // A malformed body of a known type is an error, not `Other`.
        let bytes = wire(b'Q', b"no terminator");
        assert_eq!(
            Message::from_frame(client(&bytes)),
            Err(ParseError::UnterminatedString)
        );
    }

    #[test]
    fn debug_output_omits_content() {
        const MARKER: &str = "SECRETMARKER";
        let m = MARKER.as_bytes();
        let with = |prefix: &[u8], suffix: &[u8]| [prefix, m, suffix].concat();

        let bodies: Vec<(u8, Vec<u8>)> = vec![
            (b'Q', with(b"select '", b"'\0")),
            (b'P', with(b"", b"\0select 1\0\0\0")),
            (b'P', with(b"s\0select '", b"'\0\0\0")),
            (b'B', with(b"", b"\0s\0\0\0\0\0\0\0")),
            (b'B', with(b"p\0", b"\0\0\0\0\0\0\0")),
            (b'B', with(b"p\0s\0\0\0\0\x01\0\0\0\x0c", b"\0\0")),
            (b'D', with(b"S", b"\0")),
            (b'C', with(b"P", b"\0")),
            (b'E', with(b"", b"\0\0\0\0\0")),
            (b'd', with(b"1\t", b"\n")),
            (b'p', with(b"", b"\0")),
        ];
        for (tag, body) in bodies {
            let bytes = wire(tag, &body);
            let message = Message::from_frame(client(&bytes)).unwrap();
            let text = format!("{message:?}");
            assert!(!text.contains(MARKER), "{text}");
            assert!(!text.contains("83, 69, 67"), "{text}");
        }
    }
}
