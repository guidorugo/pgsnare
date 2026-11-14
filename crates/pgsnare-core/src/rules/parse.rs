// SPDX-License-Identifier: Apache-2.0

//! The one place that calls the SQL parser.
//!
//! The parser returns the statement as a tree. The tree is walked once, in
//! full, and what the rules need is noted on the way. The walk does not
//! know the kinds of node by a list of its own: it asks every node to
//! describe itself, through the description the parser's library generates
//! for all of them, so a kind of node that is added later is walked like
//! the others. A relation or a function cannot hide in a corner of the
//! grammar that somebody forgot.
//!
//! The library also offers a cheaper summary of a statement. It is not
//! used: it was seen to miss the functions and relations in `RETURNING`, in
//! the arguments of `EXECUTE`, in `DECLARE ... CURSOR FOR`, in the source
//! of `MERGE` and in the expressions of `ALTER TABLE`.

use core::fmt;

use serde::ser::{self, Serialize};

use super::analysis::{Analysis, RelationUse, StatementFlags};
use super::precheck::{
    Limits, MAX_NORMALISE_INPUT_BYTES, MAX_NORMALISED_BYTES, ParseFailure, precheck,
};
use super::thread::ParserThread;

/// Reads a statement and returns what the rules need to know about it.
///
/// The text is what the database will parse: for a `Query` message, the
/// bytes up to its first NUL. It is checked by [`precheck`] first, and the
/// parser only runs when that passes.
///
/// The caller must be a parser thread, which the last argument proves. The
/// call takes time and memory in proportion to the statement, see the
/// module documentation, so it belongs on no thread that relays traffic.
///
/// An analysis that [is not complete](Analysis::is_complete) is returned
/// as it is; the caller decides what that means.
///
/// # Errors
///
/// Returns why the statement has no analysis. The parser's message is
/// never part of it.
pub fn analyse(
    text: &[u8],
    limits: &Limits,
    _thread: &ParserThread,
) -> Result<Analysis, ParseFailure> {
    let text = precheck(text, limits)?;
    let parsed = pg_query::parse(text, 0).map_err(|error| failure(&error))?;
    let mut walker = Walker::default();
    parsed
        .protobuf
        .serialize(&mut walker)
        .map_err(|_| ParseFailure::Unreadable)?;
    drop(parsed);

    let mut analysis = walker.analysis;
    if limits.normalise {
        let normalised = if text.len() <= MAX_NORMALISE_INPUT_BYTES {
            pg_query::normalize(text)
                .ok()
                .filter(|normalised| normalised.len() <= MAX_NORMALISED_BYTES)
                .map(String::into_boxed_str)
        } else {
            None
        };
        let fingerprint = pg_query::fingerprint(text, 0, 0)
            .ok()
            .map(|fingerprint| fingerprint.value);
        analysis.set_normalised(normalised, fingerprint);
    }
    analysis.shrink();
    Ok(analysis)
}

/// The reason behind an error of the parser's library. The message of a
/// parse error quotes the statement, so it is looked at here and goes no
/// further.
fn failure(error: &pg_query::Error) -> ParseFailure {
    const TOO_DEEP: [&str; 3] = [
        "stack depth limit exceeded",
        "memory exhausted",
        "parse tree is nested too deeply",
    ];
    match error {
        pg_query::Error::Conversion(_) => ParseFailure::EmbeddedNul,
        pg_query::Error::Parse(message) => {
            if TOO_DEEP.iter().any(|start| message.starts_with(start)) {
                ParseFailure::TooDeep
            } else {
                ParseFailure::Rejected
            }
        }
        pg_query::Error::Decode(inner) => {
            if inner.to_string().contains("recursion limit reached") {
                ParseFailure::TooDeep
            } else {
                ParseFailure::Unreadable
            }
        }
        _ => ParseFailure::Unreadable,
    }
}

/// One node of the tree that the walk is inside of.
#[derive(Default)]
struct Frame {
    /// The kind of node.
    name: &'static str,
    /// The field of the node the walk is in.
    field: &'static str,
    /// A `RangeVar`: its schema. A `String`: its value.
    first: String,
    /// A `RangeVar`: its name.
    second: String,
    /// The last two parts of a name that is a list of strings, such as the
    /// name of a called function.
    qualifier: Option<String>,
    last_part: Option<String>,
    /// Relations this statement reads, with whether something has narrowed
    /// the rows down so far.
    reads: Vec<(usize, bool)>,
    /// The relations this statement is aimed at.
    targets: Vec<usize>,
    has_where: bool,
    has_limit: bool,
    limit_is_null: bool,
    has_returning: bool,
    is_null: bool,
    is_from: bool,
    is_program: bool,
    has_filename: bool,
}

impl Frame {
    fn is(&self, name: &str, field: &str) -> bool {
        self.name == name && self.field == field
    }
}

/// Walks the tree and fills in an [`Analysis`].
#[derive(Default)]
struct Walker {
    frames: Vec<Frame>,
    analysis: Analysis,
}

/// Nodes that sit between a relation and the statement that reads it.
const BETWEEN_RELATION_AND_STATEMENT: [&str; 3] = ["Node", "JoinExpr", "RangeTableSample"];

/// Nodes that sit between a query and the query that reads from it.
const BETWEEN_QUERIES: [&str; 3] = ["Node", "RangeSubselect", "JoinExpr"];

impl Walker {
    /// The innermost node the walk is in.
    fn top(&mut self) -> Option<&mut Frame> {
        self.frames.last_mut()
    }

    /// The nearest node around the current one that is not one of `skip`.
    fn around(&mut self, skip: &[&str]) -> Option<&mut Frame> {
        self.frames
            .iter_mut()
            .rev()
            .find(|frame| !skip.contains(&frame.name))
    }

    fn enter(&mut self, name: &'static str) {
        match name {
            "DoStmt" | "CreateFunctionStmt" => {
                self.analysis.add_flags(StatementFlags::OPAQUE_BODY);
            }
            "ExecuteStmt" | "FetchStmt" => self.analysis.add_flags(StatementFlags::RUNS_STORED),
            _ => {}
        }
        self.frames.push(Frame {
            name,
            ..Frame::default()
        });
    }

    fn boolean(&mut self, value: bool) {
        let Some(top) = self.top() else { return };
        match (top.name, top.field) {
            ("AConst", "isnull") => top.is_null = value,
            ("CopyStmt", "is_from") => top.is_from = value,
            ("CopyStmt", "is_program") => top.is_program = value,
            _ => {}
        }
    }

    fn text(&mut self, value: &str) {
        let Some(top) = self.top() else { return };
        match (top.name, top.field) {
            ("String", "sval") | ("RangeVar", "schemaname") => value.clone_into(&mut top.first),
            ("RangeVar", "relname") => value.clone_into(&mut top.second),
            ("CopyStmt", "filename") => top.has_filename = !value.is_empty(),
            _ => {}
        }
    }

    /// A field that may be absent is present.
    fn present(&mut self) {
        let Some(top) = self.top() else { return };
        match top.field {
            "where_clause" => top.has_where = true,
            "limit_count" => top.has_limit = true,
            "returning_clause" => top.has_returning = true,
            _ => {}
        }
    }

    /// The walk enters one of the alternatives of a node.
    fn variant(&mut self, variant: &'static str) {
        let mut around = self.frames.iter().rev();
        if around.next().is_some_and(|node| node.is("Node", "node"))
            && around.next().is_some_and(|raw| raw.is("RawStmt", "stmt"))
        {
            self.analysis.add_statement(variant);
        }
    }

    fn leave(&mut self) {
        let Some(frame) = self.frames.pop() else {
            return;
        };
        if let Some(name) = &frame.last_part {
            self.analysis
                .add_function(frame.qualifier.as_deref().unwrap_or_default(), name);
        }
        match frame.name {
            "String" => self.leave_string(frame),
            "AConst" => {
                // `LIMIT ALL` and `LIMIT NULL` are a null constant.
                let mut around = self.frames.iter_mut().rev();
                if frame.is_null
                    && around.next().is_some_and(|node| node.name == "Node")
                    && let Some(select) = around.next()
                    && select.is("SelectStmt", "limit_count")
                {
                    select.limit_is_null = true;
                }
            }
            "RangeVar" => self.leave_relation(&frame),
            "SelectStmt" => self.leave_select(frame),
            "CopyStmt" => {
                let mut flags = if frame.is_from {
                    StatementFlags::COPY_FROM
                } else {
                    StatementFlags::COPY_TO
                };
                if frame.is_program {
                    flags = flags.union(StatementFlags::COPY_PROGRAM);
                } else if frame.has_filename {
                    flags = flags.union(StatementFlags::COPY_FILE);
                }
                self.analysis.add_flags(flags);
                // `COPY table TO` has no way to narrow the rows down.
                let usage = if frame.is_from {
                    RelationUse::WRITTEN
                } else {
                    RelationUse::UNBOUNDED_READ
                };
                for index in frame.targets {
                    self.analysis.use_relation(index, usage);
                }
            }
            "InsertStmt" => {
                for index in frame.targets {
                    self.analysis.use_relation(index, RelationUse::WRITTEN);
                }
            }
            "UpdateStmt" | "DeleteStmt" | "MergeStmt" => {
                // Without RETURNING no row reaches the client. With it and
                // without WHERE, every row does.
                let returned = match (frame.has_returning, frame.has_where) {
                    (false, _) => RelationUse::NAMED,
                    (true, true) => RelationUse::READ,
                    (true, false) => RelationUse::UNBOUNDED_READ,
                };
                for index in frame.targets {
                    self.analysis
                        .use_relation(index, RelationUse::WRITTEN.union(returned));
                }
                for (index, _) in frame.reads {
                    self.analysis
                        .use_relation(index, RelationUse::READ.union(returned));
                }
            }
            _ => {}
        }
    }

    /// A string that is one part of a name goes to the node that holds the
    /// name: `holder { funcname: [Node { String }, ...] }`.
    fn leave_string(&mut self, frame: Frame) {
        let mut around = self.frames.iter_mut().rev();
        if around.next().is_none_or(|node| node.name != "Node") {
            return;
        }
        let Some(holder) = around.next() else { return };
        if matches!(holder.field, "funcname" | "func_name")
            || holder.is("ObjectWithArgs", "objname")
        {
            holder.qualifier = holder.last_part.take();
            holder.last_part = Some(frame.first);
        }
    }

    fn leave_relation(&mut self, frame: &Frame) {
        let Some(index) = self.analysis.add_relation(&frame.first, &frame.second) else {
            return;
        };
        let Some(owner) = self.around(&BETWEEN_RELATION_AND_STATEMENT) else {
            return;
        };
        match (owner.name, owner.field) {
            ("SelectStmt" | "UpdateStmt", "from_clause")
            | ("DeleteStmt", "using_clause")
            | ("MergeStmt", "source_relation") => owner.reads.push((index, false)),
            ("CopyStmt" | "InsertStmt" | "UpdateStmt" | "DeleteStmt" | "MergeStmt", "relation") => {
                owner.targets.push(index)
            }
            ("IntoClause", "rel") => self.analysis.use_relation(index, RelationUse::WRITTEN),
            _ => {}
        }
    }

    /// A query ends. What it reads is settled here, unless another query
    /// reads from this one: then that one's `WHERE` and `LIMIT` count too.
    fn leave_select(&mut self, frame: Frame) {
        let narrowed = frame.has_where || (frame.has_limit && !frame.limit_is_null);
        let outer = self.around(&BETWEEN_QUERIES).filter(|outer| {
            outer.name == "SelectStmt" && matches!(outer.field, "from_clause" | "larg" | "rarg")
        });
        if let Some(outer) = outer {
            outer.reads.extend(
                frame
                    .reads
                    .into_iter()
                    .map(|(index, bounded)| (index, bounded || narrowed)),
            );
            return;
        }
        for (index, bounded) in frame.reads {
            let usage = if bounded || narrowed {
                RelationUse::READ
            } else {
                RelationUse::UNBOUNDED_READ
            };
            self.analysis.use_relation(index, usage);
        }
    }
}

/// The walk never fails on its own. This is what a node could report, and
/// its message is dropped.
#[derive(Debug)]
struct Stop;

impl fmt::Display for Stop {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("the walk of a statement stopped")
    }
}

impl core::error::Error for Stop {}

impl ser::Error for Stop {
    fn custom<T: fmt::Display>(_: T) -> Self {
        Self
    }
}

macro_rules! ignore {
    ($($method:ident: $type:ty),* $(,)?) => {
        $(fn $method(self, _: $type) -> Result<(), Stop> {
            Ok(())
        })*
    };
}

impl ser::Serializer for &mut Walker {
    type Ok = ();
    type Error = Stop;
    type SerializeSeq = Self;
    type SerializeTuple = Self;
    type SerializeTupleStruct = Self;
    type SerializeTupleVariant = Self;
    type SerializeMap = Self;
    type SerializeStruct = Self;
    type SerializeStructVariant = Self;

    ignore! {
        serialize_i8: i8, serialize_i16: i16, serialize_i32: i32, serialize_i64: i64,
        serialize_u8: u8, serialize_u16: u16, serialize_u32: u32, serialize_u64: u64,
        serialize_f32: f32, serialize_f64: f64, serialize_char: char,
        serialize_bytes: &[u8], serialize_unit_struct: &'static str,
    }

    fn serialize_bool(self, value: bool) -> Result<(), Stop> {
        self.boolean(value);
        Ok(())
    }

    fn serialize_str(self, value: &str) -> Result<(), Stop> {
        self.text(value);
        Ok(())
    }

    fn serialize_none(self) -> Result<(), Stop> {
        Ok(())
    }

    fn serialize_some<T: ?Sized + Serialize>(self, value: &T) -> Result<(), Stop> {
        self.present();
        value.serialize(self)
    }

    fn serialize_unit(self) -> Result<(), Stop> {
        Ok(())
    }

    fn serialize_unit_variant(self, _: &'static str, _: u32, _: &'static str) -> Result<(), Stop> {
        Ok(())
    }

    fn serialize_newtype_struct<T: ?Sized + Serialize>(
        self,
        _: &'static str,
        value: &T,
    ) -> Result<(), Stop> {
        value.serialize(self)
    }

    fn serialize_newtype_variant<T: ?Sized + Serialize>(
        self,
        _: &'static str,
        _: u32,
        variant: &'static str,
        value: &T,
    ) -> Result<(), Stop> {
        self.variant(variant);
        value.serialize(self)
    }

    fn serialize_seq(self, _: Option<usize>) -> Result<Self, Stop> {
        Ok(self)
    }

    fn serialize_tuple(self, _: usize) -> Result<Self, Stop> {
        Ok(self)
    }

    fn serialize_tuple_struct(self, _: &'static str, _: usize) -> Result<Self, Stop> {
        Ok(self)
    }

    fn serialize_tuple_variant(
        self,
        _: &'static str,
        _: u32,
        _: &'static str,
        _: usize,
    ) -> Result<Self, Stop> {
        Ok(self)
    }

    fn serialize_map(self, _: Option<usize>) -> Result<Self, Stop> {
        Ok(self)
    }

    fn serialize_struct(self, name: &'static str, _: usize) -> Result<Self, Stop> {
        self.enter(name);
        Ok(self)
    }

    fn serialize_struct_variant(
        self,
        _: &'static str,
        _: u32,
        variant: &'static str,
        _: usize,
    ) -> Result<Self, Stop> {
        self.enter(variant);
        Ok(self)
    }
}

macro_rules! walk_elements {
    ($($trait:ident: $method:ident),* $(,)?) => {
        $(impl ser::$trait for &mut Walker {
            type Ok = ();
            type Error = Stop;

            fn $method<T: ?Sized + Serialize>(&mut self, value: &T) -> Result<(), Stop> {
                value.serialize(&mut **self)
            }

            fn end(self) -> Result<(), Stop> {
                Ok(())
            }
        })*
    };
}

walk_elements! {
    SerializeSeq: serialize_element,
    SerializeTuple: serialize_element,
    SerializeTupleStruct: serialize_field,
    SerializeTupleVariant: serialize_field,
}

impl ser::SerializeMap for &mut Walker {
    type Ok = ();
    type Error = Stop;

    fn serialize_key<T: ?Sized + Serialize>(&mut self, _: &T) -> Result<(), Stop> {
        Ok(())
    }

    fn serialize_value<T: ?Sized + Serialize>(&mut self, value: &T) -> Result<(), Stop> {
        value.serialize(&mut **self)
    }

    fn end(self) -> Result<(), Stop> {
        Ok(())
    }
}

macro_rules! walk_fields {
    ($($trait:ident),* $(,)?) => {
        $(impl ser::$trait for &mut Walker {
            type Ok = ();
            type Error = Stop;

            fn serialize_field<T: ?Sized + Serialize>(
                &mut self,
                key: &'static str,
                value: &T,
            ) -> Result<(), Stop> {
                if let Some(top) = self.top() {
                    top.field = key;
                }
                value.serialize(&mut **self)
            }

            fn end(self) -> Result<(), Stop> {
                self.leave();
                Ok(())
            }
        })*
    };
}

walk_fields! { SerializeStruct, SerializeStructVariant }
