// SPDX-License-Identifier: Apache-2.0

//! Optional SQL rules. Compiled only with the `rules` feature.
//!
//! A rule looks at what a statement is, not at its bytes: comments, case,
//! quoting and escapes all change the bytes of a statement without changing
//! what the database runs. So a statement is first read by PostgreSQL's own
//! parser, through the `pg_query` library, and the rules judge the result.
//!
//! # The parts
//!
//! - [`analyse`] reads one statement and returns an [`Analysis`]: the kinds
//!   of statement, the relations and functions it names, and a few flags.
//!   It is the only code that calls the parser.
//! - [`precheck`] is what `analyse` does before the parser runs: a size cap,
//!   valid UTF-8, no NUL byte, and a cap on nesting.
//! - [`RuleSet`] is the rules of one policy, compiled once from
//!   configuration. [`RuleSet::evaluate`] is a pure function from an
//!   analysis, a listener and a database user to the rules that fire.
//!
//! # The parser is C code that reads attacker input
//!
//! It is kept apart from everything else:
//!
//! - It is only built with this feature.
//! - It only runs on a thread started by [`spawn_parser_thread`] or
//!   [`on_parser_thread`], which have a stack of [`PARSER_STACK_BYTES`].
//!   `analyse` asks for a [`ParserThread`], which only those two hand out
//!   and which cannot leave its thread. The parser measures the stack it
//!   runs on and refuses a statement that would exhaust it; decoding its
//!   result is recursive too, and bounded by the decoder's own limit.
//! - Nothing here is called by the session logic or on a thread that relays
//!   traffic. The runtime owns the threads and their queue.
//! - A failure is a [`ParseFailure`], a fixed reason. The parser's message
//!   quotes the statement, so it is read to tell the reasons apart and then
//!   dropped.
//!
//! # What an analysis costs
//!
//! Measured once with an optimised build, on statements built to be
//! expensive: reading a statement takes up to about 1,500 times its size in
//! memory while the call runs (1.5 GiB for 1 MiB of function calls, 94 MiB
//! for 64 KiB) and up to about 1.7 s per MiB. The normalised text costs up
//! to about 3,800 times the size, which is why it is only made for a
//! statement of at most [`MAX_NORMALISE_INPUT_BYTES`]. Peak memory is
//! therefore about the number of parser threads times
//! [`Limits::max_bytes`] times 1,500.
//!
//! # What the parser cannot see
//!
//! - Code inside a string: the body of `DO`, of a function written as a
//!   string, and any statement a function builds and runs. Such statements
//!   are marked with [`StatementFlags::OPAQUE_BODY`].
//! - What an SQL-level `EXECUTE` or `FETCH` will run. The statement is
//!   judged where it is written, at `PREPARE` or `DECLARE`. These are
//!   marked with [`StatementFlags::RUNS_STORED`].
//! - Which relation a name finally refers to. The search path is unknown,
//!   so a name without a schema is taken to be any relation of that name,
//!   and a name that a `WITH` clause defines is taken to be a table too.
//!   Both err on the side of a rule firing.

mod analysis;
mod name;
mod parse;
mod precheck;
mod ruleset;
mod thread;

#[cfg(test)]
mod tests;

pub use analysis::{
    Analysis, Function, MAX_FUNCTIONS, MAX_KINDS, MAX_RELATIONS, Relation, RelationUse,
    StatementFlags,
};
pub use name::{InvalidName, MAX_IDENTIFIER_BYTES, QualifiedName};
pub use parse::analyse;
pub use precheck::{
    DEFAULT_MAX_DEPTH, DEFAULT_MAX_PARSE_BYTES, Limits, MAX_NORMALISE_INPUT_BYTES,
    MAX_NORMALISED_BYTES, ParseFailure, precheck,
};
pub use ruleset::{
    CATALOG_ENUMERATION, FUNCTIONS, OnParseFailure, ROW_THRESHOLD, RowThreshold, RuleScope,
    RuleSet, RuleSetBuilder, RuleSetError, Subject, UNBOUNDED_READ,
};
pub use thread::{PARSER_STACK_BYTES, ParserThread, on_parser_thread, spawn_parser_thread};
