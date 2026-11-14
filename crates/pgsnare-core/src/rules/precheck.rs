// SPDX-License-Identifier: Apache-2.0

//! The limits of an analysis, the reasons it can fail, and the checks that
//! run before the parser does.

use core::fmt;

/// The default for [`Limits::max_bytes`]: 64 KiB.
pub const DEFAULT_MAX_PARSE_BYTES: usize = 64 * 1024;

/// The default for [`Limits::max_depth`].
pub const DEFAULT_MAX_DEPTH: u32 = 256;

/// The longest statement a normalised text is made for: 16 KiB. Making it
/// is the most expensive thing the parser does, see the module
/// documentation.
pub const MAX_NORMALISE_INPUT_BYTES: usize = 16 * 1024;

/// The longest normalised text an analysis keeps: as much as an event shows
/// of a statement. A longer one is not kept at all, because a text that was
/// cut could end inside a value.
pub const MAX_NORMALISED_BYTES: usize = crate::event::MAX_STATEMENT_BYTES;

/// How much work one analysis may be.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
#[non_exhaustive]
pub struct Limits {
    /// A longer statement is not parsed.
    pub max_bytes: usize,
    /// A statement that nests brackets, or stacks operators in front of one
    /// operand, deeper than this is not parsed.
    pub max_depth: u32,
    /// Also make the normalised text and the fingerprint, which an event
    /// shows in place of the statement.
    pub normalise: bool,
}

impl Limits {
    /// The default limits with another size cap.
    #[must_use]
    pub const fn with_max_bytes(max_bytes: usize) -> Self {
        Self {
            max_bytes,
            max_depth: DEFAULT_MAX_DEPTH,
            normalise: false,
        }
    }

    /// These limits, with the normalised text asked for or not.
    #[must_use]
    pub const fn normalised(mut self, normalise: bool) -> Self {
        self.normalise = normalise;
        self
    }

    /// These limits with another cap on nesting.
    #[must_use]
    pub const fn with_max_depth(mut self, max_depth: u32) -> Self {
        self.max_depth = max_depth;
        self
    }
}

impl Default for Limits {
    fn default() -> Self {
        Self::with_max_bytes(DEFAULT_MAX_PARSE_BYTES)
    }
}

/// Why there is no analysis of a statement.
///
/// A fixed reason and nothing else: the parser's own message quotes the
/// statement and is never kept.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
#[non_exhaustive]
pub enum ParseFailure {
    /// The statement is longer than the size cap.
    TooLarge,
    /// The statement is not valid UTF-8.
    InvalidUtf8,
    /// The statement holds a NUL byte, where the database would stop
    /// reading.
    EmbeddedNul,
    /// The statement nests deeper than the cap, or deeper than the parser
    /// or the decoder of its result can follow.
    TooDeep,
    /// The parser rejected the statement: it is not valid SQL.
    Rejected,
    /// The parser read the statement and its result could not be used, or
    /// the message that carries the statement is malformed.
    Unreadable,
    /// The statement names more relations, functions or kinds of statement
    /// than an analysis holds.
    Incomplete,
    /// Every parser thread was busy and their queue was full.
    Busy,
    /// The parser thread panicked on this statement.
    Panicked,
    /// The message that carries the statement arrived in parts, because it
    /// is larger than a session holds.
    Streamed,
    /// The database reads the statement in a way the parser does not: the
    /// session's `client_encoding` is not `UTF8`, or was never reported,
    /// or `standard_conforming_strings` is off.
    Encoding,
    /// No answer came from the parser threads in the time allowed.
    TimedOut,
    /// The statement carries code as a string, which the parser does not
    /// read: `DO`, and `CREATE FUNCTION` or `CREATE PROCEDURE`.
    OpaqueBody,
    /// A `FunctionCall` message: it names the function by a number, which
    /// no rule can tie to a name.
    FunctionCall,
}

impl ParseFailure {
    /// A fixed name, fit for a log line or a label.
    #[must_use]
    pub const fn name(self) -> &'static str {
        match self {
            Self::TooLarge => "too_large",
            Self::InvalidUtf8 => "invalid_utf8",
            Self::EmbeddedNul => "embedded_nul",
            Self::TooDeep => "too_deep",
            Self::Rejected => "rejected",
            Self::Unreadable => "unreadable",
            Self::Incomplete => "incomplete",
            Self::Busy => "busy",
            Self::Panicked => "panicked",
            Self::Streamed => "streamed",
            Self::Encoding => "encoding",
            Self::TimedOut => "timed_out",
            Self::OpaqueBody => "opaque_body",
            Self::FunctionCall => "function_call",
        }
    }
}

impl fmt::Display for ParseFailure {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.name())
    }
}

impl core::error::Error for ParseFailure {}

/// Checks a statement before the parser sees it, and returns it as text.
///
/// In this order: the size cap, valid UTF-8, no NUL byte, and the cap on
/// nesting. The last one follows PostgreSQL's rules for strings, quoted
/// names and comments, with `standard_conforming_strings` on, so that a
/// bracket inside one of those does not count. It looks for two things: how
/// deep `(` and `[` nest, and how many operator characters and `NOT`s stand
/// in a row, since each is one more level in `- - - 1` or `NOT NOT true`.
///
/// This is a first line of defence and not the only one. Nesting has other
/// forms, such as a long chain of `UNION`, and the parser checks its own
/// stack for those.
///
/// # Errors
///
/// Returns the first check that fails.
pub fn precheck<'a>(text: &'a [u8], limits: &Limits) -> Result<&'a str, ParseFailure> {
    if text.len() > limits.max_bytes {
        return Err(ParseFailure::TooLarge);
    }
    let text = core::str::from_utf8(text).map_err(|_| ParseFailure::InvalidUtf8)?;
    if text.as_bytes().contains(&0) {
        return Err(ParseFailure::EmbeddedNul);
    }
    if nesting(text.as_bytes()) > limits.max_depth {
        return Err(ParseFailure::TooDeep);
    }
    Ok(text)
}

/// Where the scan of a statement is.
enum Lex {
    /// Between tokens, or in a word, a number or an operator.
    Code,
    /// In `'...'`. With `escapes`, a backslash takes the next byte with it.
    Single { escapes: bool },
    /// In `"..."`.
    Double,
    /// In `$tag$...$tag$`. The tag is `text[start..end]`, without the `$`.
    Dollar { start: usize, end: usize },
    /// In `-- ...`.
    Line,
    /// In `/* ... */`, which nests.
    Block { depth: u32 },
}

const fn is_word(byte: u8) -> bool {
    byte.is_ascii_alphanumeric() || byte == b'_' || byte == b'$' || byte >= 0x80
}

const fn is_operator(byte: u8) -> bool {
    matches!(
        byte,
        b'+' | b'-'
            | b'*'
            | b'/'
            | b'<'
            | b'>'
            | b'='
            | b'~'
            | b'!'
            | b'@'
            | b'#'
            | b'%'
            | b'^'
            | b'&'
            | b'|'
            | b'`'
            | b'?'
    )
}

/// The deepest nesting the scan finds: of brackets, or of operators and
/// `NOT`s in a row, whichever is more. It never fails and never looks at a
/// byte twice, apart from the tag of a dollar quote.
fn nesting(text: &[u8]) -> u32 {
    let mut state = Lex::Code;
    let mut depth: u32 = 0;
    let mut run: u32 = 0;
    let mut deepest: u32 = 0;
    // Whether a word is running, where it began, and whether it is a name
    // (it began with a letter) or a number. A `$` belongs to a name and
    // ends a number: `a$b$` is one name, `1$b$` is a number and the start
    // of a dollar quote.
    let mut in_word = false;
    let mut word_is_name = false;
    let mut word_start = 0_usize;
    let mut at = 0_usize;

    while let Some(&byte) = text.get(at) {
        let next = text.get(at.saturating_add(1)).copied();
        let mut step = 1_usize;
        match state {
            Lex::Code => {
                let continues = if byte == b'$' {
                    in_word && word_is_name
                } else {
                    is_word(byte)
                };
                if continues {
                    if !in_word {
                        in_word = true;
                        word_is_name = !byte.is_ascii_digit();
                        word_start = at;
                    }
                    at = at.saturating_add(1);
                    continue;
                }
                if in_word {
                    // A word just ended.
                    in_word = false;
                    let word = text.get(word_start..at).unwrap_or_default();
                    if word.eq_ignore_ascii_case(b"not") {
                        run = run.saturating_add(1);
                        deepest = deepest.max(run);
                    } else {
                        run = 0;
                    }
                    if byte == b'\'' {
                        // `E'...'` is the one string with backslash escapes.
                        state = Lex::Single {
                            escapes: word.eq_ignore_ascii_case(b"e"),
                        };
                        at = at.saturating_add(1);
                        continue;
                    }
                }
                match byte {
                    b'\'' => {
                        run = 0;
                        state = Lex::Single { escapes: false };
                    }
                    b'"' => {
                        run = 0;
                        state = Lex::Double;
                    }
                    b'-' if next == Some(b'-') => {
                        state = Lex::Line;
                        step = 2;
                    }
                    b'/' if next == Some(b'*') => {
                        state = Lex::Block { depth: 1 };
                        step = 2;
                    }
                    b'$' => {
                        // `$tag$` opens a dollar quote; `$1` is a parameter.
                        let tag_start = at.saturating_add(1);
                        let mut tag_end = tag_start;
                        while text.get(tag_end).is_some_and(|&b| is_word(b) && b != b'$') {
                            tag_end = tag_end.saturating_add(1);
                        }
                        let starts_with_digit = text.get(tag_start).is_some_and(u8::is_ascii_digit);
                        run = 0;
                        if text.get(tag_end) == Some(&b'$') && !starts_with_digit {
                            state = Lex::Dollar {
                                start: tag_start,
                                end: tag_end,
                            };
                            step = tag_end.saturating_sub(at).saturating_add(1);
                        }
                    }
                    b'(' | b'[' => {
                        run = 0;
                        depth = depth.saturating_add(1);
                        deepest = deepest.max(depth);
                    }
                    b')' | b']' => {
                        run = 0;
                        depth = depth.saturating_sub(1);
                    }
                    _ if is_operator(byte) => {
                        run = run.saturating_add(1);
                        deepest = deepest.max(run);
                    }
                    _ if byte.is_ascii_whitespace() => {}
                    _ => run = 0,
                }
            }
            Lex::Single { escapes } => {
                if escapes && byte == b'\\' {
                    step = 2;
                } else if byte == b'\'' {
                    if next == Some(b'\'') {
                        step = 2;
                    } else {
                        state = Lex::Code;
                    }
                }
            }
            Lex::Double => {
                if byte == b'"' {
                    if next == Some(b'"') {
                        step = 2;
                    } else {
                        state = Lex::Code;
                    }
                }
            }
            Lex::Dollar { start, end } => {
                if byte == b'$' {
                    let tag = text.get(start..end).unwrap_or_default();
                    let from = at.saturating_add(1);
                    let to = from.saturating_add(tag.len());
                    if text.get(from..to) == Some(tag) && text.get(to) == Some(&b'$') {
                        state = Lex::Code;
                        step = to.saturating_sub(at).saturating_add(1);
                    }
                }
            }
            Lex::Line => {
                if byte == b'\n' || byte == b'\r' {
                    state = Lex::Code;
                }
            }
            Lex::Block { depth: comments } => {
                if byte == b'/' && next == Some(b'*') {
                    state = Lex::Block {
                        depth: comments.saturating_add(1),
                    };
                    step = 2;
                } else if byte == b'*' && next == Some(b'/') {
                    state = match comments.checked_sub(1) {
                        Some(0) | None => Lex::Code,
                        Some(left) => Lex::Block { depth: left },
                    };
                    step = 2;
                }
            }
        }
        at = at.saturating_add(step);
    }
    // A word that runs to the end of the text.
    if in_word
        && text
            .get(word_start..)
            .is_some_and(|word| word.eq_ignore_ascii_case(b"not"))
    {
        deepest = deepest.max(run.saturating_add(1));
    }
    deepest
}

#[cfg(test)]
mod tests {
    use super::*;

    fn depth(text: &str) -> u32 {
        nesting(text.as_bytes())
    }

    #[test]
    fn the_checks_run_in_order() {
        let limits = Limits::with_max_bytes(8);
        // Too long wins over everything else that is wrong with it.
        assert_eq!(
            precheck(b"\xff\0(((((((", &limits),
            Err(ParseFailure::TooLarge)
        );
        assert_eq!(precheck(b"\xff\0", &limits), Err(ParseFailure::InvalidUtf8));
        assert_eq!(precheck(b"a\0b", &limits), Err(ParseFailure::EmbeddedNul));
        assert_eq!(precheck(b"SELECT 1", &limits), Ok("SELECT 1"));
        assert_eq!(precheck(b"SELECT 12", &limits), Err(ParseFailure::TooLarge));
        assert_eq!(precheck(b"", &limits), Ok(""));
    }

    #[test]
    fn invalid_utf8_is_refused_in_every_form() {
        let limits = Limits::default();
        for bytes in [
            &b"SELECT '\xc3'"[..],
            b"SELECT '\xed\xa0\x80'",
            b"\xf8\x88\x80\x80\x80",
            b"SELECT \xc0\xaf",
        ] {
            assert_eq!(precheck(bytes, &limits), Err(ParseFailure::InvalidUtf8));
        }
    }

    #[test]
    fn nesting_ten_thousand_deep_is_refused() {
        let limits = Limits::with_max_bytes(1 << 20);
        let n = 10_000;
        for text in [
            format!("SELECT {}1{}", "(".repeat(n), ")".repeat(n)),
            format!("SELECT {}true", "NOT ".repeat(n)),
            format!("SELECT {}1", "- ".repeat(n)),
            format!("SELECT {}1{}", "ARRAY[".repeat(n), "]".repeat(n)),
            format!("SELECT {}1", "+-".repeat(n)),
            format!("SELECT {}true", "not\n".repeat(n)),
        ] {
            assert_eq!(
                precheck(text.as_bytes(), &limits),
                Err(ParseFailure::TooDeep),
                "{}",
                text.get(..24).unwrap()
            );
        }
    }

    #[test]
    fn the_cap_on_nesting_is_exact() {
        let limits = Limits::default().with_max_depth(3);
        assert!(precheck(b"SELECT (((1)))", &limits).is_ok());
        assert_eq!(
            precheck(b"SELECT ((((1))))", &limits),
            Err(ParseFailure::TooDeep)
        );
        assert!(precheck(b"SELECT NOT NOT NOT true", &limits).is_ok());
        assert_eq!(
            precheck(b"SELECT NOT NOT NOT NOT true", &limits),
            Err(ParseFailure::TooDeep)
        );
        assert!(precheck(b"SELECT - - - 1", &limits).is_ok());
        assert_eq!(
            precheck(b"SELECT - - - - 1", &limits),
            Err(ParseFailure::TooDeep)
        );
    }

    #[test]
    fn brackets_that_close_do_not_add_up() {
        assert_eq!(depth("INSERT INTO t VALUES (1),(2),(3),(4)"), 1);
        assert_eq!(depth("SELECT f(g(1)), h(2)"), 2);
        assert_eq!(depth("SELECT a[1][2], ARRAY[ARRAY[1]]"), 2);
        assert_eq!(depth("SELECT 1 + 2 - 3 * 4"), 1);
        assert_eq!(depth("SELECT a <> b AND c >= d"), 2);
        assert_eq!(depth("SELECT nothing, knot, not_a"), 0);
        assert_eq!(depth("SELECT NOT a AND NOT b"), 1);
    }

    #[test]
    fn brackets_in_strings_names_and_comments_do_not_count() {
        assert_eq!(depth("SELECT '((((', \"((((\", $$(((($$, $a$(((($a$"), 0);
        assert_eq!(depth("SELECT 1 -- ((((\n, (2)"), 1);
        assert_eq!(depth("SELECT 1 /* (((( /* (( */ (( */ , (2)"), 1);
        // A doubled quote stays inside the string or the name.
        assert_eq!(depth("SELECT 'a''((((', \"a\"\"((((\""), 0);
        // The tag of a dollar quote must match in full.
        assert_eq!(depth("SELECT $ab$ $a$ (( $ab$"), 0);
    }

    #[test]
    fn a_closing_bracket_inside_a_string_does_not_hide_an_open_one() {
        // Every `)` is inside a string, so the real nesting is four deep.
        assert_eq!(depth("SELECT ( ')' ( ')' ( ')' ( 1"), 4);
        assert_eq!(depth("SELECT ( \")\" ( /* ) */ ( -- )\n ( 1"), 4);
        assert_eq!(depth("SELECT ( $$)$$ ( $x$)$x$ ( 1"), 3);
    }

    #[test]
    fn a_string_ends_where_postgresql_ends_it() {
        // Without the E, a backslash is an ordinary character.
        assert_eq!(depth(r"SELECT '\' , ((1))"), 2);
        // With it, the backslash takes the quote with it.
        assert_eq!(depth(r"SELECT E'\' , ((1)) '"), 0);
        assert_eq!(depth(r"SELECT e'\\' , ((1))"), 2);
        // An E that ends a longer word is not a prefix.
        assert_eq!(depth(r"SELECT fooE'\' , ((1))"), 2);
        // A dollar inside a word does not open a quote, and `$1` is a
        // parameter.
        assert_eq!(depth("SELECT a$b$ , ((1)) , $1 , ((($2)))"), 3);
        // After a number it does open one, so these three `)` are text.
        assert_eq!(depth("SELECT ( ( ( 1$a$ ))) $a$ ( ( ( 1"), 6);
        assert_eq!(depth("SELECT ( $1 , $a$ ) $a$ ( 1"), 2);
        // An unterminated string or comment swallows the rest.
        assert_eq!(depth("SELECT ' (((("), 0);
        assert_eq!(depth("SELECT /* (((("), 0);
    }

    #[test]
    fn the_names_of_the_failures_are_fixed() {
        for (failure, name) in [
            (ParseFailure::TooLarge, "too_large"),
            (ParseFailure::InvalidUtf8, "invalid_utf8"),
            (ParseFailure::EmbeddedNul, "embedded_nul"),
            (ParseFailure::TooDeep, "too_deep"),
            (ParseFailure::Rejected, "rejected"),
            (ParseFailure::Unreadable, "unreadable"),
            (ParseFailure::Incomplete, "incomplete"),
            (ParseFailure::Busy, "busy"),
            (ParseFailure::Panicked, "panicked"),
            (ParseFailure::Streamed, "streamed"),
            (ParseFailure::Encoding, "encoding"),
            (ParseFailure::TimedOut, "timed_out"),
            (ParseFailure::OpaqueBody, "opaque_body"),
            (ParseFailure::FunctionCall, "function_call"),
        ] {
            assert_eq!(failure.name(), name);
            assert_eq!(failure.to_string(), name);
        }
    }
}
