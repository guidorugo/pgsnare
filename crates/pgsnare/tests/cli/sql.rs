// SPDX-License-Identifier: Apache-2.0

//! A reader for the SQL script that `token generate` prints.
//!
//! It is written from the lexical rules in the PostgreSQL documentation,
//! section 4.1, and shares nothing with the code that writes the script.
//! It knows what such a script may contain and refuses everything else, so
//! a name or a value that got out of its quotes shows up as an error or as
//! a second statement.

/// One piece of a statement.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Token {
    /// A word outside quotes, such as `INSERT`.
    Word(String),
    /// A quoted identifier, as the name it stands for.
    Identifier(String),
    /// A string constant, as the text it stands for.
    Literal(String),
    /// Any other character, such as `(`.
    Symbol(char),
}

/// What a backslash means between a pair of quotes.
#[derive(Clone, Copy, PartialEq, Eq)]
enum Backslash {
    /// Nothing: it is a character like any other.
    Plain,
    /// It begins a code point, as in `U&"..."`.
    CodePoint,
    /// It begins a C-style escape, as in `E'...'`.
    CStyle,
}

/// Reads up to the closing `quote` and returns the text between the quotes
/// and the position after them. A quote written twice is one quote.
fn quoted(
    characters: &[char],
    mut at: usize,
    quote: char,
    backslash: Backslash,
) -> Result<(String, usize), String> {
    let mut text = String::new();
    loop {
        let Some(&character) = characters.get(at) else {
            return Err(format!("a {quote} is never closed"));
        };
        at += 1;
        if character == quote {
            if characters.get(at) == Some(&quote) {
                text.push(quote);
                at += 1;
                continue;
            }
            return Ok((text, at));
        }
        if character != '\\' || backslash == Backslash::Plain {
            text.push(character);
            continue;
        }
        // A backslash that means something. Written twice, it is one.
        if characters.get(at) == Some(&'\\') {
            text.push('\\');
            at += 1;
            continue;
        }
        if backslash == Backslash::CStyle {
            // The script may hold no other escape: any other would be a
            // character the writer did not write as itself.
            return Err("an escape other than a doubled backslash in an E'' constant".to_owned());
        }
        let digits = if characters.get(at) == Some(&'+') {
            at += 1;
            6
        } else {
            4
        };
        let hex: String = characters.iter().skip(at).take(digits).collect();
        if hex.len() != digits || !hex.chars().all(|digit| digit.is_ascii_hexdigit()) {
            return Err("a code point that is not four or six hexadecimal digits".to_owned());
        }
        at += digits;
        let code = u32::from_str_radix(&hex, 16).map_err(|error| error.to_string())?;
        text.push(char::from_u32(code).ok_or("a code point that is no character")?);
    }
}

/// Skips a comment that begins at `at`, with the comments inside it, and
/// returns the position after it.
fn skip_comment(characters: &[char], mut at: usize) -> Result<usize, String> {
    let mut depth = 0usize;
    loop {
        match (characters.get(at), characters.get(at + 1)) {
            (Some('/'), Some('*')) => {
                depth += 1;
                at += 2;
            }
            (Some('*'), Some('/')) => {
                depth -= 1;
                at += 2;
                if depth == 0 {
                    return Ok(at);
                }
            }
            (Some(_), _) => at += 1,
            (None, _) => return Err("a comment is never closed".to_owned()),
        }
    }
}

/// Splits a script into statements, at the semicolons that stand outside
/// quotes and comments.
pub fn statements(script: &str) -> Result<Vec<Vec<Token>>, String> {
    let characters: Vec<char> = script.chars().collect();
    let mut statements = Vec::new();
    let mut statement = Vec::new();
    let mut at = 0;
    while let Some(&character) = characters.get(at) {
        let next = characters.get(at + 1).copied();
        match character {
            _ if character.is_whitespace() => at += 1,
            '-' if next == Some('-') => {
                while characters
                    .get(at)
                    .is_some_and(|character| *character != '\n')
                {
                    at += 1;
                }
            }
            '/' if next == Some('*') => at = skip_comment(&characters, at)?,
            '"' => {
                let (name, end) = quoted(&characters, at + 1, '"', Backslash::Plain)?;
                statement.push(Token::Identifier(name));
                at = end;
            }
            'U' | 'u' if next == Some('&') && characters.get(at + 2) == Some(&'"') => {
                let (name, end) = quoted(&characters, at + 3, '"', Backslash::CodePoint)?;
                statement.push(Token::Identifier(name));
                at = end;
            }
            '\'' => {
                let (text, end) = quoted(&characters, at + 1, '\'', Backslash::Plain)?;
                if text.contains('\\') {
                    // With `standard_conforming_strings` off, this
                    // backslash would be an escape.
                    return Err("a backslash in a constant that is not an E'' constant".to_owned());
                }
                statement.push(Token::Literal(text));
                at = end;
            }
            'E' | 'e' if next == Some('\'') => {
                let (text, end) = quoted(&characters, at + 2, '\'', Backslash::CStyle)?;
                statement.push(Token::Literal(text));
                at = end;
            }
            ';' => {
                statements.push(std::mem::take(&mut statement));
                at += 1;
            }
            // Outside quotes, psql takes a backslash for one of its own
            // commands, and `\!` runs a program.
            '\\' => return Err("a backslash outside quotes".to_owned()),
            _ if character.is_ascii_alphanumeric() || character == '_' => {
                let mut word = String::new();
                while let Some(&character) = characters.get(at) {
                    if !(character.is_ascii_alphanumeric() || character == '_') {
                        break;
                    }
                    word.push(character);
                    at += 1;
                }
                statement.push(Token::Word(word));
            }
            other => {
                statement.push(Token::Symbol(other));
                at += 1;
            }
        }
    }
    if statement.is_empty() {
        Ok(statements)
    } else {
        Err("the script ends in the middle of a statement".to_owned())
    }
}

/// The one statement of a script: an `INSERT` of rows of constants.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Insert {
    /// The parts of the name of the table.
    pub table: Vec<String>,
    /// The names of the columns.
    pub columns: Vec<String>,
    /// The values of every row.
    pub rows: Vec<Vec<String>>,
}

/// Walks over the tokens of a statement.
struct Cursor {
    tokens: std::vec::IntoIter<Token>,
    peeked: Option<Token>,
}

impl Cursor {
    fn next(&mut self) -> Option<Token> {
        self.peeked.take().or_else(|| self.tokens.next())
    }

    fn peek(&mut self) -> Option<&Token> {
        if self.peeked.is_none() {
            self.peeked = self.tokens.next();
        }
        self.peeked.as_ref()
    }

    fn word(&mut self, expected: &str) -> Result<(), String> {
        match self.next() {
            Some(Token::Word(word)) if word == expected => Ok(()),
            other => Err(format!("expected {expected}, found {other:?}")),
        }
    }

    fn symbol(&mut self, expected: char) -> Result<(), String> {
        match self.next() {
            Some(Token::Symbol(symbol)) if symbol == expected => Ok(()),
            other => Err(format!("expected {expected}, found {other:?}")),
        }
    }

    fn identifier(&mut self) -> Result<String, String> {
        match self.next() {
            Some(Token::Identifier(name)) => Ok(name),
            other => Err(format!("expected a quoted identifier, found {other:?}")),
        }
    }

    fn literal(&mut self) -> Result<String, String> {
        match self.next() {
            Some(Token::Literal(text)) => Ok(text),
            other => Err(format!("expected a string constant, found {other:?}")),
        }
    }

    /// Whether the next token is this symbol. If so, it is taken.
    fn take_symbol(&mut self, expected: char) -> bool {
        if self.peek() == Some(&Token::Symbol(expected)) {
            self.next();
            true
        } else {
            false
        }
    }
}

/// Reads a script that must be exactly one `INSERT INTO name (columns)
/// VALUES (constants), ...` and comments.
pub fn read(script: &str) -> Result<Insert, String> {
    let mut statements = statements(script)?;
    if statements.len() != 1 {
        return Err(format!(
            "expected one statement, found {}",
            statements.len()
        ));
    }
    let mut cursor = Cursor {
        tokens: statements.remove(0).into_iter(),
        peeked: None,
    };

    cursor.word("INSERT")?;
    cursor.word("INTO")?;
    let mut table = vec![cursor.identifier()?];
    while cursor.take_symbol('.') {
        table.push(cursor.identifier()?);
    }

    cursor.symbol('(')?;
    let mut columns = vec![cursor.identifier()?];
    while cursor.take_symbol(',') {
        columns.push(cursor.identifier()?);
    }
    cursor.symbol(')')?;

    cursor.word("VALUES")?;
    let mut rows = Vec::new();
    loop {
        cursor.symbol('(')?;
        let mut row = vec![cursor.literal()?];
        while cursor.take_symbol(',') {
            row.push(cursor.literal()?);
        }
        cursor.symbol(')')?;
        rows.push(row);
        if !cursor.take_symbol(',') {
            break;
        }
    }
    match cursor.next() {
        None => Ok(Insert {
            table,
            columns,
            rows,
        }),
        Some(other) => Err(format!(
            "expected the end of the statement, found {other:?}"
        )),
    }
}

/// The token file of a script: what stands between the line `/*` and the
/// line `*/` at its end.
pub fn token_file(script: &str) -> Result<&str, String> {
    let (_, rest) = script
        .split_once("\n/*\n")
        .ok_or("the script has no comment with a token file")?;
    rest.strip_suffix("*/\n")
        .ok_or_else(|| "the script does not end with the end of a comment".to_owned())
}

#[test]
fn the_reader_tells_one_statement_from_two() {
    // If the reader accepted anything, it could show nothing.
    let one = "INSERT INTO \"t\" (\"c\") VALUES\n    ('a');\n";
    assert_eq!(
        read(one),
        Ok(Insert {
            table: vec!["t".to_owned()],
            columns: vec!["c".to_owned()],
            rows: vec![vec!["a".to_owned()]],
        })
    );

    // A name that ends its quotes early and brings a statement of its own.
    let escaped = "INSERT INTO \"t\"; DROP TABLE users; --\" (\"c\") VALUES ('a');\n";
    assert!(read(escaped).is_err());
    assert_eq!(
        statements("SELECT 1; DROP TABLE users;").map(|found| found.len()),
        Ok(2)
    );
    // The same name with its quote doubled stays one identifier.
    let kept = "INSERT INTO \"t\"\"; DROP TABLE users; --\" (\"c\") VALUES ('a');\n";
    assert_eq!(
        read(kept).map(|insert| insert.table),
        Ok(vec!["t\"; DROP TABLE users; --".to_owned()])
    );

    // A value that ends its quotes early.
    assert!(read("INSERT INTO \"t\" (\"c\") VALUES ('a'); DROP TABLE users; --');\n").is_err());
    assert_eq!(
        read("INSERT INTO \"t\" (\"c\") VALUES ('a''); DROP TABLE users; --');\n")
            .map(|insert| insert.rows),
        Ok(vec![vec!["a'); DROP TABLE users; --".to_owned()]])
    );

    // What the old setting of the server would read differently.
    assert!(read("INSERT INTO \"t\" (\"c\") VALUES ('a\\');\n").is_err());
    assert_eq!(
        read("INSERT INTO \"t\" (\"c\") VALUES (E'a\\\\');\n").map(|insert| insert.rows),
        Ok(vec![vec!["a\\".to_owned()]])
    );
    assert!(read("INSERT INTO \"t\" (\"c\") VALUES (E'a\\'');\n").is_err());

    // Things that are no part of such a script.
    for script in [
        "INSERT INTO t (\"c\") VALUES ('a');",
        "INSERT INTO \"t\" (c) VALUES ('a');",
        "INSERT INTO \"t\" (\"c\") VALUES (1);",
        "INSERT INTO \"t\" (\"c\") VALUES ('a') RETURNING \"c\";",
        "INSERT INTO \"t\" (\"c\") VALUES ('a')",
        "INSERT INTO \"t\" (\"c\") VALUES ('a'); \\! true",
        "INSERT INTO \"t\" (\"c\") VALUES ('a'); /* open",
        "INSERT INTO \"t\" (\"c\") VALUES ('a);",
        "",
    ] {
        assert!(read(script).is_err(), "{script}");
    }

    // Comments are skipped, also one inside another.
    let commented = "-- a; b\n/* x; /* y; */ z; */\nINSERT INTO U&\"\\00E9\\\\\" (\"c\") VALUES ('a');\n/*\ntokens: []\n*/\n";
    assert_eq!(
        read(commented).map(|insert| insert.table),
        Ok(vec!["\u{e9}\\".to_owned()])
    );
    assert_eq!(token_file(commented), Ok("tokens: []\n"));
}
