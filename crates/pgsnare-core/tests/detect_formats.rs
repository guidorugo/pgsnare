// SPDX-License-Identifier: Apache-2.0

//! A honeytoken value is found wherever PostgreSQL prints it as it is.
//!
//! Unless a comment says otherwise, each sample is output of PostgreSQL
//! 16.15 for a query over a synthetic value, copied byte for byte. The query
//! is given next to the sample. Every sample is scanned whole and in chunks
//! of several sizes, and all scans must agree.
//!
//! The last tests record what is *not* found: values that were changed
//! before they were sent. They are asserted as misses so that the limits of
//! substring matching stay documented.

use pgsnare_core::detect::{Matcher, PatternForm, TokenSpec};

/// The value most samples contain. It needs no escaping in any text format.
const VALUE: &str = "svc.backup.8f3k2q@mail.example";

/// A value with a comma and spaces. Arrays, composite rows and CSV put
/// quotes around it but do not change it.
const SPACED: &str = "canary, with spaces 0042";

/// A value with a double quote and a backslash, which several text formats
/// escape.
const QUOTED: &str = r#"quote"and\slash-0001"#;

/// A value with characters that XML output escapes.
const MARKUP: &str = "r&d-canary<0042>";

fn matcher_for(value: &str) -> Matcher {
    Matcher::build(&[TokenSpec::new("planted", [value])]).expect("the value is valid")
}

fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|byte| format!("{byte:02x}")).collect()
}

/// Decodes a sample that is written as hexadecimal digits here because it is
/// binary.
fn binary(hex: &str) -> Vec<u8> {
    hex.as_bytes()
        .chunks(2)
        .map(|pair| {
            let digits = std::str::from_utf8(pair).expect("hex digits are ASCII");
            u8::from_str_radix(digits, 16).expect("the sample is hexadecimal")
        })
        .collect()
}

/// Where `needle` occurs in `sample`, by trying every position.
fn occurrences(sample: &[u8], needle: &[u8]) -> Vec<u64> {
    (0..sample.len())
        .filter(|&start| sample[start..].starts_with(needle))
        .map(|start| start as u64)
        .collect()
}

/// The form and start of every match in `sample`. The sample is scanned
/// whole and as a stream in chunks of several sizes; all must agree.
fn hits(matcher: &Matcher, sample: &[u8]) -> Vec<(PatternForm, u64)> {
    let summarize = |mut matches: Vec<pgsnare_core::detect::Match>| {
        matches.sort();
        matches
            .iter()
            .map(|found| {
                assert_eq!(found.token_id().as_str(), "planted");
                (found.form(), found.start())
            })
            .collect::<Vec<_>>()
    };

    let whole = summarize(
        matcher
            .scan(sample)
            .collect::<Result<Vec<_>, _>>()
            .expect("a scan does not fail"),
    );
    for size in [1, 2, 3, 5, 8, 13, 21, 34, 55, 89] {
        let mut scanner = matcher.stream();
        let mut streamed = Vec::new();
        for chunk in sample.chunks(size) {
            for found in scanner.feed(chunk) {
                streamed.push(found.expect("a scan does not fail"));
            }
        }
        assert_eq!(summarize(streamed), whole, "in chunks of {size} bytes");
    }
    whole
}

/// Asserts that `value` is found in `sample` exactly `times` times, in raw
/// form, at the positions a plain search gives.
#[track_caller]
fn assert_found(value: &str, sample: impl AsRef<[u8]>, times: usize) {
    let sample = sample.as_ref();
    let expected: Vec<(PatternForm, u64)> = occurrences(sample, value.as_bytes())
        .into_iter()
        .map(|start| (PatternForm::Raw, start))
        .collect();
    assert_eq!(
        expected.len(),
        times,
        "the sample itself is not as described"
    );
    assert_eq!(hits(&matcher_for(value), sample), expected);
}

/// Asserts that `value` is found in `sample` exactly `times` times, in hex
/// form, at the positions a plain search gives.
#[track_caller]
fn assert_found_as_hex(value: &str, sample: impl AsRef<[u8]>, times: usize) {
    let sample = sample.as_ref();
    let expected: Vec<(PatternForm, u64)> = occurrences(sample, hex(value.as_bytes()).as_bytes())
        .into_iter()
        .map(|start| (PatternForm::Hex, start))
        .collect();
    assert_eq!(
        expected.len(),
        times,
        "the sample itself is not as described"
    );
    assert_eq!(hits(&matcher_for(value), sample), expected);
}

/// Asserts that nothing is found in `sample`.
#[track_caller]
fn assert_missed(value: &str, sample: impl AsRef<[u8]>) {
    assert_eq!(hits(&matcher_for(value), sample.as_ref()), []);
}

// ---------------------------------------------------------------------------
// Text formats
// ---------------------------------------------------------------------------

#[test]
fn found_in_json() {
    // SELECT row_to_json(t) FROM (SELECT 7 AS id, '…' AS email, true AS active) t
    assert_found(
        VALUE,
        r#"{"id":7,"email":"svc.backup.8f3k2q@mail.example","active":true}"#,
        1,
    );
    // SELECT json_agg(t) FROM (VALUES (7, '…'), (8, 'someone@mail.example')) AS t(id, email)
    assert_found(
        VALUE,
        "[{\"id\":7,\"email\":\"svc.backup.8f3k2q@mail.example\"}, \n {\"id\":8,\"email\":\"someone@mail.example\"}]",
        1,
    );
    // SELECT jsonb_build_object('email', '…', 'tags', jsonb_build_array('a', '…'))
    assert_found(
        VALUE,
        r#"{"tags": ["a", "svc.backup.8f3k2q@mail.example"], "email": "svc.backup.8f3k2q@mail.example"}"#,
        2,
    );
    // SELECT jsonb_pretty(jsonb_build_object('email', '…', 'id', 7))
    assert_found(
        VALUE,
        "{\n    \"id\": 7,\n    \"email\": \"svc.backup.8f3k2q@mail.example\"\n}",
        1,
    );
    // SELECT to_json('…'::text)
    assert_found(VALUE, r#""svc.backup.8f3k2q@mail.example""#, 1);
    // SELECT row_to_json(t) FROM (SELECT 'canary, with spaces 0042' AS v) t
    assert_found(SPACED, r#"{"v":"canary, with spaces 0042"}"#, 1);
    // SELECT row_to_json(t) FROM (SELECT 'r&d-canary<0042>' AS v) t
    assert_found(MARKUP, r#"{"v":"r&d-canary<0042>"}"#, 1);
}

#[test]
fn found_in_arrays() {
    // SELECT ARRAY['alpha', '…', 'two words']
    assert_found(
        VALUE,
        r#"{alpha,svc.backup.8f3k2q@mail.example,"two words"}"#,
        1,
    );
    // SELECT array_agg(e) FROM (VALUES ('…'), ('other@mail.example'), (NULL)) AS t(e)
    assert_found(
        VALUE,
        "{svc.backup.8f3k2q@mail.example,other@mail.example,NULL}",
        1,
    );
    // SELECT ARRAY[ARRAY['a', '…'], ARRAY['b', 'c']]
    assert_found(VALUE, "{{a,svc.backup.8f3k2q@mail.example},{b,c}}", 1);
    // SELECT ARRAY['a', 'canary, with spaces 0042']
    assert_found(SPACED, r#"{a,"canary, with spaces 0042"}"#, 1);
}

#[test]
fn found_in_composite_rows() {
    // SELECT ROW(42, '…', 'two words', true, NULL)
    assert_found(
        VALUE,
        r#"(42,svc.backup.8f3k2q@mail.example,"two words",t,)"#,
        1,
    );
    // SELECT u FROM users u, where the row is (7, '…', 'Doe, Jane')
    assert_found(
        VALUE,
        r#"(7,svc.backup.8f3k2q@mail.example,"Doe, Jane")"#,
        1,
    );
    // SELECT array_agg(u) FROM users u
    assert_found(
        VALUE,
        r#"{"(7,svc.backup.8f3k2q@mail.example,\"Doe, Jane\")"}"#,
        1,
    );
    // SELECT ROW(1, 'canary, with spaces 0042')
    assert_found(SPACED, r#"(1,"canary, with spaces 0042")"#, 1);
}

#[test]
fn found_in_csv() {
    // COPY (SELECT 7, '…', 'Doe, Jane') TO STDOUT WITH (FORMAT csv)
    assert_found(VALUE, "7,svc.backup.8f3k2q@mail.example,\"Doe, Jane\"\n", 1);
    // COPY users TO STDOUT WITH (FORMAT csv, HEADER, FORCE_QUOTE *)
    assert_found(
        VALUE,
        "id,email,note\n\"7\",\"svc.backup.8f3k2q@mail.example\",\"Doe, Jane\"\n",
        1,
    );
    // COPY (SELECT 1, 'canary, with spaces 0042') TO STDOUT WITH (FORMAT csv)
    assert_found(SPACED, "1,\"canary, with spaces 0042\"\n", 1);
}

#[test]
fn found_in_copy_text_output() {
    // COPY (SELECT 7, '…', NULL, E'tab\there') TO STDOUT
    assert_found(
        VALUE,
        "7\tsvc.backup.8f3k2q@mail.example\t\\N\ttab\\there\n",
        1,
    );
    // COPY (SELECT 1, 'canary, with spaces 0042') TO STDOUT
    assert_found(SPACED, "1\tcanary, with spaces 0042\n", 1);
    // Several rows in one buffer, as a client sends them with COPY FROM.
    let rows = "7\tsvc.backup.8f3k2q@mail.example\t\\N\n".repeat(3);
    assert_found(VALUE, rows, 3);
}

#[test]
fn found_in_bytea_hex_output() {
    // SELECT '…'::bytea
    assert_found_as_hex(
        VALUE,
        r"\x7376632e6261636b75702e3866336b3271406d61696c2e6578616d706c65",
        1,
    );
    // SELECT '\x00ff'::bytea || '…'::bytea || '\xbeef'::bytea
    assert_found_as_hex(
        VALUE,
        r"\x00ff7376632e6261636b75702e3866336b3271406d61696c2e6578616d706c65beef",
        1,
    );
    // COPY (SELECT 7, '…'::bytea) TO STDOUT
    assert_found_as_hex(
        VALUE,
        "7\t\\\\x7376632e6261636b75702e3866336b3271406d61696c2e6578616d706c65\n",
        1,
    );
    // COPY (SELECT 7, '…'::bytea) TO STDOUT WITH (FORMAT csv)
    assert_found_as_hex(
        VALUE,
        "7,\\x7376632e6261636b75702e3866336b3271406d61696c2e6578616d706c65\n",
        1,
    );
    // SELECT row_to_json(t) FROM (SELECT '…'::bytea AS raw) t
    assert_found_as_hex(
        VALUE,
        r#"{"raw":"\\x7376632e6261636b75702e3866336b3271406d61696c2e6578616d706c65"}"#,
        1,
    );
    // SELECT encode('…'::bytea, 'hex')
    assert_found_as_hex(
        VALUE,
        "7376632e6261636b75702e3866336b3271406d61696c2e6578616d706c65",
        1,
    );
}

#[test]
fn found_in_bytea_escape_output() {
    // SET bytea_output = escape; SELECT '…'::bytea
    assert_found(VALUE, "svc.backup.8f3k2q@mail.example", 1);
}

#[test]
fn found_in_aggregated_and_concatenated_strings() {
    // SELECT string_agg(e, '; ') FROM (VALUES ('first@mail.example'), ('…')) AS t(e)
    assert_found(
        VALUE,
        "first@mail.example; svc.backup.8f3k2q@mail.example",
        1,
    );
    // SELECT 'user=' || '…' || ';role=admin'
    assert_found(VALUE, "user=svc.backup.8f3k2q@mail.example;role=admin", 1);
    // SELECT xmlelement(name email, '…')
    assert_found(VALUE, "<email>svc.backup.8f3k2q@mail.example</email>", 1);
}

#[test]
fn found_in_error_and_notice_text() {
    // SELECT '…'::int
    assert_found(
        VALUE,
        r#"invalid input syntax for type integer: "svc.backup.8f3k2q@mail.example""#,
        1,
    );
    // INSERT of a second row with the same primary key: the DETAIL line.
    assert_found(
        VALUE,
        "Key (email)=(svc.backup.8f3k2q@mail.example) already exists.",
        1,
    );
    // DO $$ BEGIN RAISE NOTICE 'value %', '…'; END $$
    assert_found(VALUE, "value svc.backup.8f3k2q@mail.example", 1);

    // The same message as the body of an ErrorResponse: fields that each
    // start with a type byte and end with a zero byte. Built by hand from
    // the protocol documentation.
    let mut body = Vec::new();
    for (field, text) in [
        (b'S', "ERROR"),
        (b'V', "ERROR"),
        (b'C', "22P02"),
        (
            b'M',
            r#"invalid input syntax for type integer: "svc.backup.8f3k2q@mail.example""#,
        ),
        (b'F', "numutils.c"),
        (b'R', "pg_strtoint32_safe"),
    ] {
        body.push(field);
        body.extend_from_slice(text.as_bytes());
        body.push(0);
    }
    body.push(0);
    assert_found(VALUE, body, 1);
}

#[test]
fn found_in_query_text() {
    // What a client sends. Built by hand.
    assert_found(
        VALUE,
        "SELECT * FROM users WHERE email = 'svc.backup.8f3k2q@mail.example'",
        1,
    );
    // SELECT format('INSERT INTO users VALUES (%s, %L);', 7, '…')
    assert_found(
        VALUE,
        "INSERT INTO users VALUES (7, 'svc.backup.8f3k2q@mail.example');",
        1,
    );
    // A startup packet that names the value as the user: parameter names
    // and values, each ended by a zero byte. Built by hand.
    let mut startup = Vec::new();
    for text in ["user", VALUE, "database", "app"] {
        startup.extend_from_slice(text.as_bytes());
        startup.push(0);
    }
    startup.push(0);
    assert_found(VALUE, startup, 1);
}

// ---------------------------------------------------------------------------
// Binary formats
// ---------------------------------------------------------------------------

#[test]
fn found_in_binary_results() {
    // COPY (SELECT 7::int4, '…'::text, '…'::bytea, NULL::text) TO STDOUT WITH (FORMAT binary)
    //
    // In binary format a text value and a bytea value are both sent as
    // their bytes, so both are found in raw form.
    assert_found(
        VALUE,
        binary(concat!(
            "5047434f50590aff0d0a00",
            "00000000",
            "00000000",
            "0004",
            "0000000400000007",
            "0000001e7376632e6261636b75702e3866336b3271406d61696c2e6578616d706c65",
            "0000001e7376632e6261636b75702e3866336b3271406d61696c2e6578616d706c65",
            "ffffffff",
            "ffff",
        )),
        2,
    );
    // SELECT jsonb_send(jsonb_build_object('email', '…'))
    assert_found(
        VALUE,
        binary(
            "017b22656d61696c223a20227376632e6261636b75702e3866336b3271406d61696c2e6578616d706c65227d",
        ),
        1,
    );
    // SELECT array_send(ARRAY['alpha', '…'])
    assert_found(
        VALUE,
        binary(concat!(
            "000000010000000000000019000000020000000100000005616c706861",
            "0000001e7376632e6261636b75702e3866336b3271406d61696c2e6578616d706c65",
        )),
        1,
    );
    // SELECT record_send(ROW(42, '…'::text))
    assert_found(
        VALUE,
        binary(concat!(
            "0000000200000017000000040000002a00000019",
            "0000001e7376632e6261636b75702e3866336b3271406d61696c2e6578616d706c65",
        )),
        1,
    );
}

#[test]
fn found_in_a_data_row() {
    // The body of a DataRow message with three columns in text format: a
    // column count, then a length and the bytes for each column, with
    // length -1 for NULL. Built by hand from the protocol documentation.
    let mut body = Vec::new();
    body.extend_from_slice(&3i16.to_be_bytes());
    for column in [Some("7"), Some(VALUE), None] {
        match column {
            Some(text) => {
                body.extend_from_slice(&(text.len() as i32).to_be_bytes());
                body.extend_from_slice(text.as_bytes());
            }
            None => body.extend_from_slice(&(-1i32).to_be_bytes()),
        }
    }
    assert_found(VALUE, body, 1);
}

// ---------------------------------------------------------------------------
// Letter case
// ---------------------------------------------------------------------------

#[test]
fn found_in_another_letter_case_only_when_the_token_asks() {
    // SELECT upper('…'), lower('…'), initcap('…')
    let sample = b"SVC.BACKUP.8F3K2Q@MAIL.EXAMPLE|svc.backup.8f3k2q@mail.example|Svc.Backup.8f3k2q@Mail.Example";

    let strict = matcher_for(VALUE);
    assert_eq!(hits(&strict, sample), [(PatternForm::Raw, 31)]);

    let loose = Matcher::build(&[TokenSpec::new("planted", [VALUE]).case_insensitive(true)])
        .expect("the value is valid");
    assert_eq!(
        hits(&loose, sample),
        [
            (PatternForm::CaseInsensitive, 0),
            (PatternForm::Raw, 31),
            (PatternForm::CaseInsensitive, 62),
        ]
    );
}

// ---------------------------------------------------------------------------
// Known gaps: values that were changed before they were sent
// ---------------------------------------------------------------------------

#[test]
fn missed_when_the_database_transformed_the_value() {
    // SELECT upper(encode('…'::bytea, 'hex'))
    assert_missed(
        VALUE,
        "7376632E6261636B75702E3866336B3271406D61696C2E6578616D706C65",
    );
    // SELECT encode('…'::bytea, 'base64')
    assert_missed(VALUE, "c3ZjLmJhY2t1cC44ZjNrMnFAbWFpbC5leGFtcGxl");
    // SELECT md5('…')
    assert_missed(VALUE, "5e4bb9d099c8e74dc807e603997fa57e");
    // SELECT reverse('…')
    assert_missed(VALUE, "elpmaxe.liam@q2k3f8.pukcab.cvs");
    // SELECT substr('…', 1, 15), substr('…', 16)
    assert_missed(VALUE, "svc.backup.8f3k|2q@mail.example");
}

#[test]
fn missed_where_a_text_format_escaped_a_character() {
    // The value is found where it is printed as it is.
    // SELECT 'quote"and\slash-0001'
    assert_found(QUOTED, r#"quote"and\slash-0001"#, 1);
    // SELECT xmlelement(name v, 'quote"and\slash-0001')
    assert_found(QUOTED, r#"<v>quote"and\slash-0001</v>"#, 1);

    // It is missed where the quote or the backslash was escaped or doubled.
    // SELECT row_to_json(t) FROM (SELECT 'quote"and\slash-0001' AS v) t
    assert_missed(QUOTED, r#"{"v":"quote\"and\\slash-0001"}"#);
    // SELECT ARRAY['quote"and\slash-0001']
    assert_missed(QUOTED, r#"{"quote\"and\\slash-0001"}"#);
    // SELECT ROW(1, 'quote"and\slash-0001')
    assert_missed(QUOTED, r#"(1,"quote""and\\slash-0001")"#);
    // COPY (SELECT 1, 'quote"and\slash-0001') TO STDOUT WITH (FORMAT csv)
    assert_missed(QUOTED, "1,\"quote\"\"and\\slash-0001\"\n");
    // COPY (SELECT 1, 'quote"and\slash-0001') TO STDOUT
    assert_missed(QUOTED, "1\tquote\"and\\\\slash-0001\n");
}

#[test]
fn missed_where_a_control_character_or_markup_was_escaped() {
    let tabbed = "canary\twith\ttabs-0042";
    // SELECT E'canary\twith\ttabs-0042', in a plain text result
    assert_found(tabbed, "canary\twith\ttabs-0042", 1);
    // COPY (SELECT E'canary\twith\ttabs-0042') TO STDOUT
    assert_missed(tabbed, "canary\\twith\\ttabs-0042\n");
    // SELECT to_json(E'canary\twith\ttabs-0042'::text)
    assert_missed(tabbed, r#""canary\twith\ttabs-0042""#);

    // SELECT 'r&d-canary<0042>'
    assert_found(MARKUP, "r&d-canary<0042>", 1);
    // SELECT xmlelement(name v, 'r&d-canary<0042>')
    assert_missed(MARKUP, "<v>r&amp;d-canary&lt;0042&gt;</v>");
}

#[test]
fn missed_where_a_query_escaped_a_single_quote() {
    let quoted = "it's-a-quoted-value";
    // The value as a result prints it.
    assert_found(quoted, "it's-a-quoted-value", 1);
    // SELECT format('%L', 'it''s-a-quoted-value'): the value as a string
    // literal, which is how it appears in the text of a query.
    assert_missed(quoted, "'it''s-a-quoted-value'");
    // A value without such a character is found in a literal.
    assert_found(VALUE, "'svc.backup.8f3k2q@mail.example'", 1);
}

#[test]
fn missed_in_the_binary_form_of_a_type_that_is_not_text() {
    // A number is its digits in text format and something else in binary.
    let card = "4929000000000017";
    // SELECT 4929000000000017::bigint
    assert_found(card, "4929000000000017", 1);
    // SELECT int8send(4929000000000017::bigint)
    assert_missed(card, binary("001182e63e191011"));
    // SELECT numeric_send(4929000000000017::numeric)
    assert_missed(card, binary("00040003000000001341000000000011"));

    // A uuid is printed in lowercase, and is sixteen bytes in binary.
    let uuid = "f81d4fae-7dec-11d0-a765-00a0c91e6bf6";
    // SELECT 'F81D4FAE-7DEC-11D0-A765-00A0C91E6BF6'::uuid
    assert_found(uuid, "f81d4fae-7dec-11d0-a765-00a0c91e6bf6", 1);
    // SELECT uuid_send('f81d4fae-7dec-11d0-a765-00a0c91e6bf6'::uuid)
    assert_missed(uuid, binary("f81d4fae7dec11d0a76500a0c91e6bf6"));
}
