// SPDX-License-Identifier: Apache-2.0

//! Tests of the redaction layer.

use std::net::{IpAddr, Ipv4Addr};

use pgsnare_core::event::{EventBody, EventKind, MAX_NAME_BYTES, Query, SessionId, text_from_wire};
use pgsnare_core::session::SessionOrigin;
use proptest::prelude::*;

use super::*;

const EMAIL: &str = "svc.backup.8f3k2q@mail.example";
const EMAIL_HEX: &str = "7376632e6261636b75702e3866336b3271406d61696c2e6578616d706c65";
const CANARY: &str = "Canary.Invoice.000417";
const URL: &str = "https://alerts.example.com/hooks/T0p-S3cret-Path";

fn redactor() -> Redactor {
    Redactor::builder()
        .token("users-admin-backup", [EMAIL], false)
        .token("billing-canary", [CANARY], true)
        .secret_text(URL)
        .build()
        .unwrap()
}

#[test]
fn a_redactor_that_knows_nothing_changes_nothing() {
    let nothing = Redactor::nothing();
    assert!(nothing.is_empty());
    assert!(matches!(nothing.text(EMAIL), Cow::Borrowed(EMAIL)));
    assert!(matches!(nothing.text(""), Cow::Borrowed("")));
    assert_eq!(
        nothing.text(&format!("cut{TRUNCATION_MARK}")),
        format!("cut{TRUNCATION_MARK}")
    );
    assert!(Redactor::builder().build().unwrap().is_empty());
    assert!(!redactor().is_empty());
}

#[test]
fn text_without_a_value_is_returned_as_it_is() {
    let redactor = redactor();
    for text in [
        "",
        "app",
        "svc.backup",
        "SELECT * FROM users WHERE id = $1",
        "caf\u{e9} \u{1f980}",
    ] {
        assert!(
            matches!(redactor.text(text), Cow::Borrowed(same) if same == text),
            "{text}"
        );
    }
}

#[test]
fn a_value_is_removed_wherever_it_is() {
    let redactor = redactor();
    assert_eq!(redactor.text(EMAIL), REDACTED);
    assert_eq!(
        redactor.text(&format!("SELECT * FROM users WHERE email = '{EMAIL}'")),
        "SELECT * FROM users WHERE email = '[redacted]'"
    );
    assert_eq!(
        redactor.text(&format!("{EMAIL} and again {EMAIL}!")),
        "[redacted] and again [redacted]!"
    );
    // Next to characters that take several bytes.
    assert_eq!(
        redactor.text(&format!("caf\u{e9}{EMAIL}\u{1f980}")),
        "caf\u{e9}[redacted]\u{1f980}"
    );
}

#[test]
fn a_value_is_removed_in_every_form_the_matcher_finds() {
    let redactor = redactor();
    // As lowercase hexadecimal digits, the way a `bytea` is printed.
    assert_eq!(redactor.text(&format!("\\x{EMAIL_HEX}")), "\\x[redacted]");
    // In another letter case, for the token that asks for it.
    assert_eq!(redactor.text("CANARY.INVOICE.000417"), REDACTED);
    assert_eq!(redactor.text("id=canary.invoice.000417;"), "id=[redacted];");
    // And not for the one that does not.
    let shouted = EMAIL.to_uppercase();
    assert_eq!(redactor.text(&shouted), shouted);
}

#[test]
fn values_that_touch_or_follow_each_other_are_removed_together() {
    let redactor = redactor();
    assert_eq!(redactor.text(&format!("{EMAIL}{CANARY}")), REDACTED);
    assert_eq!(redactor.text(&format!("{EMAIL}{EMAIL}{EMAIL}")), REDACTED);
    assert_eq!(
        redactor.text(&format!("{EMAIL} {CANARY}")),
        "[redacted] [redacted]"
    );
}

#[test]
fn the_beginning_of_a_value_is_removed_where_a_text_was_cut() {
    let redactor = redactor();
    let mark = TRUNCATION_MARK;

    // A name that is cut inside a value: what is left of the value goes.
    let long_name = format!("{}{EMAIL}", "a".repeat(MAX_NAME_BYTES - 10));
    let cut = text_from_wire(long_name.as_bytes(), MAX_NAME_BYTES);
    assert!(cut.ends_with(&format!("svc.backup{mark}")));
    let clean = redactor.text(&cut).into_owned();
    assert_eq!(
        clean,
        format!("{}{REDACTED}{mark}", "a".repeat(MAX_NAME_BYTES - 10))
    );
    assert!(!clean.contains("svc."));

    // The same in hexadecimal, and in another letter case.
    assert_eq!(
        redactor.text(&format!("\\x{}{mark}", &EMAIL_HEX[..20])),
        format!("\\x{REDACTED}{mark}")
    );
    assert_eq!(
        redactor.text(&format!("x CANARY.INV{mark}")),
        format!("x {REDACTED}{mark}")
    );
    // All of a value but its last byte.
    assert_eq!(
        redactor.text(&format!("{}{mark}", &EMAIL[..EMAIL.len() - 1])),
        format!("{REDACTED}{mark}")
    );

    // A beginning shorter than four bytes tells nothing and stays.
    assert_eq!(
        redactor.text(&format!("x svc{mark}")),
        format!("x svc{mark}")
    );
    assert_eq!(
        redactor.text(&format!("x svc.{mark}")),
        format!("x {REDACTED}{mark}")
    );
    // Something that is not the beginning of a value stays.
    assert_eq!(
        redactor.text(&format!("backup.8f3k{mark}")),
        format!("backup.8f3k{mark}")
    );
    // And so does the beginning of a value in a text that was not cut:
    // that is all its sender wrote.
    assert_eq!(redactor.text("x svc.backup"), "x svc.backup");
    // The mark by itself is no cut value.
    assert_eq!(redactor.text(&mark.to_string()), mark.to_string());

    // A whole value before the cut is found as any other.
    assert_eq!(
        redactor.text(&format!("{EMAIL}{mark}")),
        format!("{REDACTED}{mark}")
    );
    // A whole value and then the beginning of another.
    assert_eq!(
        redactor.text(&format!("{EMAIL} Canary.In{mark}")),
        format!("{REDACTED} {REDACTED}{mark}")
    );
}

#[test]
fn another_text_that_must_not_be_shown_is_removed_too() {
    let redactor = redactor();
    assert_eq!(
        redactor.text(&format!("cannot reach {URL}: refused")),
        "cannot reach [redacted]: refused"
    );
    // Only the text as it was given: a part of it is not looked for.
    assert_eq!(
        redactor.text("https://alerts.example.com/"),
        "https://alerts.example.com/"
    );

    // A text that is too short to look for is not taken.
    let short = Redactor::builder().secret_text("/hook").build().unwrap();
    assert!(short.is_empty());
    assert_eq!(short.text("POST /hook"), "POST /hook");
    // Given twice, it is one text.
    let twice = Redactor::builder()
        .secret_text(URL)
        .secret_text(URL)
        .build()
        .unwrap();
    assert_eq!(
        format!("{twice:?}"),
        "Redactor { tokens: 0, other_texts: 1 }"
    );
}

fn body() -> EventBody {
    let origin = SessionOrigin::new(
        SessionId::from_u128(1),
        IpAddr::V4(Ipv4Addr::new(192, 0, 2, 10)),
        49_152,
        true,
    );
    EventBody::new(EventKind::TokenHit, &origin)
}

#[test]
fn every_text_of_an_event_that_comes_from_the_network_is_redacted() {
    let mut event = body();
    event.db_user = Some(EMAIL.to_owned());
    event.database = Some(format!("db-{EMAIL}"));
    event.application_name = Some(format!("app {CANARY} v2"));
    let mut query = Query::full(format!("SELECT '{EMAIL}'"));
    query.fingerprint = Some("f00d".to_owned());
    query.normalized = Some(format!("SELECT '{EMAIL}' -- normalised"));
    event.query = Some(query);

    redactor().event(&mut event);

    assert_eq!(event.db_user.as_deref(), Some(REDACTED));
    assert_eq!(event.database.as_deref(), Some("db-[redacted]"));
    assert_eq!(event.application_name.as_deref(), Some("app [redacted] v2"));
    let query = event.query.as_ref().unwrap();
    assert_eq!(query.text.as_deref(), Some("SELECT '[redacted]'"));
    assert_eq!(
        query.normalized.as_deref(),
        Some("SELECT '[redacted]' -- normalised")
    );
    assert_eq!(query.fingerprint.as_deref(), Some("f00d"));

    let json = serde_json::to_string(&event).unwrap();
    assert!(!json.contains("svc.backup"), "{json}");
    assert!(!json.contains("Canary"), "{json}");

    // An event with nothing to remove stays as it is.
    let mut clean = body();
    clean.db_user = Some("app".to_owned());
    let before = clean.clone();
    redactor().event(&mut clean);
    assert_eq!(clean, before);
}

#[test]
fn a_label_is_plain_bounded_and_redacted() {
    let redactor = redactor();
    assert_eq!(redactor.label("webhook-0"), "webhook-0");
    assert_eq!(redactor.label("users-admin-backup"), "users-admin-backup");
    assert_eq!(redactor.label("eu.west_2:a"), "eu.west_2:a");
    // What could break the format of the metrics does not get through.
    assert_eq!(redactor.label("a\"b\\c\nd{e}=f g\u{e9}"), "a_b_c_d_e__f_g_");
    assert_eq!(redactor.label(""), "");
    assert_eq!(redactor.label(&"n".repeat(1000)).len(), MAX_LABEL_BYTES);
    // A value never becomes a label.
    assert_eq!(redactor.label(EMAIL), "_redacted_");
    assert_eq!(redactor.label(&format!("sink-{CANARY}")), "sink-_redacted_");
}

#[test]
fn a_handle_gives_every_holder_the_redactor_in_force() {
    let redaction = Redaction::default();
    let other = redaction.clone();
    assert!(redaction.current().is_empty());
    assert_eq!(other.text(EMAIL), EMAIL);

    redaction.replace(redactor());
    assert_eq!(other.text(EMAIL), REDACTED);
    assert_eq!(other.label(EMAIL), "_redacted_");
    assert!(!other.current().is_empty());

    other.replace(Redactor::nothing());
    assert_eq!(redaction.text(EMAIL), EMAIL);

    let fresh = Redaction::new(redactor());
    assert_eq!(fresh.text(CANARY), REDACTED);
}

#[test]
fn nothing_about_a_redactor_shows_a_value() {
    let builder = Redactor::builder()
        .token("users-admin-backup", [EMAIL], false)
        .secret_text(URL);
    let shown = format!("{builder:?}");
    assert_eq!(shown, "RedactorBuilder { tokens: 1, other_texts: 1 }");

    let redactor = redactor();
    assert_eq!(
        format!("{redactor:?}"),
        "Redactor { tokens: 2, other_texts: 1 }"
    );
    let redaction = Redaction::new(redactor);
    let shown = format!("{redaction:?}");
    assert!(!shown.contains("svc.backup"), "{shown}");
    assert!(!shown.contains("S3cret"), "{shown}");
}

#[test]
fn tokens_the_matcher_refuses_are_refused_without_showing_a_value() {
    for builder in [
        // Too short for a value.
        Redactor::builder().token("short", ["2short"], false),
        // The same value twice.
        Redactor::builder()
            .token("first", [EMAIL], false)
            .token("second", [EMAIL], false),
        // A value inside another.
        Redactor::builder().token("inner", [EMAIL], false).token(
            "outer",
            ["prefix-svc.backup.8f3k2q@mail.example-suffix"],
            false,
        ),
    ] {
        let error = builder.build().unwrap_err();
        assert!(matches!(error, RedactError::Tokens(_)));
        let shown = format!("{error} {error:?}");
        assert!(!shown.contains("svc.backup"), "{shown}");
        assert!(!shown.contains("2short"), "{shown}");
    }
}

/// Text a client could send as a name: anything, with a value somewhere.
fn text_with(value: &'static str) -> impl Strategy<Value = String> {
    (".{0,40}", ".{0,40}").prop_map(move |(before, after)| format!("{before}{value}{after}"))
}

proptest! {
    #[test]
    fn a_value_never_survives_whatever_surrounds_it(
        text in prop_oneof![text_with(EMAIL), text_with(EMAIL_HEX), text_with(CANARY)],
    ) {
        let clean = redactor().text(&text).into_owned();
        prop_assert!(!clean.contains(EMAIL), "{clean}");
        prop_assert!(!clean.contains(EMAIL_HEX), "{clean}");
        prop_assert!(!clean.to_lowercase().contains(&CANARY.to_lowercase()), "{clean}");
        prop_assert!(clean.contains(REDACTED));
    }

    #[test]
    fn a_cut_value_never_survives_wherever_the_cut_falls(
        before in "[a-z ]{0,300}",
        limit in 0usize..400,
    ) {
        let name = format!("{before}{EMAIL}");
        let cut = text_from_wire(name.as_bytes(), limit);
        let clean = redactor().text(&cut).into_owned();
        // No four bytes from the beginning of the value are left at the cut.
        let shown = clean.strip_suffix(TRUNCATION_MARK).unwrap_or(&clean);
        for length in MIN_CUT_VALUE_BYTES..=EMAIL.len() {
            prop_assert!(!shown.ends_with(&EMAIL[..length]), "{clean}");
        }
        prop_assert!(!clean.contains(EMAIL));
    }

    #[test]
    fn text_without_a_value_is_never_changed(text in "[ -~]{0,200}") {
        prop_assume!(!text.contains(EMAIL) && !text.contains(EMAIL_HEX));
        prop_assume!(!text.to_lowercase().contains(&CANARY.to_lowercase()));
        prop_assume!(!text.contains(URL));
        prop_assert_eq!(redactor().text(&text), text.as_str());
    }

    #[test]
    fn a_label_is_always_plain_and_bounded(name in ".{0,300}") {
        let label = redactor().label(&name);
        prop_assert!(label.len() <= MAX_LABEL_BYTES);
        let plain = label
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'.' | b'_' | b':' | b'-'));
        prop_assert!(plain, "{label}");
    }
}
