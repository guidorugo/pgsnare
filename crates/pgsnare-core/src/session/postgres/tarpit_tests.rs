// SPDX-License-Identifier: Apache-2.0

//! Tests of `tarpit`: the session goes on, each batch for the client is
//! held back for a jittered delay, and the number and the time of
//! tarpitted sessions are bounded, past which the session is killed.

use core::time::Duration;
use std::sync::Arc;

use pgsnare_proto::encode;

use crate::actions::TarpitPlaces;
use crate::bait::{Entropy, EntropyError};
use crate::detect::{Matcher, TokenSpec};
use crate::extension::{ProtocolSession as _, Relay};
use crate::policy::{
    Action, ActionSet, ActionSettings, Escalation, Inspection, OnError, PolicySnapshot,
    TarpitSettings, TokenId, TokenPolicy,
};
use crate::session::{Effect, Leg, Output, Report};

use super::messages::admin_shutdown;
use super::scan_tests::{
    CANARY, CANARY_ID, EMAIL, EMAIL_ID, Harness, LIMIT, data_row, digest, frame, join, origin,
    startup,
};
use super::{Postgres, Responses};

const PROCESS_ID: i32 = 4242;
const KEY: [u8; 4] = [9, 8, 7, 6];
const MIN: Duration = Duration::from_millis(2_000);
const MAX: Duration = Duration::from_millis(30_000);
const LONGEST: Duration = Duration::from_secs(600);

/// Bytes that change at every call.
pub(super) struct Counting(pub(super) u64);

impl Entropy for Counting {
    fn fill(&mut self, dest: &mut [u8]) -> Result<(), EntropyError> {
        for byte in dest.iter_mut() {
            // xorshift: no short period.
            self.0 ^= self.0 << 13;
            self.0 ^= self.0 >> 7;
            self.0 ^= self.0 << 17;
            *byte = self.0.to_le_bytes()[0];
        }
        Ok(())
    }
}

fn set(actions: &[Action]) -> ActionSet {
    ActionSet::of(actions)
}

fn tarpit_settings(max_sessions: u32, rate: Option<u64>) -> TarpitSettings {
    TarpitSettings::new(MIN, MAX, LONGEST, max_sessions, rate)
}

/// `EMAIL` is answered with `email`, `CANARY` with `canary`.
fn policy(email: TokenPolicy, canary: ActionSet, tarpit: TarpitSettings) -> PolicySnapshot {
    let specs = [
        TokenSpec::new(EMAIL_ID, [EMAIL]),
        TokenSpec::new(CANARY_ID, [CANARY]),
    ];
    let mut canary_token = TokenPolicy::new(TokenId::new(CANARY_ID).unwrap());
    canary_token.actions = canary;
    PolicySnapshot::builder()
        .inspection(Inspection::new(OnError::FailClosed, LIMIT))
        .tokens([email, canary_token])
        .actions(ActionSettings {
            tarpit,
            ..ActionSettings::default()
        })
        .matcher(Matcher::build(&specs).unwrap())
        .build()
        .unwrap()
}

fn email(actions: ActionSet) -> TokenPolicy {
    let mut token = TokenPolicy::new(TokenId::new(EMAIL_ID).unwrap());
    token.actions = actions;
    token
}

/// A session that answers with `tarpit` and was given a cancel key.
pub(super) fn session_in(places: &Arc<TarpitPlaces>, policy: PolicySnapshot) -> Harness {
    let responses = Responses::new(
        || -> Box<dyn Entropy + Send> { Box::new(Counting(3)) },
        Arc::clone(places),
    );
    let module = Postgres::responding(Arc::new(digest), responses);
    let mut harness = Harness::with_policy(policy);
    harness.session = module.session(origin(), Arc::new(Relay));
    harness.client(&startup(&[(b"user", b"app"), (b"database", b"shop")]));
    let mut out = Output::new();
    harness
        .session
        .on_report(
            Report::BackendConnected { tls: false },
            &harness.policy,
            &mut out,
        )
        .unwrap();
    let mut key = PROCESS_ID.to_be_bytes().to_vec();
    key.extend_from_slice(&KEY);
    harness.server(&join(&[
        &frame(b'R', &0u32.to_be_bytes()),
        &frame(b'K', &key),
        &frame(b'Z', b"I"),
    ]));
    assert!(harness.session.is_established());
    harness.to_client.clear();
    harness.to_server.clear();
    harness.effects.clear();
    harness
}

fn tarpitted(places: &Arc<TarpitPlaces>) -> Harness {
    session_in(
        places,
        policy(
            email(set(&[Action::Tarpit])),
            ActionSet::ALERT,
            tarpit_settings(2, None),
        ),
    )
}

fn fatal() -> Vec<u8> {
    let mut bytes = Vec::new();
    admin_shutdown(&mut bytes).unwrap();
    bytes
}

fn cancel() -> Vec<u8> {
    let mut bytes = Vec::new();
    encode::cancel_request(PROCESS_ID, &KEY, &mut bytes).unwrap();
    bytes
}

fn delays(effects: &[Effect]) -> Vec<Duration> {
    effects
        .iter()
        .filter_map(|effect| match effect {
            Effect::Delay(delay) => Some(*delay),
            _ => None,
        })
        .collect()
}

/// The responses carried out for each hit, in order.
fn carried_out(effects: &[Effect]) -> Vec<ActionSet> {
    effects
        .iter()
        .filter_map(|effect| match effect {
            Effect::TokenHit { actions, .. } => Some(*actions),
            _ => None,
        })
        .collect()
}

fn event_actions(effects: &[Effect]) -> Vec<ActionSet> {
    effects
        .iter()
        .filter_map(|effect| match effect {
            Effect::Emit(body) if body.token_id.is_some() => Some(body.action_taken),
            _ => None,
        })
        .collect()
}

#[test]
fn a_tarpitted_session_goes_on_with_each_batch_held_back_within_the_range() {
    let places = Arc::new(TarpitPlaces::new());
    let mut harness = tarpitted(&places);
    let row = data_row(EMAIL.as_bytes());
    harness.server(&row);

    let effects = std::mem::take(&mut harness.effects);
    assert_eq!(carried_out(&effects), [set(&[Action::Tarpit])]);
    assert_eq!(event_actions(&effects), [set(&[Action::Tarpit])]);
    assert!(effects.contains(&Effect::Tarpit {
        max_duration: LONGEST
    }));
    assert_eq!(harness.to_client, row, "the row goes on");
    assert_eq!(places.held(), 1);

    let mut all = delays(&effects);
    assert_eq!(all.len(), 1, "one delay for the batch");
    // Every later batch for the client is held back too, and nothing the
    // client sends is.
    for _ in 0..50 {
        harness.server(&data_row(b"plain"));
        harness.client(&frame(b'Q', b"select 1\0"));
        all.extend(delays(&std::mem::take(&mut harness.effects)));
    }
    assert_eq!(all.len(), 51);
    for delay in &all {
        assert!(*delay >= MIN && *delay <= MAX, "{delay:?}");
    }
    let distinct: std::collections::BTreeSet<_> = all.iter().collect();
    assert!(distinct.len() > 40, "the delays look periodic: {all:?}");
}

#[test]
fn a_session_is_tarpitted_once_and_holds_one_place_until_it_ends() {
    let places = Arc::new(TarpitPlaces::new());
    let mut harness = tarpitted(&places);
    harness.server(&data_row(EMAIL.as_bytes()));
    harness.server(&data_row(EMAIL.as_bytes()));
    let starts = harness
        .effects
        .iter()
        .filter(|effect| matches!(effect, Effect::Tarpit { .. }))
        .count();
    assert_eq!(starts, 1);
    assert_eq!(places.held(), 1);
    drop(harness);
    assert_eq!(places.held(), 0, "the place is given back");
}

#[test]
fn a_rate_cap_holds_a_batch_as_long_as_its_size_asks() {
    let places = Arc::new(TarpitPlaces::new());
    let mut harness = session_in(
        &places,
        policy(
            email(set(&[Action::Tarpit])),
            ActionSet::ALERT,
            tarpit_settings(2, Some(100)),
        ),
    );
    harness.server(&data_row(EMAIL.as_bytes()));
    harness.effects.clear();
    // 40 rows of 15 bytes each, 600 bytes: 6 s at 100 bytes a second.
    let rows: Vec<u8> = (0..40).flat_map(|_| data_row(b"0123")).collect();
    assert_eq!(rows.len(), 600);
    harness.server(&rows);
    let all = delays(&harness.effects);
    assert_eq!(all.len(), 1);
    assert!(all[0] >= Duration::from_secs(6), "{all:?}");
}

#[test]
fn when_every_place_is_taken_the_session_is_killed_not_held() {
    let places = Arc::new(TarpitPlaces::new());
    let mut first = tarpitted(&places);
    let mut second = tarpitted(&places);
    first.server(&data_row(EMAIL.as_bytes()));
    second.server(&data_row(EMAIL.as_bytes()));
    assert_eq!(places.held(), 2);

    let mut third = tarpitted(&places);
    third.server(&data_row(EMAIL.as_bytes()));
    let effects = std::mem::take(&mut third.effects);
    assert_eq!(carried_out(&effects), [set(&[Action::Kill])]);
    assert_eq!(event_actions(&effects), [set(&[Action::Kill])]);
    assert_eq!(third.to_client, fatal(), "the row never reaches the client");
    assert!(delays(&effects).is_empty(), "nothing waits before a kill");
    assert!(effects.contains(&Effect::Cancel { request: cancel() }));
    assert!(effects.contains(&Effect::Close(Leg::Client)));
    assert!(effects.contains(&Effect::Close(Leg::Backend)));
    assert_eq!(places.held(), 2);
}

#[test]
fn past_the_longest_time_the_session_is_killed_at_once() {
    let places = Arc::new(TarpitPlaces::new());
    let mut harness = tarpitted(&places);
    harness.server(&data_row(EMAIL.as_bytes()));
    harness.to_client.clear();
    harness.effects.clear();

    let mut out = Output::new();
    harness
        .session
        .on_report(Report::TarpitOver, &harness.policy, &mut out)
        .unwrap();
    assert_eq!(out.to_client, fatal());
    assert_eq!(
        out.effects,
        [
            Effect::Cancel { request: cancel() },
            Effect::Close(Leg::Client),
            Effect::Close(Leg::Backend),
        ]
    );
    // Nothing more goes through.
    harness.server(&data_row(b"later"));
    assert!(harness.to_client.is_empty());
    assert!(harness.session.is_closed());
}

#[test]
fn a_scanner_without_responses_answers_tarpit_with_alert() {
    let mut harness = Harness::logged_in(
        policy(
            email(set(&[Action::Tarpit])),
            ActionSet::ALERT,
            tarpit_settings(2, None),
        ),
        &[(b"user", b"app")],
    );
    harness.effects.clear();
    harness.server(&data_row(EMAIL.as_bytes()));
    assert_eq!(carried_out(&harness.effects), [ActionSet::ALERT]);
    assert!(delays(&harness.effects).is_empty());
}

#[test]
fn kill_with_tarpit_kills_and_takes_no_place() {
    let places = Arc::new(TarpitPlaces::new());
    let mut harness = session_in(
        &places,
        policy(
            email(set(&[Action::Tarpit, Action::Kill, Action::Alert])),
            ActionSet::ALERT,
            tarpit_settings(2, None),
        ),
    );
    harness.server(&data_row(EMAIL.as_bytes()));
    assert_eq!(
        carried_out(&harness.effects),
        [set(&[Action::Kill, Action::Alert])]
    );
    assert_eq!(harness.to_client, fatal());
    assert_eq!(places.held(), 0);
}

#[test]
fn alert_and_tarpit_are_both_carried_out() {
    let places = Arc::new(TarpitPlaces::new());
    let mut harness = session_in(
        &places,
        policy(
            email(set(&[Action::Tarpit, Action::Alert])),
            ActionSet::ALERT,
            tarpit_settings(2, None),
        ),
    );
    harness.server(&data_row(EMAIL.as_bytes()));
    assert_eq!(
        event_actions(&harness.effects),
        [set(&[Action::Tarpit, Action::Alert])]
    );
    assert_eq!(delays(&harness.effects).len(), 1);
}

#[test]
fn escalation_turns_tarpit_into_kill() {
    let places = Arc::new(TarpitPlaces::new());
    let mut token = email(set(&[Action::Tarpit]));
    token.escalate = Some(Escalation::new(2, set(&[Action::Kill])));
    let mut harness = session_in(
        &places,
        policy(token, ActionSet::ALERT, tarpit_settings(2, None)),
    );
    harness.server(&data_row(EMAIL.as_bytes()));
    harness.server(&data_row(EMAIL.as_bytes()));
    assert_eq!(
        carried_out(&harness.effects),
        [set(&[Action::Tarpit]), set(&[Action::Kill])]
    );
    assert!(harness.to_client.ends_with(&fatal()));
    assert!(harness.session.is_closed());
}

#[test]
fn a_hit_of_another_token_in_a_tarpitted_session_only_alerts() {
    let places = Arc::new(TarpitPlaces::new());
    let mut harness = tarpitted(&places);
    harness.server(&data_row(EMAIL.as_bytes()));
    harness.effects.clear();
    harness.server(&data_row(CANARY.as_bytes()));
    assert_eq!(carried_out(&harness.effects), [ActionSet::ALERT]);
    assert_eq!(delays(&harness.effects).len(), 1, "still tarpitted");
}
