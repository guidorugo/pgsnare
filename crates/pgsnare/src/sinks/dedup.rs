// SPDX-License-Identifier: Apache-2.0

//! Folding repeated hits into one event.
//!
//! A session that reads a honeytoken a thousand times is one piece of news,
//! not a thousand. The dispatcher therefore reports the first hit of a
//! token in a session at once and folds the ones that follow:
//!
//! - **A window opens with the first hit**, which is delivered as it is.
//!   The window closes after the time the configuration gives.
//! - **A hit inside the window is folded.** It is not delivered, and it is
//!   counted.
//! - **When the window closes, one event reports what was folded**: the
//!   last of those hits, with their number as its `hit_count`. A window in
//!   which nothing was folded reports nothing.
//! - **A hit after that opens a new window.**
//!
//! The first event is never held back, so deduplication costs an alert no
//! time. Adding up the `hit_count` of every event of a session and a token
//! gives the number of hits.
//!
//! # What counts as a repetition
//!
//! A hit of the same token in the same session, answered with the same
//! responses. A hit that was answered differently, for example because the
//! response escalated, is news: what was folded so far is reported, the
//! hit is delivered at once, and the window goes on with its responses.
//!
//! Only `token_hit` events are folded. Every other event is delivered as
//! it is.
//!
//! # Bounded
//!
//! There are at most [`MAX_WINDOWS`] windows. A hit that would need one
//! more is delivered as it is: a full table costs events that could have
//! been folded, and never an event.

use std::collections::{HashMap, VecDeque};
use std::time::Duration;

use pgsnare_core::event::{EventBody, EventKind, SessionId, Timestamp};
use pgsnare_core::policy::{ActionSet, TokenId};
use tokio::time::Instant;

/// The most windows that are open at once.
pub(super) const MAX_WINDOWS: usize = 4096;

/// An event as a session raised it, and when.
#[derive(Clone, Debug, PartialEq, Eq)]
pub(super) struct Raised {
    pub(super) body: Box<EventBody>,
    pub(super) at: Timestamp,
}

#[derive(Clone, Debug, PartialEq, Eq, Hash)]
struct Key {
    session: SessionId,
    token: TokenId,
}

struct Window {
    closes: Instant,
    /// The responses of the hit that was delivered last.
    actions: ActionSet,
    /// How many hits were folded since.
    folded: u64,
    /// The last of them.
    last: Option<Raised>,
}

impl Window {
    /// The event that reports what was folded, if anything was.
    fn report(&mut self) -> Option<Raised> {
        let mut last = self.last.take()?;
        last.body.hit_count = std::mem::take(&mut self.folded);
        Some(last)
    }
}

/// The open windows.
pub(super) struct Dedup {
    window: Duration,
    windows: HashMap<Key, Window>,
    /// The keys in the order their windows close, which is the order they
    /// were opened in.
    order: VecDeque<Key>,
}

impl Dedup {
    /// With a window of zero, nothing is ever folded.
    pub(super) fn new(window: Duration) -> Self {
        Self {
            window,
            windows: HashMap::new(),
            order: VecDeque::new(),
        }
    }

    /// Takes an event and appends what is to be delivered now to `out`.
    /// Returns whether the event was folded.
    pub(super) fn take(&mut self, raised: Raised, now: Instant, out: &mut Vec<Raised>) -> bool {
        self.close_due(now, out);

        let key = match (&raised.body.kind, &raised.body.token_id) {
            (EventKind::TokenHit, Some(token)) if !self.window.is_zero() => Key {
                session: raised.body.session_id,
                token: token.clone(),
            },
            _ => {
                out.push(raised);
                return false;
            }
        };

        if let Some(window) = self.windows.get_mut(&key) {
            if window.actions == raised.body.action_taken {
                window.folded = window.folded.saturating_add(raised.body.hit_count);
                window.last = Some(raised);
                return true;
            }
            // Answered differently: that is news.
            out.extend(window.report());
            window.actions = raised.body.action_taken;
            out.push(raised);
            return false;
        }

        if self.windows.len() < MAX_WINDOWS {
            self.windows.insert(
                key.clone(),
                Window {
                    closes: now + self.window,
                    actions: raised.body.action_taken,
                    folded: 0,
                    last: None,
                },
            );
            self.order.push_back(key);
        }
        out.push(raised);
        false
    }

    /// Closes the windows whose time is over and appends what they report
    /// to `out`.
    pub(super) fn close_due(&mut self, now: Instant, out: &mut Vec<Raised>) {
        while let Some(key) = self.order.front() {
            let due = self
                .windows
                .get(key)
                .is_none_or(|window| window.closes <= now);
            if !due {
                break;
            }
            if let Some(key) = self.order.pop_front()
                && let Some(mut window) = self.windows.remove(&key)
            {
                out.extend(window.report());
            }
        }
    }

    /// The moment the next window closes.
    pub(super) fn next_close(&self) -> Option<Instant> {
        let key = self.order.front()?;
        self.windows.get(key).map(|window| window.closes)
    }

    /// Closes every window, whatever its time, and appends what they
    /// report to `out`. This is for a dispatcher that stops.
    pub(super) fn close_all(&mut self, out: &mut Vec<Raised>) {
        while let Some(key) = self.order.pop_front() {
            if let Some(mut window) = self.windows.remove(&key) {
                out.extend(window.report());
            }
        }
    }

    #[cfg(test)]
    pub(super) fn open_windows(&self) -> usize {
        self.windows.len()
    }
}

#[cfg(test)]
mod tests {
    use std::net::{IpAddr, Ipv4Addr};

    use pgsnare_core::policy::Action;
    use pgsnare_core::session::SessionOrigin;

    use super::*;

    const WINDOW: Duration = Duration::from_secs(60);

    fn body(kind: EventKind, session: u128, token: Option<&str>) -> Box<EventBody> {
        let origin = SessionOrigin::new(
            SessionId::from_u128(session),
            IpAddr::V4(Ipv4Addr::new(192, 0, 2, 10)),
            49_152,
            true,
        );
        let mut body = EventBody::new(kind, &origin);
        body.token_id = token.map(|id| TokenId::new(id).unwrap());
        body.action_taken = ActionSet::ALERT;
        Box::new(body)
    }

    /// A hit of a token in a session. `row` tells the hits of a test apart.
    fn hit(session: u128, token: &str, row: u64) -> Raised {
        let mut body = body(EventKind::TokenHit, session, Some(token));
        body.rows_so_far = Some(row);
        Raised {
            body,
            at: Timestamp::from_unix_micros(row).unwrap(),
        }
    }

    /// What a test saw delivered: the row and the hit count of each event.
    fn seen(out: &[Raised]) -> Vec<(u64, u64)> {
        out.iter()
            .map(|raised| (raised.body.rows_so_far.unwrap(), raised.body.hit_count))
            .collect()
    }

    #[tokio::test(start_paused = true)]
    async fn the_first_hit_goes_out_at_once_and_the_rest_of_the_window_is_one_event() {
        let start = Instant::now();
        let mut dedup = Dedup::new(WINDOW);
        let mut out = Vec::new();

        assert!(!dedup.take(hit(1, "users-admin-backup", 1), start, &mut out));
        assert_eq!(seen(&out), [(1, 1)]);
        assert_eq!(dedup.next_close(), Some(start + WINDOW));

        // Five more inside the window: nothing is delivered.
        out.clear();
        for row in 2..=6 {
            let now = start + Duration::from_secs(row);
            assert!(dedup.take(hit(1, "users-admin-backup", row), now, &mut out));
        }
        assert!(out.is_empty());

        // Nothing closes before its time.
        dedup.close_due(start + WINDOW - Duration::from_millis(1), &mut out);
        assert!(out.is_empty());

        // When the window closes, one event stands for the five: the last
        // of them, with its own time.
        dedup.close_due(start + WINDOW, &mut out);
        assert_eq!(seen(&out), [(6, 5)]);
        assert_eq!(out[0].at, Timestamp::from_unix_micros(6).unwrap());
        assert_eq!(dedup.open_windows(), 0);
        assert_eq!(dedup.next_close(), None);

        // The next hit is the first of a new window.
        out.clear();
        let later = start + WINDOW + Duration::from_secs(1);
        assert!(!dedup.take(hit(1, "users-admin-backup", 7), later, &mut out));
        assert_eq!(seen(&out), [(7, 1)]);
        assert_eq!(dedup.next_close(), Some(later + WINDOW));
    }

    #[tokio::test(start_paused = true)]
    async fn a_window_in_which_nothing_was_folded_reports_nothing() {
        let start = Instant::now();
        let mut dedup = Dedup::new(WINDOW);
        let mut out = Vec::new();
        dedup.take(hit(1, "users-admin-backup", 1), start, &mut out);
        out.clear();
        dedup.close_due(start + WINDOW, &mut out);
        assert!(out.is_empty());
        assert_eq!(dedup.open_windows(), 0);
    }

    #[tokio::test(start_paused = true)]
    async fn a_hit_that_arrives_after_its_window_closes_it_first() {
        let start = Instant::now();
        let mut dedup = Dedup::new(WINDOW);
        let mut out = Vec::new();
        dedup.take(hit(1, "users-admin-backup", 1), start, &mut out);
        dedup.take(hit(1, "users-admin-backup", 2), start, &mut out);
        out.clear();

        // No timer ran in between. The late hit still finds its window
        // closed: first the report of the old one, then the hit itself.
        let later = start + WINDOW * 2;
        assert!(!dedup.take(hit(1, "users-admin-backup", 3), later, &mut out));
        assert_eq!(seen(&out), [(2, 1), (3, 1)]);
    }

    #[tokio::test(start_paused = true)]
    async fn sessions_and_tokens_are_kept_apart() {
        let start = Instant::now();
        let mut dedup = Dedup::new(WINDOW);
        let mut out = Vec::new();

        assert!(!dedup.take(hit(1, "users-admin-backup", 1), start, &mut out));
        assert!(!dedup.take(hit(2, "users-admin-backup", 2), start, &mut out));
        assert!(!dedup.take(hit(1, "card-test-0002", 3), start, &mut out));
        assert_eq!(seen(&out), [(1, 1), (2, 1), (3, 1)]);
        assert_eq!(dedup.open_windows(), 3);

        out.clear();
        assert!(dedup.take(hit(2, "users-admin-backup", 4), start, &mut out));
        assert!(dedup.take(hit(1, "card-test-0002", 5), start, &mut out));
        assert!(dedup.take(hit(1, "card-test-0002", 6), start, &mut out));
        assert!(out.is_empty());

        dedup.close_due(start + WINDOW, &mut out);
        assert_eq!(seen(&out), [(4, 1), (6, 2)]);
    }

    #[tokio::test(start_paused = true)]
    async fn a_hit_that_was_answered_differently_is_not_a_repetition() {
        let start = Instant::now();
        let mut dedup = Dedup::new(WINDOW);
        let mut out = Vec::new();

        dedup.take(hit(1, "users-admin-backup", 1), start, &mut out);
        dedup.take(hit(1, "users-admin-backup", 2), start, &mut out);
        dedup.take(hit(1, "users-admin-backup", 3), start, &mut out);
        assert_eq!(seen(&out), [(1, 1)]);

        // The third repetition is answered with a kill.
        out.clear();
        let mut escalated = hit(1, "users-admin-backup", 4);
        escalated.body.action_taken = ActionSet::of(&[Action::Alert, Action::Kill]);
        assert!(!dedup.take(escalated.clone(), start, &mut out));
        // What was folded so far is reported, and then the kill, at once.
        assert_eq!(seen(&out), [(3, 2), (4, 1)]);
        assert!(out[1].body.action_taken.contains(Action::Kill));

        // A kill after a kill is a repetition again, in the same window.
        out.clear();
        let mut again = escalated;
        again.body.rows_so_far = Some(5);
        assert!(dedup.take(again, start + Duration::from_secs(1), &mut out));
        assert!(out.is_empty());
        assert_eq!(dedup.next_close(), Some(start + WINDOW));
        dedup.close_due(start + WINDOW, &mut out);
        assert_eq!(seen(&out), [(5, 1)]);
    }

    #[tokio::test(start_paused = true)]
    async fn the_hit_count_of_a_folded_event_is_added_not_counted() {
        let start = Instant::now();
        let mut dedup = Dedup::new(WINDOW);
        let mut out = Vec::new();
        dedup.take(hit(1, "users-admin-backup", 1), start, &mut out);
        let mut many = hit(1, "users-admin-backup", 2);
        many.body.hit_count = 40;
        dedup.take(many, start, &mut out);
        dedup.take(hit(1, "users-admin-backup", 3), start, &mut out);
        out.clear();
        dedup.close_all(&mut out);
        assert_eq!(seen(&out), [(3, 41)]);
    }

    #[tokio::test(start_paused = true)]
    async fn only_token_hits_are_folded() {
        let start = Instant::now();
        let mut dedup = Dedup::new(WINDOW);
        let mut out = Vec::new();
        for kind in [
            EventKind::RuleHit,
            EventKind::ParseFailure,
            EventKind::SessionActivity,
            EventKind::InspectionBypassed,
        ] {
            for _ in 0..3 {
                let raised = Raised {
                    body: body(kind, 1, Some("users-admin-backup")),
                    at: Timestamp::UNIX_EPOCH,
                };
                assert!(!dedup.take(raised, start, &mut out));
            }
        }
        // A token hit that names no token cannot be told from another.
        for _ in 0..3 {
            let raised = Raised {
                body: body(EventKind::TokenHit, 1, None),
                at: Timestamp::UNIX_EPOCH,
            };
            assert!(!dedup.take(raised, start, &mut out));
        }
        assert_eq!(out.len(), 15);
        assert_eq!(dedup.open_windows(), 0);
    }

    #[tokio::test(start_paused = true)]
    async fn a_window_of_zero_turns_deduplication_off() {
        let start = Instant::now();
        let mut dedup = Dedup::new(Duration::ZERO);
        let mut out = Vec::new();
        for row in 1..=3 {
            assert!(!dedup.take(hit(1, "users-admin-backup", row), start, &mut out));
        }
        assert_eq!(seen(&out), [(1, 1), (2, 1), (3, 1)]);
        assert_eq!(dedup.open_windows(), 0);
        assert_eq!(dedup.next_close(), None);
    }

    #[tokio::test(start_paused = true)]
    async fn a_full_table_costs_folding_and_never_an_event() {
        let start = Instant::now();
        let mut dedup = Dedup::new(WINDOW);
        let mut out = Vec::new();
        for session in 0..MAX_WINDOWS {
            dedup.take(
                hit(session as u128, "users-admin-backup", 1),
                start,
                &mut out,
            );
        }
        assert_eq!(out.len(), MAX_WINDOWS);
        assert_eq!(dedup.open_windows(), MAX_WINDOWS);

        // One session too many: each of its hits is delivered.
        out.clear();
        let extra = MAX_WINDOWS as u128;
        for row in 1..=3 {
            assert!(!dedup.take(hit(extra, "users-admin-backup", row), start, &mut out));
        }
        assert_eq!(seen(&out), [(1, 1), (2, 1), (3, 1)]);
        assert_eq!(dedup.open_windows(), MAX_WINDOWS);

        // The sessions that have a window are still folded.
        out.clear();
        assert!(dedup.take(hit(0, "users-admin-backup", 2), start, &mut out));
        assert!(out.is_empty());

        // And once the windows have closed there is room again.
        let later = start + WINDOW;
        assert!(!dedup.take(hit(extra, "users-admin-backup", 4), later, &mut out));
        assert_eq!(seen(&out), [(2, 1), (4, 1)]);
        assert_eq!(dedup.open_windows(), 1);
        out.clear();
        assert!(dedup.take(hit(extra, "users-admin-backup", 5), later, &mut out));
    }

    #[tokio::test(start_paused = true)]
    async fn closing_everything_reports_what_every_window_holds() {
        let start = Instant::now();
        let mut dedup = Dedup::new(WINDOW);
        let mut out = Vec::new();
        dedup.take(hit(1, "users-admin-backup", 1), start, &mut out);
        dedup.take(hit(1, "users-admin-backup", 2), start, &mut out);
        dedup.take(hit(2, "users-admin-backup", 3), start, &mut out);
        out.clear();
        dedup.close_all(&mut out);
        assert_eq!(seen(&out), [(2, 1)]);
        assert_eq!(dedup.open_windows(), 0);
        dedup.close_all(&mut out);
        assert_eq!(out.len(), 1);
    }
}
