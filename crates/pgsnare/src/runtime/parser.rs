// SPDX-License-Identifier: Apache-2.0

//! The threads that run the SQL parser, and the cache of what they found.
//!
//! The parser is C code that reads what a client sent. It runs here and
//! nowhere else: on a fixed number of named threads with a stack of a
//! chosen size, never on a thread that relays traffic.
//!
//! - **The queue is bounded and never waited on.** [`ParserPool::submit`]
//!   either hands the statement over or answers [`ParseFailure::Busy`] at
//!   once. The answer to a statement that was handed over arrives later,
//!   through the function given with it.
//! - **A panic ends one job, not a thread.** Every analysis runs under
//!   `catch_unwind`, and so does the function that receives the answer.
//! - **The work is bounded.** A statement over the size cap is answered
//!   without being hashed or parsed. At most as many statements are parsed
//!   at once as there are threads, so the memory the parser takes is at
//!   most the number of threads times the size cap times its overhead,
//!   which `pgsnare_core::rules` gives.
//! - **The cache holds analyses, not verdicts.** It is keyed by the SHA-256
//!   of the exact bytes of the statement, so one statement cannot stand in
//!   for another, and it knows nothing about the rules, so a reload does
//!   not need to empty it. It is bounded by entries and by bytes; a client
//!   that sends ever new statements evicts old entries and nothing more.
//!
//! # Who asks
//!
//! A session whose policy has rules asks for the analysis of each
//! statement before the statement is passed on, and holds the statement
//! until the answer is there. `Awaited` is that wait, as the task of the
//! session keeps it: the answer of the pool, or
//! [`ParseFailure::TimedOut`] once the time allowed has passed, whichever
//! comes first. A session therefore never waits for the parser for longer
//! than that time, however long the queue is.

use std::collections::{HashMap, VecDeque};
use std::io;
use std::panic::{self, AssertUnwindSafe};
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::mpsc::{self, Receiver, SyncSender};
use std::sync::{Arc, Mutex, MutexGuard, PoisonError};
use std::time::Duration;

use pgsnare_core::event::StatementDigest;
use pgsnare_core::rules::{
    Analysis, Limits, ParseFailure, ParserThread, analyse, spawn_parser_thread,
};

use pgsnare_core::session::StatementText;
use tokio::sync::oneshot;
use tokio::time::{Instant, sleep_until};

use crate::redact::Sha256;

/// How long a session waits for the analysis of a statement, unless the
/// runtime is told otherwise.
pub const DEFAULT_ANALYSIS_DEADLINE: Duration = Duration::from_secs(5);

/// The answer to one statement: its analysis, shared with the cache, or
/// the reason there is none.
pub type Outcome = Result<Arc<Analysis>, ParseFailure>;

/// How large the pool and its cache are.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[non_exhaustive]
pub struct ParserSettings {
    /// The number of parser threads, at least one. This is also how many
    /// statements are parsed at once.
    pub threads: usize,
    /// How many statements may wait for a thread, at least one.
    pub queue: usize,
    /// The most analyses the cache keeps.
    pub cache_entries: usize,
    /// The most memory the cache takes, in bytes, by its own estimate.
    pub cache_bytes: usize,
}

impl Default for ParserSettings {
    fn default() -> Self {
        Self {
            threads: 2,
            queue: 256,
            cache_entries: 4096,
            cache_bytes: 8 * 1024 * 1024,
        }
    }
}

/// What the pool has done so far.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
#[non_exhaustive]
pub struct ParserStats {
    /// Statements that went through the parser's checks.
    pub analysed: u64,
    /// Statements answered from the cache.
    pub cache_hits: u64,
    /// Statements refused because the queue was full.
    pub busy: u64,
    /// Jobs that panicked.
    pub panicked: u64,
    /// Analyses in the cache right now.
    pub cache_entries: usize,
    /// The cache's estimate of its size right now, in bytes.
    pub cache_bytes: usize,
}

/// One unit of work for a parser thread. It answers by itself.
type Job = Box<dyn FnOnce(&Shared, &ParserThread) + Send>;

/// What the threads share.
struct Shared {
    cache: Mutex<Cache>,
    analysed: AtomicU64,
    cache_hits: AtomicU64,
    busy: AtomicU64,
    panicked: AtomicU64,
}

impl Shared {
    /// The cache. A lock that a panic left poisoned is used all the same:
    /// the cache is consistent after every step of every operation on it
    /// that can panic.
    fn cache(&self) -> MutexGuard<'_, Cache> {
        self.cache.lock().unwrap_or_else(PoisonError::into_inner)
    }

    fn analyse(&self, text: &[u8], limits: &Limits, thread: &ParserThread) -> Outcome {
        // Before anything that takes time in proportion to the text.
        if text.len() > limits.max_bytes {
            return Err(ParseFailure::TooLarge);
        }
        let key = Sha256.digest(text);
        if let Some(found) = self.cache().get(&key, limits) {
            self.cache_hits.fetch_add(1, Ordering::Relaxed);
            return found;
        }
        let outcome = analyse(text, limits, thread).map(Arc::new);
        self.analysed.fetch_add(1, Ordering::Relaxed);
        self.cache().insert(key, limits, outcome.clone());
        outcome
    }
}

/// The parser threads. Dropping the pool lets the threads finish what is
/// queued and end.
pub struct ParserPool {
    jobs: SyncSender<Job>,
    shared: Arc<Shared>,
}

impl ParserPool {
    /// Starts the threads.
    ///
    /// # Errors
    ///
    /// Returns the error of the operating system when a thread cannot be
    /// started. Threads that were started before it end by themselves.
    pub fn start(settings: ParserSettings) -> io::Result<Self> {
        let (jobs, queue) = mpsc::sync_channel::<Job>(settings.queue.max(1));
        let queue = Arc::new(Mutex::new(queue));
        let shared = Arc::new(Shared {
            cache: Mutex::new(Cache::new(settings.cache_entries, settings.cache_bytes)),
            analysed: AtomicU64::new(0),
            cache_hits: AtomicU64::new(0),
            busy: AtomicU64::new(0),
            panicked: AtomicU64::new(0),
        });
        for index in 0..settings.threads.max(1) {
            let queue = Arc::clone(&queue);
            let shared = Arc::clone(&shared);
            spawn_parser_thread(format!("pgsnare-sql-{index}"), move |thread| {
                work(&queue, &shared, thread);
            })?;
        }
        Ok(Self { jobs, shared })
    }

    /// Asks for the analysis of a statement. `reply` is called with it, on
    /// a parser thread, so it must be quick and must not wait: typically
    /// it sends the answer to the task that asked.
    ///
    /// This never waits. The text is not copied: pass something that
    /// shares it.
    ///
    /// # Errors
    ///
    /// Returns [`ParseFailure::Busy`] when the queue is full, or the pool
    /// has no thread left. `reply` is then dropped without being called.
    pub fn submit<T, F>(&self, text: T, limits: Limits, reply: F) -> Result<(), ParseFailure>
    where
        T: AsRef<[u8]> + Send + 'static,
        F: FnOnce(Outcome) + Send + 'static,
    {
        self.enqueue(
            move |shared, thread| shared.analyse(text.as_ref(), &limits, thread),
            reply,
        )
    }

    fn enqueue<W, F>(&self, work: W, reply: F) -> Result<(), ParseFailure>
    where
        W: FnOnce(&Shared, &ParserThread) -> Outcome + Send + 'static,
        F: FnOnce(Outcome) + Send + 'static,
    {
        let job: Job = Box::new(move |shared, thread| {
            let outcome = panic::catch_unwind(AssertUnwindSafe(|| work(shared, thread)))
                .unwrap_or_else(|_| {
                    shared.panicked.fetch_add(1, Ordering::Relaxed);
                    Err(ParseFailure::Panicked)
                });
            // The receiver of the answer must not end the thread either.
            if panic::catch_unwind(AssertUnwindSafe(|| reply(outcome))).is_err() {
                shared.panicked.fetch_add(1, Ordering::Relaxed);
            }
        });
        self.jobs.try_send(job).map_err(|_| {
            self.shared.busy.fetch_add(1, Ordering::Relaxed);
            ParseFailure::Busy
        })
    }

    /// What the pool has done so far.
    #[must_use]
    pub fn stats(&self) -> ParserStats {
        let cache = self.shared.cache();
        ParserStats {
            analysed: self.shared.analysed.load(Ordering::Relaxed),
            cache_hits: self.shared.cache_hits.load(Ordering::Relaxed),
            busy: self.shared.busy.load(Ordering::Relaxed),
            panicked: self.shared.panicked.load(Ordering::Relaxed),
            cache_entries: cache.entries.len(),
            cache_bytes: cache.bytes,
        }
    }
}

/// The analysis one session waits for.
pub(crate) struct Awaited {
    /// The `id` the session logic gave its request.
    pub(crate) id: u64,
    /// When the request was made.
    pub(crate) since: Instant,
    answer: oneshot::Receiver<Outcome>,
    deadline: Instant,
}

impl Awaited {
    /// Asks `pool` for the analysis of `text`, to be answered within
    /// `patience`. This never waits.
    ///
    /// # Errors
    ///
    /// Returns [`ParseFailure::Busy`] when the pool did not take the
    /// statement, or when there is no pool.
    pub(crate) fn ask(
        pool: Option<&ParserPool>,
        id: u64,
        text: StatementText,
        limits: Limits,
        patience: Duration,
    ) -> Result<Self, ParseFailure> {
        let pool = pool.ok_or(ParseFailure::Busy)?;
        let (reply, answer) = oneshot::channel();
        pool.submit(text, limits, move |outcome| {
            // Nobody waits any more when the session has given up or gone.
            let _ = reply.send(outcome);
        })?;
        let since = Instant::now();
        Ok(Self {
            id,
            since,
            answer,
            // A moment the clock cannot name is now.
            deadline: since.checked_add(patience).unwrap_or(since),
        })
    }

    /// Waits for the answer, for as long as was allowed. Dropping the wait
    /// loses nothing: it can be taken up again.
    pub(crate) async fn outcome(&mut self) -> Outcome {
        tokio::select! {
            // The pool only drops a request unanswered when it is gone.
            answer = &mut self.answer => answer.unwrap_or(Err(ParseFailure::Busy)),
            () = sleep_until(self.deadline) => Err(ParseFailure::TimedOut),
        }
    }
}

impl std::fmt::Debug for ParserPool {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("ParserPool")
            .field("stats", &self.stats())
            .finish()
    }
}

/// The loop of one parser thread: take a job, run it, until the pool is
/// gone. A job catches its own panics, so the loop never unwinds.
fn work(queue: &Mutex<Receiver<Job>>, shared: &Shared, thread: &ParserThread) {
    loop {
        // The lock is held while waiting. The other idle threads wait for
        // the lock instead, which comes to the same.
        let job = queue.lock().unwrap_or_else(PoisonError::into_inner).recv();
        match job {
            Ok(job) => job(shared, thread),
            Err(_) => return,
        }
    }
}

/// The digest of a statement.
type Key = [u8; 32];

struct Entry {
    outcome: Outcome,
    /// The cap on nesting the outcome was found under. Another cap could
    /// give another outcome.
    max_depth: u32,
    weight: usize,
    /// Whether the entry was asked for since it was last passed over.
    used: bool,
}

/// What an entry costs beyond its analysis: the key twice, the entry, and
/// an allowance for the tables that hold them.
const ENTRY_OVERHEAD: usize = 2 * size_of::<Key>() + size_of::<Entry>() + 64;

/// How many entries that were recently used an eviction passes over before
/// it takes one anyway. This bounds the work of one insertion.
const MAX_SECOND_CHANCES: usize = 16;

/// Analyses by the digest of their statement, bounded by entries and by
/// bytes. The oldest entry goes first, except that one that was asked for
/// since is passed over once.
struct Cache {
    entries: HashMap<Key, Entry>,
    /// Every key of `entries`, oldest first.
    order: VecDeque<Key>,
    bytes: usize,
    max_entries: usize,
    max_bytes: usize,
}

impl Cache {
    fn new(max_entries: usize, max_bytes: usize) -> Self {
        Self {
            entries: HashMap::new(),
            order: VecDeque::new(),
            bytes: 0,
            max_entries,
            max_bytes,
        }
    }

    /// The outcome kept for a statement, if it answers what `limits` asks.
    fn get(&mut self, key: &Key, limits: &Limits) -> Option<Outcome> {
        let entry = self.entries.get_mut(key)?;
        // An analysis may lack what is asked for now, and another cap on
        // nesting could give another outcome.
        let lacking = entry
            .outcome
            .as_ref()
            .is_ok_and(|analysis| !analysis.covers(limits));
        if lacking || entry.max_depth != limits.max_depth {
            return None;
        }
        entry.used = true;
        Some(entry.outcome.clone())
    }

    fn insert(&mut self, key: Key, limits: &Limits, outcome: Outcome) {
        let weight = outcome
            .as_ref()
            .map_or(0, |analysis| analysis.weight())
            .saturating_add(ENTRY_OVERHEAD);
        // One entry may not take the cache for itself.
        if weight > self.max_bytes / 8 || self.max_entries == 0 {
            return;
        }
        let entry = Entry {
            outcome,
            max_depth: limits.max_depth,
            weight,
            used: false,
        };
        match self.entries.insert(key, entry) {
            // The key keeps its place in the order.
            Some(old) => self.bytes = self.bytes.saturating_sub(old.weight),
            None => self.order.push_back(key),
        }
        self.bytes = self.bytes.saturating_add(weight);

        let mut chances = 0;
        while self.entries.len() > self.max_entries || self.bytes > self.max_bytes {
            let Some(oldest) = self.order.pop_front() else {
                break;
            };
            let spared = oldest != key
                && chances < MAX_SECOND_CHANCES
                && self.entries.get_mut(&oldest).is_some_and(|entry| {
                    let was_used = entry.used;
                    entry.used = false;
                    was_used
                });
            if spared {
                chances += 1;
                self.order.push_back(oldest);
            } else if let Some(gone) = self.entries.remove(&oldest) {
                self.bytes = self.bytes.saturating_sub(gone.weight);
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use std::sync::mpsc::{Sender, channel};
    use std::thread;
    use std::time::Duration;

    use super::*;

    /// Long enough for any analysis here, short enough to fail a test that
    /// would otherwise hang.
    const WAIT: Duration = Duration::from_secs(30);

    fn pool(threads: usize, queue: usize) -> ParserPool {
        ParserPool::start(ParserSettings {
            threads,
            queue,
            ..ParserSettings::default()
        })
        .unwrap()
    }

    fn ask(pool: &ParserPool, text: &str, limits: Limits) -> Outcome {
        let (answer, answers) = channel();
        pool.submit(text.to_owned(), limits, move |outcome| {
            let _ = answer.send(outcome);
        })
        .unwrap();
        answers.recv_timeout(WAIT).unwrap()
    }

    #[test]
    fn a_statement_is_analysed_once_and_then_comes_from_the_cache() {
        let pool = pool(2, 8);
        let limits = Limits::default();
        let first = ask(&pool, "SELECT pg_sleep(1) FROM users", limits).unwrap();
        let second = ask(&pool, "SELECT pg_sleep(1) FROM users", limits).unwrap();
        assert!(Arc::ptr_eq(&first, &second));
        assert_eq!(first.functions().len(), 1);
        // One byte of difference is another statement.
        let other = ask(&pool, "SELECT pg_sleep(1) FROM users ", limits).unwrap();
        assert!(!Arc::ptr_eq(&first, &other));

        let stats = pool.stats();
        assert_eq!((stats.analysed, stats.cache_hits), (2, 1));
        assert_eq!(stats.cache_entries, 2);
        assert!(stats.cache_bytes > 0);
    }

    #[test]
    fn a_failure_is_answered_and_kept_too() {
        let pool = pool(1, 8);
        let limits = Limits::default();
        assert_eq!(ask(&pool, "SELEC 1", limits), Err(ParseFailure::Rejected));
        assert_eq!(ask(&pool, "SELEC 1", limits), Err(ParseFailure::Rejected));
        assert_eq!(
            ask(&pool, "SELECT 'a\0b'", limits),
            Err(ParseFailure::EmbeddedNul)
        );
        let stats = pool.stats();
        assert_eq!((stats.analysed, stats.cache_hits), (2, 1));
    }

    #[test]
    fn a_statement_over_the_cap_is_neither_hashed_nor_parsed_nor_kept() {
        let pool = pool(1, 8);
        let limits = Limits::with_max_bytes(16);
        assert_eq!(
            ask(&pool, "SELECT 1, 2, 3, 4, 5", limits),
            Err(ParseFailure::TooLarge)
        );
        let stats = pool.stats();
        assert_eq!(
            (stats.analysed, stats.cache_hits, stats.cache_entries),
            (0, 0, 0)
        );
        // An analysis made under a larger cap does not answer for it.
        assert!(ask(&pool, "SELECT 1, 2, 3, 4, 5", Limits::default()).is_ok());
        assert_eq!(
            ask(&pool, "SELECT 1, 2, 3, 4, 5", limits),
            Err(ParseFailure::TooLarge)
        );
    }

    #[test]
    fn an_analysis_without_the_normalised_text_does_not_answer_for_one_with_it() {
        let pool = pool(1, 8);
        let plain = Limits::default();
        let full = plain.normalised(true);
        let sql = "SELECT * FROM users WHERE id = 42";
        assert_eq!(ask(&pool, sql, plain).unwrap().normalised(), None);
        assert!(ask(&pool, sql, full).unwrap().normalised().is_some());
        // The fuller one took its place and answers both.
        assert!(ask(&pool, sql, plain).unwrap().normalised().is_some());
        let stats = pool.stats();
        assert_eq!(
            (stats.analysed, stats.cache_hits, stats.cache_entries),
            (2, 1, 1)
        );

        // Another cap on nesting is another question.
        assert_eq!(
            ask(&pool, sql, plain.with_max_depth(0)),
            Err(ParseFailure::TooDeep)
        );
        assert!(ask(&pool, "SELECT (1)", plain).is_ok());
        assert_eq!(
            ask(&pool, "SELECT (1)", plain.with_max_depth(0)),
            Err(ParseFailure::TooDeep)
        );
    }

    /// Holds a parser thread until the returned sender is dropped or used.
    fn occupy(pool: &ParserPool) -> (Sender<()>, Receiver<Outcome>) {
        let (release, released) = channel::<()>();
        let (started, has_started) = channel();
        let (answer, answers) = channel();
        pool.enqueue(
            move |_, _| {
                let _ = started.send(());
                let _ = released.recv_timeout(WAIT);
                Err(ParseFailure::Unreadable)
            },
            move |outcome| {
                let _ = answer.send(outcome);
            },
        )
        .unwrap();
        has_started.recv_timeout(WAIT).unwrap();
        (release, answers)
    }

    #[test]
    fn a_full_queue_answers_busy_at_once() {
        let pool = pool(1, 2);
        let (release, held) = occupy(&pool);
        let (answer, answers) = channel();
        let submit = |text: &str| {
            let answer = answer.clone();
            pool.submit(text.to_owned(), Limits::default(), move |outcome| {
                let _ = answer.send(outcome);
            })
        };
        // The thread is held, so these two fill the queue.
        assert_eq!(submit("SELECT 1"), Ok(()));
        assert_eq!(submit("SELECT 2"), Ok(()));
        // The third comes back while the thread is still held: had it
        // waited for room, this test would not get past this line.
        assert_eq!(submit("SELECT 3"), Err(ParseFailure::Busy));
        assert_eq!(submit("SELECT 4"), Err(ParseFailure::Busy));
        assert!(answers.try_recv().is_err());
        assert_eq!(pool.stats().busy, 2);

        release.send(()).unwrap();
        assert_eq!(
            held.recv_timeout(WAIT).unwrap(),
            Err(ParseFailure::Unreadable)
        );
        assert!(answers.recv_timeout(WAIT).unwrap().is_ok());
        assert!(answers.recv_timeout(WAIT).unwrap().is_ok());
        // The two that were refused are never answered.
        drop(answer);
        assert!(answers.recv_timeout(WAIT).is_err());
        // With room again, a statement is taken.
        assert!(ask(&pool, "SELECT 3", Limits::default()).is_ok());
    }

    #[test]
    fn a_panic_ends_one_job_and_not_the_thread() {
        let pool = pool(1, 8);
        let (answer, answers) = channel();
        pool.enqueue(
            |_, _| panic!("a test panic in a parser job"),
            move |outcome| {
                let _ = answer.send(outcome);
            },
        )
        .unwrap();
        assert_eq!(
            answers.recv_timeout(WAIT).unwrap(),
            Err(ParseFailure::Panicked)
        );
        // A receiver that panics is survived as well.
        pool.submit("SELECT 1".to_owned(), Limits::default(), |_| {
            panic!("a test panic in a reply")
        })
        .unwrap();
        // The only thread still works.
        assert!(ask(&pool, "SELECT 2", Limits::default()).is_ok());
        assert_eq!(pool.stats().panicked, 2);
    }

    #[test]
    fn the_work_runs_on_the_named_parser_threads() {
        let pool = pool(3, 16);
        let caller = thread::current().id();
        let (name, names) = channel();
        // Hold all three threads at once, so each takes one job.
        let held: Vec<_> = (0..3)
            .map(|_| {
                let name = name.clone();
                let (release, released) = channel::<()>();
                pool.enqueue(
                    move |_, _| {
                        let current = thread::current();
                        let _ = name.send((current.id(), current.name().map(str::to_owned)));
                        let _ = released.recv_timeout(WAIT);
                        Err(ParseFailure::Unreadable)
                    },
                    |_| {},
                )
                .unwrap();
                release
            })
            .collect();
        let mut seen: Vec<String> = (0..3)
            .map(|_| {
                let (id, name) = names.recv_timeout(WAIT).unwrap();
                assert_ne!(id, caller);
                name.unwrap()
            })
            .collect();
        seen.sort();
        assert_eq!(seen, ["pgsnare-sql-0", "pgsnare-sql-1", "pgsnare-sql-2"]);
        drop(held);
    }

    #[test]
    fn dropping_the_pool_ends_its_threads() {
        let pool = pool(2, 4);
        let (answer, answers) = channel();
        pool.submit("SELECT 1".to_owned(), Limits::default(), move |outcome| {
            let _ = answer.send(outcome);
        })
        .unwrap();
        let queue = Arc::downgrade(&pool.shared);
        drop(pool);
        // What was queued is still answered.
        assert!(answers.recv_timeout(WAIT).unwrap().is_ok());
        // The threads let go of what they shared, which they only do when
        // their loop has ended.
        for _ in 0..3000 {
            if queue.strong_count() == 0 {
                return;
            }
            thread::sleep(Duration::from_millis(10));
        }
        panic!("the parser threads did not end");
    }

    fn key(n: u32) -> Key {
        let mut key = [0; 32];
        key[..4].copy_from_slice(&n.to_be_bytes());
        key
    }

    fn failure() -> Outcome {
        Err(ParseFailure::Rejected)
    }

    #[test]
    fn the_cache_is_bounded_by_entries() {
        let limits = Limits::default();
        let mut cache = Cache::new(3, usize::MAX);
        for n in 0..10 {
            cache.insert(key(n), &limits, failure());
            assert!(cache.entries.len() <= 3);
            assert_eq!(cache.entries.len(), cache.order.len());
        }
        // The newest three are left.
        for n in 0..7 {
            assert!(cache.get(&key(n), &limits).is_none(), "{n}");
        }
        for n in 7..10 {
            assert!(cache.get(&key(n), &limits).is_some(), "{n}");
        }
        assert_eq!(cache.bytes, 3 * ENTRY_OVERHEAD);

        let mut none = Cache::new(0, usize::MAX);
        none.insert(key(1), &limits, failure());
        assert_eq!(
            (none.entries.len(), none.order.len(), none.bytes),
            (0, 0, 0)
        );
    }

    #[test]
    fn the_cache_is_bounded_by_bytes() {
        let limits = Limits::default();
        let budget = 20 * ENTRY_OVERHEAD;
        let mut cache = Cache::new(usize::MAX, budget);
        for n in 0..1000 {
            cache.insert(key(n), &limits, failure());
            assert!(cache.bytes <= budget);
            assert_eq!(cache.entries.len(), cache.order.len());
        }
        assert_eq!(cache.entries.len(), 20);
        assert_eq!(cache.bytes, budget);

        // An entry heavier than an eighth of the budget is not kept.
        let mut small = Cache::new(usize::MAX, 8 * ENTRY_OVERHEAD - 1);
        small.insert(key(1), &limits, failure());
        assert_eq!((small.entries.len(), small.bytes), (0, 0));

        // Writing an entry again does not count it twice.
        let mut same = Cache::new(usize::MAX, budget);
        for _ in 0..100 {
            same.insert(key(1), &limits, failure());
        }
        assert_eq!((same.entries.len(), same.order.len()), (1, 1));
        assert_eq!(same.bytes, ENTRY_OVERHEAD);
    }

    #[test]
    fn an_entry_that_is_in_use_is_passed_over_once() {
        let limits = Limits::default();
        let mut cache = Cache::new(3, usize::MAX);
        for n in 0..3 {
            cache.insert(key(n), &limits, failure());
        }
        // The oldest is asked for, so the next one goes in its place.
        assert!(cache.get(&key(0), &limits).is_some());
        cache.insert(key(3), &limits, failure());
        assert!(cache.get(&key(1), &limits).is_none());
        assert!(cache.entries.contains_key(&key(0)));
        // Not asked for again, it goes when its turn comes.
        for n in 4..7 {
            cache.insert(key(n), &limits, failure());
        }
        assert!(!cache.entries.contains_key(&key(0)));
        assert_eq!(cache.entries.len(), 3);

        // Even when every entry is in use, an insertion ends and the
        // bound holds.
        let mut busy = Cache::new(64, usize::MAX);
        for n in 0..64 {
            busy.insert(key(n), &limits, failure());
        }
        for round in 0..10 {
            for n in 0..64 + round {
                let _ = busy.get(&key(n), &limits);
            }
            busy.insert(key(64 + round), &limits, failure());
            assert_eq!(busy.entries.len(), 64);
            assert_eq!(busy.order.len(), 64);
        }
    }
}
