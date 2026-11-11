// SPDX-License-Identifier: Apache-2.0

//! Micro-benchmarks for honeytoken detection: how fast a matcher scans rows
//! of typical sizes with 100 and with 10,000 tokens loaded.
//!
//! Run them with
//!
//! ```text
//! cargo bench -p pgsnare-core --bench detect_scan
//! ```
//!
//! The run takes about half a minute and prints one line per case, in
//! MiB/s. The figures say how one core behaves on the machine at hand; they
//! are for comparing changes, not for quoting.
//!
//! This is a plain program, not a benchmark framework: it needs nothing but
//! the standard library. Each case is scanned repeatedly for a fixed time,
//! several times over, and the median rate is reported. Without the
//! `--bench` argument, which `cargo bench` passes, every case runs once on a
//! small input, so that `cargo test --benches` can check that the benchmark
//! still works.

use std::fmt::Write as _;
use std::hint::black_box;
use std::time::{Duration, Instant};

use pgsnare_core::detect::{Matcher, TokenSpec};

/// How many tokens are loaded.
const TOKEN_COUNTS: [usize; 2] = [100, 10_000];

/// Typical sizes of a row, in bytes.
const ROW_SIZES: [usize; 4] = [64, 256, 1024, 8192];

/// How much data one pass over a case scans.
const POOL_BYTES: usize = 1 << 20;

/// The size of a message for the streaming case, and of the chunks it
/// arrives in.
const STREAM_BYTES: usize = 4 << 20;
const STREAM_CHUNK: usize = 8192;

const WARM_UP: Duration = Duration::from_millis(40);
const SAMPLE: Duration = Duration::from_millis(70);
const SAMPLES: usize = 5;

const MIB: f64 = 1024.0 * 1024.0;

/// A small deterministic generator (SplitMix64), so that every run scans
/// the same data.
struct Rng(u64);

impl Rng {
    fn next(&mut self) -> u64 {
        self.0 = self.0.wrapping_add(0x9e37_79b9_7f4a_7c15);
        let mut z = self.0;
        z = (z ^ (z >> 30)).wrapping_mul(0xbf58_476d_1ce4_e5b9);
        z = (z ^ (z >> 27)).wrapping_mul(0x94d0_49bb_1331_11eb);
        z ^ (z >> 31)
    }

    fn below(&mut self, limit: usize) -> usize {
        (self.next() % limit as u64) as usize
    }

    fn pick<'a>(&mut self, items: &[&'a str]) -> &'a str {
        items[self.below(items.len())]
    }

    fn letters_and_digits(&mut self, len: usize) -> String {
        const CHARACTERS: &[u8] = b"abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789";
        (0..len)
            .map(|_| char::from(CHARACTERS[self.below(CHARACTERS.len())]))
            .collect()
    }
}

const WORDS: &[&str] = &[
    "amber", "basil", "cedar", "delta", "ember", "fjord", "grove", "harbor", "island", "juniper",
    "kestrel", "lagoon", "meadow", "nectar", "orchid", "pebble", "quarry", "river", "summit",
    "thistle", "umber", "valley", "willow", "yarrow", "zephyr", "invoice", "account", "customer",
    "payment", "pending", "shipped", "address", "balance", "monthly", "standard", "premium",
];

/// Synthetic honeytokens in three common shapes: an email address, an
/// opaque key and a card number. Each has one value, and no value can
/// contain another.
fn tokens(count: usize, case_insensitive: bool) -> Vec<TokenSpec> {
    let mut rng = Rng(0x5eed_0001);
    (0..count)
        .map(|index| {
            let value = match index % 3 {
                0 => format!(
                    "{}.{}.{}{index}@mail.example",
                    rng.pick(WORDS),
                    rng.pick(WORDS),
                    rng.letters_and_digits(4),
                ),
                1 => format!("ht{index:05}{}", rng.letters_and_digits(27)),
                _ => format!(
                    "4929-{index:04}-{:04}-{:04}",
                    rng.below(10_000),
                    rng.below(10_000)
                ),
            };
            TokenSpec::new(format!("token-{index}"), [value]).case_insensitive(case_insensitive)
        })
        .collect()
}

/// One row of a result in text format: a few typed columns, then words up
/// to the wanted size.
fn row(size: usize, rng: &mut Rng) -> Vec<u8> {
    let mut text = String::with_capacity(size + 96);
    let _ = write!(
        text,
        "{}\t{} {}\t{}.{}@{}.example\t2026-{:02}-{:02} {:02}:{:02}:{:02}+00\t{}.{:02}\t",
        rng.below(10_000_000),
        rng.pick(WORDS),
        rng.pick(WORDS),
        rng.pick(WORDS),
        rng.pick(WORDS),
        rng.pick(WORDS),
        1 + rng.below(12),
        1 + rng.below(28),
        rng.below(24),
        rng.below(60),
        rng.below(60),
        rng.below(100_000),
        rng.below(100),
    );
    while text.len() < size {
        text.push_str(rng.pick(WORDS));
        text.push(if rng.below(8) == 0 { '\t' } else { ' ' });
    }
    let mut row = text.into_bytes();
    row.truncate(size);
    row
}

fn rows(size: usize, total: usize, rng: &mut Rng) -> Vec<Vec<u8>> {
    (0..total.div_ceil(size)).map(|_| row(size, rng)).collect()
}

/// Puts one token value into the middle of each row.
fn plant(rows: &mut [Vec<u8>], tokens: &[TokenSpec]) {
    for (row, token) in rows.iter_mut().zip(tokens.iter().cycle()) {
        let value = token.values()[0].expose();
        let start = (row.len() - value.len()) / 2;
        row[start..start + value.len()].copy_from_slice(value);
    }
}

/// Scans every row on its own, as the proxy scans one message at a time.
/// Returns the number of matches.
fn scan_rows(matcher: &Matcher, rows: &[Vec<u8>]) -> usize {
    rows.iter()
        .map(|row| matcher.scan(black_box(row)).count())
        .sum()
}

/// Scans one message that arrives in chunks. Returns the number of matches.
fn scan_stream(matcher: &Matcher, message: &[u8], chunk: usize) -> usize {
    let mut scanner = matcher.stream();
    message
        .chunks(chunk)
        .map(|chunk| scanner.feed(black_box(chunk)).count())
        .sum()
}

/// Runs `pass` repeatedly and returns the median rate in MiB/s. `pass`
/// scans `bytes` bytes each time it is called.
fn rate(full: bool, bytes: usize, mut pass: impl FnMut() -> usize) -> f64 {
    if !full {
        black_box(pass());
        return 0.0;
    }

    let warm_up = Instant::now();
    while warm_up.elapsed() < WARM_UP {
        black_box(pass());
    }

    let mut rates: Vec<f64> = (0..SAMPLES)
        .map(|_| {
            let start = Instant::now();
            let mut scanned = 0usize;
            loop {
                black_box(pass());
                scanned += bytes;
                if start.elapsed() >= SAMPLE {
                    break;
                }
            }
            scanned as f64 / start.elapsed().as_secs_f64() / MIB
        })
        .collect();
    rates.sort_by(f64::total_cmp);
    rates[rates.len() / 2]
}

fn report(full: bool, case: &str, rate: f64) {
    if full {
        println!("  {case:<46} {rate:>8.0} MiB/s");
    } else {
        println!("  {case:<46} ok");
    }
}

fn run(full: bool, token_count: usize, case_insensitive: bool) {
    let tokens = tokens(token_count, case_insensitive);
    let started = Instant::now();
    let matcher = Matcher::build(&tokens).expect("the generated tokens are valid");
    let build_time = started.elapsed();

    println!();
    println!(
        "{token_count} tokens{}: {} patterns, built in {:.1} ms, {:.1} MiB of compiled patterns",
        if case_insensitive {
            ", all case-insensitive"
        } else {
            ""
        },
        matcher.pattern_count(),
        build_time.as_secs_f64() * 1000.0,
        matcher.memory_usage() as f64 / MIB,
    );
    println!("  {matcher:?}");

    let pool = if full { POOL_BYTES } else { 16 * 1024 };
    let mut rng = Rng(0x5eed_0002);

    for size in ROW_SIZES {
        let rows = rows(size, pool, &mut rng);
        let bytes = rows.len() * size;
        assert_eq!(scan_rows(&matcher, &rows), 0, "clean rows contain no token");
        let rate = rate(full, bytes, || scan_rows(&matcher, &rows));
        report(full, &format!("rows of {size} B, no token"), rate);
    }

    let size = 256;
    let mut with_token = rows(size, pool, &mut rng);
    plant(&mut with_token, &tokens);
    let bytes = with_token.len() * size;
    assert_eq!(
        scan_rows(&matcher, &with_token),
        with_token.len(),
        "every row contains one token"
    );
    let rate_with_token = rate(full, bytes, || scan_rows(&matcher, &with_token));
    report(
        full,
        &format!("rows of {size} B, one token in each"),
        rate_with_token,
    );

    let stream_bytes = if full { STREAM_BYTES } else { 64 * 1024 };
    let message: Vec<u8> = rows(ROW_SIZES[2], stream_bytes, &mut rng).concat();
    assert_eq!(scan_stream(&matcher, &message, STREAM_CHUNK), 0);
    let rate_stream = rate(full, message.len(), || {
        scan_stream(&matcher, &message, STREAM_CHUNK)
    });
    report(
        full,
        &format!(
            "stream of {} KiB in {} KiB chunks, no token",
            message.len() >> 10,
            STREAM_CHUNK >> 10
        ),
        rate_stream,
    );
}

fn main() {
    // `cargo bench` passes `--bench`. Anything else, such as
    // `cargo test --benches`, gets a quick run that only checks the cases.
    let full = std::env::args().any(|argument| argument == "--bench");

    println!("detect_scan: scan throughput on one core, median of {SAMPLES} samples");
    if !full {
        println!("quick check only; run with `cargo bench` for figures");
    }

    for token_count in TOKEN_COUNTS {
        // A quick check does not need the large token list.
        let token_count = if full {
            token_count
        } else {
            token_count.min(300)
        };
        for case_insensitive in [false, true] {
            run(full, token_count, case_insensitive);
        }
    }
}
