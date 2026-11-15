// SPDX-License-Identifier: Apache-2.0

//! The seeds of the `scanning` fuzz target, and its checks, run as a test.
//!
//! The fuzz target lives in the fuzz crate beside this one, which is built
//! only when the fuzzer runs. Its code is plain Rust over the public
//! interface of this crate, so it is compiled here a second time: every
//! seed is run through it, with all the checks the fuzzer makes, and the
//! seeds are held to reach what they are named for. A seed that no longer
//! gets a session to a hit, a kill, a tarpit or made-up rows would leave
//! the fuzzer to find its own way there.

#[path = "../fuzz/src/scanning.rs"]
mod scanning;

use std::collections::BTreeMap;

use scanning::{Reached, fuzz_scanning, run_scanning};

fn seeds() -> BTreeMap<String, Vec<u8>> {
    let directory = concat!(env!("CARGO_MANIFEST_DIR"), "/fuzz/seeds/scanning");
    std::fs::read_dir(directory)
        .unwrap()
        .map(|entry| {
            let entry = entry.unwrap();
            (
                entry.file_name().into_string().unwrap(),
                std::fs::read(entry.path()).unwrap(),
            )
        })
        .collect()
}

#[test]
fn every_seed_passes_the_checks_and_reaches_what_it_is_named_for() {
    let seeds = seeds();
    assert!(seeds.len() >= 30, "{} seeds", seeds.len());
    let mut all = Reached::default();
    for (name, data) in &seeds {
        let reached = run_scanning(data);
        all.hit |= reached.hit;
        all.kill |= reached.kill;
        all.tarpit |= reached.tarpit;
        all.fake_data |= reached.fake_data;
        all.kept_back_in_vain |= reached.kept_back_in_vain;

        if name != "raw-streams" {
            assert!(reached.hit, "{name}: no hit");
        }
        let kills = name.starts_with("kill") || name == "escalation" || name.ends_with("then-kill");
        assert_eq!(reached.kill, kills, "{name}: kill");
        let tarpits = name.contains("tarpit");
        assert_eq!(reached.tarpit, tarpits, "{name}: tarpit");
        // The seeds named for a case where rows cannot be added.
        let adds = name.starts_with("fake-data")
            && ![
                "then-kill",
                "due",
                "other-portal",
                "made-again",
                "in-parts",
                "binary-column",
                "no-clean-row",
                "short-row",
                "large-row",
                "error",
                "shutdown",
                "session-ends",
                "fail-open",
            ]
            .iter()
            .any(|case| name.ends_with(case));
        assert_eq!(
            reached.fake_data,
            adds || name == "reload",
            "{name}: fake_data"
        );
    }
    assert_eq!(
        all,
        Reached {
            hit: true,
            kill: true,
            tarpit: true,
            fake_data: true,
            kept_back_in_vain: true,
        }
    );
}

/// Bytes that are the same in every run of the test.
struct Sequence(u64);

impl Sequence {
    fn next(&mut self) -> u64 {
        self.0 ^= self.0 << 13;
        self.0 ^= self.0 >> 7;
        self.0 ^= self.0 << 17;
        self.0
    }

    fn below(&mut self, limit: usize) -> usize {
        usize::try_from(self.next() % u64::try_from(limit).unwrap()).unwrap()
    }
}

#[test]
fn seeds_that_are_changed_at_random_pass_the_checks() {
    // Not a fuzzer: some fifteen hundred inputs near the seeds, so that a check
    // of the target that is wrong shows here and not only in a fuzz run.
    let seeds: Vec<Vec<u8>> = seeds().into_values().collect();
    let mut sequence = Sequence(0x2545_f491_4f6c_dd1d);
    for _ in 0..1_500 {
        let mut data = seeds[sequence.below(seeds.len())].clone();
        for _ in 0..=sequence.below(4) {
            let other = &seeds[sequence.below(seeds.len())];
            match sequence.below(4) {
                0 if !data.is_empty() => {
                    let at = sequence.below(data.len());
                    data[at] = sequence.next().to_le_bytes()[0];
                }
                1 if !data.is_empty() => {
                    let at = sequence.below(data.len());
                    data.truncate(at.max(1));
                }
                2 => {
                    // Whole steps of another seed, at a step of this one.
                    let from = 1 + 3 * sequence.below(other.len() / 3 + 1);
                    let at = 1 + 3 * sequence.below(data.len() / 3 + 1);
                    let piece = other.get(from..).unwrap_or_default();
                    let at = at.min(data.len());
                    data.splice(at..at, piece.iter().copied());
                }
                _ => {
                    let at = sequence.below(data.len() + 1);
                    data.insert(at, sequence.next().to_le_bytes()[0]);
                }
            }
        }
        fuzz_scanning(&data);
    }
}
