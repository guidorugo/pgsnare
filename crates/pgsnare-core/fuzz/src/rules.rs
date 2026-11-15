// SPDX-License-Identifier: Apache-2.0

//! The `rules` target: any bytes as a statement, through the checks, the
//! SQL parser and the rules.
//!
//! The first byte of an input chooses the limits. The rest is the
//! statement. For every input the target checks what the analysis
//! promises:
//!
//! - **The first check decides first.** A statement it refuses has the same
//!   failure from the analysis and never an analysis.
//! - **An analysis is bounded.** Its lists stay within their bounds, and
//!   the normalised text is only there when it was asked for and is short
//!   enough.
//! - **The same statement gives the same analysis**, and the same rules
//!   fire for it.
//! - **A rule fires for a reason that is in the analysis**, and a user who
//!   is excluded sets off nothing.

use std::sync::mpsc::{Receiver, Sender, channel};
use std::sync::{Mutex, OnceLock};

use pgsnare_core::policy::ActionSet;
use pgsnare_core::rules::{
    Analysis, CATALOG_ENUMERATION, FUNCTIONS, Limits, MAX_FUNCTIONS, MAX_KINDS,
    MAX_NORMALISE_INPUT_BYTES, MAX_NORMALISED_BYTES, MAX_RELATIONS, ParseFailure, RelationUse,
    RuleScope, RuleSet, StatementFlags, Subject, UNBOUNDED_READ, analyse, precheck,
    spawn_parser_thread,
};

type Outcome = Result<Analysis, ParseFailure>;

/// The one parser thread of the target, with the way to it and back. The
/// parser may only run on such a thread, and one that lives as long as the
/// process keeps what the parser sets up once per thread.
fn parser() -> &'static Mutex<(Sender<(Vec<u8>, Limits)>, Receiver<Outcome>)> {
    static PARSER: OnceLock<Mutex<(Sender<(Vec<u8>, Limits)>, Receiver<Outcome>)>> =
        OnceLock::new();
    PARSER.get_or_init(|| {
        let (ask, questions) = channel::<(Vec<u8>, Limits)>();
        let (answer, answers) = channel();
        spawn_parser_thread("pgsnare-sql-fuzz".to_owned(), move |thread| {
            for (text, limits) in questions {
                if answer.send(analyse(&text, &limits, thread)).is_err() {
                    return;
                }
            }
        })
        .expect("the parser thread of the fuzz target starts");
        Mutex::new((ask, answers))
    })
}

fn read(text: &[u8], limits: &Limits) -> Outcome {
    let parser = parser().lock().expect("no fuzz input panicked before");
    parser
        .0
        .send((text.to_vec(), *limits))
        .expect("the parser thread is alive");
    parser.1.recv().expect("the analysis does not panic")
}

fn rule_set() -> RuleSet {
    let scope = || RuleScope::new(None, None, &["migrator".to_owned()]);
    let tables = ["public.users".to_owned(), "cards".to_owned()];
    let functions = ["pg_read_file".to_owned(), "pg_catalog.pg_sleep".to_owned()];
    RuleSet::builder()
        .catalog_enumeration(ActionSet::ALERT, scope())
        .and_then(|rules| rules.unbounded_read(&tables, ActionSet::ALERT, scope()))
        .and_then(|rules| rules.row_threshold(&tables, 10, ActionSet::ALERT, scope()))
        .and_then(|rules| rules.functions(&functions, ActionSet::ALERT, scope()))
        .expect("the rule set of the fuzz target is valid")
        .build()
}

fn check_bounds(analysis: &Analysis, text: &[u8], limits: &Limits) {
    assert!(analysis.relations().len() <= MAX_RELATIONS);
    assert!(analysis.functions().len() <= MAX_FUNCTIONS);
    assert!(analysis.kinds().len() <= MAX_KINDS);
    for relation in analysis.relations() {
        assert!(!relation.name().is_empty() && relation.name().len() <= 255);
        assert!(relation.schema().is_none_or(|schema| !schema.is_empty()));
    }
    for function in analysis.functions() {
        assert!(!function.name().is_empty() && function.name().len() <= 255);
    }
    if analysis.statement_count() == 0 {
        assert!(analysis.relations().is_empty() && analysis.functions().is_empty());
        assert!(analysis.kinds().is_empty());
    } else {
        assert!(!analysis.kinds().is_empty() || !analysis.is_complete());
    }
    assert!(analysis.covers(limits));
    if limits.normalise {
        if let Some(normalised) = analysis.normalised() {
            assert!(normalised.len() <= MAX_NORMALISED_BYTES);
            assert!(text.len() <= MAX_NORMALISE_INPUT_BYTES);
        }
    } else {
        assert!(analysis.normalised().is_none() && analysis.fingerprint().is_none());
    }
    // Names are never part of the debug output; a name of one character
    // could be there by chance, a long one could not.
    let shown = format!("{analysis:?}");
    for relation in analysis.relations() {
        assert!(relation.name().len() < 12 || !shown.contains(relation.name()));
    }
}

fn check_rules(analysis: &Analysis) {
    let rules = rule_set();
    let app = Subject {
        listener: "main",
        user: Some("app"),
    };
    let hits = rules.evaluate(analysis, &app);
    assert_eq!(hits, rules.evaluate(analysis, &app));
    assert!(hits.len() <= 3);
    for (index, (id, actions)) in hits.iter().enumerate() {
        assert!(!actions.is_empty());
        assert!(hits.iter().skip(index + 1).all(|(other, _)| other != id));
        let reads = |usage| {
            analysis
                .relations()
                .iter()
                .any(|r| r.usage().contains(usage))
        };
        match id.as_str() {
            CATALOG_ENUMERATION => assert!(reads(RelationUse::READ)),
            UNBOUNDED_READ => assert!(reads(RelationUse::UNBOUNDED_READ)),
            FUNCTIONS => assert!(!analysis.functions().is_empty()),
            other => panic!("a rule fired that is not evaluated here: {other}"),
        }
    }
    if rules.row_threshold(analysis, &app).is_some() {
        // A listed table is read, or what an earlier statement stored is
        // run.
        assert!(
            !analysis.relations().is_empty()
                || analysis.flags().contains(StatementFlags::RUNS_STORED)
        );
    }
    let excluded = Subject {
        listener: "main",
        user: Some("migrator"),
    };
    assert!(rules.evaluate(analysis, &excluded).is_empty());
    assert!(rules.row_threshold(analysis, &excluded).is_none());
}

/// Runs one input of the `rules` target.
///
/// # Panics
///
/// Panics when the analysis breaks one of its promises, which is what the
/// fuzzer is looking for.
pub fn fuzz_rules(data: &[u8]) {
    let Some((&choice, text)) = data.split_first() else {
        return;
    };
    let mut limits = Limits::with_max_bytes(if choice & 1 == 0 { 16 * 1024 } else { 96 })
        .normalised(choice & 2 != 0);
    if choice & 4 != 0 {
        limits = limits.with_max_depth(6);
    }

    let checked = precheck(text, &limits).map(|_| ());
    let outcome = read(text, &limits);
    match (&checked, &outcome) {
        (Err(early), Err(late)) => assert_eq!(early, late),
        (Err(_), Ok(_)) => panic!("a statement that failed the first check was analysed"),
        (Ok(()), Err(reason)) => assert!(
            matches!(
                reason,
                ParseFailure::Rejected | ParseFailure::TooDeep | ParseFailure::Unreadable
            ),
            "{reason}"
        ),
        (Ok(()), Ok(analysis)) => {
            check_bounds(analysis, text, &limits);
            check_rules(analysis);
        }
    }
    if choice & 8 != 0 {
        assert_eq!(outcome, read(text, &limits));
    }
}

#[cfg(test)]
mod tests {
    #[test]
    fn every_seed_runs() {
        let seeds = concat!(env!("CARGO_MANIFEST_DIR"), "/seeds/rules");
        let mut count = 0;
        for entry in std::fs::read_dir(seeds).unwrap() {
            let data = std::fs::read(entry.unwrap().path()).unwrap();
            // Under every choice of limits, not only the one of the seed.
            for choice in 0..16u8 {
                let mut input = vec![choice];
                input.extend_from_slice(data.get(1..).unwrap_or_default());
                super::fuzz_rules(&input);
            }
            super::fuzz_rules(&data);
            count += 1;
        }
        assert!(count >= 20, "{count} seeds");
    }
}
