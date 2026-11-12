// SPDX-License-Identifier: Apache-2.0

//! Fuzzes the configuration loader.
//!
//! For any input, reading it as a configuration and as a token file must:
//!
//! - return, without a panic and in bounded time and memory
//! - when it fails, report an error that does not repeat the input
//! - when it succeeds, give a configuration that converts to a policy
//!
//! The second point is checked with a marker. The seeds place the marker
//! where a honeytoken value, a key or broken syntax could carry it into an
//! error message, and the fuzzer moves it around from there.

#![no_main]

use libfuzzer_sys::fuzz_target;
use pgsnare::config::{Config, TokenFile};

/// Stands for a honeytoken value. No part of the schema contains it, so if
/// it shows up in an error, the error repeated the document.
const MARKER: &str = "Zq7honeytokenValue9xK";

fn assert_no_leak(error: &dyn std::fmt::Display, debug: &dyn std::fmt::Debug) {
    let shown = format!("{error}\n{debug:?}");
    assert!(
        !shown.contains(MARKER),
        "an error repeats text from the document: {shown}"
    );
}

fuzz_target!(|data: &[u8]| {
    let Ok(text) = std::str::from_utf8(data) else {
        return;
    };

    match Config::from_yaml(text) {
        Ok(config) => {
            // A configuration that passed every check is a valid policy.
            if let Err(error) = config.policy(1) {
                panic!("a checked configuration gives an invalid policy: {error}");
            }
            // Showing it must not panic either.
            let _ = format!("{config:?}");
        }
        Err(error) => assert_no_leak(&error, &error),
    }

    if let Err(error) = TokenFile::from_yaml(text) {
        assert_no_leak(&error, &error);
    }
});
