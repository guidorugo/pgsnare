// SPDX-License-Identifier: Apache-2.0

//! Fuzzes the checks in front of the SQL parser, the parser, the walk of
//! its result and the rules, with any bytes as a statement.

#![no_main]

use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    pgsnare_core_fuzz::fuzz_rules(data);
});
