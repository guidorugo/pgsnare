// SPDX-License-Identifier: Apache-2.0

//! Fuzzes a PostgreSQL session that looks for honeytokens and carries out
//! every response to them, with client and server bytes in any order and
//! with everything else a runtime can tell it.

#![no_main]

use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    pgsnare_core_fuzz::fuzz_scanning(data);
});
