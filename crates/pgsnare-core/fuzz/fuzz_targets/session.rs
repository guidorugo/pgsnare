// SPDX-License-Identifier: Apache-2.0

//! Fuzzes the whole logic of a PostgreSQL session with client and server
//! bytes in any order, and with everything else a runtime can tell it.

#![no_main]

use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    pgsnare_core_fuzz::fuzz_session(data);
});
