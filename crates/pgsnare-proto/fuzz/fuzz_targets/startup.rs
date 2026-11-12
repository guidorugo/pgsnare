// SPDX-License-Identifier: Apache-2.0

//! Fuzzes the classifier of the first bytes of a connection and the views
//! of the startup-phase packets.

#![no_main]

use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    pgsnare_proto_fuzz::fuzz_startup(data);
});
