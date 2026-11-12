// SPDX-License-Identifier: Apache-2.0

//! Fuzzes the framer on a stream of bytes from the client, and every view
//! of a client message on the frames it finds.

#![no_main]

use libfuzzer_sys::fuzz_target;
use pgsnare_proto::Direction;

fuzz_target!(|data: &[u8]| {
    pgsnare_proto_fuzz::fuzz_framer(Direction::FromClient, data);
});
