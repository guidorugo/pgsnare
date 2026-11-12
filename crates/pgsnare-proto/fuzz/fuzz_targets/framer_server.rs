// SPDX-License-Identifier: Apache-2.0

//! Fuzzes the framer on a stream of bytes from the server, and every view
//! of a server message on the frames it finds.

#![no_main]

use libfuzzer_sys::fuzz_target;
use pgsnare_proto::Direction;

fuzz_target!(|data: &[u8]| {
    pgsnare_proto_fuzz::fuzz_framer(Direction::FromServer, data);
});
