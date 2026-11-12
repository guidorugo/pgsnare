// SPDX-License-Identifier: Apache-2.0

//! Fuzzes every view of a server message. The first byte of the input is
//! the type byte and the rest is the body.

#![no_main]

use libfuzzer_sys::fuzz_target;
use pgsnare_proto::Direction;

fuzz_target!(|data: &[u8]| {
    pgsnare_proto_fuzz::fuzz_views(Direction::FromServer, data);
});
