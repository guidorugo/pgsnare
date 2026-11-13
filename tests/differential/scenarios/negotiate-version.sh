#!/usr/bin/env bash
# SPDX-License-Identifier: Apache-2.0
#
# A startup message that asks for protocol 3.99 and carries protocol
# options no server knows. The server answers with
# NegotiateProtocolVersion. pgsnare caps such a startup message before it
# reaches the server, and has to give the client the answer the server
# would have given.
#
# No libpq client can do this, so the messages are written by
# tests/differential/wire.pl, and the output is every message the server
# sent.
#
# Usage: negotiate-version.sh CONNINFO

exec perl "$(dirname "$0")/../wire.pl" "$1" negotiate
