#!/usr/bin/env bash
# SPDX-License-Identifier: Apache-2.0
#
# A FunctionCall message with arguments and a result in binary, and one
# for a function that does not exist.
#
# No libpq client can do this, so the messages are written by
# tests/differential/wire.pl, and the output is every message the server
# sent.
#
# Usage: function-call-binary.sh CONNINFO

exec perl "$(dirname "$0")/../wire.pl" "$1" function
