#!/usr/bin/env bash
# SPDX-License-Identifier: Apache-2.0
#
# A COPY that the client starts and then gives up on with CopyFail.
#
# No libpq client can do this, so the messages are written by
# tests/differential/wire.pl, and the output is every message the server
# sent.
#
# Usage: copy-fail.sh CONNINFO

exec perl "$(dirname "$0")/../wire.pl" "$1" copy-fail
