#!/usr/bin/env bash
# SPDX-License-Identifier: Apache-2.0
#
# Portal suspension: a client fetches a result a few rows at a time with
# the extended query protocol. The server sends that many rows and
# PortalSuspended, and waits for the next Execute.
#
# No libpq client can do this, so the messages are written by
# tests/differential/wire.pl, and the output is every message the server
# sent.
#
# Usage: portal-suspension.sh CONNINFO

exec perl "$(dirname "$0")/../wire.pl" "$1" portal
