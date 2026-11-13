#!/usr/bin/env bash
# SPDX-License-Identifier: Apache-2.0
#
# Checks that an endpoint is the PostgreSQL version it is meant to be.
#
# Usage:
#   version.sh MAJOR CONNINFO
#
#   MAJOR      the major version expected, for example 17
#   CONNINFO   a libpq keyword/value string without `dbname`. The password
#              comes from the environment (PGPASSWORD or PGPASSFILE).
#
# A comparison between PostgreSQL and pgsnare in front of PostgreSQL means
# something only when both endpoints lead to the version the test names.
# Nothing else would notice a service that runs another version: every
# scenario would still give identical output on both sides.
#
# Exit status:
#   0  the endpoint runs PostgreSQL MAJOR
#   1  the endpoint runs another version
#   2  the version could not be determined: bad usage, or an endpoint that
#      cannot be reached

set -euo pipefail

if [[ $# -ne 2 || ! "$1" =~ ^[0-9]+$ ]]; then
    echo "Usage: version.sh MAJOR CONNINFO" >&2
    exit 2
fi
expected="$1"
conninfo="$2"

work="$(mktemp -d)"
trap 'rm -rf "$work"' EXIT

if ! number="$(psql --no-psqlrc --no-password --quiet --tuples-only --no-align \
    --set ON_ERROR_STOP=1 --dbname "$conninfo dbname=postgres" \
    --command 'SHOW server_version_num' 2>"$work/error")"; then
    echo "version.sh: cannot ask the endpoint for its version:" >&2
    sed 's/^/    /' "$work/error" >&2
    exit 2
fi
if ! [[ "$number" =~ ^[0-9]+$ ]]; then
    echo "version.sh: the endpoint gave no version number" >&2
    exit 2
fi

major=$((number / 10000))
if [[ "$major" -ne "$expected" ]]; then
    echo "version.sh: expected PostgreSQL $expected, but the endpoint runs PostgreSQL $major (server_version_num $number)" >&2
    exit 1
fi
