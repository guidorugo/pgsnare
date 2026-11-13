#!/usr/bin/env bash
# SPDX-License-Identifier: Apache-2.0
#
# The login table: which logins work through pgsnare, and which must fail.
#
# pgsnare relays a login and never ends it itself. SCRAM channel binding
# ties a login to the certificate the client saw, so whether a login works
# depends on which legs use TLS and on whose certificate pgsnare presents.
# Section 7 of the design document has the table. This script tries every
# row of it with a real client, and a row that must fail is checked for the
# failure it must fail with.
#
# Usage:
#   table.sh VERSION...       check every row against each PostgreSQL version
#   table.sh --selfcheck VERSION
#                             prove that a wrong expectation is reported
#
# The endpoints are the listeners tests/proxy/setup.sh configures. The
# password comes from the environment (PGPASSWORD).
#
# Exit status:
#   0  every login went as expected
#   1  at least one did not
#   2  bad usage

set -euo pipefail

selfcheck=0
if [[ "${1:-}" == "--selfcheck" ]]; then
    selfcheck=1
    shift
fi
if [[ $# -eq 0 ]]; then
    echo "Usage: table.sh [--selfcheck] VERSION..." >&2
    exit 2
fi

ca=/state/certs/ca.crt
failures=0
checks=0

# login CONNINFO: tries to log in and to run a query. Sets `outcome` to
# `works` or `fails`, and `message` to what the client said.
login() {
    if message="$(psql --no-psqlrc --no-password --quiet --tuples-only --no-align \
        --dbname "$1 user=postgres dbname=postgres connect_timeout=10" \
        --command 'SELECT 42' 2>&1)" && [[ "$message" == "42" ]]; then
        outcome=works
    else
        outcome=fails
    fi
}

# expect DESCRIPTION CONNINFO works
# expect DESCRIPTION CONNINFO fails TEXT
#
# A login that must fail must fail with TEXT in what the client reports.
# Any other failure does not count.
expect() {
    local description="$1" conninfo="$2" expected="$3" text="${4:-}"
    checks=$((checks + 1))
    login "$conninfo"
    if [[ "$outcome" != "$expected" ]]; then
        echo "WRONG  $description: expected a login that $expected, got one that $outcome"
        sed 's/^/           /' <<<"$message"
        failures=$((failures + 1))
    elif [[ "$expected" == fails && "$message" != *"$text"* ]]; then
        echo "WRONG  $description: the login failed, but not with: $text"
        sed 's/^/           /' <<<"$message"
        failures=$((failures + 1))
    else
        echo "ok     $description: $expected"
    fi
}

no_binding="channel binding is required, but server did not offer an authentication method that supports channel binding"
no_tls_for_binding="channel binding required, but SSL not in use"
binding_mismatch="SCRAM channel binding check failed"
unavailable="the database system is not accepting connections"

# The rows of the table for one PostgreSQL version.
table() {
    local v="$1"
    local plain="host=pgsnare sslmode=disable"
    local tls="host=pgsnare sslmode=require"

    echo "PostgreSQL $v"

    # Row 1. TLS on both legs, and pgsnare presents the certificate of the
    # database: the login is relayed unchanged and channel binding works.
    expect "TLS with the database's certificate to TLS, default settings" \
        "$tls port=64$v" works
    expect "TLS with the database's certificate to TLS, channel binding required" \
        "$tls port=64$v channel_binding=require" works
    expect "TLS with the database's certificate to TLS, channel binding off" \
        "$tls port=64$v channel_binding=disable" works

    # Row 2. TLS on the client leg with pgsnare's own certificate, and no
    # TLS behind it: the login works, and channel binding cannot be had,
    # because the database has nothing to bind to.
    expect "TLS with pgsnare's certificate to plaintext, default settings" \
        "$tls port=62$v" works
    expect "TLS with pgsnare's certificate to plaintext, channel binding required" \
        "$tls port=62$v channel_binding=require" fails "$no_binding"
    expect "TLS with pgsnare's certificate to plaintext, channel binding off" \
        "$tls port=62$v channel_binding=disable" works
    expect "TLS with pgsnare's certificate to a Unix socket, default settings" \
        "$tls port=63$v" works
    expect "TLS with pgsnare's certificate to a Unix socket, channel binding required" \
        "$tls port=63$v channel_binding=require" fails "$no_binding"
    # The certificate is a real one: a client that verifies it is served.
    expect "TLS with pgsnare's certificate, verified by the client" \
        "host=pgsnare sslmode=verify-full sslrootcert=$ca port=62$v" works

    # Row 3. Plaintext on the client leg and TLS behind it: the database
    # offers channel binding, which pgsnare removes from the offer.
    expect "plaintext to TLS, default settings" \
        "$plain port=61$v" works
    expect "plaintext to TLS, channel binding off" \
        "$plain port=61$v channel_binding=disable" works
    expect "plaintext to TLS, channel binding required" \
        "$plain port=61$v channel_binding=require" fails "$no_tls_for_binding"

    # Row 4. No TLS anywhere.
    expect "plaintext to plaintext, default settings" \
        "$plain port=60$v" works
    expect "plaintext to plaintext, channel binding required" \
        "$plain port=60$v channel_binding=require" fails "$no_tls_for_binding"

    # Row 5. TLS on both legs with different certificates: the setup the
    # design rules out. The database notices that the client bound the
    # login to another certificate than its own.
    expect "TLS with pgsnare's certificate to TLS, default settings" \
        "$tls port=65$v" fails "$binding_mismatch"
    expect "TLS with pgsnare's certificate to TLS, channel binding required" \
        "$tls port=65$v channel_binding=require" fails "$binding_mismatch"
    expect "TLS with pgsnare's certificate to TLS, channel binding off" \
        "$tls port=65$v channel_binding=disable" works

    # Beside the table: the client leg does what its mode says.
    expect "a client that asks for TLS where none is offered" \
        "$tls port=60$v" fails "server does not support SSL, but SSL was required"
    expect "a plaintext client where TLS is required" \
        "$plain port=62$v" fails "no pg_hba.conf entry for host"
    expect "a plaintext client where TLS is offered" \
        "$plain port=68$v" works
    expect "a TLS client where TLS is offered" \
        "$tls port=68$v" works
    expect "a client that opens with a TLS handshake" \
        "$tls port=62$v sslnegotiation=direct" works
    expect "a client that opens with a TLS handshake, with the database's certificate" \
        "$tls port=64$v sslnegotiation=direct channel_binding=require" works

    # Beside the table: the certificate of the database is verified.
    expect "a database whose certificate is for another name" \
        "$plain port=66$v" fails "$unavailable"
    expect "a database whose certificate is from an unknown authority" \
        "$plain port=67$v" fails "$unavailable"
    expect "a database verified against the system's certificate store" \
        "$plain port=69$v" works
}

if [[ "$selfcheck" -eq 1 ]]; then
    v="$1"
    # Three expectations that are wrong on purpose. Each must be reported.
    expect "selfcheck: a login that fails, expected to work" \
        "host=pgsnare sslmode=require port=65$v" works >/dev/null
    expect "selfcheck: a login that works, expected to fail" \
        "host=pgsnare sslmode=disable port=60$v" fails "anything" >/dev/null
    expect "selfcheck: a login that fails for another reason than expected" \
        "host=pgsnare sslmode=require port=65$v" fails "$no_binding" >/dev/null
    if [[ "$failures" -ne 3 ]]; then
        echo "table.sh: selfcheck FAILED: $failures of 3 wrong expectations were reported" >&2
        exit 1
    fi
    echo "table.sh: selfcheck passed, 3 wrong expectations were reported"
    exit 0
fi

for version in "$@"; do
    table "$version"
done
# A database that speaks no TLS version above 1.1 is not used.
expect "a database that only speaks TLS 1.1" \
    "host=pgsnare sslmode=disable port=7000" fails "$unavailable"

echo "table.sh: $checks logins, $failures not as expected"
if [[ "$failures" -ne 0 ]]; then
    exit 1
fi
