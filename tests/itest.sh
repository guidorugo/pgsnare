#!/bin/sh
# SPDX-License-Identifier: Apache-2.0
#
# The integration tests: `make itest`.
#
# Starts PostgreSQL 15 to 18 and one pgsnare in front of them with Docker
# Compose, and then checks:
#
#   - The differential scenarios. Each runs against PostgreSQL itself and
#     through pgsnare, in every supported TLS setup and for protocol 3.0
#     and 3.2. The outputs must be identical.
#   - The login table. Every row of the table in section 7 of the design
#     document is tried with a real client, and a row that must fail is
#     checked for the failure it must fail with.
#   - What pgsnare logs when it starts.
#
# A pass has to mean something, so the run also proves that its checks can
# fail:
#
#   - every endpoint is asked for its version before it is used, and the
#     check that does so is shown to reject a wrong version
#   - the runner is shown to report a difference, with pgsnare in between
#   - the runner is shown not to mistake an unreachable endpoint for a match
#   - the login table is shown to report a login that does not go as
#     expected
#
# Environment:
#   DOCKER          the docker command (default: docker)
#   ITEST_PROJECT   the Compose project name (default: pgsnare-itest)
#   ITEST_VERSIONS  the PostgreSQL versions to test (default: "15 16 17 18")
#   ITEST_BINARY    the pgsnare binary to test (default: the release build
#                   in target/, which `make itest` makes)

set -eu

cd "$(dirname "$0")/.."

docker="${DOCKER:-docker}"
project="${ITEST_PROJECT:-pgsnare-itest}"
versions="${ITEST_VERSIONS:-15 16 17 18}"
binary="${ITEST_BINARY:-$PWD/target/release/pgsnare}"

if [ ! -x "$binary" ]; then
    echo "itest: there is no pgsnare binary at $binary: run the tests with make itest" >&2
    exit 2
fi

set -- $versions
first="$1"
last="$1"
for version in $versions; do
    last="$version"
done

# A password for this run only. It is never written to disk.
PGSNARE_ITEST_PASSWORD="$(od -An -N24 -tx1 /dev/urandom | tr -d ' \n')"
export PGSNARE_ITEST_PASSWORD
export ITEST_VERSIONS="$versions"
export ITEST_BINARY="$binary"
# The listener the health check of pgsnare asks: see tests/proxy/setup.sh.
export ITEST_READY_PORT="60$first"

compose() {
    "$docker" compose --project-name "$project" --file tests/compose.yaml "$@"
}

cleanup() {
    compose --profile client --profile setup down --volumes --remove-orphans >/dev/null 2>&1 || true
}
trap cleanup EXIT
trap 'exit 130' INT
trap 'exit 143' TERM

# runner ARGUMENTS...: runs the differential runner in the client container.
runner() {
    compose --profile client run --rm --no-deps -T client "$@"
}

# version MAJOR CONNINFO: checks which PostgreSQL an endpoint leads to.
version() {
    compose --profile client run --rm --no-deps -T \
        --entrypoint /differential/version.sh client "$@"
}

# expect_status EXPECTED DESCRIPTION COMMAND...: runs a command that must
# end with exactly this status.
expect_status() {
    expected="$1"
    description="$2"
    shift 2
    status=0
    "$@" >/dev/null 2>&1 || status=$?
    if [ "$status" -ne "$expected" ]; then
        echo "itest: FAILED: $description: expected exit status $expected, got $status" >&2
        failed=1
    fi
}

# login ARGUMENTS...: runs the login table in the client container.
login() {
    compose --profile client run --rm --no-deps -T \
        --entrypoint /login/table.sh client "$@"
}

direct() {
    echo "host=pg$1 port=5432 user=postgres sslmode=disable"
}

# The plaintext listener in front of a plaintext backend leg.
proxied() {
    echo "host=pgsnare port=60$1 user=postgres sslmode=disable"
}

# compare VERSION PROTOCOL PATH...: runs scenarios against PostgreSQL
# VERSION itself and through pgsnare in every supported TLS setup, with a
# client that asks for PROTOCOL at most.
compare() {
    v="$1"
    options="user=postgres max_protocol_version=$2"
    shift 2
    runner --direct "host=pg$v port=5432 sslmode=disable $options" \
        --as "plaintext to plaintext" \
        --proxied "host=pgsnare port=60$v sslmode=disable $options" \
        --as "plaintext to TLS" \
        --proxied "host=pgsnare port=61$v sslmode=disable $options" \
        --as "TLS to plaintext" \
        --proxied "host=pgsnare port=62$v sslmode=require $options" \
        --as "TLS to a Unix socket" \
        --proxied "host=pgsnare port=63$v sslmode=require $options" \
        --as "TLS to TLS with the database's certificate" \
        --proxied "host=pgsnare port=64$v sslmode=require $options" \
        "$@"
}

# logged TEXT: whether pgsnare has written a line with TEXT to its log.
# A second argument narrows it to the lines that also contain that.
logged() {
    compose logs --no-log-prefix pgsnare 2>&1 | grep -F -- "$1" | grep -qF -- "${2:-}"
}

services=""
for version in $versions; do
    services="$services pg$version"
done

echo "itest: preparing certificates and the configuration of pgsnare"
compose --profile setup run --rm --no-deps -T setup

# The databases come first. pgsnare asks each for its certificate when it
# starts, and the volumes with their sockets must be theirs.
echo "itest: starting PostgreSQL $versions"
# shellcheck disable=SC2086
if ! compose up --detach --wait --wait-timeout 180 $services pglegacy; then
    echo "itest: FAILED: the databases did not start" >&2
    exit 1
fi
echo "itest: starting pgsnare"
if ! compose up --detach --wait --wait-timeout 60 pgsnare; then
    echo "itest: FAILED: pgsnare did not start" >&2
    compose logs --no-log-prefix --tail 50 pgsnare >&2 || true
    exit 1
fi

failed=0

# Every endpoint must lead to the version its name says. Otherwise the
# range of versions under test could shrink without anything failing.
echo "itest: the version check must reject a wrong version, and an endpoint that does not answer"
expect_status 1 "a wrong version, directly" \
    version 14 "$(direct "$first")"
expect_status 1 "a wrong version, through pgsnare" \
    version 14 "$(proxied "$first")"
expect_status 2 "an endpoint that does not answer" \
    version "$first" "host=pg$first port=1 user=postgres connect_timeout=5"

for version in $versions; do
    echo "itest: PostgreSQL $version must be what its endpoints lead to"
    for port in 60 61 62 63 64; do
        mode=disable
        if [ "$port" -ge 62 ]; then
            mode=require
        fi
        if ! version "$version" "host=pgsnare port=$port$version user=postgres sslmode=$mode"; then
            failed=1
        fi
    done
    if ! version "$version" "$(direct "$version")"; then
        failed=1
    fi
done
if [ "$failed" -ne 0 ]; then
    echo "itest: FAILED: an endpoint does not lead to the version it is named after" >&2
    exit 1
fi

# What pgsnare said when it started.
echo "itest: the log of pgsnare at startup"
for version in $versions; do
    if ! logged "is not the one the database presents" "listener=own-tls-$version"; then
        echo "itest: FAILED: no warning that listener own-tls-$version presents another certificate than its database" >&2
        failed=1
    fi
    if logged "is not the one the database presents" "listener=shared-tls-$version"; then
        echo "itest: FAILED: listener shared-tls-$version presents the certificate of its database and was warned about" >&2
        failed=1
    fi
    if ! logged "the certificate of the database is not verified" "listener=own-tls-$version"; then
        echo "itest: FAILED: no warning that listener own-tls-$version does not verify its database" >&2
        failed=1
    fi
    if logged "the certificate of the database is not verified" "listener=shared-tls-$version"; then
        echo "itest: FAILED: listener shared-tls-$version verifies its database and was warned about" >&2
        failed=1
    fi
done

# The login table, and the proof that it can fail.
echo "itest: the login table"
# shellcheck disable=SC2086
if ! login $versions; then
    failed=1
fi
expect_status 0 "the self-check of the login table" login --selfcheck "$first"
# The failed logins above must have failed for the reason they were meant
# to, which only the log of pgsnare tells.
for reason in \
    "the certificate is not valid for the name of the database" \
    "the certificate is not signed by a trusted authority"; do
    if ! logged "$reason"; then
        echo "itest: FAILED: pgsnare did not log: $reason" >&2
        failed=1
    fi
done
if ! logged "listener=legacy-tls" "the database could not be reached"; then
    echo "itest: FAILED: pgsnare did not refuse the database that only speaks TLS 1.1" >&2
    failed=1
fi

for version in $versions; do
    for protocol in 3.0 3.2; do
        echo "itest: PostgreSQL $version, protocol $protocol, directly and through pgsnare"
        if ! compare "$version" "$protocol" /differential/scenarios; then
            failed=1
        fi
    done
done

# The runner must report a difference when there is one, with pgsnare
# between the client and the database that differs.
if [ "$first" != "$last" ]; then
    echo "itest: the runner must tell PostgreSQL $first from PostgreSQL $last through pgsnare"
    expect_status 1 "different output" \
        runner --direct "$(direct "$first")" --proxied "$(proxied "$last")" \
        /differential/selfcheck
fi

# The runner must not mistake an unreachable endpoint for a match.
echo "itest: the runner must reject an endpoint that does not answer"
expect_status 2 "an unreachable endpoint" \
    runner --direct "$(direct "$first")" \
    --proxied "host=pg$first port=1 user=postgres connect_timeout=5" \
    /differential/selfcheck

if [ "$failed" -ne 0 ]; then
    echo "itest: the log of pgsnare ends with:" >&2
    compose logs --no-log-prefix --tail 40 pgsnare >&2 || true
    echo "itest: FAILED" >&2
    exit 1
fi
echo "itest: passed"
