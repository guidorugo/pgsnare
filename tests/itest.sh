#!/bin/sh
# SPDX-License-Identifier: Apache-2.0
#
# The integration tests: `make itest`.
#
# Starts PostgreSQL 15 to 18 and one pgsnare in front of them with Docker
# Compose, and runs every differential scenario against each version twice:
# against PostgreSQL itself and through pgsnare. The outputs must be
# identical.
#
# A pass has to mean something, so the run also proves that its checks can
# fail:
#
#   - every endpoint is asked for its version before it is used, and the
#     check that does so is shown to reject a wrong version
#   - the runner is shown to report a difference, with pgsnare in between
#   - the runner is shown not to mistake an unreachable endpoint for a match
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

direct() {
    echo "host=pg$1 port=5432 user=postgres"
}

proxied() {
    echo "host=pgsnare port=60$1 user=postgres"
}

services=""
for version in $versions; do
    services="$services pg$version"
done

echo "itest: preparing the configuration of pgsnare"
compose --profile setup run --rm --no-deps -T setup

echo "itest: starting PostgreSQL $versions, and pgsnare"
# shellcheck disable=SC2086
if ! compose up --detach --wait --wait-timeout 180 $services pgsnare; then
    echo "itest: FAILED: the services did not start" >&2
    compose logs --tail 50 pgsnare >&2 || true
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
    echo "itest: PostgreSQL $version, directly and through pgsnare"
    if ! version "$version" "$(direct "$version")" \
        || ! version "$version" "$(proxied "$version")"; then
        echo "itest: FAILED: PostgreSQL $version is not what its endpoints lead to" >&2
        failed=1
        continue
    fi
    if ! runner --direct "$(direct "$version")" --proxied "$(proxied "$version")" \
        /differential/scenarios; then
        failed=1
    fi
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
