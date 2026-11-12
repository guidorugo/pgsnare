#!/bin/sh
# SPDX-License-Identifier: Apache-2.0
#
# The integration tests: `make itest`.
#
# Starts PostgreSQL 15 to 18 with Docker Compose and runs every differential
# scenario against each version. Until pgsnare can relay traffic, both
# endpoints of a comparison are the same PostgreSQL server, which proves the
# harness. The run also proves that the runner reports a difference and an
# unreachable endpoint, so a pass means something.
#
# Environment:
#   DOCKER          the docker command (default: docker)
#   ITEST_PROJECT   the Compose project name (default: pgsnare-itest)
#   ITEST_VERSIONS  the PostgreSQL versions to test (default: "15 16 17 18")

set -eu

cd "$(dirname "$0")/.."

docker="${DOCKER:-docker}"
project="${ITEST_PROJECT:-pgsnare-itest}"
versions="${ITEST_VERSIONS:-15 16 17 18}"

# A password for this run only. It is never written to disk.
PGSNARE_ITEST_PASSWORD="$(od -An -N24 -tx1 /dev/urandom | tr -d ' \n')"
export PGSNARE_ITEST_PASSWORD

compose() {
    "$docker" compose --project-name "$project" --file tests/compose.yaml "$@"
}

cleanup() {
    compose --profile client down --volumes --remove-orphans >/dev/null 2>&1 || true
}
trap cleanup EXIT
trap 'exit 130' INT
trap 'exit 143' TERM

# runner ARGUMENTS...: runs the differential runner in the client container.
runner() {
    compose --profile client run --rm --no-deps -T client "$@"
}

services=""
for version in $versions; do
    services="$services pg$version"
done

echo "itest: starting PostgreSQL $versions"
# shellcheck disable=SC2086
compose up --detach --wait --wait-timeout 180 $services

failed=0

for version in $versions; do
    echo "itest: PostgreSQL $version, both endpoints direct"
    endpoint="host=pg$version port=5432 user=postgres"
    if ! runner --direct "$endpoint" --proxied "$endpoint" /differential/scenarios; then
        failed=1
    fi
done

# The runner must report a difference when there is one.
set -- $versions
first="$1"
last="$1"
for version in $versions; do
    last="$version"
done
if [ "$first" != "$last" ]; then
    echo "itest: the runner must tell PostgreSQL $first from PostgreSQL $last"
    status=0
    runner --direct "host=pg$first port=5432 user=postgres" \
        --proxied "host=pg$last port=5432 user=postgres" \
        /differential/selfcheck >/dev/null 2>&1 || status=$?
    if [ "$status" -ne 1 ]; then
        echo "itest: FAILED: expected exit status 1 for different output, got $status" >&2
        failed=1
    fi
fi

# The runner must not mistake an unreachable endpoint for a match.
echo "itest: the runner must reject an endpoint that does not answer"
status=0
runner --direct "host=pg$first port=5432 user=postgres" \
    --proxied "host=pg$first port=1 user=postgres connect_timeout=5" \
    /differential/selfcheck >/dev/null 2>&1 || status=$?
if [ "$status" -ne 2 ]; then
    echo "itest: FAILED: expected exit status 2 for an unreachable endpoint, got $status" >&2
    failed=1
fi

if [ "$failed" -ne 0 ]; then
    echo "itest: FAILED" >&2
    exit 1
fi
echo "itest: passed"
