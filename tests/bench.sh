#!/bin/sh
# SPDX-License-Identifier: Apache-2.0
#
# A baseline benchmark: the same load against PostgreSQL itself and
# through pgsnare.
#
# It is a baseline and not a gate. It runs wherever the integration tests
# run, on whatever that machine is doing at the time, without pinned
# processors, with the load generator, pgsnare and the database sharing
# them. The figures say how the two paths compare on one machine on one
# day. They are not the reference benchmark of the design document.
#
# What it measures, with pgbench:
#
#   - select-only transactions with prepared statements, for a fixed time:
#     transactions per second and the average latency, in plaintext and
#     with TLS, directly and through pgsnare
#   - the memory pgsnare needs for a connection that is open and idle
#
# Usage: tests/bench.sh        (after `make itest` has built the binary)
#
# Environment:
#   DOCKER          the docker command (default: docker)
#   BENCH_PROJECT   the Compose project name (default: pgsnare-bench)
#   BENCH_VERSION   the PostgreSQL version to use (default: 18)
#   BENCH_SECONDS   how long each run lasts (default: 20)
#   BENCH_CLIENTS   how many clients each run uses (default: 8)
#   BENCH_IDLE      how many idle connections the memory figure is taken
#                   from (default: 80)
#   ITEST_BINARY    the pgsnare binary (default: the release build in
#                   target/)

set -eu

cd "$(dirname "$0")/.."

docker="${DOCKER:-docker}"
project="${BENCH_PROJECT:-pgsnare-bench}"
version="${BENCH_VERSION:-18}"
seconds="${BENCH_SECONDS:-20}"
clients="${BENCH_CLIENTS:-8}"
idle="${BENCH_IDLE:-80}"
binary="${ITEST_BINARY:-$PWD/target/release/pgsnare}"

if [ ! -x "$binary" ]; then
    echo "bench: there is no pgsnare binary at $binary: run make itest first" >&2
    exit 2
fi

PGSNARE_ITEST_PASSWORD="$(od -An -N24 -tx1 /dev/urandom | tr -d ' \n')"
export PGSNARE_ITEST_PASSWORD
export ITEST_VERSIONS="$version"
export ITEST_BINARY="$binary"
export ITEST_READY_PORT="60$version"

compose() {
    "$docker" compose --project-name "$project" --file tests/compose.yaml "$@"
}

cleanup() {
    compose --profile client --profile setup down --volumes --remove-orphans >/dev/null 2>&1 || true
}
trap cleanup EXIT
trap 'exit 130' INT
trap 'exit 143' TERM

# client COMMAND ARGUMENTS...: runs a command in the client container.
client() {
    command="$1"
    shift
    compose --profile client run --rm --no-deps -T --entrypoint "$command" client "$@"
}

# resident: the memory the pgsnare process holds right now, in kB.
resident() {
    "$docker" exec "$proxy" sed -n 's/^VmRSS:[[:space:]]*\([0-9]*\) kB$/\1/p' /proc/1/status
}

echo "bench: starting PostgreSQL $version and pgsnare" >&2
compose --profile setup run --rm --no-deps -T setup >/dev/null
compose up --detach --wait --wait-timeout 180 "pg$version" >/dev/null 2>&1
compose up --detach --wait --wait-timeout 60 pgsnare >/dev/null 2>&1
proxy="$(compose ps --quiet pgsnare)"

direct="host=pg$version port=5432 user=postgres dbname=postgres"
through="host=pgsnare user=postgres dbname=postgres"

echo "bench: filling the tables" >&2
client pgbench --initialize --scale 10 --quiet "$direct sslmode=disable" >/dev/null 2>&1

# run CLIENTS NAME CONNINFO: one select-only run, reported as one line.
run() {
    result="$(client pgbench --select-only --protocol prepared --client "$1" --jobs 2 \
        --time "$seconds" --no-vacuum "$3" 2>/dev/null)"
    tps="$(echo "$result" | sed -n 's/^tps = \([0-9.]*\) .*$/\1/p')"
    latency="$(echo "$result" | sed -n 's/^latency average = \([0-9.]*\) ms$/\1/p')"
    printf '| %s | %s | %.0f | %s |\n' "$2" "$1" "$tps" "$latency"
}

echo
echo "Select-only transactions with prepared statements, $seconds seconds each, PostgreSQL $version:"
echo
echo "| Path | Clients | Transactions per second | Average latency (ms) |"
echo "|---|---|---|---|"
# One client shows what a transaction waits for on its way through
# pgsnare. Several show what is left of the throughput when the load
# generator, pgsnare and the database compete for the same processors.
for count in 1 "$clients"; do
    run "$count" "Direct, plaintext" "$direct sslmode=disable"
    run "$count" "Through pgsnare, plaintext on both legs" "$through port=60$version sslmode=disable"
    run "$count" "Direct, TLS" "$direct sslmode=require"
    run "$count" "Through pgsnare, TLS on both legs" "$through port=64$version sslmode=require"
done

# Connections that are open and idle. They log in, run one statement and
# then wait, long enough for pgsnare to give back what a busy session
# holds.
idle_memory() {
    name="$1"
    before="$(resident)"
    client sh -c 'printf "SELECT 1;\n\\\\sleep 12 s\n" > /tmp/idle.sql
        exec pgbench --client "$1" --jobs 4 --transactions 1 --no-vacuum --file /tmp/idle.sql "$2"' \
        sh "$idle" "$2" >/dev/null 2>&1 &
    waiting=$!
    sleep 9
    during="$(resident)"
    wait "$waiting" || true
    each=$(((during - before) * 1024 / idle))
    printf '| %s | %s | %s | %s |\n' "$name" "$before" "$during" "$each"
}

echo
echo "Memory of the pgsnare process with $idle connections that are open and idle:"
echo
echo "| Connections | Before (kB) | With the connections (kB) | Per connection (bytes) |"
echo "|---|---|---|---|"
idle_memory "Plaintext on both legs" "$through port=60$version sslmode=disable"
idle_memory "TLS on both legs" "$through port=64$version sslmode=require"
