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
#   - pgsnare as a container: it refuses to start with files that are open
#     to other users, its worker threads follow the processors it may use,
#     it stays within a memory limit that is smaller than the largest
#     message of the scenarios, it cannot write a core dump, and as
#     process 1 it stops on SIGTERM and on SIGINT the way the design says.
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
    # The containers that were started under a name of their own.
    "$docker" rm --force "$project-open-files" "$project-watcher" >/dev/null 2>&1 || true
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

# await_log CONTAINER TEXT: waits until a container has logged TEXT.
await_log() {
    tries=0
    until "$docker" logs "$1" 2>&1 | grep -qF -- "$2"; do
        tries=$((tries + 1))
        if [ "$tries" -ge 150 ]; then
            return 1
        fi
        sleep 0.2
    done
}

# await_exit CONTAINER SECONDS: waits until a container has stopped, for
# SECONDS at most, and prints whether it still runs and its exit status.
# A process 1 that does not handle a signal is not stopped by it at all,
# so a wait for it needs an end of its own.
await_exit() {
    tries=0
    while [ "$("$docker" inspect --format '{{.State.Running}}' "$1")" = "true" ]; do
        tries=$((tries + 1))
        if [ "$tries" -ge "$(($2 * 5))" ]; then
            break
        fi
        sleep 0.2
    done
    "$docker" inspect --format '{{.State.Running}} {{.State.ExitCode}}' "$1"
}

# logged TEXT: whether pgsnare has written a line with TEXT to its log.
# A second argument narrows it to the lines that also contain that.
logged() {
    compose logs --no-log-prefix pgsnare 2>&1 | grep -F -- "$1" | grep -qF -- "${2:-}"
}

# The log of pgsnare is JSON, one object for each line. field NAME VALUE
# gives a field as such a line holds it, for a value that is text.
field() {
    printf '"%s":"%s"' "$1" "$2"
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
    if ! logged "is not the one the database presents" "$(field listener "own-tls-$version")"; then
        echo "itest: FAILED: no warning that listener own-tls-$version presents another certificate than its database" >&2
        failed=1
    fi
    if logged "is not the one the database presents" "$(field listener "shared-tls-$version")"; then
        echo "itest: FAILED: listener shared-tls-$version presents the certificate of its database and was warned about" >&2
        failed=1
    fi
    if ! logged "the certificate of the database is not verified" "$(field listener "own-tls-$version")"; then
        echo "itest: FAILED: no warning that listener own-tls-$version does not verify its database" >&2
        failed=1
    fi
    if logged "the certificate of the database is not verified" "$(field listener "shared-tls-$version")"; then
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
if ! logged "$(field listener legacy-tls)" "the database could not be reached"; then
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

# --- pgsnare as a container ---------------------------------------------------

echo "itest: pgsnare must refuse to start with files that are open to other users"
for config in open-key open-config open-tokens; do
    status=0
    output="$(compose run --rm --no-deps -T pgsnare run \
        --config "/state/config/$config.yaml" 2>&1)" || status=$?
    case "$config" in
        open-key) file="/state/certs/open.key" ;;
        open-tokens) file="/state/config/tokens/open.yaml" ;;
        *) file="/state/config/open-config.yaml" ;;
    esac
    if [ "$status" -ne 1 ] \
        || ! echo "$output" | grep -qF "refusing to start" \
        || ! echo "$output" | grep -qF "$file: the file is open to the group or to others"; then
        echo "itest: FAILED: pgsnare did not refuse $file (exit status $status):" >&2
        echo "$output" | sed 's/^/    /' >&2
        failed=1
    fi
done
# With the override it starts, and says which file it was warned about.
compose run --detach --no-deps --name "$project-open-files" pgsnare run \
    --config /state/config/open-key.yaml --allow-insecure-file-permissions >/dev/null
if ! await_log "$project-open-files" "listening" \
    || ! "$docker" logs "$project-open-files" 2>&1 \
        | grep -F "starting although a file that holds secrets is not protected" \
        | grep -qF "$(field file /state/certs/open.key)"; then
    echo "itest: FAILED: pgsnare did not start with --allow-insecure-file-permissions, or did not say so" >&2
    failed=1
fi
"$docker" rm --force "$project-open-files" >/dev/null 2>&1 || true

echo "itest: the worker threads of pgsnare must follow the processors its container may use"
compose --profile limits up --detach pgsnare-one-cpu pgsnare-two-cpus >/dev/null 2>&1
for limit in "one-cpu 1" "two-cpus 2"; do
    service="pgsnare-${limit% *}"
    if ! await_log "$(compose --profile limits ps --all --quiet "$service")" \
        "\"worker_threads\":${limit#* }}"; then
        echo "itest: FAILED: $service does not run ${limit#* } worker thread(s)" >&2
        compose --profile limits logs --no-log-prefix --tail 20 "$service" >&2 || true
        failed=1
    fi
done
# One of the two is stopped with SIGINT, which must do what SIGTERM does.
interrupted="$(compose --profile limits ps --all --quiet pgsnare-one-cpu)"
"$docker" kill --signal INT "$interrupted" >/dev/null
if [ "$(await_exit "$interrupted" 30)" != "false 0" ] \
    || ! "$docker" logs "$interrupted" 2>&1 | grep -qF "received SIGINT" \
    || ! "$docker" logs "$interrupted" 2>&1 | grep -qF "stopped"; then
    echo "itest: FAILED: pgsnare did not stop on SIGINT with exit status 0" >&2
    failed=1
fi
compose --profile limits rm --stop --force pgsnare-one-cpu pgsnare-two-cpus >/dev/null 2>&1 || true

# The scenarios sent messages of 100 MB through a pgsnare that may use
# 64 MiB. It is still the same process.
proxy="$(compose ps --quiet pgsnare)"
if [ "$("$docker" inspect --format '{{.State.OOMKilled}} {{.RestartCount}}' "$proxy")" != "false 0" ] \
    || [ "$("$docker" exec "$proxy" cat /proc/1/comm)" != "pgsnare" ]; then
    echo "itest: FAILED: pgsnare did not stay within its memory limit, or is not process 1" >&2
    failed=1
fi
peak="$("$docker" exec "$proxy" cat /sys/fs/cgroup/memory.peak 2>/dev/null || echo unknown)"
echo "itest: pgsnare and its health check used at most $peak bytes of memory"

# A core dump would write keys and traffic to disk, so pgsnare switches
# core dumps off for itself.
if ! "$docker" exec "$proxy" grep -Eq '^Max core file size +0 +0 +bytes' /proc/1/limits; then
    echo "itest: FAILED: pgsnare can still write a core dump:" >&2
    "$docker" exec "$proxy" grep 'Max core file size' /proc/1/limits >&2 || true
    failed=1
fi

# The last check, because it ends pgsnare: it stops on SIGTERM.
#
# What a look at pgsnare shows now depends on when the look is taken. So
# everything that has to happen within the grace period happens in a
# client that is already running: on a busy machine, starting a container
# for each look can take longer than the grace period.
echo "itest: pgsnare must stop on SIGTERM, as process 1 of its container"
# The grace period tests/proxy/setup.sh configures, in seconds.
grace=10
watcher="$project-watcher"
compose --profile client run --detach --no-deps --name "$watcher" \
    --entrypoint sleep client 900 >/dev/null

# in_client COMMAND ARGUMENTS...: runs a command in that client.
in_client() {
    "$docker" exec "$watcher" "$@"
}

# A session that is busy when the signal arrives. What the client saw is
# kept, and so is the moment it ended.
staying="$(mktemp)"
(
    in_client psql --no-psqlrc --no-password --quiet \
        --dbname "$(proxied "$first") dbname=postgres" \
        --command "SELECT pg_sleep(300)" 2>&1 || true
    echo "ended at $(date +%s)"
) >"$staying" 2>&1 &
client=$!
tries=0
until [ "$(in_client psql --no-psqlrc --no-password --quiet --tuples-only --no-align \
    --dbname "$(direct "$first") dbname=postgres" \
    --command "SELECT count(*) FROM pg_stat_activity WHERE state = 'active' AND query = 'SELECT pg_sleep(300)'" \
    2>/dev/null)" = "1" ]; do
    tries=$((tries + 1))
    if [ "$tries" -ge 150 ]; then
        echo "itest: FAILED: the session that is to be shut down did not start" >&2
        failed=1
        break
    fi
    sleep 0.2
done

asked="$(date +%s)"
"$docker" kill --signal TERM "$proxy" >/dev/null
# While open sessions get their grace period, nobody new is let in.
refused=0
in_client /differential/version.sh "$first" "$(proxied "$first") connect_timeout=3" \
    >/dev/null 2>&1 || refused=$?
still_draining="$("$docker" inspect --format '{{.State.Running}}' "$proxy")"
looked=$(($(date +%s) - asked))
# pgsnare must end by itself: whether it still runs, and the status it
# ended with.
state="$(await_exit "$proxy" "$((grace + 30))")"
took=$(($(date +%s) - asked))
# Without pgsnare the session is over, whatever became of pgsnare.
"$docker" kill "$proxy" >/dev/null 2>&1 || true
wait "$client" || true
"$docker" rm --force "$watcher" >/dev/null 2>&1 || true

# pgsnare was still there after the new client had been turned away, so
# it was turned away during the grace period.
if [ "$still_draining" != "true" ]; then
    echo "itest: FAILED: pgsnare was gone $looked seconds after SIGTERM, before its grace period of $grace seconds was over, or this machine was too busy to look in time" >&2
    failed=1
elif [ "$refused" -ne 2 ]; then
    echo "itest: FAILED: a new client after SIGTERM: expected exit status 2, got $refused" >&2
    failed=1
fi
# The open session was kept for the grace period, and then closed with
# the error of an administrator shutdown.
ended="$(sed -n 's/^ended at \([0-9][0-9]*\)$/\1/p' "$staying")"
if [ -z "$ended" ]; then
    echo "itest: FAILED: the open session did not say when it ended:" >&2
    sed 's/^/    /' "$staying" >&2
    failed=1
elif [ "$((ended - asked))" -lt "$((grace - 1))" ]; then
    echo "itest: FAILED: the open session was closed $((ended - asked)) seconds after SIGTERM, before its grace period of $grace seconds was over" >&2
    failed=1
fi
if ! grep -qF "FATAL:  terminating connection due to administrator command" "$staying"; then
    echo "itest: FAILED: the open session was not closed with the error of an administrator shutdown:" >&2
    sed 's/^/    /' "$staying" >&2
    failed=1
fi
rm -f "$staying"
if [ "$state" != "false 0" ] || [ "$took" -lt "$((grace - 1))" ]; then
    echo "itest: FAILED: $took seconds after SIGTERM, pgsnare was in the state \"$state\" (whether it runs, and its exit status): it must end with status 0 once its grace period of $grace seconds is over" >&2
    failed=1
fi
for line in "received SIGTERM" "stopping: no new clients are accepted" \
    "the grace period is over" "stopped"; do
    if ! "$docker" logs "$proxy" 2>&1 | grep -qF "$line"; then
        echo "itest: FAILED: pgsnare did not log: $line" >&2
        failed=1
    fi
done

if [ "$failed" -ne 0 ]; then
    echo "itest: the log of pgsnare ends with:" >&2
    compose logs --no-log-prefix --tail 40 pgsnare >&2 || true
    echo "itest: FAILED" >&2
    exit 1
fi
echo "itest: passed"
