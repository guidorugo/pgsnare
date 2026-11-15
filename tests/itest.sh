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
#   - What `pgsnare token generate` prints. PostgreSQL itself runs the
#     statement, with names that try to get out of their quotes, and is
#     given the SCRAM-SHA-256 and bcrypt bait: tests/bait/check.sh. The
#     command is also run without a network and without a place to write.
#   - `pgsnare config check`. It must pass the configuration pgsnare runs
#     with, and refuse the ones pgsnare refuses to start with.
#   - The responses against each database: kill over the extended protocol
#     in text and in binary format (no byte of the value reaches the client
#     and the backend is gone), tarpit (each answer is held back at least
#     the shortest delay, and both of its limits end a session), fake_data
#     (the rows parse and the command tag counts them; a binary result gets
#     no rows and its event says alert), a reload under the running process
#     by SIGHUP, by a change of the file and with a broken file, and a hit
#     that reaches a webhook within 2 seconds.
#   - A statement that calls a function from the list of the SQL rules
#     (`pg_sleep`, with `kill`) is ended before it reaches the database,
#     also when its text hides the name, and a rule_hit event names the rule.
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
#   - the checks of the bait are each made on input that must fail them
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
    "$docker" rm --force "$project-open-files" "$project-watcher" "$project-live" >/dev/null 2>&1 || true
    compose --profile client --profile setup --profile offline down --volumes --remove-orphans >/dev/null 2>&1 || true
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
if ! compose up --detach --wait --wait-timeout 180 $services pglegacy receiver; then
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

# --- The commands -------------------------------------------------------------

echo "itest: what token generate prints, checked by PostgreSQL $versions"
# shellcheck disable=SC2086
if ! compose --profile client run --rm --no-deps -T \
    --entrypoint /bait/check.sh client $versions; then
    failed=1
fi

# token generate connects to nothing and writes nothing but its output, so
# it must do its work in a container that has no network and no place to
# write to.
echo "itest: token generate must work without a network and without a place to write"
status=0
output="$(compose --profile offline run --rm --no-deps -T offline \
    token generate --kind scram-sha-256 --table auth.roles --count 2 2>&1)" || status=$?
if [ "$status" -ne 0 ] \
    || ! echo "$output" | grep -qF 'INSERT INTO "auth"."roles" ("password_hash") VALUES' \
    || [ "$(echo "$output" | grep -c "^    ('SCRAM-SHA-256\$4096:")" -ne 2 ]; then
    echo "itest: FAILED: token generate did not work without a network (exit status $status):" >&2
    echo "$output" | sed 's/^/    /' >&2
    failed=1
fi

# config check and run share their code, so they must say the same about a
# configuration. This one is what pgsnare is running with right now.
echo "itest: config check must pass the configuration pgsnare runs with"
status=0
output="$(compose run --rm --no-deps -T pgsnare config check \
    --config /state/config/pgsnare.yaml 2>&1)" || status=$?
unverified="$(echo "$output" | grep -c 'upstream_tls.mode: the certificate of the database is not verified' || true)"
# One listener for each version does not verify its database: see
# tests/proxy/setup.sh.
expected=0
for version in $versions; do
    expected=$((expected + 1))
done
if [ "$status" -ne 0 ] \
    || ! echo "$output" | grep -qF "ok: /state/config/pgsnare.yaml: pgsnare would start with" \
    || [ "$unverified" -ne "$expected" ]; then
    echo "itest: FAILED: config check did not pass the configuration pgsnare runs with, or did not warn about each of the $expected listeners that do not verify their database (exit status $status, $unverified warnings):" >&2
    echo "$output" | sed 's/^/    /' >&2
    failed=1
fi

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

    # config check refuses what run refuses, and names the same file.
    status=0
    output="$(compose run --rm --no-deps -T pgsnare config check \
        --config "/state/config/$config.yaml" 2>&1)" || status=$?
    if [ "$status" -ne 1 ] \
        || ! echo "$output" | grep -qF "error: $file: the file is open to the group or to others" \
        || ! echo "$output" | grep -qF "failed: /state/config/$config.yaml: pgsnare would not start"; then
        echo "itest: FAILED: config check did not refuse $file (exit status $status):" >&2
        echo "$output" | sed 's/^/    /' >&2
        failed=1
    fi
    # With the override that lets run start, it passes and warns.
    status=0
    output="$(compose run --rm --no-deps -T pgsnare config check \
        --config "/state/config/$config.yaml" --allow-insecure-file-permissions 2>&1)" || status=$?
    if [ "$status" -ne 0 ] \
        || ! echo "$output" | grep -qF "warning: $file: the file is open to the group or to others" \
        || ! echo "$output" | grep -qF "ok: /state/config/$config.yaml: pgsnare would start"; then
        echo "itest: FAILED: config check with --allow-insecure-file-permissions did not pass $file with a warning (exit status $status):" >&2
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

# --- A honeytoken read through pgsnare ---------------------------------------

echo "itest: a honeytoken read through pgsnare must raise an event, and kill must end the session"
# psql_as WHERE ARGUMENTS...: runs psql in the client container against
# the database itself or through pgsnare.
psql_as() {
    conninfo="$1"
    shift
    compose --profile client run --rm --no-deps -T --entrypoint psql client \
        --no-psqlrc --no-password --quiet --tuples-only --no-align \
        --dbname "$conninfo dbname=postgres" "$@"
}
psql_as "$(direct "$first")" --command \
    "CREATE TABLE itest_bait (v text); INSERT INTO itest_bait VALUES ('itest-bait-alert-5d83c1'); CREATE TABLE itest_bait_kill (v text); INSERT INTO itest_bait_kill VALUES ('itest-bait-kill-7e20a9')" \
    >/dev/null

# alert: the client gets the row, and an event names the token.
if ! psql_as "$(proxied "$first")" --command "SELECT v FROM itest_bait" 2>&1 \
    | grep -qxF "itest-bait-alert-5d83c1"; then
    echo "itest: FAILED: a session that hit an alert token did not get its row" >&2
    failed=1
fi
tries=0
until logged "$(field kind token_hit)" "$(field token_id itest-alert)"; do
    tries=$((tries + 1))
    if [ "$tries" -ge 50 ]; then
        echo "itest: FAILED: no token_hit event for the token that was read" >&2
        failed=1
        break
    fi
    sleep 0.2
done

# kill: the client gets the error of an administrator shutdown and never
# the row, and an event names the token.
status=0
output="$(psql_as "$(proxied "$first")" --command "SELECT v FROM itest_bait_kill" 2>&1)" || status=$?
if [ "$status" -eq 0 ] \
    || ! echo "$output" | grep -qF "terminating connection due to administrator command" \
    || echo "$output" | grep -qF "itest-bait-kill-7e20a9"; then
    echo "itest: FAILED: a session that hit a kill token was not ended with the error, or got the row (exit status $status):" >&2
    echo "$output" | sed 's/^/    /' >&2
    failed=1
fi
tries=0
until logged "$(field kind token_hit)" "$(field token_id itest-kill)"; do
    tries=$((tries + 1))
    if [ "$tries" -ge 50 ]; then
        echo "itest: FAILED: no token_hit event for the token of kill" >&2
        failed=1
        break
    fi
    sleep 0.2
done
psql_as "$(direct "$first")" --command "DROP TABLE itest_bait, itest_bait_kill" >/dev/null 2>&1 || true

# --- The responses against real databases --------------------------------------
#
# kill over the extended protocol, tarpit, fake_data, a reload under the
# running process, and a hit delivered to a webhook. Everything that
# measures time runs in one client container that stays up, so that the
# start of a container is never part of what is measured. The tokens are
# those of tests/proxy/setup.sh.

echo "itest: the responses, against PostgreSQL $versions"
live="$project-live"
compose --profile client run --detach --no-deps --name "$live" \
    --entrypoint sleep client 1800 >/dev/null
receiver="$(compose ps --quiet receiver)"
killed_text="terminating connection due to administrator command"

# in_live COMMAND ARGUMENTS...: runs a command in that client.
in_live() {
    "$docker" exec "$live" "$@"
}

# psql_live CONNINFO: runs the statements on standard input with psql in
# that client.
psql_live() {
    "$docker" exec -i "$live" psql --no-psqlrc --no-password --quiet \
        --tuples-only --no-align --dbname "$1 dbname=postgres"
}

# backends VERSION CONDITION: how many backends of PostgreSQL VERSION that
# meet CONDITION pg_stat_activity shows.
backends() {
    echo "SELECT count(*) FROM pg_stat_activity WHERE $2;" \
        | psql_live "$(direct "$1")" 2>/dev/null
}

# await_backends VERSION CONDITION COUNT: waits up to 10 seconds until
# COUNT backends meet CONDITION.
await_backends() {
    tries=0
    until [ "$(backends "$1" "$2")" = "$3" ]; do
        tries=$((tries + 1))
        if [ "$tries" -ge 50 ]; then
            return 1
        fi
        sleep 0.2
    done
}

# hits TOKEN_ID: how many token_hit events for TOKEN_ID pgsnare has logged.
hits() {
    compose logs --no-log-prefix pgsnare 2>&1 | grep -F "$(field kind token_hit)" \
        | grep -cF "$(field token_id "$1")" || true
}

# await_hits TOKEN_ID COUNT: waits up to 10 seconds until there are COUNT.
await_hits() {
    tries=0
    until [ "$(hits "$1")" -ge "$2" ]; do
        tries=$((tries + 1))
        if [ "$tries" -ge 50 ]; then
            return 1
        fi
        sleep 0.2
    done
}

# taken TOKEN_ID: the action_taken of the last token_hit event for TOKEN_ID.
taken() {
    compose logs --no-log-prefix pgsnare 2>&1 | grep -F "$(field kind token_hit)" \
        | grep -F "$(field token_id "$1")" | tail -n 1 \
        | sed -n 's/.*"action_taken":\(\[[^]]*\]\).*/\1/p'
}

# hex TEXT: TEXT in lowercase hexadecimal, as wire.pl prints a message.
hex() {
    printf '%s' "$1" | od -An -tx1 | tr -d ' \n'
}

# leaks OUTPUT VALUE: whether OUTPUT holds VALUE as it is written, in
# hexadecimal of either case, or in base64.
leaks() {
    lower="$(hex "$2")"
    upper="$(echo "$lower" | tr 'a-f' 'A-F')"
    encoded="$(printf '%s' "$2" | base64 | tr -d '\n')"
    for form in "$2" "$lower" "$upper" "$encoded"; do
        if printf '%s' "$1" | grep -qF -- "$form"; then
            return 0
        fi
    done
    return 1
}

# ext_text CONNINFO / ext_binary CONNINFO: read the kill token over the
# extended protocol, with a text result (psql's \bind) and with a binary
# one (wire.pl). Each prints the process id of its backend first.
ext_text() {
    printf '%s\n' 'SELECT pg_backend_pid();' \
        'SELECT v FROM itest_kill_ext WHERE v <> $1 \bind itest-none \g' \
        | psql_live "$1"
}
ext_binary() {
    in_live perl /differential/wire.pl "$1 dbname=postgres" extended \
        "SELECT v FROM itest_kill_ext" binary
}

killext_value="itest-bait-killext-3f6b91"
expected_hits=0
for version in $versions; do
    if ! printf '%s\n' \
        "CREATE TABLE itest_kill_ext (v text);" \
        "INSERT INTO itest_kill_ext VALUES ('$killext_value');" \
        "CREATE TABLE itest_tarpit (v text);" \
        "INSERT INTO itest_tarpit VALUES ('itest-bait-tarpit-a4d702');" \
        "CREATE TABLE itest_fake (id int4, name text, code varchar(12), ref uuid);" \
        "INSERT INTO itest_fake VALUES (1, 'itest-bait-fake-41ac0e', 'alpha', gen_random_uuid()), (2, 'second', 'bravo-two', gen_random_uuid()), (3, 'third', 'charlie', gen_random_uuid());" \
        "CREATE TABLE itest_hook (v text);" \
        "INSERT INTO itest_hook VALUES ('itest-bait-hook-90e5c3');" \
        | psql_live "$(direct "$version")" >/dev/null; then
        echo "itest: FAILED: the tables of the responses could not be made in PostgreSQL $version" >&2
        failed=1
    fi
done

# The search for the value must find it where it is: PostgreSQL itself
# sends it in both forms.
for form in text binary; do
    output="$("ext_$form" "$(direct "$first")" 2>&1)" || true
    if ! leaks "$output" "$killext_value"; then
        echo "itest: FAILED: the search for a value does not find it in the $form result of PostgreSQL itself:" >&2
        echo "$output" | sed 's/^/    /' >&2
        failed=1
    fi
done

echo "itest: kill over the extended protocol, in text and in binary format"
for version in $versions; do
    for form in text binary; do
        status=0
        output="$("ext_$form" "$(proxied "$version")" 2>&1)" || status=$?
        backend="$(echo "$output" | sed -n 's/^\(backend \)\{0,1\}\([0-9][0-9]*\)$/\2/p' | head -n 1)"
        said="$killed_text"
        if [ "$form" = binary ]; then
            said="$(hex "$killed_text")"
        fi
        if [ "$status" -eq 0 ] || [ -z "$backend" ] \
            || ! echo "$output" | grep -qF "$said" \
            || leaks "$output" "$killext_value"; then
            echo "itest: FAILED: a session that read a kill token over the extended protocol ($form, PostgreSQL $version) was not ended with the error, or got a form of the value (exit status $status):" >&2
            echo "$output" | sed 's/^/    /' >&2
            failed=1
        elif ! await_backends "$version" "pid = $backend" 0; then
            echo "itest: FAILED: the backend of a killed session ($form, PostgreSQL $version) was still there 10 seconds later" >&2
            failed=1
        fi
        expected_hits=$((expected_hits + 1))
    done
done
if ! await_hits itest-kill-ext "$expected_hits"; then
    echo "itest: FAILED: $(hits itest-kill-ext) token_hit events for the kill token over the extended protocol, expected $expected_hits" >&2
    failed=1
fi

echo "itest: tarpit: each answer is held back, and both limits end a session"
for version in $versions; do
    name="itest-tarpit-$version"
    before="$(hits itest-tarpit)"
    timed="$(mktemp)"
    # The first session holds the only place in the tarpit until its
    # longest time (10 seconds) is over; its last statement would take a
    # minute.
    (
        printf '%s\n' '\timing on' 'SELECT pg_backend_pid();' \
            'SELECT v FROM itest_tarpit;' "SELECT 'itest-tarpit-after';" \
            'SELECT pg_sleep(60) AS itest_tarpit_wait;' \
            | "$docker" exec -i "$live" sh -c '
                started=$(date +%s%N)
                status=0
                psql --no-psqlrc --no-password --quiet --tuples-only --no-align \
                    --dbname "$1" 2>&1 || status=$?
                echo "itest-ended $(( ($(date +%s%N) - started) / 1000000 )) $status"' \
                sh "$(proxied "$version") dbname=postgres application_name=$name"
    ) >"$timed" 2>&1 &
    held=$!
    if ! await_backends "$version" "application_name = '$name'" 1 \
        || ! await_hits itest-tarpit "$((before + 1))"; then
        echo "itest: FAILED: the session to be tarpitted (PostgreSQL $version) did not start, or its hit was not reported" >&2
        failed=1
    else
        # A second session while the place is taken is killed at once.
        status=0
        output="$(echo 'SELECT v FROM itest_tarpit;' | psql_live "$(proxied "$version")" 2>&1)" || status=$?
        if [ "$status" -eq 0 ] || ! echo "$output" | grep -qF "$killed_text" \
            || leaks "$output" itest-bait-tarpit-a4d702; then
            echo "itest: FAILED: a session to be tarpitted while the tarpit was full (PostgreSQL $version) was not killed (exit status $status):" >&2
            echo "$output" | sed 's/^/    /' >&2
            failed=1
        fi
    fi
    wait "$held" || true
    # psql's own times, in whole milliseconds: before the hit, the hit,
    # and the statement after it.
    times="$(sed -n 's/^Time: \([0-9][0-9]*\).*/\1/p' "$timed" | tr '\n' ' ')"
    ended="$(sed -n 's/^itest-ended \([0-9][0-9]*\) \([0-9][0-9]*\)$/\1 \2/p' "$timed")"
    set -- $times 0 0 0
    took="${ended% *}"
    if [ -z "$ended" ] || [ "$1" -ge 2000 ] || [ "$2" -lt 2000 ] || [ "$3" -lt 2000 ] \
        || [ "$took" -lt 9000 ] || [ "$took" -ge 40000 ] || [ "${ended#* }" -eq 0 ] \
        || ! grep -qF "$killed_text" "$timed"; then
        echo "itest: FAILED: the tarpitted session (PostgreSQL $version) was not held back at least 2 s per answer, or was not killed after 10 s (times in ms: $times; ended after ms, status: $ended):" >&2
        sed 's/^/    /' "$timed" >&2
        failed=1
    else
        echo "itest: PostgreSQL $version: answers in the tarpit took $2 and $3 ms, the session ended after $took ms"
    fi
    rm -f "$timed"
    if ! await_backends "$version" "application_name = '$name'" 0; then
        echo "itest: FAILED: the backend of the tarpitted session (PostgreSQL $version) was not released" >&2
        failed=1
    fi
done

echo "itest: fake_data: the rows parse and the tag counts them; a binary result falls back"
fake_row='^-?[0-9]{1,10}\|[^|]*\|[^|]{0,12}\|[0-9A-Fa-f]{8}-[0-9A-Fa-f]{4}-[0-9A-Fa-f]{4}-[0-9A-Fa-f]{4}-[0-9A-Fa-f]{12}$'
for version in $versions; do
    before="$(hits itest-fake)"
    status=0
    output="$(printf '%s\n' 'SELECT id, name, code, ref FROM itest_fake;' \
        '\echo itest-tag :ROW_COUNT' | psql_live "$(proxied "$version")" 2>&1)" || status=$?
    rows="$(echo "$output" | grep -v '^itest-tag ' || true)"
    tag="$(echo "$output" | sed -n 's/^itest-tag \([0-9][0-9]*\)$/\1/p')"
    total="$(echo "$rows" | grep -c . || true)"
    good="$(echo "$rows" | grep -cE "$fake_row" || true)"
    ids="$(echo "$rows" | cut -d '|' -f 1 | sort -u | grep -c . || true)"
    # Three rows of the table and the three the settings add.
    if [ "$status" -ne 0 ] || [ "$total" -ne 6 ] || [ "$tag" != "$total" ] \
        || [ "$good" -ne 6 ] || [ "$ids" -ne 6 ]; then
        echo "itest: FAILED: fake_data in a text result (PostgreSQL $version): expected 6 well-formed rows with distinct ids and a tag that counts them (exit status $status, $total rows, $good well-formed, $ids ids, tag ${tag:-none}):" >&2
        echo "$output" | sed 's/^/    /' >&2
        failed=1
    fi
    if ! await_hits itest-fake "$((before + 1))" || [ "$(taken itest-fake)" != '["fake_data"]' ]; then
        echo "itest: FAILED: the event of fake_data in a text result (PostgreSQL $version) does not say fake_data: $(taken itest-fake)" >&2
        failed=1
    fi

    before="$(hits itest-fake)"
    status=0
    output="$(in_live perl /differential/wire.pl "$(proxied "$version") dbname=postgres" \
        extended 'SELECT id, name, code, ref FROM itest_fake' binary 2>&1)" || status=$?
    if [ "$status" -ne 0 ] || [ "$(echo "$output" | grep -c '^D ')" -ne 3 ] \
        || ! echo "$output" | grep -qxF "C $(hex 'SELECT 3')00"; then
        echo "itest: FAILED: a binary result with a fake_data token (PostgreSQL $version) did not pass unchanged (exit status $status):" >&2
        echo "$output" | sed 's/^/    /' >&2
        failed=1
    fi
    if ! await_hits itest-fake "$((before + 1))" || [ "$(taken itest-fake)" != '["alert"]' ]; then
        echo "itest: FAILED: the event of a binary result with a fake_data token (PostgreSQL $version) does not say alert: $(taken itest-fake)" >&2
        failed=1
    fi
done

echo "itest: a hit must reach the webhook within 2 seconds"
# deliveries: how many token_hit events for itest-hook the receiver got.
deliveries() {
    "$docker" logs "$receiver" 2>&1 | grep -c ' token_hit itest-hook ' || true
}
for version in $versions; do
    before="$(deliveries)"
    status=0
    # The time is taken in the client just before psql starts, so the
    # delay measured includes the login and the whole statement.
    output="$(echo 'SELECT v FROM itest_hook;' | "$docker" exec -i "$live" sh -c '
        date +%s.%N
        exec psql --no-psqlrc --no-password --quiet --tuples-only --no-align --dbname "$1"' \
        sh "$(proxied "$version") dbname=postgres" 2>&1)" || status=$?
    started="$(echo "$output" | sed -n 1p)"
    if [ "$status" -ne 0 ] || ! echo "$output" | grep -qxF itest-bait-hook-90e5c3; then
        echo "itest: FAILED: the read for the webhook (PostgreSQL $version) did not get its row (exit status $status)" >&2
        failed=1
        continue
    fi
    tries=0
    until [ "$(deliveries)" -gt "$before" ]; do
        tries=$((tries + 1))
        if [ "$tries" -ge 50 ]; then
            break
        fi
        sleep 0.2
    done
    arrived="$("$docker" logs "$receiver" 2>&1 | grep ' token_hit itest-hook ' | sed -n "$((before + 1))p")"
    at="$(echo "$arrived" | cut -d ' ' -f 2)"
    delay="$(awk -v from="$started" -v to="${at:-0}" 'BEGIN { printf "%.3f", to - from }')"
    if [ -z "$arrived" ] || [ "$(echo "$arrived" | cut -d ' ' -f 5)" != signed ] \
        || ! awk -v delay="$delay" 'BEGIN { exit !(delay >= 0 && delay <= 2) }'; then
        echo "itest: FAILED: the hit (PostgreSQL $version) did not reach the webhook signed within 2 seconds (${arrived:-nothing arrived}; $delay s)" >&2
        failed=1
    else
        echo "itest: PostgreSQL $version: the hit reached the webhook $delay s after the client started"
    fi
done

echo "itest: a reload under the running process: by SIGHUP, by a change of the file, and a broken file"
# reload STAGE: changes the token file: tests/proxy/reload.sh.
reload() {
    compose --profile setup run --rm --no-deps -T --entrypoint /proxy/reload.sh setup "$1"
}
# to_session STATEMENT: sends a line to the session that stays open.
to_session() {
    "$docker" exec "$live" sh -c 'printf "%s\n" "$1" > /tmp/reload.in' sh "$1"
}
# probe TOKEN_ID VALUE: sends VALUE on the open session four times a
# second, for 6 seconds at most, until a token_hit names TOKEN_ID.
probe() {
    tries=0
    while [ "$tries" -lt 24 ]; do
        to_session "SELECT '$2' AS itest_probe;"
        sleep 0.25
        tries=$((tries + 1))
        if [ "$((tries % 4))" -eq 0 ] && [ "$(hits "$1")" -gt 0 ]; then
            return 0
        fi
    done
    [ "$(hits "$1")" -gt 0 ]
}
# first_hit TOKEN_ID: when the first token_hit for TOKEN_ID reached the log,
# in seconds since the epoch, by the clock of the containers.
first_hit() {
    stamp="$("$docker" logs --timestamps "$proxy" 2>&1 | grep -F "$(field kind token_hit)" \
        | grep -F "$(field token_id "$1")" | head -n 1 | cut -d ' ' -f 1)"
    if [ -n "$stamp" ]; then
        in_live date -d "$stamp" +%s.%N
    fi
}
# within FROM TO: whether TO is at most 3 seconds after FROM.
within() {
    awk -v from="${1:-0}" -v to="${2:-0}" 'BEGIN { d = to - from; exit !(from > 0 && d >= 0 && d <= 3) }'
}
reload_failures() {
    compose logs --no-log-prefix pgsnare 2>&1 \
        | grep -F "the configuration could not be reloaded" \
        | grep -cF "$(field file /state/config/reload/tokens.yaml)" || true
}

in_live mkfifo /tmp/reload.in
"$docker" exec -d "$live" sh -c 'exec sleep 900 > /tmp/reload.in'
"$docker" exec -d "$live" sh -c 'exec psql --no-psqlrc --no-password --quiet --tuples-only --no-align --dbname "$1" < /tmp/reload.in > /tmp/reload.out 2>&1' \
    sh "$(proxied "$first") dbname=postgres application_name=itest-reload"
if ! await_backends "$first" "application_name = 'itest-reload'" 1; then
    echo "itest: FAILED: the session that is to stay open across the reloads did not start" >&2
    failed=1
else
    to_session "SELECT 'itest-reload-' || pg_backend_pid();"

    # SIGHUP. The change is one the watch cannot see, which the first
    # probe proves: it must not be detected before the signal.
    if ! reload signal; then
        echo "itest: FAILED: the token file could not be changed" >&2
        failed=1
    fi
    sleep 3
    to_session "SELECT 'itest-bait-reload-signal-d81f4a' AS itest_probe;"
    sleep 1
    if [ "$(hits itest-reload-signal)" -ne 0 ]; then
        echo "itest: FAILED: a change the watch of the files cannot see was in force before SIGHUP, so the check of SIGHUP proves nothing" >&2
        failed=1
    fi
    sent="$(in_live date +%s.%N)"
    "$docker" kill --signal HUP "$proxy" >/dev/null
    if ! probe itest-reload-signal itest-bait-reload-signal-d81f4a \
        || ! within "$sent" "$(first_hit itest-reload-signal)" \
        || ! logged "received SIGHUP"; then
        echo "itest: FAILED: a token added before SIGHUP was not detected on the open session within 3 seconds (signal at $sent, hit at $(first_hit itest-reload-signal))" >&2
        failed=1
    fi

    # A change of the file, without a signal.
    to_session "SELECT 'itest-bait-reload-watch-37b09e' AS itest_probe;"
    sleep 1
    if [ "$(hits itest-reload-watch)" -ne 0 ]; then
        echo "itest: FAILED: a token was detected before it was added to the file" >&2
        failed=1
    fi
    changed="$(reload watch)" || changed=""
    if ! probe itest-reload-watch itest-bait-reload-watch-37b09e \
        || ! within "$changed" "$(first_hit itest-reload-watch)"; then
        echo "itest: FAILED: a token added to the file was not detected on the open session within 3 seconds (changed at ${changed:-unknown}, hit at $(first_hit itest-reload-watch))" >&2
        failed=1
    fi

    # A broken file: logged, and the policy in force stays.
    before="$(reload_failures)"
    reload broken || true
    tries=0
    until [ "$(reload_failures)" -gt "$before" ]; do
        tries=$((tries + 1))
        if [ "$tries" -ge 50 ]; then
            echo "itest: FAILED: pgsnare did not log that the broken token file could not be reloaded" >&2
            failed=1
            break
        fi
        sleep 0.2
    done
    output="$(echo "SELECT 'itest-bait-reload-base-6c2e17' AS itest_probe;" | psql_live "$(proxied "$first")" 2>&1)" || true
    if ! await_hits itest-reload-base 1; then
        echo "itest: FAILED: after a broken token file the tokens in force were no longer detected" >&2
        failed=1
    fi

    # The session was the same one all along.
    to_session "SELECT 'itest-reload-' || pg_backend_pid();"
    to_session '\q'
    if ! await_backends "$first" "application_name = 'itest-reload'" 0; then
        echo "itest: FAILED: the open session did not end when it was told to" >&2
        failed=1
    fi
    output="$(in_live cat /tmp/reload.out 2>&1)" || true
    if [ "$(echo "$output" | grep -c '^itest-reload-[0-9][0-9]*$')" -ne 2 ] \
        || [ "$(echo "$output" | grep '^itest-reload-[0-9][0-9]*$' | sort -u | grep -c .)" -ne 1 ]; then
        echo "itest: FAILED: the session that was open across the reloads was dropped or replaced:" >&2
        echo "$output" | sed 's/^/    /' >&2
        failed=1
    fi
fi

for version in $versions; do
    echo "DROP TABLE IF EXISTS itest_kill_ext, itest_tarpit, itest_fake, itest_hook;" \
        | psql_live "$(direct "$version")" >/dev/null 2>&1 || true
done
"$docker" rm --force "$live" >/dev/null 2>&1 || true

# --- A statement that sets off a rule ------------------------------------------

echo "itest: a statement that calls a listed function must be ended before it reaches the database"
# The listeners of setup 71 are the only ones the rule applies to. The
# client asks for UTF8 because the rules read a statement only when the
# database has been told how the client encodes it.
for version in $versions; do
    ruled="host=pgsnare port=71$version user=postgres sslmode=disable client_encoding=UTF8"
    if ! psql_as "$ruled" --command "SELECT 1 AS itest_ruled" 2>&1 | grep -qxF "1"; then
        echo "itest: FAILED: a statement that no rule concerns did not get its answer on a listener with rules (PostgreSQL $version)" >&2
        failed=1
    fi
    # Written so that a search of the text would not see the function:
    # a comment, a schema, other case, quotes ("pg_sleep" is the same name).
    for statement in \
        "SELECT pg_sleep(300)" \
        "SELECT /* x */ Pg_Catalog.\"pg_sleep\"(300)"; do
        status=0
        started="$(date +%s)"
        output="$(psql_as "$ruled" --command "$statement" 2>&1)" || status=$?
        if [ "$status" -eq 0 ] \
            || ! echo "$output" | grep -qF "terminating connection due to administrator command" \
            || [ "$(($(date +%s) - started))" -ge 60 ]; then
            echo "itest: FAILED: a session that called a listed function was not ended at once with the error (PostgreSQL $version, exit status $status):" >&2
            echo "$output" | sed 's/^/    /' >&2
            failed=1
        fi
    done
done
tries=0
until logged "$(field kind rule_hit)" "$(field rule_id functions)"; do
    tries=$((tries + 1))
    if [ "$tries" -ge 50 ]; then
        echo "itest: FAILED: no rule_hit event for the rule that fired" >&2
        failed=1
        break
    fi
    sleep 0.2
done

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
