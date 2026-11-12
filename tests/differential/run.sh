#!/usr/bin/env bash
# SPDX-License-Identifier: Apache-2.0
#
# The differential runner. It runs each scenario against two PostgreSQL
# endpoints with psql and compares everything the client saw. Transparency
# means the two outputs are identical.
#
# Usage:
#   run.sh --direct CONNINFO --proxied CONNINFO PATH...
#
#   CONNINFO   a libpq keyword/value string without `dbname`, for example
#              "host=db.example.com port=5432 user=postgres". The password
#              comes from the environment (PGPASSWORD or PGPASSFILE).
#   PATH       a scenario file, or a directory whose *.sql files are run in
#              name order.
#
# `--direct` is meant to reach PostgreSQL itself and `--proxied` to reach it
# through pgsnare. The runner does not care which is which.
#
# Each scenario runs in a database of its own, which is dropped and created
# again before each run. Scenarios therefore do not see each other, and a
# scenario starts from the same empty database on both sides, even when both
# endpoints lead to the same server.
#
# Exit status:
#   0  every scenario produced identical output on both endpoints
#   1  at least one scenario differed
#   2  the comparison could not be made: bad usage, an endpoint that cannot
#      be reached, or a scenario that psql could not finish

set -euo pipefail

usage() {
    cat <<'USAGE'
Usage: run.sh --direct CONNINFO --proxied CONNINFO PATH...

Runs each scenario against both endpoints and compares the output.

  CONNINFO  a libpq keyword/value string without dbname
  PATH      a scenario file, or a directory of *.sql files

Exit status: 0 identical, 1 different, 2 the comparison could not be made.
USAGE
}

direct=""
proxied=""
paths=()
while [[ $# -gt 0 ]]; do
    case "$1" in
        --direct)
            [[ $# -ge 2 ]] || { usage >&2; exit 2; }
            direct="$2"
            shift 2
            ;;
        --proxied)
            [[ $# -ge 2 ]] || { usage >&2; exit 2; }
            proxied="$2"
            shift 2
            ;;
        -h | --help)
            usage
            exit 0
            ;;
        -*)
            echo "run.sh: unknown option: $1" >&2
            exit 2
            ;;
        *)
            paths+=("$1")
            shift
            ;;
    esac
done

if [[ -z "$direct" || -z "$proxied" || "${#paths[@]}" -eq 0 ]]; then
    usage >&2
    exit 2
fi

# The database every scenario runs in. It is dropped and created again
# before each run, with the same name on both endpoints, so the name never
# shows up as a difference.
database="pgsnare_scenario"

work="$(mktemp -d)"
trap 'rm -rf "$work"' EXIT

psql_common=(psql --no-psqlrc --no-password --quiet --pset pager=off)

# Collect the scenario files.
scenarios=()
for path in "${paths[@]}"; do
    if [[ -d "$path" ]]; then
        found=0
        while IFS= read -r -d '' file; do
            scenarios+=("$file")
            found=1
        done < <(find "$path" -maxdepth 1 -type f -name '*.sql' -print0 | sort -z)
        if [[ "$found" -eq 0 ]]; then
            echo "run.sh: no *.sql files in $path" >&2
            exit 2
        fi
    elif [[ -f "$path" ]]; then
        scenarios+=("$path")
    else
        echo "run.sh: no such scenario: $path" >&2
        exit 2
    fi
done

# prepare NAME CONNINFO: checks that the endpoint answers and gives it an
# empty scenario database.
prepare() {
    local name="$1" conninfo="$2"
    if ! "${psql_common[@]}" --set ON_ERROR_STOP=1 --dbname "$conninfo dbname=postgres" \
        --command "DROP DATABASE IF EXISTS $database WITH (FORCE)" \
        --command "CREATE DATABASE $database" >"$work/prepare.log" 2>&1; then
        echo "run.sh: cannot prepare the $name endpoint:" >&2
        sed 's/^/    /' "$work/prepare.log" >&2
        return 1
    fi
}

# execute CONNINFO SCENARIO OUTPUT: runs one scenario and records what the
# client saw, including how psql ended.
execute() {
    local conninfo="$1" scenario="$2" output="$3" status=0
    "${psql_common[@]}" --echo-all --dbname "$conninfo dbname=$database" \
        --file "$scenario" >"$output.raw" 2>&1 || status=$?
    # The only thing that legitimately differs between two connections to
    # the same server is the process that serves them.
    sed -E 's/(server process with PID) [0-9]+/\1 <pid>/' "$output.raw" >"$output"
    printf 'psql exit status: %d\n' "$status" >>"$output"
    return "$status"
}

identical=0
different=0
broken=0
for scenario in "${scenarios[@]}"; do
    name="$(basename "$scenario" .sql)"

    # One endpoint at a time: prepare it, then run. Both endpoints may lead
    # to the same server, and the second run must not see what the first
    # one left behind.
    direct_status=0
    proxied_status=0
    prepare direct "$direct" || exit 2
    execute "$direct" "$scenario" "$work/direct.out" || direct_status=$?
    prepare proxied "$proxied" || exit 2
    execute "$proxied" "$scenario" "$work/proxied.out" || proxied_status=$?

    if [[ "$direct_status" -ne 0 ]]; then
        # A scenario must run to its end against PostgreSQL itself.
        # Otherwise two identical failures would look like a pass.
        echo "BROKEN     $name: psql ended with status $direct_status on the direct endpoint"
        tail -n 20 "$work/direct.out" | sed 's/^/    /'
        broken=$((broken + 1))
    elif cmp --silent "$work/direct.out" "$work/proxied.out"; then
        echo "identical  $name"
        identical=$((identical + 1))
    else
        echo "DIFFERENT  $name"
        diff --unified --label direct --label proxied \
            "$work/direct.out" "$work/proxied.out" | sed 's/^/    /' || true
        different=$((different + 1))
    fi
done

echo "run.sh: $identical identical, $different different, $broken broken"
if [[ "$broken" -ne 0 ]]; then
    exit 2
fi
if [[ "$different" -ne 0 ]]; then
    exit 1
fi
