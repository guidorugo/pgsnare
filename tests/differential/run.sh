#!/usr/bin/env bash
# SPDX-License-Identifier: Apache-2.0
#
# The differential runner. It runs each scenario against PostgreSQL itself
# and against one or more other endpoints, and compares everything the
# client saw. Transparency means the outputs are identical.
#
# Usage:
#   run.sh --direct CONNINFO [--as NAME] --proxied CONNINFO ... PATH...
#
#   CONNINFO   a libpq keyword/value string without `dbname`, for example
#              "host=db.example.com port=5432 user=postgres". The password
#              comes from the environment (PGPASSWORD or PGPASSFILE).
#   NAME       a name for the endpoint that follows, for the report
#   PATH       a scenario, or a directory whose scenarios are run in name
#              order
#
# `--direct` is meant to reach PostgreSQL itself and each `--proxied` to
# reach it through pgsnare. The runner does not care which is which. With
# several proxied endpoints, a scenario runs once directly and once through
# each of them.
#
# A scenario is one of:
#
#   NAME.sql   run with psql, which echoes every statement
#   NAME.sh    a script, for what psql cannot do by itself. It is called
#              with the connection string of the scenario database as its
#              only argument, and everything it prints is the output.
#
# Each scenario runs in a database of its own, which is dropped and created
# again before each run. Scenarios therefore do not see each other, and a
# scenario starts from the same empty database on every endpoint, even when
# several endpoints lead to the same server.
#
# Exit status:
#   0  every scenario produced identical output on every endpoint
#   1  at least one scenario differed
#   2  the comparison could not be made: bad usage, an endpoint that cannot
#      be reached, or a scenario that did not finish against PostgreSQL

set -euo pipefail

usage() {
    cat <<'USAGE'
Usage: run.sh --direct CONNINFO [--as NAME] --proxied CONNINFO ... PATH...

Runs each scenario against every endpoint and compares the output.

  CONNINFO  a libpq keyword/value string without dbname
  NAME      a name for the endpoint that follows
  PATH      a scenario (*.sql or *.sh), or a directory of scenarios

Exit status: 0 identical, 1 different, 2 the comparison could not be made.
USAGE
}

direct=""
proxied=()
names=()
name=""
paths=()
while [[ $# -gt 0 ]]; do
    case "$1" in
        --direct)
            [[ $# -ge 2 ]] || { usage >&2; exit 2; }
            direct="$2"
            shift 2
            ;;
        --as)
            [[ $# -ge 2 ]] || { usage >&2; exit 2; }
            name="$2"
            shift 2
            ;;
        --proxied)
            [[ $# -ge 2 ]] || { usage >&2; exit 2; }
            proxied+=("$2")
            names+=("$name")
            name=""
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

if [[ -z "$direct" || "${#proxied[@]}" -eq 0 || "${#paths[@]}" -eq 0 ]]; then
    usage >&2
    exit 2
fi

# The database every scenario runs in. It is dropped and created again
# before each run, with the same name on every endpoint, so the name never
# shows up as a difference.
database="pgsnare_scenario"

work="$(mktemp -d)"
trap 'rm -rf "$work"' EXIT

psql_common=(psql --no-psqlrc --no-password --quiet --pset pager=off)

# Collect the scenarios.
scenarios=()
for path in "${paths[@]}"; do
    if [[ -d "$path" ]]; then
        found=0
        while IFS= read -r -d '' file; do
            scenarios+=("$file")
            found=1
        done < <(find "$path" -maxdepth 1 -type f \( -name '*.sql' -o -name '*.sh' \) -print0 | sort -z)
        if [[ "$found" -eq 0 ]]; then
            echo "run.sh: no scenarios in $path" >&2
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
    local endpoint="$1" conninfo="$2"
    if ! "${psql_common[@]}" --set ON_ERROR_STOP=1 --dbname "$conninfo dbname=postgres" \
        --command "DROP DATABASE IF EXISTS $database WITH (FORCE)" \
        --command "CREATE DATABASE $database" >"$work/prepare.log" 2>&1; then
        echo "run.sh: cannot prepare the $endpoint endpoint:" >&2
        sed 's/^/    /' "$work/prepare.log" >&2
        return 1
    fi
}

# execute CONNINFO SCENARIO OUTPUT: runs one scenario and records what the
# client saw, including how it ended.
execute() {
    local conninfo="$1" scenario="$2" output="$3" status=0
    case "$scenario" in
        *.sh)
            "$scenario" "$conninfo dbname=$database" >"$output.raw" 2>&1 || status=$?
            ;;
        *)
            "${psql_common[@]}" --echo-all --dbname "$conninfo dbname=$database" \
                --file "$scenario" >"$output.raw" 2>&1 || status=$?
            ;;
    esac
    # The only thing that legitimately differs between two connections to
    # the same server is the process that serves them.
    sed -E 's/(server process with PID) [0-9]+/\1 <pid>/' "$output.raw" >"$output"
    printf 'exit status: %d\n' "$status" >>"$output"
    return "$status"
}

identical=0
different=0
broken=0
for scenario in "${scenarios[@]}"; do
    title="$(basename "$scenario")"
    title="${title%.*}"

    # One endpoint at a time: prepare it, then run. Several endpoints may
    # lead to the same server, and a run must not see what the one before
    # it left behind.
    direct_status=0
    prepare direct "$direct" || exit 2
    execute "$direct" "$scenario" "$work/direct.out" || direct_status=$?
    if [[ "$direct_status" -ne 0 ]]; then
        # A scenario must run to its end against PostgreSQL itself.
        # Otherwise two identical failures would look like a pass.
        echo "BROKEN     $title: ended with status $direct_status on the direct endpoint"
        tail -n 20 "$work/direct.out" | sed 's/^/    /'
        broken=$((broken + 1))
        continue
    fi

    for index in "${!proxied[@]}"; do
        label="${names[$index]}"
        endpoint="${label:-proxied}"
        prepare "$endpoint" "${proxied[$index]}" || exit 2
        execute "${proxied[$index]}" "$scenario" "$work/proxied.out" || true
        if cmp --silent "$work/direct.out" "$work/proxied.out"; then
            echo "identical  $title${label:+  ($label)}"
            identical=$((identical + 1))
        else
            echo "DIFFERENT  $title${label:+  ($label)}"
            # A difference can be as large as the output. Its beginning
            # is enough to see what went wrong.
            diff --unified --label direct --label "$endpoint" \
                "$work/direct.out" "$work/proxied.out" | head -n 60 | cut -c 1-300 \
                | sed 's/^/    /' || true
            different=$((different + 1))
        fi
    done
done

echo "run.sh: $identical identical, $different different, $broken broken"
if [[ "$broken" -ne 0 ]]; then
    exit 2
fi
if [[ "$different" -ne 0 ]]; then
    exit 1
fi
