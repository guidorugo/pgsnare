#!/bin/sh
# SPDX-License-Identifier: Apache-2.0
#
# The detection corpus: ways to get a honeytoken out of a database through
# the connection itself, each labelled as one pgsnare detects (a hit) or as
# one it is known not to detect (a gap). tests/itest.sh runs it.
#
# Usage: run.sh CONTAINER VERSION...
#
#   CONTAINER  a running client container of the integration tests, with
#              this directory at /corpus
#   VERSION    the PostgreSQL versions to run the cases against
#
# Environment:
#   DOCKER         the docker command (default: docker)
#   ITEST_PROJECT  the Compose project name (default: pgsnare-itest)
#
# A case is a file cases/NN-name.sql: a header of comment lines, and the
# statements. Adding a technique is adding a file. The header:
#
#   -- label: hit|gap     whether pgsnare detects it (required)
#   -- describe: TEXT     what the technique is (required)
#   -- token: typed       it reads the token that is written as a UUID, from
#                         bait_typed, instead of the one in bait
#   -- modes: MODE...     the modes it can run in, when not all three
#   -- gap-in: MODE...    the modes in which a hit is a known gap
#   -- expect: error      one of its statements fails, by intent
#   -- setup: STATEMENT;  run before each run, not through pgsnare
#   -- pipeline: yes      all statements are sent before the first answer
#   -- rows: N            each Execute asks for N rows of its portal
#   -- kill-passes: TEXT  with kill, the client has received TEXT, which
#                         comes before the value in the same message
#   -- needs: pg_dump|replication|login|rules
#                         the run is a tool instead of statements (pg_dump
#                         with the line `arguments`, pg_recvlogical, or a
#                         login with the value as the password), or it runs
#                         on a listener with the SQL rules
#   -- arguments: TEXT    for pg_dump
#   -- rule: ID alert|kill
#                         with `needs: rules`: the rule that fires, and what
#                         it does in the configuration of the tests
#
# In the statements, a statement ends with a line that ends with a
# semicolon. They read the tables of schema.sql and never name a value.
#
# Every case runs in three modes: `simple` (psql, a Query message for each
# statement), `extended-text` and `extended-binary` (tests/differential/
# wire.pl: Parse, Bind, Describe, Execute and Sync for each statement, with
# the result in that format). Every case runs once with a token that alerts
# and once with a token that kills. A case that cannot run in a mode says
# so with `modes`, and such a run is counted as not run, never as passed.
#
# What must hold:
#
#   - A hit raises a token_hit event with the id of the token (or a
#     rule_hit event with the id of the rule) for its session.
#   - With kill, the session ends, and nothing the client received holds
#     the value as it is written, in hexadecimal or in base64.
#   - A gap raises no such event, and its session goes on to the end. A gap
#     that is detected fails the run, so that the list of gaps stays true.
#   - At least 50 cases ran, and all of them to the end.
#
# tests/corpus/client.sh runs the sessions and judges what a client sees;
# this script judges the events, which it reads from the log of pgsnare. A
# session is told from the others by its application name.

set -eu

cd "$(dirname "$0")/../.."

docker="${DOCKER:-docker}"
project="${ITEST_PROJECT:-pgsnare-itest}"
container="${1:?Usage: run.sh CONTAINER VERSION...}"
shift

runs="$(mktemp)"
events="$(mktemp)"
report="$(mktemp)"
trap 'rm -f "$runs" "$events" "$report"' EXIT

# raised: the hits of the sessions of the corpus that pgsnare has logged,
# each as "APPLICATION KIND ID".
raised() {
    "$docker" compose --project-name "$project" --file tests/compose.yaml \
        logs --no-log-prefix pgsnare 2>&1 | awk '
        function field(name) {
            if (match($0, "\"" name "\":\"[^\"]*\"")) {
                return substr($0, RSTART + length(name) + 4, RLENGTH - length(name) - 5)
            }
            return "-"
        }
        /"kind":"(token_hit|rule_hit)"/ && /"application_name":"corpus-/ {
            kind = field("kind")
            print field("application_name"), kind, field(kind == "token_hit" ? "token_id" : "rule_id")
        }'
}

# judge VERSION: compares the runs with the events. It prints a line for
# each run that failed and a summary, and fails if a run failed, if an
# event is missing or if fewer than 50 cases ran.
judge() {
    awk -v version="$1" '
        NR == FNR {
            seen[$1 " " $2 " " $3] = 1
            any[$1] = any[$1] " " $2 " for " $3
            next
        }
        $1 != "run" { next }
        {
            what = $6 " (" $7 ", " $8 ")"
            cases[$6] = 1
            if ($5 == "notrun") {
                notrun++
                next
            }
            reason = ""
            if ($5 != "ok") {
                reason = $9
                for (i = 10; i <= NF; i++) {
                    reason = reason " " $i
                }
            } else if ($3 == "none") {
                if ($2 in any) {
                    reason = "it is a known gap, and pgsnare raised" any[$2]
                }
            } else if (!(($2 " " $3 " " $4) in seen)) {
                reason = "pgsnare raised no " $3 " event for " $4
                missing++
            }
            if (reason != "") {
                print "corpus: FAILED: PostgreSQL " version ": " what ": " reason
                bad++
            } else if ($3 == "none") {
                gaps++
            } else {
                hits++
            }
        }
        END {
            count = 0
            for (name in cases) {
                count++
            }
            printf "corpus: PostgreSQL %s: %d cases; %d runs detected, %d runs of known gaps not detected, %d failed, %d not run in a mode the case cannot use\n", \
                version, count, hits, gaps, bad, notrun
            if (count < 50) {
                print "corpus: FAILED: PostgreSQL " version ": fewer than 50 cases ran"
                exit 1
            }
            if (missing > 0) {
                exit 3
            }
            exit bad > 0
        }' "$events" "$runs"
}

failed=0
for version in "$@"; do
    status=0
    "$docker" exec \
        --env "CORPUS_DIRECT=host=pg$version port=5432 user=postgres sslmode=disable" \
        --env "CORPUS_PROXIED=host=pgsnare port=60$version user=postgres sslmode=disable" \
        --env "CORPUS_RULED=host=pgsnare port=71$version user=postgres sslmode=disable client_encoding=UTF8" \
        "$container" /corpus/client.sh "$version" >"$runs" || status=$?
    if [ "$status" -ne 0 ] || ! grep -q "^end $version " "$runs"; then
        echo "corpus: FAILED: PostgreSQL $version: the cases did not run to the end (exit status $status)" >&2
        grep -v '^run ' "$runs" | sed 's/^/    /' >&2 || true
        failed=1
        continue
    fi

    # An event leaves pgsnare a moment after its hit. As long as one is
    # missing the log is read again, for 10 seconds at most.
    tries=0
    while :; do
        raised >"$events"
        status=0
        judge "$version" >"$report" || status=$?
        tries=$((tries + 1))
        if [ "$status" -ne 3 ] || [ "$tries" -ge 10 ]; then
            break
        fi
        sleep 1
    done
    if [ "$status" -ne 0 ]; then
        cat "$report" >&2
        failed=1
    else
        cat "$report"
    fi
done

exit "$failed"
