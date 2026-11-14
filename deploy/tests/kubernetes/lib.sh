#!/usr/bin/env bash
# SPDX-License-Identifier: Apache-2.0
#
# Names and helpers of the Kubernetes tests. The scripts of this directory
# read it with `source`; it does nothing when it is run.
#
# The tests need `kind`, `kubectl` and `helm` on the path, all three from
# deploy/tools/tools.txt, and Docker. They are written for a CI runner:
# they create a cluster and leave it to the end of the job.

# The cluster, and the context `kind` writes for it. Every command names
# the context, so that no other cluster is ever touched.
cluster="${PGSNARE_KIND_CLUSTER:-pgsnare}"
context="kind-$cluster"

# Where pgsnare is installed: a namespace that enforces the restricted
# Pod Security Standard.
namespace="pgsnare-test"
# Where the database runs.
database_namespace="pgsnare-db"
# The release of the chart, and the name the chart gives its objects.
release="snare"
fullname="snare-pgsnare"

root="$(cd "$(dirname "${BASH_SOURCE[0]}")/../../.." && pwd)"
chart="$root/deploy/chart/pgsnare"

k() {
    kubectl --context "$context" "$@"
}

say() {
    echo "kubernetes: $*" >&2
}

die() {
    say "FAILED: $*"
    exit 1
}

# What the cluster looked like, for the log of a failed job. Nothing here
# prints the content of a Secret.
diagnose() {
    {
        echo "--- pods"
        k get pods --all-namespaces --output wide
        echo "--- events of $namespace"
        k --namespace "$namespace" get events --sort-by=.lastTimestamp | tail -n 30
        echo "--- pods of $namespace"
        k --namespace "$namespace" describe pods | grep -E '^(Name|Status|Reason|Message):|^  (Ready|ContainersReady) |Warning|Failed|probe' | tail -n 40
        echo "--- log of pgsnare"
        k --namespace "$namespace" logs --selector "app.kubernetes.io/name=pgsnare" --tail 30 --prefix
        echo "--- NetworkPolicy"
        k --namespace "$namespace" get networkpolicy --output yaml | grep -v -E '^\s+(uid|resourceVersion|creationTimestamp):' | tail -n 80
    } >&2 2>&1 || true
}

# query POD [SECONDS]: one login through the Service of the release, as the
# pod POD of the test namespace. Prints the user the database reports.
query() {
    local pod="$1" timeout="${2:-5}"
    k --namespace "$namespace" exec "$pod" -- \
        psql "host=$fullname port=5432 user=postgres dbname=postgres sslmode=disable connect_timeout=$timeout" \
        --no-psqlrc --quiet --tuples-only --no-align --command 'select current_user'
}

# --- Helpers of the tests that follow the install (step 3) ------------------

# Where the webhook receiver runs (sinks.sh), and the namespaces of the
# isolation test (isolation.sh).
sink_namespace="pgsnare-sink"
receiver_url="https://receiver.$sink_namespace.svc.cluster.local:8443/events"
other_namespace="pgsnare-other"
monitoring_namespace="pgsnare-monitoring"

# sql POD SQL [SECONDS]: one statement through the Service of the release,
# as the pod POD of the test namespace. Prints the rows, unaligned.
sql() {
    local pod="$1" statement="$2" timeout="${3:-5}"
    k --namespace "$namespace" exec "$pod" -- \
        psql "host=$fullname port=5432 user=postgres dbname=postgres sslmode=disable connect_timeout=$timeout" \
        --no-psqlrc --quiet --tuples-only --no-align -v ON_ERROR_STOP=1 --command "$statement"
}

# database SQL: one statement in the database itself, not through pgsnare.
# Used to plant tokens, so that planting raises nothing.
database() {
    k --namespace "$database_namespace" exec deployment/postgres -- \
        bash -c 'PGPASSWORD="$POSTGRES_PASSWORD" exec psql "host=127.0.0.1 user=postgres dbname=postgres" --no-psqlrc --quiet --tuples-only --no-align -v ON_ERROR_STOP=1 --command "$1"' \
        _ "$1"
}

# new_token PREFIX: a random synthetic token value, made for one run.
new_token() {
    printf '%s-%s' "$1" "$(openssl rand -hex 12)"
}

# token_file ID VALUE: a token file with one token.
token_file() {
    printf 'tokens:\n  - id: %s\n    values: ["%s"]\n' "$1" "$2"
}

# hits ID: the token_hit events for the token ID that the receiver
# accepted, one JSON line each. The receiver prints an event only after it
# verified its signature.
hits() {
    k --namespace "$sink_namespace" logs pod/receiver 2>/dev/null \
        | grep -F '"kind":"token_hit"' | grep -F "\"token_id\":\"$1\"" || true
}

# wait_hit ID SECONDS: waits until the receiver holds a token_hit for ID.
wait_hit() {
    local id="$1" seconds="$2" waited=0
    until [[ -n "$(hits "$id")" ]]; do
        [[ "$waited" -lt "$seconds" ]] || return 1
        sleep 1
        waited=$((waited + 1))
    done
}

# pods_of_release: name, uid and restart count of every pod of the release
# that is not being deleted, one per line, sorted.
pods_of_release() {
    k --namespace "$namespace" get pods --selector "app.kubernetes.io/instance=$release" \
        --output 'jsonpath={range .items[*]}{.metadata.name} {.metadata.uid} {.status.containerStatuses[0].restartCount} {.metadata.deletionTimestamp}{"\n"}{end}' \
        | awk 'NF == 3' | sort
}

# release_image: the image of the release, by digest, as install.sh gave it.
release_image() {
    k --namespace "$namespace" get deployment "$fullname" \
        --output 'jsonpath={.spec.template.spec.containers[0].image}'
}

# no_value_in_logs VALUE: fails when VALUE is in a log of pgsnare or of the
# receiver.
no_value_in_logs() {
    if k --namespace "$namespace" logs --selector "app.kubernetes.io/name=pgsnare" --tail -1 2>/dev/null | grep -qF -- "$1"; then
        die "a token value is in the log of pgsnare"
    fi
    if k --namespace "$sink_namespace" logs pod/receiver 2>/dev/null | grep -qF -- "$1"; then
        die "a token value is in the log of the receiver"
    fi
}
