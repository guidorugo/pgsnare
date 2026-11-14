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
