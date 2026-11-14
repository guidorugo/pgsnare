#!/usr/bin/env bash
# SPDX-License-Identifier: Apache-2.0
#
# A rolling update lets an open session finish within the grace period.
# Runs after sinks.sh, which sets the grace period to 60 seconds.
#
#   deploy/tests/kubernetes/rollout.sh
#
# A client starts a statement that takes 30 seconds. While it runs, the
# Deployment is restarted, and the roll-out completes: every pod of the old
# generation, the one that holds the session included, has been told to
# stop. The statement must still be running then (or the test proves
# nothing), and it must end with its result, before the grace period ends.
# Then the old pods are gone and the new ones serve.

set -euo pipefail

here="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
# shellcheck source=deploy/tests/kubernetes/lib.sh
source "$here/lib.sh"

work="$(mktemp -d)"
session=""
finish() {
    local status=$?
    [[ -z "$session" ]] || kill "$session" 2>/dev/null || true
    rm -rf "$work"
    [[ "$status" -eq 0 ]] || diagnose
}
trap finish EXIT

statement_seconds=30
grace="$(k --namespace "$namespace" get deployment "$fullname" --output 'jsonpath={.spec.template.spec.terminationGracePeriodSeconds}')"
[[ "$grace" -gt $((statement_seconds + 10)) ]] || die "the grace period ($grace s) is too short for this test"

old="$(pods_of_release | awk '{ print $1 }')"
[[ "$(grep -c . <<<"$old")" -eq 2 ]] || die "expected 2 pods of the release: $old"

say "a session starts a statement of $statement_seconds seconds"
sql client "SELECT 'finished' FROM pg_sleep($statement_seconds)" 10 > "$work/answer" 2> "$work/error" &
session=$!
started="$(date +%s)"
sleep 3
kill -0 "$session" 2>/dev/null || die "the session ended before the roll-out: $(tail -n 2 "$work/error" | tr '\n' ' ')"

say "rolling update"
k --namespace "$namespace" rollout restart "deployment/$fullname" >&2
k --namespace "$namespace" rollout status "deployment/$fullname" --timeout=120s >&2
rolled="$(date +%s)"

# Every old pod has been told to stop, or is gone already.
for pod in $old; do
    deleting="$(k --namespace "$namespace" get pod "$pod" --ignore-not-found --output 'jsonpath={.metadata.name} {.metadata.deletionTimestamp}')"
    [[ -z "$deleting" || "$deleting" == *" "?* ]] || die "the old pod $pod was not told to stop by the roll-out"
done
kill -0 "$session" 2>/dev/null \
    || die "the statement ended before every old pod was told to stop ($((rolled - started)) s), so the test proves nothing"
say "the roll-out completed after $((rolled - started)) s, with the statement still running"

status=0
wait "$session" || status=$?
session=""
ended="$(date +%s)"
[[ "$status" -eq 0 ]] || die "the session failed: $(tail -n 2 "$work/error" | tr '\n' ' ')"
[[ "$(cat "$work/answer")" == finished ]] || die "the session ended without its result"
[[ $((ended - rolled)) -lt "$grace" ]] || die "the result came after the grace period"
say "the session got its result $((ended - rolled)) s after the roll-out completed"

# The old pods leave, and two new ones serve.
for pod in $old; do
    k --namespace "$namespace" wait --for=delete "pod/$pod" --timeout="${grace}s" >&2 2>/dev/null || true
done
new="$(pods_of_release)"
[[ "$(grep -c . <<<"$new")" -eq 2 ]] || die "expected 2 new pods: $new"
for pod in $old; do
    ! grep -q "^$pod " <<<"$new" || die "the old pod $pod still serves"
done
awk '$3 != 0 { exit 1 }' <<<"$new" || die "a new pod was restarted: $new"
[[ "$(query client 5)" == postgres ]] || die "the client cannot log in after the roll-out"

say "passed"
