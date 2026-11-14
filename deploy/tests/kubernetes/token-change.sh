#!/usr/bin/env bash
# SPDX-License-Identifier: Apache-2.0
#
# A token added by changing the mounted Secret is active without a restart.
# Runs after sinks.sh.
#
#   deploy/tests/kubernetes/token-change.sh
#
# A new value is planted in the database and read through pgsnare before it
# is a token: nothing is raised. Then it is added to the Secret
# pgsnare-tokens-live as a second token file. The kubelet updates the
# mounted volume (it can take a minute or more), pgsnare reloads its
# tokens, and the same read raises a token_hit, in the same pods, which
# were not restarted.

set -euo pipefail

here="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
# shellcheck source=deploy/tests/kubernetes/lib.sh
source "$here/lib.sh"

work="$(mktemp -d)"
trap 'status=$?; rm -rf "$work"; [[ $status -eq 0 ]] || diagnose' EXIT
umask 077

id="kubernetes-test-added"
token="$(new_token kube-added)"
before="$(pods_of_release)"
[[ "$(grep -c . <<<"$before")" -eq 2 ]] || die "expected 2 pods of the release: $before"

database "CREATE TABLE added_bait (v text); INSERT INTO added_bait VALUES ('$token')" > /dev/null

# Before the change the value is not a token.
[[ "$(sql client "SELECT v FROM added_bait")" == "$token" ]] || die "the client did not get the row"
[[ "$(sql client "SELECT v FROM added_bait")" == "$token" ]] || die "the client did not get the row"
sleep 5
[[ -z "$(hits "$id")" ]] || die "the value raised a token_hit before it was a token"
say "before the Secret changed, reading the value raised nothing"

# The Secret keeps its first file and gets a second.
k --namespace "$namespace" get secret pgsnare-tokens-live --output 'jsonpath={.data.live\.yaml}' \
    | base64 --decode > "$work/live.yaml"
token_file "$id" "$token" > "$work/added.yaml"
k --namespace "$namespace" create secret generic pgsnare-tokens-live \
    --from-file=live.yaml="$work/live.yaml" --from-file=added.yaml="$work/added.yaml" \
    --dry-run=client --output yaml \
    | k --namespace "$namespace" replace --filename - >&2
changed="$(date +%s)"
say "the Secret has the new token; waiting for the volume and the reload (up to 3 minutes)"

found=0
while [[ $(( $(date +%s) - changed )) -lt 180 ]]; do
    sql client "SELECT v FROM added_bait" > /dev/null 2>&1 || true
    if wait_hit "$id" 4; then
        found=1
        break
    fi
done
[[ "$found" == 1 ]] || die "no token_hit for the added token within 3 minutes of the change"
say "the added token raised a token_hit $(( $(date +%s) - changed )) s after the Secret changed"

after="$(pods_of_release)"
[[ "$after" == "$before" ]] || die "the pods changed or restarted: before [$before], after [$after]"
say "the same pods, with the same restart counts, before and after"

no_value_in_logs "$token"
say "passed"
