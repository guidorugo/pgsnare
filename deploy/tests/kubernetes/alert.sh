#!/usr/bin/env bash
# SPDX-License-Identifier: Apache-2.0
#
# The first alert of the central proxy, from a planted row to a verified
# webhook. Runs after sinks.sh.
#
#   deploy/tests/kubernetes/alert.sh
#
# The token of pgsnare-tokens-live is planted in the database directly, not
# through pgsnare. Before any client reads it the receiver holds no hit for
# it; then the client reads the row through the Service, gets it, and the
# receiver holds a token_hit for that token whose signature it verified.
# The token's value is in no log.

set -euo pipefail

here="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
# shellcheck source=deploy/tests/kubernetes/lib.sh
source "$here/lib.sh"

trap '[[ $? -eq 0 ]] || diagnose' EXIT

id="kubernetes-test-live"
token="$(k --namespace "$namespace" get secret pgsnare-tokens-live --output 'jsonpath={.data.live\.yaml}' \
    | base64 --decode | sed -n 's/.*values: \["\([a-z0-9-]*\)"\].*/\1/p')"
[[ "$token" == kube-live-* ]] || die "the token of pgsnare-tokens-live could not be read"

database "CREATE TABLE live_bait (v text); INSERT INTO live_bait VALUES ('$token')" > /dev/null

# A query that reads no token goes through and raises nothing.
[[ "$(sql client "SELECT count(*) FROM live_bait")" == 1 ]] \
    || die "the client cannot read through the Service"
sleep 3
[[ -z "$(hits "$id")" ]] || die "a token_hit arrived before the token was read, so the test proves nothing"

say "the client reads the planted row"
answer="$(sql client "SELECT v FROM live_bait")"
[[ "$answer" == "$token" ]] || die "the client did not get the planted row"
wait_hit "$id" 30 || die "the receiver holds no verified token_hit for the token after 30 seconds"
say "the receiver verified a token_hit: $(hits "$id" | head -n 1 | grep -o '"event_id":"[^"]*"')"

no_value_in_logs "$token"
say "passed"
