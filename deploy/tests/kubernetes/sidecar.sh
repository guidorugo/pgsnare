#!/usr/bin/env bash
# SPDX-License-Identifier: Apache-2.0
#
# The sidecar pattern, from install to a first alert, in a namespace that
# enforces the restricted Pod Security Standard. Runs after sinks.sh.
#
#   deploy/tests/kubernetes/sidecar.sh native|classic
#
# It applies deploy/sidecar/<variant>.yaml as a reader would, with only
# what its comments say to replace: the image (the one of the release),
# the database's address, and, because the test database has no TLS, the
# upstream TLS mode. Each replacement must change exactly one line. Then
# the stand-in application reads a planted row through 127.0.0.1, and the
# receiver holds a verified token_hit for it.

set -euo pipefail

here="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
# shellcheck source=deploy/tests/kubernetes/lib.sh
source "$here/lib.sh"

variant="${1:?usage: sidecar.sh native|classic}"
[[ "$variant" == native || "$variant" == classic ]] || die "the variant is native or classic"

target="pgsnare-sidecar-$variant"
id="kubernetes-sidecar-$variant"
definition="$root/deploy/sidecar/$variant.yaml"

work="$(mktemp -d)"
finish() {
    local status=$?
    rm -rf "$work"
    if [[ "$status" -ne 0 ]]; then
        diagnose
        {
            echo "--- pods of $target"
            k --namespace "$target" describe pods | grep -E '^(Name|Status):|Warning|Failed|probe' | tail -n 30
            echo "--- log of the sidecar"
            k --namespace "$target" logs deployment/app --container pgsnare --tail 30
        } >&2 2>&1 || true
    fi
}
trap finish EXIT
umask 077

image="$(release_image)"
[[ "$image" =~ @sha256:[0-9a-f]{64}$ ]] || die "the release's image is not named by digest: $image"

# --- The namespace and what the definition says to create first ---------------------

say "namespace $target, which enforces the restricted standard"
k create namespace "$target" >&2
k label namespace "$target" \
    pod-security.kubernetes.io/enforce=restricted \
    pod-security.kubernetes.io/enforce-version=latest >&2
for attempt in $(seq 1 60); do
    k --namespace "$target" get serviceaccount default > /dev/null 2>&1 && break
    sleep 1
done

token="$(new_token "kube-$variant")"
token_file "$id" "$token" > "$work/sidecar.yaml"
k --namespace "$target" create secret generic pgsnare-sidecar-tokens --from-file=sidecar.yaml="$work/sidecar.yaml" >&2
# The webhook and its authority are the release's: the same receiver.
for name in url hmac-secret; do
    k --namespace "$namespace" get secret pgsnare-webhook --output "jsonpath={.data.$name}" \
        | base64 --decode > "$work/$name"
done
k --namespace "$target" create secret generic pgsnare-sidecar-webhook \
    --from-file=url="$work/url" --from-file=hmac-secret="$work/hmac-secret" >&2
k --namespace "$namespace" get secret pgsnare-webhook-ca --output 'jsonpath={.data.ca\.crt}' \
    | base64 --decode > "$work/ca.crt"
k --namespace "$target" create secret generic pgsnare-sidecar-webhook-ca --from-file=ca.crt="$work/ca.crt" >&2
k --namespace "$namespace" get secret postgres --output 'jsonpath={.data.password}' \
    | base64 --decode > "$work/password"
k --namespace "$target" create secret generic app-database --from-file=password="$work/password" >&2
rm -f "$work/url" "$work/hmac-secret" "$work/password"

# --- The definition, with what its comments say to replace ----------------------------

# replace FROM TO: replaces FROM on exactly one line of the definition.
cp "$definition" "$work/definition.yaml"
replace() {
    [[ "$(grep -c -F -- "$1" "$work/definition.yaml")" -eq 1 ]] \
        || die "the definition does not have exactly one line with: $1"
    FROM="$1" TO="$2" awk '{ i = index($0, ENVIRON["FROM"]); if (i) $0 = substr($0, 1, i - 1) ENVIRON["TO"] substr($0, i + length(ENVIRON["FROM"])); print }' \
        "$work/definition.yaml" > "$work/next.yaml"
    mv "$work/next.yaml" "$work/definition.yaml"
}
replace '${PGSNARE_IMAGE:?the pgsnare image by digest}' "$image"
replace 'upstream: db.example.com:5432' "upstream: postgres.$database_namespace.svc.cluster.local:5432"
replace 'mode: verify-full' 'mode: disable'

say "applying deploy/sidecar/$variant.yaml"
k --namespace "$target" apply --filename "$work/definition.yaml" >&2
k --namespace "$target" rollout status deployment/app --timeout=300s >&2

pod="$(k --namespace "$target" get pods --selector app.kubernetes.io/name=app --output name)"
[[ "$(grep -c . <<<"$pod")" -eq 1 ]] || die "expected one pod of the application: $pod"
if [[ "$variant" == native ]]; then
    policy="$(k --namespace "$target" get "$pod" --output 'jsonpath={.spec.initContainers[?(@.name=="pgsnare")].restartPolicy}')"
    [[ "$policy" == Always ]] || die "pgsnare is not a native sidecar in $pod"
    started="$(k --namespace "$target" get "$pod" --output 'jsonpath={.status.initContainerStatuses[?(@.name=="pgsnare")].started}')"
    [[ "$started" == true ]] || die "the sidecar of $pod has not started"
fi
say "the pod with its sidecar is ready in $target"

# --- First alert ----------------------------------------------------------------------------

table="sidecar_${variant}_bait"
database "CREATE TABLE $table (v text); INSERT INTO $table VALUES ('$token')" > /dev/null

# app SQL: one statement as the application, through pgsnare on loopback.
app() {
    k --namespace "$target" exec "$pod" --container app -- \
        psql --no-psqlrc --quiet --tuples-only --no-align -v ON_ERROR_STOP=1 --command "$1"
}
answer=""
for attempt in $(seq 1 30); do
    answer="$(app "SELECT count(*) FROM $table" 2>/dev/null)" && break
    sleep 2
done
[[ "$answer" == 1 ]] || die "the application cannot read through the sidecar"
sleep 3
[[ -z "$(hits "$id")" ]] || die "a token_hit arrived before the token was read, so the test proves nothing"

[[ "$(app "SELECT v FROM $table")" == "$token" ]] || die "the application did not get the planted row"
wait_hit "$id" 30 || die "the receiver holds no verified token_hit from the sidecar after 30 seconds"
say "the receiver verified a token_hit from the sidecar"

if k --namespace "$target" logs "$pod" --container pgsnare --tail -1 2>/dev/null | grep -qF -- "$token"; then
    die "the token value is in the log of the sidecar"
fi
no_value_in_logs "$token"
say "passed"
