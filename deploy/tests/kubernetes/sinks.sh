#!/usr/bin/env bash
# SPDX-License-Identifier: Apache-2.0
#
# Prepares the tests that follow install.sh, in the same cluster:
#
#   deploy/tests/kubernetes/sinks.sh
#
#   1. A webhook receiver in the namespace pgsnare-sink, with a certificate
#      authority, a server certificate and a signing key made here for this
#      run. The receiver must refuse an unsigned, a forged and an old
#      request and accept a signed one, or the tests that read its log
#      would prove nothing.
#   2. The Secrets the release needs for it: the webhook's address and key
#      (pgsnare-webhook), the receiver's authority (pgsnare-webhook-ca),
#      and a second token Secret (pgsnare-tokens-live) with one token.
#   3. An upgrade of the release with values-live.yaml, and its pods ready
#      again.
#
# Nothing made here is kept outside the cluster: the keys are in a
# temporary directory that is removed at the end.

set -euo pipefail

here="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
# shellcheck source=deploy/tests/kubernetes/lib.sh
source "$here/lib.sh"

work="$(mktemp -d)"
finish() {
    local status=$?
    rm -rf "$work"
    if [[ "$status" -ne 0 ]]; then
        diagnose
        k --namespace "$sink_namespace" logs pod/receiver --tail 20 >&2 2>&1 || true
    fi
}
trap finish EXIT
umask 077
cd "$work"

# --- 1. The receiver ----------------------------------------------------------------

say "certificates and the signing key of the receiver"
openssl req -x509 -new -newkey ec -pkeyopt ec_paramgen_curve:P-256 -noenc \
    -keyout ca.key -out ca.crt -days 2 -subj "/CN=pgsnare test CA" \
    -addext "basicConstraints=critical,CA:TRUE" \
    -addext "keyUsage=critical,keyCertSign,cRLSign" 2>/dev/null
openssl req -new -newkey ec -pkeyopt ec_paramgen_curve:P-256 -noenc \
    -keyout tls.key -out tls.csr -subj "/CN=receiver.$sink_namespace.svc" 2>/dev/null
printf 'subjectAltName=DNS:receiver.%s.svc.cluster.local,DNS:receiver.%s.svc\nextendedKeyUsage=serverAuth\nbasicConstraints=critical,CA:FALSE\n' \
    "$sink_namespace" "$sink_namespace" > tls.ext
openssl x509 -req -in tls.csr -CA ca.crt -CAkey ca.key -CAcreateserial -days 2 \
    -extfile tls.ext -out tls.crt 2>/dev/null
openssl rand -hex 32 | tr -d '\n' > hmac-key
rm ca.key

k create namespace "$sink_namespace" >&2
for attempt in $(seq 1 60); do
    k --namespace "$sink_namespace" get serviceaccount default > /dev/null 2>&1 && break
    sleep 1
done
k --namespace "$sink_namespace" create configmap receiver-script \
    --from-file=receiver.py="$root/examples/compose/receiver/receiver.py" >&2
k --namespace "$sink_namespace" create secret generic receiver \
    --from-file=tls.crt --from-file=tls.key --from-file=hmac-key --from-file=ca.crt >&2
k --namespace "$sink_namespace" apply --filename "$here/receiver.yaml" >&2
k --namespace "$sink_namespace" wait --for=condition=Ready pod/receiver --timeout=300s >&2

say "the receiver must refuse what is not signed and accept what is"
# The Service gets its endpoint a moment after the pod is ready, and
# refuses connections until then.
checked=0
for attempt in $(seq 1 30); do
    if k --namespace "$sink_namespace" exec receiver -- python3 /app/receiver.py check "$receiver_url"; then
        checked=1
        break
    fi
    sleep 2
done
[[ "$checked" == 1 ]] || die "the receiver does not check signatures as it must"

# --- 2. The Secrets of the release --------------------------------------------------------

printf '%s' "$receiver_url" > url
k --namespace "$namespace" create secret generic pgsnare-webhook \
    --from-file=url --from-file=hmac-secret=hmac-key >&2
k --namespace "$namespace" create secret generic pgsnare-webhook-ca --from-file=ca.crt >&2
token_file kubernetes-test-live "$(new_token kube-live)" > live.yaml
k --namespace "$namespace" create secret generic pgsnare-tokens-live --from-file=live.yaml >&2

# --- 3. The upgrade ------------------------------------------------------------------------

say "upgrading the release with a webhook, a second token Secret and a scraper"
helm --kube-context "$context" upgrade "$release" "$chart" \
    --namespace "$namespace" \
    --reuse-values \
    --values "$here/values-live.yaml" >&2
k --namespace "$namespace" rollout status "deployment/$fullname" --timeout=300s >&2

# The pods of the old configuration are gone before a test counts pods.
for attempt in $(seq 1 120); do
    [[ "$(pods_of_release | grep -c .)" -eq 2 ]] \
        && [[ "$(k --namespace "$namespace" get pods --selector "app.kubernetes.io/instance=$release" --output name | grep -c .)" -eq 2 ]] \
        && break
    sleep 1
done
[[ "$(pods_of_release | grep -c .)" -eq 2 ]] || die "the release does not have 2 pods after the upgrade"
grace="$(k --namespace "$namespace" get deployment "$fullname" --output 'jsonpath={.spec.template.spec.terminationGracePeriodSeconds}')"
[[ "$grace" == 65 ]] || die "terminationGracePeriodSeconds is $grace, not 60 + 5"

say "passed"
