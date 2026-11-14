#!/usr/bin/env bash
# SPDX-License-Identifier: Apache-2.0
#
# Installs the chart into the cluster that cluster.sh created, and checks
# that it works there.
#
#   deploy/tests/kubernetes/install.sh IMAGE
#
# IMAGE is the pgsnare image by digest, as deploy/tests/registry/load.sh
# prints it: 127.0.0.1:5000/pgsnare@sha256:...
#
# What it shows:
#
#   1. The namespace of pgsnare enforces the restricted Pod Security
#      Standard: it refuses a privileged pod, which a namespace without the
#      rule admits.
#   2. The chart installs there, with the image pulled by digest from the
#      registry, and its pods become ready through their own probe, which
#      runs `pgsnare healthcheck` inside the container.
#   3. A pod that the values list as a client logs in to the database
#      through the Service.
#   4. A pod that differs from it in one label does not get through. So
#      the network plugin enforces the NetworkPolicy of the chart, and the
#      login of step 3 passed because the policy allows it: the name
#      service, the database and that client, and nothing else.
#
# The release, the database and the two client pods are left in place for
# the tests that follow in the same job. The password of the database and
# the honeytoken are made here for each run and are worth nothing.

set -euo pipefail

image="${1:?usage: install.sh IMAGE}"

here="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
# shellcheck source=deploy/tests/kubernetes/lib.sh
source "$here/lib.sh"

[[ "$image" =~ ^([a-z0-9][a-z0-9.:/_-]*)@(sha256:[0-9a-f]{64})$ ]] \
    || die "the image must be named by digest: NAME@sha256:..."
repository="${BASH_REMATCH[1]}"
digest="${BASH_REMATCH[2]}"

work="$(mktemp -d)"
finish() {
    local status=$?
    rm -rf "$work"
    if [[ "$status" -ne 0 ]]; then
        diagnose
    fi
}
trap finish EXIT

# --- 1. The namespaces ---------------------------------------------------------

say "namespaces"
k create namespace "$database_namespace" >&2
k create namespace "$namespace" >&2
k label namespace "$namespace" \
    pod-security.kubernetes.io/enforce=restricted \
    pod-security.kubernetes.io/enforce-version=latest >&2

# A pod needs the account `default` of its namespace, which the cluster
# creates a moment after the namespace.
for target in "$database_namespace" "$namespace"; do
    for attempt in $(seq 1 60); do
        k --namespace "$target" get serviceaccount default > /dev/null 2>&1 && break
        sleep 1
    done
    k --namespace "$target" get serviceaccount default > /dev/null \
        || die "the namespace $target has no default account after a minute"
done

# The cluster is asked whether it would admit the pod; nothing is started.
# Where no rule is enforced it would, so the manifest is a valid pod and
# the refusal that follows is the namespace's.
k --namespace "$database_namespace" apply --dry-run=server --filename "$here/privileged-pod.yaml" >&2 \
    || die "the privileged pod is not a valid pod, so its refusal would prove nothing"
if k --namespace "$namespace" apply --dry-run=server --filename "$here/privileged-pod.yaml" > "$work/privileged.txt" 2>&1; then
    die "the namespace $namespace admits a privileged pod"
fi
grep -q 'violates PodSecurity "restricted' "$work/privileged.txt" \
    || die "the privileged pod was refused, but not by the restricted standard: $(head -c 300 "$work/privileged.txt")"
say "the namespace $namespace refuses a privileged pod"

# --- 2. The database, and what the release needs first --------------------------

say "database"
umask 077
openssl rand -hex 16 | tr -d '\n' > "$work/password"
for target in "$database_namespace" "$namespace"; do
    k --namespace "$target" create secret generic postgres --from-file=password="$work/password" >&2
done
k --namespace "$database_namespace" apply --filename "$here/postgres.yaml" >&2

# The honeytokens, as the chart wants them: a Secret whose keys that end in
# .yaml are token files.
token="kube-$(openssl rand -hex 12)"
cat > "$work/seeded.yaml" <<TOKENS
tokens:
  - id: kubernetes-test-seeded
    values: ["$token"]
TOKENS
k --namespace "$namespace" create secret generic pgsnare-tokens --from-file=seeded.yaml="$work/seeded.yaml" >&2

k --namespace "$database_namespace" rollout status deployment/postgres --timeout=300s >&2

# --- 3. The chart ----------------------------------------------------------------

say "installing the chart with $repository@$digest"
helm --kube-context "$context" install "$release" "$chart" \
    --namespace "$namespace" \
    --values "$here/values.yaml" \
    --set-string image.repository="$repository" \
    --set-string image.digest="$digest" >&2

k --namespace "$namespace" rollout status "deployment/$fullname" --timeout=300s >&2

# Every pod of the release is ready, runs the image that was named, and
# has the probe that runs the binary.
pods="$(k --namespace "$namespace" get pods --selector "app.kubernetes.io/instance=$release" --output name)"
[[ "$(grep -c . <<<"$pods")" -eq 2 ]] || die "expected 2 pods of the release, found: $pods"
for pod in $pods; do
    ready="$(k --namespace "$namespace" get "$pod" --output 'jsonpath={.status.conditions[?(@.type=="Ready")].status}')"
    [[ "$ready" == True ]] || die "$pod is not ready"
    probe="$(k --namespace "$namespace" get "$pod" --output 'jsonpath={.spec.containers[0].readinessProbe.exec.command}')"
    [[ "$probe" == '["/usr/local/bin/pgsnare","healthcheck","--ready"]' ]] \
        || die "$pod is ready by another probe than the health check of the binary: $probe"
    running="$(k --namespace "$namespace" get "$pod" --output 'jsonpath={.status.containerStatuses[0].imageID}')"
    [[ "$running" == *"$digest" ]] || die "$pod runs $running, not the image with $digest"
    restarts="$(k --namespace "$namespace" get "$pod" --output 'jsonpath={.status.containerStatuses[0].restartCount}')"
    [[ "$restarts" == 0 ]] || die "$pod was restarted $restarts times"
done
say "2 pods are ready through the exec probe, in a namespace that enforces the restricted standard"

# The Service carries the proxy port and nothing else.
ports="$(k --namespace "$namespace" get service "$fullname" --output 'jsonpath={.spec.type} {.spec.ports[*].port}')"
[[ "$ports" == "ClusterIP 5432" ]] || die "the Service is not ClusterIP with port 5432 alone: $ports"

# --- 4. A client logs in, and a stranger does not --------------------------------

say "clients"
k --namespace "$namespace" apply --filename "$here/clients.yaml" >&2
k --namespace "$namespace" wait --for=condition=Ready pod/client pod/stranger --timeout=300s >&2

# The network plugin learns of a new pod a moment after it starts, so the
# first attempts of the client may still be refused.
answer=""
for attempt in $(seq 1 30); do
    if answer="$(query client 5 2> "$work/client.txt")"; then
        break
    fi
    answer=""
    sleep 2
done
[[ "$answer" == postgres ]] \
    || die "the client did not log in through the Service after $attempt attempts: $(tail -n 2 "$work/client.txt" | tr '\n' ' ')"
say "the client logged in through the Service (attempt $attempt)"

# The stranger gets no answer at all. An answer from a server, even a
# refusal of its password, would mean that it got through.
if query stranger 8 > "$work/stranger.txt" 2>&1; then
    die "a pod that is not listed as a client logged in through the Service"
fi
if grep -q -E 'FATAL|password|authentication' "$work/stranger.txt"; then
    die "a pod that is not listed as a client reached a server: $(tail -n 2 "$work/stranger.txt" | tr '\n' ' ')"
fi
grep -q -i -E 'timeout expired|timed out|connection refused|unreachable' "$work/stranger.txt" \
    || die "the stranger failed for another reason than a connection that was not let through: $(tail -n 2 "$work/stranger.txt" | tr '\n' ' ')"
say "a pod without the client label gets no answer from the proxy"

# The client still gets through: the refusal was the policy's, not an
# outage.
[[ "$(query client 5 2> "$work/client.txt")" == postgres ]] \
    || die "the client no longer logs in: $(tail -n 2 "$work/client.txt" | tr '\n' ' ')"

say "passed"
