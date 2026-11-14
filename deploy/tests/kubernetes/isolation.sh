#!/usr/bin/env bash
# SPDX-License-Identifier: Apache-2.0
#
# Only the listed clients reach the proxy, and only the listed scrapers
# reach the metrics. Runs after sinks.sh, and last: it deletes the
# NetworkPolicy of the release at the end.
#
#   deploy/tests/kubernetes/isolation.sh
#
# Each check opens a TCP connection from inside a pod:
#
#   from                                  proxy (Service)   metrics (each pod)
#   client   (listed, pgsnare-test)       yes               no
#   stranger (unlisted, pgsnare-test)     no                no
#   outsider (client label, other ns)     no                no
#   scraper  (listed, pgsnare-monitoring) no                yes, and answers
#
# Then the NetworkPolicy is deleted, and the stranger and the outsider get
# through: so the refusals above were the policy's.

set -euo pipefail

here="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
# shellcheck source=deploy/tests/kubernetes/lib.sh
source "$here/lib.sh"

trap '[[ $? -eq 0 ]] || diagnose' EXIT

proxy_host="$fullname.$namespace.svc.cluster.local"
metrics_port=9642

# reach NAMESPACE POD HOST PORT: whether POD opens a TCP connection to
# HOST:PORT within 4 seconds.
reach() {
    k --namespace "$1" exec "$2" -- timeout 4 bash -c 'exec 3<>"/dev/tcp/$0/$1"' "$3" "$4" > /dev/null 2>&1
}

# scrape NAMESPACE POD HOST: what POD gets from /metrics of HOST.
scrape() {
    k --namespace "$1" exec "$2" -- timeout 5 bash -c \
        'exec 3<>"/dev/tcp/$0/$1" && printf "GET /metrics HTTP/1.0\r\nHost: pgsnare\r\n\r\n" >&3 && cat <&3' \
        "$3" "$metrics_port" 2>/dev/null
}

# eventually CHECK...: retries the check for a minute, for a network
# plugin that learns of a new pod or a deleted policy a moment late.
eventually() {
    local attempt
    for attempt in $(seq 1 20); do
        "$@" && return 0
        sleep 2
    done
    return 1
}

scraped() {
    local answer
    answer="$(scrape "$1" "$2" "$3")" || return 1
    head -n 1 <<<"$answer" | grep -q ' 200 ' && grep -q '^pgsnare_' <<<"$answer"
}

say "the pods outside the namespace of pgsnare"
for attempt in $(seq 1 30); do
    k apply --filename "$here/others.yaml" >&2 2>/dev/null && break
    sleep 2
done
k --namespace "$other_namespace" wait --for=condition=Ready pod/outsider --timeout=300s >&2
k --namespace "$monitoring_namespace" wait --for=condition=Ready pod/scraper --timeout=300s >&2

ips=""
for pod in $(pods_of_release | awk '{ print $1 }'); do
    ips="$ips $(k --namespace "$namespace" get pod "$pod" --output 'jsonpath={.status.podIP}')"
done
ips="${ips# }"
[[ "$(wc -w <<<"$ips")" -eq 2 ]] || die "expected 2 pod addresses: $ips"

# --- Allowed ---------------------------------------------------------------------

eventually reach "$namespace" client "$proxy_host" 5432 || die "the listed client cannot reach the proxy"
for ip in $ips; do
    eventually scraped "$monitoring_namespace" scraper "$ip" || die "the listed scraper cannot read the metrics of $ip"
done
say "ok: the client reaches the proxy, the scraper reads the metrics of both pods"

# --- Refused ----------------------------------------------------------------------

! reach "$namespace" stranger "$proxy_host" 5432 || die "an unlisted pod reaches the proxy"
! reach "$other_namespace" outsider "$proxy_host" 5432 || die "a pod of another namespace with the client label reaches the proxy"
! reach "$monitoring_namespace" scraper "$proxy_host" 5432 || die "the scraper reaches the proxy"
for ip in $ips; do
    ! reach "$namespace" client "$ip" "$metrics_port" || die "the client reaches the metrics of $ip"
    ! reach "$namespace" stranger "$ip" "$metrics_port" || die "an unlisted pod reaches the metrics of $ip"
    ! reach "$other_namespace" outsider "$ip" "$metrics_port" || die "a pod of another namespace reaches the metrics of $ip"
done
say "ok: the stranger, the outsider and the scraper do not reach the proxy; only the scraper reaches the metrics"

# --- Without the policy -------------------------------------------------------------

say "deleting the NetworkPolicy of the release"
k --namespace "$namespace" delete networkpolicy "$fullname" >&2
eventually reach "$namespace" stranger "$proxy_host" 5432 \
    || die "without the policy the stranger still cannot reach the proxy, so its refusal proved nothing"
eventually reach "$other_namespace" outsider "$proxy_host" 5432 \
    || die "without the policy the outsider still cannot reach the proxy, so its refusal proved nothing"
first_ip="${ips%% *}"
eventually reach "$namespace" stranger "$first_ip" "$metrics_port" \
    || die "without the policy the stranger still cannot reach the metrics, so its refusal proved nothing"
say "ok: without the policy the refused pods get through"

say "passed"
