#!/usr/bin/env bash
# SPDX-License-Identifier: Apache-2.0
#
# Only the listed clients reach the proxy, only the listed scrapers reach
# the metrics, and a pod of pgsnare reaches nothing that is not listed.
# Runs after sinks.sh, and last: it deletes the NetworkPolicy of the
# release at the end.
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
# Outwards, each pod of pgsnare opens a TCP connection to a pod of the
# name service: to its port 53, which the policy lists, and to the port of
# that pod's own metrics, which it does not. The address is the same and
# the namespace of the name service has no policy, so the difference is the
# egress rule.
#
# Then the NetworkPolicy is deleted, and the stranger, the outsider and the
# connection to the unlisted port get through: so the refusals above were
# the policy's.

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

# out POD ADDRESS PORT: whether POD of the release opens a TCP connection
# to ADDRESS:PORT within 3 seconds. The image of pgsnare has no bash; its
# base has nc, which ends when the other side closes the connection that
# it was given nothing to read on.
out() {
    k --namespace "$namespace" exec "$1" -- timeout 8 nc -w 3 "$2" "$3" > /dev/null 2>&1
}

# scrape NAMESPACE POD HOST: what POD gets from /metrics of HOST.
scrape() {
    k --namespace "$1" exec "$2" -- timeout 5 bash -c \
        'exec 3<>"/dev/tcp/$0/$1" && printf "GET /metrics HTTP/1.0\r\nHost: pgsnare\r\nConnection: close\r\n\r\n" >&3 && cat <&3' \
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
    # The answer counts, not how the connection ended.
    answer="$(scrape "$1" "$2" "$3" || true)"
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

# --- Outwards -----------------------------------------------------------------------

dns_port=53
unlisted_port=9153
dns_ip="$(k --namespace kube-system get pods --selector k8s-app=kube-dns \
    --output 'jsonpath={range .items[*]}{.status.phase} {.status.podIP}{"\n"}{end}' \
    | awk '$1 == "Running" && NF == 2 { print $2; exit }')"
[[ -n "$dns_ip" ]] || die "no running pod of the name service has an address"
release_pods="$(pods_of_release | awk '{ print $1 }')"
[[ "$(wc -w <<<"$release_pods")" -eq 2 ]] || die "expected 2 pods of the release: $release_pods"

# The unlisted port is open: a pod that no policy selects reaches it.
eventually reach "$other_namespace" outsider "$dns_ip" "$unlisted_port" \
    || die "nothing listens on port $unlisted_port of the name service, so a refusal there would prove nothing"
for pod in $release_pods; do
    # The same command, to the listed port of the same address: so a
    # failure of the next one is not a failure to run the command.
    eventually out "$pod" "$dns_ip" "$dns_port" \
        || die "$pod cannot reach the name service on port $dns_port"
    ! out "$pod" "$dns_ip" "$unlisted_port" \
        || die "$pod reaches port $unlisted_port of the name service, which the policy does not list"
done
say "ok: the pods of pgsnare reach the name service on its port and not on a port that is not listed"

# --- Without the policy -------------------------------------------------------------

say "deleting the NetworkPolicy of the release"
k --namespace "$namespace" delete networkpolicy "$fullname" >&2
for pod in $release_pods; do
    eventually out "$pod" "$dns_ip" "$unlisted_port" \
        || die "without the policy $pod still cannot reach port $unlisted_port of the name service, so its refusal proved nothing"
done
eventually reach "$namespace" stranger "$proxy_host" 5432 \
    || die "without the policy the stranger still cannot reach the proxy, so its refusal proved nothing"
eventually reach "$other_namespace" outsider "$proxy_host" 5432 \
    || die "without the policy the outsider still cannot reach the proxy, so its refusal proved nothing"
first_ip="${ips%% *}"
eventually reach "$namespace" stranger "$first_ip" "$metrics_port" \
    || die "without the policy the stranger still cannot reach the metrics, so its refusal proved nothing"
say "ok: without the policy the refused pods and the refused connection outwards get through"

say "passed"
