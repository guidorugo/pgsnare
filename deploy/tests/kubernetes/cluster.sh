#!/usr/bin/env bash
# SPDX-License-Identifier: Apache-2.0
#
# Creates the cluster of the Kubernetes tests and lets its node pull from
# the registry of the runner.
#
#   deploy/tests/kubernetes/cluster.sh
#
# The registry is the one deploy/tests/registry/start.sh started, on the
# loopback address of the runner. An image is named as the runner names it,
# 127.0.0.1:PORT/NAME@sha256:..., and the node is told to fetch that name
# from the registry container, over the network the two share. So the
# image a pod runs is pulled by digest from a registry, as it would be in a
# real cluster.

set -euo pipefail

here="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
# shellcheck source=deploy/tests/kubernetes/lib.sh
source "$here/lib.sh"

port="${PGSNARE_REGISTRY_PORT:-5000}"
registry="pgsnare-registry"
[[ "$port" =~ ^[0-9]{2,5}$ ]] || die "the port of the registry is not a number"

for tool in kind kubectl helm docker; do
    command -v "$tool" >/dev/null || die "$tool is not on the path"
done
[[ "$(docker inspect --format '{{.State.Running}}' "$registry" 2>/dev/null || true)" == true ]] \
    || die "the registry is not running: start it with deploy/tests/registry/start.sh"

say "creating the cluster $cluster"
kind create cluster --name "$cluster" --config "$here/kind.yaml" --wait 180s

# The node resolves the runner's name for the registry to the registry
# container.
for node in $(kind get nodes --name "$cluster"); do
    directory="/etc/containerd/certs.d/127.0.0.1:$port"
    docker exec "$node" mkdir -p "$directory"
    printf '[host."http://%s:5000"]\n' "$registry" \
        | docker exec --interactive "$node" cp /dev/stdin "$directory/hosts.toml"
done
if [[ "$(docker inspect --format '{{json .NetworkSettings.Networks.kind}}' "$registry")" == null ]]; then
    docker network connect kind "$registry"
fi

k wait --for=condition=Ready nodes --all --timeout=180s >&2
k --namespace kube-system rollout status deployment/coredns --timeout=180s >&2

# The chart's default for the name service must be true of this cluster.
[[ -n "$(k --namespace kube-system get pods --selector k8s-app=kube-dns --output name)" ]] \
    || die "no pod of the name service carries the label the chart expects"

say "the cluster is ready: $(k version --output json | grep -o '"gitVersion": *"[^"]*"' | tail -n 1)"
