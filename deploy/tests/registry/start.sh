#!/usr/bin/env bash
# SPDX-License-Identifier: Apache-2.0
#
# Starts the registry of deploy/tests/registry/compose.yaml and waits until
# it answers. For CI runners: it publishes a port on the loopback interface.
#
#   deploy/tests/registry/start.sh
#
# PGSNARE_REGISTRY_PORT is the port, 5000 unless set.

set -euo pipefail

here="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
port="${PGSNARE_REGISTRY_PORT:-5000}"
[[ "$port" =~ ^[0-9]{2,5}$ ]] || { echo "registry: the port is not a number" >&2; exit 1; }

docker compose --file "$here/compose.yaml" up --detach --quiet-pull

tries=0
until curl --fail --silent --show-error --max-time 2 --output /dev/null "http://127.0.0.1:$port/v2/" 2>/dev/null; do
    tries=$((tries + 1))
    if [[ "$tries" -ge 60 ]]; then
        echo "registry: no answer on port $port after a minute" >&2
        docker compose --file "$here/compose.yaml" logs --no-color 2>&1 | tail -n 20 >&2 || true
        exit 1
    fi
    sleep 1
done
echo "registry: listening on 127.0.0.1:$port" >&2
