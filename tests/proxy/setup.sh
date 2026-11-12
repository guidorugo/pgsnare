#!/bin/sh
# SPDX-License-Identifier: Apache-2.0
#
# Prepares what the integration tests need before anything else starts: the
# certificates of a test authority and the configuration of pgsnare.
#
# It runs once, in a container of its own, as the first step of
# `make itest`. Everything it writes goes to the volume mounted at
# /var/lib/postgresql, which the databases and pgsnare then mount read-only
# at /state. Nothing is written to the source tree, and every key exists
# only for the run that made it.
#
# Environment:
#   ITEST_VERSIONS  the PostgreSQL versions under test, for example "15 16"

set -eu

state=/var/lib/postgresql
versions="${ITEST_VERSIONS:?run the tests with make itest}"

# Keys and the configuration are for their owner alone: pgsnare and
# PostgreSQL both refuse to start otherwise.
umask 077

mkdir -p "$state/certs" "$state/config"

# --- The configuration of pgsnare -------------------------------------------
#
# One pgsnare serves every database. Each listener has a port of its own:
# two digits for the setup and two for the PostgreSQL version.
#
#   60NN  client leg in plaintext, backend leg in plaintext

config="$state/config/pgsnare.yaml"
{
    echo "listeners:"
    for version in $versions; do
        cat <<LISTENER
  - name: plain-plain-$version
    listen: 0.0.0.0:60$version
    upstream: pg$version:5432
    client_tls: { mode: disable }
    upstream_tls: { mode: disable }
LISTENER
    done
    cat <<'REST'
events:
  sinks:
    - type: stdout
shutdown:
  grace_period: 5s
REST
} > "$config"

echo "setup: wrote $config"
