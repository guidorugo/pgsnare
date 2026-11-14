#!/bin/sh
# SPDX-License-Identifier: Apache-2.0
#
# Writes the configuration of the image test to the volume /state, which
# the pgsnare container mounts at /etc/pgsnare. It runs as the user of the
# image under test, and every file is for that user alone: pgsnare refuses
# a configuration or a token file that other users can read.
#
# The token value comes from test.sh, which makes a new one for each run.
# It is synthetic and has no meaning outside this test.

set -eu

case "${PGSNARE_IMAGE_TEST_TOKEN:-}" in
    "" | *[!a-z0-9-]*)
        echo "setup: PGSNARE_IMAGE_TEST_TOKEN must be lower-case letters, digits and hyphens" >&2
        exit 1
        ;;
esac

umask 077
mkdir -p /state/tokens

# The database is found by its name on the network of the test.
cat > /state/pgsnare.yaml <<'CONFIG'
listeners:
  - name: image-test
    listen: 0.0.0.0:5432
    upstream: postgres:5432
    client_tls: { mode: disable }
    upstream_tls: { mode: disable }
token_files:
  - tokens/*.yaml
events:
  sinks:
    - type: stdout
shutdown:
  grace_period: 5s
CONFIG

cat > /state/tokens/seeded.yaml <<TOKENS
tokens:
  - id: image-test-seeded
    values: ["$PGSNARE_IMAGE_TEST_TOKEN"]
TOKENS

chmod 0600 /state/pgsnare.yaml /state/tokens/seeded.yaml
chmod 0700 /state /state/tokens
