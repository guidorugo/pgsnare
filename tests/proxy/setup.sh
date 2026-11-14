#!/bin/sh
# SPDX-License-Identifier: Apache-2.0
#
# Prepares what the integration tests need before anything else starts: a
# certificate authority, the certificates of the databases and of pgsnare,
# and the configuration of pgsnare.
#
# It runs once, in a container of its own, as the first step of
# `make itest`. Everything it writes goes to the volume mounted at
# /var/lib/postgresql, which the databases, pgsnare and the test client
# then mount read-only at /state. Nothing is written to the source tree,
# and every key exists only for the run that made it.
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

# --- Certificates -----------------------------------------------------------

cd "$state/certs"

# authority NAME: a certificate authority of its own.
authority() {
    cat > "$1.cnf" <<CONFIG
[req]
distinguished_name = name
prompt = no
x509_extensions = authority
[name]
CN = pgsnare integration tests $1
[authority]
basicConstraints = critical, CA:TRUE
keyUsage = critical, keyCertSign, cRLSign
subjectKeyIdentifier = hash
CONFIG
    openssl req -x509 -new -newkey ec -pkeyopt ec_paramgen_curve:P-256 -noenc \
        -days 2 -config "$1.cnf" -keyout "$1.key" -out "$1.crt" 2>/dev/null
}

# certificate NAME: a key, and a certificate for the host NAME signed by
# the authority `ca`.
certificate() {
    cat > "$1.cnf" <<CONFIG
[req]
distinguished_name = name
prompt = no
[name]
CN = $1
[server]
basicConstraints = critical, CA:FALSE
keyUsage = critical, digitalSignature
extendedKeyUsage = serverAuth
subjectAltName = DNS:$1
CONFIG
    openssl req -new -newkey ec -pkeyopt ec_paramgen_curve:P-256 -noenc \
        -config "$1.cnf" -keyout "$1.key" -out "$1.csr" 2>/dev/null
    openssl x509 -req -in "$1.csr" -CA ca.crt -CAkey ca.key -CAcreateserial \
        -days 2 -extfile "$1.cnf" -extensions server -out "$1.crt" 2>/dev/null
}

authority ca
# An authority that signed nothing, to show that verification can fail.
authority stranger
certificate pgsnare
for version in $versions; do
    certificate "pg$version"
done
certificate pglegacy

# --- The configuration of pgsnare -------------------------------------------
#
# One pgsnare serves every database. Each listener has a port of its own:
# two digits for the setup and two for the PostgreSQL version.
#
#   60NN  plaintext                       to  plaintext
#   61NN  plaintext                       to  TLS, verified
#   62NN  TLS, certificate of pgsnare     to  plaintext
#   63NN  TLS, certificate of pgsnare     to  a Unix socket
#   64NN  TLS, certificate of the database to TLS, verified
#   65NN  TLS, certificate of pgsnare     to  TLS, not verified
#   66NN  plaintext                       to  TLS, verified against the
#                                             wrong name
#   67NN  plaintext                       to  TLS, verified against the
#                                             wrong authority
#   68NN  TLS offered, plaintext accepted to  plaintext
#   69NN  plaintext                       to  TLS, verified against the
#                                             system's certificate store
#   7000  plaintext                       to  TLS, with a server that
#                                             speaks nothing above TLS 1.1
#
# Setups 60 to 64 are the supported ones. 65 is the one the design rules
# out, 66, 67 and 7000 must fail, 68 shows a listener that takes both
# kinds of client, and 69 names no authority of its own: tests/compose.yaml
# makes the authority of the tests the system's store for pgsnare.

config="$state/config/pgsnare.yaml"

# listener NAME PORT UPSTREAM CLIENT_TLS UPSTREAM_TLS
listener() {
    cat <<LISTENER
  - name: $1
    listen: 0.0.0.0:$2
    upstream: $3
    client_tls: $4
    upstream_tls: $5
LISTENER
}

own="{ mode: require, cert: /state/certs/pgsnare.crt, key: /state/certs/pgsnare.key }"
offered="{ mode: prefer, cert: /state/certs/pgsnare.crt, key: /state/certs/pgsnare.key }"
plain="{ mode: disable }"
verified="{ mode: verify-full, ca: /state/certs/ca.crt }"

{
    echo "listeners:"
    for version in $versions; do
        host="pg$version"
        shared="{ mode: require, cert: /state/certs/$host.crt, key: /state/certs/$host.key }"
        listener "plain-plain-$version" "60$version" "$host:5432" "$plain" "$plain"
        listener "plain-tls-$version" "61$version" "$host:5432" "$plain" "$verified"
        listener "own-plain-$version" "62$version" "$host:5432" "$own" "$plain"
        listener "own-unix-$version" "63$version" \
            "unix:/sockets/$host/.s.PGSQL.5432" "$own" "$plain"
        listener "shared-tls-$version" "64$version" "$host:5432" "$shared" "$verified"
        listener "own-tls-$version" "65$version" "$host:5432" "$own" "{ mode: require }"
        listener "wrong-name-$version" "66$version" "$host:5432" "$plain" \
            "{ mode: verify-full, ca: /state/certs/ca.crt, server_name: other.example.com }"
        listener "wrong-authority-$version" "67$version" "$host:5432" "$plain" \
            "{ mode: verify-full, ca: /state/certs/stranger.crt }"
        listener "offered-plain-$version" "68$version" "$host:5432" "$offered" "$plain"
        listener "system-store-$version" "69$version" "$host:5432" "$plain" \
            "{ mode: verify-full }"
    done
    listener "legacy-tls" "7000" "pglegacy:5432" "$plain" "$verified"
    cat <<'REST'
tokens:
  - id: itest-alert
    values: ["itest-bait-alert-5d83c1"]
  - id: itest-kill
    values: ["itest-bait-kill-7e20a9"]
    actions: [kill]
events:
  sinks:
    - type: stdout
shutdown:
  grace_period: 10s
REST
} > "$config"

# --- Files that are open to other users --------------------------------------
#
# pgsnare must refuse to start with any of these: a configuration that
# names a private key the group can read, a configuration that everybody
# can read, and a configuration that names a token file the group can
# read.

cp "$state/certs/pgsnare.key" "$state/certs/open.key"
chmod 0640 "$state/certs/open.key"

# The value is made up for this file and is planted nowhere.
mkdir -p "$state/config/tokens"
cat > "$state/config/tokens/open.yaml" <<'TOKENS'
tokens:
  - id: itest
    values: ["itest-value-planted-nowhere"]
TOKENS
chmod 0640 "$state/config/tokens/open.yaml"

minimal() {
    cat <<MINIMAL
listeners:
  - name: main
    listen: 0.0.0.0:6000
    upstream: pg.example.com:5432
    client_tls: { mode: require, cert: /state/certs/pgsnare.crt, key: /state/certs/$1 }
    upstream_tls: { mode: disable }
events:
  sinks:
    - type: stdout
shutdown:
  grace_period: 1s
MINIMAL
}

minimal open.key > "$state/config/open-key.yaml"
minimal pgsnare.key > "$state/config/open-config.yaml"
chmod 0644 "$state/config/open-config.yaml"
{
    minimal pgsnare.key
    echo "token_files:"
    echo "  - tokens/open.yaml"
} > "$state/config/open-tokens.yaml"

echo "setup: wrote the certificates and $config"
