#!/bin/sh
# SPDX-License-Identifier: Apache-2.0
#
# Runs once, at the first `docker compose up`, in the service `setup`. It
# makes everything this example needs that must not be committed: the
# certificates and keys, the password of the database, the signing key of
# the webhook, and the honeytokens. Each consumer gets a volume of its own
# with only what it needs, its files readable by its user alone:
#
#   /out/pgsnare    pgsnare (user 65532): configuration, token file,
#                   certificate and key, signing key, the receiver's CA
#   /out/receiver   the receiver (user 65533): certificate, key, signing key
#   /out/postgres   PostgreSQL (user 999): certificate, key, password
#   /out/initdb     PostgreSQL's first start: the SQL that plants the tokens
#   /out/client     psql (user 999): the CA and a password file
#
# Every value is random and made on this machine. The tokens are synthetic
# demonstration values: for real use generate your own, with
# `pgsnare token generate`, and plant them where an intruder would look.

set -eu

if [ -e /out/pgsnare/.done ]; then
    echo "setup: already done"
    exit 0
fi

umask 077
work=/tmp/setup
mkdir -p "$work"
cd "$work"

# --- Certificates: one authority, made here and never kept -----------------

openssl req -x509 -new -newkey ec -pkeyopt ec_paramgen_curve:P-256 -noenc \
    -keyout ca.key -out ca.crt -days 30 -subj "/CN=pgsnare example CA" \
    -addext "basicConstraints=critical,CA:TRUE" \
    -addext "keyUsage=critical,keyCertSign,cRLSign" 2>/dev/null

# issue NAME SAN...: a server certificate signed by the authority.
issue() {
    name="$1"
    shift
    sans=""
    for san in "$@"; do
        sans="${sans:+$sans,}DNS:$san"
    done
    openssl req -new -newkey ec -pkeyopt ec_paramgen_curve:P-256 -noenc \
        -keyout "$name.key" -out "$name.csr" -subj "/CN=$1" 2>/dev/null
    printf 'subjectAltName=%s\nextendedKeyUsage=serverAuth\nbasicConstraints=critical,CA:FALSE\n' "$sans" > "$name.ext"
    openssl x509 -req -in "$name.csr" -CA ca.crt -CAkey ca.key -CAcreateserial \
        -days 30 -extfile "$name.ext" -out "$name.crt" 2>/dev/null
}

# The database and pgsnare present the same certificate: with TLS on both
# legs, SCRAM channel binding only works when the client sees the
# database's own certificate.
issue database postgres pgsnare
issue receiver receiver

# --- Secrets ------------------------------------------------------------------

openssl rand -hex 24 | tr -d '\n' > password
openssl rand -hex 32 | tr -d '\n' > hmac-key
email="carol.$(openssl rand -hex 6)@example.com"
api_key="pgs_demo_$(openssl rand -hex 20)"

# --- pgsnare --------------------------------------------------------------------

mkdir -p /out/pgsnare/tokens
cat > /out/pgsnare/pgsnare.yaml <<'CONFIG'
# Made by setup.sh for the Compose example.
listeners:
  - name: example
    listen: 0.0.0.0:5432
    upstream: postgres:5432
    client_tls:
      mode: require
      cert: /etc/pgsnare/database.crt
      key: /etc/pgsnare/database.key
    upstream_tls:
      mode: verify-full
      ca: /etc/pgsnare/ca.crt
token_files:
  - tokens/*.yaml
events:
  sinks:
    - type: stdout
    - type: webhook
      url: https://receiver:8443/events
      hmac_secret_file: /etc/pgsnare/webhook-hmac-key
shutdown:
  grace_period: 5s
CONFIG

cat > /out/pgsnare/tokens/demo.yaml <<TOKENS
# Synthetic tokens made at the first start of the Compose example.
# Generate your own for real use: pgsnare token generate
tokens:
  - id: demo-customer-email
    values: ["$email"]
    scope: { database: postgres, table: public.customers, column: email }
    actions: [alert]
  - id: demo-api-key
    values: ["$api_key"]
    scope: { database: postgres, table: public.api_keys, column: key }
    actions: [alert]
TOKENS
cp database.crt database.key ca.crt /out/pgsnare/
cp hmac-key /out/pgsnare/webhook-hmac-key
# pgsnare trusts the receiver through this file (SSL_CERT_FILE).
cp ca.crt /out/pgsnare/receiver-ca.crt

# --- The receiver ---------------------------------------------------------------

cp receiver.crt receiver.key hmac-key ca.crt /out/receiver/

# --- PostgreSQL -------------------------------------------------------------------

cp database.crt database.key password /out/postgres/
cat > /out/initdb/plant.sql <<SQL
-- Made by setup.sh: a small table of customers and one of API keys, each
-- with one honeytoken among real-looking rows. Nobody has a reason to
-- read the tokens; whoever does is reported.
CREATE TABLE customers (id integer PRIMARY KEY, name text NOT NULL, email text NOT NULL);
INSERT INTO customers VALUES
    (1, 'Alice Example', 'alice@example.com'),
    (2, 'Bob Example', 'bob@example.com'),
    (3, 'Carol Example', '$email');
CREATE TABLE api_keys (id integer PRIMARY KEY, owner text NOT NULL, key text NOT NULL);
INSERT INTO api_keys VALUES (1, 'reporting', '$api_key');
SQL

# --- psql -----------------------------------------------------------------------------

cp ca.crt /out/client/
printf 'pgsnare:5432:*:postgres:%s\n' "$(cat password)" > /out/client/pgpass

# --- Owners --------------------------------------------------------------------------

# Modes first: once a file belongs to another user, root without the
# capability FOWNER can no longer change it. The volumes' own directories
# stay root's, readable by all; what is in them belongs to the consumer.
find /out/pgsnare /out/receiver /out/postgres /out/initdb /out/client -type f -exec chmod 0600 {} +
chmod 0700 /out/pgsnare/tokens
chmod 0755 /out/pgsnare /out/receiver /out/postgres /out/initdb /out/client
find /out/pgsnare -mindepth 1 -exec chown 65532:65532 {} +
find /out/receiver -mindepth 1 -exec chown 65533:65533 {} +
find /out/postgres /out/initdb /out/client -mindepth 1 -exec chown 999:999 {} +

rm -rf "$work"
: > /out/pgsnare/.done
echo "setup: done"
