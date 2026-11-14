#!/usr/bin/env bash
# SPDX-License-Identifier: Apache-2.0
#
# The smoke test of the Compose example: the commands of docs/quickstart.md,
# with checks between them.
#
#   PGSNARE_IMAGE=REGISTRY/pgsnare@sha256:... examples/compose/smoke.sh
#
# It passes when, from `docker compose up` on:
#
#   - pgsnare becomes healthy through the health check of its image;
#   - the receiver refuses a request without a signature, with the
#     signature of another key and with an old timestamp, and accepts a
#     signed one (so its checks can fail);
#   - a query that reads no token reaches the database and raises nothing;
#   - a query that reads a token is answered, and the receiver holds a
#     token_hit for it whose signature it verified, less than 2 seconds
#     after the database ran the query;
#   - all of this took less than 5 minutes;
#   - the value of the token is in no log.
#
# Everything it started is removed at the end, volumes included, unless
# PGSNARE_SMOKE_KEEP=1.

set -euo pipefail

: "${PGSNARE_IMAGE:?set PGSNARE_IMAGE to the pgsnare image by digest}"
[[ "$PGSNARE_IMAGE" =~ ^[a-z0-9][a-z0-9.:/_-]*@sha256:[0-9a-f]{64}$ ]] \
    || { echo "smoke: PGSNARE_IMAGE must be NAME@sha256:<64 hex digits>" >&2; exit 1; }
export PGSNARE_IMAGE

cd "$(dirname "${BASH_SOURCE[0]}")"

say() {
    echo "smoke: $*" >&2
}

finish() {
    local status=$?
    if [[ "$status" -ne 0 ]]; then
        say "FAILED; the state of the example:"
        docker compose ps --all >&2 || true
        for service in setup postgres receiver pgsnare; do
            echo "--- $service" >&2
            docker compose logs --no-log-prefix --tail 20 "$service" >&2 || true
        done
    fi
    if [[ "${PGSNARE_SMOKE_KEEP:-0}" != 1 ]]; then
        docker compose down --volumes --remove-orphans > /dev/null 2>&1 || true
    fi
    exit "$status"
}
trap finish EXIT

die() {
    say "$*"
    exit 1
}

started="$(date +%s.%N)"

# --- 1. Up, and healthy -----------------------------------------------------------

docker compose up --detach
health=""
for _ in $(seq 1 240); do
    health="$(docker compose ps --format '{{.Health}}' pgsnare 2>/dev/null || true)"
    [[ "$health" == healthy ]] && break
    sleep 1
done
[[ "$health" == healthy ]] || die "pgsnare did not become healthy within 4 minutes (last: ${health:-none})"
docker compose ps pgsnare
say "ok: pgsnare is healthy"

# --- 2. The receiver checks what it must --------------------------------------------

checked=0
for _ in $(seq 1 30); do
    if docker compose exec -T receiver python3 /app/receiver.py check https://receiver:8443/events; then
        checked=1
        break
    fi
    sleep 1
done
[[ "$checked" == 1 ]] || die "the receiver did not refuse and accept what it must"
say "ok: the receiver refuses unsigned, forged and old requests and accepts a signed one"

received() {
    docker compose logs --no-log-prefix receiver 2>/dev/null | grep -F '"kind":"token_hit"' || true
}

# --- 3. A query that reads no token ---------------------------------------------------

answer="$(docker compose run --rm -T client -c "SELECT name FROM customers WHERE id = 1")"
echo "$answer"
grep -qF 'Alice Example' <<<"$answer" || die "a client could not read through pgsnare"
sleep 2
[[ -z "$(received)" ]] || die "a token_hit arrived before a token was read, so the next check proves nothing"
say "ok: a query that reads no token raised nothing"

# --- 4. A query that reads a token ----------------------------------------------------

answer="$(docker compose run --rm -T client -c "SELECT name, email, extract(epoch FROM clock_timestamp()) AS queried_at FROM customers")"
echo "$answer"
# The rows are "name | email | queried_at"; the token is Carol's email.
token="$(awk -F'|' '/Carol Example/ { gsub(/ /, "", $2); print $2 }' <<<"$answer")"
queried="$(awk -F'|' 'NF == 3 && $3 ~ /^ *[0-9]+(\.[0-9]+)? *$/ { gsub(/ /, "", $3); print $3; exit }' <<<"$answer")"
[[ "$token" == carol.*@example.com ]] || die "the row with the token was not answered"
[[ -n "$queried" ]] || die "the answer carries no time of the query"

line=""
for _ in $(seq 1 100); do
    line="$(received | grep -F '"token_id":"demo-customer-email"' | head -n 1 || true)"
    [[ -n "$line" ]] && break
    sleep 0.2
done
[[ -n "$line" ]] || die "the receiver holds no verified token_hit for the token that was read"
[[ "$line" =~ \"received_at\":([0-9]+(\.[0-9]+)?) ]] || die "the receiver's line has no time"
arrived="${BASH_REMATCH[1]}"
finished="$(date +%s.%N)"

delay="$(awk -v a="$arrived" -v q="$queried" 'BEGIN { printf "%.3f", a - q }')"
total="$(awk -v f="$finished" -v s="$started" 'BEGIN { printf "%.1f", f - s }')"
say "from the query to the receiver: $delay s"
say "from docker compose up to the verified token_hit: $total s"
awk -v d="$delay" 'BEGIN { exit !(d >= 0 && d < 2) }' || die "the token_hit took $delay s, not less than 2 s"
awk -v t="$total" 'BEGIN { exit !(t < 300) }' || die "the first alert took $total s, not less than 5 minutes"
say "ok: the receiver verified the token_hit"

# --- 5. The token's value is in no log -------------------------------------------------

if docker compose logs --no-log-prefix pgsnare receiver 2>&1 | grep -qF -- "$token"; then
    die "the value of the token is in a log"
fi
say "ok: the value of the token is in no log"

say "passed"
