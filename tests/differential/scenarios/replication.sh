#!/usr/bin/env bash
# SPDX-License-Identifier: Apache-2.0
#
# A logical replication stream: the server sends changes as they were
# decoded, and the client confirms what it has received, both inside one
# COPY that runs in both directions.
#
# Usage: replication.sh CONNINFO

set -u

conninfo="$1"
slot=pgsnare_scenario_slot
sql=(psql --no-psqlrc --no-password --quiet --tuples-only --no-align --dbname "$conninfo")

# A slot keeps its database from being dropped, so it never outlives this
# script.
drop_slot() {
    "${sql[@]}" --command "SELECT pg_drop_replication_slot(slot_name)
        FROM pg_replication_slots WHERE slot_name = '$slot'" >/dev/null 2>&1
}
trap drop_slot EXIT
drop_slot

pg_recvlogical --no-password --dbname "$conninfo" --slot "$slot" --create-slot --plugin test_decoding
echo "creating the slot ended with status $?"

"${sql[@]}" \
    --command "CREATE TABLE replicated (id int PRIMARY KEY, note text)" \
    --command "INSERT INTO replicated VALUES (1, 'first'), (2, 'second')" \
    --command "UPDATE replicated SET note = 'changed' WHERE id = 2" \
    --command "INSERT INTO replicated VALUES (3, repeat('long ', 60000))" \
    --command "DELETE FROM replicated WHERE id = 1"

# Only the transactions above count. The server may commit one of its own
# in this database at any moment, for example when autovacuum analyzes a
# catalog here. Such a transaction changes no table and is left out
# everywhere below, or it would show up as a difference that neither
# endpoint is responsible for.
#
# The stream ends at the last change that exists now.
last="$("${sql[@]}" --command "SELECT lsn
    FROM pg_logical_slot_peek_changes('$slot', NULL, NULL, 'skip-empty-xacts', '1')
    ORDER BY lsn DESC LIMIT 1")"

# The decoded changes go to standard output. Transaction ids differ from
# run to run and are left out.
timeout 60 pg_recvlogical --no-password --dbname "$conninfo" --slot "$slot" --start \
    --endpos "$last" --no-loop --file - \
    --option include-xids=0 --option skip-empty-xacts=1 | md5sum
echo "the stream ended with status ${PIPESTATUS[0]}"

# The client has confirmed what it received, inside the same COPY, so the
# server has nothing left to send: this counts the changes that remain.
"${sql[@]}" --command "SELECT count(*)
    FROM pg_logical_slot_peek_changes('$slot', NULL, NULL, 'skip-empty-xacts', '1')"
