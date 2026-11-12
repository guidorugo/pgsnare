#!/usr/bin/env bash
# SPDX-License-Identifier: Apache-2.0
#
# Cancellation: a client interrupts a query that is running.
#
# The client sends a CancelRequest on a connection of its own, to the
# address it is connected to. Through pgsnare that address is pgsnare,
# which has to pass the request on to the database for the query to end.
#
# Usage: cancel.sh CONNINFO

set -u

conninfo="$1"
sql=(psql --no-psqlrc --no-password --quiet --dbname "$conninfo")

"${sql[@]}" --command "SELECT pg_sleep(120)" &
client=$!

# The interrupt must find the query running.
running=0
for _ in $(seq 200); do
    running="$("${sql[@]}" --tuples-only --no-align --command \
        "SELECT count(*) FROM pg_stat_activity
          WHERE datname = current_database() AND state = 'active'
            AND query = 'SELECT pg_sleep(120)'")"
    if [[ "$running" == "1" ]]; then
        break
    fi
    sleep 0.05
done
echo "queries running before the interrupt: $running"

kill -INT "$client"
wait "$client"
echo "the client ended with status $?"

# The query is gone, and the server takes the next one.
"${sql[@]}" --tuples-only --no-align --command \
    "SELECT count(*) AS still_running FROM pg_stat_activity
      WHERE datname = current_database() AND query = 'SELECT pg_sleep(120)' AND state = 'active'" \
    --command "SELECT 'after the cancel' AS state"
