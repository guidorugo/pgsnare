#!/bin/sh
# SPDX-License-Identifier: Apache-2.0
#
# Captures the golden-byte fixtures of pgsnare-proto from real PostgreSQL
# servers.
#
# For each server version the script starts a throwaway server and a
# recorder in containers on a private network, runs every scenario through
# the recorder with a real client, and stores what each side sent in
# ../pg<version>-<protocol>/. Nothing is installed on the host and no port
# is published. The host needs only Docker.
#
#   ./capture.sh              capture every version
#   ./capture.sh 17 18        capture only these versions
#
# Environment:
#   SERVER_IMAGE    image of the servers, with %s for the major version
#                   (default: postgres:%s-alpine)
#   CLIENT_IMAGE    image with psql and libpq 18 (default: postgres:18-alpine)
#   RECORDER_IMAGE  image with Python 3 (default: python:3.14-alpine)
#   PREFIX          prefix of the container and network names
#                   (default: pgsnare-capture)
#   VERBOSE         set to 1 to see the output of the clients
#
# Everything the servers hold is synthetic, and the one password in use
# exists only inside them. A new capture differs from the last in every
# random value: salts, nonces, cancel keys and process ids. The tests do
# not depend on those.

set -eu

here=$(cd "$(dirname "$0")" && pwd)
fixtures=$(dirname "$here")

SERVER_IMAGE=${SERVER_IMAGE:-postgres:%s-alpine}
CLIENT_IMAGE=${CLIENT_IMAGE:-postgres:18-alpine}
RECORDER_IMAGE=${RECORDER_IMAGE:-python:3.14-alpine}
PREFIX=${PREFIX:-pgsnare-capture}

network=$PREFIX-net
server=$PREFIX-server
recorder=$PREFIX-recorder
client=$PREFIX-client

# The clients reach the recorder under a reserved documentation name, and
# the network uses a reserved documentation range, so that no real name or
# address can end up in a capture.
recorder_host=db.example.com
subnet=192.0.2.0/24

password=not-a-secret
user_ids="$(id -u):$(id -g)"

if [ "${VERBOSE:-0}" = 1 ]; then
    log=/dev/stderr
else
    log=/dev/null
fi

# One port of the recorder per scenario.
ports="6001=simple 6002=extended 6003=copy 6004=auth-md5 6005=auth-cleartext
6006=auth-failed 6007=ssl-refused 6008=cancel 6009=replication
6010=negotiate 6011=crafted-negotiate 6012=crafted-binary 6013=direct-tls"

port_of() {
    for mapping in $ports; do
        if [ "${mapping#*=}" = "$1" ]; then
            echo "${mapping%%=*}"
            return
        fi
    done
    echo "unknown scenario: $1" >&2
    exit 1
}

cleanup() {
    docker rm --force --volumes "$client" "$recorder" "$server" >/dev/null 2>&1 || true
    docker network rm "$network" >/dev/null 2>&1 || true
}
trap cleanup EXIT INT TERM

# Runs a command in a container on the capture network.
#   in_container IMAGE PASSWORD COMMAND...
in_container() {
    image=$1
    secret=$2
    shift 2
    docker run --rm --name "$client" --network "$network" --user "$user_ids" \
        --cap-drop ALL --security-opt no-new-privileges \
        --env PGPASSWORD="$secret" \
        --volume "$here/scenarios:/scenarios:ro" \
        --volume "$here/crafted_client.py:/crafted_client.py:ro" \
        "$image" "$@" >"$log" 2>&1
}

# Runs psql, with libpq 18, against the recorder.
run_psql() {
    in_container "$CLIENT_IMAGE" "$password" psql --no-psqlrc --quiet "$@"
}

# Runs psql inside the server container, as the superuser, bypassing the
# recorder.
admin() {
    docker exec --user "$user_ids" "$server" \
        psql --no-psqlrc --quiet --tuples-only --no-align \
        --username postgres --dbname appdb --command "$1"
}

# The connection string of a scenario.
#   target SCENARIO PROTOCOL [SSLMODE]
target() {
    echo "host=$recorder_host port=$(port_of "$1") dbname=appdb gssencmode=disable max_protocol_version=$2 sslmode=${3:-disable}"
}

start_server() {
    docker run --detach --name "$server" --network "$network" --network-alias pg \
        --user "$user_ids" --cap-drop ALL --security-opt no-new-privileges \
        --tmpfs "/pgdata:uid=$(id -u),gid=$(id -g),mode=0700" \
        --env PGDATA=/pgdata \
        --env POSTGRES_PASSWORD="$password" \
        --env POSTGRES_INITDB_ARGS=--auth-host=scram-sha-256 \
        --volume "$here/initdb:/docker-entrypoint-initdb.d:ro" \
        "$1" \
        -c wal_level=logical -c max_wal_senders=4 -c max_replication_slots=4 \
        -c wal_sender_timeout=4s -c fsync=off >/dev/null
    # The server accepts TCP connections only once initialisation is over.
    tries=0
    until docker exec --user "$user_ids" "$server" pg_isready --quiet --host 127.0.0.1 --username postgres; do
        tries=$((tries + 1))
        if [ "$tries" -gt 120 ]; then
            echo "the server did not start" >&2
            docker logs "$server" >&2 || true
            exit 1
        fi
        sleep 0.5
    done
}

start_recorder() {
    # shellcheck disable=SC2086
    docker run --detach --name "$recorder" --network "$network" \
        --network-alias "$recorder_host" --user "$user_ids" \
        --read-only --cap-drop ALL --security-opt no-new-privileges \
        --volume "$here/recorder.py:/recorder.py:ro" --volume "$1:/out" \
        "$RECORDER_IMAGE" python3 /recorder.py --upstream pg:5432 --out /out $ports >/dev/null
    tries=0
    until docker logs "$recorder" 2>/dev/null | grep -q 'recorder ready'; do
        tries=$((tries + 1))
        if [ "$tries" -gt 60 ]; then
            echo "the recorder did not start" >&2
            docker logs "$recorder" >&2 || true
            exit 1
        fi
        sleep 0.25
    done
}

# The scenarios that a real client drives.
#   libpq_scenarios PROTOCOL
libpq_scenarios() {
    protocol=$1

    run_psql "$(target simple "$protocol") user=app_scram" --file /scenarios/simple.sql
    run_psql "$(target extended "$protocol") user=app_scram" --file /scenarios/extended.sql
    run_psql "$(target copy "$protocol") user=app_scram" --file /scenarios/copy.sql
    run_psql "$(target auth-md5 "$protocol") user=app_md5" --command 'SELECT 1'
    run_psql "$(target auth-cleartext "$protocol") user=app_plain" --command 'SELECT 1'

    # A wrong password: the login must fail.
    if in_container "$CLIENT_IMAGE" wrong-on-purpose psql --no-psqlrc --quiet \
        "$(target auth-failed "$protocol") user=app_scram" --command 'SELECT 1'; then
        echo "the login with a wrong password succeeded" >&2
        exit 1
    fi

    # The client asks for TLS, the server has none and declines, and the
    # session continues in the clear on the same connection.
    run_psql "$(target ssl-refused "$protocol" prefer) user=app_scram" --command 'SELECT 1'

    # Interrupt a running query, which makes psql open a second connection
    # and send a CancelRequest on it. psql then exits with an error.
    if in_container "$CLIENT_IMAGE" "$password" timeout -s INT 2 psql --no-psqlrc --quiet \
        "$(target cancel "$protocol") user=app_scram" --command 'SELECT pg_sleep(30)'; then
        echo "the query was not cancelled" >&2
        exit 1
    fi

    # Logical replication, which runs in COPY BOTH mode. A change is made
    # first, so that there is something to stream, and the stream ends at
    # the position reached after it.
    admin "SELECT pg_create_logical_replication_slot('fixture_slot', 'test_decoding')" >/dev/null
    admin "INSERT INTO contacts VALUES (100, 'replicated@example.com', 'streamed')"
    admin "DELETE FROM contacts WHERE id = 100"
    end=$(admin 'SELECT pg_current_wal_lsn()')
    in_container "$CLIENT_IMAGE" "$password" timeout 30 pg_recvlogical \
        --dbname "$(target replication "$protocol") user=app_repl" \
        --slot fixture_slot --start --endpos "$end" --no-loop --file /dev/null
    admin "SELECT pg_drop_replication_slot('fixture_slot')" >/dev/null
}

#   capture VERSION PROTOCOL
capture() {
    version=$1
    protocol=$2
    out=$fixtures/pg$version-$protocol
    rm -rf "$out"
    mkdir -p "$out"
    start_recorder "$out"

    libpq_scenarios "$protocol"

    if [ "$protocol" = 3.0 ]; then
        if [ "$version" -lt 18 ]; then
            # libpq 18 asks an older server for protocol 3.2. The server
            # answers with NegotiateProtocolVersion and the session goes on
            # with 3.0.
            run_psql "$(target negotiate 3.2) user=app_scram" --command 'SELECT 1'
        fi

        # Messages that libpq cannot be made to send, written by hand.
        in_container "$RECORDER_IMAGE" "$password" python3 /crafted_client.py negotiate \
            "$recorder_host" "$(port_of crafted-negotiate)"
        in_container "$RECORDER_IMAGE" "$password" python3 /crafted_client.py binary \
            "$recorder_host" "$(port_of crafted-binary)" "$password"

        if [ "$version" -eq 18 ]; then
            # Direct TLS: the client opens with a TLS handshake. The server
            # has no TLS and closes the connection, so only the first
            # flight of the client is captured.
            if run_psql "$(target direct-tls 3.0 require) sslnegotiation=direct user=app_scram" \
                --command 'SELECT 1'; then
                echo "a TLS connection to a server without TLS succeeded" >&2
                exit 1
            fi
        fi
    fi

    # Give the last connection time to close, then stop recording.
    sleep 1
    docker rm --force "$recorder" >/dev/null

    {
        echo "Captured by capture/capture.sh. Every value is synthetic."
        echo "Protocol asked for by the client: $protocol"
        echo "Server: $(docker exec --user "$user_ids" "$server" postgres --version)"
        echo "Server image: $server_image $(image_digest "$server_image")"
        echo "Client: $(docker run --rm --user "$user_ids" "$CLIENT_IMAGE" psql --version)"
        echo "Client image: $CLIENT_IMAGE $(image_digest "$CLIENT_IMAGE")"
        echo "Recorder image: $RECORDER_IMAGE $(image_digest "$RECORDER_IMAGE")"
    } >"$out/MANIFEST.txt"

    find "$out" -type f -name '*.bin' | sort | while read -r file; do
        printf '  %6d  %s\n' "$(wc -c <"$file")" "${file#"$fixtures"/}"
    done
}

image_digest() {
    docker image inspect --format '{{index .RepoDigests 0}}' "$1" 2>/dev/null || true
}

cleanup
docker network create --internal --subnet "$subnet" "$network" >/dev/null

for version in ${*:-15 16 17 18}; do
    # shellcheck disable=SC2059
    server_image=$(printf "$SERVER_IMAGE" "$version")
    echo "PostgreSQL $version ($server_image)"
    start_server "$server_image"
    # Check, against the server itself, which startup packet layouts it
    # accepts. The tests of the startup parser rely on this.
    in_container "$RECORDER_IMAGE" "$password" python3 /crafted_client.py layouts pg 5432
    capture "$version" 3.0
    if [ "$version" -eq 18 ]; then
        capture "$version" 3.2
    fi
    docker rm --force --volumes "$server" >/dev/null
done

echo "done"
