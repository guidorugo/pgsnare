#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
"""Records PostgreSQL wire traffic for the golden-byte fixtures.

The recorder listens on one port per scenario and relays every connection
to a real server. It writes the bytes of each direction, exactly as they
passed, to two files in the output directory:

    <scenario>.client.bin    what the client sent
    <scenario>.server.bin    what the server sent

A scenario that opens more than one connection gets a number on the later
ones: <scenario>.2.client.bin and so on, in the order the connections were
accepted.

The connections must not use TLS, because the recorder does not decrypt.

Usage:
    recorder.py --upstream HOST:PORT --out DIR PORT=SCENARIO [PORT=SCENARIO ...]
"""

import argparse
import os
import socket
import threading


def relay(source, sink, path):
    """Copies bytes from source to sink until source ends, recording them."""
    with open(path, "wb", buffering=0) as record:
        while True:
            try:
                data = source.recv(65536)
            except OSError:
                break
            if not data:
                break
            record.write(data)
            try:
                sink.sendall(data)
            except OSError:
                break
    try:
        sink.shutdown(socket.SHUT_WR)
    except OSError:
        pass


def handle(client, upstream, stem):
    """Relays one connection in both directions, then closes it."""
    try:
        server = socket.create_connection(upstream)
    except OSError:
        client.close()
        raise
    for connection in (client, server):
        connection.setsockopt(socket.IPPROTO_TCP, socket.TCP_NODELAY, 1)
    directions = [
        threading.Thread(target=relay, args=(client, server, stem + ".client.bin")),
        threading.Thread(target=relay, args=(server, client, stem + ".server.bin")),
    ]
    for direction in directions:
        direction.start()
    for direction in directions:
        direction.join()
    client.close()
    server.close()


def serve(listener, scenario, upstream, out_dir):
    """Accepts the connections of one scenario."""
    count = 0
    while True:
        client, _ = listener.accept()
        count += 1
        name = scenario if count == 1 else "%s.%d" % (scenario, count)
        stem = os.path.join(out_dir, name)
        threading.Thread(target=handle, args=(client, upstream, stem), daemon=True).start()


def main():
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("--upstream", required=True, help="the real server, as HOST:PORT")
    parser.add_argument("--out", required=True, help="the directory to write captures to")
    parser.add_argument("ports", nargs="+", metavar="PORT=SCENARIO")
    arguments = parser.parse_args()

    host, _, port = arguments.upstream.rpartition(":")
    upstream = (host, int(port))

    threads = []
    for mapping in arguments.ports:
        port, _, scenario = mapping.partition("=")
        listener = socket.create_server(("", int(port)))
        thread = threading.Thread(
            target=serve, args=(listener, scenario, upstream, arguments.out), daemon=True
        )
        thread.start()
        threads.append(thread)
    print("recorder ready", flush=True)
    for thread in threads:
        thread.join()


if __name__ == "__main__":
    main()
