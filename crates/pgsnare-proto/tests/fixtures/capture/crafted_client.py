#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
"""Sends hand-built protocol messages that libpq cannot be made to send.

The client side of these captures is written by this script, not by a real
client. The server side is what a real server answered.

Usage:
    crafted_client.py negotiate HOST PORT
        Sends a StartupMessage that asks for protocol 3.99 and carries a
        protocol option no server knows. The server answers with
        NegotiateProtocolVersion and an authentication request. The script
        then closes the connection without logging in.

    crafted_client.py binary HOST PORT PASSWORD
        Logs in with a cleartext password, then runs one extended query
        with a binary parameter, a text parameter, a NULL parameter and
        binary results.
"""

import socket
import struct
import sys

USER = b"app_plain"
DATABASE = b"appdb"


def startup(major, minor, parameters):
    body = struct.pack("!HH", major, minor)
    for name, value in parameters:
        body += name + b"\0" + value + b"\0"
    body += b"\0"
    return struct.pack("!I", len(body) + 4) + body


def message(kind, body=b""):
    return kind + struct.pack("!I", len(body) + 4) + body


def read_exact(connection, count):
    data = b""
    while len(data) < count:
        part = connection.recv(count - len(data))
        if not part:
            raise EOFError("the server closed the connection")
        data += part
    return data


def read_message(connection):
    header = read_exact(connection, 5)
    (length,) = struct.unpack("!I", header[1:])
    return header[:1], read_exact(connection, length - 4)


def read_until(connection, kind):
    """Reads messages up to and including the first of the given kind."""
    while True:
        found, body = read_message(connection)
        if found == b"E":
            raise RuntimeError("the server reported an error")
        if found == kind:
            return body


def negotiate(host, port):
    with socket.create_connection((host, port)) as connection:
        connection.sendall(
            startup(
                3,
                99,
                [
                    (b"user", USER),
                    (b"database", DATABASE),
                    (b"_pq_.fixture_option", b"on"),
                ],
            )
        )
        # NegotiateProtocolVersion, then the request for the password.
        read_until(connection, b"R")


def binary(host, port, password):
    with socket.create_connection((host, port)) as connection:
        connection.sendall(startup(3, 0, [(b"user", USER), (b"database", DATABASE)]))
        request = read_until(connection, b"R")
        if struct.unpack("!I", request[:4])[0] != 3:
            raise RuntimeError("expected a request for a cleartext password")
        connection.sendall(message(b"p", password.encode() + b"\0"))
        read_until(connection, b"Z")

        query = b"SELECT $1::int4 + 1 AS n, $2::text AS t, $3::int8 AS missing, true AS flag"
        parse = b"\0" + query + b"\0" + struct.pack("!H", 0)
        bind = (
            b"\0\0"
            # Parameter formats: binary, text, text.
            + struct.pack("!HHHH", 3, 1, 0, 0)
            # Parameters: the int4 41 in binary, a text value, NULL.
            + struct.pack("!H", 3)
            + struct.pack("!i", 4)
            + struct.pack("!i", 41)
            + struct.pack("!i", 9)
            + b"synthetic"
            + struct.pack("!i", -1)
            # Result formats: binary for every column.
            + struct.pack("!HH", 1, 1)
        )
        describe = b"P\0"
        execute = b"\0" + struct.pack("!i", 0)
        connection.sendall(
            message(b"P", parse)
            + message(b"B", bind)
            + message(b"D", describe)
            + message(b"E", execute)
            + message(b"S")
        )
        read_until(connection, b"Z")
        connection.sendall(message(b"X"))


def main():
    mode = sys.argv[1]
    host, port = sys.argv[2], int(sys.argv[3])
    if mode == "negotiate":
        negotiate(host, port)
    elif mode == "binary":
        binary(host, port, sys.argv[4])
    else:
        raise SystemExit("unknown mode: " + mode)


if __name__ == "__main__":
    main()
