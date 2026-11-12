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

    crafted_client.py layouts HOST PORT
        Sends startup messages with unusual parameter layouts and checks
        that the server accepts and rejects them as LAYOUTS below says. The
        startup parser of pgsnare-proto is tested against a port of the
        server's own parsing loop, and this check ties that port to what
        real servers do. Nothing is recorded: run it against the server
        directly.
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


# The bytes after the protocol version of a startup message, and whether a
# server accepts their layout. PostgreSQL wants pairs of a name and a value
# followed by one more byte that ends the packet. It does not look at that
# last byte, so a packet whose last byte is not zero passes. pgsnare-proto
# is stricter there and wants a zero. tests/properties.rs holds the same
# list.
LAYOUTS = [
    (b"user\0app_plain\0database\0appdb\0\0", True),
    # The last byte is not zero.
    (b"user\0app_plain\0database\0appdb\0x", True),
    # No terminator.
    (b"user\0app_plain\0database\0appdb\0", False),
    # A byte after the terminator.
    (b"user\0app_plain\0database\0appdb\0\0x", False),
    (b"user\0app_plain\0database\0appdb\0\0\0", False),
    # A name without a value.
    (b"user\0app_plain\0database\0", False),
    # An empty value, then the end of the packet.
    (b"user\0app_plain\0options\0\0", False),
    # A value that is not terminated.
    (b"user\0app_plain\0database\0appdb", False),
    # A terminator first.
    (b"\0user\0app_plain\0\0", False),
    # Nothing after the version.
    (b"", False),
    # No parameters: the layout passes and the login fails for want of a user.
    (b"\0", True),
    (b"x", True),
]

LAYOUT_ERROR = b"invalid startup packet layout"


def layout_accepted(host, port, region):
    """Sends one startup message and reports whether its layout passed."""
    body = struct.pack("!HH", 3, 0) + region
    with socket.create_connection((host, port)) as connection:
        connection.sendall(struct.pack("!I", len(body) + 4) + body)
        kind, answer = read_message(connection)
    if kind == b"R":
        return True
    if kind == b"E":
        return LAYOUT_ERROR not in answer
    raise RuntimeError("unexpected answer of type %r" % kind)


def layouts(host, port):
    wrong = 0
    for region, expected in LAYOUTS:
        accepted = layout_accepted(host, port, region)
        print("%-8s %r" % ("accepted" if accepted else "rejected", region))
        if accepted != expected:
            wrong += 1
            print("  expected the opposite", file=sys.stderr)
    if wrong:
        raise SystemExit("%d layouts were judged differently than expected" % wrong)


def main():
    mode = sys.argv[1]
    host, port = sys.argv[2], int(sys.argv[3])
    if mode == "negotiate":
        negotiate(host, port)
    elif mode == "binary":
        binary(host, port, sys.argv[4])
    elif mode == "layouts":
        layouts(host, port)
    else:
        raise SystemExit("unknown mode: " + mode)


if __name__ == "__main__":
    main()
