#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
"""Tests of receiver.py, with the Python standard library only.

    docker compose exec -T receiver python3 /app/test_receiver.py

They need the files of the example that the receiver itself runs with:
RECEIVER_CERT and RECEIVER_KEY for a server on the loopback interface, and
RECEIVER_CA to speak to it. The certificate names the host `receiver`.

What is tested:

- an event is accepted once for as long as its request passes the check of
  the timestamp, whatever the difference between the two clocks;
- what is remembered is forgotten again, and has an upper limit;
- a request that arrives slowly loses its connection when the time of a
  request is over, in the head and in the body, and the receiver goes on
  answering.
"""

import json
import os
import select
import socket
import ssl
import sys
import threading
import time
import unittest

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import receiver  # noqa: E402

KEY = b"k" * 32
NOW = 1_800_000_000
TOLERANCE = receiver.TOLERANCE_SECONDS


def request(verifier, timestamp, now, event_id="one"):
    """The status of a signed request for the event, read at `now`."""
    body = json.dumps({"event_id": event_id}).encode()
    stamp = str(timestamp)
    return verifier.check(stamp, receiver.sign(KEY, stamp, body), body, now)[0]


class Repetition(unittest.TestCase):
    def test_an_event_is_accepted_once_whatever_the_clocks(self):
        for ahead in (-TOLERANCE, -1, 0, 1, TOLERANCE // 2, TOLERANCE - 1, TOLERANCE):
            verifier = receiver.Verifier(KEY)
            stamp = NOW + ahead
            self.assertEqual(request(verifier, stamp, NOW), 204, f"sender ahead by {ahead}")
            for later in range(NOW, NOW + 2 * TOLERANCE + 3):
                expected = 200 if later - stamp <= TOLERANCE else 401
                self.assertEqual(
                    request(verifier, stamp, later), expected,
                    f"sender ahead by {ahead}, the same request {later - NOW} s later",
                )

        # The case in numbers: sent by a clock five minutes ahead, and the
        # same request again a second after five minutes have passed here.
        verifier = receiver.Verifier(KEY)
        self.assertEqual(request(verifier, NOW + TOLERANCE, NOW), 204)
        self.assertEqual(request(verifier, NOW + TOLERANCE, NOW + TOLERANCE + 1), 200)

    def test_an_event_signed_again_is_a_repetition(self):
        verifier = receiver.Verifier(KEY)
        self.assertEqual(request(verifier, NOW - 200, NOW), 204)
        # The first timestamp is out of tolerance by now; the event is not.
        self.assertEqual(request(verifier, NOW + 250, NOW + 250), 200)
        # And the later timestamp keeps it for its own time.
        self.assertEqual(request(verifier, NOW + 250, NOW + 250 + TOLERANCE), 200)

    def test_what_is_remembered_is_forgotten(self):
        verifier = receiver.Verifier(KEY)
        for number in range(50):
            self.assertEqual(request(verifier, NOW + number, NOW, f"event-{number}"), 204)
        self.assertEqual(len(verifier._seen), 50)
        self.assertEqual(request(verifier, NOW + 2 * TOLERANCE, NOW + 2 * TOLERANCE, "late"), 204)
        self.assertEqual(list(verifier._seen), ["late"])

    def test_what_is_remembered_has_a_limit(self):
        verifier = receiver.Verifier(KEY)
        limit = receiver.MAX_REMEMBERED
        receiver.MAX_REMEMBERED = 3
        try:
            for number in range(3):
                self.assertEqual(request(verifier, NOW, NOW, f"event-{number}"), 204)
            self.assertEqual(request(verifier, NOW, NOW, "one too many"), 503)
            self.assertEqual(request(verifier, NOW, NOW, "event-0"), 200)
            self.assertEqual(len(verifier._seen), 3)
        finally:
            receiver.MAX_REMEMBERED = limit


class SlowRequest(unittest.TestCase):
    """A server of the receiver on the loopback interface, with two
    seconds for a request."""

    SECONDS = 2
    STEP = 0.25

    def setUp(self):
        context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        context.load_cert_chain(os.environ["RECEIVER_CERT"], os.environ["RECEIVER_KEY"])
        self.server = receiver.Server(("127.0.0.1", 0), receiver.Verifier(KEY), context)
        self.port = self.server.server_address[1]
        self.before = receiver.REQUEST_TIMEOUT_SECONDS
        receiver.REQUEST_TIMEOUT_SECONDS = self.SECONDS
        self.thread = threading.Thread(target=self.server.serve_forever, daemon=True)
        self.thread.start()
        self.client = ssl.create_default_context(cafile=os.environ["RECEIVER_CA"])

    def tearDown(self):
        receiver.REQUEST_TIMEOUT_SECONDS = self.before
        self.server.shutdown()
        self.server.server_close()
        self.thread.join(5)

    def connect(self):
        plain = socket.create_connection(("127.0.0.1", self.port), timeout=5)
        return self.client.wrap_socket(plain, server_hostname="receiver")

    def closed_after(self, connection, first, rest):
        """Sends `first`, then `rest` a byte every STEP seconds, which is
        far quicker than the timeout of one read. Returns after how many
        seconds the receiver closed the connection, or None when it was
        still open at three times the time of a request."""
        started = time.monotonic()
        connection.settimeout(self.STEP)
        connection.sendall(first)
        for byte in rest:
            elapsed = time.monotonic() - started
            if elapsed > 3 * self.SECONDS:
                return None
            readable, _, _ = select.select([connection], [], [], self.STEP)
            try:
                if readable and connection.recv(1) == b"":
                    return time.monotonic() - started
                connection.sendall(bytes([byte]))
            except TimeoutError:
                continue
            except (ssl.SSLError, OSError):
                return time.monotonic() - started
        return None

    def assert_closed_in_time(self, seconds):
        self.assertIsNotNone(seconds, "the connection was still open long after the time of a request")
        self.assertGreaterEqual(seconds, self.SECONDS - self.STEP)
        self.assertLess(seconds, self.SECONDS + 2)

    def signed(self, event_id):
        body = json.dumps({"event_id": event_id}).encode()
        stamp = str(int(time.time()))
        head = (
            "POST /events HTTP/1.1\r\nhost: receiver\r\n"
            f"content-length: {len(body)}\r\n"
            f"x-pgsnare-timestamp: {stamp}\r\n"
            f"x-pgsnare-signature: {receiver.sign(KEY, stamp, body)}\r\n\r\n"
        ).encode()
        return head, body

    def answer(self, head, body):
        with self.connect() as connection:
            connection.sendall(head + body)
            return connection.recv(64).split(b"\r\n")[0]

    def test_a_slow_head_loses_its_connection(self):
        with self.connect() as connection:
            seconds = self.closed_after(connection, b"POST /events HTTP/1.1\r\n", b"x-slow: " + b"a" * 4000)
        self.assert_closed_in_time(seconds)
        head, body = self.signed("after a slow head")
        self.assertEqual(self.answer(head, body), b"HTTP/1.1 204 No Content")

    def test_a_slow_body_loses_its_connection(self):
        head, body = self.signed("slow")
        with self.connect() as connection:
            seconds = self.closed_after(connection, head.replace(
                f"content-length: {len(body)}".encode(), b"content-length: 4000"), b"a" * 4000)
        self.assert_closed_in_time(seconds)
        head, body = self.signed("after a slow body")
        self.assertEqual(self.answer(head, body), b"HTTP/1.1 204 No Content")

    def test_a_request_in_time_is_answered(self):
        head, body = self.signed("in time")
        with self.connect() as connection:
            # Slowly, and still well within the time of a request.
            connection.sendall(head)
            for byte in body:
                time.sleep(0.01)
                connection.sendall(bytes([byte]))
            self.assertEqual(connection.recv(64).split(b"\r\n")[0], b"HTTP/1.1 204 No Content")


if __name__ == "__main__":
    unittest.main(verbosity=2)
