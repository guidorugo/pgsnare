#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
"""A demonstration receiver for the webhook sink of pgsnare.

It uses the Python standard library only. It accepts a request only after
the four checks of the signature scheme (design document, section 12.3):

1. both headers are there and in their form;
2. the timestamp is within five minutes of the receiver's clock;
3. the HMAC-SHA256 of "timestamp.body" under the shared key matches the
   signature, compared in constant time;
4. the event_id of the body was not accepted before (a repetition is
   answered 200 and not printed again).

Every accepted event is printed to standard output as one JSON line,
{"received_at": <seconds since 1970>, "event": {...}}. A refusal prints one
fixed line to standard error and nothing of the request.

    receiver.py serve   listen with TLS (RECEIVER_LISTEN, RECEIVER_CERT,
                        RECEIVER_KEY, RECEIVER_HMAC_KEY_FILE)
    receiver.py check URL
                        send requests to a running receiver that it must
                        refuse, and one it must accept; exit 0 when it
                        answered each as it should (RECEIVER_CA,
                        RECEIVER_HMAC_KEY_FILE)

This is an example, not a product: it keeps nothing, and it has no
authentication of its own beyond the signature.
"""

import hashlib
import hmac
import http.client
import http.server
import json
import os
import socket
import ssl
import sys
import threading
import time
import urllib.parse
import uuid

TOLERANCE_SECONDS = 300
MAX_BODY_BYTES = 256 * 1024
MAX_REMEMBERED = 10_000
MAX_CONNECTIONS = 32
SOCKET_TIMEOUT_SECONDS = 10
MIN_KEY_BYTES = 32
HEX = frozenset("0123456789abcdef")


def read_key(path):
    with open(path, "rb") as handle:
        key = handle.read(4097)
    if len(key) > 4096:
        sys.exit("receiver: the key file is longer than 4096 bytes")
    if key.endswith(b"\n"):
        key = key[:-1]
    if len(key) < MIN_KEY_BYTES:
        sys.exit("receiver: the key must be at least 32 bytes")
    return key


def sign(key, timestamp, body):
    return "v1=" + hmac.new(key, timestamp.encode("ascii") + b"." + body, hashlib.sha256).hexdigest()


class Verifier:
    """The four checks. Remembers at most MAX_REMEMBERED event ids, each
    for TOLERANCE_SECONDS; when it is full it answers "not now"."""

    def __init__(self, key):
        self._key = key
        self._seen = {}
        self._lock = threading.Lock()

    def check(self, timestamp, signature, body, now):
        """Returns (status, reason, event)."""
        if timestamp is None or signature is None:
            return 401, "a header is missing", None
        if not (0 < len(timestamp) <= 20 and timestamp.isascii() and timestamp.isdigit()):
            return 401, "the timestamp is not a decimal number", None
        if len(timestamp) > 1 and timestamp.startswith("0"):
            return 401, "the timestamp is not a decimal number", None
        if not (len(signature) == 67 and signature.startswith("v1=") and set(signature[3:]) <= HEX):
            return 401, "the signature is not in its form", None
        if abs(now - int(timestamp)) > TOLERANCE_SECONDS:
            return 401, "the timestamp is too far from this clock", None
        if not hmac.compare_digest(sign(self._key, timestamp, body), signature):
            return 401, "the signature does not match", None
        try:
            event = json.loads(body)
            event_id = event["event_id"]
        except (ValueError, KeyError, TypeError):
            return 400, "the body is not an event", None
        if not isinstance(event_id, str):
            return 400, "the body is not an event", None
        with self._lock:
            for old in [k for k, seen in self._seen.items() if now - seen > TOLERANCE_SECONDS]:
                del self._seen[old]
            if event_id in self._seen:
                return 200, "a repetition", None
            if len(self._seen) >= MAX_REMEMBERED:
                return 503, "too many events at once", None
            self._seen[event_id] = now
        return 204, None, event


class Handler(http.server.BaseHTTPRequestHandler):
    protocol_version = "HTTP/1.1"
    timeout = SOCKET_TIMEOUT_SECONDS
    server_version = "receiver"
    sys_version = ""

    def setup(self):
        # The TLS handshake runs here, in the thread of this connection,
        # under the timeout, and not in the loop that accepts.
        self.request.settimeout(SOCKET_TIMEOUT_SECONDS)
        self.request.do_handshake()
        super().setup()

    def log_message(self, *args):
        pass

    def answer(self, status):
        self.send_response(status)
        self.send_header("content-length", "0")
        self.send_header("connection", "close")
        self.end_headers()
        self.close_connection = True

    def do_POST(self):
        if urllib.parse.urlsplit(self.path).path != "/events":
            return self.answer(404)
        length = self.headers.get("content-length", "")
        if not (length.isascii() and length.isdigit() and 0 < len(length) <= 7):
            return self.answer(411)
        if int(length) > MAX_BODY_BYTES:
            return self.answer(413)
        body = self.rfile.read(int(length))
        if len(body) != int(length):
            return self.answer(400)
        status, reason, event = self.server.verifier.check(
            self.headers.get("x-pgsnare-timestamp"),
            self.headers.get("x-pgsnare-signature"),
            body,
            int(time.time()),
        )
        if event is not None:
            line = json.dumps({"received_at": time.time(), "event": event}, separators=(",", ":"))
            print(line, flush=True)
        elif status >= 400:
            print(f"receiver: refused a request: {reason}", file=sys.stderr, flush=True)
        self.answer(status)


class Server(http.server.ThreadingHTTPServer):
    daemon_threads = True
    request_queue_size = MAX_CONNECTIONS

    def __init__(self, address, verifier, context):
        self.verifier = verifier
        self._slots = threading.BoundedSemaphore(MAX_CONNECTIONS)
        super().__init__(address, Handler)
        self.socket = context.wrap_socket(self.socket, server_side=True, do_handshake_on_connect=False)

    def process_request(self, request, client_address):
        # At most MAX_CONNECTIONS at a time; one more is closed at once.
        if not self._slots.acquire(blocking=False):
            self.shutdown_request(request)
            return
        try:
            super().process_request(request, client_address)
        except BaseException:
            self._slots.release()
            raise

    def process_request_thread(self, request, client_address):
        try:
            super().process_request_thread(request, client_address)
        finally:
            self._slots.release()

    def handle_error(self, request, client_address):
        print("receiver: a connection failed", file=sys.stderr, flush=True)


def serve():
    host, _, port = os.environ.get("RECEIVER_LISTEN", "0.0.0.0:8443").rpartition(":")
    context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    context.minimum_version = ssl.TLSVersion.TLSv1_2
    context.load_cert_chain(os.environ["RECEIVER_CERT"], os.environ["RECEIVER_KEY"])
    verifier = Verifier(read_key(os.environ["RECEIVER_HMAC_KEY_FILE"]))
    server = Server((host, int(port)), verifier, context)
    print(f"receiver: listening on {host}:{port}", file=sys.stderr, flush=True)
    server.serve_forever()


def post(url, context, headers, body):
    parts = urllib.parse.urlsplit(url)
    connection = http.client.HTTPSConnection(parts.hostname, parts.port or 443, timeout=10, context=context)
    try:
        connection.request("POST", parts.path or "/", body=body, headers=headers)
        return connection.getresponse().status
    finally:
        connection.close()


def check(url):
    """Sends what the receiver must refuse, then what it must accept."""
    context = ssl.create_default_context(cafile=os.environ["RECEIVER_CA"])
    key = read_key(os.environ["RECEIVER_HMAC_KEY_FILE"])
    body = json.dumps({"event_id": str(uuid.uuid4()), "kind": "receiver_check"}).encode()
    now = str(int(time.time()))
    stale = str(int(time.time()) - 3600)
    cases = [
        ("no signature", {}, 401),
        ("a signature under another key", {"x-pgsnare-timestamp": now, "x-pgsnare-signature": sign(os.urandom(32), now, body)}, 401),
        ("an old timestamp", {"x-pgsnare-timestamp": stale, "x-pgsnare-signature": sign(key, stale, body)}, 401),
        ("a signed event", {"x-pgsnare-timestamp": now, "x-pgsnare-signature": sign(key, now, body)}, 204),
        ("the same event again", {"x-pgsnare-timestamp": now, "x-pgsnare-signature": sign(key, now, body)}, 200),
    ]
    failed = 0
    for name, headers, expected in cases:
        headers = dict(headers, **{"content-type": "application/json"})
        try:
            status = post(url, context, headers, body)
        except (OSError, http.client.HTTPException) as error:
            status = f"no answer ({type(error).__name__})"
        verdict = "ok" if status == expected else "FAILED"
        failed += status != expected
        print(f"receiver check: {verdict}: {name}: {status}, expected {expected}", file=sys.stderr)
    return 1 if failed else 0


def main(arguments):
    if arguments == ["serve"]:
        serve()
        return 0
    if len(arguments) == 2 and arguments[0] == "check":
        return check(arguments[1])
    print("usage: receiver.py serve | receiver.py check URL", file=sys.stderr)
    return 2


if __name__ == "__main__":
    try:
        sys.exit(main(sys.argv[1:]))
    except KeyboardInterrupt:
        sys.exit(130)
    except socket.error as error:
        sys.exit(f"receiver: {type(error).__name__}")
