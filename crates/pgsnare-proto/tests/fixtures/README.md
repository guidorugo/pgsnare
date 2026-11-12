# Golden-byte fixtures

These files hold PostgreSQL wire traffic captured from real servers. `tests/golden.rs` reads them to check that `pgsnare-proto` frames and parses what real clients and servers send, and that its encoders reproduce it byte for byte.

**Everything in them is synthetic.** The servers were throwaway containers, the database held three invented rows, and the one password in use (`not-a-secret`) existed only inside those containers. Names and addresses come from the ranges reserved for documentation (`example.com`, `192.0.2.0/24`).

## Layout

| Directory | Server | Protocol the client asked for |
|---|---|---|
| `pg15-3.0` | PostgreSQL 15 | 3.0 |
| `pg16-3.0` | PostgreSQL 16 | 3.0 |
| `pg17-3.0` | PostgreSQL 17 | 3.0 |
| `pg18-3.0` | PostgreSQL 18 | 3.0 |
| `pg18-3.2` | PostgreSQL 18 | 3.2 |

The client is always psql and libpq 18, because protocol 3.2 needs it. Each directory has a `MANIFEST.txt` with the exact server and client versions and the image digests.

One connection gives two files:

- `<scenario>.client.bin`: every byte the client sent
- `<scenario>.server.bin`: every byte the server sent

A scenario with a second connection names it `<scenario>.2`.

## Scenarios

| Scenario | What it shows |
|---|---|
| `simple` | SCRAM login, simple queries, command tags, errors, a notice, a parameter change, a notification |
| `extended` | `Parse`, `Bind`, `Describe`, `Execute`, `Close`, an error, and a pipeline |
| `copy` | COPY out in text, CSV and binary form, COPY in, and a COPY the server rejects |
| `auth-md5`, `auth-cleartext` | Logins with the MD5 and the cleartext password method |
| `auth-failed` | A login with a wrong password |
| `ssl-refused` | `SSLRequest`, declined by a server without TLS, then a session in the clear |
| `cancel`, `cancel.2` | A query that is cancelled, and the `CancelRequest` on its own connection |
| `replication` | Logical replication in COPY BOTH mode, driven by `pg_recvlogical` |
| `negotiate` | Servers older than 18 only: libpq asks for 3.2 and gets `NegotiateProtocolVersion` |
| `crafted-negotiate` | A startup message asking for protocol 3.99 with an unknown protocol option |
| `crafted-binary` | An extended query with binary parameters and binary results |
| `direct-tls` | `pg18-3.0` only: the first flight of a direct TLS handshake |

In the two `crafted-` scenarios the client side was written by `capture/crafted_client.py`, because libpq cannot be made to send those messages. The server side is what a real server answered.

The fuzz targets `framer_client`, `framer_server` and `startup` use `pg18-3.0` as their seed corpus, through links in `fuzz/seeds/`.

## What is not here

- Sessions inside TLS. The recorder does not decrypt, so there is no captured `SCRAM-SHA-256-PLUS` offer.
- `GSSENCRequest` and the Kerberos, GSSAPI and SSPI authentication messages, which need a Kerberos setup.

Unit tests and fuzzing cover those.

## Capturing again

```sh
capture/capture.sh
```

The script needs only Docker. It starts each server and a recording relay in containers on a private network, publishes no port, and removes everything when it ends. Its header describes the options.

A new capture differs from the last in every random value: salts, nonces, cancel keys and process ids. The tests do not depend on those. They do depend on the scenarios, so a change to a scenario file may need a change in `tests/golden.rs`.
