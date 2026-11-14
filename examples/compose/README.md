# Compose example

PostgreSQL 18, pgsnare with seeded honeytokens, and a webhook receiver that verifies every signature. [`docs/quickstart.md`](../../docs/quickstart.md) walks through it.

| File | What it is |
|---|---|
| `compose.yaml` | The services. pgsnare's image comes from `PGSNARE_IMAGE`, by digest. No port is published. |
| `setup.sh` | Runs once at the first start: makes the certificates, keys, password and tokens, and the SQL that plants the tokens. Nothing secret is committed. |
| `receiver/receiver.py` | The receiver, Python standard library only. `serve` listens with TLS and prints each verified event; `check URL` shows that it refuses unsigned, forged and old requests. |
| `smoke.sh` | The quickstart as a test: from `docker compose up` to a verified `token_hit` in under 5 minutes, less than 2 seconds from the query to the receiver. CI runs it in the `example` job. |

The tokens are random demonstration values. For real use, generate your own with `pgsnare token generate`.
