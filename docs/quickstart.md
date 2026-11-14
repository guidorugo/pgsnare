# Quickstart

This walks through the Compose example in [`examples/compose/`](../examples/compose/): PostgreSQL 18, pgsnare in front of it with two seeded honeytokens, and a webhook receiver that verifies the signature of every event. You read a token through pgsnare and watch the alert arrive.

The commands below are the ones the smoke test [`examples/compose/smoke.sh`](../examples/compose/smoke.sh) runs in CI on every change, with its checks left out. The test requires the alert to reach the receiver less than 2 seconds after the query, and the whole walk to take less than 5 minutes.

## What you need

- Docker with Compose v2.
- The pgsnare image, named by digest. **No release has been published yet**, so there is no public image to pull. Until there is, build the image from [`deploy/Dockerfile`](../deploy/Dockerfile) and push it to a registry you control, then name it by the digest that registry reports. The example refuses an image given by tag.

```sh
cd examples/compose
export PGSNARE_IMAGE=registry.example.com/pgsnare@sha256:<64 hexadecimal digits>
```

Nothing in the example is published on a port of the host, and nothing secret is in the directory. At the first start, the `setup` service makes a certificate authority, the certificates of the database, pgsnare and the receiver, the database password, the webhook's signing key and two random tokens, and gives each service only the files it needs.

## 1. Start it

```sh
docker compose up --detach
docker compose ps pgsnare
```

Wait until `docker compose ps pgsnare` shows the container as `healthy`. The image's own health check runs `pgsnare healthcheck`.

## 2. Check the receiver

```sh
docker compose exec receiver python3 /app/receiver.py check https://receiver:8443/events
```

The receiver must refuse a request without a signature, one signed with another key and one with an old timestamp, and accept a signed one. Every line of the output says `ok`. The receiver follows the four checks of the signature scheme (design document, section 12.3). Use it as a starting point for your own receiver.

## 3. A query that reads no token

```sh
docker compose run --rm client -c "SELECT name FROM customers WHERE id = 1"
```

`client` is psql, connecting to pgsnare with TLS and verifying its certificate. The answer is `Alice Example`, and no alert is raised: pgsnare passes traffic through until a token appears in it.

## 4. A query that reads a token

```sh
docker compose run --rm client -c "SELECT name, email, extract(epoch FROM clock_timestamp()) AS queried_at FROM customers"
```

Carol's email address is a honeytoken. The query gets its answer, because the token's only action is `alert`, and pgsnare raises a `token_hit`. The last column is the database's clock when it ran the query, which the smoke test compares with the time the receiver got the event.

## 5. The alert

```sh
docker compose logs receiver
```

The receiver prints each event it accepted as one JSON line: `received_at`, then the event with `"kind":"token_hit"` and `"token_id":"demo-customer-email"`. The event names the token, not its value. `docker compose logs pgsnare` shows the same event on pgsnare's standard output.

## 6. Clean up

```sh
docker compose down --volumes
```

This removes the containers and the volumes with every key, password and token the example made.

## Going further

- The tokens of this example are random demonstration values made at the first start. Generate your own with `pgsnare token generate`, and plant them where only an intruder would look.
- The example keeps the receiver's signing key in a file and gives pgsnare the receiver's certificate authority through `SSL_CERT_FILE`. With a receiver whose certificate is signed by a public authority, leave `SSL_CERT_FILE` out.
- pgsnare and the database present the same certificate here. With TLS on both legs, SCRAM channel binding works only when the client sees the database's own certificate.
- For Kubernetes, see the chart in [`deploy/chart/pgsnare/`](../deploy/chart/pgsnare/README.md) and the sidecar definitions in [`deploy/sidecar/`](../deploy/sidecar/README.md).
