# Hardening guide

pgsnare sits inline in front of a production database, sees all its traffic and may hold the database's TLS key. These are the settings and habits that keep it a safe thing to have there. The checklist at the end is the short form.

`pgsnare config check` reports many of these as warnings: run it on every configuration before you deploy it.

## Make it the only way in

pgsnare sees only what passes through it.

- Close the database to every address except pgsnare's. A client that connects to the database directly is not inspected.
- In Kubernetes, keep the NetworkPolicy of the chart, and use a network plugin that enforces it. List in `clients` only the pods that need the database.
- Prefer the central proxy to the sidecar where bypass matters. A pod has one network identity, so an application with a sidecar can still reach the database without it.
- Do not put a load balancer that hides client addresses in front of pgsnare while you keep exemptions by `client_cidr`: the address pgsnare sees would be the balancer's.

## Run it confined

- Run as a non-root user, with every capability dropped, a read-only root filesystem and `no-new-privileges`. The image's user is `65532`, and the chart and the examples start it this way.
- Name the image by digest, never by tag. Verify a release before you run it ([Verifying a release](verifying-a-release.md)).
- The image's base has a shell and a package manager. That was the owner's choice of base. What keeps them harmless is the confinement above: the process cannot write to its filesystem, cannot gain privileges and is not root. Do not weaken it, for example by mounting a writable volume over a binary directory or running the container as root.
- Give the pod or container requests and limits. pgsnare starts as many worker threads as the CPU limit allows.
- In Kubernetes, mount no service-account token. The chart does not.

## Keep the listeners where they are

- The admin (`9641`) and metrics (`9642`) listeners speak plain HTTP and ask for no login. They bind to loopback by default and the chart has no value to move the admin listener. Keep them there. Beyond loopback, whoever can reach the address sees health and metrics. `config check` warns, and so does the log at startup.
- Expose metrics to a scraper only through a NetworkPolicy that names it (`metrics.scrapers`), and only where the cluster enforces policies.
- The image's health check and the chart's probes use `pgsnare healthcheck`, which needs no exposed port and reads no file.

## TLS

- Use `upstream_tls.mode: verify-full` to the database. `prefer` and `require` encrypt and verify nothing, and pgsnare logs that at startup.
- Choose the TLS setup deliberately: [Deploying pgsnare](deployment.md#tls-which-setup-to-choose). The preferred setup gives pgsnare the database's own certificate and key; guard that key like the database's.
- TLS 1.2 is the floor. Set `min_version: tls1.3` on a leg where all peers support it.
- Webhooks must be HTTPS with a certificate verified against the system's certificate store, and follow no redirect. Plain HTTP needs `allow_insecure_http`; do not set it outside a test.
- `SSL_CERT_FILE` replaces the authorities of the image for webhooks. Use it for a receiver signed by a private authority, and leave it out for a publicly signed one.

## Secrets and files

- Never write a secret in the configuration. Name a file (`url_file`, `hmac_secret_file`) or an environment variable; files are better, because an environment variable is visible in more places.
- pgsnare refuses a configuration, token file or key that other users can read: owned by its user with mode `0600` or less, or by root with `0640` or less. In Kubernetes mount secrets as whole volumes with `defaultMode: 0440` and an `fsGroup`; the chart does. Never use `subPath` for a secret: the cluster never updates it.
- **Signing keys.** A webhook signing key is at least 32 random bytes, for example `head -c 32 /dev/urandom | base64`. Use a different key for each endpoint, so that a receiver that leaks its key exposes one endpoint only. `config check` warns about a shorter key.
- **A `file` sink** belongs in a directory that nobody else can write, and the file should not be readable by others: events name tokens, sessions and statements. The chart offers no `file` sink.
- Keep the token files as secret as the database: they hold the values that identify a thief. Generate them with `pgsnare token generate`, put them in a Secret or a root-owned file, and keep them out of the repository and of backups that more people can read than the database itself.
- A token value is never printed by any command, log, event or metric. Do not defeat that by pasting values into tickets or chat. `pgsnare token test` reads a value from standard input for this reason.

## Events and statement redaction

- Set `events.query_redaction: fingerprint` in production. It is the default. An event then carries the SHA-256 hash of the statement as sent, and no text.
- **`full` is a debugging mode.** It puts each statement into events as it was sent, cut at 4,096 bytes. Token values are still removed, but **a password written in a statement is shown**, as is any other secret in it, because the redaction layer does not look for passwords. Anyone who can read the sinks or the log then reads them. Use `full` briefly and on data you can afford to show.
- `none` shows no statement.
- Webhook receivers must check the signature, the timestamp and the event id of every request. The Compose example's receiver ([`examples/compose/receiver/receiver.py`](../examples/compose/receiver/receiver.py)) shows the checks, and design document section 12.3 states them. It is a demonstration, not a product.
- Alert on `pgsnare_reload_failures_total` increasing (a token change that did not load) and watch that events are delivered: a full queue loses events and counts them.

## Limits to set

- `listeners[].max_connections` and `login_timeout` bound what an unauthenticated client can hold open.
- `actions.tarpit.max_sessions` is counted for each process. **Keep it, times the number of replicas, below the connections the database has to spare**, or a flood of flagged sessions held by the tarpit can use up the database's connection slots. A session past the cap is killed.
- Keep `actions.tarpit.max_duration` short enough that held sessions do not accumulate.
- `inspection.max_buffered_frame` (1 MiB by default) sets how large a message is scanned whole. A larger message is scanned as a stream, and bytes before the token inside it can reach the client even with `kill`. Raise it only if your rows are larger and memory allows.
- Keep `inspection.on_error: fail_closed` (the default). `fail_open` turns a session that pgsnare cannot follow into an uninspected tunnel; it raises an `inspection_bypassed` event, but the session is not inspected.

## Exemptions

- An exemption lets a user read tokens without triggering a response (the hit is counted). Use it for the nightly backup and for replication, with both a user and an address range, so that the user name alone is not enough: `{ db_user: backup, client_cidr: 192.0.2.5/32 }`.
- A user name counts only after the database has accepted the login. `application_name` and other client fields never exempt. Keep exemptions few and review them.
- An address exemption trusts the address pgsnare sees. Do not use it where something rewrites client addresses.

## Honeytokens

- Generate tokens yourself; never reuse a value from an example.
- A honeytoken used as a password is not detected: login messages are not scanned. See [Honeytoken placement](honeytoken-placement.md) and the [threat model](threat-model.md).

## Operations

- Run at least two replicas behind the Service, so that a node drain does not interrupt the service. The chart's PodDisruptionBudget lets one pod go at a time.
- Give `terminationGracePeriodSeconds` (Kubernetes) or the stop timeout (containers) more than the shutdown grace period plus two seconds.
- Update the image regularly. The repository scans the image for known vulnerabilities on every build and nightly, and checks the dependencies for advisories and licences.
- Review who may reach the sinks and who can change the Secrets; a person who can change the token Secret can switch detection off.

## Checklist

- [ ] The database accepts connections only from pgsnare.
- [ ] The image is named by digest and was verified.
- [ ] Non-root, no capabilities, read-only root filesystem, `no-new-privileges`.
- [ ] Admin and metrics listeners on loopback; metrics scrapers listed, if any.
- [ ] `upstream_tls.mode: verify-full`; a deliberate TLS setup.
- [ ] Tokens generated for this installation; token files mode `0600` or `0440`.
- [ ] Signing keys of 32 or more random bytes, one for each endpoint; webhooks over HTTPS.
- [ ] `events.query_redaction: fingerprint`.
- [ ] `tarpit.max_sessions` times the replicas below the database's spare connections.
- [ ] `inspection.on_error: fail_closed`.
- [ ] `pgsnare config check` is clean.
- [ ] A test read of a token raises an alert at your receiver.
