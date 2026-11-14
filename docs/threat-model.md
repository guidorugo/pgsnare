# Threat model and known gaps

pgsnare sits inline in front of production databases, sees all traffic and may hold the database's TLS key. It is a target in its own right, so this page says what it defends against, what it does not, and which gaps are known. The binding version of the requirements is [section 15 of the design document](high-level-design.md#15-security-design); this page restates it for the reader who deploys pgsnare.

**This model has not had the review that the design document asks for before a release** ([section 15.7](high-level-design.md#157-repository-and-process)). Treat it as the written model, not as an audited one.

## What pgsnare is for

Data theft is often found late. pgsnare watches the traffic between applications and PostgreSQL for **honeytokens**: planted values that no legitimate code reads. When one appears in a result, a COPY stream, an error, a notification or a client message, someone is reading data they should not, and pgsnare responds as configured: alert, kill, tarpit or fake data.

It protects the **detection of data leaving the database through a connection that passes through it**. It is not a firewall, a database user manager or an encryption layer, and it replaces none of them.

## Assets

- The honeytoken values and the token files (they say what to avoid touching).
- The database's TLS key, when pgsnare is given it (the preferred TLS setup).
- The signing keys of the webhooks, and the webhook addresses.
- The integrity of detection: that an alert is raised when it should be.
- The availability of the database path: pgsnare is inline, so a fault in it is a fault in the service.

## Trust boundaries

| Boundary | Trust |
|---|---|
| Client to pgsnare | None. A client may be hostile, and may be the attacker pgsnare exists to catch. |
| pgsnare to the database | The database is trusted to speak the protocol correctly, but malformed server messages must not harm pgsnare. |
| pgsnare to a sink | A sink is trusted to receive events, over a verified channel. Its failures must not stop traffic. |
| The host or pod | The operating system and the orchestrator are trusted. **An attacker with root on the host is out of scope.** |

## Adversaries and what must hold

| Adversary | What must hold |
|---|---|
| Unauthenticated network client | Cannot crash, stall or exhaust the proxy, and gains no access to the database it would not have directly. |
| Authenticated database user, the attacker pgsnare exists to catch | Sees no pgsnare-specific behaviour in the protocol, cannot switch off inspection or desynchronise it with crafted messages, and cannot read tokens or configuration. |
| Malicious or compromised database server | Malformed server messages cannot crash the proxy or affect other sessions. |
| Reader of logs, events or metrics | Learns no token values, passwords, bind parameters or key material. |
| Supply-chain attacker | A tampered dependency, CI action or release artefact is detectable. |

## How the design meets them

- **Limits on everything from the network.** Every size and count taken from the network is bounded, and parsers have fuzz targets. Slow or abusive clients are bounded by `login_timeout`, `max_connections` and the limit on held sessions.
- **No panic ends the process for one session's fault.** A panic ends one session, one delivery of a sink or one connection to the admin or metrics listener, and is counted. A fault in a listener's accept loop stops the proxy with a non-zero status so that the supervisor restarts it.
- **Fail closed.** An inspection error ends the session (`fail_closed`). `fail_open` is a choice you make explicitly, and raises an `inspection_bypassed` event.
- **The sinks never make traffic wait.** Events pass through a bounded queue; a full queue loses the event and counts it, and each sink keeps a quarter of its queue for hits.
- **No secret in any output.** A redaction layer stands before every event, log line and metric label; a leak test searches everything pgsnare writes for secrets made for the run.
- **No database credentials.** pgsnare relays logins and learns no password.
- **Verified TLS and webhooks.** Webhooks need HTTPS verified against the certificate store, follow no redirect and are signed; the signature scheme is in section 12.3 of the design document.
- **Confinement.** The image and the chart run non-root with no capability and a read-only root filesystem; the admin and metrics listeners stay on loopback.
- **Supply chain.** Dependencies come from crates.io and are checked for advisories and licences on every change; CI runs only actions of GitHub or verified publishers, pinned by commit; the image is scanned on every build and nightly; a release is built only by CI from a tag, with signatures, checksums, SBOMs and provenance. **No release has been made yet, so the release chain has not run for real** (see [Verifying a release](verifying-a-release.md)).

## Known gaps

These are stated in the README and the design document and are repeated here, so that nobody relies on what is not there.

**Detection**

- **Transformed values.** A value hashed, cut, re-encoded or encrypted inside the database before it leaves does not match.
- **Blind extraction.** Boolean or time-based SQL injection infers data without returning it. The optional SQL rules, not yet built, are meant to flag the functions such attacks rely on.
- **Rows already sent.** `kill` withholds the message that holds the token, not the earlier rows of the same result. A message larger than `inspection.max_buffered_frame` is scanned as a stream, and bytes before the token inside it can reach the client.
- **Honeytokens used as a password are not detected.** Login messages are not scanned. A honeytoken used as a user name is detected, and so is one used in a query. Alternatives are on the [future work](../README.md#future-work) list.
- **Bypass.** Traffic that does not pass through pgsnare is not seen. The network must force every connection through it. In the sidecar pattern the application can still reach the database directly, because one pod has one network identity.
- **Statement attribution.** Statements are attributed by following the protocol, not by parsing SQL. A statement prepared or deallocated by an SQL command is not followed, and the event then says the statement is unknown. The hit is still raised.
- **`fake_data` limits.** It works only on a text-format result of one `SELECT`, `TABLE` or `VALUES` statement whose description pgsnare has seen; otherwise the hit is reported as `alert`. Rows are added at the end, so an `ORDER BY` other than ascending `id` is broken.

**Operation**

- **`fail_open`** turns a session pgsnare cannot follow into an uninspected tunnel.
- **Statements in events.** `query_redaction: full` shows statements as sent, passwords written in them included. The default `fingerprint` shows a hash, which someone who knows a statement except for a short constant can try every value against.
- **Exemptions by address** trust the address pgsnare sees; behind a load balancer that hides client addresses they are unsafe.
- **Admin and metrics** speak plain HTTP and ask for no login. They are safe on loopback and nowhere else without a NetworkPolicy that names the readers.
- **Replicas are independent.** Deduplication windows and the tarpit cap apply to each replica.
- **A lost event.** A full queue loses events and counts them. A sink that is down costs events, never traffic.
- **The image has a shell and a package manager** (the owner's choice of the Alpine base). The confinement of the process, not the absence of tools, is what protects it.
- **The NetworkPolicy of the chart** protects only on a network plugin that enforces it; the chart cannot check that.

**Not supported**

- Login with client certificates, GSSAPI encryption, and a central proxy with TLS on both legs in front of a database whose key is not available.
- IPv6-only pod networks.

## Reporting a vulnerability

Use [GitHub's private vulnerability reporting](https://github.com/guidorugo/pgsnare/security/advisories/new) and do not open a public issue. [SECURITY.md](../SECURITY.md) has the details.
