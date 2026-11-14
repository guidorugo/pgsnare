# Deploying pgsnare

pgsnare sits between your applications and one PostgreSQL server. This guide covers the three ways to run it, and the TLS setup that each of them needs. For a first try, start with the [quickstart](quickstart.md).

**No release exists yet.** No image and no chart is published. Until the first release, build the image from [`deploy/Dockerfile`](../deploy/Dockerfile), push it to a registry you control and name it by digest. How a release will be built and checked is in [Verifying a release](verifying-a-release.md) and [Releasing](releasing.md). Everything below that names `ghcr.io/guidorugo` describes where the first release is meant to be published; it is not there today.

## Before you start

- **Generate honeytokens of your own** with `pgsnare token generate`. Never use a value from an example, a document or a test: those are public. [Honeytoken placement](honeytoken-placement.md) says where to put them.
- **Nothing may reach the database except through pgsnare.** A client that connects to the database directly is not seen. Close the database to every address but pgsnare's.
- **Take the image by digest**, never by tag. A tag can be moved to another image.
- Read [Hardening](hardening.md) before the first production use.

## What the image holds

- One static binary, `/usr/local/bin/pgsnare`, owned by root and not writable.
- An Alpine base, pinned by digest, with the CA certificates and the files that name users. **The base has a shell (busybox) and a package manager.** That is the owner's choice of base. Nothing installs a package at run time: the process is not root, has no capability and has a read-only root filesystem when started as below.
- User and group `65532`, named by number so that Kubernetes can check it is not root.
- The entry point `pgsnare`, and the default command `run --config /etc/pgsnare/pgsnare.yaml`.
- A health check, `pgsnare healthcheck`. It asks the admin listener on `127.0.0.1:9641`, reads no file, and takes two seconds at most. If your configuration moves the admin listener, the image's check no longer finds it.
- The image does not set the admin or metrics listener beyond loopback, and publishes no port by itself. Port 5432 is declared with `EXPOSE`, which opens nothing.

## Files pgsnare reads

pgsnare refuses to start when the configuration, a token file, a certificate key or a signing key is open to other users: the file must belong to the user it runs as with mode `0600` or less, or to root with mode `0640` or less. In the image that user is `65532`. A secret is never written in the configuration: name a file (`url_file`, `hmac_secret_file`) or an environment variable. Prefer files.

The configuration is read from `/etc/pgsnare/pgsnare.yaml`. [`examples/config/pgsnare.yaml`](../examples/config/pgsnare.yaml) lists every setting with its default. `pgsnare config check --config FILE` reports every problem of a configuration, with the same code and the same file checks as `run`, and warns about settings that give up protection. Run it with the image, as the same user:

```sh
docker run --rm --read-only --cap-drop ALL --security-opt no-new-privileges \
    --network none --volume pgsnare-config:/etc/pgsnare:ro \
    "$PGSNARE_IMAGE" config check --config /etc/pgsnare/pgsnare.yaml
```

## Standalone container

```sh
docker run --detach --name pgsnare \
    --read-only --cap-drop ALL --security-opt no-new-privileges \
    --memory 256m --cpus 1 \
    --volume pgsnare-config:/etc/pgsnare:ro \
    --publish 192.0.2.20:5432:5432 \
    --stop-timeout 40 \
    "$PGSNARE_IMAGE"
```

- Publish the client port on one address of the machine, the one the applications reach, and nothing else. The admin (`9641`) and metrics (`9642`) listeners stay on loopback inside the container and are not published.
- `--read-only` is enough with the `stdout` sink. A `file` sink needs a volume that only pgsnare can write.
- The volume `pgsnare-config` must hold the configuration, the token files, the certificate and key, and the signing keys, each owned by `65532` and closed to others. The [Compose example](../examples/compose/README.md) shows one way to make such a volume without a root container at run time.
- Docker and Compose report the container `healthy` through the image's own health check.
- **Stopping.** On `SIGTERM` pgsnare stops accepting clients, lets open sessions finish for `shutdown.grace_period` (25 seconds by default), gives its sinks two seconds to deliver what waits, and exits with status 0. Give `docker stop` more time than both: `--stop-timeout 40` above.
- **Changing tokens.** Edit the token files, or send `SIGHUP`. pgsnare reads the policy again about two seconds after a file changes, builds it in full and swaps it in one step; a policy that does not load is refused and the old one stays. Everything but the policy (listeners, TLS, sinks, the grace period) needs a restart.
- There is a shell in the image, but the process is not meant to be debugged through it. Read the log (`docker logs`), which is one JSON object per line on standard error, and the metrics.

The [Compose example](../examples/compose/compose.yaml) runs the whole thing with TLS on both legs, a signed webhook, and no published port; its [README](../examples/compose/README.md) says what to change before you copy it.

## TLS: which setup to choose

pgsnare relays logins and never terminates them: it knows no password. TLS, on the other hand, is terminated on both legs, because pgsnare must read the traffic. SCRAM channel binding ties a login to the certificate the client saw, and a relay that does not know the password cannot get around that check. The choice of setup therefore matters; [section 7 of the design document](high-level-design.md#7-authentication-and-tls) has the full table, which the integration tests try row by row against PostgreSQL 15 to 18.

| Setup | Client leg | Backend leg | Use it when |
|---|---|---|---|
| 1. Shared certificate | TLS, with the database's own certificate and key | TLS | pgsnare can be given the database's key. Clients cannot tell the difference and `channel_binding=require` works. **Preferred.** |
| 2. Next to the database | TLS, with pgsnare's own certificate | Plaintext or Unix socket | pgsnare runs on the machine of the database. `channel_binding=require` fails: there is nothing to bind to. |
| 3. Next to the application | Plaintext, on loopback | TLS | A managed database that enforces TLS and does not hand out its key. pgsnare removes `SCRAM-SHA-256-PLUS` from the server's offer. This is the sidecar. |
| Not supported | TLS, with pgsnare's own certificate | TLS | Clients that use channel binding (libpq does by default) fail with a channel binding error. It works only with `channel_binding=disable`. |

Not supported at all in this version: login with client certificates, GSSAPI encryption, and a central proxy with TLS on both legs in front of a database whose key is not available.

In every setup with TLS to the database, use `upstream_tls.mode: verify-full`. The modes `prefer` and `require` encrypt and do not verify the certificate, and pgsnare says so in its log when it starts. When both legs use TLS, pgsnare compares its own certificate with the database's and warns at startup if they differ.

### Setup 1 in the configuration

```yaml
listeners:
  - name: main
    listen: 0.0.0.0:5432
    upstream: db.example.com:5432
    client_tls:
      mode: require
      cert: /etc/pgsnare/server.crt      # the database's own certificate
      key: /etc/pgsnare/server.key       # and its key
    upstream_tls:
      mode: verify-full
      ca: /etc/pgsnare/root.crt          # leave out to use the image's authorities
      server_name: db.example.com
```

Treat that key like the database's own: it is as sensitive in pgsnare as it is in PostgreSQL.

### Setup 3 in the configuration

```yaml
listeners:
  - name: main
    listen: 127.0.0.1:5432
    upstream: db.example.com:5432
    client_tls: { mode: disable }
    upstream_tls: { mode: verify-full, server_name: db.example.com }
```

## Kubernetes: central proxy

The chart in [`deploy/chart/pgsnare/`](../deploy/chart/pgsnare/README.md) installs a Deployment (two pods by default), a `ClusterIP` Service, a NetworkPolicy, a PodDisruptionBudget, a ServiceAccount and the configuration. Its README lists every value and the Secrets to create first; this section is the short path.

1. **Create the Secrets** in the namespace of the release: the token files (`pgsnare-tokens`), the TLS Secret for clients (setup 1: the database's certificate and key), a Secret for each webhook with the keys `url` and `hmac-secret`, and, if the receiver's certificate is signed by an authority the image does not know, a Secret with `ca.crt`. The chart creates no Secret and accepts no secret as a value.
2. **Write the values.** The image is named by digest only. With the defaults **nobody can connect and the proxy can reach nothing** until you fill `clients` (which pods may connect) and `database.peers` (where the database is). An empty list means nobody.

   ```yaml
   image:
     repository: registry.example.com/pgsnare
     digest: sha256:<64 hexadecimal digits>
   proxy:
     clientTLS:
       secretName: pgsnare-server-tls
   clients:
     - podLabels:
         app.kubernetes.io/name: api
   database:
     host: db.example.com
     peers:
       - cidr: 192.0.2.10/32
   tokens:
     secretNames: [pgsnare-tokens]
   sinks:
     webhooks:
       - secretName: pgsnare-webhook
         peers:
           - cidr: 192.0.2.30/32
   ```

3. **Install** with `helm install pgsnare deploy/chart/pgsnare --namespace NAMESPACE --values my-values.yaml`.
4. **Point the applications** at the Service (`<release>-pgsnare`, port 5432) instead of the database.

What to know:

- **The NetworkPolicy needs a network plugin that enforces it.** Where the plugin does not, nothing in the chart restricts who reaches the pods, and the metrics port must not be opened. The chart cannot check this. It is tested on one plugin only.
- **Namespace.** The pods meet the "restricted" Pod Security Standard in full, so a namespace that enforces it accepts them. The chart is installed that way in CI.
- **Changing a token Secret needs no restart.** The kubelet updates the mounted files, which can take up to a few minutes (62 seconds in the CI cluster), and pgsnare reads them about two seconds later. A change of any other Secret, or of the values, needs new pods: `kubectl rollout restart deployment/<release>-pgsnare`.
- **Rolling updates.** A new pod is ready before an old one is told to stop, and open sessions get the grace period. `terminationGracePeriodSeconds` is computed from `shutdown.gracePeriodSeconds` and the time for the sinks. Set `shutdown.preStopSleepSeconds` above 0 on a cluster that supports the sleep action to close the short gap in which a client can be sent to a pod that has just stopped accepting. This was not tried in a cluster.
- **Replicas are independent.** Deduplication windows and the cap of `tarpit.max_sessions` apply to each pod. Keep `max_sessions` times the replicas below the connections the database has to spare.
- **The Service stays `ClusterIP`.** Behind anything that hides client addresses, an exemption by `client_cidr` is unsafe.
- **Debugging.** Use `kubectl logs` and `kubectl describe`; the probes run `pgsnare healthcheck` inside the container and expose no health port.
- **Limits.** One database and one listener for each release; the listener binds IPv4 only; the chart offers the `stdout` and webhook sinks, and no SQL rules yet; it cannot be a dependency of another chart. Only Kubernetes 1.37 is tested, though the chart declares `>=1.30.0-0`.

## Kubernetes: sidecar

[`deploy/sidecar/`](../deploy/sidecar/README.md) holds two definitions that add pgsnare to an application pod: `native.yaml` for Kubernetes 1.29 and later (an init container with `restartPolicy: Always`, so the application starts only when pgsnare is ready and pgsnare stops after it), and `classic.yaml` for older clusters (two ordinary containers; the application must retry its first connection). The application connects to `127.0.0.1:5432` with TLS off, and pgsnare uses `verify-full` to the database (setup 3). Both were run from install to a first alert in a namespace that enforces the restricted standard.

Know its limits before you choose it: a pod has one network identity, so the application can reach the database without the sidecar and no NetworkPolicy can prevent it; everything in the pod can reach the admin and metrics listeners on loopback; and deduplication and the tarpit cap count for each pod. Where bypass matters, prefer the central proxy.

## Verifying what you run

Check a release before you run it: [Verifying a release](verifying-a-release.md) says what is signed and how to check it by hand or with the script. Use the image digest from the release's `digests` file, and the chart of that release, which already names that digest.
