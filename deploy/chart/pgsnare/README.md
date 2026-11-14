# pgsnare chart

Installs pgsnare as a central proxy: a Deployment and a Service in front of one PostgreSQL database. Applications connect to the Service in place of the database.

One release serves one database. For a second database, install the chart a second time.

No release of pgsnare exists yet, so no image and no packaged chart are published. The chart is installed from this directory, with an image you built yourself and pushed to a registry of your own.

## What the chart creates

| Object | What it is for |
|---|---|
| Deployment | The pgsnare pods, two by default |
| Service | Type `ClusterIP`, with the proxy port and no other |
| NetworkPolicy | Refuses everything in both directions except what the values list |
| PodDisruptionBudget | At most one pod is taken away on purpose at a time |
| ServiceAccount | An account without a role, whose token is not mounted |
| ConfigMap | The configuration file. It names files and holds no secret |

The chart creates no Secret and takes no secret as a value. A value it does not know is an error.

## What you create first

All of these are Secrets in the namespace of the release. The chart mounts each as a whole volume, readable by the group pgsnare runs in and by nobody else.

1. **Honeytokens** (required). One or more Secrets in which every key that ends in `.yaml` is a token file. Every such Secret must hold at least one. Generate the values yourself, with `pgsnare token generate`: never use values from an example.

   ```sh
   kubectl --namespace NAMESPACE create secret generic pgsnare-tokens --from-file=tokens.yaml
   ```

2. **The certificate for clients** (required unless `proxy.clientTLS.mode` is `disable`). A Secret of type `kubernetes.io/tls`. For logins with SCRAM channel binding to work with TLS on both legs, it must be the certificate and key of the database itself.

   ```sh
   kubectl --namespace NAMESPACE create secret tls pgsnare-server-tls --cert=server.crt --key=server.key
   ```

3. **The certificate authority of the database** (optional). A Secret with the key `ca.crt`, used with `database.tls.mode: verify-full`. Without it, the authorities of the image are trusted.

4. **A Secret for each webhook** (optional), with the keys `url` and `hmac-secret`. The address must be HTTPS. Use a signing key of at least 32 random bytes, and a different one for each webhook.

   ```sh
   kubectl --namespace NAMESPACE create secret generic pgsnare-webhook \
       --from-literal=url=https://alerts.example.com/hooks/pgsnare \
       --from-file=hmac-secret=signing.key
   ```

5. **Certificate authorities for webhooks** (optional). A Secret with the key `ca.crt`, when a receiver's certificate is signed by an authority the image does not know. It replaces the authorities of the image for webhooks, so it must hold every authority a webhook needs.

## Installing

```sh
helm install pgsnare deploy/chart/pgsnare --namespace NAMESPACE --values my-values.yaml
```

The least a values file holds:

```yaml
image:
  repository: registry.example.com/pgsnare
  digest: sha256:...            # of the image you built
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
  secretNames:
    - pgsnare-tokens
```

## Values

### Image and pods

| Value | Default | Meaning |
|---|---|---|
| `image.repository` | `ghcr.io/guidorugo/pgsnare` | Registry and path, without a tag and without a digest |
| `image.digest` | none, **required** | `sha256:` and 64 hexadecimal digits. The image is named by digest only |
| `image.pullPolicy` | `IfNotPresent` | `Always`, `IfNotPresent` or `Never` |
| `imagePullSecrets` | `[]` | Names of existing Secrets for the registry |
| `nameOverride`, `fullnameOverride` | empty | Replace the names the chart gives its objects |
| `replicaCount` | `2` | Replicas are independent of each other. With one, a node drain interrupts the service |
| `resources.requests` | `cpu: 100m`, `memory: 64Mi` | Both are required |
| `resources.limits` | `cpu: "1"`, `memory: 256Mi` | Both are required. pgsnare starts as many worker threads as the CPU limit allows |
| `podLabels`, `podAnnotations` | `{}` | Added to the pods. The labels of the chart cannot be replaced |
| `nodeSelector` | `{}` | Labels of the nodes the pods may run on |
| `priorityClassName` | empty | An existing priority class |

### The proxy and its clients

| Value | Default | Meaning |
|---|---|---|
| `proxy.port` | `5432` | The port of the pods and of the Service, 1024 or higher |
| `proxy.maxConnections` | `1000` | Sessions one pod accepts at a time |
| `proxy.loginTimeout` | `60s` | Time a client has to log in |
| `proxy.clientTLS.mode` | `require` | `disable`, `prefer` or `require` |
| `proxy.clientTLS.secretName` | none | The Secret of item 2 above. Required unless the mode is `disable` |
| `proxy.clientTLS.minVersion` | `tls1.2` | `tls1.2` or `tls1.3` |
| `clients` | `[]` | Who may connect to the proxy. **An empty list means nobody** |

An item of `clients` names pods by their labels, in one namespace:

```yaml
clients:
  - podLabels:                    # required, at least one label
      app.kubernetes.io/name: api
  - namespace: batch              # left out: the namespace of the release
    podLabels:
      app.kubernetes.io/name: reports
```

A pod must carry every label of an item and run in its namespace. An item without a label is refused, because it would mean every pod.

### The database

| Value | Default | Meaning |
|---|---|---|
| `database.host` | none, **required** | The host name or address pgsnare connects to |
| `database.port` | `5432` | |
| `database.tls.mode` | `verify-full` | `disable`, `prefer`, `require` or `verify-full`. Only `verify-full` verifies the certificate |
| `database.tls.caSecretName` | empty | The Secret of item 3 above |
| `database.tls.serverName` | empty | The name the certificate must carry. Empty: `database.host` |
| `database.tls.minVersion` | `tls1.2` | `tls1.2` or `tls1.3` |
| `database.peers` | `[]` | Where the database is, for the NetworkPolicy. **An empty list means the proxy may connect to no database** |
| `database.peerPort` | `0` | The port the database itself listens on, when a Service in between changes it. `0`: `database.port` |

An item of `database.peers` is either pods, written as in `clients`, or a range of addresses:

```yaml
database:
  peers:
    - namespace: data
      podLabels:
        app.kubernetes.io/name: postgresql
    - cidr: 192.0.2.10/32
```

A range with a prefix of 0, which is every address, is refused.

### Name service

| Value | Default | Meaning |
|---|---|---|
| `dns.peers` | pods labelled `k8s-app: kube-dns` in `kube-system` | The name service of the cluster, written as `database.peers`. With an empty list pgsnare can look up no name |
| `dns.port` | `53` | Opened for UDP and TCP, to these peers only |

A cluster whose name service has other labels, or answers on an address of the node, needs its own peers here.

### Honeytokens

| Value | Default | Meaning |
|---|---|---|
| `tokens.secretNames` | none, **required** | The Secrets of item 1 above, at least one |

A change of one of these Secrets reaches the running pods without a restart: the cluster updates the mounted files, which can take a few minutes, and pgsnare reads them again about two seconds later. A change that pgsnare refuses is logged, and the tokens it had stay active.

### Events

| Value | Default | Meaning |
|---|---|---|
| `sinks.stdout` | `true` | Events as JSON lines on standard output |
| `sinks.webhooks` | `[]` | Webhooks, each with the Secret of item 4 above |
| `sinks.webhooks[].secretName` | **required** | The Secret with the keys `url` and `hmac-secret` |
| `sinks.webhooks[].peers` | none | Where the receiver is, written as `database.peers`. **Without peers the NetworkPolicy lets no event reach it** |
| `sinks.webhooks[].port` | `443` | The port of the receiver, for the NetworkPolicy |
| `sinks.webhooks[].config` | none | `timeout`, `max_retries`, `queue_size` and `max_events_per_second`, as in the configuration file |
| `sinks.webhookCA.secretName` | empty | The Secret of item 5 above |

At least one sink is required. The chart offers no `file` and no `syslog` sink.

Every event carries the name and the namespace of the pod that wrote it, as the labels `POD_NAME` and `POD_NAMESPACE`.

### Metrics

| Value | Default | Meaning |
|---|---|---|
| `metrics.scrapers` | `[]` | Who may read the metrics, written as `clients`. An empty list: the metrics stay on the loopback address of the pod |
| `metrics.port` | `9642` | The port of the pod, opened only when scrapers are listed |

The metrics are plain HTTP without a login. The port is not part of the Service, and the NetworkPolicy is its only protection: on a cluster whose network plugin does not enforce NetworkPolicy, list no scraper.

### Settings of the configuration file

These are copied into the configuration file as they are, under the names the configuration file uses. `examples/config/pgsnare.yaml` in the repository explains each.

| Value | Settings |
|---|---|
| `config.inspection` | `on_error`, `max_buffered_frame` |
| `config.exemptions` | A list of `{ db_user, client_cidr }` |
| `config.actions` | `kill` (`sqlstate`, `message`), `tarpit` (`delay`, `max_duration`, `max_sessions`, `max_bytes_per_second`), `fake_data` (`rows`) |
| `config.events` | `query_redaction`, `dedup_window`, `queue_size`, `labels` |

Nothing else of the configuration file can be set. In particular there is no value for the admin listener: it stays on the loopback address of the pod.

`tarpit.max_sessions` applies to each pod. Keep it, times the number of replicas, below the connections the database has to spare.

An exemption by `client_cidr` trusts the address a connection comes from. Use it only where pgsnare sees the real address of the client. The Service of this chart is of type `ClusterIP` for that reason; do not put a load balancer that hides client addresses in front of it and keep such exemptions.

### Stopping

| Value | Default | Meaning |
|---|---|---|
| `shutdown.gracePeriodSeconds` | `25` | How long open sessions may finish after a pod was told to stop |
| `shutdown.preStopSleepSeconds` | `0` | How long a pod keeps accepting clients after it was told to stop, while the cluster takes it out of the Service. More than `0` needs a cluster with the sleep action for containers |

The time the cluster gives a pod is computed: both values, 2 seconds for the sinks, and 3 seconds to spare. With the defaults that is 30 seconds.

## What the chart fixes

These have no value, on purpose.

- **The pod.** It meets the "restricted" Pod Security Standard: user and group 65532, no privilege escalation, no capabilities, the default seccomp profile. Its root filesystem is read-only, it mounts no service-account token, and it uses nothing of the host.
- **Probes.** The startup, liveness and readiness probes run `pgsnare healthcheck` inside the container. It asks the admin listener over loopback and reads no file, so no health port is open to the cluster. Readiness does not depend on the database.
- **The Service** is of type `ClusterIP`.
- **The NetworkPolicy** is always rendered, for both directions. It needs a network plugin that enforces NetworkPolicy; where the plugin does not, nothing in this chart restricts who reaches the pods.
- **Secrets** are mounted as whole volumes with mode `0440`, never through `subPath` and never as environment variables.
- **Updates.** A new pod is ready before an old one is told to stop. Pods are spread over nodes where that is possible.

## Changing things later

- A change of the values that changes the configuration file starts new pods.
- A change of a token Secret needs nothing.
- A change of any other Secret needs new pods: `kubectl rollout restart deployment/NAME`.

## Limits

- One database for each release.
- The listener for clients binds to IPv4 addresses. A cluster whose pods have only IPv6 addresses is not supported.
- The SQL rules of the configuration file cannot be set yet.
- The chart cannot be used as a dependency of another chart: it accepts no `global` values.
