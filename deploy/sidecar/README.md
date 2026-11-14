# pgsnare as a sidecar

The chart in [`../chart/pgsnare/`](../chart/pgsnare/README.md) runs pgsnare as a central proxy in front of a database. These two definitions run it instead inside an application's pod, as a second container that only that pod's application talks to:

| File | For | How pgsnare runs |
|---|---|---|
| [`native.yaml`](native.yaml) | Kubernetes 1.29 and later | A native sidecar: an init container with `restartPolicy: Always`. The application starts only once pgsnare's startup probe (`pgsnare healthcheck --ready`) has passed, and pgsnare stops after the application. |
| [`classic.yaml`](classic.yaml) | Older clusters | An ordinary second container. Both start and stop together: the application must retry its first connection, and sessions still open when the pod stops get pgsnare's grace period but nothing after it. |

Each file holds a ConfigMap with pgsnare's configuration and a Deployment whose container `app` stands in for your application: it has psql and waits. Both are tested in CI (`kubernetes` job, `deploy/tests/kubernetes/sidecar.sh`): applied in a namespace that enforces the restricted Pod Security Standard, they go from install to a verified `token_hit` at a webhook receiver.

## What you replace

- `${PGSNARE_IMAGE:?…}`: the pgsnare image, by digest (`…/pgsnare@sha256:…`). A tag can be moved to another image.
- The container `app`: your application, pointed at `127.0.0.1:5432` with TLS off (the connection never leaves the pod).
- `upstream: db.example.com:5432`: your database. `upstream_tls` is `verify-full` against the image's certificate authorities; add `ca:` with a mounted file for a private authority.
- Anything else in `pgsnare.yaml` that the configuration reference allows. Changing the ConfigMap needs a restart of the pod; only the tokens are read again while pgsnare runs.

## What you create first

In the namespace of the pod:

```sh
# Token files: every key ending in .yaml. Generate tokens of your own with
# `pgsnare token generate`.
kubectl create secret generic pgsnare-sidecar-tokens --from-file=tokens.yaml

# The webhook's address and its signing key: at least 32 random bytes, one
# key for each endpoint.
kubectl create secret generic pgsnare-sidecar-webhook --from-file=url --from-file=hmac-secret

# Only for a receiver whose certificate a private authority signed:
kubectl create secret generic pgsnare-sidecar-webhook-ca --from-file=ca.crt

# Only for the stand-in application:
kubectl create secret generic app-database --from-file=password
```

If the receiver's certificate is signed by an authority the image knows, remove the volume `pgsnare-webhook-ca`, its mount and the `SSL_CERT_FILE` variable.

## How it is built

- **Listener on loopback.** pgsnare listens on `127.0.0.1:5432`, so nothing outside the pod can reach it. The admin listener (`127.0.0.1:9641`) and the metrics (`127.0.0.1:9642`) stay on loopback too; your application must not use those ports.
- **Security context as in the chart.** User and group 65532, `runAsNonRoot`, `readOnlyRootFilesystem`, no privilege escalation, every capability dropped, the `RuntimeDefault` seccomp profile, no service-account token, requests and limits.
- **Mounts as in the chart.** The configuration and every Secret are whole volumes with mode `0440` and the pod's `fsGroup: 65532`, never `subPath` and never environment variables. pgsnare refuses a file that others can read, and a change of the token Secret reaches the pod: pgsnare reloads its tokens without a restart (the kubelet can take a minute or more to update the volume).
- **Probes run the binary.** `pgsnare healthcheck` asks the admin listener over loopback and reads no file; no health port is opened.
- **Shutdown.** `terminationGracePeriodSeconds: 30` covers `shutdown.grace_period` (25 s) and the 2 s the sinks get. Keep it above both if you change them.

## Limits

- **The application can bypass the sidecar.** A pod has one network identity, so a NetworkPolicy cannot let pgsnare reach the database and keep the application from reaching it directly. The sidecar sees what the application sends through it; an intruder inside the pod who connects to the database directly is not seen. Where that matters, use the central proxy and let the database accept connections from pgsnare only.
- **Everything in the pod can reach the admin and metrics listeners.** They answer health and readiness, and the metrics, without a login.
- **One sidecar per pod.** Each pod deduplicates events and counts its tarpitted sessions on its own; `tarpit.max_sessions` times the number of pods must stay below the database's spare connections.
