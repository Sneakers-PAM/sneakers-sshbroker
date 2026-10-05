# Runbook

## Before you deploy

- **Pin every SSH target's host keys** in the vault (`Target.ssh_host_keys`, set by a site admin)
  before anyone opens a session to it. The broker refuses a target with no pins and a host that
  presents any other key; see [Host key refusals](#host-key-refusals).
- **Set the UI's origin.** The WebSocket endpoint accepts browsers only from
  `SSHBROKER_ALLOWED_ORIGINS`, which defaults to the origin of `SSHBROKER_PUBLIC_WS_URL` (the UI
  on the same host). Set it when the web app is served from another origin. Serve the endpoint
  through an ingress that terminates TLS (`wss://`).
- **Workload authentication on gRPC.** Set `WORKLOAD_OIDC_ISSUER` and
  `WORKLOAD_ALLOWED_SERVICEACCOUNTS=<namespace>/sneakers-gateway` (see
  [configuration](configuration.md#workload-authentication)); the broker won't start without them
  unless `WORKLOAD_AUTH=disabled`, which is for local development only. Only the gateway may
  create a session. Mount the broker's own projected token and set `WORKLOAD_TOKEN_FILE` so the
  vault and audit accept its calls. Keep a network policy that lets only the gateway reach the
  gRPC port as well.
- **Plaintext gRPC** to the vault, the audit service and the OTLP collector. Keep those hops on a
  private network or behind a service mesh with mTLS.

## Start up

At start the service:

1. reads its configuration from the environment;
2. starts OpenTelemetry export to `OTEL_EXPORTER_OTLP_ENDPOINT`;
3. creates the in-memory ticket store and, when `REDIS_URL` is set, starts connecting to Redis in
   the background (see [Replicas and Redis](#replicas-and-redis));
4. sets up the clients for the audit service (`AUDIT_ADDR`) and the vault (`VAULT_ADDR`), with
   the workload token from `WORKLOAD_TOKEN_FILE` when it's set; both connect lazily, on the first
   call;
5. reads the workload authentication settings and starts loading the issuer's keys in the
   background (until they load, gRPC calls other than health get `Unavailable`);
6. serves HTTP on `HTTP_PORT` and gRPC on `GRPC_PORT`.

A failure in step 2 or a gRPC server error is logged at fatal level and the process exits
non-zero, and so does a malformed `REDIS_URL`, a malformed or missing workload authentication
setting (no `WORKLOAD_OIDC_ISSUER` without `WORKLOAD_AUTH=disabled`), or an unreadable
`WORKLOAD_TOKEN_FILE`. With `REDIS_URL` unset the broker logs one warning
and runs with in-memory tickets only. An HTTP listener error (for example the port already
in use) is logged at error level, but the process keeps running with gRPC only, so watch for it.

## Health

- HTTP on `HTTP_PORT`: `GET /readyz` (200 or 503, with the readiness report as JSON),
  `GET /livez` (always 200) and `GET /health` (`200 ok` or `503 not ready`, from the readiness).
- gRPC: the standard health check; service `""` is readiness and service `liveness` is the
  process only:

  ```bash
  grpcurl -plaintext localhost:9096 grpc.health.v1.Health/Check
  grpcurl -plaintext -d '{"service":"liveness"}' localhost:9096 grpc.health.v1.Health/Check
  ```

### Readiness and liveness

Readiness fails while a required dependency is down, so traffic stops reaching a pod that can't
serve it; liveness never looks at a dependency, so an outage doesn't restart every pod. The
kubelet's gRPC liveness probe has to ask for service `liveness` (or the HTTP probe for `/livez`);
that is set in the sneakers-release chart.

| Dependency | Required | Check | Why |
|---|---|---|---|
| `valkey` | yes | `PING` on the shared ticket store; down until it first connects | With `REDIS_URL` set every reference ticket lives in Redis, so a broker that can't reach it can't mint or redeem one, and `CreateSession` answers `Unavailable`. Present only when `REDIS_URL` is set: without it the tickets are in memory and the broker is ready at once. |
| `vault` | no | its gRPC health check | The broker reaches the vault only when a reference ticket is redeemed at WebSocket connect, to reveal the key. `CreateSession` and inline-key sessions don't need it, so an unreachable vault makes the broker `degraded`, not unready. |
| `audit` | no | its gRPC health check | Session events are best effort: a session never fails because audit is down. |

Read the report with `grpcurl -v -plaintext localhost:9096 grpc.health.v1.Health/Check` (the
`sneakers-health` header) or `curl localhost:9097/readyz`. Each change of a dependency's state is
logged once: `health: dependency down` or `degraded` at warn, `health: dependency recovered` at
info, with the dependency's name and error class.

To see which build is running, ask for the response headers (`grpcurl -v ... grpc.health.v1.Health/Check`):
the answer carries `sneakers-version` and `sneakers-commit`. The image build stamps them from its
`VERSION` and `COMMIT` build arguments:

```bash
docker build --build-arg VERSION=v0.1.0 --build-arg COMMIT="$(git rev-parse HEAD)" .
```

## Replicas and Redis

- With `REDIS_URL` set, reference tickets go to Redis only. A broker that starts before Redis
  answers logs `redis unreachable; not ready, retrying` on every attempt (1 second apart, doubling
  to 30 seconds) and logs `shared redis ticket store attached; ready (HA)` once it connects. It
  never falls back to memory, so every replica redeems every reference ticket. The chart's
  startup and readiness probes use the gRPC readiness check, so a broker whose Redis never
  answers fails its startup probe and is restarted; once started, a Redis outage takes the pod
  out of service until Redis is back, without restarting it.
- With Redis, reference tickets are stored under `sneakers:sshbroker:ticket:<ticket>`, as JSON
  holding the target, the user, the secret id and the actor (never key material), with the
  ticket's time to live as the key's expiry. Redemption uses `GETDEL`, so a ticket is used once
  across all replicas. Give the broker a Redis database nobody else writes to.
- Inline-key tickets never go to Redis: they're redeemable only on the replica that minted them.
  Run inline callers against one replica, or route them with session affinity.
- If Redis fails after start, a reference ticket that can't be written is simply missing: the
  browser gets `403 invalid or expired ticket`. Nothing falls back to memory on its own; restart
  the broker without `REDIS_URL` to run single-replica.
- Losing Redis loses only pending tickets. Open sessions are held by the replica running them and
  carry on.

## Sessions

Each open session holds one SSH connection to the target and one WebSocket to the browser, on one
replica. Key material lives only on that replica's session record and is zeroized when the session
ends. A session ends when either side closes, when the browser misses pongs for 60 seconds, when an
SSH keepalive fails, or after 8 hours.

Every session logs `ssh session opening` and `ssh session closed` at info level, with the host,
target id, secret id, actor id and (on close) the reason. Failures log `ssh session failed` at
error level with the reason. Keys and passphrases are never logged.

Common close reasons, which also appear in the `session.end` audit event:

| Reason | Meaning |
|---|---|
| `closed` | The browser or the target closed the session, or a liveness check ended it. |
| `vault reveal failed` | The vault refused the actor or failed; check the vault's audit log. |
| `key parse error` | The stored key isn't a valid private key, or its passphrase is wrong. |
| `host key not pinned for this target` | The target has no SSH host keys pinned in the vault. |
| `host key mismatch` | The host presented a key that isn't pinned for the target. |
| `ssh dial failed` | The target is unreachable, or rejected the user or the key. |
| `ws upgrade failed` | The browser's request wasn't a valid WebSocket upgrade. |
| `pty request failed`, `shell start failed` | The target refused a PTY or a shell for this user. |

## Host key refusals

The broker checks the host key during key exchange, before it offers the session's key, so a host
that fails the check never sees the credential. Each check logs `ssh host key check` at info level
with the target id, the presented key's SHA256 fingerprint, the number of pins and the outcome
(`verified`, `mismatch` or `not pinned`); key material is never logged.

- **`host key not pinned for this target`:** a site admin adds the host's public key to the
  target in the vault. Read it from the host itself (`ssh-keygen -lf
  /etc/ssh/ssh_host_ed25519_key.pub` there shows the fingerprint to compare), not from a scan
  across the network.
- **`host key mismatch`:** compare the logged fingerprint with the host's own. If the host's keys
  were changed on purpose, pin the new key and remove the old one. If they weren't, treat it as a
  possible interception and don't re-pin.

## Shutdown

On SIGINT or SIGTERM the HTTP server stops accepting connections and the gRPC server stops
accepting calls; each waits up to 10 seconds for in-flight work before stopping. Open WebSocket
sessions are not drained: they end when the process exits, and the browser has to reconnect with a
new ticket.

## Panics

A panic in a gRPC handler is recovered: the caller gets a generic `Internal` error, and the panic
value and stack go only to the log (at error level) and to the active trace span.
