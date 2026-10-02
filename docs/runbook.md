# Runbook

## Before you deploy

- **Host keys aren't verified.** The broker accepts any host key from the target
  (`ssh.InsecureIgnoreHostKey`), so it can't tell a target from something impersonating it on the
  network path. Run it only where that path is trusted, until host-key pinning is added.
- **Any origin is accepted** on the WebSocket endpoint; the single-use ticket is the only check.
  Serve it through an ingress that terminates TLS (`wss://`) for the UI's host only.
- **No caller authorization on gRPC.** Anyone who reaches the gRPC port can mint a ticket for any
  host, user and key reference (the vault still checks the actor on a reference reveal). Expose the
  gRPC port to the gateway only, for example with a network policy.
- **Plaintext gRPC** to the vault, the audit service and the OTLP collector. Keep those hops on a
  private network or behind a service mesh with mTLS.

## Start up

At start the service:

1. reads its configuration from the environment;
2. starts OpenTelemetry export to `OTEL_EXPORTER_OTLP_ENDPOINT`;
3. creates the in-memory ticket store and, when `REDIS_URL` is set and Redis answers within 5
   seconds, the shared Redis store;
4. sets up the clients for the audit service (`AUDIT_ADDR`) and the vault (`VAULT_ADDR`); both
   connect lazily, on the first call;
5. serves HTTP on `HTTP_PORT` and gRPC on `GRPC_PORT`.

A failure in step 2 or a gRPC server error is logged at fatal level and the process exits
non-zero. Redis is best-effort: unset, malformed or unreachable at start, the broker logs one
warning and runs with in-memory tickets only. An HTTP listener error (for example the port already
in use) is logged at error level, but the process keeps running with gRPC only, so watch for it.

## Health

- HTTP: `GET /health` on `HTTP_PORT` answers `200 ok`.
- gRPC: the standard health check:

  ```bash
  grpcurl -plaintext localhost:9096 grpc.health.v1.Health/Check
  ```

Neither checks Redis, the vault or the audit service.

## Replicas and Redis

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
| `ssh dial failed` | The target is unreachable, or rejected the user or the key. |
| `ws upgrade failed` | The browser's request wasn't a valid WebSocket upgrade. |
| `pty request failed`, `shell start failed` | The target refused a PTY or a shell for this user. |

## Shutdown

On SIGINT or SIGTERM the HTTP server stops accepting connections and the gRPC server stops
accepting calls; each waits up to 10 seconds for in-flight work before stopping. Open WebSocket
sessions are not drained: they end when the process exits, and the browser has to reconnect with a
new ticket.

## Panics

A panic in a gRPC handler is recovered: the caller gets a generic `Internal` error, and the panic
value and stack go only to the log (at error level) and to the active trace span.
