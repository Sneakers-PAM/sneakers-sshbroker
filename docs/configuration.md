# Configuration

The service reads its configuration from the environment. Every setting has a default.

| Variable | Default | Purpose |
|---|---|---|
| `GRPC_PORT` | `9096` | TCP port the gRPC server listens on (all interfaces). |
| `HTTP_PORT` | `9097` | TCP port the HTTP server listens on (all interfaces): `/readyz`, `/livez` and the WebSocket endpoint. |
| `SSHBROKER_PUBLIC_WS_URL` | `ws://localhost:9097/ssh/session` | The WebSocket URL returned to callers in `ws_url`. Set it to the address the browser reaches, for example `wss://sneakers.example.org/proto/ssh/session` behind an ingress. The browser appends `?ticket=`. |
| `SSHBROKER_ALLOWED_ORIGINS` | the origin of `SSHBROKER_PUBLIC_WS_URL` | Comma-separated browser origins (`scheme://host[:port]`, `http` or `https`) allowed to open a WebSocket session, for example `https://sneakers.example.org`. Unset, it's the public WebSocket URL's origin (`wss://h/...` gives `https://h`), which fits a web app served from the same host. A browser from any other origin gets 403. A malformed value stops the start. |
| `REDIS_URL` | unset | Redis for the shared reference-ticket store, as a `redis://[:password@]host:port/db` URL. Unset means in-memory tickets only (one replica), with a warning. Set, every reference ticket goes to Redis and never to memory: if Redis isn't answering, the broker keeps trying (1 second, doubling to 30 seconds) and stays not ready until it does. Malformed stops the start. Only the address, database number and password are used: TLS and other URL options are not applied. Keep the password in your secret store and inject the URL at run time. |
| `VAULT_ADDR` | `localhost:9091` | `host:port` of the vault service's gRPC API, used to reveal the key for a reference ticket. The connection is plaintext and made lazily. |
| `AUDIT_ADDR` | `localhost:9194` | `host:port` of the audit service's gRPC API, for the session start and end events. The connection is plaintext and made lazily. |
| `OTEL_EXPORTER_OTLP_ENDPOINT` | `localhost:4317` | OTLP gRPC endpoint for traces and metrics (plaintext). |
| `LOG_LEVEL` | `info` | `trace`, `debug`, `info`, `warn`, `error`, `fatal`, `panic` or `disabled`. |
| `LOG_FORMAT` | `json` | `json`, `console` (or `pretty`), or `both` (JSON on stdout, console on stderr). |

Local development logs at `trace` in `console` format (see `.env.example`). Cluster environments
log JSON, at `debug` in a dev cluster, `info` in QA or staging and `error` in production.

## Workload authentication

The gRPC API takes calls only from authenticated workloads (see [API](api.md#callers)). The
settings are those of the owner's helper package
[`github.com/Bugs5382/go-workload-identity`](https://github.com/Bugs5382/go-workload-identity)
(v1.0.0), which every Sneakers service imports in place of its old private copy.
`internal/server/workloadauth.go` sets the Sneakers values the package has no default for: the
audience `sneakers` when `WORKLOAD_AUDIENCE` is unset, and the caller-name prefix `sneakers-`
(`WORKLOAD_SERVICEACCOUNT_PREFIX` is not read).

| Variable | Default | Purpose |
|---|---|---|
| `WORKLOAD_OIDC_ISSUER` | unset | The cluster's service-account issuer (`https://`); a token's `iss` must equal it. Required unless `WORKLOAD_AUTH=disabled`: with neither set, the start fails. |
| `WORKLOAD_OIDC_JWKS_URL` | discovered | The JWKS URL (`https://`). Unset, it's read from `<issuer>/.well-known/openid-configuration`. |
| `WORKLOAD_OIDC_CA_FILE` | system roots | Extra PEM CA bundle for the discovery and JWKS fetch, such as the cluster CA. |
| `WORKLOAD_OIDC_BEARER_FILE` | unset | Token sent on the discovery and JWKS fetch, read again on every fetch. |
| `WORKLOAD_AUDIENCE` | `sneakers` | The token's `aud` must contain it. |
| `WORKLOAD_ALLOWED_SERVICEACCOUNTS` | unset | Comma list of `<namespace>/<serviceaccount>` that may present a token at all. For the broker: `<namespace>/sneakers-gateway`. Required with the issuer. |
| `WORKLOAD_AUTH` | unset | `disabled` turns the check off and trusts every caller, with a warning every 5 minutes. Local development only; no other value is accepted, and it can't be set together with the issuer. |
| `WORKLOAD_TOKEN_FILE` | unset | The broker's own projected token (`/var/run/secrets/sneakers/token` in the charts), sent on its calls to the vault and audit and read again on every call. Unset, those calls carry no token. A set path that can't be read stops the start. |

No caller can be checked before the issuer's key set has loaded, so readiness waits for it too:
`/readyz` and the gRPC health check answer `NOT_SERVING`, with `workload-identity` reported down
in the readiness body (`server.WorkloadIdentity`, checking `Verifier.Ready`), until then. It's
left out of the readiness body when `WORKLOAD_AUTH=disabled`. Liveness is unaffected.

The broker loads the key set with `server.RunWorkloadKeys` rather than the package's
`Verifier.Run`. While no set has loaded (a first fetch that times out while the pod network
comes up, say) it retries with backoff from 1 second doubling to 30 seconds, logging each failed
attempt at debug (target, attempt, outcome, duration) and the recovery at info, so readiness
turns `SERVING` as soon as a fetch succeeds, with no restart. After that the set is refetched
every 15 minutes, and a failed refresh keeps the last good set.

## Fixed limits

These are constants in the code, not settings:

- a ticket lives for `ttl_seconds` from the request, or 30 seconds when that is 0 or less;
- unconsumed in-memory tickets are swept every second;
- a Redis call for a ticket gives up after 3 seconds;
- the SSH dial gives up after 10 seconds;
- the broker pings the browser every 30 seconds and closes the session when no pong arrives for
  60 seconds (ordinary messages don't count);
- the broker sends an SSH keepalive every 30 seconds and closes the session when one fails;
- a session is closed 8 hours after it started, whatever the activity;
- the workload key set is retried from 1 second doubling to 30 seconds until it first loads,
  then refreshed every 15 minutes;
- the PTY starts at 80 columns by 24 rows as `xterm-256color`, until the browser sends a resize.
