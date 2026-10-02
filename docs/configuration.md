# Configuration

The service reads its configuration from the environment. Every setting has a default.

| Variable | Default | Purpose |
|---|---|---|
| `GRPC_PORT` | `9096` | TCP port the gRPC server listens on (all interfaces). |
| `HTTP_PORT` | `9097` | TCP port the HTTP server listens on (all interfaces): `/health` and the WebSocket endpoint. |
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
- the PTY starts at 80 columns by 24 rows as `xterm-256color`, until the browser sends a resize.
