# API

The broker has two surfaces: a gRPC API for the gateway, and a WebSocket endpoint for the browser.

## gRPC

The service implements `sneakers.sshbroker.v1.SSHBrokerService`, defined in
[proto/sneakers/sshbroker/v1/sshbroker.proto](../proto/sneakers/sshbroker/v1/sshbroker.proto). Go
clients import the generated code from
`github.com/Sneakers-PAM/sneakers-sshbroker/gen/go/sneakers/sshbroker/v1`.

The server also registers the standard gRPC health service (`grpc.health.v1.Health`), the small
`sneakers.common.v1.HealthService` (its `Check` answers `SERVING`), and server reflection.

The broker enforces no caller authorization itself: any caller that reaches the gRPC port can mint
a ticket. Only the gateway is meant to call it, after it has authorized the user; run the broker
where only the gateway reaches its gRPC port.

### CreateSession

Registers a pending session and returns its ticket. It needs `host`, `username` and
`actor_user_id` (the user, recorded in the audit events; it is not used for authorization), plus
the key in one of two forms:

- **Reference** (preferred): leave `private_key` empty and send `secret_id` and `actor`
  (`actor.user_id` is required). The ticket holds only the reference. When the browser connects,
  the broker calls the vault's `RevealSecretField` for the `privateKey` field, and the
  `passphrase` field if there is one, passing `actor` through, so the vault applies its own access
  rules and audits the reveal. With `REDIS_URL` set, the ticket goes to Redis and any replica can
  redeem it.
- **Inline**: send `private_key` (PEM) and, if it has one, `passphrase`. The ticket and the key stay
  in the memory of the replica that minted it, so the browser must reach that same replica. This
  form is kept for older callers.

A missing field returns `InvalidArgument`. `port` 0 means port 0 is dialled, so callers should
send the target's port (22 for most targets). `ttl_seconds` 0 or less means 30 seconds.

The response carries `session_id`, the `ticket`, `ws_url` (`SSHBROKER_PUBLIC_WS_URL`) and
`expires_in_seconds`. A `session.start` audit event is sent before the response.

## WebSocket

The browser connects to `ws_url` with `?ticket=<ticket>`. The endpoint is served at both
`/ssh/session` and `/proto/ssh/session`, so it works behind an ingress that keeps a `/proto` prefix.

Before the upgrade the broker consumes the ticket, reveals the key when the ticket is a reference,
and dials the target. A failure there is a plain HTTP error and no upgrade:

| Status | Body | Cause |
|---|---|---|
| 403 | `invalid or expired ticket` | No ticket, an unknown or used ticket, or one past its time to live. |
| 502 | `session key error` | The vault refused or failed the reveal, or no vault client is configured. |
| 500 | `session key error` | The key could not be parsed (or the passphrase is wrong). |
| 502 | `ssh dial failed` | The target was unreachable, or refused the key. |

After the upgrade:

- binary messages from the browser are written to the shell's stdin;
- the shell's stdout and stderr come back as binary messages;
- a text message `{"type":"resize","cols":<n>,"rows":<n>}` resizes the PTY; any other text
  message is ignored.

The session ends when either side closes, the browser stops answering pings, an SSH keepalive
fails, or the 8-hour cutoff is reached (see [configuration.md](configuration.md)). A `session.end`
audit event is then sent with the duration and the reason.

## Audit events

Both events go to the audit service's `RecordEvent` at the audit tier, marked sensitive, with the
actor and the secret id as the subject. They are best-effort: a failed send is logged and the
session carries on. No key material is ever put in an event.

| Action | When | Attributes |
|---|---|---|
| `session.start` | `CreateSession` | `host`, `target_id` |
| `session.end` | the session ends, or fails at any point after its ticket was consumed | `target_id`, `duration_ms`, `reason` |
