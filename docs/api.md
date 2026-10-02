# API

The broker has two surfaces: a gRPC API for the gateway, and a WebSocket endpoint for the browser.

## gRPC

The service implements `sneakers.sshbroker.v1.SSHBrokerService`, defined in
[proto/sneakers/sshbroker/v1/sshbroker.proto](../proto/sneakers/sshbroker/v1/sshbroker.proto).
Other services don't import this module's Go code: they pin a commit of this repo and generate
their own client stubs from that proto, the way the broker calls the vault and audit (see
[Calling other services](#calling-other-services)).

The server also registers the standard gRPC health service (`grpc.health.v1.Health`) and server
reflection.

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

With `REDIS_URL` set and Redis not answering yet, `CreateSession` returns `Unavailable` for both
forms.
- **Inline**: send `private_key` (PEM) and, if it has one, `passphrase`. The ticket and the key stay
  in the memory of the replica that minted it, so the browser must reach that same replica. This
  form is kept for older callers.

`host_keys` carries the target's pinned SSH host keys, one OpenSSH public key per entry in
authorized_keys form, as the vault returns them in `Target.ssh_host_keys`. They travel on the
ticket (the Redis copy too; they are public keys). An entry that doesn't parse, or carries options,
returns `InvalidArgument`. An empty list is accepted here, and the connection is then refused.

Only a person in the web app starts a brokered session. `actor.principal_kind` (the same values
as the vault's `PrincipalKind`) is `PRINCIPAL_KIND_HUMAN` when unset; any other kind
(`PRINCIPAL_KIND_USER_TOKEN` for an MCP or agent token, `PRINCIPAL_KIND_SERVICE_ACCOUNT` or
`PRINCIPAL_KIND_WORKLOAD`) returns `PermissionDenied` on both forms, mints no ticket and sends a
`session.refuse` audit event. The gateway sets the kind from the principal it authenticated.

A missing field returns `InvalidArgument`. `port` 0 means port 0 is dialled, so callers should
send the target's port (22 for most targets). `ttl_seconds` 0 or less means 30 seconds.

The response carries `session_id`, the `ticket`, `ws_url` (`SSHBROKER_PUBLIC_WS_URL`) and
`expires_in_seconds`. A `session.start` audit event is sent before the response.

## WebSocket

The browser connects to `ws_url` with `?ticket=<ticket>`. The endpoint is served at both
`/ssh/session` and `/proto/ssh/session`, so it works behind an ingress that keeps a `/proto` prefix.

First the broker checks the request's `Origin` header against the allowed origins
(`SSHBROKER_ALLOWED_ORIGINS`, see [configuration](configuration.md)). A browser origin that isn't
listed gets `403 origin not allowed`, and the ticket is left unused. A request with no `Origin`
header isn't from a browser, so it can't be a cross-site WebSocket hijack, and it goes on to the
ticket check.

Before the upgrade the broker then consumes the ticket, reveals the key when the ticket is a reference,
and dials the target. The dial checks the target's host key against the ticket's `host_keys` (it
asks for the pinned keys' algorithms, so a host with several keys presents a pinned one). A
host-key refusal reaches the client as its reason text: a WebSocket client gets the upgrade and
then a close frame with code 1008 (policy violation) and the reason, since a browser can't read
the body of a failed handshake; any other client gets the reason as a 502 body.

| Close or status | Reason | Cause |
|---|---|---|
| 1008, or 502 | `host key not pinned for this target` | The ticket has no `host_keys`. |
| 1008, or 502 | `host key mismatch` | The host presented a key that isn't one of the `host_keys`. |

Any other failure there is a plain HTTP error and no upgrade:

| Status | Body | Cause |
|---|---|---|
| 403 | `origin not allowed` | A browser `Origin` that isn't in `SSHBROKER_ALLOWED_ORIGINS`. The ticket stays unused. |
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

The events go to the audit service's `RecordEvent` at the audit tier, marked sensitive, with the
actor and the secret id as the subject. They are best-effort: a failed send is logged and the
session carries on. No key material is ever put in an event.

| Action | When | Attributes |
|---|---|---|
| `session.start` | `CreateSession` | `host`, `target_id` |
| `session.refuse` | `CreateSession` refused for its principal kind | `target_id`, `reason`, `principal_kind` |
| `session.end` | the session ends, or fails at any point after its ticket was consumed (a host-key refusal included, with its reason) | `target_id`, `duration_ms`, `reason` |

## Calling other services

The broker never imports another service's Go module. It generates its own client stubs from each
callee's protos, pinned by commit:

- `proto-refs.env` pins each callee: `SNEAKERS_AUDIT_REF=<commit>` for `Sneakers-PAM/sneakers-audit`
  and `SNEAKERS_VAULT_REF=<commit>` for `Sneakers-PAM/sneakers-vault`.
- `scripts/proto-generate.sh` downloads only the callee's `proto/` at that commit into `.protos/`
  (git-ignored) and runs `buf generate`. The stubs land in `gen/go/thirdparty/audit/v1` and
  `gen/go/thirdparty/vault/v1`, inside this module, so they can't collide with the owner's Go
  packages. The stubs are committed, so a build needs no network; the protos never are.
- To try an unmerged proto change, point `SNEAKERS_AUDIT_PROTO_DIR` and `SNEAKERS_VAULT_PROTO_DIR`
  at a local `proto/` directory and run the script.
- To move to a newer callee, change its ref, run the script and commit `proto-refs.env` and `gen/`
  together. Build & Test fails when `gen/` doesn't match the pins.
- The `proto-sync` check (from `Sneakers-PAM/.github`) fails a PR whose pin isn't on the owner's
  `main` or that the owner's `main` breaks, and warns when `main` has moved on. On a schedule it
  opens a PR that bumps stale pins.
