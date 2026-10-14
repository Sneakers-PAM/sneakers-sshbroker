# API

The broker has two surfaces: a gRPC API for the gateway, and a WebSocket endpoint for the browser.

## gRPC

The service implements `sneakers.sshbroker.v1.SSHBrokerService`, defined in
[proto/sneakers/sshbroker/v1/sshbroker.proto](../proto/sneakers/sshbroker/v1/sshbroker.proto).
Other services don't import this module's Go code: they pin a commit of this repo and generate
their own client stubs from that proto, the way the broker calls the vault and audit (see
[Calling other services](#calling-other-services)).

The server also registers the gRPC health service (`grpc.health.v1.Health`) and server
reflection. The health service is go-buildinfo's (`github.com/Bugs5382/go-buildinfo`) and answers
two names:

- `""` (the default) is readiness: `SERVING` unless a required dependency is down, then
  `NOT_SERVING`. Its answer carries `sneakers-health`, the readiness report as compact JSON:
  `{"status":"ok|degraded|down","ready":true,"dependencies":[{"name":"valkey","state":"ok","required":true,"checkedAt":"2026-10-05T12:00:00Z"}]}`.
  A failing dependency adds `error`, a class from a fixed set (`timeout`, `refused`,
  `unavailable`, `unauthenticated`, `connection-refused`, `dns`, `network`, `canceled`, `panic`,
  `error`), never the error's text or an address.
- `liveness` is the process only: `SERVING` while the process answers, whatever its
  dependencies.

Any other name gets `NotFound`. `Watch` streams the serving status of either name as it changes.
The dependencies are checked in the
background every 5 seconds, each with a 1-second timeout, and a health check (gRPC or `/readyz`)
only reads the last result, so a probe never waits on a dependency and probes don't load them;
readiness recovers on its own at the next pass after the dependency is back. Right after the
start, before the first pass, each dependency is `down` with the class `pending`.

The HTTP port serves the same readiness: `GET /readyz` answers 200 (ok or degraded) or 503 (a
required dependency down) with the report and the build as its body
(`{"status":"ok","ready":true,"build":{"version":"v0.1.0","commit":"...","goVersion":"...","modified":false},"dependencies":[...]}`),
and `GET /livez` always answers 200 `{"status":"ok"}`. There is no plain `/health` route.

Every health check's answer, gRPC or HTTP, carries the build in its response headers:
`sneakers-version` (the image tag, `dev` when unstamped) and `sneakers-commit` (the source commit,
`unknown` when neither the build nor Go's VCS stamp knows it). A readiness answer also carries
`sneakers-depstate-<name>` (`ok`, `degraded` or `down`) for each dependency. HTTP writes the names
canonicalized (`Sneakers-Version`). The gateway's diagnostics read them.

### Callers

Every call is authenticated with the caller's Kubernetes workload identity (the
`github.com/Bugs5382/go-workload-identity` package; see [Workload authentication](#workload-authentication)), then
checked against the allow-list in `internal/grpcsvc/callers.go`:

| Method | Caller | Access |
|---|---|---|
| `CreateSession` | gateway (`<namespace>/sneakers-gateway`) | on behalf: it passes the signed-in user's actor, which the broker forwards to the vault |
| `ScanHostKey` | gateway (`<namespace>/sneakers-gateway`) | on behalf: the gateway checks the user may change the target's pins before it calls |

No other service may call the broker, and the MCP server never may. A missing or rejected token
returns `Unauthenticated`, a caller that isn't listed returns `PermissionDenied`, and a verifier
with no key set loaded yet returns `Unavailable`. Each refusal is logged and sent to the audit
service as `session.refuse`, with `reason`, `caller`, `method` and `code`. The health service needs
no token.

### CreateSession

Registers a pending session and returns its ticket. It needs `host`, `username` and
`actor_user_id` (the user, recorded in the audit events; it is not used for authorization), plus
the credential in one of these forms:

- **Reference, key** (preferred): leave `private_key` empty and `password_auth` unset, and send
  `secret_id` and `actor` (`actor.user_id` is required). The ticket holds only the reference. When
  the browser connects, the broker calls the vault's `RevealSecretField` for the `privateKey`
  field, and the `passphrase` field if there is one, passing `actor` through, so the vault applies
  its own access rules and audits the reveal. With `REDIS_URL` set, the ticket goes to Redis and
  any replica can redeem it.
- **Reference, password**: set `password_auth = true` and send `secret_id` and `actor`, the same as
  the key reference form (and leave `private_key` empty: the two are mutually exclusive and
  `password_auth` with a `private_key` returns `InvalidArgument`). When the browser connects, the
  broker reveals the secret's `password` field instead of `privateKey`/`passphrase`, and the dial
  offers the target SSH password auth and keyboard-interactive (answering a single prompt with the
  password) instead of publickey, so a target that only speaks one of the two still works. There is
  no inline form for a password secret: it is always revealed by reference.

With `REDIS_URL` set and Redis not answering yet, `CreateSession` returns `Unavailable` for every
form.
- **Inline, key**: send `private_key` (PEM) and, if it has one, `passphrase`. The ticket and the key
  stay in the memory of the replica that minted it, so the browser must reach that same replica.
  This form is kept for older callers.

`host_keys` carries the target's pinned SSH host keys, one OpenSSH public key per entry in
authorized_keys form, as the vault returns them in `Target.ssh_host_keys`. They travel on the
ticket (the Redis copy too; they are public keys). An entry that doesn't parse, or carries options,
returns `InvalidArgument`. An empty list means the target has no pinned host key: after the input
checks, `CreateSession` returns `FailedPrecondition` with the message `host key not pinned for this
target: an admin pins it on the target first; no connection was made` and a `google.rpc.ErrorInfo`
(domain `sneakers.sshbroker`, reason `HOST_KEY_NOT_PINNED`, metadata `target_id`). No ticket is
issued, and a `session.refuse` audit event is sent with the reason `host key not pinned`. The
gateway passes the reason to the web app, which shows it without opening a WebSocket. The dial
still checks the pins, so a ticket that somehow has none is refused there too.

Only a person in the web app starts a brokered session. `actor.principal_kind` (the same values
as the vault's `PrincipalKind`) is `PRINCIPAL_KIND_HUMAN` when unset; any other kind
(`PRINCIPAL_KIND_USER_TOKEN` for an MCP or agent token, `PRINCIPAL_KIND_SERVICE_ACCOUNT` or
`PRINCIPAL_KIND_WORKLOAD`) returns `PermissionDenied` on both forms, mints no ticket and sends a
`session.refuse` audit event. The gateway sets the kind from the principal it authenticated.
`actor.session_ref` is the opaque reference to the person's signed-in web session. The ticket
keeps it (the Redis copy too) and the key reveal passes it to the vault, which refuses a person's
reveal that doesn't carry one.

A missing field returns `InvalidArgument`. `port` 0 defaults to 22 (the SSH convention); a port
outside 1-65535 returns `InvalidArgument`. `ttl_seconds` 0 or less means 30 seconds.

The response carries `session_id`, the `ticket`, `ws_url` (`SSHBROKER_PUBLIC_WS_URL`) and
`expires_in_seconds`. The web app uses only the path of `ws_url` and opens it on the page's own
origin, so the terminal works whether the box was opened by its name, an IPv4 address or an IPv6
address. A `session.start` audit event is sent before the response.

### ScanHostKey

Reads the host key a target offers, so a person can see its fingerprint before pinning it. It needs
`host`, `target_id` (the vault target, for the audit event) and `actor_user_id` (the user, for the
audit event and the rate limit); `port` 0 means 22, and anything outside 1 to 65535 returns
`InvalidArgument`. The broker connects and runs the SSH handshake only as far as the host key,
then drops the connection: it never sends an authentication request, so no credential is used and
the target records no login attempt. The whole scan, connect included, is bounded by 5 seconds.

The response carries `key_type` (`ssh-ed25519`, say), `public_key` in authorized_keys form with no
comment, and `fingerprint_sha256` (`SHA256:<base64>`, as `ssh-keygen -l` prints it). A target that
can't be reached, or that offers no host key in time, returns `Unavailable`.

The broker only reports what the target offered. It pins nothing: the gateway pins a key only
when the person confirms the exact fingerprint they were shown and a fresh scan still returns it.

So the broker can't be driven as a port scanner, each `actor_user_id` gets 5 scans back to back,
refilled one every 12 seconds; past that the call returns `ResourceExhausted`. As with
`CreateSession`, any `actor.principal_kind` but `PRINCIPAL_KIND_HUMAN` returns `PermissionDenied`.
Every call that gets past the input checks sends a `hostkey.scan` audit event.

## WebSocket

The browser connects to `ws_url` with `?ticket=<ticket>`. The endpoint is served at both
`/ssh/session` and `/proto/ssh/session`, so it works behind an ingress that keeps a `/proto` prefix.

First the broker checks the request's `Origin` header. It allows:

- an origin listed in `SSHBROKER_ALLOWED_ORIGINS` (see [configuration](configuration.md));
- the page's own origin: an `Origin` whose host and port are the request's own `Host` header. This
  is how a box opened by its name, its IPv4 address or its IPv6 address (`https://[2001:db8::1]`)
  reaches its terminal. Names compare case-insensitively, an IPv6 address compares by value (two
  spellings of one address match), and a missing port is the origin scheme's default (443 for
  `https`, 80 for `http`). An address with a zone id (`fe80::1%eth0`) never matches: browsers
  don't send one in an `Origin`, and the box isn't served on a link-local address. The edge must
  pass the browser's `Host` header through, as Traefik does by default.

Any other browser origin, another site's name or address included, gets `403 origin not allowed`,
and the ticket is left unused. A request with no `Origin` header isn't from a browser, so it can't
be a cross-site WebSocket hijack, and it goes on to the ticket check. The ticket is what grants the
session either way.

Before the upgrade the broker then consumes the ticket, reveals the key when the ticket is a
reference, dials the target, runs the SSH handshake and authentication, and starts the PTY and the
shell. The dial checks the target's host key against the ticket's `host_keys` (it asks for the
pinned keys' algorithms, so a host with several keys presents a pinned one). Every step is bounded,
and so is the whole open:

| Step | Bound |
|---|---|
| The vault reveal of the credential (key or password) | 10 s |
| The TCP connect to the target | 15 s |
| The SSH banner, key exchange, host-key check and authentication | 15 s |
| The session channel, PTY and shell | 15 s |
| The whole open, from the ticket to the upgrade | 45 s |

A failed step reaches the client as one sentence naming the step and the reason. A browser can't
read the body of a failed handshake, so a WebSocket client gets the upgrade and then a close frame
carrying the sentence (cut to the frame's 123 bytes); any other client gets the sentence as the
response body. The same sentence is the `session.end` reason.

| Close, or status | Sentence | Cause |
|---|---|---|
| 1008, or 502 | `host key not pinned for this target` | The ticket has no `host_keys`. |
| 1008, or 502 | `host key mismatch` | The host presented a key that isn't one of the `host_keys`. |
| 1011, or 502 | `couldn't get the key: the vault didn't answer in 10s`, `... the vault refused access to it`, `... the vault isn't reachable`; the same sentences with `couldn't get the password: ...` for a password secret | The reveal timed out or the vault refused or failed it. |
| 1011, or 500 | `the stored key isn't a private key the broker can read`, `the stored passphrase doesn't open the stored key` | The key could not be parsed (key secrets only). |
| 1011, or 502 | `can't reach <host>:<port>: connection timed out`, `... connection refused`, `... no route to host`, `can't find <host> in DNS` | The TCP connect failed. |
| 1011, or 502 | `<host>:<port> didn't finish the SSH handshake in 15s` | The target took the connection but never finished the handshake. |
| 1011, or 502 | `<host>:<port> refused the key for <user>` | A key secret's authentication was refused. |
| 1011, or 502 | `the target refused the password` | A password secret's authentication was refused, whether the target took password or keyboard-interactive. One attempt only: the broker never retries a wrong password. |
| 1011, or 502 | `the target asked for more than a password` | A password secret's target asked for a second keyboard-interactive step (a TOTP code, say) after the password. Out of scope here: see sneakers-sshbroker#68. |
| 1011, or 502 | `<host>:<port> didn't start a shell in 15s`, `<host>:<port> refused a shell: ...` | The session, PTY or shell request stalled or was refused. |

A step cut short by the whole open's bound says `within the 45s open limit` in place of its own
bound.

Before any of that, two failures are plain HTTP errors with no upgrade, and they leave no
`session.end`:

| Status | Body | Cause |
|---|---|---|
| 403 | `origin not allowed` | A browser `Origin` that isn't in `SSHBROKER_ALLOWED_ORIGINS` and isn't the request's own `Host`. The ticket stays unused. |
| 403 | `invalid or expired ticket` | No ticket, an unknown or used ticket, or one past its time to live. |

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
actor and the secret id as the subject. They are best-effort: each send is bounded at 5 seconds, and a
failed one is logged and the session carries on. No key material is ever put in an event.

| Action | When | Attributes |
|---|---|---|
| `session.start` | `CreateSession` | `host`, `target_id`, `auth_kind` (`publickey` or `password`, the credential the request asked for) |
| `session.refuse` | `CreateSession` refused for its principal kind, or any call refused by the caller check | `target_id`, `reason`, and `principal_kind`, or `caller`, `method` and `code` |
| `session.end` | the session ends, or fails at any point after its ticket was consumed (a host-key refusal included, with its reason) | `target_id`, `duration_ms`, `reason`, `auth_method` (`publickey`, `password` or `keyboard-interactive`, whichever actually authenticated; empty if auth never completed) |
| `hostkey.scan` | `ScanHostKey`, with the target id as the subject and not marked sensitive (no secret is involved) | `target_id`, `host`, `outcome` (`ok`, `refused`, `rate_limited`, `unreachable` or `handshake_failed`), and `port`, `key_type`, `fingerprint_sha256` or `principal_kind` as they apply; never the key itself |

## Workload authentication

The broker's calls to the vault and audit carry its own workload token: the projected
service-account token (audience `sneakers`) named by `WORKLOAD_TOKEN_FILE`, sent as
`authorization: Bearer <token>` and read again on every call. The vault lists the broker as an
on-behalf caller of `RevealSecretField` only.

The token checks, the interceptors and the caller credentials come from the owner's helper package
`github.com/Bugs5382/go-workload-identity`, the same release every Sneakers service imports; a
new version arrives as a `go.mod` bump.

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
