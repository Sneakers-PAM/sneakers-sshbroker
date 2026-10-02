# AGENTS.md - sneakers-sshbroker

Guide for AI agents working in this repository. Pair with `CLAUDE.md` (the working agreement and
hook-enforced rules). Keep this file current when the build, layout, or public API changes.

## What this is

Sneakers SSH broker: brokered SSH sessions for the in-browser terminal. A gRPC service
(`sneakers.sshbroker.v1.SSHBrokerService`) that the gateway calls to mint a single-use ticket, and
an HTTP WebSocket endpoint where the browser redeems it: the broker gets the SSH key (from the
vault, as the actor, on the reference path), dials the target, and streams a PTY over the socket.
Before changing it, know the rules it keeps: key material never enters the shared Redis store,
never reaches a log or an audit event, and is zeroized on every exit path; tickets are single-use;
every session is bounded by liveness checks and a maximum length. Keep it that way.

## Layout

- `cmd/sshbroker/` - the service entrypoint: environment, the ticket stores, the audit and vault
  clients, the HTTP and gRPC servers.
- `internal/grpcsvc/` - `CreateSession` and its tests.
- `internal/session/` - the ticket stores: in-memory (holds inline keys), Redis (references only)
  and the composite that routes between them, with their tests.
- `internal/wsproxy/` - the WebSocket endpoint: ticket redemption, key reveal, SSH dial, PTY, the
  pumps and the liveness checks, with tests against an in-process SSH server.
- `internal/vault/` - reveals the key and passphrase from the vault for a reference ticket.
- `internal/audit/` - the best-effort `session.start` and `session.end` events.
- `internal/safeconv/` - the bounds-checked int to int32 conversion.
- `internal/server/` - the gRPC server bootstrap.
- `proto/` - the API; `gen/go/` - the generated Go (committed, checked current in CI).
- `docs/` - configuration, API and runbook.

## Build, test, lint

- Build: `task build`
- Test: `task test`; the tests start an in-process Redis and an in-process SSH server, so nothing
  else is needed.
- Lint: `task lint`, plus `buf lint` for the proto (after `scripts/proto-generate.sh` has
  fetched the vault and audit protos).
- Generated code: `scripts/proto-generate.sh`, with the plugin versions pinned in
  `.github/workflows/job-go-lang-ci.yaml`.
- License headers: `task license` (golic, the Apache-2.0 SPDX header in `.golic.yaml`).

## Logging

Follow the logging rules in `CLAUDE.md`. In short:

- Log generously: entry and exit of significant operations, decisions and branches, retries, state
  changes, external calls (target, duration, outcome), and every error with its context.
- Levels: `trace` for step-by-step detail, `debug` for flow, `info` for lifecycle, `warn` and
  `error` for problems. The environment filters the volume, so err on the side of too much.
- Environments: local dev `trace` with `LOG_FORMAT=console` (never JSON), dev cluster `debug`,
  qa/staging `info`, production `error`. Every cluster environment logs JSON. Set levels through
  `LOG_LEVEL` and `LOG_FORMAT`, never in code; local settings live in the run target or
  `.env.example`.
- Never log secrets, tokens, or personal data, not even at `trace`. Log an opaque or keyed ID.

## Conventions and gotchas

- See `CLAUDE.md` for the branch/commit/PR rules; they are enforced by the git hooks in
  `.claude/hooks` (run `bash .claude/hooks/install.sh` once per clone).
- Open every PR as a draft. CI skips drafts, so run the full checks locally, push once they pass,
  and mark the PR ready when the work is finished; see CLAUDE.md "CI and Actions minutes".
- Every commit carries a DCO sign-off (`git commit -s`); the `checks / scrub` job fails without it.
- No real identifiers anywhere: fixtures use example.org, 192.0.2.0/24, 2001:db8::/32 and invented
  names.
- Test keys, host keys and the test SSH server are generated at run time. Never commit a private
  key, host key, `known_hosts` entry, certificate or recorded session, not even a throwaway one.
- The vault and audit client stubs in `gen/go/thirdparty/` are generated from the commits pinned
  in `proto-refs.env` (see docs/api.md, "Calling other services"); never import another
  service's Go module.
- The lint config exempts `HandlerWithConfig` in `internal/wsproxy` from the complexity linters; if
  you split it, keep the teardown (zeroize, remove from the store, audit) on every exit path.
