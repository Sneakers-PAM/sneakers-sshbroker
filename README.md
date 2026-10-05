# SSH Broker Service 🔑

> 🔌 Brokered SSH sessions for the in-browser terminal: the browser gets a terminal, never the key.

The broker sits between the browser and the SSH targets. The gateway, having authorized the user,
calls `sneakers.sshbroker.v1.SSHBrokerService/CreateSession` over gRPC and gets back a single-use,
short-lived ticket and a WebSocket URL. The browser opens that URL with the ticket; the broker
consumes the ticket, gets the SSH key, dials the target, opens a PTY and a shell, and streams it
over the socket until either side closes.

## ✨ Highlights

- 🎟️ **Single-use tickets:** opaque random tokens with a short time to live (30 seconds by default), consumed on first use.
- 🗝️ **Key at connect time:** on the reference path the ticket holds only a secret id and the actor, and the broker reveals the key from the vault as that actor when the browser connects.
- 🔁 **Any replica:** reference tickets live in a shared Redis with no key material, so any broker replica can redeem them; without Redis it runs as a single replica.
- 🧹 **Zeroized keys:** key material stays in the memory of the process running the session and is wiped on every exit path; it's never logged.
- ⏱️ **Bounded sessions:** WebSocket ping and pong, SSH keepalives and an 8-hour cutoff end sessions whose peer has gone away.
- 📜 **Audited:** session start and end are sent to the audit service.
- 🔐 **Pinned host keys:** the broker connects only to a host that presents one of the target's pinned SSH host keys, and refuses unpinned targets.

- 🪪 **Gateway only:** every gRPC call carries the caller's Kubernetes workload identity, and only the gateway may create a session.

## ⚠️ Before production

Read [docs/runbook.md](docs/runbook.md) before you deploy it.

## 🚀 Run it

```bash
go run ./cmd/sshbroker
```

gRPC listens on port 9096 and HTTP (the WebSocket endpoint, `/health`, `/readyz` and `/livez`) on port 9097. With no
`REDIS_URL` the tickets stay in memory; with it, the broker is not ready until Redis answers. The
audit and vault services are optional for a local run: audit events that can't be sent are logged
and dropped, and a reference ticket fails without the vault.
[docs/configuration.md](docs/configuration.md) lists every setting.

Run the tests (they use an in-process Redis and an in-process SSH server with keys generated at run
time, so nothing else is needed):

```bash
go test ./...
```

## 🛠 Develop

```bash
task build    # go build ./...
task test     # go test ./...
task lint     # tests, gofmt check, golangci-lint and yamllint
task license  # check the Apache-2.0 headers (golic)
```

## 📚 Where to look

- [docs/configuration.md](docs/configuration.md): environment variables and fixed limits.
- [docs/api.md](docs/api.md): the gRPC API and the WebSocket protocol.
- [docs/runbook.md](docs/runbook.md): operating the service.
- [proto/sneakers/sshbroker/v1/sshbroker.proto](proto/sneakers/sshbroker/v1/sshbroker.proto): the API definition.

## ⚖️ License

Apache-2.0. See [LICENSE](LICENSE) and [NOTICE](NOTICE).
