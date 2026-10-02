# Contributing to sneakers-sshbroker

This repository follows the Sneakers-PAM workflow in the org
[CONTRIBUTING.md](https://github.com/Sneakers-PAM/.github/blob/main/.github/CONTRIBUTING.md):
issues from a template, a branch per issue, Conventional Commits, squash-merged PRs, and a
[DCO](DCO) sign-off (`git commit -s`) on every commit.

## Working on this repo

- Build and test: see [README.md](README.md). The tests start an in-process Redis and an
  in-process SSH server, so `go test ./...` needs nothing else running.
- Changing the API: edit `proto/sneakers/sshbroker/v1/sshbroker.proto`, then run `buf generate`
  (with the `protoc-gen-go` and `protoc-gen-go-grpc` versions pinned in
  `.github/workflows/job-go-lang-ci.yaml`) and commit the result under `gen/go`. CI fails if the
  generated code is stale or the change breaks the API.
- Every `.go` and `.proto` file starts with the Apache-2.0 header:

  ```
  // Copyright 2026 The Sneakers-PAM Authors
  // SPDX-License-Identifier: Apache-2.0
  ```

- No real names, hosts, addresses or other identifiers in code, tests, fixtures or docs. Use
  example.org, 192.0.2.0/24, 2001:db8::/32 and invented names.
- No key material in the tree: generate SSH keys, host keys and certificates inside the tests at
  run time. Never commit a private key, a `known_hosts` entry or a recorded session.
