// Copyright 2026 The Sneakers-PAM Authors
// SPDX-License-Identifier: Apache-2.0

package main

import (
	"context"
	"errors"

	"github.com/Bugs5382/go-buildinfo/health"
	workloadauth "github.com/Bugs5382/go-workload-identity"
	"github.com/Sneakers-PAM/sneakers-sshbroker/internal/server"
	"github.com/Sneakers-PAM/sneakers-sshbroker/internal/session"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

// readinessDeps are what the broker's readiness follows:
//
//   - valkey (only with REDIS_URL): required. Every reference ticket lives in
//     Redis, so a broker that can't reach it can't mint or redeem one.
//   - vault: optional. It's reached only when a reference ticket is redeemed
//     at WebSocket connect; CreateSession and inline-key sessions work without
//     it, so its outage degrades the broker rather than taking it out.
//   - audit: optional. Session events are best effort; a session never fails
//     because audit is down.
//   - workload-identity (only when service-to-service authentication is on):
//     required. No caller can be checked before its key set has loaded.
func readinessDeps(store *session.Composite, redisSet bool, vault, audit server.HealthChecker, workloadVerifier *workloadauth.Verifier) []health.Dependency {
	var deps []health.Dependency
	if redisSet {
		deps = append(deps, health.Dependency{Name: "valkey", Required: true, Check: func(ctx context.Context) error {
			err := store.Ping(ctx)
			if errors.Is(err, session.ErrSharedNotAttached) {
				return status.Error(codes.Unavailable, "ticket store not connected")
			}
			return err
		}})
	}
	deps = append(deps,
		health.Dependency{Name: "vault", Check: server.GRPCPeer(vault)},
		health.Dependency{Name: "audit", Check: server.GRPCPeer(audit)},
	)
	if workloadVerifier != nil {
		deps = append(deps, server.WorkloadIdentity(workloadVerifier))
	}
	return deps
}
