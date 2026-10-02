// Copyright 2026 The Sneakers-PAM Authors
// SPDX-License-Identifier: Apache-2.0

package grpcsvc

import (
	"context"

	log "github.com/Bugs5382/go-log"
	"google.golang.org/grpc"

	sshbrokerv1 "github.com/Sneakers-PAM/sneakers-sshbroker/gen/go/sneakers/sshbroker/v1"
	"github.com/Sneakers-PAM/sneakers-sshbroker/internal/audit"
	"github.com/Sneakers-PAM/sneakers-sshbroker/internal/workloadauth"
)

// CallerGateway is the only caller of the broker's gRPC API: the gateway,
// service account sneakers-gateway.
const CallerGateway = "gateway"

// CallerPolicy is the broker's per-method allow-list. Only the gateway may
// call CreateSession, and it passes the signed-in user's actor, which the
// broker forwards to the vault. Every other caller, the MCP server included,
// is refused.
func CallerPolicy() workloadauth.Policy {
	return workloadauth.Policy{
		sshbrokerv1.SSHBrokerService_CreateSession_FullMethodName: {CallerGateway: workloadauth.OnBehalf},
	}
}

// AuthServerOptions returns the interceptors that check every call's workload
// token against CallerPolicy, auditing each refusal as session.refuse.
func AuthServerOptions(v workloadauth.TokenVerifier, aud *audit.Emitter, lg log.Logger) []grpc.ServerOption {
	hook := workloadauth.WithDenyHook(func(ctx context.Context, d workloadauth.Denial) {
		req, _ := d.Request.(*sshbrokerv1.CreateSessionRequest)
		aud.Refused(ctx, req.GetActorUserId(), req.GetSecretId(), req.GetTargetId(), d.Reason, map[string]string{
			"caller": d.Caller.Name,
			"method": d.Method,
			"code":   d.Code.String(),
		})
	})
	p := CallerPolicy()
	return []grpc.ServerOption{
		grpc.ChainUnaryInterceptor(workloadauth.UnaryServerInterceptor(v, p, lg, hook)),
		grpc.ChainStreamInterceptor(workloadauth.StreamServerInterceptor(v, p, lg, hook)),
	}
}
