// Copyright 2026 The Sneakers-PAM Authors
// SPDX-License-Identifier: Apache-2.0

package grpcsvc

import (
	"context"
	"time"

	"golang.org/x/crypto/ssh"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	sshbrokerv1 "github.com/Sneakers-PAM/sneakers-sshbroker/gen/go/sneakers/sshbroker/v1"
	"github.com/Sneakers-PAM/sneakers-sshbroker/internal/audit"
	"github.com/Sneakers-PAM/sneakers-sshbroker/internal/safeconv"
	"github.com/Sneakers-PAM/sneakers-sshbroker/internal/session"
)

// Broker implements sshbrokerv1.SSHBrokerServiceServer. It issues single-use
// WS tickets backed by an in-memory session.Store; key material never
// leaves process memory and is never logged.
type Broker struct {
	sshbrokerv1.UnimplementedSSHBrokerServiceServer

	store  session.TicketStore
	audit  *audit.Emitter
	wsBase string
}

// readiness is implemented by a ticket store that can be not ready yet (the
// composite with Redis configured, before Redis answers).
type readiness interface{ Ready() bool }

// NewBroker constructs a Broker over the given (shared) ticket store, audit
// emitter, and base WS URL returned to callers.
func NewBroker(store session.TicketStore, aud *audit.Emitter, wsBase string) *Broker {
	return &Broker{store: store, audit: aud, wsBase: wsBase}
}

// CreateSession validates the request, creates a pending session ticket, and
// emits a best-effort session.start audit event. It never logs key material.
//
// Two forms are accepted (see the contract): the reference form (no
// private_key; secret_id + actor identify the key to reveal from the vault at
// redeem time) and the inline form (private_key supplied for back-compat).
func (b *Broker) CreateSession(ctx context.Context, req *sshbrokerv1.CreateSessionRequest) (*sshbrokerv1.CreateSessionResponse, error) {
	if r, ok := b.store.(readiness); ok && !r.Ready() {
		return nil, status.Error(codes.Unavailable, "ticket store not ready")
	}
	if req.GetHost() == "" {
		return nil, status.Error(codes.InvalidArgument, "host is required")
	}
	if req.GetUsername() == "" {
		return nil, status.Error(codes.InvalidArgument, "username is required")
	}
	if req.GetActorUserId() == "" {
		return nil, status.Error(codes.InvalidArgument, "actor_user_id is required")
	}
	// One of the two supply forms must be usable: an inline key, or a reference
	// (secret_id + an actor to reveal it with). Otherwise there is no way to
	// obtain key material at redeem time.
	if req.GetPrivateKey() == "" {
		if req.GetSecretId() == "" {
			return nil, status.Error(codes.InvalidArgument, "secret_id is required when private_key is omitted")
		}
		if req.GetActor().GetUserId() == "" {
			return nil, status.Error(codes.InvalidArgument, "actor.user_id is required when private_key is omitted")
		}
	}

	// Pins come from the vault, which checked them on save; a pin that does
	// not parse here means a caller bypassed that, so refuse the ticket.
	for i, k := range req.GetHostKeys() {
		if _, _, opts, rest, err := ssh.ParseAuthorizedKey([]byte(k)); err != nil || len(opts) > 0 || len(rest) > 0 {
			return nil, status.Errorf(codes.InvalidArgument, "host_keys[%d] is not an OpenSSH public key", i)
		}
	}

	ttl := time.Duration(req.GetTtlSeconds()) * time.Second

	id, ticket, expiresIn := b.store.Create(session.Params{
		Host:        req.GetHost(),
		Port:        req.GetPort(),
		Username:    req.GetUsername(),
		PrivateKey:  req.GetPrivateKey(),
		Passphrase:  req.GetPassphrase(),
		ActorUserID: req.GetActorUserId(),
		SecretID:    req.GetSecretId(),
		TargetID:    req.GetTargetId(),
		Actor: session.Actor{
			UserID:      req.GetActor().GetUserId(),
			IsSiteAdmin: req.GetActor().GetIsSiteAdmin(),
			IsRoot:      req.GetActor().GetIsRoot(),
			GroupNames:  req.GetActor().GetGroupNames(),
		},
		HostKeys: req.GetHostKeys(),
		TTL:      ttl,
	})
	if ticket == "" {
		return nil, status.Error(codes.Unavailable, "ticket store not ready")
	}

	b.audit.Start(ctx, req.GetActorUserId(), req.GetSecretId(), req.GetTargetId(), req.GetHost())

	return &sshbrokerv1.CreateSessionResponse{
		SessionId:        id,
		Ticket:           ticket,
		WsUrl:            b.wsBase,
		ExpiresInSeconds: safeconv.Int32(expiresIn),
	}, nil
}

// RegisterServer wires the sshbroker gRPC server into a grpc.Server. The
// standard gRPC health service is registered by internal/server.
func RegisterServer(gs *grpc.Server, b *Broker) {
	sshbrokerv1.RegisterSSHBrokerServiceServer(gs, b)
}
