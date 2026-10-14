// Copyright 2026 The Sneakers-PAM Authors
// SPDX-License-Identifier: Apache-2.0

package grpcsvc

import (
	"context"
	"time"

	log "github.com/Bugs5382/go-log"
	"golang.org/x/crypto/ssh"
	"google.golang.org/genproto/googleapis/rpc/errdetails"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	sshbrokerv1 "github.com/Sneakers-PAM/sneakers-sshbroker/gen/go/sneakers/sshbroker/v1"
	"github.com/Sneakers-PAM/sneakers-sshbroker/internal/audit"
	"github.com/Sneakers-PAM/sneakers-sshbroker/internal/safeconv"
	"github.com/Sneakers-PAM/sneakers-sshbroker/internal/session"
)

var logger = log.New("sshbroker-grpc")

// ErrorDomain is the google.rpc.ErrorInfo domain of the broker's coded
// refusals; the gateway passes reasons in a sneakers.* domain to its clients.
const ErrorDomain = "sneakers.sshbroker"

// ReasonHostKeyNotPinned is the refusal reason for a target with no pinned
// SSH host key, and HostKeyNotPinnedMessage its one-line message.
const (
	ReasonHostKeyNotPinned  = "HOST_KEY_NOT_PINNED"
	HostKeyNotPinnedMessage = "host key not pinned for this target: an admin pins it on the target first; no connection was made"
)

// Broker implements sshbrokerv1.SSHBrokerServiceServer. It issues single-use
// WS tickets backed by an in-memory session.Store; key material never
// leaves process memory and is never logged.
type Broker struct {
	sshbrokerv1.UnimplementedSSHBrokerServiceServer

	store  session.TicketStore
	audit  *audit.Emitter
	wsBase string

	scanLimit   *scanLimiter
	scanTimeout time.Duration
}

// readiness is implemented by a ticket store that can be not ready yet (the
// composite with Redis configured, before Redis answers).
type readiness interface{ Ready() bool }

// NewBroker constructs a Broker over the given (shared) ticket store, audit
// emitter, and base WS URL returned to callers.
func NewBroker(store session.TicketStore, aud *audit.Emitter, wsBase string) *Broker {
	return &Broker{store: store, audit: aud, wsBase: wsBase, scanLimit: newScanLimiter(), scanTimeout: defaultScanTimeout}
}

// CreateSession validates the request, creates a pending session ticket, and
// emits a best-effort session.start audit event. It never logs key material.
//
// Two forms are accepted (see the contract): the reference form (no
// private_key; secret_id + actor identify the key to reveal from the vault at
// redeem time) and the inline form (private_key supplied for back-compat).
func (b *Broker) CreateSession(ctx context.Context, req *sshbrokerv1.CreateSessionRequest) (*sshbrokerv1.CreateSessionResponse, error) {
	// Only a person in the web app starts a brokered session: never an MCP
	// or agent token, a service account or a workload.
	if kind := req.GetActor().GetPrincipalKind(); kind != sshbrokerv1.PrincipalKind_PRINCIPAL_KIND_HUMAN {
		logger.Warn().Str("actor_user_id", req.GetActorUserId()).Str("principal_kind", kind.String()).
			Str("target_id", req.GetTargetId()).Msg("session refused: principal kind not allowed")
		b.audit.Refused(ctx, req.GetActorUserId(), req.GetSecretId(), req.GetTargetId(),
			"principal kind not allowed", map[string]string{"principal_kind": kind.String()})
		return nil, status.Error(codes.PermissionDenied, "brokered sessions are for people in the web app only")
	}
	if r, ok := b.store.(readiness); ok && !r.Ready() {
		return nil, status.Error(codes.Unavailable, "ticket store not ready")
	}
	port, err := validateCreate(req)
	if err != nil {
		return nil, err
	}
	// The dial refuses an unpinned host too, but only once the browser's
	// WebSocket arrives; refusing here gives the reason with no ticket and
	// no socket at all.
	if len(req.GetHostKeys()) == 0 {
		return nil, b.refuseUnpinned(ctx, req)
	}
	ttl := time.Duration(req.GetTtlSeconds()) * time.Second
	authKind := session.AuthKindPublicKey
	if req.GetPasswordAuth() {
		authKind = session.AuthKindPassword
	}

	id, ticket, expiresIn, err := b.store.Create(session.Params{
		Host:        req.GetHost(),
		Port:        port,
		Username:    req.GetUsername(),
		PrivateKey:  req.GetPrivateKey(),
		Passphrase:  req.GetPassphrase(),
		AuthKind:    authKind,
		ActorUserID: req.GetActorUserId(),
		SecretID:    req.GetSecretId(),
		TargetID:    req.GetTargetId(),
		Actor: session.Actor{
			UserID:      req.GetActor().GetUserId(),
			IsSiteAdmin: req.GetActor().GetIsSiteAdmin(),
			IsRoot:      req.GetActor().GetIsRoot(),
			GroupNames:  req.GetActor().GetGroupNames(),
			SessionRef:  req.GetActor().GetSessionRef(),
		},
		HostKeys: req.GetHostKeys(),
		TTL:      ttl,
	})
	if err != nil {
		logger.Error().Err(err).Str("actor_user_id", req.GetActorUserId()).Str("target_id", req.GetTargetId()).Msg("ticket store create failed")
		return nil, status.Error(codes.Unavailable, "ticket store not ready")
	}
	if ticket == "" {
		return nil, status.Error(codes.Unavailable, "ticket store not ready")
	}

	authKindLabel := "publickey"
	if authKind == session.AuthKindPassword {
		authKindLabel = "password"
	}
	b.audit.Start(ctx, req.GetActorUserId(), req.GetSecretId(), req.GetTargetId(), req.GetHost(), authKindLabel)
	logger.Info().
		Str("session_id", id).
		Str("host", req.GetHost()).
		Int32("port", port).
		Str("target_id", req.GetTargetId()).
		Str("secret_id", req.GetSecretId()).
		Str("actor_user_id", req.GetActorUserId()).
		Int("host_keys", len(req.GetHostKeys())).
		Bool("reference", req.GetPrivateKey() == "").
		Str("auth_kind", authKindLabel).
		Dur("ttl", ttl).
		Msg("ssh session ticket issued")

	return &sshbrokerv1.CreateSessionResponse{
		SessionId:        id,
		Ticket:           ticket,
		WsUrl:            b.wsBase,
		ExpiresInSeconds: safeconv.Int32(expiresIn),
	}, nil
}

// refuseUnpinned audits and logs a CreateSession for a target with no pinned
// host key and returns its FailedPrecondition, with the reason and target id
// in an ErrorInfo.
func (b *Broker) refuseUnpinned(ctx context.Context, req *sshbrokerv1.CreateSessionRequest) error {
	logger.Info().Str("actor_user_id", req.GetActorUserId()).Str("target_id", req.GetTargetId()).
		Str("secret_id", req.GetSecretId()).Str("host", req.GetHost()).Msg("session refused: host key not pinned")
	b.audit.Refused(ctx, req.GetActorUserId(), req.GetSecretId(), req.GetTargetId(), "host key not pinned", nil)
	// WithDetails fails only for an OK status or a detail that can't be
	// marshalled, neither of which this is.
	st, _ := status.New(codes.FailedPrecondition, HostKeyNotPinnedMessage).WithDetails(&errdetails.ErrorInfo{
		Domain:   ErrorDomain,
		Reason:   ReasonHostKeyNotPinned,
		Metadata: map[string]string{"target_id": req.GetTargetId()},
	})
	return st.Err()
}

// validateCreate checks a CreateSession request's inputs and returns the
// port to dial (22 when unset).
func validateCreate(req *sshbrokerv1.CreateSessionRequest) (int32, error) {
	if req.GetHost() == "" {
		return 0, status.Error(codes.InvalidArgument, "host is required")
	}
	if req.GetUsername() == "" {
		return 0, status.Error(codes.InvalidArgument, "username is required")
	}
	if req.GetActorUserId() == "" {
		return 0, status.Error(codes.InvalidArgument, "actor_user_id is required")
	}
	if err := validateCredentialForm(req); err != nil {
		return 0, err
	}
	if err := validateHostKeys(req.GetHostKeys()); err != nil {
		return 0, err
	}

	port := req.GetPort()
	if port == 0 {
		port = 22
	}
	if port < 1 || port > 65535 {
		return 0, status.Error(codes.InvalidArgument, "port must be between 1 and 65535")
	}
	return port, nil
}

// validateCredentialForm checks that the request supplies a usable
// credential: an inline key, or a reference (secret_id + an actor to reveal
// it with, as a key or a password) -- otherwise there is no way to obtain
// credential material at redeem time. password_auth has no inline form: a
// password secret is always revealed from the vault by reference, never
// passed as private_key.
func validateCredentialForm(req *sshbrokerv1.CreateSessionRequest) error {
	if req.GetPasswordAuth() && req.GetPrivateKey() != "" {
		return status.Error(codes.InvalidArgument, "private_key and password_auth are mutually exclusive")
	}
	if req.GetPrivateKey() != "" {
		return nil
	}
	if req.GetSecretId() == "" {
		return status.Error(codes.InvalidArgument, "secret_id is required when private_key is omitted")
	}
	if req.GetActor().GetUserId() == "" {
		return status.Error(codes.InvalidArgument, "actor.user_id is required when private_key is omitted")
	}
	return nil
}

// validateHostKeys checks that every pin is an OpenSSH public key with no
// options or trailing data. Pins come from the vault, which checked them on
// save; a pin that does not parse here means a caller bypassed that, so
// refuse the ticket.
func validateHostKeys(hostKeys []string) error {
	for i, k := range hostKeys {
		if _, _, opts, rest, err := ssh.ParseAuthorizedKey([]byte(k)); err != nil || len(opts) > 0 || len(rest) > 0 {
			return status.Errorf(codes.InvalidArgument, "host_keys[%d] is not an OpenSSH public key", i)
		}
	}
	return nil
}

// RegisterServer wires the sshbroker gRPC server into a grpc.Server. The
// standard gRPC health service is registered by internal/server.
func RegisterServer(gs *grpc.Server, b *Broker) {
	sshbrokerv1.RegisterSSHBrokerServiceServer(gs, b)
}
