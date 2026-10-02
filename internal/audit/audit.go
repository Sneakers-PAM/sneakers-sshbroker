// Copyright 2026 The Sneakers-PAM Authors
// SPDX-License-Identifier: Apache-2.0

// Package audit emits session.start/session.end audit events for the
// sshbroker. Emission is best-effort: a session must never fail because the
// audit service is unreachable, but failures are logged.
//
// NEVER put key material (private key, passphrase) into audit attributes.
package audit

import (
	"context"
	"strconv"
	"time"

	log "github.com/Bugs5382/go-log"
	auditv1 "github.com/Sneakers-PAM/sneakers-sshbroker/gen/go/thirdparty/audit/v1"
)

// logger is package-scoped (type inferred from log.New) so callers never
// need to import zerolog directly.
var logger = log.New("sshbroker-audit")

// Emitter wraps an audit service client to record sshbroker session
// lifecycle events. It is safe for concurrent use (the underlying gRPC
// client is).
type Emitter struct {
	client auditv1.AuditServiceClient
}

// New returns an Emitter backed by the given audit service client.
func New(client auditv1.AuditServiceClient) *Emitter {
	return &Emitter{client: client}
}

// Start records a session.start audit event. Best-effort: errors are logged
// and swallowed.
func (e *Emitter) Start(ctx context.Context, actorUserID, secretID, targetID, host string) {
	e.emit(ctx, &auditv1.RecordEventRequest{
		Tier:        auditv1.Tier_TIER_AUDIT,
		Action:      "session.start",
		ActorUserId: actorUserID,
		Subject:     secretID,
		Sensitive:   true,
		Attributes: map[string]string{
			"host":      host,
			"target_id": targetID,
		},
		OccurredAt: time.Now().UTC().Format(time.RFC3339),
	})
}

// End records a session.end audit event. Best-effort: errors are logged and
// swallowed.
func (e *Emitter) End(ctx context.Context, actorUserID, secretID, targetID string, dur time.Duration, reason string) {
	e.emit(ctx, &auditv1.RecordEventRequest{
		Tier:        auditv1.Tier_TIER_AUDIT,
		Action:      "session.end",
		ActorUserId: actorUserID,
		Subject:     secretID,
		Sensitive:   true,
		Attributes: map[string]string{
			"target_id":   targetID,
			"duration_ms": strconv.FormatInt(dur.Milliseconds(), 10),
			"reason":      reason,
		},
		OccurredAt: time.Now().UTC().Format(time.RFC3339),
	})
}

func (e *Emitter) emit(ctx context.Context, req *auditv1.RecordEventRequest) {
	if e == nil || e.client == nil {
		return
	}
	if _, err := e.client.RecordEvent(ctx, req); err != nil {
		logger.Error().Err(err).Str("action", req.Action).Msg("audit emit failed")
	}
}
