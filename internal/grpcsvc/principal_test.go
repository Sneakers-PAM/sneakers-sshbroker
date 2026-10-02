// Copyright 2026 The Sneakers-PAM Authors
// SPDX-License-Identifier: Apache-2.0

package grpcsvc

import (
	"context"
	"sync"
	"testing"

	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	sshbrokerv1 "github.com/Sneakers-PAM/sneakers-sshbroker/gen/go/sneakers/sshbroker/v1"
	auditv1 "github.com/Sneakers-PAM/sneakers-sshbroker/gen/go/thirdparty/audit/v1"
	"github.com/Sneakers-PAM/sneakers-sshbroker/internal/audit"
	"github.com/Sneakers-PAM/sneakers-sshbroker/internal/session"
)

type recordingAudit struct {
	auditv1.AuditServiceClient
	mu     sync.Mutex
	events []*auditv1.RecordEventRequest
}

func (r *recordingAudit) RecordEvent(_ context.Context, in *auditv1.RecordEventRequest, _ ...grpc.CallOption) (*auditv1.RecordEventResponse, error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.events = append(r.events, in)
	return &auditv1.RecordEventResponse{}, nil
}

// TestCreateSessionRefusesNonHumanPrincipals: brokered sessions are for a
// person in the web app only. A personal token (MCP or agent), a service
// account or a workload is refused on both paths, no ticket is minted, and
// the refusal is audited.
func TestCreateSessionRefusesNonHumanPrincipals(t *testing.T) {
	kinds := []sshbrokerv1.PrincipalKind{
		sshbrokerv1.PrincipalKind_PRINCIPAL_KIND_USER_TOKEN,
		sshbrokerv1.PrincipalKind_PRINCIPAL_KIND_SERVICE_ACCOUNT,
		sshbrokerv1.PrincipalKind_PRINCIPAL_KIND_WORKLOAD,
	}
	for _, kind := range kinds {
		for _, inline := range []bool{false, true} {
			name := kind.String()
			if inline {
				name += "/inline"
			}
			t.Run(name, func(t *testing.T) {
				store := session.NewStore()
				defer store.Close()
				rec := &recordingAudit{}
				b := NewBroker(store, audit.New(rec), "ws://localhost:9097/ssh/session")
				req := &sshbrokerv1.CreateSessionRequest{
					Host: "192.0.2.1", Port: 22, Username: "root", ActorUserId: "actor-1",
					SecretId: "secret-1", TargetId: "target-1",
					Actor: &sshbrokerv1.ActorContext{UserId: "actor-1", PrincipalKind: kind},
				}
				if inline {
					req.PrivateKey = "PEM"
				}
				_, err := b.CreateSession(context.Background(), req)
				if status.Code(err) != codes.PermissionDenied {
					t.Fatalf("code = %v, want PermissionDenied (err %v)", status.Code(err), err)
				}
				if len(rec.events) != 1 || rec.events[0].GetAction() != "session.refuse" {
					t.Fatalf("audit events = %v, want one session.refuse", rec.events)
				}
				ev := rec.events[0]
				if ev.GetActorUserId() != "actor-1" || ev.GetSubject() != "secret-1" ||
					ev.GetAttributes()["reason"] != "principal kind not allowed" ||
					ev.GetAttributes()["principal_kind"] != kind.String() {
					t.Fatalf("audit event = %v", ev)
				}
			})
		}
	}
}

// TestCreateSessionAcceptsHumanPrincipal: the default kind (HUMAN, also what
// a caller that predates the field sends) still gets a ticket.
func TestCreateSessionAcceptsHumanPrincipal(t *testing.T) {
	store := session.NewStore()
	defer store.Close()
	rec := &recordingAudit{}
	b := NewBroker(store, audit.New(rec), "ws://localhost:9097/ssh/session")
	resp, err := b.CreateSession(context.Background(), &sshbrokerv1.CreateSessionRequest{
		Host: "192.0.2.1", Port: 22, Username: "root", ActorUserId: "actor-1", SecretId: "secret-1",
		Actor: &sshbrokerv1.ActorContext{UserId: "actor-1", PrincipalKind: sshbrokerv1.PrincipalKind_PRINCIPAL_KIND_HUMAN},
	})
	if err != nil || resp.GetTicket() == "" {
		t.Fatalf("human refused: resp=%v err=%v", resp, err)
	}
	if len(rec.events) != 1 || rec.events[0].GetAction() != "session.start" {
		t.Fatalf("audit events = %v, want one session.start", rec.events)
	}
}
