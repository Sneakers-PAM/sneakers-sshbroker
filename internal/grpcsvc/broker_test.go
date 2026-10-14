// Copyright 2026 The Sneakers-PAM Authors
// SPDX-License-Identifier: Apache-2.0

package grpcsvc

import (
	"context"
	"testing"
	"time"

	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	sshbrokerv1 "github.com/Sneakers-PAM/sneakers-sshbroker/gen/go/sneakers/sshbroker/v1"
	"github.com/Sneakers-PAM/sneakers-sshbroker/internal/audit"
	"github.com/Sneakers-PAM/sneakers-sshbroker/internal/session"
)

// nilAudit is a nil-tolerant audit emitter: its client is nil, so Start/End
// are no-ops (best-effort emission must never fail a session).
func nilAudit() *audit.Emitter { return audit.New(nil) }

func TestCreateSessionReturnsConsumableTicket(t *testing.T) {
	store := session.NewStore()
	b := NewBroker(store, nilAudit(), "ws://localhost:9097/ssh/session")

	resp, err := b.CreateSession(context.Background(), &sshbrokerv1.CreateSessionRequest{
		Host:        "192.0.2.1",
		Port:        22,
		Username:    "root",
		PrivateKey:  "PEM",
		ActorUserId: "actor-1",
		SecretId:    "secret-1",
		TargetId:    "target-1",
		HostKeys:    []string{pinnedHostKey},
	})
	if err != nil {
		t.Fatalf("CreateSession error: %v", err)
	}
	if resp.GetTicket() == "" || resp.GetSessionId() == "" {
		t.Fatalf("expected non-empty ticket and session id, got %+v", resp)
	}
	if resp.GetWsUrl() != "ws://localhost:9097/ssh/session" {
		t.Fatalf("unexpected ws_url: %q", resp.GetWsUrl())
	}
	if resp.GetExpiresInSeconds() <= 0 {
		t.Fatalf("expected positive expires_in_seconds, got %d", resp.GetExpiresInSeconds())
	}

	sess, ok := store.Consume(resp.GetTicket())
	if !ok || sess.Host != "192.0.2.1" {
		t.Fatalf("ticket not consumable from shared store: ok=%v sess=%+v", ok, sess)
	}
	if _, ok := store.Consume(resp.GetTicket()); ok {
		t.Fatal("ticket must be single-use")
	}
}

func TestCreateSessionReferencePath(t *testing.T) {
	store := session.NewStore()
	b := NewBroker(store, nilAudit(), "ws://localhost:9097/ssh/session")

	// No private_key: a reference session carrying secret_id + actor.
	resp, err := b.CreateSession(context.Background(), &sshbrokerv1.CreateSessionRequest{
		Host:        "192.0.2.1",
		Port:        22,
		Username:    "root",
		ActorUserId: "actor-1",
		SecretId:    "secret-1",
		TargetId:    "target-1",
		HostKeys:    []string{pinnedHostKey},
		Actor: &sshbrokerv1.ActorContext{
			UserId:      "actor-1",
			IsSiteAdmin: true,
			GroupNames:  []string{"ops"},
		},
	})
	if err != nil {
		t.Fatalf("reference CreateSession error: %v", err)
	}
	sess, ok := store.Consume(resp.GetTicket())
	if !ok {
		t.Fatal("reference ticket not consumable")
	}
	if sess.HasKey() {
		t.Fatal("reference session must not carry key material")
	}
	if sess.SecretID != "secret-1" || sess.Actor.UserID != "actor-1" ||
		!sess.Actor.IsSiteAdmin || len(sess.Actor.GroupNames) != 1 {
		t.Fatalf("actor/secret not carried into session: %+v", sess.Actor)
	}
}

// TestCreateSessionPasswordAuthReference covers #319: a password secret's
// CreateSession request carries password_auth=true and no private_key, and
// the session it mints carries AuthKindPassword through to the open path.
func TestCreateSessionPasswordAuthReference(t *testing.T) {
	store := session.NewStore()
	rec := &recordingAudit{}
	b := NewBroker(store, audit.New(rec), "ws://localhost:9097/ssh/session")

	resp, err := b.CreateSession(context.Background(), &sshbrokerv1.CreateSessionRequest{
		Host:         "192.0.2.1",
		Port:         22,
		Username:     "root",
		PasswordAuth: true,
		ActorUserId:  "actor-1",
		SecretId:     "secret-1",
		TargetId:     "target-1",
		HostKeys:     []string{pinnedHostKey},
		Actor:        &sshbrokerv1.ActorContext{UserId: "actor-1"},
	})
	if err != nil {
		t.Fatalf("CreateSession error: %v", err)
	}
	sess, ok := store.Consume(resp.GetTicket())
	if !ok {
		t.Fatal("password reference ticket not consumable")
	}
	if sess.AuthKind != session.AuthKindPassword {
		t.Fatalf("AuthKind = %v, want AuthKindPassword", sess.AuthKind)
	}
	if sess.HasKey() || sess.HasPassword() {
		t.Fatal("reference session must not carry credential material yet")
	}

	deadline := time.Now().Add(2 * time.Second)
	for time.Now().Before(deadline) {
		rec.mu.Lock()
		for _, e := range rec.events {
			if e.GetAction() == "session.start" {
				if got := e.GetAttributes()["auth_kind"]; got != "password" {
					t.Fatalf("session.start auth_kind = %q, want password", got)
				}
				rec.mu.Unlock()
				return
			}
		}
		rec.mu.Unlock()
		time.Sleep(10 * time.Millisecond)
	}
	t.Fatal("no session.start audit event")
}

// password_auth and private_key are mutually exclusive: a password secret is
// always revealed by reference, never passed inline.
func TestCreateSessionPasswordAuthRejectsInlineKey(t *testing.T) {
	store := session.NewStore()
	b := NewBroker(store, nilAudit(), "ws://localhost:9097/ssh/session")

	_, err := b.CreateSession(context.Background(), &sshbrokerv1.CreateSessionRequest{
		Host: "192.0.2.1", Username: "root", PrivateKey: "PEM", PasswordAuth: true,
		ActorUserId: "actor-1",
	})
	if status.Code(err) != codes.InvalidArgument {
		t.Fatalf("expected InvalidArgument, got %v", err)
	}
}

func TestCreateSessionReferenceRequiresSecretAndActor(t *testing.T) {
	store := session.NewStore()
	b := NewBroker(store, nilAudit(), "ws://localhost:9097/ssh/session")

	cases := []struct {
		name string
		req  *sshbrokerv1.CreateSessionRequest
	}{
		{"no key, no secret", &sshbrokerv1.CreateSessionRequest{
			Host: "h", Username: "u", ActorUserId: "a",
			Actor: &sshbrokerv1.ActorContext{UserId: "a"},
		}},
		{"no key, no actor", &sshbrokerv1.CreateSessionRequest{
			Host: "h", Username: "u", ActorUserId: "a", SecretId: "s",
		}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if _, err := b.CreateSession(context.Background(), tc.req); status.Code(err) != codes.InvalidArgument {
				t.Fatalf("expected InvalidArgument, got %v", err)
			}
		})
	}
}

func TestCreateSessionValidatesRequiredFields(t *testing.T) {
	store := session.NewStore()
	b := NewBroker(store, nilAudit(), "ws://localhost:9097/ssh/session")

	newReq := func() *sshbrokerv1.CreateSessionRequest {
		return &sshbrokerv1.CreateSessionRequest{
			Host:        "192.0.2.1",
			Username:    "root",
			PrivateKey:  "PEM",
			ActorUserId: "actor-1",
		}
	}

	cases := []struct {
		name   string
		mutate func(*sshbrokerv1.CreateSessionRequest)
	}{
		{"missing host", func(r *sshbrokerv1.CreateSessionRequest) { r.Host = "" }},
		{"missing username", func(r *sshbrokerv1.CreateSessionRequest) { r.Username = "" }},
		{"missing private key", func(r *sshbrokerv1.CreateSessionRequest) { r.PrivateKey = "" }},
		{"missing actor user id", func(r *sshbrokerv1.CreateSessionRequest) { r.ActorUserId = "" }},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			req := newReq()
			tc.mutate(req)
			_, err := b.CreateSession(context.Background(), req)
			if err == nil {
				t.Fatal("expected error, got nil")
			}
			if status.Code(err) != codes.InvalidArgument {
				t.Fatalf("expected InvalidArgument, got %v", err)
			}
		})
	}
}

// TestCreateSessionPort covers #22: port 0 must not be dialled as port 0 (it
// defaults to 22, the SSH convention also used by ScanHostKey), and an
// out-of-range port is refused rather than passed through to the dialer.
func TestCreateSessionPort(t *testing.T) {
	newReq := func(port int32) *sshbrokerv1.CreateSessionRequest {
		return &sshbrokerv1.CreateSessionRequest{
			Host: "192.0.2.1", Port: port, Username: "root", PrivateKey: "PEM",
			ActorUserId: "actor-1", SecretId: "secret-1", TargetId: "target-1",
			HostKeys: []string{pinnedHostKey},
		}
	}

	t.Run("zero defaults to 22", func(t *testing.T) {
		store := session.NewStore()
		b := NewBroker(store, nilAudit(), "ws://localhost:9097/ssh/session")
		resp, err := b.CreateSession(context.Background(), newReq(0))
		if err != nil {
			t.Fatalf("CreateSession error: %v", err)
		}
		sess, ok := store.Consume(resp.GetTicket())
		if !ok || sess.Port != 22 {
			t.Fatalf("port 0 stored as %d, want 22 (ok=%v)", sess.Port, ok)
		}
	})

	t.Run("out of range refused", func(t *testing.T) {
		store := session.NewStore()
		b := NewBroker(store, nilAudit(), "ws://localhost:9097/ssh/session")
		_, err := b.CreateSession(context.Background(), newReq(70000))
		if status.Code(err) != codes.InvalidArgument {
			t.Fatalf("expected InvalidArgument for an out-of-range port, got %v", err)
		}
	})
}
