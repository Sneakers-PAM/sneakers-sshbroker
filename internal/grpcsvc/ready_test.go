// Copyright 2026 The Sneakers-PAM Authors
// SPDX-License-Identifier: Apache-2.0

package grpcsvc

import (
	"context"
	"testing"

	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	sshbrokerv1 "github.com/Sneakers-PAM/sneakers-sshbroker/gen/go/sneakers/sshbroker/v1"
	"github.com/Sneakers-PAM/sneakers-sshbroker/internal/session"
)

// TestCreateSessionUnavailableUntilSharedStoreReady: with Redis configured but
// not answering yet, the broker refuses to mint tickets (Unavailable) rather
// than keeping them in one pod's memory.
func TestCreateSessionUnavailableUntilSharedStoreReady(t *testing.T) {
	store := session.NewRequiredComposite(session.NewStore())
	defer store.Close()
	b := NewBroker(store, nilAudit(), "ws://localhost:9097/ssh/session")

	reqs := map[string]*sshbrokerv1.CreateSessionRequest{
		"reference": {
			Host: "192.0.2.1", Port: 22, Username: "root", ActorUserId: "actor-1",
			SecretId: "secret-1", Actor: &sshbrokerv1.ActorContext{UserId: "actor-1"},
		},
		"inline": {
			Host: "192.0.2.1", Port: 22, Username: "root", ActorUserId: "actor-1", PrivateKey: "PEM",
		},
	}
	for name, req := range reqs {
		t.Run(name, func(t *testing.T) {
			_, err := b.CreateSession(context.Background(), req)
			if status.Code(err) != codes.Unavailable {
				t.Fatalf("code = %v, want Unavailable (err %v)", status.Code(err), err)
			}
		})
	}
}
