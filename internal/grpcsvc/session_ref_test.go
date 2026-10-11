// Copyright 2026 The Sneakers-PAM Authors
// SPDX-License-Identifier: Apache-2.0

package grpcsvc

import (
	"context"
	"testing"

	sshbrokerv1 "github.com/Sneakers-PAM/sneakers-sshbroker/gen/go/sneakers/sshbroker/v1"
	"github.com/Sneakers-PAM/sneakers-sshbroker/internal/session"
)

// A reference session keeps the person's web session reference, so the key
// reveal at redeem is made for that person's own session.
func TestCreateSessionKeepsTheWebSessionRef(t *testing.T) {
	store := session.NewStore()
	b := NewBroker(store, nilAudit(), "ws://localhost:9097/ssh/session")
	resp, err := b.CreateSession(context.Background(), &sshbrokerv1.CreateSessionRequest{
		Host: "192.0.2.1", Port: 22, Username: "root", ActorUserId: "actor-1", SecretId: "secret-1", TargetId: "target-1",
		Actor: &sshbrokerv1.ActorContext{UserId: "actor-1", SessionRef: "ref-web-1"},
	})
	if err != nil {
		t.Fatal(err)
	}
	sess, ok := store.Consume(resp.GetTicket())
	if !ok || sess.Actor.SessionRef != "ref-web-1" {
		t.Fatalf("session actor = %+v", sess.Actor)
	}
}
