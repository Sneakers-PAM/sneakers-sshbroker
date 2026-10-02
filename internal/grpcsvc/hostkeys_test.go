// Copyright 2026 The Sneakers-PAM Authors
// SPDX-License-Identifier: Apache-2.0

package grpcsvc

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"strings"
	"testing"

	"golang.org/x/crypto/ssh"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	sshbrokerv1 "github.com/Sneakers-PAM/sneakers-sshbroker/gen/go/sneakers/sshbroker/v1"
	"github.com/Sneakers-PAM/sneakers-sshbroker/internal/session"
)

func genHostKeyLine(t *testing.T) string {
	t.Helper()
	pub, _, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	sp, err := ssh.NewPublicKey(pub)
	if err != nil {
		t.Fatal(err)
	}
	return strings.TrimSpace(string(ssh.MarshalAuthorizedKey(sp)))
}

func TestCreateSessionCarriesHostKeys(t *testing.T) {
	store := session.NewStore()
	t.Cleanup(store.Close)
	b := NewBroker(store, nilAudit(), "ws://localhost:9097/ssh/session")
	keys := []string{genHostKeyLine(t), genHostKeyLine(t) + " second"}

	resp, err := b.CreateSession(context.Background(), &sshbrokerv1.CreateSessionRequest{
		Host: "192.0.2.1", Port: 22, Username: "root", ActorUserId: "actor-1",
		SecretId: "secret-1", TargetId: "target-1", Actor: &sshbrokerv1.ActorContext{UserId: "actor-1"},
		HostKeys: keys,
	})
	if err != nil {
		t.Fatalf("CreateSession: %v", err)
	}
	sess, ok := store.Consume(resp.GetTicket())
	if !ok {
		t.Fatal("ticket not consumable")
	}
	if strings.Join(sess.HostKeys, "|") != strings.Join(keys, "|") {
		t.Fatalf("host keys on ticket = %q, want %q", sess.HostKeys, keys)
	}
}

func TestCreateSessionRejectsUnparseableHostKey(t *testing.T) {
	store := session.NewStore()
	t.Cleanup(store.Close)
	b := NewBroker(store, nilAudit(), "ws://localhost:9097/ssh/session")
	for name, bad := range map[string]string{
		"garbage": "not a key",
		"options": "no-pty " + genHostKeyLine(t),
	} {
		t.Run(name, func(t *testing.T) {
			_, err := b.CreateSession(context.Background(), &sshbrokerv1.CreateSessionRequest{
				Host: "192.0.2.1", Port: 22, Username: "root", PrivateKey: "PEM", ActorUserId: "actor-1",
				HostKeys: []string{genHostKeyLine(t), bad},
			})
			if status.Code(err) != codes.InvalidArgument {
				t.Fatalf("code = %v (%v), want InvalidArgument", status.Code(err), err)
			}
		})
	}
}
