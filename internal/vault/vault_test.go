// Copyright 2026 The Sneakers-PAM Authors
// SPDX-License-Identifier: Apache-2.0

package vault

import (
	"context"
	"testing"

	vaultv1 "github.com/Sneakers-PAM/sneakers-sshbroker/gen/go/thirdparty/vault/v1"
	"github.com/Sneakers-PAM/sneakers-sshbroker/internal/session"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

type revealVault struct {
	vaultv1.VaultServiceClient
	actors []*vaultv1.ActorContext
}

func (f *revealVault) RevealSecretField(_ context.Context, in *vaultv1.RevealSecretFieldRequest, _ ...grpc.CallOption) (*vaultv1.RevealSecretFieldResponse, error) {
	f.actors = append(f.actors, in.GetActor())
	switch in.GetFieldKey() {
	case fieldPassphrase:
		return nil, status.Error(codes.NotFound, "no passphrase")
	case fieldPassword:
		return &vaultv1.RevealSecretFieldResponse{Value: "hunter2"}, nil
	}
	return &vaultv1.RevealSecretFieldResponse{Value: "example-key"}, nil
}

// deniedVault refuses every reveal, as the vault would for an actor without
// read access.
type deniedVault struct{ vaultv1.VaultServiceClient }

func (deniedVault) RevealSecretField(context.Context, *vaultv1.RevealSecretFieldRequest, ...grpc.CallOption) (*vaultv1.RevealSecretFieldResponse, error) {
	return nil, status.Error(codes.PermissionDenied, "no access")
}

// The key is revealed as the person, in their own web session: the vault
// gets a HUMAN actor with the session reference the gateway sent.
func TestFetchKeyRevealsForThePersonsWebSession(t *testing.T) {
	v := &revealVault{}
	pk, _, err := New(v).FetchKey(context.Background(), &session.Session{
		SecretID: "secret-1",
		Actor:    session.Actor{UserID: "actor-1", GroupNames: []string{"ops"}, SessionRef: "ref-web-1"},
	})
	if err != nil || string(pk) != "example-key" {
		t.Fatalf("key = %q, err = %v", pk, err)
	}
	for _, a := range v.actors {
		if a.GetUserId() != "actor-1" || a.GetSessionRef() != "ref-web-1" || a.GetPrincipalKind() != vaultv1.PrincipalKind_PRINCIPAL_KIND_HUMAN {
			t.Fatalf("vault actor = %+v", a)
		}
	}
}

// A password secret (type-unix-ssh) reveals through the same actor-gated
// path as a key, but the "password" field.
func TestFetchPasswordRevealsForThePersonsWebSession(t *testing.T) {
	v := &revealVault{}
	pw, err := New(v).FetchPassword(context.Background(), &session.Session{
		SecretID: "secret-2",
		Actor:    session.Actor{UserID: "actor-2", SessionRef: "ref-web-2"},
	})
	if err != nil || string(pw) != "hunter2" {
		t.Fatalf("password = %q, err = %v", pw, err)
	}
}

// An RBAC refusal from the vault is fatal: FetchPassword never returns a
// usable value for an actor without read access.
func TestFetchPasswordPropagatesPermissionDenied(t *testing.T) {
	_, err := New(deniedVault{}).FetchPassword(context.Background(), &session.Session{SecretID: "secret-3"})
	if status.Code(err) != codes.PermissionDenied {
		t.Fatalf("err = %v, want PermissionDenied", err)
	}
}
