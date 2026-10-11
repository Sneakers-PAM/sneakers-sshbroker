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
	if in.GetFieldKey() == fieldPassphrase {
		return nil, status.Error(codes.NotFound, "no passphrase")
	}
	return &vaultv1.RevealSecretFieldResponse{Value: "example-key"}, nil
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
