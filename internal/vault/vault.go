// Copyright 2026 The Sneakers-PAM Authors
// SPDX-License-Identifier: Apache-2.0

// Package vault fetches SSH key material from the sneakers vault at
// SSH-connect time, on the reference path. The broker no longer receives the
// private key from the gateway; instead it holds a reference (secret id +
// actor) and reveals the key here, on the pod that will terminate the SSH
// session, so key material is only ever resident in the vault and that one
// pod's memory -- never in the shared ticket store.
//
// Reveals go through the vault's RevealSecretField RPC, which is RBAC-gated on
// the actor and audited vault-side, so passing the real user's actor preserves
// exactly the authorization + audit the gateway would have applied. NEVER log
// the returned values.
package vault

import (
	"context"

	log "github.com/Bugs5382/go-log"
	vaultv1 "github.com/Sneakers-PAM/sneakers-vault/gen/go/sneakers/vault/v1"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	"github.com/Sneakers-PAM/sneakers-sshbroker/internal/session"
)

// Field keys for the SSH secret type, matching what the gateway revealed on the
// legacy inline path.
const (
	fieldPrivateKey = "privateKey"
	fieldPassphrase = "passphrase"
)

// logger is package-scoped so callers never import zerolog directly. Only
// host/target_id/secret_id/actor_user_id/reason are ever logged -- never key
// material.
var logger = log.New("sshbroker-vault")

// Client reveals SSH key material from the vault for a reference-path session.
type Client struct {
	c vaultv1.VaultServiceClient
}

// New returns a Client over an existing vault service client.
func New(c vaultv1.VaultServiceClient) *Client { return &Client{c: c} }

// FetchKey reveals the session's private key (and passphrase, if the secret has
// one) using the session's actor. It returns the PEM private key bytes and the
// passphrase bytes (nil when the key has no passphrase). A missing passphrase
// field (codes.NotFound) is treated as "no passphrase"; any other error --
// including an RBAC PermissionDenied -- is fatal, so an unauthorized redeem
// never dials.
func (v *Client) FetchKey(ctx context.Context, sess *session.Session) (privateKey, passphrase []byte, err error) {
	actor := actorContext(sess.Actor)

	pk, err := v.c.RevealSecretField(ctx, &vaultv1.RevealSecretFieldRequest{
		Actor:    actor,
		Id:       sess.SecretID,
		FieldKey: fieldPrivateKey,
	})
	if err != nil {
		logger.Error().Err(err).
			Str("secret_id", sess.SecretID).
			Str("actor_user_id", sess.ActorUserID).
			Str("reason", "reveal privateKey failed").
			Msg("vault reveal failed")
		return nil, nil, err
	}

	pp, err := v.c.RevealSecretField(ctx, &vaultv1.RevealSecretFieldRequest{
		Actor:    actor,
		Id:       sess.SecretID,
		FieldKey: fieldPassphrase,
	})
	switch {
	case status.Code(err) == codes.NotFound:
		// SSH key with no passphrase: not an error.
	case err != nil:
		logger.Error().Err(err).
			Str("secret_id", sess.SecretID).
			Str("actor_user_id", sess.ActorUserID).
			Str("reason", "reveal passphrase failed").
			Msg("vault reveal failed")
		return nil, nil, err
	default:
		if v := pp.GetValue(); v != "" {
			passphrase = []byte(v)
		}
	}

	return []byte(pk.GetValue()), passphrase, nil
}

// actorContext maps the broker-side actor to the vault's ActorContext.
func actorContext(a session.Actor) *vaultv1.ActorContext {
	return &vaultv1.ActorContext{
		UserId:      a.UserID,
		IsSiteAdmin: a.IsSiteAdmin,
		IsRoot:      a.IsRoot,
		GroupNames:  a.GroupNames,
	}
}
