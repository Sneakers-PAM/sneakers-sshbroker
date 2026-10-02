// Copyright 2026 The Sneakers-PAM Authors
// SPDX-License-Identifier: Apache-2.0

package wsproxy

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	bredis "github.com/Bugs5382/go-redis"
	"github.com/alicebob/miniredis/v2"
	"github.com/gorilla/websocket"

	"github.com/Sneakers-PAM/sneakers-sshbroker/internal/session"
)

// fakeVault is a test KeyFetcher: it returns the pre-provisioned key for the
// session's secret id, modelling the real vault's RevealSecretField. It records
// the actor it was called with so tests can assert the actor was carried across
// pods.
type fakeVault struct {
	keyBySecret map[string]string
	gotActor    session.Actor
	gotSecret   string
}

func (f *fakeVault) FetchKey(_ context.Context, sess *session.Session) (privateKey, passphrase []byte, err error) {
	f.gotActor = sess.Actor
	f.gotSecret = sess.SecretID
	pem, ok := f.keyBySecret[sess.SecretID]
	if !ok {
		return nil, nil, context.Canceled // stand-in for a vault error
	}
	return []byte(pem), nil, nil
}

// sharedRedisPods returns two independent RedisStore instances over one
// miniredis, modelling two broker pods sharing a Redis.
func sharedRedisPods(t *testing.T) (mint, ws *session.RedisStore) {
	t.Helper()
	mr, err := miniredis.Run()
	if err != nil {
		t.Fatalf("miniredis: %v", err)
	}
	t.Cleanup(mr.Close)
	newPod := func() *session.RedisStore {
		c, err := bredis.Connect(context.Background(), bredis.WithAddr(mr.Addr()))
		if err != nil {
			t.Fatalf("bredis connect: %v", err)
		}
		t.Cleanup(func() { _ = c.Close() })
		return session.NewRedisStore(c)
	}
	return newPod(), newPod()
}

// TestReferenceCrossReplicaRedeem is the end-to-end HA proof: a
// reference ticket minted against the shared store on one "pod" is redeemed by
// a SECOND pod's WS handler, which fetches the key from a fake vault with the
// ticket's actor, builds the signer, dials, and echoes. Without the reference
// path the key would live only in the minting pod's memory, so the second pod
// would fail.
func TestReferenceCrossReplicaRedeem(t *testing.T) {
	pemPriv, pub := genClientKey(t)
	host, port, stop := startEchoSSHServer(t, pub)
	defer stop()

	mintPod, wsPod := sharedRedisPods(t)

	// Pod A (the gateway's CreateSession target) mints a reference ticket: NO
	// key, just the secret id + actor.
	_, ticket, _ := mintPod.Create(session.Params{
		Host:        host,
		Port:        int32(port),
		Username:    "tester",
		SecretID:    "sec-1",
		ActorUserID: "user-9",
		Actor:       session.Actor{UserID: "user-9", GroupNames: []string{"ops"}},
		TTL:         5 * time.Second,
	})

	// Pod B serves the browser WS, fetching the key from the (fake) vault.
	vault := &fakeVault{keyBySecret: map[string]string{"sec-1": pemPriv}}
	srv := httptest.NewServer(Handler(wsPod, nil, vault))
	defer srv.Close()

	conn, resp, err := websocket.DefaultDialer.Dial(wsURLFor(srv, ticket), nil)
	if err != nil {
		t.Fatalf("second pod could not redeem reference ticket: %v (resp=%v)", err, resp)
	}
	defer func() { _ = conn.Close() }()

	msg := []byte("cross-replica hello\n")
	if err := conn.WriteMessage(websocket.BinaryMessage, msg); err != nil {
		t.Fatalf("write: %v", err)
	}
	_ = conn.SetReadDeadline(time.Now().Add(5 * time.Second))
	_, data, err := conn.ReadMessage()
	if err != nil {
		t.Fatalf("read: %v", err)
	}
	if string(data) != string(msg) {
		t.Fatalf("echo = %q, want %q", data, msg)
	}

	// The vault was called for the right secret, with the actor carried through
	// the shared ticket (proving the fetch is actor-scoped, not a service acct).
	if vault.gotSecret != "sec-1" {
		t.Fatalf("vault fetched wrong secret: %q", vault.gotSecret)
	}
	if vault.gotActor.UserID != "user-9" || len(vault.gotActor.GroupNames) != 1 {
		t.Fatalf("actor not carried to vault fetch: %+v", vault.gotActor)
	}
}

// TestReferenceTicketRejectedWithoutFetcher proves a reference ticket cannot be
// redeemed if no vault fetcher is configured (fail-closed, never dials).
func TestReferenceTicketRejectedWithoutFetcher(t *testing.T) {
	mintPod, wsPod := sharedRedisPods(t)
	_, ticket, _ := mintPod.Create(session.Params{
		Host: "192.0.2.1", Port: 22, Username: "tester",
		SecretID: "sec-1", ActorUserID: "user-9",
		Actor: session.Actor{UserID: "user-9"},
		TTL:   5 * time.Second,
	})

	srv := httptest.NewServer(Handler(wsPod, nil, nil)) // no fetcher
	defer srv.Close()

	resp, err := http.Get(srv.URL + "/ssh/session?ticket=" + ticket)
	if err != nil {
		t.Fatalf("get: %v", err)
	}
	_ = resp.Body.Close()
	if resp.StatusCode < 400 || resp.StatusCode >= 600 {
		t.Fatalf("status = %d, want an error status", resp.StatusCode)
	}
}
