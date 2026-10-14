// Copyright 2026 The Sneakers-PAM Authors
// SPDX-License-Identifier: Apache-2.0

package session

import (
	"testing"
	"time"
)

func TestCreateAndConsumeOnce(t *testing.T) {
	s := NewStore()
	id, ticket, exp, _ := s.Create(Params{Host: "h", Port: 22, Username: "u", PrivateKey: "PEM", TTL: 30 * time.Second})
	if id == "" || ticket == "" || exp != 30 {
		t.Fatalf("Create returned id=%q ticket=%q exp=%d", id, ticket, exp)
	}
	sess, ok := s.Consume(ticket)
	if !ok || sess.Host != "h" || sess.Username != "u" {
		t.Fatalf("Consume failed: ok=%v sess=%+v", ok, sess)
	}
	if _, ok := s.Consume(ticket); ok {
		t.Fatal("ticket must be single-use; second Consume should fail")
	}
}

func TestExpiredTicketRejected(t *testing.T) {
	s := NewStore()
	_, ticket, _, _ := s.Create(Params{Host: "h", Port: 22, TTL: 10 * time.Millisecond})
	time.Sleep(30 * time.Millisecond)
	if _, ok := s.Consume(ticket); ok {
		t.Fatal("expired ticket must not be consumable")
	}
}

func TestZeroizeWipesKey(t *testing.T) {
	sess := &Session{privateKey: []byte("secret-pem"), passphrase: []byte("pp"), password: []byte("hunter2")}
	sess.Zeroize()
	for _, b := range sess.privateKey {
		if b != 0 {
			t.Fatal("privateKey not zeroized")
		}
	}
	for _, b := range sess.passphrase {
		if b != 0 {
			t.Fatal("passphrase not zeroized")
		}
	}
	for _, b := range sess.password {
		if b != 0 {
			t.Fatal("password not zeroized")
		}
	}
}

// A password session created inline (back-compat/test path, mirroring the
// inline-key path) round-trips its AuthKind and password through Create and
// Consume, and HasPassword/HasKey tell the two kinds apart.
func TestCreateAndConsumePasswordSession(t *testing.T) {
	s := NewStore()
	_, ticket, _, _ := s.Create(Params{
		Host: "h", Port: 22, Username: "u", AuthKind: AuthKindPassword, Password: "hunter2", TTL: 30 * time.Second,
	})
	sess, ok := s.Consume(ticket)
	if !ok {
		t.Fatal("Consume failed")
	}
	if sess.AuthKind != AuthKindPassword {
		t.Fatalf("AuthKind = %v, want AuthKindPassword", sess.AuthKind)
	}
	if !sess.HasPassword() || string(sess.PasswordBytes()) != "hunter2" {
		t.Fatalf("PasswordBytes = %q, want hunter2", sess.PasswordBytes())
	}
	if sess.HasKey() {
		t.Fatal("a password session must not report HasKey")
	}
}

// The zero-valued AuthKind (AuthKindPublicKey) is what every session created
// before password secrets existed implicitly carries, so old callers that
// never set it keep the key-only behavior they always had.
func TestAuthKindDefaultsToPublicKey(t *testing.T) {
	if AuthKindPublicKey != 0 {
		t.Fatalf("AuthKindPublicKey = %d, want 0 (the zero value)", AuthKindPublicKey)
	}
	s := NewStore()
	_, ticket, _, _ := s.Create(Params{Host: "h", Port: 22, PrivateKey: "PEM", TTL: time.Second})
	sess, ok := s.Consume(ticket)
	if !ok || sess.AuthKind != AuthKindPublicKey {
		t.Fatalf("AuthKind = %v, want AuthKindPublicKey", sess.AuthKind)
	}
}
