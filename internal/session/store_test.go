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
	sess := &Session{privateKey: []byte("secret-pem"), passphrase: []byte("pp")}
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
}
