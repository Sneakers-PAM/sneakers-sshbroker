// Copyright 2026 The Sneakers-PAM Authors
// SPDX-License-Identifier: Apache-2.0

package session

import (
	"context"
	"strings"
	"testing"
	"time"

	bredis "github.com/Bugs5382/go-redis"
	"github.com/alicebob/miniredis/v2"
)

// newMiniRedis starts an in-memory Redis and returns a store constructor that
// builds an independent RedisStore over the SAME server -- each call models a
// separate broker pod sharing one Redis. Clients are built with bredis.Connect
// (the go-redis wrapper), matching production.
func newMiniRedis(t *testing.T) (mr *miniredis.Miniredis, newPod func() *RedisStore) {
	t.Helper()
	mr, err := miniredis.Run()
	if err != nil {
		t.Fatalf("miniredis: %v", err)
	}
	t.Cleanup(mr.Close)
	newPod = func() *RedisStore {
		c, err := bredis.Connect(context.Background(), bredis.WithAddr(mr.Addr()))
		if err != nil {
			t.Fatalf("bredis connect: %v", err)
		}
		t.Cleanup(func() { _ = c.Close() })
		return NewRedisStore(c)
	}
	return mr, newPod
}

func refParams() Params {
	return Params{
		Host:        "192.0.2.9",
		Port:        22,
		Username:    "deploy",
		ActorUserID: "user-42",
		SecretID:    "secret-abc",
		TargetID:    "target-xyz",
		Actor: Actor{
			UserID:     "user-42",
			GroupNames: []string{"ops", "ssh-users"},
		},
		TTL: 30 * time.Second,
	}
}

// TestRedisCrossReplicaRedeem is the core HA property: a ticket
// minted on one "pod" (store instance) is redeemable on a SECOND pod sharing
// the same Redis. Without a shared store the ticket would live only in the
// minting pod's memory, so a WS landing on another pod would get "invalid or
// expired ticket".
func TestRedisCrossReplicaRedeem(t *testing.T) {
	_, newPod := newMiniRedis(t)
	podA := newPod()
	podB := newPod()

	id, ticket, exp := podA.Create(refParams())
	if id == "" || ticket == "" || exp != 30 {
		t.Fatalf("Create returned id=%q ticket=%q exp=%d", id, ticket, exp)
	}

	sess, ok := podB.Consume(ticket)
	if !ok {
		t.Fatal("second pod could not redeem the ticket minted by the first pod")
	}
	if sess.Host != "192.0.2.9" || sess.Username != "deploy" || sess.SecretID != "secret-abc" {
		t.Fatalf("reference not carried across pods: %+v", sess)
	}
	if sess.Actor.UserID != "user-42" || len(sess.Actor.GroupNames) != 2 {
		t.Fatalf("actor not carried across pods: %+v", sess.Actor)
	}
	// The reference carries NO key material: the redeeming pod must fetch it
	// from the vault.
	if sess.HasKey() {
		t.Fatal("reference ticket must not carry key material")
	}
}

// TestRedisSingleUse proves GETDEL makes a ticket single-use even across pods.
func TestRedisSingleUse(t *testing.T) {
	_, newPod := newMiniRedis(t)
	podA := newPod()
	podB := newPod()

	_, ticket, _ := podA.Create(refParams())
	if _, ok := podA.Consume(ticket); !ok {
		t.Fatal("first redeem should succeed")
	}
	// A second redeem, on either pod, must fail: the ticket is gone.
	if _, ok := podB.Consume(ticket); ok {
		t.Fatal("ticket must be single-use across replicas; second redeem must fail")
	}
	if _, ok := podA.Consume(ticket); ok {
		t.Fatal("ticket must be single-use; second redeem on same pod must fail")
	}
}

// TestRedisNeverStoresKey asserts the private key/passphrase are NEVER written
// to the shared store, even if inadvertently supplied in Params.
func TestRedisNeverStoresKey(t *testing.T) {
	mr, newPod := newMiniRedis(t)
	pod := newPod()

	p := refParams()
	p.PrivateKey = "-----BEGIN OPENSSH PRIVATE KEY-----SENSITIVE-----END-----"
	p.Passphrase = "hunter2"
	_, ticket, _ := pod.Create(p)

	// Inspect the raw value stored in Redis: it must not contain the key bytes.
	raw, err := mr.Get(ticketKeyPrefix + ticket)
	if err != nil {
		t.Fatalf("stored value missing: %v", err)
	}
	if strings.Contains(raw, "SENSITIVE") || strings.Contains(raw, "hunter2") ||
		strings.Contains(raw, "PRIVATE KEY") {
		t.Fatalf("private key/passphrase leaked into the shared store: %q", raw)
	}

	sess, ok := pod.Consume(ticket)
	if !ok {
		t.Fatal("consume failed")
	}
	if sess.HasKey() {
		t.Fatal("redeemed reference session must not carry key material")
	}
}

// TestRedisTTLExpiry proves the ticket key expires with its TTL.
func TestRedisTTLExpiry(t *testing.T) {
	mr, newPod := newMiniRedis(t)
	pod := newPod()

	p := refParams()
	p.TTL = 5 * time.Second
	_, ticket, exp := pod.Create(p)
	if exp != 5 {
		t.Fatalf("expiresIn = %d, want 5", exp)
	}
	// miniredis honours TTLs only when its clock is advanced.
	mr.FastForward(6 * time.Second)
	if _, ok := pod.Consume(ticket); ok {
		t.Fatal("expired ticket must not be consumable")
	}
}

// TestRedisMissingTicketRejected covers the empty and unknown ticket cases.
func TestRedisMissingTicketRejected(t *testing.T) {
	_, newPod := newMiniRedis(t)
	pod := newPod()
	if _, ok := pod.Consume(""); ok {
		t.Fatal("empty ticket must be rejected")
	}
	if _, ok := pod.Consume("does-not-exist"); ok {
		t.Fatal("unknown ticket must be rejected")
	}
}
