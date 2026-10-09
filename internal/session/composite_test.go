// Copyright 2026 The Sneakers-PAM Authors
// SPDX-License-Identifier: Apache-2.0

package session

import (
	"testing"
	"time"
)

// TestCompositeNilSharedFallsBackToMemory proves that when Redis is absent
// (shared == nil) the broker still works: tickets are created and consumed via
// the in-memory store, carrying inline key material. This is the
// single-replica / Redis-outage degrade path.
func TestCompositeNilSharedFallsBackToMemory(t *testing.T) {
	local := NewStore()
	defer local.Close()
	c := NewComposite(local, nil)
	defer c.Close()

	id, ticket, exp, _ := c.Create(Params{
		Host: "h", Port: 22, Username: "u",
		PrivateKey: "PEM", TTL: 30 * time.Second,
	})
	if id == "" || ticket == "" || exp != 30 {
		t.Fatalf("Create returned id=%q ticket=%q exp=%d", id, ticket, exp)
	}
	sess, ok := c.Consume(ticket)
	if !ok || sess.Host != "h" || !sess.HasKey() {
		t.Fatalf("in-memory fallback consume failed: ok=%v sess=%+v", ok, sess)
	}
	if _, ok := c.Consume(ticket); ok {
		t.Fatal("ticket must be single-use")
	}
}

// TestCompositeReferenceGoesToShared proves a reference session (no inline key)
// is routed to the shared store when one exists -- the HA path.
func TestCompositeReferenceGoesToShared(t *testing.T) {
	_, newPod := newMiniRedis(t)
	local := NewStore()
	defer local.Close()
	c := NewComposite(local, newPod())
	defer c.Close()

	_, ticket, _, _ := c.Create(refParams()) // no PrivateKey -> shared

	// It must NOT be in the local in-memory store...
	if _, ok := local.Consume(ticket); ok {
		t.Fatal("reference ticket should have gone to the shared store, not local")
	}
	// ...and it must be redeemable via the composite (from the shared store).
	sess, ok := c.Consume(ticket)
	if !ok || sess.SecretID != "secret-abc" || sess.HasKey() {
		t.Fatalf("reference redeem via composite failed: ok=%v sess=%+v", ok, sess)
	}
}

// TestCompositeInlineKeyStaysLocal proves an inline-key session NEVER goes to
// the shared store, even when one is available (a private key must never enter
// Redis). It is redeemable via the composite from the local store.
func TestCompositeInlineKeyStaysLocal(t *testing.T) {
	mr, newPod := newMiniRedis(t)
	local := NewStore()
	defer local.Close()
	c := NewComposite(local, newPod())
	defer c.Close()

	_, ticket, _, _ := c.Create(Params{
		Host: "h", Port: 22, Username: "u",
		PrivateKey: "PEM-INLINE", TTL: 30 * time.Second,
	})

	// Nothing was written to Redis for an inline ticket.
	if keys := mr.Keys(); len(keys) != 0 {
		t.Fatalf("inline key ticket must not touch Redis; keys=%v", keys)
	}
	sess, ok := c.Consume(ticket)
	if !ok || !sess.HasKey() {
		t.Fatalf("inline redeem via composite failed: ok=%v sess=%+v", ok, sess)
	}
}

// TestCompositeConsumeTriesSharedThenLocal proves Consume checks both backends:
// a ticket that only exists locally is still found even with a shared store set.
func TestCompositeConsumeTriesSharedThenLocal(t *testing.T) {
	_, newPod := newMiniRedis(t)
	local := NewStore()
	defer local.Close()
	c := NewComposite(local, newPod())
	defer c.Close()

	// Seed the local store directly (as the inline path would).
	id, ticket, _, _ := local.Create(Params{Host: "h", Username: "u", PrivateKey: "PEM", TTL: time.Minute})
	if !c.Contains(id) {
		t.Fatal("composite.Contains should see the local session")
	}
	sess, ok := c.Consume(ticket)
	if !ok || sess.Host != "h" {
		t.Fatalf("composite should fall back to local consume: ok=%v", ok)
	}
}
