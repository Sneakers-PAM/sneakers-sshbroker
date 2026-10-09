// Copyright 2026 The Sneakers-PAM Authors
// SPDX-License-Identifier: Apache-2.0

package session

import (
	"context"
	"errors"
	"net"
	"sync/atomic"
	"testing"
	"time"

	bredis "github.com/Bugs5382/go-redis"
	"github.com/alicebob/miniredis/v2"
)

// TestRequiredCompositeNeverUsesMemoryForReferences: with Redis configured but
// not attached yet, a reference ticket must not land in the pod's memory,
// where another replica could never redeem it.
func TestRequiredCompositeNeverUsesMemoryForReferences(t *testing.T) {
	local := NewStore()
	c := NewRequiredComposite(local)
	defer c.Close()

	if c.Ready() {
		t.Fatal("a required composite with no shared store must not be ready")
	}
	id, ticket, _, err := c.Create(refParams())
	if id != "" || ticket != "" {
		t.Fatalf("reference ticket created before Redis attached: id=%q ticket=%q", id, ticket)
	}
	// #22: Create must say WHY no ticket came back, not just hand back
	// empty strings a caller might mistake for success.
	if err == nil {
		t.Fatal("expected an error when the required shared store isn't attached yet")
	}
	local.mu.Lock()
	n := len(local.byID)
	local.mu.Unlock()
	if n != 0 {
		t.Fatalf("reference ticket went to the in-memory store (%d entries)", n)
	}
}

// TestRequiredCompositeReadyAfterAttach: once the shared store is attached the
// composite is ready and a reference ticket minted on one replica redeems on
// another.
func TestRequiredCompositeReadyAfterAttach(t *testing.T) {
	_, newPod := newMiniRedis(t)
	a := NewRequiredComposite(NewStore())
	defer a.Close()
	b := NewRequiredComposite(NewStore())
	defer b.Close()
	a.Attach(newPod())
	b.Attach(newPod())

	if !a.Ready() || !b.Ready() {
		t.Fatal("composite not ready after Attach")
	}
	_, ticket, _, _ := a.Create(refParams())
	if ticket == "" {
		t.Fatal("no ticket after Attach")
	}
	if _, ok := b.Consume(ticket); !ok {
		t.Fatal("ticket minted on replica a did not redeem on replica b")
	}
}

// TestOptionalCompositeIsAlwaysReady: without REDIS_URL (NewComposite with a
// nil shared store) the broker is single-replica by choice and stays ready.
func TestOptionalCompositeIsAlwaysReady(t *testing.T) {
	c := NewComposite(NewStore(), nil)
	defer c.Close()
	if !c.Ready() {
		t.Fatal("an optional composite must be ready")
	}
}

// TestConnectSharedRetriesUntilRedisAnswers reproduces the install race: the
// broker starts before Redis listens. It must keep trying and attach the
// shared store once Redis answers, instead of settling on in-memory tickets.
func TestConnectSharedRetriesUntilRedisAnswers(t *testing.T) {
	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	addr := l.Addr().String()
	_ = l.Close()

	c := NewRequiredComposite(NewStore())
	defer c.Close()

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	var attempts atomic.Int32
	connect := func(ctx context.Context) (TicketStore, error) {
		attempts.Add(1)
		rc, err := bredis.Connect(ctx, bredis.WithAddr(addr), bredis.WithRetry(0, 0, 0))
		if err != nil {
			return nil, err
		}
		t.Cleanup(func() { _ = rc.Close() })
		return NewRedisStore(rc), nil
	}
	done := make(chan error, 1)
	go func() {
		done <- c.ConnectShared(ctx, connect, Backoff{Min: 10 * time.Millisecond, Max: 50 * time.Millisecond})
	}()

	deadline := time.Now().Add(5 * time.Second)
	for attempts.Load() < 2 {
		if time.Now().After(deadline) {
			t.Fatal("ConnectShared did not retry")
		}
		time.Sleep(5 * time.Millisecond)
	}
	if c.Ready() {
		t.Fatal("ready before Redis answered")
	}

	mr := miniredis.NewMiniRedis()
	if err := mr.StartAddr(addr); err != nil {
		t.Fatalf("miniredis on %s: %v", addr, err)
	}
	defer mr.Close()

	select {
	case err := <-done:
		if err != nil {
			t.Fatalf("ConnectShared: %v", err)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("ConnectShared did not attach after Redis came up")
	}
	if !c.Ready() {
		t.Fatal("not ready after Redis came up")
	}
	_, ticket, _, _ := c.Create(refParams())
	if ticket == "" || len(mr.Keys()) != 1 {
		t.Fatalf("reference ticket not in Redis: ticket=%q keys=%v", ticket, mr.Keys())
	}
}

// TestConnectSharedStopsOnCancel: a pod shutting down while Redis is still
// away returns the context's error and stays unready.
func TestConnectSharedStopsOnCancel(t *testing.T) {
	c := NewRequiredComposite(NewStore())
	defer c.Close()
	ctx, cancel := context.WithCancel(context.Background())
	connect := func(context.Context) (TicketStore, error) { return nil, errors.New("down") }
	done := make(chan error, 1)
	go func() { done <- c.ConnectShared(ctx, connect, Backoff{Min: time.Millisecond, Max: time.Millisecond}) }()
	time.Sleep(20 * time.Millisecond)
	cancel()
	select {
	case err := <-done:
		if !errors.Is(err, context.Canceled) {
			t.Fatalf("err = %v, want context.Canceled", err)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("ConnectShared ignored cancellation")
	}
	if c.Ready() {
		t.Fatal("ready without a shared store")
	}
}

func TestBackoffDoublesToMax(t *testing.T) {
	b := Backoff{Min: time.Second, Max: 5 * time.Second}
	want := []time.Duration{time.Second, 2 * time.Second, 4 * time.Second, 5 * time.Second, 5 * time.Second}
	for i, w := range want {
		if got := b.wait(i); got != w {
			t.Fatalf("wait(%d) = %v, want %v", i, got, w)
		}
	}
}
