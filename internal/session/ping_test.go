// Copyright 2026 The Sneakers-PAM Authors
// SPDX-License-Identifier: Apache-2.0

package session

import (
	"context"
	"errors"
	"testing"
	"time"
)

// TestCompositePing_FollowsTheSharedStore: a required composite isn't healthy
// until Redis is attached, then follows Redis; an optional one has nothing to
// ping.
func TestCompositePing_FollowsTheSharedStore(t *testing.T) {
	mr, newPod := newMiniRedis(t)
	c := NewRequiredComposite(NewStore())
	defer c.Close()
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()

	if err := c.Ping(ctx); !errors.Is(err, ErrSharedNotAttached) {
		t.Fatalf("before attach: %v, want ErrSharedNotAttached", err)
	}
	c.Attach(newPod())
	if err := c.Ping(ctx); err != nil {
		t.Fatalf("attached: %v", err)
	}
	mr.SetError("LOADING")
	if err := c.Ping(ctx); err == nil {
		t.Fatal("redis failing: want an error")
	}
	mr.SetError("")
	if err := c.Ping(ctx); err != nil {
		t.Fatalf("recovered: %v", err)
	}

	opt := NewComposite(NewStore(), nil)
	defer opt.Close()
	if err := opt.Ping(ctx); err != nil {
		t.Fatalf("optional composite: %v", err)
	}
}
