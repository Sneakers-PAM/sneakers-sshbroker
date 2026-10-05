// Copyright 2026 The Sneakers-PAM Authors
// SPDX-License-Identifier: Apache-2.0

package session

import (
	"context"
	"errors"
)

// ErrSharedNotAttached: a required composite's shared store hasn't connected
// yet, so reference tickets can't be minted.
var ErrSharedNotAttached = errors.New("shared ticket store not attached")

// Ping checks the shared store, for readiness: a required composite fails
// until Redis is attached, then follows Redis; an optional composite without
// a shared store has nothing to check.
func (c *Composite) Ping(ctx context.Context) error {
	shared := c.sharedStore()
	if shared == nil {
		if c.required {
			return ErrSharedNotAttached
		}
		return nil
	}
	if p, ok := shared.(interface{ Ping(context.Context) error }); ok {
		return p.Ping(ctx)
	}
	return nil
}

// Ping sends PING to Redis.
func (r *RedisStore) Ping(ctx context.Context) error {
	return r.rdb.Ping(ctx).Err()
}
