// Copyright 2026 The Sneakers-PAM Authors
// SPDX-License-Identifier: Apache-2.0

package session

// Composite routes tickets between a shared reference store (Redis) and a
// pod-local in-memory Store, giving the broker HA for the reference path while
// still supporting inline keys and degrading gracefully when Redis is absent.
//
// Routing:
//   - Create: a reference session (no inline key) goes to the shared store when
//     one is configured, so any replica can redeem it. An inline-key session --
//     or any session when there is no shared store -- goes to the local
//     in-memory Store, since a private key must never enter the shared store.
//   - Consume: try the shared store first (the HA path), then fall back to
//     local. Opaque random tickets never collide across the two.
//
// A Composite with a nil shared store behaves exactly like the bare in-memory
// Store, so single-replica deployments (and Redis outages) keep working.
type Composite struct {
	local  *Store
	shared TicketStore // nil when Redis is unavailable
}

// NewComposite builds a Composite over a required local in-memory Store and an
// optional shared store (nil to disable the HA/reference path).
func NewComposite(local *Store, shared TicketStore) *Composite {
	return &Composite{local: local, shared: shared}
}

// Create routes per the rules above.
func (c *Composite) Create(p Params) (id, ticket string, expiresIn int) {
	if c.shared != nil && p.PrivateKey == "" {
		return c.shared.Create(p)
	}
	return c.local.Create(p)
}

// Consume tries the shared store first, then the local store.
func (c *Composite) Consume(ticket string) (*Session, bool) {
	if c.shared != nil {
		if sess, ok := c.shared.Consume(ticket); ok {
			return sess, true
		}
	}
	return c.local.Consume(ticket)
}

// Remove drops the session from both stores (each is a no-op if it never held
// it), zeroizing any local key material.
func (c *Composite) Remove(id string) {
	c.local.Remove(id)
	if c.shared != nil {
		c.shared.Remove(id)
	}
}

// Contains reports whether either store still tracks the id.
func (c *Composite) Contains(id string) bool {
	if c.local.Contains(id) {
		return true
	}
	if c.shared != nil {
		return c.shared.Contains(id)
	}
	return false
}

// Close releases both stores' background resources.
func (c *Composite) Close() {
	c.local.Close()
	if c.shared != nil {
		c.shared.Close()
	}
}
