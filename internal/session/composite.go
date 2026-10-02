// Copyright 2026 The Sneakers-PAM Authors
// SPDX-License-Identifier: Apache-2.0

package session

import "sync/atomic"

// Composite routes tickets between a shared reference store (Redis) and a
// pod-local in-memory Store, giving the broker HA for the reference path while
// still supporting inline keys and degrading gracefully when Redis is absent.
//
// Routing:
//   - Create: a reference session (no inline key) goes to the shared store when
//     one is configured, so any replica can redeem it. An inline-key session --
//     or any session when there is no shared store -- goes to the local
//     in-memory Store, since a private key must never enter the shared store.
//     A required composite never puts a reference session in memory.
//   - Consume: try the shared store first (the HA path), then fall back to
//     local. Opaque random tickets never collide across the two.
//
// A Composite built by NewComposite with a nil shared store behaves exactly
// like the bare in-memory Store: the single-replica setup with no REDIS_URL.
//
// A Composite built by NewRequiredComposite has Redis configured and never
// puts a reference ticket in memory. Until Attach supplies the shared store it
// is not Ready and Create refuses reference tickets (empty id and ticket), so
// a broker that started before Redis can't mint tickets another replica can't
// redeem.
type Composite struct {
	local    *Store
	shared   atomic.Pointer[sharedRef]
	required bool
}

type sharedRef struct{ store TicketStore }

// NewComposite builds a Composite over a required local in-memory Store and an
// optional shared store (nil to disable the HA/reference path).
func NewComposite(local *Store, shared TicketStore) *Composite {
	c := &Composite{local: local}
	if shared != nil {
		c.shared.Store(&sharedRef{store: shared})
	}
	return c
}

// NewRequiredComposite builds a Composite whose reference tickets go only to
// the shared store, which Attach (or ConnectShared) supplies later.
func NewRequiredComposite(local *Store) *Composite {
	return &Composite{local: local, required: true}
}

// Attach installs the shared store. It is called once, when Redis answers.
func (c *Composite) Attach(shared TicketStore) {
	c.shared.Store(&sharedRef{store: shared})
}

// Ready reports whether the composite can mint every kind of ticket: always
// for an optional composite, and once the shared store is attached for a
// required one.
func (c *Composite) Ready() bool {
	return !c.required || c.sharedStore() != nil
}

func (c *Composite) sharedStore() TicketStore {
	if r := c.shared.Load(); r != nil {
		return r.store
	}
	return nil
}

// Create routes per the rules above.
func (c *Composite) Create(p Params) (id, ticket string, expiresIn int) {
	if p.PrivateKey == "" {
		if shared := c.sharedStore(); shared != nil {
			return shared.Create(p)
		}
		if c.required {
			return "", "", 0
		}
	}
	return c.local.Create(p)
}

// Consume tries the shared store first, then the local store.
func (c *Composite) Consume(ticket string) (*Session, bool) {
	if shared := c.sharedStore(); shared != nil {
		if sess, ok := shared.Consume(ticket); ok {
			return sess, true
		}
	}
	return c.local.Consume(ticket)
}

// Remove drops the session from both stores (each is a no-op if it never held
// it), zeroizing any local key material.
func (c *Composite) Remove(id string) {
	c.local.Remove(id)
	if shared := c.sharedStore(); shared != nil {
		shared.Remove(id)
	}
}

// Contains reports whether either store still tracks the id.
func (c *Composite) Contains(id string) bool {
	if c.local.Contains(id) {
		return true
	}
	if shared := c.sharedStore(); shared != nil {
		return shared.Contains(id)
	}
	return false
}

// Close releases both stores' background resources.
func (c *Composite) Close() {
	c.local.Close()
	if shared := c.sharedStore(); shared != nil {
		shared.Close()
	}
}
