// Copyright 2026 The Sneakers-PAM Authors
// SPDX-License-Identifier: Apache-2.0

package session

import (
	"context"
	"encoding/json"
	"time"

	bredis "github.com/Bugs5382/go-redis"
	goredis "github.com/redis/go-redis/v9"
)

// ticketKeyPrefix namespaces sshbroker ticket keys in the shared Redis so they
// never collide with other services (e.g. notify's inbox lists).
const ticketKeyPrefix = "sneakers:sshbroker:ticket:"

// redisOpTimeout bounds a single Redis round-trip (Create/Consume). The
// TicketStore surface is context-free (it mirrors the in-memory Store), so
// each op uses its own short, bounded context rather than blocking forever on
// an unreachable server.
const redisOpTimeout = 3 * time.Second

// refTicket is the JSON value stored in Redis for one pending ticket. It holds
// ONLY a reference to the secret + the actor to reveal it with -- NEVER the
// private key or passphrase. The redeeming pod fetches the key from the vault
// at connect time, so key material is never resident in the shared store.
type refTicket struct {
	ID          string    `json:"id"`
	Host        string    `json:"host"`
	Port        int32     `json:"port"`
	Username    string    `json:"user"`
	ActorUserID string    `json:"actorUserId"`
	SecretID    string    `json:"secretId"`
	TargetID    string    `json:"targetId"`
	Actor       Actor     `json:"actor"`
	Started     time.Time `json:"started"`
}

// RedisStore is a shared, short-TTL, single-use ticket store backed by Redis.
// It holds only a reference to the secret (see refTicket); the key is fetched
// from the vault when the ticket is redeemed. Because no pod-local state is
// needed to redeem, any broker replica can redeem any ticket (the HA property).
type RedisStore struct {
	rdb goredis.UniversalClient
	ttl time.Duration
}

// NewRedisStore builds a RedisStore over a go-redis wrapper client (built with
// bredis.Connect, which owns dialing/health/resilience), mirroring the notify
// service's store.NewRedis. The default ttl (used when Params.TTL is zero) is
// DefaultTTL.
func NewRedisStore(c *bredis.Client) *RedisStore {
	return &RedisStore{rdb: c.Redis(), ttl: DefaultTTL}
}

// Create stores a reference ticket in Redis with the ticket's TTL as the key
// expiry. Any inline key material in Params is deliberately ignored: this store
// never persists a private key. Callers route inline-key sessions to the
// in-memory Store instead (see Composite).
func (r *RedisStore) Create(p Params) (id, ticket string, expiresIn int) {
	ttl := p.TTL
	if ttl <= 0 {
		ttl = r.ttl
	}

	id = newOpaqueToken()
	ticket = newOpaqueToken()

	ref := refTicket{
		ID:          id,
		Host:        p.Host,
		Port:        p.Port,
		Username:    p.Username,
		ActorUserID: p.ActorUserID,
		SecretID:    p.SecretID,
		TargetID:    p.TargetID,
		Actor:       p.Actor,
		Started:     time.Now(),
	}
	// json.Marshal of this fixed, string/bool/[]string shape cannot fail.
	blob, _ := json.Marshal(ref)

	ctx, cancel := context.WithTimeout(context.Background(), redisOpTimeout)
	defer cancel()
	// A Set failure just means no ticket is stored; the browser then fails the
	// redeem with "invalid or expired ticket" (fail-closed). We do not surface
	// the error through the context-free interface, matching the in-memory
	// Store which likewise cannot fail Create.
	_ = r.rdb.Set(ctx, ticketKeyPrefix+ticket, blob, ttl).Err()

	return id, ticket, int(ttl / time.Second)
}

// Consume atomically fetches-and-deletes the ticket (GETDEL), guaranteeing
// single use even across replicas. The returned Session carries the reference
// but NO key material; the caller must fetch the key from the vault before
// dialing.
func (r *RedisStore) Consume(ticket string) (*Session, bool) {
	if ticket == "" {
		return nil, false
	}
	ctx, cancel := context.WithTimeout(context.Background(), redisOpTimeout)
	defer cancel()

	blob, err := r.rdb.GetDel(ctx, ticketKeyPrefix+ticket).Bytes()
	if err != nil {
		// redis.Nil (missing/already-consumed/expired) or any transport error:
		// reject. GETDEL makes the delete atomic with the read, so a second
		// redeem -- even on another replica -- misses.
		return nil, false
	}

	var ref refTicket
	if err := json.Unmarshal(blob, &ref); err != nil {
		return nil, false
	}
	return &Session{
		Host:        ref.Host,
		Port:        ref.Port,
		Username:    ref.Username,
		id:          ref.ID,
		Started:     ref.Started,
		ActorUserID: ref.ActorUserID,
		SecretID:    ref.SecretID,
		TargetID:    ref.TargetID,
		Actor:       ref.Actor,
	}, true
}

// Remove is a no-op: Consume already deleted the ticket via GETDEL, and no
// pod-local by-id state exists for a reference ticket. Kept to satisfy
// TicketStore.
func (r *RedisStore) Remove(string) {}

// Contains always reports false: a redeemed reference ticket leaves no tracked
// state (GETDEL removed it). Kept to satisfy TicketStore.
func (r *RedisStore) Contains(string) bool { return false }

// Close is a no-op: the underlying redis client lifecycle is owned by the
// caller that constructed it. Kept to satisfy TicketStore.
func (r *RedisStore) Close() {}
