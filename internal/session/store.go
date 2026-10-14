// Copyright 2026 The Sneakers-PAM Authors
// SPDX-License-Identifier: Apache-2.0

// Package session holds the single-use ticket store for the sshbroker.
//
// Two backends implement the TicketStore interface:
//
//   - Store (this file): in-memory, single-replica. Holds full key material as
//     byte slices in process memory, zeroized on consumption/expiry/teardown.
//     Used for the inline-key back-compat path and as the fallback when Redis
//     is unavailable.
//   - RedisStore (redisstore.go): a shared, short-TTL store that holds ONLY a
//     reference to the secret (never the key), so any broker replica can redeem
//     a ticket. The redeeming pod fetches the key from the vault at connect
//     time (see internal/vault + wsproxy).
//
// Composite (composite.go) routes between the two.
package session

import (
	"crypto/rand"
	"encoding/hex"
	"sync"
	"time"
)

// DefaultTTL is used when Params.TTL is zero.
const DefaultTTL = 30 * time.Second

// reapInterval controls how often the background reaper sweeps for expired,
// never-consumed pending sessions.
const reapInterval = 1 * time.Second

// Actor identifies the human actor a session is opened for. It mirrors
// sneakers.vault.v1.ActorContext so the redeeming pod can pass it straight to
// the vault's RevealSecretField; the vault applies the same RBAC it would have
// applied to the gateway. Carried only on the reference path.
type Actor struct {
	UserID      string
	IsSiteAdmin bool
	IsRoot      bool
	GroupNames  []string
	// SessionRef is the person's web session reference the gateway sent.
	SessionRef string
}

// TicketStore is the minimal ticket surface the broker and WS handler use. It
// is satisfied by the in-memory Store, the shared RedisStore, and Composite.
type TicketStore interface {
	// Create registers a pending session and returns its opaque id, single-use
	// ticket, and TTL in whole seconds. A non-nil err means no ticket was
	// stored (id and ticket are empty); the caller must not hand out a
	// ticket that was never written.
	Create(p Params) (id, ticket string, expiresIn int, err error)
	// Consume atomically looks up and removes a ticket (single-use), returning
	// the session and true on success.
	Consume(ticket string) (*Session, bool)
	// Remove drops a session by id, zeroizing any resident key material.
	Remove(id string)
	// Contains reports whether a session id is still tracked (test support).
	Contains(id string) bool
	// Close releases any background resources.
	Close()
}

// AuthKind selects which SSH credential a session carries and which auth
// methods the open path offers the target. The zero value, AuthKindPublicKey,
// is the only kind that existed before password secrets, so an older gateway
// (or a test) that never sets it still gets the key-only behavior it always
// had.
type AuthKind int32

const (
	// AuthKindPublicKey authenticates with the session's private key
	// (KeyBytes/PassphraseBytes). The default: back-compat with every
	// session created before password secrets.
	AuthKindPublicKey AuthKind = iota
	// AuthKindPassword authenticates with the session's password
	// (PasswordBytes), offering the target both SSH password auth and
	// keyboard-interactive (answering a single prompt with the password).
	AuthKindPassword
)

// Params describes a session to create. Key material arrives as strings
// (from the gRPC request) and is copied into byte slices on the Session so
// it can be zeroized independently of the caller's copy. On the reference
// path PrivateKey/Passphrase/Password are empty and SecretID + Actor identify
// the credential to fetch from the vault at redeem time; AuthKind says which
// vault fields (and which SSH auth methods) that fetch and the open path use.
type Params struct {
	Host       string
	Port       int32
	Username   string
	PrivateKey string
	Passphrase string
	// Password is the inline password credential (back-compat/tests), used
	// only when AuthKind is AuthKindPassword.
	Password    string
	AuthKind    AuthKind
	ActorUserID string
	SecretID    string
	TargetID    string
	Actor       Actor
	// HostKeys are the target's pinned SSH host keys (authorized_keys form).
	// Public keys, so they travel on every ticket, the shared one included.
	HostKeys []string
	TTL      time.Duration
}

// Session is a broker-memory-only record of a pending or active SSH
// connection. Key material is held only as byte slices so it can be wiped.
type Session struct {
	Host     string
	Port     int32
	Username string
	AuthKind AuthKind

	id         string
	privateKey []byte
	passphrase []byte
	password   []byte

	Started     time.Time
	ActorUserID string
	SecretID    string
	TargetID    string
	Actor       Actor
	HostKeys    []string
	// AuthMethodUsed is set by the open path once a connection authenticates:
	// "publickey", "password" or "keyboard-interactive". Empty until then.
	// Non-sensitive: carried into the audit, never the credential itself.
	AuthMethodUsed string
}

// ID returns the session's opaque store id, i.e. the key under which it is
// tracked in the Store's by-id map (see Remove). Consumers of Consume need
// this to remove the session from the store once they are done with it.
func (s *Session) ID() string { return s.id }

// KeyBytes returns the private key bytes (PEM). Callers must not retain a
// reference past the session's lifetime; the backing array is zeroized on
// teardown/expiry.
func (s *Session) KeyBytes() []byte { return s.privateKey }

// PassphraseBytes returns the passphrase bytes, if any.
func (s *Session) PassphraseBytes() []byte { return s.passphrase }

// PasswordBytes returns the password bytes (AuthKindPassword sessions only).
func (s *Session) PasswordBytes() []byte { return s.password }

// HasKey reports whether the session already carries inline key material. A
// reference-path session (redeemed from the shared store) has no key until the
// redeeming pod fetches it from the vault via SetKeyMaterial.
func (s *Session) HasKey() bool { return len(s.privateKey) > 0 }

// HasPassword reports whether the session already carries an inline
// password. A reference-path password session has none until the redeeming
// pod fetches it from the vault via SetPasswordMaterial.
func (s *Session) HasPassword() bool { return len(s.password) > 0 }

// SetKeyMaterial installs key material fetched at redeem time (reference path).
// The bytes are held only on this Session, so Zeroize still wipes them on
// teardown; callers must not retain the passed slices.
func (s *Session) SetKeyMaterial(privateKey, passphrase []byte) {
	s.privateKey = privateKey
	s.passphrase = passphrase
}

// SetPasswordMaterial installs the password fetched at redeem time (reference
// path). The bytes are held only on this Session, so Zeroize still wipes
// them on teardown; callers must not retain the passed slice.
func (s *Session) SetPasswordMaterial(password []byte) {
	s.password = password
}

// Zeroize wipes the key material in place.
func (s *Session) Zeroize() {
	for i := range s.privateKey {
		s.privateKey[i] = 0
	}
	for i := range s.passphrase {
		s.passphrase[i] = 0
	}
	for i := range s.password {
		s.password[i] = 0
	}
}

type pending struct {
	session  *Session
	id       string
	deadline time.Time
}

// Store is a mutex-guarded, in-memory ticket/session store. It is safe for
// concurrent use.
type Store struct {
	mu       sync.Mutex
	byTicket map[string]*pending
	byID     map[string]*Session

	stopOnce sync.Once
	stopCh   chan struct{}
}

// NewStore creates a Store and starts its background reaper goroutine.
func NewStore() *Store {
	s := &Store{
		byTicket: make(map[string]*pending),
		byID:     make(map[string]*Session),
		stopCh:   make(chan struct{}),
	}
	go s.reap()
	return s
}

// Close stops the background reaper. Safe to call multiple times.
func (s *Store) Close() {
	s.stopOnce.Do(func() { close(s.stopCh) })
}

// Create builds a new Session from Params, issues an opaque id and
// single-use ticket, and registers the ticket pending consumption before
// its deadline. Returns the id, ticket, and TTL in whole seconds. The
// in-memory map insert cannot fail, so err is always nil; it exists to
// satisfy TicketStore alongside RedisStore, which can.
func (s *Store) Create(p Params) (id, ticket string, expiresIn int, err error) {
	ttl := p.TTL
	if ttl <= 0 {
		ttl = DefaultTTL
	}

	id = newOpaqueToken()
	ticket = newOpaqueToken()

	sess := &Session{
		Host:        p.Host,
		Port:        p.Port,
		Username:    p.Username,
		AuthKind:    p.AuthKind,
		id:          id,
		privateKey:  []byte(p.PrivateKey),
		passphrase:  []byte(p.Passphrase),
		password:    []byte(p.Password),
		Started:     time.Now(),
		ActorUserID: p.ActorUserID,
		SecretID:    p.SecretID,
		TargetID:    p.TargetID,
		Actor:       p.Actor,
		HostKeys:    p.HostKeys,
	}

	s.mu.Lock()
	s.byID[id] = sess
	s.byTicket[ticket] = &pending{
		session:  sess,
		id:       id,
		deadline: time.Now().Add(ttl),
	}
	s.mu.Unlock()

	return id, ticket, int(ttl / time.Second), nil
}

// Consume looks up a ticket, removing it (single-use). It returns the
// Session and true on success. Expired tickets are rejected (and their
// session zeroized) even though this also removes them; the caller cannot
// consume a ticket twice regardless of expiry.
func (s *Store) Consume(ticket string) (*Session, bool) {
	s.mu.Lock()
	p, ok := s.byTicket[ticket]
	if ok {
		delete(s.byTicket, ticket)
	}
	s.mu.Unlock()

	if !ok {
		return nil, false
	}
	if time.Now().After(p.deadline) {
		s.Remove(p.id)
		return nil, false
	}
	return p.session, true
}

// Contains reports whether a session with the given id is still tracked by
// the store. It exists to support tests asserting that a session's record
// (and thus its key material) is gone after teardown; production code
// should not need to peek at store contents.
func (s *Store) Contains(id string) bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	_, ok := s.byID[id]
	return ok
}

// Remove drops a session by id, zeroizing its key material.
func (s *Store) Remove(id string) {
	s.mu.Lock()
	sess, ok := s.byID[id]
	if ok {
		delete(s.byID, id)
	}
	s.mu.Unlock()

	if ok {
		sess.Zeroize()
	}
}

// reap periodically drops and zeroizes pending sessions that were never
// consumed before their deadline.
func (s *Store) reap() {
	ticker := time.NewTicker(reapInterval)
	defer ticker.Stop()
	for {
		select {
		case <-s.stopCh:
			return
		case now := <-ticker.C:
			s.reapOnce(now)
		}
	}
}

func (s *Store) reapOnce(now time.Time) {
	var expiredIDs []string

	s.mu.Lock()
	for ticket, p := range s.byTicket {
		if now.After(p.deadline) {
			delete(s.byTicket, ticket)
			expiredIDs = append(expiredIDs, p.id)
		}
	}
	s.mu.Unlock()

	for _, id := range expiredIDs {
		s.Remove(id)
	}
}

// newOpaqueToken returns a hex-encoded, crypto/rand-sourced 32-byte token.
func newOpaqueToken() string {
	b := make([]byte, 32)
	if _, err := rand.Read(b); err != nil {
		// crypto/rand.Read failing is a fatal environment problem; panicking
		// here is preferable to silently issuing a predictable token.
		panic("session: crypto/rand unavailable: " + err.Error())
	}
	return hex.EncodeToString(b)
}
