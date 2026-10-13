// Copyright 2026 The Sneakers-PAM Authors
// SPDX-License-Identifier: Apache-2.0

// Package wsproxy implements the WebSocket endpoint that authenticates a
// single-use session ticket, dials SSH with the session's key material,
// requests a PTY + shell, and pumps bytes between the browser WebSocket and
// the SSH session.
package wsproxy

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"io"
	"net"
	"net/http"
	"slices"
	"strconv"
	"sync"
	"time"

	log "github.com/Bugs5382/go-log"
	"github.com/gorilla/websocket"
	"golang.org/x/crypto/ssh"

	"github.com/Sneakers-PAM/sneakers-sshbroker/internal/audit"
	"github.com/Sneakers-PAM/sneakers-sshbroker/internal/session"
)

// logger is package-scoped (type inferred from log.New), matching the
// internal/audit convention, so callers never need to import zerolog
// directly. Log fields are limited to host/target_id/secret_id/
// actor_user_id/reason -- key material, the private key, and the passphrase
// must never be logged.
var logger = log.New("sshbroker-wsproxy")

// Tunable liveness/lifetime defaults. Three independent mechanisms bound how
// long a session (and thus its resident SSH private key material) can
// survive a peer that never cleanly closes:
//
//   - WS read deadline + ping/pong (defaultPingPeriod/defaultPongWait):
//     detects a browser that goes dark (network partition, sleeping laptop,
//     etc. with no clean FIN/RST). defaultPingPeriod must stay below
//     defaultPongWait so a missed pong is caught before the deadline lapses.
//   - SSH keepalive (defaultSSHKeepaliveInterval): detects a target that
//     goes silently dead without ever sending EOF.
//   - Absolute cutoff (defaultMaxSessionDuration): bounds total session
//     lifetime even under continuous legitimate activity.
//
// The open path, before the WebSocket upgrade, has its own bounds (see
// open.go): each step, and the whole open below the sum of them.
const (
	defaultPongWait             = 60 * time.Second
	defaultPingPeriod           = 30 * time.Second
	defaultWriteWait            = 10 * time.Second
	defaultSSHKeepaliveInterval = 30 * time.Second
	// defaultMaxSessionDuration is the absolute session cutoff. 8h covers a
	// full working session while still guaranteeing key material is never
	// resident indefinitely (e.g. a forgotten open tab).
	defaultMaxSessionDuration = 8 * time.Hour

	defaultRevealTimeout    = 10 * time.Second
	defaultDialTimeout      = 15 * time.Second
	defaultHandshakeTimeout = 15 * time.Second
	defaultShellTimeout     = 15 * time.Second
	defaultOpenTimeout      = 45 * time.Second
)

// Config carries the liveness/lifetime tunables used by HandlerWithConfig.
// Zero-valued fields fall back to the package defaults (see withDefaults),
// so tests only need to set the fields they want to shrink.
type Config struct {
	// PongWait is how long the WS read deadline is extended by, both
	// initially and on every pong received from the browser.
	PongWait time.Duration
	// PingPeriod is how often a WS ping control frame is sent to the
	// browser. Must be smaller than PongWait.
	PingPeriod time.Duration
	// WriteWait bounds how long a single WS ping control-frame write may
	// block.
	WriteWait time.Duration
	// SSHKeepaliveInterval is how often an SSH keepalive request is sent to
	// the target.
	SSHKeepaliveInterval time.Duration
	// MaxSessionDuration is the absolute session lifetime cutoff.
	MaxSessionDuration time.Duration
	// RevealTimeout bounds the vault reveal of the session's key.
	RevealTimeout time.Duration
	// DialTimeout bounds the TCP connect to the target.
	DialTimeout time.Duration
	// HandshakeTimeout bounds the SSH banner, key exchange, host-key check
	// and authentication, after the TCP connect.
	HandshakeTimeout time.Duration
	// ShellTimeout bounds the session channel, PTY and shell requests.
	ShellTimeout time.Duration
	// OpenTimeout bounds the whole open, from the ticket to the upgrade.
	OpenTimeout time.Duration
	// AllowedOrigins are the browser origins (normalized, see ParseOrigins)
	// that may open a session from another origin. A page on the request's
	// own origin (its Host header) may always open one; with the list empty,
	// every other browser origin is refused.
	AllowedOrigins []string
}

func (c Config) withDefaults() Config {
	if c.PongWait <= 0 {
		c.PongWait = defaultPongWait
	}
	if c.PingPeriod <= 0 {
		c.PingPeriod = defaultPingPeriod
	}
	if c.WriteWait <= 0 {
		c.WriteWait = defaultWriteWait
	}
	if c.SSHKeepaliveInterval <= 0 {
		c.SSHKeepaliveInterval = defaultSSHKeepaliveInterval
	}
	if c.MaxSessionDuration <= 0 {
		c.MaxSessionDuration = defaultMaxSessionDuration
	}
	c.RevealTimeout = orDefault(c.RevealTimeout, defaultRevealTimeout)
	c.DialTimeout = orDefault(c.DialTimeout, defaultDialTimeout)
	c.HandshakeTimeout = orDefault(c.HandshakeTimeout, defaultHandshakeTimeout)
	c.ShellTimeout = orDefault(c.ShellTimeout, defaultShellTimeout)
	c.OpenTimeout = orDefault(c.OpenTimeout, defaultOpenTimeout)
	return c
}

func orDefault(d, def time.Duration) time.Duration {
	if d <= 0 {
		return def
	}
	return d
}

// resizeMsg is the only text control frame the client may send: a terminal
// resize. Any other text frame, or one that fails to parse as this shape, is
// ignored.
type resizeMsg struct {
	Type string `json:"type"`
	Cols int    `json:"cols"`
	Rows int    `json:"rows"`
}

// KeyFetcher reveals key material for a reference-path session at redeem time.
// A reference ticket (redeemed from the shared store) carries no key; the
// redeeming pod calls FetchKey to get the private key (+ passphrase, nil when
// absent) from the vault, using the session's actor. Implemented by
// internal/vault; may be nil (inline-only deployments/tests), in which case a
// reference ticket that needs a fetch is rejected.
type KeyFetcher interface {
	FetchKey(ctx context.Context, sess *session.Session) (privateKey, passphrase []byte, err error)
}

// Handler is HandlerWithConfig using the package default liveness/lifetime
// tunables. See HandlerWithConfig for behavior.
func Handler(store session.TicketStore, aud *audit.Emitter, keys KeyFetcher) http.HandlerFunc {
	return HandlerWithConfig(store, aud, keys, Config{})
}

// HandlerWithConfig validates the single-use ticket, dials SSH with the
// session's key, requests a PTY + shell, and pumps bytes between the
// WebSocket and the SSH session until either side closes, a liveness check
// fails, or the absolute session cutoff is reached.
//
// On every exit path it zeroizes the session's key material, removes the
// session from the store, and emits a best-effort session.end audit event
// (aud may be nil, e.g. in tests, in which case emission is a no-op). Key
// material is never logged or written to the WebSocket.
//
// A hung peer (e.g. a network partition with no clean FIN/RST) is bounded by
// three independent mechanisms so teardown -- and the release of the
// resident SSH private key material -- always fires in reasonable time: a
// WS read-deadline/ping-pong pair, an SSH-side keepalive probe, and an
// absolute max-session timer. All three simply close the SSH client and WS
// connection on failure/expiry, which unblocks whichever goroutine is
// currently blocked in Read/Write and drives the handler to return (running
// the deferred teardown). Every background goroutine this starts selects on
// a done channel that is closed exactly once, in the deferred cleanup, so
// none outlives the handler.
func HandlerWithConfig(store session.TicketStore, aud *audit.Emitter, keys KeyFetcher, cfg Config) http.HandlerFunc {
	cfg = cfg.withDefaults()
	origins := newOriginChecker(cfg.AllowedOrigins)
	upgrader := &websocket.Upgrader{CheckOrigin: origins.allowed}

	return func(w http.ResponseWriter, r *http.Request) {
		// Checked before the ticket is consumed, so a page on another origin
		// can't burn a ticket the real UI is about to use.
		if !origins.allowed(r) {
			logger.Warn().Str("origin", r.Header.Get("Origin")).Msg("ssh session rejected: origin not allowed")
			http.Error(w, "origin not allowed", http.StatusForbidden)
			return
		}
		ticket := r.URL.Query().Get("ticket")
		sess, ok := store.Consume(ticket)
		if !ok {
			logger.Warn().Msg("ssh session rejected: invalid or expired ticket")
			http.Error(w, "invalid or expired ticket", http.StatusForbidden)
			return
		}

		logger.Info().
			Str("host", sess.Host).
			Int32("port", sess.Port).
			Str("target_id", sess.TargetID).
			Str("secret_id", sess.SecretID).
			Str("actor_user_id", sess.ActorUserID).
			Bool("reference", !sess.HasKey()).
			Msg("ssh session opening")

		reason := "closed"
		defer func() {
			sess.Zeroize()
			store.Remove(sess.ID())
			endAudit(aud, sess, reason)
			logger.Info().
				Str("host", sess.Host).
				Str("target_id", sess.TargetID).
				Str("secret_id", sess.SecretID).
				Str("actor_user_id", sess.ActorUserID).
				Str("reason", reason).
				Msg("ssh session closed")
		}()

		// Every step that can fail runs before the upgrade, each bounded, so
		// a failure reaches the client as a sentence naming the step instead
		// of a socket that never opens.
		st := newSteps(sess)
		openCtx, cancelOpen := context.WithTimeout(r.Context(), cfg.OpenTimeout)
		tgt, oerr := openTarget(openCtx, cfg, keys, sess, st)
		cancelOpen()
		if oerr != nil {
			reason = oerr.msg
			st.failed(oerr)
			refuse(w, r, upgrader, cfg, oerr)
			return
		}
		defer tgt.close()
		client, sshSess := tgt.client, tgt.session

		conn, err := upgrader.Upgrade(w, r, nil)
		if err != nil {
			reason = "ws upgrade failed"
			logFailure(sess, reason, err)
			return
		}
		defer func() { _ = conn.Close() }()
		st.done("upgraded")

		// writeMu serializes every write to conn: gorilla/websocket forbids
		// concurrent writers, and the stdout/stderr pumps plus the ping
		// ticker below all write independently.
		var writeMu sync.Mutex

		// done is closed exactly once, in the deferred cleanup below, right
		// before the handler returns. Every background goroutine started
		// here selects on it so none outlives the handler.
		done := make(chan struct{})
		defer close(done)

		// forceClose unblocks any pump currently parked in Read/Write on
		// either side by closing both the SSH client and the WS connection.
		// Safe to call more than once (including from multiple goroutines,
		// and even though client/conn are also closed by the defers above):
		// a redundant Close just returns an already-closed error, which is
		// ignored everywhere in this handler.
		forceClose := func() {
			_ = client.Close()
			_ = conn.Close()
		}

		// (a) WS keepalive / read deadline (browser side). If the browser
		// goes dark, the ping ticker's writes may still succeed for a while
		// (TCP send buffering), but the browser will never renew the read
		// deadline via a pong, so the next ReadMessage in the ws->ssh loop
		// below fails once the deadline lapses -- breaking that loop and
		// driving teardown.
		_ = conn.SetReadDeadline(time.Now().Add(cfg.PongWait))
		conn.SetPongHandler(func(string) error {
			return conn.SetReadDeadline(time.Now().Add(cfg.PongWait))
		})
		go func() {
			ticker := time.NewTicker(cfg.PingPeriod)
			defer ticker.Stop()
			for {
				select {
				case <-done:
					return
				case <-ticker.C:
					writeMu.Lock()
					perr := conn.WriteControl(websocket.PingMessage, nil, time.Now().Add(cfg.WriteWait))
					writeMu.Unlock()
					if perr != nil {
						forceClose()
						return
					}
				}
			}
		}()

		// (b) SSH keepalive (target side). Detects a target that goes
		// silently dead without ever sending EOF (e.g. a network partition
		// with no clean FIN/RST) -- the WS-side deadline above only guards
		// against a dead browser, not a dead target.
		go func() {
			ticker := time.NewTicker(cfg.SSHKeepaliveInterval)
			defer ticker.Stop()
			for {
				select {
				case <-done:
					return
				case <-ticker.C:
					if _, _, kerr := client.SendRequest("keepalive@openssh.com", true, nil); kerr != nil { // scrub:allow=email -- an SSH request name, not an address
						forceClose()
						return
					}
				}
			}
		}()

		// (c) Absolute max-session cutoff. Bounds how long key material can
		// stay resident even under continuous legitimate activity.
		go func() {
			timer := time.NewTimer(cfg.MaxSessionDuration)
			defer timer.Stop()
			select {
			case <-done:
			case <-timer.C:
				forceClose()
			}
		}()

		writeToWS := func(p []byte) error {
			writeMu.Lock()
			defer writeMu.Unlock()
			return conn.WriteMessage(websocket.BinaryMessage, p)
		}

		var wg sync.WaitGroup
		pump := func(src io.Reader) {
			defer wg.Done()
			buf := make([]byte, 32*1024)
			for {
				n, rerr := src.Read(buf)
				if n > 0 {
					if werr := writeToWS(buf[:n]); werr != nil {
						_ = conn.Close()
						return
					}
				}
				if rerr != nil {
					_ = conn.Close()
					return
				}
			}
		}
		wg.Add(2)
		go pump(tgt.stdout)
		go pump(tgt.stderr)

		// ws -> ssh stdin (plus resize control frames).
		for {
			mt, data, rerr := conn.ReadMessage()
			if rerr != nil {
				break
			}
			if mt == websocket.TextMessage {
				var rm resizeMsg
				if json.Unmarshal(data, &rm) == nil && rm.Type == "resize" && rm.Cols > 0 && rm.Rows > 0 {
					_ = sshSess.WindowChange(rm.Rows, rm.Cols)
				}
				continue
			}
			if _, werr := tgt.stdin.Write(data); werr != nil {
				break
			}
		}
		_ = tgt.stdin.Close()
		wg.Wait()
	}
}

// The two host-key refusals. Their text is what the client is shown.
var (
	errHostKeyNotPinned = errors.New("host key not pinned for this target")
	errHostKeyMismatch  = errors.New("host key mismatch")
)

// parsePins parses the session's pinned host keys and lists the host key
// algorithms to ask for, so a host with several keys presents a pinned one.
// Pins were checked by the vault and again by CreateSession; one that still
// fails to parse is dropped, which can only make the check stricter.
func parsePins(sess *session.Session) (pins []ssh.PublicKey, algos []string) {
	for _, line := range sess.HostKeys {
		pub, _, _, _, err := ssh.ParseAuthorizedKey([]byte(line))
		if err != nil {
			logger.Warn().Str("target_id", sess.TargetID).Msg("dropping a pinned host key that does not parse")
			continue
		}
		pins = append(pins, pub)
		for _, a := range hostKeyAlgorithmsFor(pub.Type()) {
			if !slices.Contains(algos, a) {
				algos = append(algos, a)
			}
		}
	}
	return pins, algos
}

// hostKeyAlgorithmsFor maps a key type to the host key algorithms that prove
// it. An RSA key signs with SHA-2 only; the SHA-1 "ssh-rsa" algorithm is not
// offered.
func hostKeyAlgorithmsFor(keyType string) []string {
	if keyType == ssh.KeyAlgoRSA {
		return []string{ssh.KeyAlgoRSASHA512, ssh.KeyAlgoRSASHA256}
	}
	return []string{keyType}
}

// pinnedHostKeyCallback accepts the host only when it presents one of the
// pinned keys. It runs during key exchange, before the session's key is
// offered, so an unverified host never sees the credential. It logs the
// presented key's SHA256 fingerprint and the outcome, never key material.
func pinnedHostKeyCallback(sess *session.Session, pins []ssh.PublicKey) ssh.HostKeyCallback {
	return func(_ string, _ net.Addr, key ssh.PublicKey) error {
		fp := ssh.FingerprintSHA256(key)
		ev := func(outcome string) {
			logger.Info().
				Str("host", sess.Host).
				Str("target_id", sess.TargetID).
				Str("secret_id", sess.SecretID).
				Str("actor_user_id", sess.ActorUserID).
				Str("host_key_fingerprint", fp).
				Int("pinned_keys", len(pins)).
				Str("outcome", outcome).
				Msg("ssh host key check")
		}
		if len(pins) == 0 {
			ev("not pinned")
			return errHostKeyNotPinned
		}
		presented := key.Marshal()
		for _, p := range pins {
			if bytes.Equal(p.Marshal(), presented) {
				ev("verified")
				return nil
			}
		}
		ev("mismatch")
		return errHostKeyMismatch
	}
}

// hostKeyRefusal reports whether a dial failed on the host key check, and the
// message to show the client.
func hostKeyRefusal(err error) (string, bool) {
	switch {
	case errors.Is(err, errHostKeyNotPinned):
		return errHostKeyNotPinned.Error(), true
	case errors.Is(err, errHostKeyMismatch):
		return errHostKeyMismatch.Error(), true
	}
	return "", false
}

// errNoKeyFetcher is returned when a reference ticket needs a vault fetch but no
// KeyFetcher was configured (e.g. inline-only deployments).
var errNoKeyFetcher = errors.New("reference ticket but no vault key fetcher configured")

// parseSigner parses the session's private key, using the passphrase-aware
// parser when a passphrase is present. Key material is read only from the
// session's byte-slice accessors and never logged.
func parseSigner(sess *session.Session) (ssh.Signer, error) {
	if len(sess.PassphraseBytes()) > 0 {
		return ssh.ParsePrivateKeyWithPassphrase(sess.KeyBytes(), sess.PassphraseBytes())
	}
	return ssh.ParsePrivateKey(sess.KeyBytes())
}

// addr formats the session's target as a dial address.
func addr(sess *session.Session) string {
	return net.JoinHostPort(sess.Host, strconv.Itoa(int(sess.Port)))
}

// logFailure logs a session failure branch for on-call diagnosability. Only
// host/target_id/secret_id/actor_user_id/reason (plus the returned error,
// which comes from the ssh/websocket libraries and never carries key
// material) are logged -- never the private key or passphrase.
func logFailure(sess *session.Session, reason string, err error) {
	logger.Error().
		Err(err).
		Str("host", sess.Host).
		Str("target_id", sess.TargetID).
		Str("secret_id", sess.SecretID).
		Str("actor_user_id", sess.ActorUserID).
		Str("reason", reason).
		Msg("ssh session failed")
}

// endAudit emits a best-effort session.end event. It is nil-tolerant so
// tests can pass a nil *audit.Emitter.
func endAudit(aud *audit.Emitter, sess *session.Session, reason string) {
	if aud == nil {
		return
	}
	dur := time.Since(sess.Started)
	aud.End(context.Background(), sess.ActorUserID, sess.SecretID, sess.TargetID, dur, reason)
}
