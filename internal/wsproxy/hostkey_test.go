// Copyright 2026 The Sneakers-PAM Authors
// SPDX-License-Identifier: Apache-2.0

package wsproxy

import (
	"crypto"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/rsa"
	"errors"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/gorilla/websocket"
	"golang.org/x/crypto/ssh"

	"github.com/Sneakers-PAM/sneakers-sshbroker/internal/session"
)

// newHostSigner returns a fresh ed25519 SSH host key, generated per run.
func newHostSigner(t *testing.T) ssh.Signer {
	t.Helper()
	_, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("host key: %v", err)
	}
	return signerFrom(t, priv)
}

func signerFrom(t *testing.T, k crypto.Signer) ssh.Signer {
	t.Helper()
	s, err := ssh.NewSignerFromSigner(k)
	if err != nil {
		t.Fatalf("host signer: %v", err)
	}
	return s
}

// pinOf renders a host key as a pin: authorized_keys form, no newline.
func pinOf(s ssh.Signer) string {
	return strings.TrimSpace(string(ssh.MarshalAuthorizedKey(s.PublicKey())))
}

// startKeyedEchoSSHServer is startEchoSSHServer with the host keys chosen by
// the caller. authAttempts counts client public-key offers, so a test can
// prove a refused host never saw the session's credential.
func startKeyedEchoSSHServer(t *testing.T, authorizedPub ssh.PublicKey, hostKeys ...ssh.Signer) (host string, port int, authAttempts *atomic.Int32) {
	t.Helper()
	authAttempts = &atomic.Int32{}
	cfg := &ssh.ServerConfig{
		PublicKeyCallback: func(_ ssh.ConnMetadata, key ssh.PublicKey) (*ssh.Permissions, error) {
			authAttempts.Add(1)
			if string(key.Marshal()) == string(authorizedPub.Marshal()) {
				return &ssh.Permissions{}, nil
			}
			return nil, errors.New("unauthorized key")
		},
	}
	for _, hk := range hostKeys {
		cfg.AddHostKey(hk)
	}
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	t.Cleanup(func() { _ = ln.Close() })
	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			go handleTestConn(c, cfg)
		}
	}()
	return "127.0.0.1", ln.Addr().(*net.TCPAddr).Port, authAttempts
}

func pinnedSession(t *testing.T, store *session.Store, host string, port int, key string, pins []string) (id, ticket string) {
	t.Helper()
	id, ticket, _ = store.Create(session.Params{
		Host: host, Port: int32(port), Username: "tester", PrivateKey: key,
		TargetID: "target-1", HostKeys: pins, TTL: 5 * time.Second,
	})
	return id, ticket
}

func assertEcho(t *testing.T, conn *websocket.Conn) {
	t.Helper()
	msg := []byte("pinned hello\n")
	if err := conn.WriteMessage(websocket.BinaryMessage, msg); err != nil {
		t.Fatalf("write: %v", err)
	}
	_ = conn.SetReadDeadline(time.Now().Add(5 * time.Second))
	_, data, err := conn.ReadMessage()
	if err != nil {
		t.Fatalf("read: %v", err)
	}
	if string(data) != string(msg) {
		t.Fatalf("echo = %q, want %q", data, msg)
	}
}

// assertRefusedWS dials the WebSocket and expects the broker to close it with
// a policy-violation frame carrying want, the reason a browser can show.
func assertRefusedWS(t *testing.T, srv *httptest.Server, ticket, want string) {
	t.Helper()
	conn, resp, err := websocket.DefaultDialer.Dial(wsURLFor(srv, ticket), nil)
	if err != nil {
		t.Fatalf("dial: %v (resp=%v)", err, resp)
	}
	defer func() { _ = conn.Close() }()
	_ = conn.SetReadDeadline(time.Now().Add(5 * time.Second))
	_, _, err = conn.ReadMessage()
	var ce *websocket.CloseError
	if !errors.As(err, &ce) {
		t.Fatalf("read err = %v, want a close frame", err)
	}
	if ce.Code != websocket.ClosePolicyViolation || ce.Text != want {
		t.Fatalf("close = %d %q, want %d %q", ce.Code, ce.Text, websocket.ClosePolicyViolation, want)
	}
}

func waitRemoved(t *testing.T, store *session.Store, id string) {
	t.Helper()
	deadline := time.Now().Add(2 * time.Second)
	for store.Contains(id) {
		if time.Now().After(deadline) {
			t.Fatal("session was not removed from the store")
		}
		time.Sleep(10 * time.Millisecond)
	}
}

func TestHandlerConnectsWhenHostKeyPinned(t *testing.T) {
	pemPriv, pub := genClientKey(t)
	hostKey := newHostSigner(t)
	host, port, _ := startKeyedEchoSSHServer(t, pub, hostKey)

	store := newTestStore(t)
	// The matching pin need not be first.
	_, ticket := pinnedSession(t, store, host, port, pemPriv, []string{pinOf(newHostSigner(t)), pinOf(hostKey) + " app01"})
	srv := httptest.NewServer(Handler(store, nil, nil))
	defer srv.Close()

	conn, resp, err := websocket.DefaultDialer.Dial(wsURLFor(srv, ticket), nil)
	if err != nil {
		t.Fatalf("dial: %v (resp=%v)", err, resp)
	}
	defer func() { _ = conn.Close() }()
	assertEcho(t, conn)
}

// A host with several host keys is asked for the pinned key's algorithm, so a
// pin on its RSA key works even though it would offer ed25519 first.
func TestHandlerNegotiatesPinnedAlgorithm(t *testing.T) {
	pemPriv, pub := genClientKey(t)
	rsaKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	rsaHost := signerFrom(t, rsaKey)
	host, port, _ := startKeyedEchoSSHServer(t, pub, newHostSigner(t), rsaHost)

	store := newTestStore(t)
	_, ticket := pinnedSession(t, store, host, port, pemPriv, []string{pinOf(rsaHost)})
	srv := httptest.NewServer(Handler(store, nil, nil))
	defer srv.Close()

	conn, resp, err := websocket.DefaultDialer.Dial(wsURLFor(srv, ticket), nil)
	if err != nil {
		t.Fatalf("dial: %v (resp=%v)", err, resp)
	}
	defer func() { _ = conn.Close() }()
	assertEcho(t, conn)
}

func TestHandlerRefusesHostKeyMismatch(t *testing.T) {
	pemPriv, pub := genClientKey(t)
	host, port, authAttempts := startKeyedEchoSSHServer(t, pub, newHostSigner(t))

	store := newTestStore(t)
	id, ticket := pinnedSession(t, store, host, port, pemPriv, []string{pinOf(newHostSigner(t))})
	srv := httptest.NewServer(Handler(store, nil, nil))
	defer srv.Close()

	assertRefusedWS(t, srv, ticket, "host key mismatch")
	waitRemoved(t, store, id)
	if n := authAttempts.Load(); n != 0 {
		t.Fatalf("client key offered %d times to an unverified host", n)
	}
}

func TestHandlerRefusesUnpinnedTarget(t *testing.T) {
	pemPriv, pub := genClientKey(t)
	host, port, authAttempts := startKeyedEchoSSHServer(t, pub, newHostSigner(t))

	store := newTestStore(t)
	id, ticket := pinnedSession(t, store, host, port, pemPriv, nil)
	srv := httptest.NewServer(Handler(store, nil, nil))
	defer srv.Close()

	assertRefusedWS(t, srv, ticket, "host key not pinned for this target")
	waitRemoved(t, store, id)
	if n := authAttempts.Load(); n != 0 {
		t.Fatalf("client key offered %d times to an unpinned host", n)
	}
}

// A client that isn't a WebSocket gets the same reason as an HTTP error body.
func TestHandlerHostKeyRefusalOverPlainHTTP(t *testing.T) {
	pemPriv, pub := genClientKey(t)
	host, port, _ := startKeyedEchoSSHServer(t, pub, newHostSigner(t))

	store := newTestStore(t)
	_, ticket := pinnedSession(t, store, host, port, pemPriv, []string{pinOf(newHostSigner(t))})
	srv := httptest.NewServer(Handler(store, nil, nil))
	defer srv.Close()

	resp, err := http.Get(wsURLForHTTP(srv, ticket))
	if err != nil {
		t.Fatalf("get: %v", err)
	}
	body, _ := io.ReadAll(resp.Body)
	_ = resp.Body.Close()
	if resp.StatusCode != http.StatusBadGateway || strings.TrimSpace(string(body)) != "host key mismatch" {
		t.Fatalf("got %d %q, want 502 %q", resp.StatusCode, body, "host key mismatch")
	}
}
