// Copyright 2026 The Sneakers-PAM Authors
// SPDX-License-Identifier: Apache-2.0

package wsproxy

import (
	"net/http/httptest"
	"os"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/gorilla/websocket"

	"github.com/Sneakers-PAM/sneakers-sshbroker/internal/session"
)

// These tests prove the open path at the boundary, against a REAL OpenSSH
// sshd (never the in-process fakes used elsewhere in this package), the same
// way TestReadiness_RealValkeyStopsAndStarts proves readiness against a real
// Valkey: they run only when the matching env vars point at a container
// already started and reachable, so they are skipped by default (CI
// included) and run by hand, locally, against containers started for the
// purpose and torn down after:
//
//	SSHBROKER_TEST_SSH_PASSWORD_ADDR/_USER/_PASS/_HOSTKEY  -- PasswordAuthentication yes, KbdInteractiveAuthentication no
//	SSHBROKER_TEST_SSH_KBDINT_ADDR/_USER/_PASS/_HOSTKEY    -- PasswordAuthentication no, KbdInteractiveAuthentication yes
//	SSHBROKER_TEST_SSH_KEY_ADDR/_USER/_HOSTKEY + SSHBROKER_TEST_SSH_KEY_PRIVKEY_FILE (a PEM file path)
//
// _ADDR is host:port; _HOSTKEY is the container's host key, authorized_keys
// form.
func realSSHEnv(t *testing.T, prefix string) (host string, port int, user, hostKey string, ok bool) {
	t.Helper()
	addr := os.Getenv(prefix + "_ADDR")
	user = os.Getenv(prefix + "_USER")
	hostKey = os.Getenv(prefix + "_HOSTKEY")
	if addr == "" || user == "" || hostKey == "" {
		return "", 0, "", "", false
	}
	h, p, found := strings.Cut(addr, ":")
	if !found {
		t.Fatalf("%s_ADDR = %q, want host:port", prefix, addr)
	}
	port, err := strconv.Atoi(p)
	if err != nil {
		t.Fatalf("%s_ADDR = %q: %v", prefix, addr, err)
	}
	return h, port, user, hostKey, true
}

// assertShellWorks sends a command and waits for its output to appear, as
// proof a real interactive shell is running on the other end -- not just
// that auth succeeded.
func assertShellWorks(t *testing.T, conn *websocket.Conn, marker string) {
	t.Helper()
	if err := conn.WriteMessage(websocket.BinaryMessage, []byte("echo "+marker+"\n")); err != nil {
		t.Fatalf("write: %v", err)
	}
	_ = conn.SetReadDeadline(time.Now().Add(10 * time.Second))
	var got strings.Builder
	for !strings.Contains(got.String(), marker) {
		_, data, err := conn.ReadMessage()
		if err != nil {
			t.Fatalf("read: %v (got so far: %q)", err, got.String())
		}
		got.Write(data)
	}
}

func TestRealSSH_PasswordAuth(t *testing.T) {
	host, port, user, hostKey, ok := realSSHEnv(t, "SSHBROKER_TEST_SSH_PASSWORD")
	if !ok {
		t.Skip("SSHBROKER_TEST_SSH_PASSWORD_ADDR/_USER/_HOSTKEY unset")
	}
	password := os.Getenv("SSHBROKER_TEST_SSH_PASSWORD_PASS")
	if password == "" {
		t.Fatal("SSHBROKER_TEST_SSH_PASSWORD_PASS unset")
	}

	store := newTestStore(t)
	_, ticket := pinnedPasswordSession(t, store, host, port, user, password, []string{hostKey})
	srv := httptest.NewServer(HandlerWithConfig(store, nil, nil, Config{DialTimeout: 10 * time.Second, HandshakeTimeout: 10 * time.Second}))
	defer srv.Close()

	conn, resp, err := websocket.DefaultDialer.Dial(wsURLFor(srv, ticket), nil)
	if err != nil {
		t.Fatalf("dial: %v (resp=%v)", err, resp)
	}
	defer func() { _ = conn.Close() }()
	assertShellWorks(t, conn, "sshpw-password-ok")
}

func TestRealSSH_KeyboardInteractiveAuth(t *testing.T) {
	host, port, user, hostKey, ok := realSSHEnv(t, "SSHBROKER_TEST_SSH_KBDINT")
	if !ok {
		t.Skip("SSHBROKER_TEST_SSH_KBDINT_ADDR/_USER/_HOSTKEY unset")
	}
	password := os.Getenv("SSHBROKER_TEST_SSH_KBDINT_PASS")
	if password == "" {
		t.Fatal("SSHBROKER_TEST_SSH_KBDINT_PASS unset")
	}

	store := newTestStore(t)
	_, ticket := pinnedPasswordSession(t, store, host, port, user, password, []string{hostKey})
	srv := httptest.NewServer(HandlerWithConfig(store, nil, nil, Config{DialTimeout: 10 * time.Second, HandshakeTimeout: 10 * time.Second}))
	defer srv.Close()

	conn, resp, err := websocket.DefaultDialer.Dial(wsURLFor(srv, ticket), nil)
	if err != nil {
		t.Fatalf("dial: %v (resp=%v)", err, resp)
	}
	defer func() { _ = conn.Close() }()
	assertShellWorks(t, conn, "sshpw-kbdint-ok")
}

// A wrong password against a real target fails once, with the broker's own
// reason, never the target's raw protocol error.
func TestRealSSH_WrongPassword(t *testing.T) {
	host, port, user, hostKey, ok := realSSHEnv(t, "SSHBROKER_TEST_SSH_PASSWORD")
	if !ok {
		t.Skip("SSHBROKER_TEST_SSH_PASSWORD_ADDR/_USER/_HOSTKEY unset")
	}

	store := newTestStore(t)
	_, ticket := pinnedPasswordSession(t, store, host, port, user, "definitely-the-wrong-password", []string{hostKey})
	srv := httptest.NewServer(HandlerWithConfig(store, nil, nil, Config{DialTimeout: 10 * time.Second, HandshakeTimeout: 10 * time.Second}))
	defer srv.Close()

	assertFailedWS(t, srv, ticket, "the target refused the password")
}

// A real target's host key that was never pinned, or that changed since it
// was, is refused before any credential is sent -- the same check that runs
// against the in-process fakes, proven here against real OpenSSH key
// exchange framing.
func TestRealSSH_HostKeyNotPinned(t *testing.T) {
	host, port, user, _, ok := realSSHEnv(t, "SSHBROKER_TEST_SSH_PASSWORD")
	if !ok {
		t.Skip("SSHBROKER_TEST_SSH_PASSWORD_ADDR/_USER/_HOSTKEY unset")
	}
	password := os.Getenv("SSHBROKER_TEST_SSH_PASSWORD_PASS")

	store := newTestStore(t)
	_, ticket := pinnedPasswordSession(t, store, host, port, user, password, nil) // no pins at all
	srv := httptest.NewServer(HandlerWithConfig(store, nil, nil, Config{DialTimeout: 10 * time.Second, HandshakeTimeout: 10 * time.Second}))
	defer srv.Close()

	assertRefusedWS(t, srv, ticket, "host key not pinned for this target")
}

func TestRealSSH_HostKeyChanged(t *testing.T) {
	host, port, user, _, ok := realSSHEnv(t, "SSHBROKER_TEST_SSH_PASSWORD")
	if !ok {
		t.Skip("SSHBROKER_TEST_SSH_PASSWORD_ADDR/_USER/_HOSTKEY unset")
	}
	password := os.Getenv("SSHBROKER_TEST_SSH_PASSWORD_PASS")

	store := newTestStore(t)
	wrongPin := pinOf(newHostSigner(t)) // a key the real target never presents
	_, ticket := pinnedPasswordSession(t, store, host, port, user, password, []string{wrongPin})
	srv := httptest.NewServer(HandlerWithConfig(store, nil, nil, Config{DialTimeout: 10 * time.Second, HandshakeTimeout: 10 * time.Second}))
	defer srv.Close()

	assertRefusedWS(t, srv, ticket, "host key mismatch")
}

func TestRealSSH_KeyAuth(t *testing.T) {
	host, port, user, hostKey, ok := realSSHEnv(t, "SSHBROKER_TEST_SSH_KEY")
	if !ok {
		t.Skip("SSHBROKER_TEST_SSH_KEY_ADDR/_USER/_HOSTKEY unset")
	}
	keyFile := os.Getenv("SSHBROKER_TEST_SSH_KEY_PRIVKEY_FILE")
	if keyFile == "" {
		t.Fatal("SSHBROKER_TEST_SSH_KEY_PRIVKEY_FILE unset")
	}
	pem, err := os.ReadFile(keyFile) //nolint:gosec // a test-only path named by the operator via env, not user input
	if err != nil {
		t.Fatalf("read key file: %v", err)
	}

	store := newTestStore(t)
	_, ticket, _, _ := store.Create(session.Params{
		Host: host, Port: int32(port), Username: user, PrivateKey: string(pem),
		TargetID: "target-1", HostKeys: []string{hostKey}, TTL: 30 * time.Second,
	})
	srv := httptest.NewServer(HandlerWithConfig(store, nil, nil, Config{DialTimeout: 10 * time.Second, HandshakeTimeout: 10 * time.Second}))
	defer srv.Close()

	conn, resp, err := websocket.DefaultDialer.Dial(wsURLFor(srv, ticket), nil)
	if err != nil {
		t.Fatalf("dial: %v (resp=%v)", err, resp)
	}
	defer func() { _ = conn.Close() }()
	assertShellWorks(t, conn, "sshpw-key-ok")
}
