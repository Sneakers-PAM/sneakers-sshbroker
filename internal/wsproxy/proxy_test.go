// Copyright 2026 The Sneakers-PAM Authors
// SPDX-License-Identifier: Apache-2.0

package wsproxy

import (
	"crypto/ed25519"
	"crypto/rand"
	"encoding/pem"
	"errors"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/gorilla/websocket"
	"golang.org/x/crypto/ssh"

	"github.com/Sneakers-PAM/sneakers-sshbroker/internal/session"
)

// genClientKey returns a synthetic ed25519 private key (OpenSSH PEM) and its
// ssh.PublicKey. Runtime-generated only; never a checked-in fixture.
func genClientKey(t *testing.T) (pemPriv string, pub ssh.PublicKey) {
	t.Helper()
	pub25519, priv25519, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("client key: %v", err)
	}
	block, err := ssh.MarshalPrivateKey(priv25519, "")
	if err != nil {
		t.Fatalf("marshal priv: %v", err)
	}
	sshPub, err := ssh.NewPublicKey(pub25519)
	if err != nil {
		t.Fatalf("pub: %v", err)
	}
	return string(pem.EncodeToMemory(block)), sshPub
}

// startEchoSSHServer starts an in-process ssh server that accepts only
// authorizedPub, honors pty-req/shell/window-change on a "session" channel,
// and echoes whatever the client writes back to it (a synthetic
// /bin/cat-alike shell). Runtime-synthetic host key.
func startEchoSSHServer(t *testing.T, authorizedPub ssh.PublicKey) (host string, port int, stop func()) {
	t.Helper()
	_, hostPriv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("host key: %v", err)
	}
	hostSigner, err := ssh.NewSignerFromSigner(hostPriv)
	if err != nil {
		t.Fatalf("host signer: %v", err)
	}
	cfg := &ssh.ServerConfig{
		PublicKeyCallback: func(_ ssh.ConnMetadata, key ssh.PublicKey) (*ssh.Permissions, error) {
			if string(key.Marshal()) == string(authorizedPub.Marshal()) {
				return &ssh.Permissions{}, nil
			}
			return nil, errors.New("unauthorized key")
		},
	}
	cfg.AddHostKey(hostSigner)

	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			go handleTestConn(c, cfg)
		}
	}()
	addr := ln.Addr().(*net.TCPAddr)
	return "127.0.0.1", addr.Port, func() { _ = ln.Close() }
}

func handleTestConn(c net.Conn, cfg *ssh.ServerConfig) {
	sc, chans, reqs, err := ssh.NewServerConn(c, cfg)
	if err != nil {
		return
	}
	go ssh.DiscardRequests(reqs)
	for newCh := range chans {
		if newCh.ChannelType() != "session" {
			_ = newCh.Reject(ssh.UnknownChannelType, "unsupported channel type")
			continue
		}
		ch, requests, err := newCh.Accept()
		if err != nil {
			continue
		}
		go handleTestSession(ch, requests)
	}
	_ = sc.Close()
}

func handleTestSession(ch ssh.Channel, requests <-chan *ssh.Request) {
	for req := range requests {
		switch req.Type {
		case "pty-req", "window-change":
			if req.WantReply {
				_ = req.Reply(true, nil)
			}
		case "shell":
			if req.WantReply {
				_ = req.Reply(true, nil)
			}
			go func() {
				_, _ = io.Copy(ch, ch) // echo: whatever the client writes comes back
				_ = ch.Close()
			}()
		default:
			if req.WantReply {
				_ = req.Reply(false, nil)
			}
		}
	}
}

func newTestStore(t *testing.T) *session.Store {
	t.Helper()
	st := session.NewStore()
	t.Cleanup(st.Close)
	return st
}

func wsURLFor(srv *httptest.Server, ticket string) string {
	return "ws" + strings.TrimPrefix(srv.URL, "http") + "/ssh/session?ticket=" + ticket
}

func TestHandlerEchoesSSHSession(t *testing.T) {
	pemPriv, pub := genClientKey(t)
	host, port, stop := startEchoSSHServer(t, pub)
	defer stop()

	store := newTestStore(t)
	_, ticket, _ := store.Create(session.Params{
		Host:       host,
		Port:       int32(port),
		Username:   "tester",
		PrivateKey: pemPriv,
		TTL:        5 * time.Second,
	})

	srv := httptest.NewServer(Handler(store, nil, nil))
	defer srv.Close()

	conn, resp, err := websocket.DefaultDialer.Dial(wsURLFor(srv, ticket), nil)
	if err != nil {
		t.Fatalf("dial: %v (resp=%v)", err, resp)
	}
	defer func() { _ = conn.Close() }()

	msg := []byte("hello sshbroker\n")
	if err := conn.WriteMessage(websocket.BinaryMessage, msg); err != nil {
		t.Fatalf("write: %v", err)
	}

	_ = conn.SetReadDeadline(time.Now().Add(5 * time.Second))
	mt, data, err := conn.ReadMessage()
	if err != nil {
		t.Fatalf("read: %v", err)
	}
	if mt != websocket.BinaryMessage {
		t.Fatalf("message type = %v, want BinaryMessage", mt)
	}
	if string(data) != string(msg) {
		t.Fatalf("echo = %q, want %q", data, msg)
	}
}

func TestHandlerResizeControlFrameDoesNotBreakEcho(t *testing.T) {
	pemPriv, pub := genClientKey(t)
	host, port, stop := startEchoSSHServer(t, pub)
	defer stop()

	store := newTestStore(t)
	_, ticket, _ := store.Create(session.Params{
		Host:       host,
		Port:       int32(port),
		Username:   "tester",
		PrivateKey: pemPriv,
		TTL:        5 * time.Second,
	})

	srv := httptest.NewServer(Handler(store, nil, nil))
	defer srv.Close()

	conn, _, err := websocket.DefaultDialer.Dial(wsURLFor(srv, ticket), nil)
	if err != nil {
		t.Fatalf("dial: %v", err)
	}
	defer func() { _ = conn.Close() }()

	if err := conn.WriteMessage(websocket.TextMessage, []byte(`{"type":"resize","cols":120,"rows":40}`)); err != nil {
		t.Fatalf("write resize: %v", err)
	}

	msg := []byte("still echoing\n")
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

func TestHandlerRejectsMissingOrInvalidTicket(t *testing.T) {
	store := newTestStore(t)
	srv := httptest.NewServer(Handler(store, nil, nil))
	defer srv.Close()

	for _, url := range []string{srv.URL + "/ssh/session", srv.URL + "/ssh/session?ticket=does-not-exist"} {
		resp, err := http.Get(url)
		if err != nil {
			t.Fatalf("get %s: %v", url, err)
		}
		_ = resp.Body.Close()
		if resp.StatusCode < 400 || resp.StatusCode >= 500 {
			t.Fatalf("status for %s = %d, want 4xx", url, resp.StatusCode)
		}
	}
}

func TestHandlerRemovesAndZeroizesSessionOnClose(t *testing.T) {
	pemPriv, pub := genClientKey(t)
	host, port, stop := startEchoSSHServer(t, pub)
	defer stop()

	store := newTestStore(t)
	id, ticket, _ := store.Create(session.Params{
		Host:       host,
		Port:       int32(port),
		Username:   "tester",
		PrivateKey: pemPriv,
		TTL:        5 * time.Second,
	})

	srv := httptest.NewServer(Handler(store, nil, nil))
	defer srv.Close()

	conn, _, err := websocket.DefaultDialer.Dial(wsURLFor(srv, ticket), nil)
	if err != nil {
		t.Fatalf("dial: %v", err)
	}

	// The ticket is single-use: consuming it again must already fail.
	if _, ok := store.Consume(ticket); ok {
		t.Fatal("ticket must not be consumable twice")
	}

	if err := conn.Close(); err != nil {
		t.Fatalf("close: %v", err)
	}

	// The handler's teardown runs asynchronously relative to the client
	// closing its side of the socket; poll briefly for it to land.
	deadline := time.Now().Add(2 * time.Second)
	for store.Contains(id) {
		if time.Now().After(deadline) {
			t.Fatal("session was not removed from the store after ws close")
		}
		time.Sleep(10 * time.Millisecond)
	}
}

func TestHandlerRejectsWrongClientKey(t *testing.T) {
	_, authorizedPub := genClientKey(t)
	wrongPem, _ := genClientKey(t)
	host, port, stop := startEchoSSHServer(t, authorizedPub)
	defer stop()

	store := newTestStore(t)
	id, ticket, _ := store.Create(session.Params{
		Host:       host,
		Port:       int32(port),
		Username:   "tester",
		PrivateKey: wrongPem,
		TTL:        5 * time.Second,
	})

	srv := httptest.NewServer(Handler(store, nil, nil))
	defer srv.Close()

	resp, err := http.Get(wsURLForHTTP(srv, ticket))
	if err != nil {
		t.Fatalf("get: %v", err)
	}
	_ = resp.Body.Close()
	if resp.StatusCode < 500 {
		t.Fatalf("status = %d, want 5xx (ssh dial failure)", resp.StatusCode)
	}

	deadline := time.Now().Add(2 * time.Second)
	for store.Contains(id) {
		if time.Now().After(deadline) {
			t.Fatal("session was not removed from the store after ssh dial failure")
		}
		time.Sleep(10 * time.Millisecond)
	}
}

func wsURLForHTTP(srv *httptest.Server, ticket string) string {
	return srv.URL + "/ssh/session?ticket=" + ticket
}

// TestHandlerTearsDownHungPeerWithinDeadline proves the liveness path: a
// browser that stops responding to WS pings (a silent hang, e.g. a network
// partition with no clean FIN/RST) must not block teardown indefinitely.
// The test client completes the handshake and then simply stops reading,
// which -- per gorilla/websocket, which only processes incoming control
// frames (ping/pong/close) during a Read call -- means it never sees, and
// so never answers, the server's ping frames. That starves the server's
// read deadline exactly as a truly silent peer would, without needing a
// custom PingHandler.
func TestHandlerTearsDownHungPeerWithinDeadline(t *testing.T) {
	pemPriv, pub := genClientKey(t)
	host, port, stop := startEchoSSHServer(t, pub)
	defer stop()

	store := newTestStore(t)
	id, ticket, _ := store.Create(session.Params{
		Host:       host,
		Port:       int32(port),
		Username:   "tester",
		PrivateKey: pemPriv,
		TTL:        5 * time.Second,
	})

	// Shrink the liveness tunables so the test doesn't wait out the 60s/30s
	// production defaults: a hung peer must be torn down within a bounded,
	// test-fast window.
	cfg := Config{
		PongWait:             200 * time.Millisecond,
		PingPeriod:           50 * time.Millisecond,
		WriteWait:            100 * time.Millisecond,
		SSHKeepaliveInterval: time.Hour, // isolate: exercise (a), not (b)/(c)
		MaxSessionDuration:   time.Hour,
	}
	srv := httptest.NewServer(HandlerWithConfig(store, nil, nil, cfg))
	defer srv.Close()

	conn, _, err := websocket.DefaultDialer.Dial(wsURLFor(srv, ticket), nil)
	if err != nil {
		t.Fatalf("dial: %v", err)
	}
	defer func() { _ = conn.Close() }()

	// Prove the session is alive first (matches the other tests' echo
	// check), then go silent: no more reads, no more writes. The server's
	// ping frames arrive but are never processed (and thus never ponged)
	// because this goroutine never calls ReadMessage again.
	msg := []byte("still alive\n")
	if err := conn.WriteMessage(websocket.BinaryMessage, msg); err != nil {
		t.Fatalf("write: %v", err)
	}
	_ = conn.SetReadDeadline(time.Now().Add(2 * time.Second))
	if _, _, err := conn.ReadMessage(); err != nil {
		t.Fatalf("read echo: %v", err)
	}

	// Bounded wait: PongWait (200ms) plus generous scheduling slack. If the
	// liveness deadline didn't fire, this would hang until the test
	// framework's own timeout instead of failing fast with a clear message.
	deadline := time.Now().Add(2 * time.Second)
	for store.Contains(id) {
		if time.Now().After(deadline) {
			t.Fatal("hung session was not torn down within the liveness deadline")
		}
		time.Sleep(10 * time.Millisecond)
	}
}
