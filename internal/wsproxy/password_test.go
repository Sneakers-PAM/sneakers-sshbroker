// Copyright 2026 The Sneakers-PAM Authors
// SPDX-License-Identifier: Apache-2.0

package wsproxy

import (
	"errors"
	"net"
	"net/http/httptest"
	"sync/atomic"
	"testing"
	"time"

	"github.com/gorilla/websocket"
	"golang.org/x/crypto/ssh"

	"github.com/Sneakers-PAM/sneakers-sshbroker/internal/audit"
	"github.com/Sneakers-PAM/sneakers-sshbroker/internal/session"
)

// startPasswordEchoSSHServer is startKeyedEchoSSHServer for SSH password
// auth: an OpenSSH-style sshd configured with PasswordAuthentication yes,
// KbdInteractiveAuthentication no. attempts counts password offers, so a
// test can prove the broker never retries a wrong one.
func startPasswordEchoSSHServer(t *testing.T, username, password string) (host string, port int, hostPin string, attempts *atomic.Int32) {
	t.Helper()
	attempts = &atomic.Int32{}
	hostKey := newHostSigner(t)
	cfg := &ssh.ServerConfig{
		PasswordCallback: func(c ssh.ConnMetadata, pw []byte) (*ssh.Permissions, error) {
			attempts.Add(1)
			if c.User() == username && string(pw) == password {
				return &ssh.Permissions{}, nil
			}
			return nil, errors.New("wrong password")
		},
	}
	cfg.AddHostKey(hostKey)
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
	return "127.0.0.1", ln.Addr().(*net.TCPAddr).Port, pinOf(hostKey), attempts
}

// startKeyboardInteractiveEchoSSHServer stands in for a target that offers
// only keyboard-interactive (e.g. a Cisco-style device): one prompt,
// answered with the password. PasswordAuthentication is not offered at all.
func startKeyboardInteractiveEchoSSHServer(t *testing.T, username, password string) (host string, port int, hostPin string, attempts *atomic.Int32) {
	t.Helper()
	attempts = &atomic.Int32{}
	hostKey := newHostSigner(t)
	cfg := &ssh.ServerConfig{
		KeyboardInteractiveCallback: func(c ssh.ConnMetadata, client ssh.KeyboardInteractiveChallenge) (*ssh.Permissions, error) {
			attempts.Add(1)
			answers, err := client("", "", []string{"Password: "}, []bool{false})
			if err != nil {
				return nil, err
			}
			if c.User() == username && len(answers) == 1 && answers[0] == password {
				return &ssh.Permissions{}, nil
			}
			return nil, errors.New("wrong password")
		},
	}
	cfg.AddHostKey(hostKey)
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
	return "127.0.0.1", ln.Addr().(*net.TCPAddr).Port, pinOf(hostKey), attempts
}

// startTOTPKeyboardInteractiveSSHServer stands in for a target that asks a
// second keyboard-interactive question (a TOTP code, say) after the
// password -- sneakers-sshbroker#68 scope, out of reach of a password-only
// secret.
func startTOTPKeyboardInteractiveSSHServer(t *testing.T, username, password string) (host string, port int, hostPin string) {
	t.Helper()
	hostKey := newHostSigner(t)
	cfg := &ssh.ServerConfig{
		KeyboardInteractiveCallback: func(c ssh.ConnMetadata, client ssh.KeyboardInteractiveChallenge) (*ssh.Permissions, error) {
			answers, err := client("", "", []string{"Password: "}, []bool{false})
			if err != nil {
				return nil, err
			}
			if c.User() != username || len(answers) != 1 || answers[0] != password {
				return nil, errors.New("wrong password")
			}
			if _, err := client("", "", []string{"Verification code: "}, []bool{false}); err != nil {
				return nil, err
			}
			return nil, errors.New("never reached in this test")
		},
	}
	cfg.AddHostKey(hostKey)
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
	return "127.0.0.1", ln.Addr().(*net.TCPAddr).Port, pinOf(hostKey)
}

// startPAMStyleKeyboardInteractiveSSHServer stands in for a real PAM-backed
// sshd (Debian's, for one): a password round, then a second round with NO
// questions at all (a PAM acknowledgment), before success. That empty round
// must be answered with no answers, not mistaken for a second credential
// prompt.
func startPAMStyleKeyboardInteractiveSSHServer(t *testing.T, username, password string) (host string, port int, hostPin string) {
	t.Helper()
	hostKey := newHostSigner(t)
	cfg := &ssh.ServerConfig{
		KeyboardInteractiveCallback: func(c ssh.ConnMetadata, client ssh.KeyboardInteractiveChallenge) (*ssh.Permissions, error) {
			answers, err := client("", "", []string{"Password: "}, []bool{false})
			if err != nil {
				return nil, err
			}
			if c.User() != username || len(answers) != 1 || answers[0] != password {
				return nil, errors.New("wrong password")
			}
			if _, err := client("", "", nil, nil); err != nil {
				return nil, err
			}
			return &ssh.Permissions{}, nil
		},
	}
	cfg.AddHostKey(hostKey)
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
	return "127.0.0.1", ln.Addr().(*net.TCPAddr).Port, pinOf(hostKey)
}

// pinnedPasswordSession is pinnedSession for a password (AuthKindPassword)
// session.
func pinnedPasswordSession(t *testing.T, store *session.Store, host string, port int, username, password string, pins []string) (id, ticket string) {
	t.Helper()
	id, ticket, _, _ = store.Create(session.Params{
		Host: host, Port: int32(port), Username: username,
		AuthKind: session.AuthKindPassword, Password: password,
		TargetID: "target-1", HostKeys: pins, TTL: 5 * time.Second,
	})
	return id, ticket
}

// A password secret opens a terminal against an sshd that only takes
// password auth, same as a key secret does today.
func TestHandlerConnectsWithPasswordAuth(t *testing.T) {
	host, port, pin, attempts := startPasswordEchoSSHServer(t, "tester", "hunter2")

	store := newTestStore(t)
	_, ticket := pinnedPasswordSession(t, store, host, port, "tester", "hunter2", []string{pin})
	rec := &recordingAudit{}
	srv := httptest.NewServer(HandlerWithConfig(store, audit.New(rec), nil, fastOpen()))
	defer srv.Close()

	conn, resp, err := websocket.DefaultDialer.Dial(wsURLFor(srv, ticket), nil)
	if err != nil {
		t.Fatalf("dial: %v (resp=%v)", err, resp)
	}
	defer func() { _ = conn.Close() }()
	assertEcho(t, conn)
	if n := attempts.Load(); n != 1 {
		t.Fatalf("password offered %d times, want exactly 1", n)
	}
}

// A password secret also opens a terminal against a target that only speaks
// keyboard-interactive (standing in for a Cisco-style device), answering its
// single prompt with the password.
func TestHandlerConnectsWithKeyboardInteractiveAuth(t *testing.T) {
	host, port, pin, attempts := startKeyboardInteractiveEchoSSHServer(t, "tester", "hunter2")

	store := newTestStore(t)
	_, ticket := pinnedPasswordSession(t, store, host, port, "tester", "hunter2", []string{pin})
	srv := httptest.NewServer(Handler(store, nil, nil))
	defer srv.Close()

	conn, resp, err := websocket.DefaultDialer.Dial(wsURLFor(srv, ticket), nil)
	if err != nil {
		t.Fatalf("dial: %v (resp=%v)", err, resp)
	}
	defer func() { _ = conn.Close() }()
	assertEcho(t, conn)
	if n := attempts.Load(); n != 1 {
		t.Fatalf("keyboard-interactive offered %d times, want exactly 1", n)
	}
}

// A wrong password fails once, with a one-line reason, and is never retried
// against the target.
func TestOpenFailsWhenThePasswordIsWrong(t *testing.T) {
	host, port, pin, attempts := startPasswordEchoSSHServer(t, "tester", "hunter2")

	store := newTestStore(t)
	_, ticket := pinnedPasswordSession(t, store, host, port, "tester", "wrong-password", []string{pin})
	srv := httptest.NewServer(HandlerWithConfig(store, nil, nil, fastOpen()))
	defer srv.Close()

	assertFailedWS(t, srv, ticket, "the target refused the password")
	if n := attempts.Load(); n != 1 {
		t.Fatalf("password offered %d times, want exactly 1 (no retry loop)", n)
	}
}

// A target that asks for more than a password (a second keyboard-interactive
// round, e.g. a TOTP step) is refused with its own reason instead of the
// password being sent again as a wrong answer.
func TestOpenFailsWhenTargetAsksForMoreThanAPassword(t *testing.T) {
	host, port, pin := startTOTPKeyboardInteractiveSSHServer(t, "tester", "hunter2")

	store := newTestStore(t)
	_, ticket := pinnedPasswordSession(t, store, host, port, "tester", "hunter2", []string{pin})
	srv := httptest.NewServer(HandlerWithConfig(store, nil, nil, fastOpen()))
	defer srv.Close()

	assertFailedWS(t, srv, ticket, "the target asked for more than a password")
}

// A keyboard-interactive round with no questions at all (a PAM
// acknowledgment, as a real Debian sshd sends after the password round) is
// answered with no answers and does not block the login, the same as a real
// SSH client.
func TestHandlerConnectsThroughAPAMStyleEmptyRound(t *testing.T) {
	host, port, pin := startPAMStyleKeyboardInteractiveSSHServer(t, "tester", "hunter2")

	store := newTestStore(t)
	_, ticket := pinnedPasswordSession(t, store, host, port, "tester", "hunter2", []string{pin})
	srv := httptest.NewServer(Handler(store, nil, nil))
	defer srv.Close()

	conn, resp, err := websocket.DefaultDialer.Dial(wsURLFor(srv, ticket), nil)
	if err != nil {
		t.Fatalf("dial: %v (resp=%v)", err, resp)
	}
	defer func() { _ = conn.Close() }()
	assertEcho(t, conn)
}

// Every session's audit carries its auth method: a key session carries
// publickey, and a password session carries whichever of password/
// keyboard-interactive the target actually accepted.
func TestAuditCarriesTheAuthMethod(t *testing.T) {
	t.Run("publickey", func(t *testing.T) {
		pemPriv, pub := genClientKey(t)
		hostKey := newHostSigner(t)
		host, port, _ := startKeyedEchoSSHServer(t, pub, hostKey)
		store := newTestStore(t)
		_, ticket := pinnedSession(t, store, host, port, pemPriv, []string{pinOf(hostKey)})
		rec := &recordingAudit{}
		srv := httptest.NewServer(HandlerWithConfig(store, audit.New(rec), nil, fastOpen()))
		defer srv.Close()
		conn, _, err := websocket.DefaultDialer.Dial(wsURLFor(srv, ticket), nil)
		if err != nil {
			t.Fatalf("dial: %v", err)
		}
		assertEcho(t, conn)
		_ = conn.Close()
		if got := rec.endAttr(t, "auth_method"); got != "publickey" {
			t.Fatalf("auth_method = %q, want publickey", got)
		}
	})
	t.Run("password", func(t *testing.T) {
		host, port, pin, _ := startPasswordEchoSSHServer(t, "tester", "hunter2")
		store := newTestStore(t)
		_, ticket := pinnedPasswordSession(t, store, host, port, "tester", "hunter2", []string{pin})
		rec := &recordingAudit{}
		srv := httptest.NewServer(HandlerWithConfig(store, audit.New(rec), nil, fastOpen()))
		defer srv.Close()
		conn, _, err := websocket.DefaultDialer.Dial(wsURLFor(srv, ticket), nil)
		if err != nil {
			t.Fatalf("dial: %v", err)
		}
		assertEcho(t, conn)
		_ = conn.Close()
		if got := rec.endAttr(t, "auth_method"); got != "password" {
			t.Fatalf("auth_method = %q, want password", got)
		}
	})
	t.Run("keyboard-interactive", func(t *testing.T) {
		host, port, pin, _ := startKeyboardInteractiveEchoSSHServer(t, "tester", "hunter2")
		store := newTestStore(t)
		_, ticket := pinnedPasswordSession(t, store, host, port, "tester", "hunter2", []string{pin})
		rec := &recordingAudit{}
		srv := httptest.NewServer(HandlerWithConfig(store, audit.New(rec), nil, fastOpen()))
		defer srv.Close()
		conn, _, err := websocket.DefaultDialer.Dial(wsURLFor(srv, ticket), nil)
		if err != nil {
			t.Fatalf("dial: %v", err)
		}
		assertEcho(t, conn)
		_ = conn.Close()
		if got := rec.endAttr(t, "auth_method"); got != "keyboard-interactive" {
			t.Fatalf("auth_method = %q, want keyboard-interactive", got)
		}
	})
}
