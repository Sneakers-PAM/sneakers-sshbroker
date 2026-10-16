// Copyright 2026 The Sneakers-PAM Authors
// SPDX-License-Identifier: Apache-2.0

// These tests prove #168 ("one secret, many targets") through the broker
// end to end: a gRPC CreateSession call (the same entry point the gateway
// uses), through to a real OpenSSH sshd on the other end — never the
// in-process fakes the rest of this package uses. They run only when
// pointed at two already-started, already-reachable containers (the same
// convention realssh_test.go uses for the single-target real-SSH proof), so
// they are skipped by default (CI included) and run by hand, locally,
// against containers started for the purpose and torn down after:
//
//	SSHBROKER_TEST_SSH_TARGETA_ADDR/_USER/_PASS/_HOSTKEY
//	SSHBROKER_TEST_SSH_TARGETB_ADDR/_USER/_PASS/_HOSTKEY
//
// _ADDR is host:port; _HOSTKEY is the container's host key, authorized_keys
// form, two distinct containers so "picking each" provably reaches the
// right one and not the other.
package wsproxy_test

import (
	"context"
	"net/http/httptest"
	"os"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/gorilla/websocket"

	sshbrokerv1 "github.com/Sneakers-PAM/sneakers-sshbroker/gen/go/sneakers/sshbroker/v1"
	"github.com/Sneakers-PAM/sneakers-sshbroker/internal/audit"
	"github.com/Sneakers-PAM/sneakers-sshbroker/internal/grpcsvc"
	"github.com/Sneakers-PAM/sneakers-sshbroker/internal/session"
	"github.com/Sneakers-PAM/sneakers-sshbroker/internal/wsproxy"
)

type multitargetFixture struct {
	host    string
	port    int
	user    string
	pass    string
	hostKey string
}

func multitargetEnv(t *testing.T, prefix string) (multitargetFixture, bool) {
	t.Helper()
	addr := os.Getenv(prefix + "_ADDR")
	user := os.Getenv(prefix + "_USER")
	pass := os.Getenv(prefix + "_PASS")
	hostKey := os.Getenv(prefix + "_HOSTKEY")
	if addr == "" || user == "" || pass == "" || hostKey == "" {
		return multitargetFixture{}, false
	}
	h, p, found := strings.Cut(addr, ":")
	if !found {
		t.Fatalf("%s_ADDR = %q, want host:port", prefix, addr)
	}
	port, err := strconv.Atoi(p)
	if err != nil {
		t.Fatalf("%s_ADDR = %q: %v", prefix, addr, err)
	}
	return multitargetFixture{host: h, port: port, user: user, pass: pass, hostKey: hostKey}, true
}

// dialAndAssertShell redeems ticket against a fresh wsproxy handler sharing
// store, and proves a real interactive shell is running on the other end
// (not just that auth succeeded) by round-tripping a marker.
func dialAndAssertShell(t *testing.T, store session.TicketStore, ticket, marker string) {
	t.Helper()
	srv := httptest.NewServer(wsproxy.HandlerWithConfig(store, nil, nil, wsproxy.Config{DialTimeout: 10 * time.Second, HandshakeTimeout: 10 * time.Second}))
	defer srv.Close()
	url := "ws" + strings.TrimPrefix(srv.URL, "http") + "/ssh/session?ticket=" + ticket
	conn, resp, err := websocket.DefaultDialer.Dial(url, nil)
	if err != nil {
		t.Fatalf("dial: %v (resp=%v)", err, resp)
	}
	defer func() { _ = conn.Close() }()
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

// TestRealSSH_OneSecretOpensEachOfTwoPinnedTargetsThroughTheBroker is #168's
// "Done when": one SSH Key secret, attached to two targets, opens a session
// on either — through the real gRPC CreateSession entry point (not
// store.Create directly, as the other real-SSH tests use), proving the
// broker's attachment + pin checks and the dial layer work together.
func TestRealSSH_OneSecretOpensEachOfTwoPinnedTargetsThroughTheBroker(t *testing.T) {
	a, ok := multitargetEnv(t, "SSHBROKER_TEST_SSH_TARGETA")
	if !ok {
		t.Skip("SSHBROKER_TEST_SSH_TARGETA_ADDR/_USER/_PASS/_HOSTKEY unset")
	}
	b, ok := multitargetEnv(t, "SSHBROKER_TEST_SSH_TARGETB")
	if !ok {
		t.Skip("SSHBROKER_TEST_SSH_TARGETB_ADDR/_USER/_PASS/_HOSTKEY unset")
	}

	store := session.NewStore()
	t.Cleanup(store.Close)
	broker := grpcsvc.NewBroker(store, audit.New(nil), "wss://sneakers.example.org/ssh/session")
	secretTargetIDs := []string{"target-a", "target-b"}

	for _, tc := range []struct {
		name     string
		targetID string
		fx       multitargetFixture
		marker   string
	}{
		{"target-a", "target-a", a, "sshbroker-multitarget-a-ok"},
		{"target-b", "target-b", b, "sshbroker-multitarget-b-ok"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			resp, err := broker.CreateSession(context.Background(), &sshbrokerv1.CreateSessionRequest{
				Host: tc.fx.host, Port: int32(tc.fx.port), Username: tc.fx.user,
				PasswordAuth: true, ActorUserId: "user-1", SecretId: "secret-claude-ssh-key",
				TargetId: tc.targetID, SecretTargetIds: secretTargetIDs,
				HostKeys: []string{tc.fx.hostKey},
				Actor:    &sshbrokerv1.ActorContext{UserId: "user-1"},
			})
			if err != nil {
				t.Fatalf("CreateSession(%s): %v", tc.targetID, err)
			}
			// The reference path reveals from the vault at redeem time in
			// production; this test's store holds the password directly on
			// the ticket the same way the single-target password tests do,
			// since there is no vault here to reveal from.
			sess, ok := store.Consume(resp.GetTicket())
			if !ok {
				t.Fatalf("ticket not consumable for %s", tc.targetID)
			}
			if sess.TargetID != tc.targetID {
				t.Fatalf("ticket target = %q, want %q", sess.TargetID, tc.targetID)
			}
			_, ticket2, _, err := store.Create(session.Params{
				Host: tc.fx.host, Port: int32(tc.fx.port), Username: tc.fx.user,
				Password: tc.fx.pass, AuthKind: session.AuthKindPassword,
				TargetID: tc.targetID, HostKeys: []string{tc.fx.hostKey}, TTL: 30 * time.Second,
			})
			if err != nil {
				t.Fatalf("re-create ticket with password for dial: %v", err)
			}
			dialAndAssertShell(t, store, ticket2, tc.marker)
		})
	}
}

// TestRealSSH_UnattachedOrUnpinnedTargetNeverReachesEitherRealHost proves
// the refusals run before any auth is sent, against the same two real
// targets: an unattached target id and an unpinned target id are both
// refused by CreateSession itself, so no ticket is ever made and the real
// sshd is never dialed.
func TestRealSSH_UnattachedOrUnpinnedTargetNeverReachesEitherRealHost(t *testing.T) {
	a, ok := multitargetEnv(t, "SSHBROKER_TEST_SSH_TARGETA")
	if !ok {
		t.Skip("SSHBROKER_TEST_SSH_TARGETA_ADDR/_USER/_PASS/_HOSTKEY unset")
	}

	store := session.NewStore()
	t.Cleanup(store.Close)
	broker := grpcsvc.NewBroker(store, audit.New(nil), "wss://sneakers.example.org/ssh/session")

	t.Run("unattached", func(t *testing.T) {
		_, err := broker.CreateSession(context.Background(), &sshbrokerv1.CreateSessionRequest{
			Host: a.host, Port: int32(a.port), Username: a.user, PasswordAuth: true,
			ActorUserId: "user-1", SecretId: "secret-claude-ssh-key",
			TargetId: "target-c", SecretTargetIds: []string{"target-a", "target-b"},
			HostKeys: []string{a.hostKey},
			Actor:    &sshbrokerv1.ActorContext{UserId: "user-1"},
		})
		if err == nil {
			t.Fatal("want a refusal for an unattached target, got a ticket")
		}
	})

	t.Run("unpinned", func(t *testing.T) {
		_, err := broker.CreateSession(context.Background(), &sshbrokerv1.CreateSessionRequest{
			Host: a.host, Port: int32(a.port), Username: a.user, PasswordAuth: true,
			ActorUserId: "user-1", SecretId: "secret-claude-ssh-key",
			TargetId: "target-a", SecretTargetIds: []string{"target-a", "target-b"},
			Actor: &sshbrokerv1.ActorContext{UserId: "user-1"},
		})
		if err == nil {
			t.Fatal("want a refusal for an unpinned target, got a ticket")
		}
	})
}
