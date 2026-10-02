// Copyright 2026 The Sneakers-PAM Authors
// SPDX-License-Identifier: Apache-2.0

package wsproxy

import (
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/gorilla/websocket"

	"github.com/Sneakers-PAM/sneakers-sshbroker/internal/session"
)

const uiOrigin = "https://sneakers.example.org"

func originHandler(t *testing.T, store session.TicketStore) *httptest.Server {
	t.Helper()
	srv := httptest.NewServer(HandlerWithConfig(store, nil, nil, Config{AllowedOrigins: []string{uiOrigin}}))
	t.Cleanup(srv.Close)
	return srv
}

func dialWithOrigin(t *testing.T, srv *httptest.Server, ticket, origin string) (*websocket.Conn, *http.Response, error) {
	t.Helper()
	h := http.Header{}
	if origin != "" {
		h.Set("Origin", origin)
	}
	return websocket.DefaultDialer.Dial(wsURLFor(srv, ticket), h)
}

// TestHandlerRefusesUnlistedOrigin: a page on another origin can't open a
// session, and the refusal comes before the ticket is used, so the ticket is
// still good for the real UI.
func TestHandlerRefusesUnlistedOrigin(t *testing.T) {
	pemPriv, pub := genClientKey(t)
	host, port, hostPin, stop := startEchoSSHServer(t, pub)
	defer stop()
	store := newTestStore(t)
	_, ticket, _ := store.Create(session.Params{
		Host: host, Port: int32(port), Username: "tester", PrivateKey: pemPriv,
		HostKeys: []string{hostPin}, TTL: 5 * time.Second,
	})
	srv := originHandler(t, store)

	for _, origin := range []string{"https://evil.example.net", "http://sneakers.example.org", "https://sneakers.example.org:8443", "null"} {
		_, resp, err := dialWithOrigin(t, srv, ticket, origin)
		if err == nil {
			t.Fatalf("origin %q: upgrade accepted", origin)
		}
		if resp == nil || resp.StatusCode != http.StatusForbidden {
			t.Fatalf("origin %q: resp = %v, want 403", origin, resp)
		}
	}

	conn, _, err := dialWithOrigin(t, srv, ticket, uiOrigin)
	if err != nil {
		t.Fatalf("listed origin after refusals: %v", err)
	}
	_ = conn.Close()
}

// TestHandlerAcceptsListedOrigin: the configured UI origin opens a session;
// the scheme and host compare case-insensitively.
func TestHandlerAcceptsListedOrigin(t *testing.T) {
	pemPriv, pub := genClientKey(t)
	host, port, hostPin, stop := startEchoSSHServer(t, pub)
	defer stop()
	store := newTestStore(t)
	_, ticket, _ := store.Create(session.Params{
		Host: host, Port: int32(port), Username: "tester", PrivateKey: pemPriv,
		HostKeys: []string{hostPin}, TTL: 5 * time.Second,
	})
	srv := originHandler(t, store)

	conn, _, err := dialWithOrigin(t, srv, ticket, "HTTPS://Sneakers.Example.org")
	if err != nil {
		t.Fatalf("listed origin refused: %v", err)
	}
	_ = conn.Close()
}

// TestHandlerWithNoOriginsRefusesEveryBrowserOrigin: an unconfigured handler
// fails closed for browsers.
func TestHandlerWithNoOriginsRefusesEveryBrowserOrigin(t *testing.T) {
	store := newTestStore(t)
	_, ticket, _ := store.Create(session.Params{Host: "192.0.2.1", Port: 22, Username: "u", PrivateKey: "PEM", TTL: 5 * time.Second})
	srv := httptest.NewServer(Handler(store, nil, nil))
	defer srv.Close()

	_, resp, err := dialWithOrigin(t, srv, ticket, uiOrigin)
	if err == nil || resp == nil || resp.StatusCode != http.StatusForbidden {
		t.Fatalf("resp = %v err = %v, want 403", resp, err)
	}
}

func TestParseOrigins(t *testing.T) {
	got, err := ParseOrigins(" https://sneakers.example.org , HTTP://LOCALHOST:5173 ")
	if err != nil {
		t.Fatal(err)
	}
	want := []string{"https://sneakers.example.org", "http://localhost:5173"}
	if len(got) != len(want) || got[0] != want[0] || got[1] != want[1] {
		t.Fatalf("got %q, want %q", got, want)
	}
	for _, bad := range []string{"sneakers.example.org", "https://sneakers.example.org/app", "ftp://sneakers.example.org", "https://", "*", "https://sneakers.example.org?x=1"} {
		if _, err := ParseOrigins(bad); err == nil {
			t.Fatalf("ParseOrigins(%q) accepted", bad)
		}
	}
}

func TestOriginFromWSURL(t *testing.T) {
	cases := map[string]string{
		"wss://sneakers.example.org/ssh/session":      "https://sneakers.example.org",
		"ws://localhost:9097/ssh/session":             "http://localhost:9097",
		"wss://Sneakers.Example.org:8443/proto/ssh/x": "https://sneakers.example.org:8443",
	}
	for in, want := range cases {
		got, err := OriginFromWSURL(in)
		if err != nil || got != want {
			t.Fatalf("OriginFromWSURL(%q) = %q, %v; want %q", in, got, err, want)
		}
	}
	if _, err := OriginFromWSURL("http://sneakers.example.org/ssh/session"); err == nil {
		t.Fatal("non-ws scheme accepted")
	}
}
