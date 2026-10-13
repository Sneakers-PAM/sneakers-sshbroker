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
	_, ticket, _, _ := store.Create(session.Params{
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
	_, ticket, _, _ := store.Create(session.Params{
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
	_, ticket, _, _ := store.Create(session.Params{Host: "192.0.2.1", Port: 22, Username: "u", PrivateKey: "PEM", TTL: 5 * time.Second})
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

// TestOriginCheckerSameOrigin: a browser Origin that names the host and port
// the request itself was sent to (its Host header) is the page's own origin,
// whether the box was opened by its name, an IPv4 address or an IPv6
// address. Another site is still refused, and no Origin keeps today's
// behaviour (allowed; the ticket still has to be valid).
func TestOriginCheckerSameOrigin(t *testing.T) {
	c := newOriginChecker([]string{uiOrigin})
	cases := []struct {
		name, origin, host string
		want               bool
	}{
		{"listed origin, any host", "https://sneakers.example.org", "192.0.2.10", true},
		{"fqdn same origin", "https://box.example.org", "box.example.org", true},
		{"fqdn same origin, case-insensitive", "HTTPS://Box.Example.ORG", "box.EXAMPLE.org", true},
		{"fqdn same origin with port", "https://box.example.org:8443", "box.example.org:8443", true},
		{"ipv4 same origin", "https://192.0.2.10", "192.0.2.10", true},
		{"ipv4 same origin with port", "https://192.0.2.10:8443", "192.0.2.10:8443", true},
		{"ipv4 default port written out", "https://192.0.2.10", "192.0.2.10:443", true},
		{"ipv6 same origin", "https://[2001:db8::1]", "[2001:db8::1]", true},
		{"ipv6 same origin with port", "https://[2001:db8::1]:8443", "[2001:db8::1]:8443", true},
		{"ipv6 same origin, case-insensitive", "https://[2001:DB8::A]", "[2001:db8::a]", true},
		{"ipv6 same address, other spelling", "https://[2001:db8:0:0::1]", "[2001:db8::1]", true},
		{"ipv6 default port written out", "https://[2001:db8::1]", "[2001:db8::1]:443", true},
		{"no origin", "", "box.example.org", true},
		{"cross-site name", "https://evil.example.net", "box.example.org", false},
		{"cross-site ipv4", "https://192.0.2.99", "192.0.2.10", false},
		{"cross-site ipv6", "https://[2001:db8::99]", "[2001:db8::1]", false},
		{"ipv6 origin, ipv4 host", "https://[2001:db8::1]", "192.0.2.10", false},
		{"same host, other port", "https://box.example.org:8443", "box.example.org", false},
		{"ipv6 same host, other port", "https://[2001:db8::1]:8443", "[2001:db8::1]", false},
		{"ipv6 zone id in the origin", "https://[fe80::1%25eth0]", "[fe80::1%25eth0]", false},
		{"ipv6 zone id in the host", "https://[fe80::1]", "[fe80::1%25eth0]", false},
		{"unbracketed ipv6 host", "https://[2001:db8::1]", "2001:db8::1", false},
		{"opaque origin", "null", "box.example.org", false},
		{"origin with a path", "https://box.example.org/x", "box.example.org", false},
		{"no host header", "https://box.example.org", "", false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			r := httptest.NewRequest(http.MethodGet, "/ssh/session", nil)
			r.Host = tc.host
			if tc.origin != "" {
				r.Header.Set("Origin", tc.origin)
			}
			if got := c.allowed(r); got != tc.want {
				t.Fatalf("allowed(Origin %q, Host %q) = %v, want %v", tc.origin, tc.host, got, tc.want)
			}
		})
	}
}

// TestHandlerAcceptsSameOriginByAddress: a page opened by the box's address
// (not its configured name) opens a session on its own origin, for IPv4 and
// IPv6, end to end through the handler.
func TestHandlerAcceptsSameOriginByAddress(t *testing.T) {
	for _, tc := range []struct{ origin, host string }{
		{"https://192.0.2.10", "192.0.2.10"},
		{"https://[2001:db8::1]", "[2001:db8::1]"},
		{"https://box.example.org", "box.example.org"},
	} {
		t.Run(tc.host, func(t *testing.T) {
			pemPriv, pub := genClientKey(t)
			host, port, hostPin, stop := startEchoSSHServer(t, pub)
			defer stop()
			store := newTestStore(t)
			_, ticket, _, _ := store.Create(session.Params{
				Host: host, Port: int32(port), Username: "tester", PrivateKey: pemPriv,
				HostKeys: []string{hostPin}, TTL: 5 * time.Second,
			})
			srv := originHandler(t, store)
			h := http.Header{}
			h.Set("Origin", tc.origin)
			h.Set("Host", tc.host)
			conn, _, err := websocket.DefaultDialer.Dial(wsURLFor(srv, ticket), h)
			if err != nil {
				t.Fatalf("same-origin %s refused: %v", tc.origin, err)
			}
			_ = conn.Close()
		})
	}
}

// TestHandlerRefusesCrossSiteByAddress: an Origin that names another host
// than the one the request was sent to is refused before the ticket is used.
func TestHandlerRefusesCrossSiteByAddress(t *testing.T) {
	store := newTestStore(t)
	_, ticket, _, _ := store.Create(session.Params{Host: "192.0.2.1", Port: 22, Username: "u", PrivateKey: "PEM", TTL: 5 * time.Second})
	srv := originHandler(t, store)
	for _, tc := range []struct{ origin, host string }{
		{"https://evil.example.net", "192.0.2.10"},
		{"https://[2001:db8::99]", "[2001:db8::1]"},
	} {
		h := http.Header{}
		h.Set("Origin", tc.origin)
		h.Set("Host", tc.host)
		_, resp, err := websocket.DefaultDialer.Dial(wsURLFor(srv, ticket), h)
		if err == nil || resp == nil || resp.StatusCode != http.StatusForbidden {
			t.Fatalf("origin %q host %q: resp = %v err = %v, want 403", tc.origin, tc.host, resp, err)
		}
	}
	if _, ok := store.Consume(ticket); !ok {
		t.Fatal("a refused origin used up the ticket")
	}
}
