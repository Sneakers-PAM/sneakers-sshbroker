// Copyright 2026 The Sneakers-PAM Authors
// SPDX-License-Identifier: Apache-2.0

package wsproxy

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"strconv"
	"strings"
	"sync"
	"syscall"
	"testing"
	"time"

	"github.com/gorilla/websocket"
	"golang.org/x/crypto/ssh"
	"google.golang.org/grpc"

	auditv1 "github.com/Sneakers-PAM/sneakers-sshbroker/gen/go/thirdparty/audit/v1"
	"github.com/Sneakers-PAM/sneakers-sshbroker/internal/audit"
	"github.com/Sneakers-PAM/sneakers-sshbroker/internal/session"
)

// fastOpen shrinks every open-path bound so a stalled step fails in
// milliseconds instead of the production seconds.
func fastOpen() Config {
	return Config{
		RevealTimeout:    300 * time.Millisecond,
		DialTimeout:      300 * time.Millisecond,
		HandshakeTimeout: 300 * time.Millisecond,
		ShellTimeout:     300 * time.Millisecond,
		OpenTimeout:      5 * time.Second,
	}
}

// assertFailedWS dials the WebSocket, expects the broker to close it with
// an internal-error frame whose text contains want, and returns how long
// the open took.
func assertFailedWS(t *testing.T, srv *httptest.Server, ticket, want string) time.Duration {
	t.Helper()
	started := time.Now()
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
	if ce.Code != websocket.CloseInternalServerErr || !strings.Contains(ce.Text, want) {
		t.Fatalf("close = %d %q, want %d containing %q", ce.Code, ce.Text, websocket.CloseInternalServerErr, want)
	}
	return time.Since(started)
}

// startSilentTarget accepts TCP connections and never says a word: no SSH
// banner, no key exchange, as a wedged sshd or a middlebox that swallows the
// connection would.
func startSilentTarget(t *testing.T) (host string, port int) {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	var mu sync.Mutex
	var held []net.Conn
	t.Cleanup(func() {
		_ = ln.Close()
		mu.Lock()
		defer mu.Unlock()
		for _, c := range held {
			_ = c.Close()
		}
	})
	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			mu.Lock()
			held = append(held, c)
			mu.Unlock()
		}
	}()
	return "127.0.0.1", ln.Addr().(*net.TCPAddr).Port
}

// startNoShellTarget is an SSH server that verifies the client and then
// never answers a session channel open, so the shell never starts.
func startNoShellTarget(t *testing.T, authorizedPub ssh.PublicKey) (host string, port int, pin string) {
	t.Helper()
	hostKey := newHostSigner(t)
	cfg := &ssh.ServerConfig{
		PublicKeyCallback: func(_ ssh.ConnMetadata, key ssh.PublicKey) (*ssh.Permissions, error) {
			if string(key.Marshal()) == string(authorizedPub.Marshal()) {
				return &ssh.Permissions{}, nil
			}
			return nil, errors.New("unauthorized key")
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
			go func() {
				sc, chans, reqs, err := ssh.NewServerConn(c, cfg)
				if err != nil {
					return
				}
				go ssh.DiscardRequests(reqs)
				for range chans { //nolint:revive // hold every channel open request unanswered
				}
				_ = sc.Close()
			}()
		}
	}()
	return "127.0.0.1", ln.Addr().(*net.TCPAddr).Port, pinOf(hostKey)
}

// closedPort returns a local port with nothing listening on it.
func closedPort(t *testing.T) int {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	port := ln.Addr().(*net.TCPAddr).Port
	_ = ln.Close()
	return port
}

// hangingVault is a KeyFetcher that never answers until its context ends.
type hangingVault struct{}

func (hangingVault) FetchKey(ctx context.Context, _ *session.Session) ([]byte, []byte, error) {
	<-ctx.Done()
	return nil, nil, ctx.Err()
}

// recordingAudit keeps every audit event the broker records.
type recordingAudit struct {
	auditv1.AuditServiceClient
	mu     sync.Mutex
	events []*auditv1.RecordEventRequest
}

func (r *recordingAudit) RecordEvent(_ context.Context, in *auditv1.RecordEventRequest, _ ...grpc.CallOption) (*auditv1.RecordEventResponse, error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.events = append(r.events, in)
	return &auditv1.RecordEventResponse{}, nil
}

func (r *recordingAudit) endReason(t *testing.T) string {
	t.Helper()
	deadline := time.Now().Add(2 * time.Second)
	for time.Now().Before(deadline) {
		r.mu.Lock()
		for _, e := range r.events {
			if e.GetAction() == "session.end" {
				r.mu.Unlock()
				return e.GetAttributes()["reason"]
			}
		}
		r.mu.Unlock()
		time.Sleep(10 * time.Millisecond)
	}
	t.Fatal("no session.end audit event")
	return ""
}

func TestOpenFailsWhenTargetNeverAnswersSSH(t *testing.T) {
	pemPriv, _ := genClientKey(t)
	host, port := startSilentTarget(t)

	store := newTestStore(t)
	id, ticket := pinnedSession(t, store, host, port, pemPriv, []string{pinOf(newHostSigner(t))})
	srv := httptest.NewServer(HandlerWithConfig(store, nil, nil, fastOpen()))
	defer srv.Close()

	took := assertFailedWS(t, srv, ticket, "didn't finish the SSH handshake")
	if took > 3*time.Second {
		t.Fatalf("open took %s, want it bounded by the handshake timeout", took)
	}
	waitRemoved(t, store, id)
}

func TestOpenFailsWhenTargetRefusesTheConnection(t *testing.T) {
	pemPriv, _ := genClientKey(t)
	port := closedPort(t)

	store := newTestStore(t)
	_, ticket := pinnedSession(t, store, "127.0.0.1", port, pemPriv, []string{pinOf(newHostSigner(t))})
	srv := httptest.NewServer(HandlerWithConfig(store, nil, nil, fastOpen()))
	defer srv.Close()

	assertFailedWS(t, srv, ticket, "can't reach 127.0.0.1:"+strconv.Itoa(port)+": connection refused")
}

func TestOpenFailsWhenTheKeyIsRefused(t *testing.T) {
	_, authorizedPub := genClientKey(t)
	wrongPem, _ := genClientKey(t)
	hostKey := newHostSigner(t)
	host, port, _ := startKeyedEchoSSHServer(t, authorizedPub, hostKey)

	store := newTestStore(t)
	_, ticket := pinnedSession(t, store, host, port, wrongPem, []string{pinOf(hostKey)})
	srv := httptest.NewServer(HandlerWithConfig(store, nil, nil, fastOpen()))
	defer srv.Close()

	assertFailedWS(t, srv, ticket, "refused the key for tester")
}

func TestOpenFailsWhenTheShellNeverStarts(t *testing.T) {
	pemPriv, pub := genClientKey(t)
	host, port, pin := startNoShellTarget(t, pub)

	store := newTestStore(t)
	id, ticket := pinnedSession(t, store, host, port, pemPriv, []string{pin})
	srv := httptest.NewServer(HandlerWithConfig(store, nil, nil, fastOpen()))
	defer srv.Close()

	took := assertFailedWS(t, srv, ticket, "didn't start a shell")
	if took > 3*time.Second {
		t.Fatalf("open took %s, want it bounded by the shell timeout", took)
	}
	waitRemoved(t, store, id)
}

func TestOpenFailsWhenTheVaultHangs(t *testing.T) {
	store := newTestStore(t)
	id, ticket, _, _ := store.Create(session.Params{
		Host: "192.0.2.10", Port: 22, Username: "tester", SecretID: "secret-1",
		ActorUserID: "user-1", Actor: session.Actor{UserID: "user-1"}, TTL: 5 * time.Second,
	})
	rec := &recordingAudit{}
	srv := httptest.NewServer(HandlerWithConfig(store, audit.New(rec), hangingVault{}, fastOpen()))
	defer srv.Close()

	took := assertFailedWS(t, srv, ticket, "the vault didn't answer")
	if took > 3*time.Second {
		t.Fatalf("open took %s, want it bounded by the reveal timeout", took)
	}
	waitRemoved(t, store, id)
	if got := rec.endReason(t); !strings.Contains(got, "the vault didn't answer") {
		t.Fatalf("session.end reason = %q, want the step and reason", got)
	}
}

// The whole open has its own bound, below the sum of the step bounds.
func TestOpenIsBoundedAsAWhole(t *testing.T) {
	store := newTestStore(t)
	_, ticket, _, _ := store.Create(session.Params{
		Host: "192.0.2.10", Port: 22, Username: "tester", SecretID: "secret-1",
		ActorUserID: "user-1", Actor: session.Actor{UserID: "user-1"}, TTL: 5 * time.Second,
	})
	cfg := fastOpen()
	cfg.RevealTimeout = time.Hour
	cfg.OpenTimeout = 300 * time.Millisecond
	srv := httptest.NewServer(HandlerWithConfig(store, nil, hangingVault{}, cfg))
	defer srv.Close()

	assertFailedWS(t, srv, ticket, "the vault didn't answer")
}

// A client that isn't a WebSocket gets the same sentence as a 502 body.
func TestOpenFailureOverPlainHTTP(t *testing.T) {
	pemPriv, _ := genClientKey(t)
	port := closedPort(t)

	store := newTestStore(t)
	_, ticket := pinnedSession(t, store, "127.0.0.1", port, pemPriv, []string{pinOf(newHostSigner(t))})
	srv := httptest.NewServer(HandlerWithConfig(store, nil, nil, fastOpen()))
	defer srv.Close()

	resp, err := http.Get(wsURLForHTTP(srv, ticket))
	if err != nil {
		t.Fatalf("get: %v", err)
	}
	defer func() { _ = resp.Body.Close() }()
	body := make([]byte, 512)
	n, _ := resp.Body.Read(body)
	if resp.StatusCode != http.StatusBadGateway || !strings.Contains(string(body[:n]), "connection refused") {
		t.Fatalf("got %d %q, want 502 naming the refused connection", resp.StatusCode, body[:n])
	}
}

func TestReachFailureSentences(t *testing.T) {
	timeout := &net.OpError{Op: "dial", Net: "tcp", Err: timeoutErr{}}
	for _, tc := range []struct {
		err  error
		want string
	}{
		{timeout, "can't reach 192.0.2.10:22: connection timed out"},
		{context.DeadlineExceeded, "can't reach 192.0.2.10:22: connection timed out"},
		{&net.OpError{Op: "dial", Net: "tcp", Err: syscall.ECONNREFUSED}, "can't reach 192.0.2.10:22: connection refused"},
		{&net.OpError{Op: "dial", Net: "tcp", Err: syscall.EHOSTUNREACH}, "can't reach 192.0.2.10:22: no route to host"},
		{&net.OpError{Op: "dial", Net: "tcp", Err: syscall.ENETUNREACH}, "can't reach 192.0.2.10:22: network is unreachable"},
		{&net.DNSError{Name: "app01.example.org", IsNotFound: true}, "can't find app01.example.org in DNS"},
	} {
		host := "192.0.2.10"
		var dnsErr *net.DNSError
		if errors.As(tc.err, &dnsErr) {
			host = dnsErr.Name
		}
		if got := reachFailure(host, "192.0.2.10:22", tc.err); got != tc.want {
			t.Errorf("reachFailure(%v) = %q, want %q", tc.err, got, tc.want)
		}
	}
}

// A close frame holds at most 123 bytes of text; a long host name must not
// stop the reason from reaching the client.
func TestCloseTextFitsAFrame(t *testing.T) {
	long := "can't find " + strings.Repeat("a", 200) + ".example.org in DNS"
	if got := closeText(long); len(got) > 123 || !strings.HasPrefix(got, "can't find ") {
		t.Fatalf("closeText = %d bytes %q, want a prefix of at most 123 bytes", len(got), got)
	}
}

type timeoutErr struct{}

func (timeoutErr) Error() string   { return "i/o timeout" }
func (timeoutErr) Timeout() bool   { return true }
func (timeoutErr) Temporary() bool { return true }

// testLog is where the package logger writes for the whole test binary. It
// is set once in TestMain, never swapped, so handlers still tearing down
// from an earlier test can't race a test that reads it.
var testLog = &syncBuffer{}

func TestMain(m *testing.M) {
	logger = logger.Output(io.MultiWriter(testLog, os.Stderr))
	os.Exit(m.Run())
}

// captureLog returns the log lines written from now on.
func captureLog(t *testing.T) func() []map[string]any {
	t.Helper()
	from := testLog.len()
	return func() []map[string]any { return testLog.linesFrom(t, from) }
}

type syncBuffer struct {
	mu sync.Mutex
	b  bytes.Buffer
}

func (s *syncBuffer) Write(p []byte) (int, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.b.Write(p)
}

func (s *syncBuffer) len() int {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.b.Len()
}

func (s *syncBuffer) linesFrom(t *testing.T, from int) []map[string]any {
	t.Helper()
	s.mu.Lock()
	defer s.mu.Unlock()
	var out []map[string]any
	for _, l := range strings.Split(strings.TrimSpace(s.b.String()[from:]), "\n") {
		var m map[string]any
		if err := json.Unmarshal([]byte(l), &m); err == nil {
			out = append(out, m)
		}
	}
	return out
}

// Each step of an open is logged as it's reached, so a stalled open shows
// where it stopped; key material never reaches the log.
func TestOpenLogsEveryStep(t *testing.T) {
	lines := captureLog(t)
	pemPriv, pub := genClientKey(t)
	hostKey := newHostSigner(t)
	host, port, _ := startKeyedEchoSSHServer(t, pub, hostKey)

	store := newTestStore(t)
	_, ticket := pinnedSession(t, store, host, port, pemPriv, []string{pinOf(hostKey)})
	srv := httptest.NewServer(HandlerWithConfig(store, nil, nil, fastOpen()))
	defer srv.Close()

	conn, _, err := websocket.DefaultDialer.Dial(wsURLFor(srv, ticket), nil)
	if err != nil {
		t.Fatalf("dial: %v", err)
	}
	assertEcho(t, conn)
	_ = conn.Close()

	var got []string
	for _, l := range lines() {
		if l["message"] == "ssh session open step" && l["port"] == float64(port) {
			got = append(got, l["step"].(string))
			if _, ok := l["step_ms"]; !ok {
				t.Fatalf("step %v has no duration", l["step"])
			}
		}
	}
	want := []string{"tcp connected", "ssh banner received", "host key verified", "authenticated", "shell started", "upgraded"}
	if strings.Join(got, ",") != strings.Join(want, ",") {
		t.Fatalf("steps = %v, want %v", got, want)
	}
	for _, l := range lines() {
		for _, v := range l {
			if s, ok := v.(string); ok && strings.Contains(s, "PRIVATE KEY") {
				t.Fatal("key material reached the log")
			}
		}
	}
}

func TestOpenLogsTheFailedStep(t *testing.T) {
	lines := captureLog(t)
	pemPriv, _ := genClientKey(t)
	host, port := startSilentTarget(t)

	store := newTestStore(t)
	_, ticket := pinnedSession(t, store, host, port, pemPriv, []string{pinOf(newHostSigner(t))})
	srv := httptest.NewServer(HandlerWithConfig(store, nil, nil, fastOpen()))
	defer srv.Close()

	assertFailedWS(t, srv, ticket, "didn't finish the SSH handshake")
	for _, l := range lines() {
		if l["message"] == "ssh session open failed" && l["port"] == float64(port) {
			if l["step"] != "handshake" || l["level"] != "error" {
				t.Fatalf("failure line = %v, want step handshake at error", l)
			}
			return
		}
	}
	t.Fatalf("no failure line in %v", lines())
}
