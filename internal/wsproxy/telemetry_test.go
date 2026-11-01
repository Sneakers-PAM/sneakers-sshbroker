// Copyright 2026 The Sneakers-PAM Authors
// SPDX-License-Identifier: Apache-2.0

package wsproxy

import (
	"context"
	"encoding/binary"
	"net"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	otel "github.com/Bugs5382/go-otel"
	"github.com/gorilla/websocket"

	"github.com/Sneakers-PAM/sneakers-sshbroker/internal/telemetry"
	"github.com/Sneakers-PAM/sneakers-sshbroker/internal/telemetry/collectortest"
)

const canary = "CANARY-target-text-7f3a"

// startRudeTarget answers the SSH version exchange, then disconnects with
// text of its own, as a target could echo a credential back.
func startRudeTarget(t *testing.T) (host string, port int) {
	t.Helper()
	lis, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = lis.Close() })
	go func() {
		for {
			c, err := lis.Accept()
			if err != nil {
				return
			}
			go func() {
				defer func() { _ = c.Close() }()
				_, _ = c.Write([]byte("SSH-2.0-rude\r\n"))
				buf := make([]byte, 4096)
				_, _ = c.Read(buf)
				_, _ = c.Write(disconnectPacket(canary))
				_, _ = c.Read(buf)
			}()
		}
	}()
	addr := lis.Addr().(*net.TCPAddr)
	return addr.IP.String(), addr.Port
}

// disconnectPacket is an unencrypted SSH_MSG_DISCONNECT.
func disconnectPacket(text string) []byte {
	payload := []byte{1, 0, 0, 0, 2}
	payload = binary.BigEndian.AppendUint32(payload, uint32(len(text)))
	payload = append(payload, text...)
	payload = binary.BigEndian.AppendUint32(payload, 0)
	padding := 8 - (5+len(payload))%8
	if padding < 4 {
		padding += 8
	}
	out := binary.BigEndian.AppendUint32(nil, uint32(1+len(payload)+padding))
	out = append(out, byte(padding))
	out = append(out, payload...)
	return append(out, make([]byte, padding)...)
}

func logsCollector(t *testing.T) (*collectortest.Collector, func() string) {
	t.Helper()
	c := collectortest.Start(t, false)
	getenv := func(k string) string {
		if k == telemetry.EnvLogsEnabled {
			return "true"
		}
		return ""
	}
	shutdown, err := otel.InitWithOptions(context.Background(), "sshbroker", c.Endpoint, telemetry.Options(getenv)...)
	if err != nil {
		t.Fatal(err)
	}
	return c, func() string {
		if err := shutdown(context.Background()); err != nil {
			t.Fatal(err)
		}
		return c.Logs()
	}
}

func TestTargetErrorTextNeverReachesTheCollector(t *testing.T) {
	_, flush := logsCollector(t)
	lines := captureLog(t)
	pemPriv, _ := genClientKey(t)
	host, port := startRudeTarget(t)

	store := newTestStore(t)
	id, ticket := pinnedSession(t, store, host, port, pemPriv, []string{pinOf(newHostSigner(t))})
	srv := httptest.NewServer(HandlerWithConfig(store, nil, nil, fastOpen()))
	defer srv.Close()

	assertFailedWS(t, srv, ticket, canary)
	waitRemoved(t, store, id)

	// The canary must be on stdout's side, or this test proves nothing.
	var sawOnStdout bool
	for _, l := range lines() {
		if l["message"] == "ssh session open failed" && strings.Contains(l["reason"].(string), canary) {
			sawOnStdout = true
		}
	}
	if !sawOnStdout {
		t.Fatalf("target text never reached the log: %v", lines())
	}

	got := flush()
	if !strings.Contains(got, "ssh session open failed") {
		t.Fatalf("failure line wasn't exported: %s", got)
	}
	if !strings.Contains(got, "handshake") {
		t.Fatalf("stable step wasn't exported: %s", got)
	}
	if strings.Contains(got, canary) {
		t.Fatalf("target text reached the collector: %s", got)
	}
}

func TestSessionContentNeverReachesALog(t *testing.T) {
	_, flush := logsCollector(t)
	from := testLog.len()
	pemPriv, authorizedPub := genClientKey(t)
	signer := newHostSigner(t)
	host, port, _ := startKeyedEchoSSHServer(t, authorizedPub, signer)

	store := newTestStore(t)
	id, ticket := pinnedSession(t, store, host, port, pemPriv, []string{pinOf(signer)})
	srv := httptest.NewServer(HandlerWithConfig(store, nil, nil, fastOpen()))
	defer srv.Close()

	conn, _, err := websocket.DefaultDialer.Dial(wsURLFor(srv, ticket), nil)
	if err != nil {
		t.Fatal(err)
	}
	const content = "CANARY-session-content-91bd"
	if err := conn.WriteMessage(websocket.BinaryMessage, []byte(content+"\n")); err != nil {
		t.Fatal(err)
	}
	_ = conn.SetReadDeadline(time.Now().Add(5 * time.Second))
	var echoed strings.Builder
	for !strings.Contains(echoed.String(), content) {
		_, b, err := conn.ReadMessage()
		if err != nil {
			t.Fatalf("read after %q: %v", echoed.String(), err)
		}
		echoed.Write(b)
	}
	_ = conn.Close()
	waitRemoved(t, store, id)

	for _, l := range testLog.linesFrom(t, from) {
		for k, v := range l {
			if s, ok := v.(string); ok && strings.Contains(s, content) {
				t.Fatalf("session content in log field %s", k)
			}
		}
	}
	if got := flush(); strings.Contains(got, content) {
		t.Fatalf("session content reached the collector: %s", got)
	}
}
