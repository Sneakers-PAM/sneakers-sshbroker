// Copyright 2026 The Sneakers-PAM Authors
// SPDX-License-Identifier: Apache-2.0

package server

import (
	"bytes"
	"context"
	"encoding/json"
	"net"
	"strings"
	"testing"
	"time"

	"github.com/rs/zerolog"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials/insecure"
	"google.golang.org/grpc/health"
	healthpb "google.golang.org/grpc/health/grpc_health_v1"
)

// logLines parses the JSON log lines a test logger wrote.
func logLines(t *testing.T, buf *bytes.Buffer) []map[string]any {
	t.Helper()
	var out []map[string]any
	for _, l := range strings.Split(strings.TrimSpace(buf.String()), "\n") {
		if l == "" {
			continue
		}
		m := map[string]any{}
		if err := json.Unmarshal([]byte(l), &m); err != nil {
			t.Fatalf("log line is not JSON: %q: %v", l, err)
		}
		out = append(out, m)
	}
	return out
}

func TestClientLoggingRecordsTargetMethodDurationAndStatus(t *testing.T) {
	hs := health.NewServer()
	hs.SetServingStatus("example", healthpb.HealthCheckResponse_SERVING)
	gs := grpc.NewServer()
	healthpb.RegisterHealthServer(gs, hs)
	lis, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	go func() { _ = gs.Serve(lis) }()
	t.Cleanup(gs.Stop)

	// go-log sets a process-wide level at init; debug has to pass it.
	prev := zerolog.GlobalLevel()
	zerolog.SetGlobalLevel(zerolog.DebugLevel)
	t.Cleanup(func() { zerolog.SetGlobalLevel(prev) })

	var buf bytes.Buffer
	lg := zerolog.New(&buf).Level(zerolog.DebugLevel)
	conn, err := grpc.NewClient(lis.Addr().String(), grpc.WithTransportCredentials(insecure.NewCredentials()), ClientLogging(lg))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = conn.Close() })
	hc := healthpb.NewHealthClient(conn)
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	if _, err := hc.Check(ctx, &healthpb.HealthCheckRequest{Service: "example"}); err != nil {
		t.Fatalf("ok call: %v", err)
	}
	if _, err := hc.Check(ctx, &healthpb.HealthCheckRequest{Service: "missing"}); err == nil {
		t.Fatal("expected NotFound")
	}

	lines := logLines(t, &buf)
	if len(lines) != 2 {
		t.Fatalf("want 2 log lines, got %d: %s", len(lines), buf.String())
	}
	ok, bad := lines[0], lines[1]

	if ok["level"] != "debug" || ok["status"] != "OK" {
		t.Errorf("ok call: level/status = %v/%v, want debug/OK", ok["level"], ok["status"])
	}
	if ok["target"] != lis.Addr().String() {
		t.Errorf("target = %v, want %v", ok["target"], lis.Addr().String())
	}
	if ok["method"] != "/grpc.health.v1.Health/Check" {
		t.Errorf("method = %v", ok["method"])
	}
	if _, has := ok["duration"]; !has {
		t.Errorf("duration missing: %v", ok)
	}
	if _, has := ok["error"]; has {
		t.Errorf("ok call carries an error: %v", ok)
	}

	if bad["level"] != "warn" || bad["status"] != "NotFound" {
		t.Errorf("failed call: level/status = %v/%v, want warn/NotFound", bad["level"], bad["status"])
	}
	if bad["method"] != ok["method"] || bad["target"] != ok["target"] {
		t.Errorf("failed call lost target or method: %v", bad)
	}
	if _, has := bad["error"]; !has {
		t.Errorf("failed call has no error field: %v", bad)
	}
	if strings.Contains(buf.String(), "missing") && strings.Contains(buf.String(), "example") {
		t.Errorf("request content leaked into the log: %s", buf.String())
	}
}
