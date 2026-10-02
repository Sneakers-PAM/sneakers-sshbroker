// Copyright 2026 The Sneakers-PAM Authors
// SPDX-License-Identifier: Apache-2.0

package server

import (
	"context"
	"net/http"
	"net/http/httptest"
	"sync/atomic"
	"testing"
	"time"

	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials/insecure"
	"google.golang.org/grpc/health"
	healthpb "google.golang.org/grpc/health/grpc_health_v1"
)

// TestRunWithHealthReportsCallerStatus: the gRPC health check (the chart's
// probe) answers with the status the caller sets, so a broker waiting for
// Redis is NOT_SERVING and turns SERVING when Redis answers.
func TestRunWithHealthReportsCallerStatus(t *testing.T) {
	port := freePort(t)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	hs := health.NewServer()
	hs.SetServingStatus("", healthpb.HealthCheckResponse_NOT_SERVING)
	done := make(chan error, 1)
	go func() { done <- RunWithHealth(ctx, port, hs, func(*grpc.Server) {}) }()

	conn, err := grpc.NewClient("127.0.0.1:"+port, grpc.WithTransportCredentials(insecure.NewCredentials()))
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = conn.Close() }()
	hc := healthpb.NewHealthClient(conn)

	check := func() healthpb.HealthCheckResponse_ServingStatus {
		t.Helper()
		deadline := time.Now().Add(5 * time.Second)
		for {
			resp, err := hc.Check(ctx, &healthpb.HealthCheckRequest{})
			if err == nil {
				return resp.GetStatus()
			}
			if time.Now().After(deadline) {
				t.Fatalf("health check: %v", err)
			}
			time.Sleep(20 * time.Millisecond)
		}
	}
	if got := check(); got != healthpb.HealthCheckResponse_NOT_SERVING {
		t.Fatalf("status = %v, want NOT_SERVING", got)
	}
	hs.SetServingStatus("", healthpb.HealthCheckResponse_SERVING)
	if got := check(); got != healthpb.HealthCheckResponse_SERVING {
		t.Fatalf("status = %v, want SERVING", got)
	}
	cancel()
	if err := <-done; err != nil {
		t.Fatalf("RunWithHealth: %v", err)
	}
}

func TestHealthHandlerFollowsReadiness(t *testing.T) {
	var ready atomic.Bool
	h := HealthHandler(ready.Load)

	rec := httptest.NewRecorder()
	h(rec, httptest.NewRequest(http.MethodGet, "/health", nil))
	if rec.Code != http.StatusServiceUnavailable {
		t.Fatalf("not ready: code = %d, want 503", rec.Code)
	}
	ready.Store(true)
	rec = httptest.NewRecorder()
	h(rec, httptest.NewRequest(http.MethodGet, "/health", nil))
	if rec.Code != http.StatusOK || rec.Body.String() != "ok" {
		t.Fatalf("ready: code = %d body = %q, want 200 ok", rec.Code, rec.Body.String())
	}
}
