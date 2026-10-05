// Copyright 2026 The Sneakers-PAM Authors
// SPDX-License-Identifier: Apache-2.0

package server

import (
	"context"
	"encoding/json"
	"errors"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	log "github.com/Bugs5382/go-log"
	"github.com/Sneakers-PAM/sneakers-sshbroker/internal/health"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/credentials/insecure"
	healthpb "google.golang.org/grpc/health/grpc_health_v1"
	"google.golang.org/grpc/metadata"
	"google.golang.org/grpc/status"
)

type testClock struct {
	mu sync.Mutex
	t  time.Time
}

func (c *testClock) now() time.Time { c.mu.Lock(); defer c.mu.Unlock(); return c.t }
func (c *testClock) add(d time.Duration) {
	c.mu.Lock()
	c.t = c.t.Add(d)
	c.mu.Unlock()
}

// startWithHealth runs the server with checker and returns a health client.
func startWithHealth(t *testing.T, checker *health.Checker) healthpb.HealthClient {
	t.Helper()
	port := freePort(t)
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() { done <- RunWithHealth(ctx, port, checker, nil) }()
	t.Cleanup(func() { cancel(); <-done })
	conn, err := grpc.NewClient("127.0.0.1:"+port, grpc.WithTransportCredentials(insecure.NewCredentials()))
	if err != nil {
		t.Fatalf("dial: %v", err)
	}
	t.Cleanup(func() { _ = conn.Close() })
	return healthpb.NewHealthClient(conn)
}

func check(t *testing.T, hc healthpb.HealthClient, service string) (healthpb.HealthCheckResponse_ServingStatus, metadata.MD, error) {
	t.Helper()
	var md metadata.MD
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	resp, err := hc.Check(ctx, &healthpb.HealthCheckRequest{Service: service}, grpc.Header(&md), grpc.WaitForReady(true))
	return resp.GetStatus(), md, err
}

func healthHeader(t *testing.T, md metadata.MD) health.Report {
	t.Helper()
	v := md.Get(HeaderHealth)
	if len(v) != 1 {
		t.Fatalf("%s = %v", HeaderHealth, v)
	}
	var r health.Report
	if err := json.Unmarshal([]byte(v[0]), &r); err != nil {
		t.Fatalf("%s: %v", HeaderHealth, err)
	}
	return r
}

func TestHealth_ReadinessFollowsARequiredDependency(t *testing.T) {
	clk := &testClock{t: time.Date(2026, 10, 5, 12, 0, 0, 0, time.UTC)}
	var valkeyDown atomic.Bool
	checker := health.New(log.Nop(), []health.Dep{
		{Name: "valkey", Required: true, Check: func(context.Context) error {
			if valkeyDown.Load() {
				return errors.New("dial tcp valkey.example.test:6379: auth hunter2-secret")
			}
			return nil
		}},
		{Name: "audit", Check: func(context.Context) error { return nil }},
	}, health.WithClock(clk.now))
	hc := startWithHealth(t, checker)

	st, md, err := check(t, hc, "")
	if err != nil || st != healthpb.HealthCheckResponse_SERVING {
		t.Fatalf("ready: %v %v", st, err)
	}
	r := healthHeader(t, md)
	if r.Status != health.OK || len(r.Dependencies) != 2 || !r.Dependencies[0].Required || r.Dependencies[1].Required {
		t.Fatalf("header: %+v", r)
	}

	valkeyDown.Store(true)
	clk.add(health.CacheTTL)
	st, md, err = check(t, hc, "")
	if err != nil || st != healthpb.HealthCheckResponse_NOT_SERVING {
		t.Fatalf("valkey down: readiness %v %v, want NOT_SERVING", st, err)
	}
	if raw := strings.Join(md.Get(HeaderHealth), ""); strings.Contains(raw, "hunter2") || strings.Contains(raw, "valkey.example.test") {
		t.Fatalf("header leaks the error: %s", raw)
	}
	if r := healthHeader(t, md); r.Status != health.Down || r.Dependencies[0].State != health.Down || r.Dependencies[0].Error != "error" {
		t.Fatalf("header: %+v", r)
	}
	if st, md, err := check(t, hc, LivenessService); err != nil || st != healthpb.HealthCheckResponse_SERVING || len(md.Get(HeaderHealth)) != 0 {
		t.Fatalf("liveness while valkey is down: %v %v %v, want SERVING without the health header", st, err, md.Get(HeaderHealth))
	}

	valkeyDown.Store(false)
	if st, _, _ := check(t, hc, ""); st != healthpb.HealthCheckResponse_NOT_SERVING {
		t.Fatalf("inside the cache window: %v, want NOT_SERVING still", st)
	}
	clk.add(health.CacheTTL)
	if st, _, err := check(t, hc, ""); err != nil || st != healthpb.HealthCheckResponse_SERVING {
		t.Fatalf("recovered: %v %v", st, err)
	}
}

func TestHealth_OptionalDependencyDegradesButStaysServing(t *testing.T) {
	checker := health.New(log.Nop(), []health.Dep{
		{Name: "audit", Check: func(context.Context) error { return status.Error(codes.Unavailable, "down") }},
	})
	st, md, err := check(t, startWithHealth(t, checker), "")
	if err != nil || st != healthpb.HealthCheckResponse_SERVING {
		t.Fatalf("%v %v", st, err)
	}
	if r := healthHeader(t, md); r.Status != health.Degraded || r.Dependencies[0].State != health.Degraded || r.Dependencies[0].Error != "unavailable" {
		t.Fatalf("%+v", r)
	}
}

func TestHealth_UnknownServiceAndWatch(t *testing.T) {
	hc := startWithHealth(t, nil)
	if _, _, err := check(t, hc, "sneakers.other.v1.Nope"); status.Code(err) != codes.NotFound {
		t.Fatalf("unknown service: %v, want NotFound", err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	w, err := hc.Watch(ctx, &healthpb.HealthCheckRequest{})
	if err == nil {
		_, err = w.Recv()
	}
	if status.Code(err) != codes.Unimplemented {
		t.Fatalf("watch: %v, want Unimplemented", err)
	}
	if st, md, err := check(t, hc, ""); err != nil || st != healthpb.HealthCheckResponse_SERVING || healthHeader(t, md).Status != health.OK {
		t.Fatalf("no checker: %v %v", st, err)
	}
}
