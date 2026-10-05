// Copyright 2026 The Sneakers-PAM Authors
// SPDX-License-Identifier: Apache-2.0

package server

import (
	"context"
	"net/http"
	"os"
	"os/exec"
	"testing"
	"time"

	log "github.com/Bugs5382/go-log"
	bredis "github.com/Bugs5382/go-redis"
	"github.com/Sneakers-PAM/sneakers-sshbroker/internal/health"
	"github.com/Sneakers-PAM/sneakers-sshbroker/internal/session"
	healthpb "google.golang.org/grpc/health/grpc_health_v1"
)

// TestReadiness_RealValkeyStopsAndStarts stops a real Valkey mid-test:
// readiness goes NOT_SERVING (and /readyz 503), liveness stays up, and
// readiness recovers after Valkey is back and the cache window passes. It runs
// only with SSHBROKER_TEST_VALKEY_ADDR (host:port, a fixed host port so it
// survives the restart) and SSHBROKER_TEST_VALKEY_CONTAINER (the container to
// stop and start) set.
func TestReadiness_RealValkeyStopsAndStarts(t *testing.T) {
	addr, container := os.Getenv("SSHBROKER_TEST_VALKEY_ADDR"), os.Getenv("SSHBROKER_TEST_VALKEY_CONTAINER")
	if addr == "" || container == "" {
		t.Skip("SSHBROKER_TEST_VALKEY_ADDR and SSHBROKER_TEST_VALKEY_CONTAINER unset")
	}
	ctx := context.Background()
	rc, err := bredis.Connect(ctx, bredis.WithAddr(addr))
	if err != nil {
		t.Fatalf("connect: %v", err)
	}
	t.Cleanup(func() { _ = rc.Close() })
	store := session.NewRequiredComposite(session.NewStore())
	t.Cleanup(store.Close)
	store.Attach(session.NewRedisStore(rc))

	clk := &testClock{t: time.Now()}
	checker := health.New(log.Nop(), []health.Dep{{Name: "valkey", Required: true, Check: store.Ping}}, health.WithClock(clk.now))
	hc := startWithHealth(t, checker)
	mux := http.NewServeMux()
	RegisterHTTPHealth(mux, checker)

	if st, _, err := check(t, hc, ""); err != nil || st != healthpb.HealthCheckResponse_SERVING {
		t.Fatalf("valkey up: %v %v", st, err)
	}
	docker := func(args ...string) {
		t.Helper()
		if out, err := exec.Command("docker", args...).CombinedOutput(); err != nil {
			t.Fatalf("docker %v: %v %s", args, err, out)
		}
	}
	docker("stop", container)
	t.Cleanup(func() { _ = exec.Command("docker", "start", container).Run() })
	clk.add(health.CacheTTL)
	if st, _, err := check(t, hc, ""); err != nil || st != healthpb.HealthCheckResponse_NOT_SERVING {
		t.Fatalf("valkey stopped: readiness %v %v, want NOT_SERVING", st, err)
	}
	if rec := get(t, mux, "/readyz"); rec.Code != http.StatusServiceUnavailable {
		t.Fatalf("valkey stopped: /readyz %d, want 503", rec.Code)
	}
	if st, _, err := check(t, hc, LivenessService); err != nil || st != healthpb.HealthCheckResponse_SERVING {
		t.Fatalf("valkey stopped: liveness %v %v, want SERVING", st, err)
	}
	if rec := get(t, mux, "/livez"); rec.Code != http.StatusOK {
		t.Fatalf("valkey stopped: /livez %d, want 200", rec.Code)
	}

	docker("start", container)
	deadline := time.Now().Add(30 * time.Second)
	for {
		clk.add(health.CacheTTL)
		st, _, err := check(t, hc, "")
		if err == nil && st == healthpb.HealthCheckResponse_SERVING {
			break
		}
		if time.Now().After(deadline) {
			t.Fatalf("valkey back: readiness %v %v, want SERVING", st, err)
		}
		time.Sleep(200 * time.Millisecond)
	}
}
