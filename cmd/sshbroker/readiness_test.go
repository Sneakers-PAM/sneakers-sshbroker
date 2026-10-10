// Copyright 2026 The Sneakers-PAM Authors
// SPDX-License-Identifier: Apache-2.0

package main

import (
	"context"
	"testing"
	"time"

	"github.com/Bugs5382/go-buildinfo/health"
	log "github.com/Bugs5382/go-log"
	workloadauth "github.com/Bugs5382/go-workload-identity"
	"github.com/Sneakers-PAM/sneakers-sshbroker/internal/server"
	"github.com/Sneakers-PAM/sneakers-sshbroker/internal/session"
	"google.golang.org/grpc"
	healthpb "google.golang.org/grpc/health/grpc_health_v1"
)

type peer struct {
	st healthpb.HealthCheckResponse_ServingStatus
}

func (p peer) Check(context.Context, *healthpb.HealthCheckRequest, ...grpc.CallOption) (*healthpb.HealthCheckResponse, error) {
	return &healthpb.HealthCheckResponse{Status: p.st}, nil
}

func checker(t *testing.T, deps []health.Dependency) *health.Checker {
	t.Helper()
	c, err := server.NewChecker(log.Nop(), deps)
	if err != nil {
		t.Fatal(err)
	}
	// Reports read what the background refresh recorded: run it, as the
	// server does, and wait for its first pass.
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	go func() { c.Run(ctx); close(done) }()
	t.Cleanup(func() { cancel(); <-done })
	deadline := time.Now().Add(5 * time.Second)
	for {
		pending := false
		for _, d := range c.Report(context.Background()).Dependencies {
			pending = pending || d.Error == health.ClassPending
		}
		if !pending {
			return c
		}
		if time.Now().After(deadline) {
			t.Fatal("the first background refresh never settled")
		}
		time.Sleep(10 * time.Millisecond)
	}
}

func states(r health.Report) map[string]health.DependencyReport {
	out := map[string]health.DependencyReport{}
	for _, d := range r.Dependencies {
		out[d.Name] = d
	}
	return out
}

// TestReadinessDeps_ValkeyRequiredPeersOptional: with REDIS_URL set, the
// ticket store is required (down until Redis attaches, as "unavailable");
// the vault and audit are optional, so their outage only degrades.
func TestReadinessDeps_ValkeyRequiredPeersOptional(t *testing.T) {
	store := session.NewRequiredComposite(session.NewStore())
	defer store.Close()
	down := peer{healthpb.HealthCheckResponse_NOT_SERVING}
	r := checker(t, readinessDeps(store, true, down, down, nil)).Report(context.Background())
	got := states(r)
	if r.Status != health.StateDown || got["valkey"].State != health.StateDown || !got["valkey"].Required || got["valkey"].Error != "unavailable" {
		t.Fatalf("valkey not attached: %+v", r)
	}
	if got["vault"].State != health.StateDegraded || got["vault"].Required || got["audit"].State != health.StateDegraded || got["audit"].Required {
		t.Fatalf("vault and audit must be optional: %+v", r)
	}
}

// TestReadinessDeps_NoRedisNoValkey: without REDIS_URL the broker is
// single-replica in memory, so there's no valkey dependency at all.
func TestReadinessDeps_NoRedisNoValkey(t *testing.T) {
	store := session.NewComposite(session.NewStore(), nil)
	defer store.Close()
	up := peer{healthpb.HealthCheckResponse_SERVING}
	r := checker(t, readinessDeps(store, false, up, up, nil)).Report(context.Background())
	if _, has := states(r)["valkey"]; has || r.Status != health.StateOK || len(r.Dependencies) != 2 {
		t.Fatalf("%+v", r)
	}
}

// TestReadinessDeps_WorkloadIdentityRequiredWhenAuthenticationIsOn: no caller
// can be checked before the issuer's key set has loaded, so the verifier is
// a required dependency once it exists, and absent when authentication is
// disabled (verifier nil).
func TestReadinessDeps_WorkloadIdentityRequiredWhenAuthenticationIsOn(t *testing.T) {
	store := session.NewComposite(session.NewStore(), nil)
	defer store.Close()
	up := peer{healthpb.HealthCheckResponse_SERVING}
	verifier, err := workloadauth.NewVerifier(workloadauth.Config{
		Issuer: "https://issuer.example.test", Audience: "sneakers",
		AllowedServiceAccounts: []string{"sneakers/sneakers-gateway"},
	}, log.Nop())
	if err != nil {
		t.Fatal(err)
	}
	r := checker(t, readinessDeps(store, false, up, up, verifier)).Report(context.Background())
	got := states(r)
	if _, has := got["workload-identity"]; !has || !got["workload-identity"].Required {
		t.Fatalf("workload-identity must be a required dependency: %+v", r)
	}
}
