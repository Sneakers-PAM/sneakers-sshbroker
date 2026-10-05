// Copyright 2026 The Sneakers-PAM Authors
// SPDX-License-Identifier: Apache-2.0

package server

import (
	"context"
	"errors"
	"testing"
	"time"

	log "github.com/Bugs5382/go-log"
	"github.com/Sneakers-PAM/sneakers-sshbroker/internal/buildinfo"
	"github.com/Sneakers-PAM/sneakers-sshbroker/internal/health"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials/insecure"
	healthpb "google.golang.org/grpc/health/grpc_health_v1"
	"google.golang.org/grpc/metadata"
)

// TestRun_HealthCheckReportsBuild checks the health answer carries the build's
// version and commit in its response headers, for the gateway's diagnostics.
func TestRun_HealthCheckReportsBuild(t *testing.T) {
	oldV, oldC := buildinfo.Version, buildinfo.Commit
	buildinfo.Version, buildinfo.Commit = "v9.9.9-test", "0123456789abcdef"
	t.Cleanup(func() { buildinfo.Version, buildinfo.Commit = oldV, oldC })

	port := freePort(t)
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() { done <- Run(ctx, port, nil) }()
	t.Cleanup(func() { cancel(); <-done })
	checkBuildHeaders(t, port)
}

// TestRunWithHealth_NotServingStillReportsBuild covers the readiness main
// uses: while the ticket store is down it answers NOT_SERVING, and the answer
// still carries the build.
func TestRunWithHealth_NotServingStillReportsBuild(t *testing.T) {
	oldV, oldC := buildinfo.Version, buildinfo.Commit
	buildinfo.Version, buildinfo.Commit = "v9.9.9-test", "0123456789abcdef"
	t.Cleanup(func() { buildinfo.Version, buildinfo.Commit = oldV, oldC })

	checker := health.New(log.Nop(), []health.Dep{
		{Name: "valkey", Required: true, Check: func(context.Context) error { return errors.New("down") }},
	})
	port := freePort(t)
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() { done <- RunWithHealth(ctx, port, checker, nil) }()
	t.Cleanup(func() { cancel(); <-done })
	if st := checkBuildHeaders(t, port); st != healthpb.HealthCheckResponse_NOT_SERVING {
		t.Fatalf("status = %v, want NOT_SERVING", st)
	}
}

func checkBuildHeaders(t *testing.T, port string) healthpb.HealthCheckResponse_ServingStatus {
	t.Helper()

	conn, err := grpc.NewClient("127.0.0.1:"+port, grpc.WithTransportCredentials(insecure.NewCredentials()))
	if err != nil {
		t.Fatalf("dial: %v", err)
	}
	t.Cleanup(func() { _ = conn.Close() })

	var md metadata.MD
	var st healthpb.HealthCheckResponse_ServingStatus
	deadline := time.Now().Add(5 * time.Second)
	for {
		cctx, ccancel := context.WithTimeout(context.Background(), time.Second)
		var resp *healthpb.HealthCheckResponse
		resp, err = healthpb.NewHealthClient(conn).Check(cctx, &healthpb.HealthCheckRequest{}, grpc.Header(&md), grpc.WaitForReady(true))
		ccancel()
		st = resp.GetStatus()
		if err == nil || time.Now().After(deadline) {
			break
		}
	}
	if err != nil {
		t.Fatalf("health check: %v", err)
	}
	if got := md.Get(HeaderVersion); len(got) != 1 || got[0] != "v9.9.9-test" {
		t.Errorf("%s = %v, want v9.9.9-test", HeaderVersion, got)
	}
	if got := md.Get(HeaderCommit); len(got) != 1 || got[0] != "0123456789abcdef" {
		t.Errorf("%s = %v, want 0123456789abcdef", HeaderCommit, got)
	}
	return st
}
