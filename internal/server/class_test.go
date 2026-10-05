// Copyright 2026 The Sneakers-PAM Authors
// SPDX-License-Identifier: Apache-2.0

package server

import (
	"context"
	"errors"
	"fmt"
	"net"
	"strings"
	"syscall"
	"testing"

	"github.com/Bugs5382/go-buildinfo/health"
	log "github.com/Bugs5382/go-log"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	healthpb "google.golang.org/grpc/health/grpc_health_v1"
	"google.golang.org/grpc/status"
)

// reportedClass is the error class the readiness report gives check's error.
func reportedClass(t *testing.T, check func(context.Context) error) string {
	t.Helper()
	c, err := NewChecker(log.Nop(), []health.Dependency{{Name: "dep", Check: check}})
	if err != nil {
		t.Fatal(err)
	}
	return c.Report(context.Background()).Dependencies[0].Error
}

func TestClassify(t *testing.T) {
	refused := &net.OpError{Op: "dial", Net: "tcp", Err: &net.DNSError{}}
	cases := []struct {
		err  error
		want string
	}{
		{nil, ""},
		{context.DeadlineExceeded, "timeout"},
		{fmt.Errorf("ping: %w", syscall.ECONNREFUSED), "refused"},
		{status.Error(codes.Unavailable, "x"), "unavailable"},
		{status.Error(codes.DeadlineExceeded, "x"), "timeout"},
		{status.Error(codes.Unauthenticated, "x"), "unauthenticated"},
		{status.Error(codes.PermissionDenied, "x"), "unauthenticated"},
		{status.Error(codes.Internal, "x"), "error"},
		{refused, "unavailable"},
		{errors.New("secret text"), "error"},
	}
	for _, tc := range cases {
		if got := reportedClass(t, func(context.Context) error { return tc.err }); got != tc.want {
			t.Errorf("class of %v = %q, want %q", tc.err, got, tc.want)
		}
	}
}

func TestReport_NeverCarriesErrorText(t *testing.T) {
	c, err := NewChecker(log.Nop(), []health.Dependency{{Name: "postgres", Required: true, Check: func(context.Context) error {
		return errors.New("connect to db.example.test:5432 failed: password=hunter2")
	}}})
	if err != nil {
		t.Fatal(err)
	}
	r := c.Report(context.Background())
	if s := fmt.Sprintf("%+v", r); strings.Contains(s, "hunter2") || strings.Contains(s, "db.example.test") {
		t.Fatalf("report leaks the error: %s", s)
	}
}

func TestGRPCPeer(t *testing.T) {
	if err := GRPCPeer(fakePeer{status: healthpb.HealthCheckResponse_SERVING})(context.Background()); err != nil {
		t.Fatalf("serving: %v", err)
	}
	if got := reportedClass(t, GRPCPeer(fakePeer{status: healthpb.HealthCheckResponse_NOT_SERVING})); got != "unavailable" {
		t.Fatalf("not serving: class %q, want unavailable", got)
	}
	if got := reportedClass(t, GRPCPeer(fakePeer{err: status.Error(codes.Unavailable, "x")})); got != "unavailable" {
		t.Fatalf("unreachable: class %q", got)
	}
}

type fakePeer struct {
	status healthpb.HealthCheckResponse_ServingStatus
	err    error
}

func (f fakePeer) Check(context.Context, *healthpb.HealthCheckRequest, ...grpc.CallOption) (*healthpb.HealthCheckResponse, error) {
	if f.err != nil {
		return nil, f.err
	}
	return &healthpb.HealthCheckResponse{Status: f.status}, nil
}
