// Copyright 2026 The Sneakers-PAM Authors
// SPDX-License-Identifier: Apache-2.0

package server

import (
	"context"
	"encoding/json"

	"github.com/Sneakers-PAM/sneakers-sshbroker/internal/health"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	healthpb "google.golang.org/grpc/health/grpc_health_v1"
	"google.golang.org/grpc/metadata"
	"google.golang.org/grpc/status"
)

// HeaderHealth carries the readiness report (health.Report as JSON) on a
// readiness check's response.
const HeaderHealth = "sneakers-health"

// LivenessService is the health service name the liveness probe asks for. It
// answers SERVING while the process does, whatever its dependencies.
const LivenessService = "liveness"

// healthServer answers grpc.health.v1: service "" is readiness, which follows
// the checker; LivenessService is the process only; anything else is
// NotFound. Watch is unimplemented.
type healthServer struct {
	healthpb.UnimplementedHealthServer
	checker *health.Checker
}

// report is the checker's report, or ok with no dependencies when there is no
// checker.
func report(ctx context.Context, checker *health.Checker) health.Report {
	if checker == nil {
		return health.Report{Status: health.OK, Dependencies: []health.DepStatus{}}
	}
	return checker.Report(ctx)
}

func (h *healthServer) Check(ctx context.Context, req *healthpb.HealthCheckRequest) (*healthpb.HealthCheckResponse, error) {
	switch req.GetService() {
	case LivenessService:
		return &healthpb.HealthCheckResponse{Status: healthpb.HealthCheckResponse_SERVING}, nil
	case "":
	default:
		return nil, status.Error(codes.NotFound, "unknown service")
	}
	r := report(ctx, h.checker)
	if b, err := json.Marshal(r); err == nil {
		_ = grpc.SetHeader(ctx, metadata.Pairs(HeaderHealth, string(b)))
	}
	if !r.Ready() {
		return &healthpb.HealthCheckResponse{Status: healthpb.HealthCheckResponse_NOT_SERVING}, nil
	}
	return &healthpb.HealthCheckResponse{Status: healthpb.HealthCheckResponse_SERVING}, nil
}
