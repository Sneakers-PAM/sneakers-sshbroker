// Copyright 2026 The Sneakers-PAM Authors
// SPDX-License-Identifier: Apache-2.0

package grpcsvc

import (
	"context"

	commonv1 "github.com/Sneakers-PAM/sneakers-sshbroker/gen/go/sneakers/common/v1"
	"google.golang.org/grpc"
)

// HealthServer implements the sneakers HealthService.
type HealthServer struct {
	commonv1.UnimplementedHealthServiceServer
}

func NewHealthServer() *HealthServer { return &HealthServer{} }

func (s *HealthServer) Check(_ context.Context, _ *commonv1.CheckRequest) (*commonv1.CheckResponse, error) {
	return &commonv1.CheckResponse{Status: "SERVING"}, nil
}

// Register wires the health service into a gRPC server (used by main.go).
func Register(gs *grpc.Server) {
	commonv1.RegisterHealthServiceServer(gs, NewHealthServer())
}
