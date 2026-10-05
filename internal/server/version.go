// Copyright 2026 The Sneakers-PAM Authors
// SPDX-License-Identifier: Apache-2.0

package server

import (
	"context"

	"github.com/Sneakers-PAM/sneakers-sshbroker/internal/buildinfo"
	"google.golang.org/grpc"
	"google.golang.org/grpc/metadata"
)

// The response headers a health check carries, read by the gateway's
// diagnostics.
const (
	HeaderVersion = "sneakers-version"
	HeaderCommit  = "sneakers-commit"
)

const healthCheckMethod = "/grpc.health.v1.Health/Check"

// VersionUnaryInterceptor adds the build's version and commit to the response
// headers of every health check. Other calls are untouched.
func VersionUnaryInterceptor() grpc.UnaryServerInterceptor {
	return func(ctx context.Context, req any, info *grpc.UnaryServerInfo, handler grpc.UnaryHandler) (any, error) {
		if info.FullMethod == healthCheckMethod {
			v, c := buildinfo.Info()
			_ = grpc.SetHeader(ctx, metadata.Pairs(HeaderVersion, v, HeaderCommit, c))
		}
		return handler(ctx, req)
	}
}
