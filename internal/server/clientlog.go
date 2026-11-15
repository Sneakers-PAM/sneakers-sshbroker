// Copyright 2026 The Sneakers-PAM Authors
// SPDX-License-Identifier: Apache-2.0

package server

import (
	"context"
	"time"

	"github.com/rs/zerolog"
	"google.golang.org/grpc"
	"google.golang.org/grpc/status"
)

// ClientLogging returns the grpc.DialOption that logs every outbound unary
// call on the connection: at debug with the target, method, duration and
// status code, and at warn, with the error, when the call fails. It never
// logs a request or a reply, so key material and secret values stay out of
// the log. Install it beside ClientStatsHandler:
//
//	conn, err := grpc.NewClient(target, server.ClientStatsHandler(), server.ClientLogging(lg))
func ClientLogging(lg zerolog.Logger) grpc.DialOption {
	return grpc.WithChainUnaryInterceptor(func(ctx context.Context, method string, req, reply any, cc *grpc.ClientConn, invoker grpc.UnaryInvoker, opts ...grpc.CallOption) error {
		start := time.Now()
		err := invoker(ctx, method, req, reply, cc, opts...)
		dur := time.Since(start)
		code := status.Code(err).String()
		if err != nil {
			lg.Warn().Err(err).Str("target", cc.Target()).Str("method", method).
				Dur("duration", dur).Str("status", code).Msg("outbound grpc call failed")
			return err
		}
		lg.Debug().Str("target", cc.Target()).Str("method", method).
			Dur("duration", dur).Str("status", code).Msg("outbound grpc call")
		return nil
	})
}
