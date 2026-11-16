// Copyright 2026 The Sneakers-PAM Authors
// SPDX-License-Identifier: Apache-2.0

package server

import (
	"context"
	"errors"
	"fmt"
	"net"
	"os"
	"time"

	"github.com/Bugs5382/go-buildinfo/health"
	mtls "github.com/Bugs5382/go-mtls"
	"google.golang.org/grpc"
	healthpb "google.golang.org/grpc/health/grpc_health_v1"
)

// MTLSFromEnv builds the mutual-TLS provider from MTLS_CERT_FILE,
// MTLS_KEY_FILE and MTLS_CA_FILE. With none of the three set it returns a nil
// provider and no error: the service runs in plaintext, as before. With only
// some set, or with files that cannot be read, it returns an error so a
// half-configured service never starts in the wrong mode. onError receives
// reload failures (the provider keeps the last good files) and may be nil.
func MTLSFromEnv(onError func(error)) (*mtls.Provider, error) {
	if os.Getenv(mtls.EnvCertFile) == "" && os.Getenv(mtls.EnvKeyFile) == "" && os.Getenv(mtls.EnvCAFile) == "" {
		return nil, nil
	}
	files, err := mtls.FilesFromEnv()
	if err != nil {
		return nil, err
	}
	var opts []mtls.Option
	if onError != nil {
		opts = append(opts, mtls.WithErrorHandler(onError))
	}
	p, err := mtls.NewProvider(files, opts...)
	if err != nil {
		return nil, fmt.Errorf("mtls: %w", err)
	}
	return p, nil
}

// RunPlainHealth serves only the gRPC health services (readiness "" and
// "liveness") in plaintext on :port until ctx is cancelled. The kubelet's gRPC
// probe cannot present a client certificate, so with mutual TLS on the main
// port this port is the one probes use. It registers no other service and no
// reflection, so nothing but health answers on it.
func RunPlainHealth(ctx context.Context, port string, checker *health.Checker) error {
	hs, bi, err := newHealth(checker)
	if err != nil {
		return fmt.Errorf("health: %w", err)
	}
	lis, err := net.Listen("tcp", ":"+port)
	if err != nil {
		return fmt.Errorf("listen: %w", err)
	}
	s := grpc.NewServer(
		grpc.ChainUnaryInterceptor(RecoveryUnaryInterceptor(), bi.UnaryServerInterceptor(), reportUnaryInterceptor(checker)),
		grpc.ChainStreamInterceptor(RecoveryStreamInterceptor(), bi.StreamServerInterceptor()),
	)
	healthpb.RegisterHealthServer(s, hs)

	biCtx, stopBI := context.WithCancel(ctx)
	defer stopBI()
	go bi.Run(biCtx)

	errCh := make(chan error, 1)
	go func() { errCh <- s.Serve(lis) }()

	select {
	case <-ctx.Done():
		hs.Shutdown()
		stopped := make(chan struct{})
		go func() {
			s.GracefulStop()
			close(stopped)
		}()
		select {
		case <-stopped:
		case <-time.After(gracefulStopTimeout):
			s.Stop()
		}
		if err := <-errCh; err != nil && !errors.Is(err, grpc.ErrServerStopped) {
			return err
		}
		return nil
	case err := <-errCh:
		if errors.Is(err, grpc.ErrServerStopped) {
			return nil
		}
		return err
	}
}
