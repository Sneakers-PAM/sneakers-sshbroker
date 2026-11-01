// Copyright 2026 The Sneakers-PAM Authors
// SPDX-License-Identifier: Apache-2.0

// Package collectortest is an in-process OTLP collector for tests.
package collectortest

import (
	"context"
	"net"
	"strings"
	"sync"
	"testing"

	collogs "go.opentelemetry.io/proto/otlp/collector/logs/v1"
	coltrace "go.opentelemetry.io/proto/otlp/collector/trace/v1"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
	"google.golang.org/protobuf/encoding/protojson"
)

// Collector records the log export requests it receives, as JSON text.
type Collector struct {
	collogs.UnimplementedLogsServiceServer
	// Endpoint is the URL to export to.
	Endpoint string

	mu         sync.Mutex
	logs       []string
	failTraces bool
}

// Start runs a collector until the test ends. With failTraces it refuses
// every trace export.
func Start(t *testing.T, failTraces bool) *Collector {
	t.Helper()
	lis, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	c := &Collector{Endpoint: "http://" + lis.Addr().String(), failTraces: failTraces}
	gs := grpc.NewServer()
	collogs.RegisterLogsServiceServer(gs, c)
	coltrace.RegisterTraceServiceServer(gs, traceServer{c: c})
	go func() { _ = gs.Serve(lis) }()
	t.Cleanup(gs.Stop)
	return c
}

// Export takes logs.
func (c *Collector) Export(_ context.Context, req *collogs.ExportLogsServiceRequest) (*collogs.ExportLogsServiceResponse, error) {
	b, err := protojson.Marshal(req)
	if err != nil {
		return nil, err
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	c.logs = append(c.logs, string(b))
	return &collogs.ExportLogsServiceResponse{}, nil
}

// Logs is everything received so far.
func (c *Collector) Logs() string {
	c.mu.Lock()
	defer c.mu.Unlock()
	return strings.Join(c.logs, "\n")
}

type traceServer struct {
	coltrace.UnimplementedTraceServiceServer
	c *Collector
}

// Export takes traces, or refuses them.
func (s traceServer) Export(context.Context, *coltrace.ExportTraceServiceRequest) (*coltrace.ExportTraceServiceResponse, error) {
	if s.c.failTraces {
		return nil, status.Error(codes.PermissionDenied, "refused")
	}
	return &coltrace.ExportTraceServiceResponse{}, nil
}
