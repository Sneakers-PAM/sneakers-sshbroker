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
	colmetrics "go.opentelemetry.io/proto/otlp/collector/metrics/v1"
	coltrace "go.opentelemetry.io/proto/otlp/collector/trace/v1"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
	"google.golang.org/protobuf/encoding/protojson"
)

// Collector records the export requests it receives, as JSON text.
type Collector struct {
	collogs.UnimplementedLogsServiceServer
	// Endpoint is the URL to export to.
	Endpoint string

	mu         sync.Mutex
	logs       []string
	traces     []string
	metrics    []string
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
	colmetrics.RegisterMetricsServiceServer(gs, metricsServer{c: c})
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

// Traces is every trace export accepted so far.
func (c *Collector) Traces() string {
	c.mu.Lock()
	defer c.mu.Unlock()
	return strings.Join(c.traces, "\n")
}

// Metrics is every metric export received so far.
func (c *Collector) Metrics() string {
	c.mu.Lock()
	defer c.mu.Unlock()
	return strings.Join(c.metrics, "\n")
}

type traceServer struct {
	coltrace.UnimplementedTraceServiceServer
	c *Collector
}

// Export takes traces, or refuses them.
func (s traceServer) Export(_ context.Context, req *coltrace.ExportTraceServiceRequest) (*coltrace.ExportTraceServiceResponse, error) {
	if s.c.failTraces {
		return nil, status.Error(codes.PermissionDenied, "refused")
	}
	b, err := protojson.Marshal(req)
	if err != nil {
		return nil, err
	}
	s.c.mu.Lock()
	defer s.c.mu.Unlock()
	s.c.traces = append(s.c.traces, string(b))
	return &coltrace.ExportTraceServiceResponse{}, nil
}

type metricsServer struct {
	colmetrics.UnimplementedMetricsServiceServer
	c *Collector
}

// Export takes metrics.
func (s metricsServer) Export(_ context.Context, req *colmetrics.ExportMetricsServiceRequest) (*colmetrics.ExportMetricsServiceResponse, error) {
	b, err := protojson.Marshal(req)
	if err != nil {
		return nil, err
	}
	s.c.mu.Lock()
	defer s.c.mu.Unlock()
	s.c.metrics = append(s.c.metrics, string(b))
	return &colmetrics.ExportMetricsServiceResponse{}, nil
}
