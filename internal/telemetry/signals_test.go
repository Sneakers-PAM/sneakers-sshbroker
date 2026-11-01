// Copyright 2026 The Sneakers-PAM Authors
// SPDX-License-Identifier: Apache-2.0

package telemetry_test

import (
	"context"
	"encoding/binary"
	"net"
	"strconv"
	"strings"
	"testing"
	"time"

	otel "github.com/Bugs5382/go-otel"
	sdkotel "go.opentelemetry.io/otel"
	"go.opentelemetry.io/otel/attribute"
	"go.opentelemetry.io/otel/baggage"
	"go.opentelemetry.io/otel/metric"
	"go.opentelemetry.io/otel/trace"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/credentials/insecure"
	"google.golang.org/grpc/metadata"
	"google.golang.org/grpc/status"

	sshbrokerv1 "github.com/Sneakers-PAM/sneakers-sshbroker/gen/go/sneakers/sshbroker/v1"
	"github.com/Sneakers-PAM/sneakers-sshbroker/internal/audit"
	"github.com/Sneakers-PAM/sneakers-sshbroker/internal/grpcsvc"
	"github.com/Sneakers-PAM/sneakers-sshbroker/internal/server"
	"github.com/Sneakers-PAM/sneakers-sshbroker/internal/session"
	"github.com/Sneakers-PAM/sneakers-sshbroker/internal/telemetry"
	"github.com/Sneakers-PAM/sneakers-sshbroker/internal/telemetry/collectortest"
)

const (
	targetCanary = "CANARY-target-5d1e"
	hostEcho     = "echo-target-text"
	hostPanic    = "panic-target-text"
)

// noisyBroker is the real broker, except that two hosts stand in for a handler
// that gets target text wrong: it can put it in a status, or panic with it, and
// attach it to the span and a metric. The filter has to hold when that happens.
type noisyBroker struct {
	sshbrokerv1.UnimplementedSSHBrokerServiceServer
	real      *grpcsvc.Broker
	counter   metric.Int64Counter
	baggageIn chan int
}

func (b *noisyBroker) ScanHostKey(ctx context.Context, req *sshbrokerv1.ScanHostKeyRequest) (*sshbrokerv1.ScanHostKeyResponse, error) {
	b.baggageIn <- baggage.FromContext(ctx).Len()
	switch req.GetHost() {
	case hostEcho:
		trace.SpanFromContext(ctx).SetAttributes(attribute.String("url.path", targetCanary))
		b.counter.Add(ctx, 1, metric.WithAttributes(attribute.String("host", targetCanary)))
		return nil, status.Error(codes.Unavailable, "target said "+targetCanary)
	case hostPanic:
		panic("target said " + targetCanary)
	}
	return b.real.ScanHostKey(ctx, req)
}

// startRudeTarget answers the SSH version exchange, then disconnects with the
// canary as its own text.
func startRudeTarget(t *testing.T) int32 {
	t.Helper()
	lis, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = lis.Close() })
	go func() {
		for {
			c, err := lis.Accept()
			if err != nil {
				return
			}
			go func() {
				defer func() { _ = c.Close() }()
				_, _ = c.Write([]byte("SSH-2.0-rude\r\n"))
				buf := make([]byte, 4096)
				_, _ = c.Read(buf)
				_, _ = c.Write(disconnectPacket(targetCanary))
				_, _ = c.Read(buf)
			}()
		}
	}()
	return int32(lis.Addr().(*net.TCPAddr).Port) // #nosec G115 -- a TCP port
}

func disconnectPacket(text string) []byte {
	payload := []byte{1, 0, 0, 0, 2}
	payload = binary.BigEndian.AppendUint32(payload, uint32(len(text))) // #nosec G115 -- a short constant
	payload = append(payload, text...)
	payload = binary.BigEndian.AppendUint32(payload, 0)
	padding := 8 - (5+len(payload))%8
	if padding < 4 {
		padding += 8
	}
	out := binary.BigEndian.AppendUint32(nil, uint32(1+len(payload)+padding)) // #nosec G115 -- a short constant
	out = append(out, byte(padding))                                          // #nosec G115 -- under 16
	out = append(out, payload...)
	return append(out, make([]byte, padding)...)
}

func freePort(t *testing.T) string {
	t.Helper()
	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = l.Close() }()
	return strconv.Itoa(l.Addr().(*net.TCPAddr).Port)
}

// TestCanaryStaysOutOfEverySignal sends real calls through the service's own
// gRPC server and checks what reached the collector.
func TestCanaryStaysOutOfEverySignal(t *testing.T) {
	t.Setenv("OTEL_RESOURCE_ATTRIBUTES", "deployment.note="+targetCanary)
	c := collectortest.Start(t, false)
	shutdown, err := otel.InitWithOptions(context.Background(), "sshbroker", c.Endpoint, telemetry.Options(logsOn)...)
	if err != nil {
		t.Fatal(err)
	}
	counter, err := sdkotel.Meter("t").Int64Counter("t.calls")
	if err != nil {
		t.Fatal(err)
	}
	store := session.NewStore()
	t.Cleanup(store.Close)
	broker := &noisyBroker{real: grpcsvc.NewBroker(store, audit.New(nil), "ws://localhost:9097/ssh/session"), counter: counter, baggageIn: make(chan int, 8)}

	ctx, cancel := context.WithCancel(context.Background())
	port := freePort(t)
	done := make(chan error, 1)
	go func() {
		done <- server.Run(ctx, port, func(s *grpc.Server) {
			sshbrokerv1.RegisterSSHBrokerServiceServer(s, broker)
		})
	}()
	conn, err := grpc.NewClient("127.0.0.1:"+port, grpc.WithTransportCredentials(insecure.NewCredentials()))
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = conn.Close() }()
	client := sshbrokerv1.NewSSHBrokerServiceClient(conn)

	callCtx, callCancel := context.WithTimeout(metadata.AppendToOutgoingContext(ctx, "baggage", "note="+targetCanary), 10*time.Second)
	defer callCancel()
	req := func(host string, port int32) *sshbrokerv1.ScanHostKeyRequest {
		return &sshbrokerv1.ScanHostKeyRequest{
			Host: host, Port: port, TargetId: "target-1", ActorUserId: "actor-1",
			Actor: &sshbrokerv1.ActorContext{UserId: "actor-1", PrincipalKind: sshbrokerv1.PrincipalKind_PRINCIPAL_KIND_HUMAN},
		}
	}
	for _, r := range []*sshbrokerv1.ScanHostKeyRequest{
		req("127.0.0.1", startRudeTarget(t)), req(hostEcho, 22), req(hostPanic, 22),
	} {
		_, err := client.ScanHostKey(callCtx, r, grpc.WaitForReady(true))
		if err == nil {
			t.Fatalf("scan of %s worked, want a failure", r.GetHost())
		}
		if got := <-broker.baggageIn; got != 0 {
			t.Fatalf("a caller's baggage came in, %d members", got)
		}
	}
	// A method name is the caller's text. It must not name a span or a label.
	_ = conn.Invoke(callCtx, "/"+strings.ReplaceAll(targetCanary, "-", ".")+"/Scan", &sshbrokerv1.ScanHostKeyRequest{}, &sshbrokerv1.ScanHostKeyResponse{})

	cancel()
	if err := <-done; err != nil {
		t.Fatal(err)
	}
	if err := shutdown(context.Background()); err != nil {
		t.Fatal(err)
	}

	// The package loggers read the logs switch at start, so log export is proven
	// in internal/wsproxy, where a test builds its own.
	traces, metrics := c.Traces(), c.Metrics()
	for want, got := range map[string]string{
		"sneakers.sshbroker.v1.SSHBrokerService/ScanHostKey": traces,
		"rpc.response.status_code":                           traces,
		"t.calls":                                            metrics,
		"rpc.method":                                         metrics,
	} {
		if !strings.Contains(got, want) {
			t.Fatalf("%q wasn't exported: %s", want, got)
		}
	}
	canaryDotted := strings.ReplaceAll(targetCanary, "-", ".")
	for name, got := range map[string]string{"traces": traces, "metrics": metrics, "logs": c.Logs()} {
		for _, leak := range []string{targetCanary, canaryDotted, "exception", "url.path", "deployment.note"} {
			if strings.Contains(got, leak) {
				t.Fatalf("%q reached the collector in %s: %s", leak, name, got)
			}
		}
	}
}
