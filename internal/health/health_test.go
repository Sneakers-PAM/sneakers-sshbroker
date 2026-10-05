// Copyright 2026 The Sneakers-PAM Authors
// SPDX-License-Identifier: Apache-2.0

package health

import (
	"context"
	"errors"
	"fmt"
	"net"
	"strings"
	"sync"
	"sync/atomic"
	"syscall"
	"testing"
	"time"

	log "github.com/Bugs5382/go-log"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	healthpb "google.golang.org/grpc/health/grpc_health_v1"
	"google.golang.org/grpc/status"
)

type clock struct {
	mu sync.Mutex
	t  time.Time
}

func (c *clock) now() time.Time { c.mu.Lock(); defer c.mu.Unlock(); return c.t }
func (c *clock) add(d time.Duration) {
	c.mu.Lock()
	c.t = c.t.Add(d)
	c.mu.Unlock()
}

type toggle struct {
	err   atomic.Value
	calls atomic.Int32
}

func (f *toggle) set(err error) { f.err.Store(&err) }
func (f *toggle) check(context.Context) error {
	f.calls.Add(1)
	if p, ok := f.err.Load().(*error); ok {
		return *p
	}
	return nil
}

func newChecker(clk *clock, deps ...Dep) *Checker {
	return New(log.Nop(), deps, WithClock(clk.now))
}

func TestReport_RequiredDownThenRecoversAfterTheCacheWindow(t *testing.T) {
	clk := &clock{t: time.Date(2026, 10, 5, 12, 0, 0, 0, time.UTC)}
	pg := &toggle{}
	c := newChecker(clk, Dep{Name: "postgres", Required: true, Check: pg.check})

	if r := c.Report(context.Background()); r.Status != OK || r.Dependencies[0].State != OK {
		t.Fatalf("start: %+v", r)
	}
	pg.set(errors.New("dial tcp db.example.test:5432: connect: connection refused password=hunter2"))
	if r := c.Report(context.Background()); r.Status != OK {
		t.Fatalf("inside the cache window the old result stands: %+v", r)
	}
	clk.add(CacheTTL)
	r := c.Report(context.Background())
	if r.Status != Down || r.Dependencies[0].State != Down || r.Dependencies[0].Error != "error" {
		t.Fatalf("down: %+v", r)
	}
	if !r.Dependencies[0].Required || r.Dependencies[0].CheckedAt != "2026-10-05T12:00:05Z" {
		t.Fatalf("down: %+v", r.Dependencies[0])
	}
	pg.set(nil)
	clk.add(CacheTTL)
	if r := c.Report(context.Background()); r.Status != OK || r.Dependencies[0].Error != "" {
		t.Fatalf("recovered: %+v", r)
	}
}

func TestReport_OptionalFailingIsDegraded(t *testing.T) {
	clk := &clock{t: time.Unix(0, 0)}
	audit := &toggle{}
	audit.set(status.Error(codes.Unavailable, "audit down"))
	c := newChecker(clk,
		Dep{Name: "postgres", Required: true, Check: func(context.Context) error { return nil }},
		Dep{Name: "audit", Check: audit.check})
	r := c.Report(context.Background())
	if r.Status != Degraded || r.Dependencies[1].State != Degraded || r.Dependencies[1].Error != "unavailable" || r.Dependencies[1].Required {
		t.Fatalf("%+v", r)
	}
}

func TestReport_CachesAndSharesOneRun(t *testing.T) {
	clk := &clock{t: time.Unix(0, 0)}
	release := make(chan struct{})
	var calls atomic.Int32
	c := newChecker(clk, Dep{Name: "postgres", Required: true, Check: func(context.Context) error {
		calls.Add(1)
		<-release
		return nil
	}})
	var wg sync.WaitGroup
	for range 8 {
		wg.Add(1)
		go func() { defer wg.Done(); c.Report(context.Background()) }()
	}
	time.Sleep(50 * time.Millisecond)
	close(release)
	wg.Wait()
	c.Report(context.Background())
	if n := calls.Load(); n != 1 {
		t.Fatalf("checks ran %d times, want 1", n)
	}
}

func TestReport_ChecksTimeOut(t *testing.T) {
	c := New(log.Nop(), []Dep{{Name: "kratos", Required: true, Check: func(ctx context.Context) error {
		<-ctx.Done()
		return ctx.Err()
	}}}, WithTimeout(20*time.Millisecond))
	start := time.Now()
	r := c.Report(context.Background())
	if r.Status != Down || r.Dependencies[0].Error != "timeout" || time.Since(start) > time.Second {
		t.Fatalf("%+v after %v", r, time.Since(start))
	}
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
		{&HTTPStatusError{Code: 401}, "unauthenticated"},
		{&HTTPStatusError{Code: 403}, "unauthenticated"},
		{&HTTPStatusError{Code: 503}, "error"},
		{refused, "unavailable"},
		{errors.New("secret text"), "error"},
	}
	for _, tc := range cases {
		if got := Classify(tc.err); got != tc.want {
			t.Errorf("Classify(%v) = %q, want %q", tc.err, got, tc.want)
		}
	}
}

func TestReport_NeverCarriesErrorText(t *testing.T) {
	c := New(log.Nop(), []Dep{{Name: "postgres", Required: true, Check: func(context.Context) error {
		return errors.New("connect to db.example.test:5432 failed: password=hunter2")
	}}})
	r := c.Report(context.Background())
	if s := fmt.Sprintf("%+v", r); strings.Contains(s, "hunter2") || strings.Contains(s, "db.example.test") {
		t.Fatalf("report leaks the error: %s", s)
	}
}

func TestGRPCPeer(t *testing.T) {
	if err := GRPCPeer(fakePeer{status: healthpb.HealthCheckResponse_SERVING})(context.Background()); err != nil {
		t.Fatalf("serving: %v", err)
	}
	if got := Classify(GRPCPeer(fakePeer{status: healthpb.HealthCheckResponse_NOT_SERVING})(context.Background())); got != "unavailable" {
		t.Fatalf("not serving: class %q, want unavailable", got)
	}
	if got := Classify(GRPCPeer(fakePeer{err: status.Error(codes.Unavailable, "x")})(context.Background())); got != "unavailable" {
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
