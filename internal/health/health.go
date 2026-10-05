// Copyright 2026 The Sneakers-PAM Authors
// SPDX-License-Identifier: Apache-2.0

// Package health checks the service's dependencies for readiness. Each check
// runs with a short timeout and its result is cached for a few seconds, so
// probes don't load the dependencies. A required dependency that fails makes
// the service down (not ready); an optional one makes it degraded.
package health

import (
	"context"
	"errors"
	"net"
	"strconv"
	"sync"
	"syscall"
	"time"

	log "github.com/Bugs5382/go-log"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	healthpb "google.golang.org/grpc/health/grpc_health_v1"
	"google.golang.org/grpc/status"
)

// CacheTTL is how long a check's result is reused; CheckTimeout bounds each
// check.
const (
	CacheTTL     = 5 * time.Second
	CheckTimeout = time.Second
)

// State is a dependency's or the service's state.
type State string

const (
	OK       State = "ok"
	Degraded State = "degraded"
	Down     State = "down"
)

// Dep is one dependency. Check must be cheap; it gets a context bounded by the
// check timeout.
type Dep struct {
	Name     string
	Required bool
	Check    func(context.Context) error
}

// DepStatus is a dependency's last result. Error is an error class from
// Classify, never the error's text.
type DepStatus struct {
	Name      string `json:"name"`
	State     State  `json:"state"`
	Required  bool   `json:"required"`
	Error     string `json:"error,omitempty"`
	CheckedAt string `json:"checkedAt"`
	Version   string `json:"version,omitempty"`
}

// Report is the service's state and every dependency's.
type Report struct {
	Status       State       `json:"status"`
	Dependencies []DepStatus `json:"dependencies"`
}

// Ready reports whether the service should take traffic: true unless a
// required dependency is down.
func (r Report) Ready() bool { return r.Status != Down }

// Option configures a Checker.
type Option func(*Checker)

// WithClock replaces time.Now, for tests.
func WithClock(now func() time.Time) Option { return func(c *Checker) { c.now = now } }

// WithTimeout replaces CheckTimeout, for tests.
func WithTimeout(d time.Duration) Option { return func(c *Checker) { c.timeout = d } }

// Checker runs the dependency checks and caches the result.
type Checker struct {
	deps    []Dep
	lg      log.Logger
	now     func() time.Time
	timeout time.Duration

	mu       sync.Mutex
	last     *Report
	at       time.Time
	inflight chan struct{}
	prev     map[string]State
}

// New returns a Checker over deps. lg gets one line per state change.
func New(lg log.Logger, deps []Dep, opts ...Option) *Checker {
	c := &Checker{deps: deps, lg: lg, now: time.Now, timeout: CheckTimeout, prev: map[string]State{}}
	for _, o := range opts {
		o(c)
	}
	return c
}

// Report returns the cached report, or runs the checks when it is older than
// CacheTTL. Concurrent callers share one run.
func (c *Checker) Report(ctx context.Context) Report {
	for {
		c.mu.Lock()
		if c.last != nil && c.now().Sub(c.at) < CacheTTL {
			r := *c.last
			c.mu.Unlock()
			return r
		}
		if wait := c.inflight; wait != nil {
			c.mu.Unlock()
			select {
			case <-wait:
				continue
			case <-ctx.Done():
				return Report{Status: Down, Dependencies: []DepStatus{}}
			}
		}
		done := make(chan struct{})
		c.inflight = done
		c.mu.Unlock()

		r := c.run(context.WithoutCancel(ctx))

		c.mu.Lock()
		c.last, c.at, c.inflight = &r, c.now(), nil
		c.mu.Unlock()
		close(done)
		return r
	}
}

func (c *Checker) run(ctx context.Context) Report {
	checked := c.now().UTC().Format(time.RFC3339)
	out := make([]DepStatus, len(c.deps))
	var wg sync.WaitGroup
	for i, d := range c.deps {
		wg.Add(1)
		go func() {
			defer wg.Done()
			cctx, cancel := context.WithTimeout(ctx, c.timeout)
			defer cancel()
			err := d.Check(cctx)
			if err == nil && cctx.Err() != nil {
				err = cctx.Err()
			}
			st := DepStatus{Name: d.Name, State: OK, Required: d.Required, CheckedAt: checked}
			if err != nil {
				st.Error = Classify(err)
				st.State = Degraded
				if d.Required {
					st.State = Down
				}
			}
			out[i] = st
		}()
	}
	wg.Wait()

	r := Report{Status: OK, Dependencies: out}
	for _, d := range out {
		switch {
		case d.State == Down:
			r.Status = Down
		case d.State == Degraded && r.Status == OK:
			r.Status = Degraded
		}
		c.logChange(d)
	}
	return r
}

func (c *Checker) logChange(d DepStatus) {
	prev, seen := c.prev[d.Name]
	c.prev[d.Name] = d.State
	if (seen && prev == d.State) || (!seen && d.State == OK) || c.lg == nil {
		return
	}
	fields := []log.Field{log.F("dependency", d.Name), log.F("required", d.Required), log.F("state", string(d.State))}
	if d.State == OK {
		c.lg.Info("health: dependency recovered", fields...)
		return
	}
	c.lg.Warn("health: dependency "+string(d.State), append(fields, log.F("error_class", d.Error))...)
}

// HTTPStatusError is a dependency's unexpected HTTP status.
type HTTPStatusError struct{ Code int }

func (e *HTTPStatusError) Error() string { return "unexpected status " + strconv.Itoa(e.Code) }

// Classify maps err to a fixed error class: timeout, refused, unavailable,
// unauthenticated or error; "" for nil. It never returns the error's text.
func Classify(err error) string {
	if err == nil {
		return ""
	}
	var hs *HTTPStatusError
	var gs interface{ GRPCStatus() *status.Status }
	var ne net.Error
	switch {
	case errors.Is(err, context.DeadlineExceeded):
		return "timeout"
	case errors.Is(err, syscall.ECONNREFUSED):
		return "refused"
	case errors.As(err, &hs):
		if hs.Code == 401 || hs.Code == 403 {
			return "unauthenticated"
		}
		return "error"
	case errors.As(err, &gs):
		switch gs.GRPCStatus().Code() {
		case codes.DeadlineExceeded:
			return "timeout"
		case codes.Unavailable:
			return "unavailable"
		case codes.Unauthenticated, codes.PermissionDenied:
			return "unauthenticated"
		}
		return "error"
	case errors.As(err, &ne):
		if ne.Timeout() {
			return "timeout"
		}
		return "unavailable"
	}
	return "error"
}

// HealthChecker is the Check half of a grpc.health.v1 client.
type HealthChecker interface {
	Check(ctx context.Context, in *healthpb.HealthCheckRequest, opts ...grpc.CallOption) (*healthpb.HealthCheckResponse, error)
}

// GRPCPeer checks a gRPC peer through its standard health check (readiness,
// service ""). A peer that answers anything but SERVING is unavailable.
func GRPCPeer(hc HealthChecker) func(context.Context) error {
	return func(ctx context.Context) error {
		resp, err := hc.Check(ctx, &healthpb.HealthCheckRequest{})
		if err != nil {
			return err
		}
		if resp.GetStatus() != healthpb.HealthCheckResponse_SERVING {
			return status.Error(codes.Unavailable, "peer not serving")
		}
		return nil
	}
}
