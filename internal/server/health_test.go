// Copyright 2026 The Sneakers-PAM Authors
// SPDX-License-Identifier: Apache-2.0

package server

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"slices"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/Bugs5382/go-buildinfo/health"
)

func get(t *testing.T, h http.Handler, path string) *httptest.ResponseRecorder {
	t.Helper()
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, path, nil))
	return rec
}

// TestHTTPHealth_FollowsReadiness: /readyz answers 503 while a required
// dependency is down and recovers after the cache window; /livez stays 200
// throughout, and the plain /health route is gone.
func TestHTTPHealth_FollowsReadiness(t *testing.T) {
	var down atomic.Bool
	down.Store(true)
	checker := newTestChecker(t,
		health.Dependency{Name: "valkey", Required: true, Check: func(context.Context) error {
			if down.Load() {
				return errors.New("dial tcp valkey.example.test:6379: auth hunter2-secret")
			}
			return nil
		}},
	)
	refreshed(t, checker)
	mux := http.NewServeMux()
	if err := RegisterHTTPHealth(mux, checker); err != nil {
		t.Fatal(err)
	}

	if rec := get(t, mux, "/health"); rec.Code != http.StatusNotFound {
		t.Fatalf("/health: %d, want 404", rec.Code)
	}
	rec := get(t, mux, "/readyz")
	if rec.Code != http.StatusServiceUnavailable {
		t.Fatalf("/readyz down: %d, want 503", rec.Code)
	}
	if strings.Contains(rec.Body.String(), "hunter2") || strings.Contains(rec.Body.String(), "valkey.example.test") {
		t.Fatalf("/readyz leaks the error: %s", rec.Body.String())
	}
	var r health.Report
	if err := json.Unmarshal(rec.Body.Bytes(), &r); err != nil || r.Status != health.StateDown || r.Dependencies[0].Error != "error" {
		t.Fatalf("/readyz body %q: %+v %v", rec.Body.String(), r, err)
	}
	if rec := get(t, mux, "/livez"); rec.Code != http.StatusOK || strings.TrimSpace(rec.Body.String()) != `{"status":"ok"}` {
		t.Fatalf("/livez while down: %d %q, want 200", rec.Code, rec.Body.String())
	}

	down.Store(false)
	time.Sleep(2 * testTTL)
	if rec := get(t, mux, "/readyz"); rec.Code != http.StatusOK {
		t.Fatalf("/readyz recovered: %d", rec.Code)
	}
}

func TestHTTPHealth_OptionalDependencyStaysReady(t *testing.T) {
	checker := newTestChecker(t,
		health.Dependency{Name: "vault", Check: func(context.Context) error { return errors.New("down") }},
	)
	mux := http.NewServeMux()
	if err := RegisterHTTPHealth(mux, checker); err != nil {
		t.Fatal(err)
	}
	rec := get(t, mux, "/readyz")
	var r health.Report
	_ = json.Unmarshal(rec.Body.Bytes(), &r)
	if rec.Code != http.StatusOK || r.Status != health.StateDegraded {
		t.Fatalf("/readyz: %d %+v, want 200 degraded", rec.Code, r)
	}
}

// TestHTTPHealth_HeaderNames pins the exact header names /readyz and /livez
// carry.
func TestHTTPHealth_HeaderNames(t *testing.T) {
	stampBuild(t)
	mux := http.NewServeMux()
	if err := RegisterHTTPHealth(mux, newTestChecker(t,
		health.Dependency{Name: "valkey", Required: true, Check: func(context.Context) error { return nil }},
	)); err != nil {
		t.Fatal(err)
	}
	sneakersKeys := func(h http.Header) []string {
		var keys []string
		for k := range h {
			if strings.HasPrefix(k, "Sneakers-") {
				keys = append(keys, k)
			}
		}
		slices.Sort(keys)
		return keys
	}
	rec := get(t, mux, "/readyz")
	if got, want := sneakersKeys(rec.Header()), []string{"Sneakers-Commit", "Sneakers-Depstate-Valkey", "Sneakers-Version"}; !slices.Equal(got, want) {
		t.Fatalf("/readyz headers = %v, want %v", got, want)
	}
	if v := rec.Header().Get("Sneakers-Version"); v != "v9.9.9-test" {
		t.Fatalf("Sneakers-Version = %q", v)
	}
	if got, want := sneakersKeys(get(t, mux, "/livez").Header()), []string{"Sneakers-Commit", "Sneakers-Version"}; !slices.Equal(got, want) {
		t.Fatalf("/livez headers = %v, want %v", got, want)
	}
}
