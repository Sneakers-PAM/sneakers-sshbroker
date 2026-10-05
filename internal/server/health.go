// Copyright 2026 The Sneakers-PAM Authors
// SPDX-License-Identifier: Apache-2.0

package server

import (
	"encoding/json"
	"net/http"

	"github.com/Sneakers-PAM/sneakers-sshbroker/internal/health"
)

// RegisterHTTPHealth serves the broker's HTTP health routes from checker, the
// same readiness the gRPC health check answers:
//
//   - /livez: 200 {"status":"ok"} while the process answers; never a dependency.
//   - /readyz: 200 when ready (ok or degraded), 503 when a required dependency
//     is down; the body is the health.Report.
//   - /health: 200 "ok" when ready, 503 otherwise (the older plain form).
func RegisterHTTPHealth(mux *http.ServeMux, checker *health.Checker) {
	mux.HandleFunc("/livez", func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"status":"ok"}`))
	})
	mux.HandleFunc("/readyz", func(w http.ResponseWriter, r *http.Request) {
		rep := report(r.Context(), checker)
		w.Header().Set("Content-Type", "application/json")
		if !rep.Ready() {
			w.WriteHeader(http.StatusServiceUnavailable)
		}
		_ = json.NewEncoder(w).Encode(rep)
	})
	mux.HandleFunc("/health", func(w http.ResponseWriter, r *http.Request) {
		if !report(r.Context(), checker).Ready() {
			http.Error(w, "not ready", http.StatusServiceUnavailable)
			return
		}
		_, _ = w.Write([]byte("ok"))
	})
}
