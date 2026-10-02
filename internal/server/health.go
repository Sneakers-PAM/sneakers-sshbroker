// Copyright 2026 The Sneakers-PAM Authors
// SPDX-License-Identifier: Apache-2.0

package server

import "net/http"

// HealthHandler serves /health: 200 "ok" when ready reports true, 503
// otherwise.
func HealthHandler(ready func() bool) http.HandlerFunc {
	return func(w http.ResponseWriter, _ *http.Request) {
		if !ready() {
			http.Error(w, "not ready", http.StatusServiceUnavailable)
			return
		}
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte("ok"))
	}
}
