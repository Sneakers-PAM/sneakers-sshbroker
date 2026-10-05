// Copyright 2026 The Sneakers-PAM Authors
// SPDX-License-Identifier: Apache-2.0

package server

import (
	"net/http"

	"github.com/Bugs5382/go-buildinfo/health"
	"github.com/Bugs5382/go-buildinfo/httpbuildinfo"
)

// RegisterHTTPHealth serves the broker's HTTP health routes from checker, the
// same readiness the gRPC health check answers, with go-buildinfo's handlers:
//
//   - /livez: 200 {"status":"ok"} while the process answers; never a dependency.
//   - /readyz: 200 when ready (ok or degraded), 503 when a required dependency
//     is down; the body is the readiness report with the build.
//
// Both carry the Sneakers-Version and Sneakers-Commit headers. A nil checker
// is always ready.
func RegisterHTTPHealth(mux *http.ServeMux, checker *health.Checker) error {
	opts := []httpbuildinfo.Option{httpbuildinfo.WithPrefix(HeaderPrefix)}
	if checker != nil {
		opts = append(opts, httpbuildinfo.WithChecker(checker))
	}
	h, err := httpbuildinfo.New(opts...)
	if err != nil {
		return err
	}
	mux.Handle("/livez", h.Livez())
	mux.Handle("/readyz", h.Readyz())
	return nil
}
