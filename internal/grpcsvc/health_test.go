// Copyright 2026 The Sneakers-PAM Authors
// SPDX-License-Identifier: Apache-2.0

package grpcsvc

import (
	"context"
	"testing"

	commonv1 "github.com/Sneakers-PAM/sneakers-sshbroker/gen/go/sneakers/common/v1"
)

func TestHealthCheckReturnsServing(t *testing.T) {
	srv := NewHealthServer()
	resp, err := srv.Check(context.Background(), &commonv1.CheckRequest{})
	if err != nil {
		t.Fatalf("Check returned error: %v", err)
	}
	if resp.GetStatus() != "SERVING" {
		t.Fatalf("got status %q, want SERVING", resp.GetStatus())
	}
}
