// Copyright 2026 The Sneakers-PAM Authors
// SPDX-License-Identifier: Apache-2.0

package server

import (
	"context"
	"errors"
	"testing"

	workloadauth "github.com/Bugs5382/go-workload-identity"
)

// fakeReadinessVerifier is a fake behind the ReadinessVerifier interface, not
// a mock of go-workload-identity's own Verifier.
type fakeReadinessVerifier struct{ err error }

func (f *fakeReadinessVerifier) Ready() error { return f.err }

func TestWorkloadIdentity_NotReadyUntilKeySetLoads(t *testing.T) {
	dep := WorkloadIdentity(&fakeReadinessVerifier{err: workloadauth.ErrUnavailable})
	if dep.Name != "workload-identity" || !dep.Required {
		t.Fatalf("dep = %+v, want a required dependency named workload-identity", dep)
	}
	if err := dep.Check(context.Background()); !errors.Is(err, workloadauth.ErrUnavailable) {
		t.Fatalf("check = %v, want ErrUnavailable", err)
	}
}

func TestWorkloadIdentity_ReadyOnceKeySetLoads(t *testing.T) {
	dep := WorkloadIdentity(&fakeReadinessVerifier{})
	if err := dep.Check(context.Background()); err != nil {
		t.Fatalf("check = %v, want nil", err)
	}
}
