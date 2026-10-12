// Copyright 2026 The Sneakers-PAM Authors
// SPDX-License-Identifier: Apache-2.0

package audit

import (
	"context"
	"testing"
	"time"

	"google.golang.org/grpc"

	auditv1 "github.com/Sneakers-PAM/sneakers-sshbroker/gen/go/thirdparty/audit/v1"
)

// hangingAudit never answers until the call's context ends.
type hangingAudit struct {
	auditv1.AuditServiceClient
}

func (hangingAudit) RecordEvent(ctx context.Context, _ *auditv1.RecordEventRequest, _ ...grpc.CallOption) (*auditv1.RecordEventResponse, error) {
	<-ctx.Done()
	return nil, ctx.Err()
}

// A session must never wait on the audit service: every emit is bounded,
// even one made with a context that has no deadline.
func TestEmitIsBoundedWhenAuditHangs(t *testing.T) {
	old := emitTimeout
	emitTimeout = 100 * time.Millisecond
	t.Cleanup(func() { emitTimeout = old })

	e := New(hangingAudit{})
	done := make(chan struct{})
	go func() {
		e.End(context.Background(), "user-1", "secret-1", "target-1", time.Second, "closed")
		e.Start(context.Background(), "user-1", "secret-1", "target-1", "192.0.2.10")
		close(done)
	}()
	select {
	case <-done:
	case <-time.After(2 * time.Second):
		t.Fatal("audit emit did not return while the audit service hung")
	}
}
