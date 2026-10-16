// Copyright 2026 The Sneakers-PAM Authors
// SPDX-License-Identifier: Apache-2.0

package grpcsvc

import (
	"context"
	"testing"

	"google.golang.org/genproto/googleapis/rpc/errdetails"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	"github.com/Sneakers-PAM/sneakers-sshbroker/internal/audit"
	"github.com/Sneakers-PAM/sneakers-sshbroker/internal/session"
)

// TestCreateSessionRefusesUnattachedTarget: #168's "one secret, several
// targets" needs the broker to check the chosen target is actually one of
// the secret's attached targets, independently of whatever the gateway
// resolved. A target missing from secret_target_ids is refused with
// FailedPrecondition and TARGET_NOT_ATTACHED, before any ticket is made and
// before the (separate) host-key pin check runs.
func TestCreateSessionRefusesUnattachedTarget(t *testing.T) {
	mem := session.NewStore()
	defer mem.Close()
	store := &countingStore{TicketStore: mem}
	rec := &recordingAudit{}
	b := NewBroker(store, audit.New(rec), "wss://sneakers.example.org/ssh/session")
	req := referenceReq()
	req.SecretTargetIds = []string{"target-other", "target-also-not-it"}

	_, err := b.CreateSession(context.Background(), req)
	st, _ := status.FromError(err)
	if st.Code() != codes.FailedPrecondition {
		t.Fatalf("code = %v, want FailedPrecondition (err %v)", st.Code(), err)
	}
	if st.Message() != TargetNotAttachedMessage {
		t.Fatalf("message = %q, want %q", st.Message(), TargetNotAttachedMessage)
	}
	var info *errdetails.ErrorInfo
	for _, d := range st.Details() {
		if i, ok := d.(*errdetails.ErrorInfo); ok {
			info = i
		}
	}
	if info == nil || info.GetReason() != ReasonTargetNotAttached || info.GetDomain() != ErrorDomain {
		t.Fatalf("error info = %v, want reason %s in domain %s", info, ReasonTargetNotAttached, ErrorDomain)
	}
	if info.GetMetadata()["target_id"] != "target-1" {
		t.Fatalf("error info metadata = %v, want the target id", info.GetMetadata())
	}
	if store.created != 0 {
		t.Fatalf("tickets made = %d, want 0", store.created)
	}
	if len(rec.events) != 1 || rec.events[0].GetAction() != "session.refuse" ||
		rec.events[0].GetAttributes()["reason"] != "target not attached to secret" {
		t.Fatalf("audit events = %v, want one session.refuse for the unattached target", rec.events)
	}
}

// TestCreateSessionRefusesUnattachedBeforeUnpinned proves the attachment
// check runs ahead of the host-key pin check: a target that is both
// unattached AND unpinned is refused as unattached, never (wrongly) blamed
// on a missing pin.
func TestCreateSessionRefusesUnattachedBeforeUnpinned(t *testing.T) {
	store := session.NewStore()
	defer store.Close()
	b := NewBroker(store, nilAudit(), "ws://localhost:9097/ssh/session")
	req := referenceReq()
	req.SecretTargetIds = []string{"target-other"}
	req.HostKeys = nil

	_, err := b.CreateSession(context.Background(), req)
	if status.Code(err) != codes.FailedPrecondition {
		t.Fatalf("code = %v, want FailedPrecondition", status.Code(err))
	}
	st, _ := status.FromError(err)
	if st.Message() != TargetNotAttachedMessage {
		t.Fatalf("message = %q, want the unattached message, not the unpinned one", st.Message())
	}
}

// TestCreateSessionAllowsEachOfSeveralAttachedTargets is #168's "picking
// each": a secret attached to several targets mints a ticket carrying
// whichever one the caller picked, as long as it's in the list, with no
// cross-talk between the two.
func TestCreateSessionAllowsEachOfSeveralAttachedTargets(t *testing.T) {
	keyA, keyB := genHostKeyLine(t), genHostKeyLine(t)
	for _, tc := range []struct {
		targetID string
		hostKey  string
	}{
		{"target-a", keyA},
		{"target-b", keyB},
	} {
		t.Run(tc.targetID, func(t *testing.T) {
			store := session.NewStore()
			defer store.Close()
			b := NewBroker(store, nilAudit(), "ws://localhost:9097/ssh/session")
			req := referenceReq()
			req.TargetId = tc.targetID
			req.SecretTargetIds = []string{"target-a", "target-b"}
			req.HostKeys = []string{tc.hostKey}

			resp, err := b.CreateSession(context.Background(), req)
			if err != nil {
				t.Fatalf("CreateSession(%s): %v", tc.targetID, err)
			}
			sess, ok := store.Consume(resp.GetTicket())
			if !ok || sess.TargetID != tc.targetID {
				t.Fatalf("ticket target = %+v, want %q", sess, tc.targetID)
			}
		})
	}
}

// TestCreateSessionInlinePathSkipsAttachmentCheck: the inline (back-compat)
// path has no secret to check attachment against, so it is never refused as
// unattached, even with secret_target_ids set to something that doesn't
// include target_id.
func TestCreateSessionInlinePathSkipsAttachmentCheck(t *testing.T) {
	store := session.NewStore()
	defer store.Close()
	b := NewBroker(store, nilAudit(), "ws://localhost:9097/ssh/session")
	req := referenceReq()
	req.PrivateKey = "PEM"
	req.SecretTargetIds = []string{"target-other"}

	if _, err := b.CreateSession(context.Background(), req); err != nil {
		t.Fatalf("inline path refused on attachment: %v", err)
	}
}
