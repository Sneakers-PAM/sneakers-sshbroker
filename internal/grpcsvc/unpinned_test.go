// Copyright 2026 The Sneakers-PAM Authors
// SPDX-License-Identifier: Apache-2.0

package grpcsvc

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"strings"
	"testing"

	"golang.org/x/crypto/ssh"
	"google.golang.org/genproto/googleapis/rpc/errdetails"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	"github.com/Sneakers-PAM/sneakers-sshbroker/internal/audit"
	"github.com/Sneakers-PAM/sneakers-sshbroker/internal/session"
)

// countingStore counts the tickets a broker asks its store for.
type countingStore struct {
	session.TicketStore
	created int
}

func (c *countingStore) Create(p session.Params) (string, string, int, error) {
	c.created++
	return c.TicketStore.Create(p)
}

// TestCreateSessionRefusesUnpinnedTarget: a target with no pinned host key
// is refused up front, with FailedPrecondition and the reason
// HOST_KEY_NOT_PINNED, before any ticket is made, on both the reference and
// the inline form. The refusal is audited.
func TestCreateSessionRefusesUnpinnedTarget(t *testing.T) {
	for _, inline := range []bool{false, true} {
		name := "reference"
		if inline {
			name = "inline"
		}
		t.Run(name, func(t *testing.T) {
			mem := session.NewStore()
			defer mem.Close()
			store := &countingStore{TicketStore: mem}
			rec := &recordingAudit{}
			b := NewBroker(store, audit.New(rec), "wss://sneakers.example.org/ssh/session")
			req := referenceReq()
			req.HostKeys = nil
			if inline {
				req.PrivateKey = "PEM"
			}
			_, err := b.CreateSession(context.Background(), req)
			st, _ := status.FromError(err)
			if st.Code() != codes.FailedPrecondition {
				t.Fatalf("code = %v, want FailedPrecondition (err %v)", st.Code(), err)
			}
			if st.Message() != HostKeyNotPinnedMessage {
				t.Fatalf("message = %q, want %q", st.Message(), HostKeyNotPinnedMessage)
			}
			var info *errdetails.ErrorInfo
			for _, d := range st.Details() {
				if i, ok := d.(*errdetails.ErrorInfo); ok {
					info = i
				}
			}
			if info == nil || info.GetReason() != ReasonHostKeyNotPinned || info.GetDomain() != ErrorDomain {
				t.Fatalf("error info = %v, want reason %s in domain %s", info, ReasonHostKeyNotPinned, ErrorDomain)
			}
			if info.GetMetadata()["target_id"] != "target-1" {
				t.Fatalf("error info metadata = %v, want the target id", info.GetMetadata())
			}
			if store.created != 0 {
				t.Fatalf("tickets made = %d, want 0", store.created)
			}
			if len(rec.events) != 1 || rec.events[0].GetAction() != "session.refuse" ||
				rec.events[0].GetAttributes()["reason"] != "host key not pinned" {
				t.Fatalf("audit events = %v, want one session.refuse for the missing pin", rec.events)
			}
		})
	}
}

// TestCreateSessionChecksInputsBeforePins: a request that is malformed
// anyway is still InvalidArgument, not a pin refusal.
func TestCreateSessionChecksInputsBeforePins(t *testing.T) {
	store := session.NewStore()
	defer store.Close()
	b := NewBroker(store, nilAudit(), "ws://localhost:9097/ssh/session")
	req := referenceReq()
	req.Host = ""
	if _, err := b.CreateSession(context.Background(), req); status.Code(err) != codes.InvalidArgument {
		t.Fatalf("code = %v, want InvalidArgument", status.Code(err))
	}
}

// pinnedHostKey is a host key line for requests that need a pinned target,
// made fresh for each test run.
var pinnedHostKey = func() string {
	pub, _, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		panic(err)
	}
	sp, err := ssh.NewPublicKey(pub)
	if err != nil {
		panic(err)
	}
	return strings.TrimSpace(string(ssh.MarshalAuthorizedKey(sp)))
}()
