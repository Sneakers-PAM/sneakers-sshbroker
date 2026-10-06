// Copyright 2026 The Sneakers-PAM Authors
// SPDX-License-Identifier: Apache-2.0

package grpcsvc

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"errors"
	"net"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"golang.org/x/crypto/ssh"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	sshbrokerv1 "github.com/Sneakers-PAM/sneakers-sshbroker/gen/go/sneakers/sshbroker/v1"
	"github.com/Sneakers-PAM/sneakers-sshbroker/internal/audit"
	"github.com/Sneakers-PAM/sneakers-sshbroker/internal/session"
)

// startScanTarget runs an SSH server with one generated host key that counts
// every authentication attempt, including "none".
func startScanTarget(t *testing.T) (port int32, hostKey ssh.PublicKey, authAttempts *atomic.Int32) {
	t.Helper()
	_, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	signer, err := ssh.NewSignerFromKey(priv)
	if err != nil {
		t.Fatal(err)
	}
	authAttempts = &atomic.Int32{}
	cfg := &ssh.ServerConfig{
		AuthLogCallback: func(ssh.ConnMetadata, string, error) { authAttempts.Add(1) },
		PasswordCallback: func(ssh.ConnMetadata, []byte) (*ssh.Permissions, error) {
			return nil, errors.New("no")
		},
		PublicKeyCallback: func(ssh.ConnMetadata, ssh.PublicKey) (*ssh.Permissions, error) {
			return nil, errors.New("no")
		},
	}
	cfg.AddHostKey(signer)
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = ln.Close() })
	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			go func() {
				defer func() { _ = c.Close() }()
				_, _, _, _ = ssh.NewServerConn(c, cfg)
			}()
		}
	}()
	return int32(ln.Addr().(*net.TCPAddr).Port), signer.PublicKey(), authAttempts // #nosec G115 -- a TCP port
}

func scanReq(port int32) *sshbrokerv1.ScanHostKeyRequest {
	return &sshbrokerv1.ScanHostKeyRequest{
		Host: "127.0.0.1", Port: port, TargetId: "target-1", ActorUserId: "actor-1",
		Actor: &sshbrokerv1.ActorContext{UserId: "actor-1"},
	}
}

func scanBroker(t *testing.T) (*Broker, *recordingAudit) {
	t.Helper()
	store := session.NewStore()
	t.Cleanup(store.Close)
	ra := &recordingAudit{}
	return NewBroker(store, audit.New(ra), "ws://localhost:9097/ssh/session"), ra
}

func TestScanHostKeyReturnsTheOfferedKeyWithoutAuthenticating(t *testing.T) {
	port, want, attempts := startScanTarget(t)
	b, ra := scanBroker(t)
	resp, err := b.ScanHostKey(context.Background(), scanReq(port))
	if err != nil {
		t.Fatalf("ScanHostKey: %v", err)
	}
	if resp.GetKeyType() != ssh.KeyAlgoED25519 {
		t.Fatalf("key type = %q", resp.GetKeyType())
	}
	if resp.GetFingerprintSha256() != ssh.FingerprintSHA256(want) {
		t.Fatalf("fingerprint = %q, want %q", resp.GetFingerprintSha256(), ssh.FingerprintSHA256(want))
	}
	got, _, _, rest, err := ssh.ParseAuthorizedKey([]byte(resp.GetPublicKey()))
	if err != nil || len(rest) > 0 || string(got.Marshal()) != string(want.Marshal()) {
		t.Fatalf("public key %q does not parse to the host key: %v", resp.GetPublicKey(), err)
	}
	time.Sleep(50 * time.Millisecond)
	if n := attempts.Load(); n != 0 {
		t.Fatalf("the scan made %d authentication attempts, want 0", n)
	}
	if len(ra.events) != 1 {
		t.Fatalf("audit events = %d, want 1", len(ra.events))
	}
	ev := ra.events[0]
	if ev.GetAction() != "hostkey.scan" || ev.GetSubject() != "target-1" || ev.GetActorUserId() != "actor-1" {
		t.Fatalf("audit = %+v", ev)
	}
	if ev.GetAttributes()["fingerprint_sha256"] != resp.GetFingerprintSha256() || ev.GetAttributes()["outcome"] != "ok" {
		t.Fatalf("audit attributes = %v", ev.GetAttributes())
	}
	for k, v := range ev.GetAttributes() {
		if strings.Contains(v, resp.GetPublicKey()[len(ssh.KeyAlgoED25519)+1:]) {
			t.Fatalf("audit attribute %s carries the key itself", k)
		}
	}
}

func TestScanHostKeyRefusesNonHumans(t *testing.T) {
	b, _ := scanBroker(t)
	req := scanReq(22)
	req.Actor.PrincipalKind = sshbrokerv1.PrincipalKind_PRINCIPAL_KIND_USER_TOKEN
	if _, err := b.ScanHostKey(context.Background(), req); status.Code(err) != codes.PermissionDenied {
		t.Fatalf("err %v, want PermissionDenied", err)
	}
}

func TestScanHostKeyValidatesInput(t *testing.T) {
	b, _ := scanBroker(t)
	for name, mut := range map[string]func(*sshbrokerv1.ScanHostKeyRequest){
		"no host":       func(r *sshbrokerv1.ScanHostKeyRequest) { r.Host = "" },
		"no target":     func(r *sshbrokerv1.ScanHostKeyRequest) { r.TargetId = "" },
		"no actor":      func(r *sshbrokerv1.ScanHostKeyRequest) { r.ActorUserId = "" },
		"bad port":      func(r *sshbrokerv1.ScanHostKeyRequest) { r.Port = 70000 },
		"negative port": func(r *sshbrokerv1.ScanHostKeyRequest) { r.Port = -1 },
	} {
		t.Run(name, func(t *testing.T) {
			req := scanReq(22)
			mut(req)
			if _, err := b.ScanHostKey(context.Background(), req); status.Code(err) != codes.InvalidArgument {
				t.Fatalf("err %v, want InvalidArgument", err)
			}
		})
	}
}

func TestScanHostKeyUnreachableIsUnavailableAndAudited(t *testing.T) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	port := int32(ln.Addr().(*net.TCPAddr).Port) // #nosec G115 -- a TCP port
	_ = ln.Close()
	b, ra := scanBroker(t)
	if _, err := b.ScanHostKey(context.Background(), scanReq(port)); status.Code(err) != codes.Unavailable {
		t.Fatalf("err %v, want Unavailable", err)
	}
	if len(ra.events) != 1 || ra.events[0].GetAttributes()["outcome"] != "unreachable" {
		t.Fatalf("audit = %v", ra.events)
	}
}

func TestScanHostKeyTimesOutOnASilentPort(t *testing.T) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = ln.Close() })
	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			t.Cleanup(func() { _ = c.Close() })
		}
	}()
	b, _ := scanBroker(t)
	b.scanTimeout = 200 * time.Millisecond
	start := time.Now()
	_, err = b.ScanHostKey(context.Background(), scanReq(int32(ln.Addr().(*net.TCPAddr).Port))) // #nosec G115 -- a TCP port
	if status.Code(err) != codes.Unavailable {
		t.Fatalf("err %v, want Unavailable", err)
	}
	if d := time.Since(start); d > 2*time.Second {
		t.Fatalf("scan took %v, want it bounded by the timeout", d)
	}
}

func TestScanHostKeyIsRateLimitedPerActor(t *testing.T) {
	port, _, _ := startScanTarget(t)
	b, ra := scanBroker(t)
	for i := 0; i < scanBurst; i++ {
		if _, err := b.ScanHostKey(context.Background(), scanReq(port)); err != nil {
			t.Fatalf("scan %d: %v", i+1, err)
		}
	}
	if _, err := b.ScanHostKey(context.Background(), scanReq(port)); status.Code(err) != codes.ResourceExhausted {
		t.Fatalf("over the limit: err %v, want ResourceExhausted", err)
	}
	if last := ra.events[len(ra.events)-1]; last.GetAttributes()["outcome"] != "rate_limited" {
		t.Fatalf("refusal not audited: %v", last)
	}
	other := scanReq(port)
	other.ActorUserId, other.Actor.UserId = "actor-2", "actor-2"
	if _, err := b.ScanHostKey(context.Background(), other); err != nil {
		t.Fatalf("another actor is limited separately: %v", err)
	}
}
