// Copyright 2026 The Sneakers-PAM Authors
// SPDX-License-Identifier: Apache-2.0

package grpcsvc

import (
	"context"
	"errors"
	"net"
	"strconv"
	"strings"
	"sync"
	"time"

	"golang.org/x/crypto/ssh"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	sshbrokerv1 "github.com/Sneakers-PAM/sneakers-sshbroker/gen/go/sneakers/sshbroker/v1"
)

const (
	// defaultScanTimeout bounds the whole scan: TCP connect plus the SSH
	// version exchange and key exchange up to the host key.
	defaultScanTimeout = 5 * time.Second
	// scanBurst scans an actor may run back to back, refilled one per
	// scanRefill, so the broker can't be driven as a port scanner.
	scanBurst  = 5
	scanRefill = 12 * time.Second
	// scanUser is the user name sent in the handshake. No authentication
	// request is ever sent, so the target never sees it used.
	scanUser = "sneakers-hostkey-scan"
)

// errHostKeyRead stops the handshake once the host key has arrived, before
// any authentication request is sent.
var errHostKeyRead = errors.New("host key read")

// scanLimiter is a token bucket per actor.
type scanLimiter struct {
	mu      sync.Mutex
	now     func() time.Time
	buckets map[string]*scanBucket
}

type scanBucket struct {
	tokens float64
	at     time.Time
}

func newScanLimiter() *scanLimiter {
	return &scanLimiter{now: time.Now, buckets: map[string]*scanBucket{}}
}

func (l *scanLimiter) allow(actor string) bool {
	l.mu.Lock()
	defer l.mu.Unlock()
	now := l.now()
	for k, b := range l.buckets {
		if now.Sub(b.at) > scanBurst*scanRefill {
			delete(l.buckets, k)
		}
	}
	b, ok := l.buckets[actor]
	if !ok {
		b = &scanBucket{tokens: scanBurst, at: now}
		l.buckets[actor] = b
	}
	b.tokens += float64(now.Sub(b.at)) / float64(scanRefill)
	if b.tokens > scanBurst {
		b.tokens = scanBurst
	}
	b.at = now
	if b.tokens < 1 {
		return false
	}
	b.tokens--
	return true
}

// ScanHostKey reads the host key a target offers during the SSH handshake.
// It never authenticates: the host key callback aborts the handshake as soon
// as the key arrives, before any authentication request is sent. Audited as
// hostkey.scan with the fingerprint only.
func (b *Broker) ScanHostKey(ctx context.Context, req *sshbrokerv1.ScanHostKeyRequest) (*sshbrokerv1.ScanHostKeyResponse, error) {
	if kind := req.GetActor().GetPrincipalKind(); kind != sshbrokerv1.PrincipalKind_PRINCIPAL_KIND_HUMAN {
		logger.Warn().Str("actor_user_id", req.GetActorUserId()).Str("principal_kind", kind.String()).
			Str("target_id", req.GetTargetId()).Msg("host key scan refused: principal kind not allowed")
		b.audit.HostKeyScan(ctx, req.GetActorUserId(), req.GetTargetId(), req.GetHost(), "refused", map[string]string{"principal_kind": kind.String()})
		return nil, status.Error(codes.PermissionDenied, "host key scans are for people in the web app only")
	}
	if req.GetHost() == "" || req.GetTargetId() == "" || req.GetActorUserId() == "" {
		return nil, status.Error(codes.InvalidArgument, "host, target_id and actor_user_id are required")
	}
	port := req.GetPort()
	if port == 0 {
		port = 22
	}
	if port < 1 || port > 65535 {
		return nil, status.Error(codes.InvalidArgument, "port must be between 1 and 65535")
	}
	if !b.scanLimit.allow(req.GetActorUserId()) {
		logger.Warn().Str("actor_user_id", req.GetActorUserId()).Str("target_id", req.GetTargetId()).Msg("host key scan refused: rate limited")
		b.audit.HostKeyScan(ctx, req.GetActorUserId(), req.GetTargetId(), req.GetHost(), "rate_limited", nil)
		return nil, status.Error(codes.ResourceExhausted, "too many host key scans; try again shortly")
	}

	addr := net.JoinHostPort(req.GetHost(), strconv.Itoa(int(port)))
	start := time.Now()
	logger.Debug().Str("target_id", req.GetTargetId()).Str("host", req.GetHost()).Int32("port", port).Msg("host key scan start")
	key, outcome, err := scanHostKey(ctx, addr, b.scanTimeout)
	dur := time.Since(start)
	if err != nil {
		logger.Warn().Err(err).Str("target_id", req.GetTargetId()).Str("host", req.GetHost()).Int32("port", port).
			Str("outcome", outcome).Dur("duration", dur).Msg("host key scan failed")
		b.audit.HostKeyScan(ctx, req.GetActorUserId(), req.GetTargetId(), req.GetHost(), outcome, map[string]string{"port": strconv.Itoa(int(port))})
		if outcome == "unreachable" {
			return nil, status.Error(codes.Unavailable, "target unreachable")
		}
		return nil, status.Error(codes.Unavailable, "no SSH host key offered")
	}
	fp := ssh.FingerprintSHA256(key)
	logger.Info().Str("target_id", req.GetTargetId()).Str("host", req.GetHost()).Int32("port", port).
		Str("host_key_fingerprint", fp).Dur("duration", dur).Msg("host key scanned")
	b.audit.HostKeyScan(ctx, req.GetActorUserId(), req.GetTargetId(), req.GetHost(), "ok", map[string]string{
		"port":               strconv.Itoa(int(port)),
		"key_type":           key.Type(),
		"fingerprint_sha256": fp,
	})
	return &sshbrokerv1.ScanHostKeyResponse{
		KeyType:           key.Type(),
		PublicKey:         strings.TrimSpace(string(ssh.MarshalAuthorizedKey(key))),
		FingerprintSha256: fp,
	}, nil
}

// scanHostKey dials addr and runs the SSH handshake only as far as the host
// key, within timeout. The outcome is "unreachable" when the TCP connect
// fails and "handshake_failed" when no host key arrived.
func scanHostKey(ctx context.Context, addr string, timeout time.Duration) (ssh.PublicKey, string, error) {
	if timeout <= 0 {
		timeout = defaultScanTimeout
	}
	ctx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()
	var d net.Dialer
	conn, err := d.DialContext(ctx, "tcp", addr)
	if err != nil {
		return nil, "unreachable", err
	}
	defer func() { _ = conn.Close() }()
	deadline, _ := ctx.Deadline()
	if err := conn.SetDeadline(deadline); err != nil {
		return nil, "handshake_failed", err
	}
	var got ssh.PublicKey
	cfg := &ssh.ClientConfig{
		User: scanUser,
		HostKeyCallback: func(_ string, _ net.Addr, key ssh.PublicKey) error {
			got = key
			return errHostKeyRead
		},
		Timeout: timeout,
	}
	_, _, _, err = ssh.NewClientConn(conn, addr, cfg)
	if got != nil {
		return got, "ok", nil
	}
	if err == nil {
		err = errors.New("handshake ended without a host key")
	}
	return nil, "handshake_failed", err
}
