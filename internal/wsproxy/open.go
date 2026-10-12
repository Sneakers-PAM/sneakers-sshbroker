// Copyright 2026 The Sneakers-PAM Authors
// SPDX-License-Identifier: Apache-2.0

package wsproxy

import (
	"context"
	"crypto/x509"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"strings"
	"sync"
	"syscall"
	"time"
	"unicode/utf8"

	"github.com/gorilla/websocket"
	"golang.org/x/crypto/ssh"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	"github.com/Sneakers-PAM/sneakers-sshbroker/internal/session"
)

// openError is a failed open: msg is the sentence the client is shown and
// the audit records (it names the step and the reason, never key material);
// err is the underlying error, for the log only.
type openError struct {
	step   string
	msg    string
	err    error
	status int
	// hostKey marks the two host-key refusals, which close with a policy
	// violation the web app recognises by their exact text.
	hostKey bool
}

// target is an SSH session ready for the pumps: authenticated, with a PTY
// and a running shell.
type target struct {
	client  *ssh.Client
	session *ssh.Session
	stdin   io.WriteCloser
	stdout  io.Reader
	stderr  io.Reader
}

func (t *target) close() {
	_ = t.session.Close()
	_ = t.client.Close()
}

// openTarget runs every fallible step of the open in order: the key reveal,
// the key parse, the TCP connect, the SSH banner, key exchange and host-key
// check, the auth, and the shell. Each step has its own bound and ctx
// bounds the whole open. Each step reached is logged with its duration.
func openTarget(ctx context.Context, cfg Config, keys KeyFetcher, sess *session.Session, st *steps) (*target, *openError) {
	if !sess.HasKey() {
		if oe := revealKey(ctx, cfg, keys, sess); oe != nil {
			return nil, oe
		}
		st.done("key revealed")
	}

	signer, err := parseSigner(sess)
	if err != nil {
		return nil, &openError{step: "key", msg: keyParseFailure(err), err: err, status: http.StatusInternalServerError}
	}

	pins, pinAlgos := parsePins(sess)
	cc := &ssh.ClientConfig{
		User:              sess.Username,
		Auth:              []ssh.AuthMethod{ssh.PublicKeys(signer)},
		HostKeyCallback:   pinnedHostKeyCallback(sess, pins),
		HostKeyAlgorithms: pinAlgos,
	}
	client, oe := dialTarget(ctx, cfg, sess, cc, st)
	if oe != nil {
		return nil, oe
	}
	st.done("authenticated")

	t, oe := startShell(ctx, cfg, sess, client)
	if oe != nil {
		_ = client.Close()
		return nil, oe
	}
	st.done("shell started")
	return t, nil
}

// revealKey fetches a reference-path session's key material from the vault
// and installs it on the session, so the teardown still zeroizes it.
func revealKey(ctx context.Context, cfg Config, keys KeyFetcher, sess *session.Session) *openError {
	if keys == nil {
		return &openError{step: "reveal", msg: "couldn't get the key: the broker has no vault client", err: errNoKeyFetcher, status: http.StatusBadGateway}
	}
	rctx, cancel := context.WithTimeout(ctx, cfg.RevealTimeout)
	defer cancel()
	priv, pass, err := keys.FetchKey(rctx, sess)
	if err != nil {
		return &openError{step: "reveal", msg: "couldn't get the key: " + vaultFailure(ctx, rctx, cfg, err), err: err, status: http.StatusBadGateway}
	}
	sess.SetKeyMaterial(priv, pass)
	return nil
}

func vaultFailure(open, step context.Context, cfg Config, err error) string {
	if step.Err() != nil || status.Code(err) == codes.DeadlineExceeded {
		return "the vault didn't answer " + within(open, cfg.RevealTimeout, cfg)
	}
	switch status.Code(err) {
	case codes.PermissionDenied, codes.Unauthenticated:
		return "the vault refused access to it"
	case codes.NotFound:
		return "the vault has no key for this secret"
	case codes.Unavailable:
		return "the vault isn't reachable"
	case codes.FailedPrecondition:
		return "the vault won't reveal it right now (" + status.Convert(err).Message() + ")"
	}
	return "the vault failed the reveal (" + status.Code(err).String() + ")"
}

// within says which bound ran out: the step's own, or the whole open's.
func within(open context.Context, step time.Duration, cfg Config) string {
	if open.Err() != nil {
		return fmt.Sprintf("within the %s open limit", cfg.OpenTimeout)
	}
	return fmt.Sprintf("in %s", step)
}

func keyParseFailure(err error) string {
	var missing *ssh.PassphraseMissingError
	switch {
	case errors.As(err, &missing):
		return "the stored key needs a passphrase, and the secret has none"
	case errors.Is(err, x509.IncorrectPasswordError):
		return "the stored passphrase doesn't open the stored key"
	}
	return "the stored key isn't a private key the broker can read"
}

// dialTarget connects to the target and runs the SSH handshake and auth.
// ssh.Dial bounds only the TCP connect; the handshake gets a deadline on
// the connection, so a target that accepts and then stalls can't hold the
// open.
func dialTarget(ctx context.Context, cfg Config, sess *session.Session, cc *ssh.ClientConfig, st *steps) (*ssh.Client, *openError) {
	address := addr(sess)
	dctx, cancel := context.WithTimeout(ctx, cfg.DialTimeout)
	var d net.Dialer
	nc, err := d.DialContext(dctx, "tcp", address)
	cancel()
	if err != nil {
		return nil, &openError{step: "connect", msg: reachFailure(sess.Host, address, err), err: err, status: http.StatusBadGateway}
	}
	st.done("tcp connected")

	deadline := time.Now().Add(cfg.HandshakeTimeout)
	if od, ok := ctx.Deadline(); ok && od.Before(deadline) {
		deadline = od
	}
	_ = nc.SetDeadline(deadline)
	stop := context.AfterFunc(ctx, func() { _ = nc.Close() })
	check := cc.HostKeyCallback
	cc.HostKeyCallback = func(hostname string, remote net.Addr, key ssh.PublicKey) error {
		err := check(hostname, remote, key)
		if err == nil {
			st.done("host key verified")
		}
		return err
	}
	bc := &bannerConn{Conn: nc, first: func() { st.done("ssh banner received") }}
	c, chans, reqs, err := ssh.NewClientConn(bc, address, cc)
	stop()
	if err != nil {
		_ = nc.Close()
		return nil, handshakeFailure(ctx, cfg, sess, address, err)
	}
	_ = nc.SetDeadline(time.Time{})
	return ssh.NewClient(c, chans, reqs), nil
}

// bannerConn calls first once, when the target's first bytes (its SSH
// version line) arrive, so the log tells a target that never speaks from
// one that stalls later in the handshake.
type bannerConn struct {
	net.Conn
	once  sync.Once
	first func()
}

func (c *bannerConn) Read(p []byte) (int, error) {
	n, err := c.Conn.Read(p)
	if n > 0 {
		c.once.Do(c.first)
	}
	return n, err
}

// reachFailure says why the TCP connect failed, in the words a person reads.
func reachFailure(host, address string, err error) string {
	var dnsErr *net.DNSError
	if errors.As(err, &dnsErr) {
		name := dnsErr.Name
		if name == "" {
			name = host
		}
		if dnsErr.IsTimeout {
			return fmt.Sprintf("can't look up %s: DNS didn't answer", name)
		}
		return fmt.Sprintf("can't find %s in DNS", name)
	}
	why := err.Error()
	var ne net.Error
	switch {
	case errors.Is(err, syscall.ECONNREFUSED):
		why = "connection refused"
	case errors.Is(err, syscall.EHOSTUNREACH):
		why = "no route to host"
	case errors.Is(err, syscall.ENETUNREACH):
		why = "network is unreachable"
	case errors.Is(err, context.DeadlineExceeded), errors.As(err, &ne) && ne.Timeout():
		why = "connection timed out"
	}
	return fmt.Sprintf("can't reach %s: %s", address, why)
}

func handshakeFailure(ctx context.Context, cfg Config, sess *session.Session, address string, err error) *openError {
	if msg, ok := hostKeyRefusal(err); ok {
		return &openError{step: "host key", msg: msg, err: err, status: http.StatusBadGateway, hostKey: true}
	}
	step, msg := "handshake", ""
	var ne net.Error
	switch {
	case strings.Contains(err.Error(), "unable to authenticate"):
		step, msg = "auth", fmt.Sprintf("%s refused the key for %s", address, sess.Username)
	case ctx.Err() != nil, errors.As(err, &ne) && ne.Timeout():
		msg = fmt.Sprintf("%s didn't finish the SSH handshake %s", address, within(ctx, cfg.HandshakeTimeout, cfg))
	case errors.Is(err, io.EOF), errors.Is(err, syscall.ECONNRESET):
		msg = fmt.Sprintf("%s closed the connection during the SSH handshake", address)
	default:
		msg = fmt.Sprintf("the SSH handshake with %s failed: %s", address, strings.TrimPrefix(err.Error(), "ssh: handshake failed: "))
	}
	return &openError{step: step, msg: msg, err: err, status: http.StatusBadGateway}
}

// startShell opens the session channel, asks for a PTY and starts the
// shell. None of those calls takes a context, so the bound closes the
// client, which unblocks whichever one is waiting.
func startShell(ctx context.Context, cfg Config, sess *session.Session, client *ssh.Client) (*target, *openError) {
	sctx, cancel := context.WithTimeout(ctx, cfg.ShellTimeout)
	defer cancel()
	stop := context.AfterFunc(sctx, func() { _ = client.Close() })
	t, err := shell(client)
	if !stop() {
		if t != nil {
			_ = t.session.Close()
		}
		if err == nil {
			err = sctx.Err()
		}
		return nil, &openError{
			step:   "shell",
			msg:    fmt.Sprintf("%s didn't start a shell %s", addr(sess), within(ctx, cfg.ShellTimeout, cfg)),
			err:    err,
			status: http.StatusBadGateway,
		}
	}
	if err != nil {
		return nil, &openError{step: "shell", msg: fmt.Sprintf("%s refused a shell: %v", addr(sess), err), err: err, status: http.StatusBadGateway}
	}
	return t, nil
}

func shell(client *ssh.Client) (*target, error) {
	s, err := client.NewSession()
	if err != nil {
		return nil, err
	}
	t := &target{client: client, session: s}
	if t.stdin, err = s.StdinPipe(); err != nil {
		return t, err
	}
	if t.stdout, err = s.StdoutPipe(); err != nil {
		return t, err
	}
	if t.stderr, err = s.StderrPipe(); err != nil {
		return t, err
	}
	modes := ssh.TerminalModes{
		ssh.ECHO:          1,
		ssh.TTY_OP_ISPEED: 14400,
		ssh.TTY_OP_OSPEED: 14400,
	}
	if err := s.RequestPty("xterm-256color", 24, 80, modes); err != nil {
		return t, fmt.Errorf("pty request: %w", err)
	}
	if err := s.Shell(); err != nil {
		return t, fmt.Errorf("shell request: %w", err)
	}
	return t, nil
}

// refuse tells the client why the open failed. A browser can't read the body
// of a failed WebSocket handshake, so a WebSocket client gets the upgrade and
// then a close frame carrying the sentence: a policy violation for a
// host-key refusal, an internal error for anything else. Any other client
// gets the sentence as the response body.
func refuse(w http.ResponseWriter, r *http.Request, upgrader *websocket.Upgrader, cfg Config, oe *openError) {
	if !websocket.IsWebSocketUpgrade(r) {
		http.Error(w, oe.msg, oe.status)
		return
	}
	conn, err := upgrader.Upgrade(w, r, nil)
	if err != nil {
		return
	}
	defer func() { _ = conn.Close() }()
	code := websocket.CloseInternalServerErr
	if oe.hostKey {
		code = websocket.ClosePolicyViolation
	}
	_ = conn.WriteControl(websocket.CloseMessage,
		websocket.FormatCloseMessage(code, closeText(oe.msg)), time.Now().Add(cfg.WriteWait))
}

// maxCloseText is what a close frame's 125-byte payload leaves after the
// 2-byte code.
const maxCloseText = 123

// closeText cuts msg to fit a close frame, on a character boundary.
func closeText(msg string) string {
	if len(msg) <= maxCloseText {
		return msg
	}
	cut := maxCloseText
	for cut > 0 && !utf8.RuneStart(msg[cut]) {
		cut--
	}
	return msg[:cut]
}

// steps logs each open step as it is reached, with how long it took and
// the time since the ticket was redeemed. Only ids, the address and
// durations are logged, never key material.
type steps struct {
	sess    *session.Session
	started time.Time
	last    time.Time
}

func newSteps(sess *session.Session) *steps {
	now := time.Now()
	return &steps{sess: sess, started: now, last: now}
}

func (s *steps) done(step string) {
	now := time.Now()
	logger.Info().
		Str("host", s.sess.Host).
		Int32("port", s.sess.Port).
		Str("target_id", s.sess.TargetID).
		Str("secret_id", s.sess.SecretID).
		Str("actor_user_id", s.sess.ActorUserID).
		Str("step", step).
		Dur("step_ms", now.Sub(s.last)).
		Dur("elapsed_ms", now.Sub(s.started)).
		Msg("ssh session open step")
	s.last = now
}

func (s *steps) failed(oe *openError) {
	logger.Error().
		Err(oe.err).
		Str("host", s.sess.Host).
		Int32("port", s.sess.Port).
		Str("target_id", s.sess.TargetID).
		Str("secret_id", s.sess.SecretID).
		Str("actor_user_id", s.sess.ActorUserID).
		Str("step", oe.step).
		Str("reason", oe.msg).
		Dur("step_ms", time.Since(s.last)).
		Dur("elapsed_ms", time.Since(s.started)).
		Msg("ssh session open failed")
}
