// Copyright 2026 The Sneakers-PAM Authors
// SPDX-License-Identifier: Apache-2.0

package grpcsvc

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"math/big"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/golang-jwt/jwt/v5"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/credentials/insecure"
	"google.golang.org/grpc/metadata"
	"google.golang.org/grpc/status"

	workloadauth "github.com/Bugs5382/go-workload-identity"
	sshbrokerv1 "github.com/Sneakers-PAM/sneakers-sshbroker/gen/go/sneakers/sshbroker/v1"
	"github.com/Sneakers-PAM/sneakers-sshbroker/internal/audit"
	"github.com/Sneakers-PAM/sneakers-sshbroker/internal/server"
	"github.com/Sneakers-PAM/sneakers-sshbroker/internal/session"
)

const testNS = "sneakers"

// issuer is a local OIDC issuer over TLS with a key made in the test.
type issuer struct {
	url, caFile string
	key         *rsa.PrivateKey
}

func newIssuer(t *testing.T) *issuer {
	t.Helper()
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	i := &issuer{key: key}
	mux := http.NewServeMux()
	mux.HandleFunc("/openid/v1/jwks", func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/jwk-set+json")
		_ = json.NewEncoder(w).Encode(map[string]any{"keys": []map[string]string{{
			"kty": "RSA", "kid": "k1", "alg": "RS256", "use": "sig",
			"n": base64.RawURLEncoding.EncodeToString(key.N.Bytes()),
			"e": base64.RawURLEncoding.EncodeToString(big.NewInt(int64(key.E)).Bytes()),
		}}})
	})
	srv := httptest.NewTLSServer(mux)
	t.Cleanup(srv.Close)
	i.url = srv.URL
	i.caFile = filepath.Join(t.TempDir(), "ca.pem")
	if err := os.WriteFile(i.caFile, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: srv.Certificate().Raw}), 0o600); err != nil {
		t.Fatal(err)
	}
	return i
}

func (i *issuer) token(t *testing.T, sa string) string {
	t.Helper()
	now := time.Now()
	tok := jwt.NewWithClaims(jwt.SigningMethodRS256, jwt.MapClaims{
		"iss": i.url, "aud": []string{"sneakers"}, "sub": "system:serviceaccount:" + testNS + ":" + sa,
		"iat": now.Unix(), "nbf": now.Unix(), "exp": now.Add(10 * time.Minute).Unix(),
		"kubernetes.io": map[string]any{"namespace": testNS, "serviceaccount": map[string]string{"name": sa}},
	})
	tok.Header["kid"] = "k1"
	s, err := tok.SignedString(i.key)
	if err != nil {
		t.Fatal(err)
	}
	return s
}

// startAuthedBroker serves the broker behind the workload-auth interceptors,
// with the given service accounts allowed to present tokens at all.
func startAuthedBroker(t *testing.T, iss *issuer, allowed []string, rec *recordingAudit) sshbrokerv1.SSHBrokerServiceClient {
	t.Helper()
	v, err := workloadauth.NewVerifier(workloadauth.Config{
		Issuer: iss.url, JWKSURL: iss.url + "/openid/v1/jwks", CAFile: iss.caFile,
		AllowedServiceAccounts: allowed,
		Audience:               server.WorkloadAudience, ServiceAccountPrefix: server.WorkloadServiceAccountPrefix,
	}, nil)
	if err != nil {
		t.Fatal(err)
	}
	if err := v.Refresh(context.Background()); err != nil {
		t.Fatal(err)
	}
	store := session.NewStore()
	t.Cleanup(store.Close)
	aud := audit.New(rec)
	gs := grpc.NewServer(AuthServerOptions(v, aud, nil)...)
	RegisterServer(gs, NewBroker(store, aud, "ws://localhost:9097/ssh/session"))
	lis, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	go func() { _ = gs.Serve(lis) }()
	t.Cleanup(gs.Stop)
	conn, err := grpc.NewClient(lis.Addr().String(), grpc.WithTransportCredentials(insecure.NewCredentials()))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = conn.Close() })
	return sshbrokerv1.NewSSHBrokerServiceClient(conn)
}

func referenceReq() *sshbrokerv1.CreateSessionRequest {
	return &sshbrokerv1.CreateSessionRequest{
		Host: "192.0.2.1", Port: 22, Username: "root", ActorUserId: "user-1", SecretId: "secret-1", TargetId: "target-1",
		Actor: &sshbrokerv1.ActorContext{UserId: "user-1", IsRoot: true},
	}
}

func withToken(tok string) context.Context {
	return metadata.AppendToOutgoingContext(context.Background(), "authorization", "Bearer "+tok)
}

// TestCreateSessionCallerCheck: only the gateway's workload token mints a
// ticket. A pod in the call graph that isn't the gateway (the MCP server,
// with a valid token for an allowed service account) is refused with
// PermissionDenied, and a caller with no token or an unallowed service account
// is refused as unauthenticated. Every refusal is audited.
func TestCreateSessionCallerCheck(t *testing.T) {
	iss := newIssuer(t)
	rec := &recordingAudit{}
	c := startAuthedBroker(t, iss, []string{testNS + "/sneakers-gateway", testNS + "/sneakers-mcp"}, rec)

	resp, err := c.CreateSession(withToken(iss.token(t, "sneakers-gateway")), referenceReq())
	if err != nil || resp.GetTicket() == "" {
		t.Fatalf("gateway refused: resp=%v err=%v", resp, err)
	}

	cases := []struct {
		name string
		ctx  context.Context
		code codes.Code
	}{
		{"mcp with a valid token", withToken(iss.token(t, "sneakers-mcp")), codes.PermissionDenied},
		{"vault service account not allowed", withToken(iss.token(t, "sneakers-vault")), codes.Unauthenticated},
		{"no token", context.Background(), codes.Unauthenticated},
		{"garbage token", withToken("not-a-jwt"), codes.Unauthenticated},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			rec.mu.Lock()
			rec.events = nil
			rec.mu.Unlock()
			_, err := c.CreateSession(tc.ctx, referenceReq())
			if status.Code(err) != tc.code {
				t.Fatalf("code = %v, want %v (err %v)", status.Code(err), tc.code, err)
			}
			rec.mu.Lock()
			defer rec.mu.Unlock()
			if len(rec.events) != 1 || rec.events[0].GetAction() != "session.refuse" {
				t.Fatalf("audit events = %v, want one session.refuse", rec.events)
			}
			ev := rec.events[0]
			if ev.GetAttributes()["code"] != tc.code.String() || ev.GetAttributes()["reason"] == "" {
				t.Fatalf("audit event = %v", ev)
			}
			if tc.code == codes.PermissionDenied && ev.GetAttributes()["caller"] != "mcp" {
				t.Fatalf("audit event = %v, want caller mcp", ev)
			}
		})
	}
}
