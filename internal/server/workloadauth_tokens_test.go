// Copyright 2026 The Sneakers-PAM Authors
// SPDX-License-Identifier: Apache-2.0

package server

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

	log "github.com/Bugs5382/go-log"
	workloadauth "github.com/Bugs5382/go-workload-identity"
	"github.com/golang-jwt/jwt/v5"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/credentials/insecure"
	"google.golang.org/grpc/metadata"
	"google.golang.org/grpc/status"
	"google.golang.org/grpc/test/bufconn"
	"google.golang.org/protobuf/types/known/emptypb"
)

const probeMethod = "/sneakers.probe.v1.Probe/Call"

// testIssuer is a local Kubernetes-style token issuer: a TLS server with
// discovery and a JWKS holding one RSA key generated for the test.
type testIssuer struct {
	url, caFile string
	key         *rsa.PrivateKey
}

func newTestIssuer(t *testing.T) *testIssuer {
	t.Helper()
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	iss := &testIssuer{key: key}
	mux := http.NewServeMux()
	mux.HandleFunc("/.well-known/openid-configuration", func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]string{"issuer": iss.url, "jwks_uri": iss.url + "/openid/v1/jwks"})
	})
	mux.HandleFunc("/openid/v1/jwks", func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/jwk-set+json")
		_ = json.NewEncoder(w).Encode(map[string]any{"keys": []map[string]string{{
			"kty": "RSA", "kid": "rsa-1", "alg": "RS256", "use": "sig",
			"n": base64.RawURLEncoding.EncodeToString(key.N.Bytes()),
			"e": base64.RawURLEncoding.EncodeToString(big.NewInt(int64(key.E)).Bytes()),
		}}})
	})
	srv := httptest.NewTLSServer(mux)
	t.Cleanup(srv.Close)
	iss.url = srv.URL
	iss.caFile = filepath.Join(t.TempDir(), "issuer-ca.pem")
	if err := os.WriteFile(iss.caFile, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: srv.Certificate().Raw}), 0o600); err != nil {
		t.Fatal(err)
	}
	return iss
}

// token signs a projected-token-shaped claim set for sneakers/<sa>; mutate
// changes the claims before signing.
func (i *testIssuer) token(t *testing.T, sa string, mutate func(jwt.MapClaims)) string {
	t.Helper()
	now := time.Now()
	c := jwt.MapClaims{
		"iss": i.url, "aud": []string{"sneakers"}, "sub": "system:serviceaccount:sneakers:" + sa,
		"iat": now.Unix(), "nbf": now.Unix(), "exp": now.Add(time.Hour).Unix(),
		"kubernetes.io": map[string]any{"namespace": "sneakers", "serviceaccount": map[string]any{"name": sa}},
	}
	if mutate != nil {
		mutate(c)
	}
	tok := jwt.NewWithClaims(jwt.SigningMethodRS256, c)
	tok.Header["kid"] = "rsa-1"
	s, err := tok.SignedString(i.key)
	if err != nil {
		t.Fatal(err)
	}
	return s
}

// probeConn serves an echo handler behind opts and returns a client for it.
func probeConn(t *testing.T, opts []grpc.ServerOption) *grpc.ClientConn {
	t.Helper()
	lis := bufconn.Listen(1 << 20)
	srv := grpc.NewServer(append(opts, grpc.UnknownServiceHandler(func(_ any, ss grpc.ServerStream) error {
		var in emptypb.Empty
		if err := ss.RecvMsg(&in); err != nil {
			return err
		}
		return ss.SendMsg(&emptypb.Empty{})
	}))...)
	go func() { _ = srv.Serve(lis) }()
	t.Cleanup(srv.Stop)
	conn, err := grpc.NewClient("passthrough:///probe",
		grpc.WithContextDialer(func(context.Context, string) (net.Conn, error) { return lis.Dial() }),
		grpc.WithTransportCredentials(insecure.NewCredentials()))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = conn.Close() })
	return conn
}

func callWith(conn *grpc.ClientConn, token string) codes.Code {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	ctx = metadata.AppendToOutgoingContext(ctx, "authorization", "Bearer "+token)
	return status.Code(conn.Invoke(ctx, probeMethod, &emptypb.Empty{}, &emptypb.Empty{}))
}

// TestWorkloadAuthAcceptsAndRefusesTokens pins which projected tokens the
// service accepts: the audience defaults to "sneakers", the caller name is
// the service account without its "sneakers-" prefix, and a token with the
// wrong audience or issuer, an expired one, or one from a caller not on the
// method's list is refused.
func TestWorkloadAuthAcceptsAndRefusesTokens(t *testing.T) {
	iss := newTestIssuer(t)
	ctx, cancel := context.WithCancel(context.Background())
	t.Cleanup(cancel)
	conn := probeConn(t, workloadAuthFor(t, ctx, map[string]string{
		"WORKLOAD_OIDC_ISSUER":             iss.url,
		"WORKLOAD_OIDC_CA_FILE":            iss.caFile,
		"WORKLOAD_ALLOWED_SERVICEACCOUNTS": "sneakers/sneakers-gateway,sneakers/sneakers-audit",
	}))

	valid := iss.token(t, "sneakers-gateway", nil)
	deadline := time.Now().Add(5 * time.Second)
	for callWith(conn, valid) == codes.Unavailable {
		if time.Now().After(deadline) {
			t.Fatal("the verifier never loaded the issuer's keys")
		}
		time.Sleep(10 * time.Millisecond)
	}
	cases := map[string]struct {
		token string
		want  codes.Code
	}{
		"listed caller":               {valid, codes.OK},
		"wrong audience":              {iss.token(t, "sneakers-gateway", func(c jwt.MapClaims) { c["aud"] = []string{"other"} }), codes.Unauthenticated},
		"wrong issuer":                {iss.token(t, "sneakers-gateway", func(c jwt.MapClaims) { c["iss"] = "https://issuer.example.org" }), codes.Unauthenticated},
		"expired":                     {iss.token(t, "sneakers-gateway", func(c jwt.MapClaims) { c["exp"] = time.Now().Add(-time.Hour).Unix() }), codes.Unauthenticated},
		"caller not on the method":    {iss.token(t, "sneakers-audit", nil), codes.PermissionDenied},
		"service account not allowed": {iss.token(t, "sneakers-identity", nil), codes.Unauthenticated},
	}
	for name, tc := range cases {
		t.Run(name, func(t *testing.T) {
			if got := callWith(conn, tc.token); got != tc.want {
				t.Fatalf("code = %v, want %v", got, tc.want)
			}
		})
	}
}

// workloadAuthFor builds the interceptors the way cmd/sshbroker does, with a
// policy that lists only the gateway on probeMethod.
func workloadAuthFor(t *testing.T, ctx context.Context, env map[string]string) []grpc.ServerOption {
	t.Helper()
	getenv := func(k string) string { return env[k] }
	cfg, on, err := WorkloadConfigFromEnv(getenv)
	if err != nil || !on {
		t.Fatalf("config: on=%v err=%v", on, err)
	}
	v, err := workloadauth.NewVerifier(cfg, log.Nop())
	if err != nil {
		t.Fatal(err)
	}
	go v.Run(ctx)
	policy := workloadauth.Policy{probeMethod: {"gateway": workloadauth.Self}}
	return []grpc.ServerOption{
		grpc.ChainUnaryInterceptor(workloadauth.UnaryServerInterceptor(v, policy, log.Nop())),
		grpc.ChainStreamInterceptor(workloadauth.StreamServerInterceptor(v, policy, log.Nop())),
	}
}

func TestWorkloadConfigFromEnvSetsTheSneakersValues(t *testing.T) {
	env := map[string]string{
		"WORKLOAD_OIDC_ISSUER":             "https://issuer.example.org",
		"WORKLOAD_ALLOWED_SERVICEACCOUNTS": "sneakers/sneakers-gateway",
		"WORKLOAD_SERVICEACCOUNT_PREFIX":   "other-",
	}
	getenv := func(k string) string { return env[k] }
	cfg, enabled, err := WorkloadConfigFromEnv(getenv)
	if err != nil || !enabled {
		t.Fatalf("enabled=%v err=%v", enabled, err)
	}
	if cfg.Audience != "sneakers" || cfg.ServiceAccountPrefix != "sneakers-" {
		t.Fatalf("audience %q prefix %q, want sneakers and sneakers-", cfg.Audience, cfg.ServiceAccountPrefix)
	}
	env["WORKLOAD_AUDIENCE"] = "sshbroker.sneakers.example.org"
	if cfg, _, _ = WorkloadConfigFromEnv(getenv); cfg.Audience != "sshbroker.sneakers.example.org" {
		t.Fatalf("audience %q, want the configured one", cfg.Audience)
	}
}
