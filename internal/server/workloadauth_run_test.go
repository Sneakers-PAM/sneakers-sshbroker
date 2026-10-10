// Copyright 2026 The Sneakers-PAM Authors
// SPDX-License-Identifier: Apache-2.0

package server

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"sync/atomic"
	"testing"
	"time"

	"github.com/Bugs5382/go-buildinfo/health"
	log "github.com/Bugs5382/go-log"
	workloadauth "github.com/Bugs5382/go-workload-identity"
)

// flakyJWKS is a fake issuer JWKS endpoint that answers 503 to the first
// failFirst requests and the key set after that.
type flakyJWKS struct {
	srv       *httptest.Server
	hits      atomic.Int32
	failFirst int32
}

func newFlakyJWKS(t *testing.T, failFirst int32) *flakyJWKS {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	pub, err := key.PublicKey.Bytes()
	if err != nil {
		t.Fatal(err)
	}
	set, err := json.Marshal(map[string]any{"keys": []map[string]string{{
		"kty": "EC", "crv": "P-256", "kid": "k1", "use": "sig", "alg": "ES256",
		"x": base64.RawURLEncoding.EncodeToString(pub[1:33]),
		"y": base64.RawURLEncoding.EncodeToString(pub[33:]),
	}}})
	if err != nil {
		t.Fatal(err)
	}
	f := &flakyJWKS{failFirst: failFirst}
	f.srv = httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		if f.hits.Add(1) <= f.failFirst {
			http.Error(w, "not yet", http.StatusServiceUnavailable)
			return
		}
		w.Header().Set("Content-Type", "application/jwk-set+json")
		_, _ = w.Write(set)
	}))
	t.Cleanup(f.srv.Close)
	return f
}

func (f *flakyJWKS) verifier(t *testing.T) *workloadauth.Verifier {
	t.Helper()
	ca := filepath.Join(t.TempDir(), "ca.pem")
	if err := os.WriteFile(ca, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: f.srv.Certificate().Raw}), 0o600); err != nil {
		t.Fatal(err)
	}
	v, err := workloadauth.NewVerifier(workloadauth.Config{
		Issuer: "https://issuer.example.test", JWKSURL: f.srv.URL + "/openid/v1/jwks", CAFile: ca,
		Audience: "sneakers", AllowedServiceAccounts: []string{"sneakers/sneakers-gateway"},
	}, log.Nop())
	if err != nil {
		t.Fatal(err)
	}
	return v
}

// TestWorkloadAuthRun_ComesUpWhenTheFirstJWKSFetchFailsThenSucceeds drives
// the broker's own readiness wiring (NewChecker plus WorkloadIdentity) over
// go-workload-identity's public Verifier.Run, the same call main.go makes.
// go-workload-identity v1.0.1 retries the first fetch itself (backoff from 1
// second to 30 seconds), so the broker turns ready without a restart and
// without any local retry loop of its own. The backoff schedule is not
// configurable from outside the package, so this waits on the real timing
// (two failures: about 1s then 2s) rather than a shortened one.
func TestWorkloadAuthRun_ComesUpWhenTheFirstJWKSFetchFailsThenSucceeds(t *testing.T) {
	f := newFlakyJWKS(t, 2)
	v := f.verifier(t)
	c, err := NewChecker(log.Nop(), []health.Dependency{WorkloadIdentity(v)}, health.WithTTL(time.Millisecond))
	if err != nil {
		t.Fatal(err)
	}
	refreshed(t, c)
	if r := c.Report(context.Background()); r.Status != health.StateDown {
		t.Fatalf("readiness before any key set: %+v", r)
	}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	go v.Run(ctx)

	deadline := time.Now().Add(15 * time.Second)
	for {
		r := c.Report(context.Background())
		if r.Status == health.StateOK {
			break
		}
		if time.Now().After(deadline) {
			t.Fatalf("readiness never turned SERVING after %d fetches: %+v", f.hits.Load(), r)
		}
		time.Sleep(20 * time.Millisecond)
	}
	if got := f.hits.Load(); got < 3 {
		t.Fatalf("fetches = %d, want the 2 failures and a success", got)
	}
}
