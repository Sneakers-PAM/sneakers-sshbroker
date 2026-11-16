// Copyright 2026 The Sneakers-PAM Authors
// SPDX-License-Identifier: Apache-2.0

package server

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"math/big"
	"net"
	"os"
	"path/filepath"
	"testing"
	"time"

	mtls "github.com/Bugs5382/go-mtls"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/credentials"
	"google.golang.org/grpc/credentials/insecure"
	healthpb "google.golang.org/grpc/health/grpc_health_v1"
	"google.golang.org/grpc/status"
)

// testCerts is a throwaway CA and one leaf pair written to dir.
type testCerts struct{ cert, key, caPath string }

func writePEM(t *testing.T, path, typ string, der []byte) {
	t.Helper()
	if err := os.WriteFile(path, pem.EncodeToMemory(&pem.Block{Type: typ, Bytes: der}), 0o600); err != nil {
		t.Fatal(err)
	}
}

func newTestCerts(t *testing.T, dir, name string) testCerts {
	t.Helper()
	caKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	caTmpl := &x509.Certificate{
		SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: "example.org test ca"},
		NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(time.Hour),
		IsCA: true, BasicConstraintsValid: true, KeyUsage: x509.KeyUsageCertSign,
	}
	caDER, err := x509.CreateCertificate(rand.Reader, caTmpl, caTmpl, &caKey.PublicKey, caKey)
	if err != nil {
		t.Fatal(err)
	}
	caCert, _ := x509.ParseCertificate(caDER)
	leafKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	leafTmpl := &x509.Certificate{
		SerialNumber: big.NewInt(2), Subject: pkix.Name{CommonName: name},
		NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(time.Hour),
		DNSNames: []string{"localhost"}, IPAddresses: []net.IP{net.ParseIP("127.0.0.1")},
		KeyUsage:    x509.KeyUsageDigitalSignature,
		ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth, x509.ExtKeyUsageClientAuth},
	}
	leafDER, err := x509.CreateCertificate(rand.Reader, leafTmpl, caCert, &leafKey.PublicKey, caKey)
	if err != nil {
		t.Fatal(err)
	}
	keyDER, err := x509.MarshalECPrivateKey(leafKey)
	if err != nil {
		t.Fatal(err)
	}
	p := testCerts{cert: filepath.Join(dir, "tls.crt"), key: filepath.Join(dir, "tls.key"), caPath: filepath.Join(dir, "ca.crt")}
	writePEM(t, p.cert, "CERTIFICATE", leafDER)
	writePEM(t, p.key, "EC PRIVATE KEY", keyDER)
	writePEM(t, p.caPath, "CERTIFICATE", caDER)
	return p
}

func setMTLSEnv(t *testing.T, p testCerts) {
	t.Helper()
	t.Setenv(mtls.EnvCertFile, p.cert)
	t.Setenv(mtls.EnvKeyFile, p.key)
	t.Setenv(mtls.EnvCAFile, p.caPath)
}

func clearMTLSEnv(t *testing.T) {
	t.Helper()
	for _, k := range []string{mtls.EnvCertFile, mtls.EnvKeyFile, mtls.EnvCAFile} {
		t.Setenv(k, "")
	}
}

func TestMTLSFromEnv_Unset(t *testing.T) {
	clearMTLSEnv(t)
	p, err := MTLSFromEnv(nil)
	if err != nil || p != nil {
		t.Fatalf("unset: provider=%v err=%v, want nil, nil", p, err)
	}
}

func TestMTLSFromEnv_Partial(t *testing.T) {
	clearMTLSEnv(t)
	t.Setenv(mtls.EnvCertFile, "/nonexistent/tls.crt")
	if p, err := MTLSFromEnv(nil); err == nil || p != nil {
		t.Fatalf("partial: provider=%v err=%v, want an error", p, err)
	}
}

func TestMTLSFromEnv_Unreadable(t *testing.T) {
	clearMTLSEnv(t)
	t.Setenv(mtls.EnvCertFile, "/nonexistent/tls.crt")
	t.Setenv(mtls.EnvKeyFile, "/nonexistent/tls.key")
	t.Setenv(mtls.EnvCAFile, "/nonexistent/ca.crt")
	if _, err := MTLSFromEnv(nil); err == nil {
		t.Fatal("unreadable files: want an error")
	}
}

func TestRunWithHealth_MTLS(t *testing.T) {
	certs := newTestCerts(t, t.TempDir(), "sshbroker.example.org")
	setMTLSEnv(t, certs)
	prov, err := MTLSFromEnv(nil)
	if err != nil || prov == nil {
		t.Fatalf("MTLSFromEnv: %v %v", prov, err)
	}

	port := freePort(t)
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() { done <- RunWithHealth(ctx, port, nil, func(*grpc.Server) {}, prov.ServerOption()) }()
	t.Cleanup(func() {
		cancel()
		if err := <-done; err != nil {
			t.Errorf("run: %v", err)
		}
	})
	time.Sleep(200 * time.Millisecond)
	target := "localhost:" + port

	t.Run("client with a certificate is served", func(t *testing.T) {
		conn, err := grpc.NewClient(target, prov.DialOption())
		if err != nil {
			t.Fatal(err)
		}
		defer func() { _ = conn.Close() }()
		cctx, c := context.WithTimeout(ctx, 5*time.Second)
		defer c()
		resp, err := healthpb.NewHealthClient(conn).Check(cctx, &healthpb.HealthCheckRequest{})
		if err != nil || resp.GetStatus() != healthpb.HealthCheckResponse_SERVING {
			t.Fatalf("check: %v %v", resp, err)
		}
	})

	t.Run("client without a certificate is refused", func(t *testing.T) {
		pool := x509.NewCertPool()
		pem, _ := os.ReadFile(certs.caPath)
		pool.AppendCertsFromPEM(pem)
		creds := credentials.NewTLS(&tls.Config{RootCAs: pool, MinVersion: tls.VersionTLS13})
		conn, err := grpc.NewClient(target, grpc.WithTransportCredentials(creds))
		if err != nil {
			t.Fatal(err)
		}
		defer func() { _ = conn.Close() }()
		cctx, c := context.WithTimeout(ctx, 5*time.Second)
		defer c()
		if _, err := healthpb.NewHealthClient(conn).Check(cctx, &healthpb.HealthCheckRequest{}); err == nil {
			t.Fatal("a client with no certificate was served")
		}
	})

	t.Run("plaintext client is refused", func(t *testing.T) {
		conn, err := grpc.NewClient(target, grpc.WithTransportCredentials(insecure.NewCredentials()))
		if err != nil {
			t.Fatal(err)
		}
		defer func() { _ = conn.Close() }()
		cctx, c := context.WithTimeout(ctx, 5*time.Second)
		defer c()
		if _, err := healthpb.NewHealthClient(conn).Check(cctx, &healthpb.HealthCheckRequest{}); err == nil {
			t.Fatal("a plaintext client was served")
		}
	})
}

func TestRunPlainHealth_ServesHealthOnly(t *testing.T) {
	port := freePort(t)
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() { done <- RunPlainHealth(ctx, port, nil) }()
	t.Cleanup(func() {
		cancel()
		if err := <-done; err != nil {
			t.Errorf("run: %v", err)
		}
	})
	time.Sleep(200 * time.Millisecond)

	conn, err := grpc.NewClient("127.0.0.1:"+port, grpc.WithTransportCredentials(insecure.NewCredentials()))
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = conn.Close() }()
	cctx, c := context.WithTimeout(ctx, 5*time.Second)
	defer c()
	hc := healthpb.NewHealthClient(conn)
	for _, svc := range []string{"", LivenessService} {
		resp, err := hc.Check(cctx, &healthpb.HealthCheckRequest{Service: svc})
		if err != nil || resp.GetStatus() != healthpb.HealthCheckResponse_SERVING {
			t.Fatalf("check %q: %v %v", svc, resp, err)
		}
	}
	// Nothing but health: a call to any other method is unimplemented.
	err = conn.Invoke(cctx, "/sneakers.sshbroker.v1.SSHBrokerService/CreateSession", &healthpb.HealthCheckRequest{}, &healthpb.HealthCheckResponse{})
	if status.Code(err) != codes.Unimplemented {
		t.Fatalf("other method: code %v, want Unimplemented", status.Code(err))
	}
}
