// Copyright 2026 The Sneakers-PAM Authors
// SPDX-License-Identifier: Apache-2.0

package grpcsvc

import (
	"testing"

	sshbrokerv1 "github.com/Sneakers-PAM/sneakers-sshbroker/gen/go/sneakers/sshbroker/v1"
	"github.com/Sneakers-PAM/sneakers-sshbroker/internal/workloadauth"
)

// TestCallerPolicy: only the gateway may call CreateSession, on behalf of the
// signed-in user. No other service, and never the MCP server, is listed.
func TestCallerPolicy(t *testing.T) {
	p := CallerPolicy()
	m := sshbrokerv1.SSHBrokerService_CreateSession_FullMethodName

	if a, ok := p.Lookup(m, "gateway"); !ok || a != workloadauth.OnBehalf {
		t.Fatalf("gateway on CreateSession = %v, %v; want on-behalf", a, ok)
	}
	for _, c := range []string{"mcp", "vault", "workflow", "connector", "notify", "identity", "audit", "sshbroker", "web"} {
		if a, ok := p.Lookup(m, c); ok {
			t.Fatalf("%s may call CreateSession (%v); only the gateway may", c, a)
		}
	}
	for _, md := range sshbrokerv1.SSHBrokerService_ServiceDesc.Methods {
		full := "/" + sshbrokerv1.SSHBrokerService_ServiceDesc.ServiceName + "/" + md.MethodName
		if len(p[full]) != 1 {
			t.Fatalf("%s: want exactly one caller (gateway), got %v", full, p[full])
		}
	}
	if len(p) != len(sshbrokerv1.SSHBrokerService_ServiceDesc.Methods) {
		t.Fatalf("policy has %d methods, the service %d", len(p), len(sshbrokerv1.SSHBrokerService_ServiceDesc.Methods))
	}
}
