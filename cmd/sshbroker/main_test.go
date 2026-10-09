// Copyright 2026 The Sneakers-PAM Authors
// SPDX-License-Identifier: Apache-2.0

package main

import "testing"

func envOf(m map[string]string) func(string) string {
	return func(k string) string { return m[k] }
}

// TestOTLPEndpointUnsetStaysEmpty covers #29: an unset or empty
// OTEL_EXPORTER_OTLP_ENDPOINT must reach go-otel's Init as "", which it
// treats as export-off, not as a localhost:4317 default nothing is
// listening on.
func TestOTLPEndpointUnsetStaysEmpty(t *testing.T) {
	if got := otlpEndpoint(envOf(map[string]string{})); got != "" {
		t.Errorf("otlpEndpoint with nothing set: got %q, want empty", got)
	}
	if got := otlpEndpoint(envOf(map[string]string{"OTHER_VAR": "x"})); got != "" {
		t.Errorf("otlpEndpoint with an unrelated var set: got %q, want empty", got)
	}
	if got := otlpEndpoint(envOf(map[string]string{"OTEL_EXPORTER_OTLP_ENDPOINT": "collector:4317"})); got != "collector:4317" {
		t.Errorf("otlpEndpoint passthrough: got %q, want %q", got, "collector:4317")
	}
}
