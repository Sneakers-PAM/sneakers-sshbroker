// Copyright 2026 The Sneakers-PAM Authors
// SPDX-License-Identifier: Apache-2.0

package main

import (
	"testing"

	goredis "github.com/redis/go-redis/v9"
)

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

// TestRedisOptionsFromHonoursTLS covers #23: a rediss:// REDIS_URL (or any
// TLSConfig go-redis's ParseURL populates) must reach the Redis client as a
// TLS option, not be silently dropped to a plaintext connection.
func TestRedisOptionsFromHonoursTLS(t *testing.T) {
	plain, err := goredis.ParseURL("redis://:secret@cache.example.org:6379/2")
	if err != nil {
		t.Fatalf("ParseURL: %v", err)
	}
	plainOpts, err := redisOptionsFrom(plain)
	if err != nil {
		t.Fatalf("redisOptionsFrom(plain): %v", err)
	}

	tlsOpt, err := goredis.ParseURL("rediss://:secret@cache.example.org:6379/2")
	if err != nil {
		t.Fatalf("ParseURL: %v", err)
	}
	tlsOpts, err := redisOptionsFrom(tlsOpt)
	if err != nil {
		t.Fatalf("redisOptionsFrom(tls): %v", err)
	}

	if len(tlsOpts) != len(plainOpts)+1 {
		t.Fatalf("rediss:// produced %d options, plain produced %d; want exactly one more (TLS)", len(tlsOpts), len(plainOpts))
	}
}

// TestRedisOptionsFromRefusesUsername covers #23: REDIS_URL carrying a
// username has no WithUsername counterpart in the go-redis helper, so it
// must be refused rather than silently connecting as the wrong identity.
func TestRedisOptionsFromRefusesUsername(t *testing.T) {
	opt, err := goredis.ParseURL("redis://alice:secret@cache.example.org:6379/0")
	if err != nil {
		t.Fatalf("ParseURL: %v", err)
	}
	if _, err := redisOptionsFrom(opt); err == nil {
		t.Fatal("expected redisOptionsFrom to refuse a username")
	}
}
