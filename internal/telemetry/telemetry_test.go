// Copyright 2026 The Sneakers-PAM Authors
// SPDX-License-Identifier: Apache-2.0

package telemetry_test

import (
	"bytes"
	"context"
	"errors"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/Bugs5382/go-buildinfo/health"
	log "github.com/Bugs5382/go-log"
	otel "github.com/Bugs5382/go-otel"
	"github.com/rs/zerolog"
	sdkotel "go.opentelemetry.io/otel"

	"github.com/Sneakers-PAM/sneakers-sshbroker/internal/server"
	"github.com/Sneakers-PAM/sneakers-sshbroker/internal/telemetry"
	"github.com/Sneakers-PAM/sneakers-sshbroker/internal/telemetry/collectortest"
)

func noEnv(string) string { return "" }

func logsOn(k string) string {
	if k == telemetry.EnvLogsEnabled {
		return "true"
	}
	return ""
}

func TestEndpointUnsetAddsNoDependency(t *testing.T) {
	if deps := telemetry.Dependencies("", noEnv); len(deps) != 0 {
		t.Fatalf("deps = %v, want none", deps)
	}
}

func TestEndpointSetAddsOptionalDependency(t *testing.T) {
	deps := telemetry.Dependencies("https://collector.example.org:4317", noEnv)
	if len(deps) != 1 || deps[0].Name != "otlp" || deps[0].Required {
		t.Fatalf("deps = %+v, want one optional otlp", deps)
	}
}

func TestSwitchesAcceptOnlyTrue(t *testing.T) {
	for _, v := range []string{"", "1", "TRUE", "yes"} {
		getenv := func(string) string { return v }
		c := collectortest.Start(t, false)
		shutdown, err := otel.InitWithOptions(context.Background(), "t", c.Endpoint, telemetry.Options(getenv)...)
		if err != nil {
			t.Fatal(err)
		}
		if got := otel.ExportState().Logs.Disabled; got == "" {
			t.Fatalf("logs on with %q", v)
		}
		_ = shutdown(context.Background())
	}
}

func TestFailingCollectorDegradesAndStaysReady(t *testing.T) {
	c := collectortest.Start(t, true)
	shutdown, err := otel.InitWithOptions(context.Background(), "t", c.Endpoint, telemetry.Options(noEnv)...)
	if err != nil {
		t.Fatal(err)
	}
	_, span := sdkotel.Tracer("t").Start(context.Background(), "s")
	span.End()
	_ = shutdown(context.Background())

	checker, err := server.NewChecker(log.Nop(), telemetry.Dependencies(c.Endpoint, noEnv), health.WithTTL(time.Millisecond))
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	go checker.Run(ctx)
	deadline := time.Now().Add(5 * time.Second)
	for {
		rep := checker.Report(ctx)
		if rep.Status == health.StateDegraded {
			if !rep.Ready {
				t.Fatalf("report = %+v, want ready", rep)
			}
			return
		}
		if time.Now().After(deadline) {
			t.Fatalf("report = %+v, want degraded", rep)
		}
		time.Sleep(10 * time.Millisecond)
	}
}

func TestLogFiltersKeepUnallowedAndTargetTextFromTheCollector(t *testing.T) {
	const canary = "CANARY-7f3a"
	c := collectortest.Start(t, false)
	shutdown, err := otel.InitWithOptions(context.Background(), "t", c.Endpoint, telemetry.Options(logsOn)...)
	if err != nil {
		t.Fatal(err)
	}
	l := zerolog.New(otel.LogWriter())
	l.Error().
		Str("unknown_field", canary).
		Str("host", canary).
		Str("error", "target said "+canary).
		Str("reason", canary).
		Str("step", "handshake").
		Str("target_id", "t-1").
		Str("actor_user_id", "snk_"+canary).
		Msg("marker")
	if err := shutdown(context.Background()); err != nil {
		t.Fatal(err)
	}
	got := c.Logs()
	if !strings.Contains(got, "marker") || !strings.Contains(got, "handshake") || !strings.Contains(got, "t-1") {
		t.Fatalf("expected record missing: %s", got)
	}
	if strings.Contains(got, canary) {
		t.Fatalf("canary reached the collector: %s", got)
	}
}

func TestLogsOffLeavesStdoutAlone(t *testing.T) {
	if w := telemetry.Output(noEnv); w != os.Stdout {
		t.Fatalf("output = %T, want stdout", w)
	}
}

func TestLoggerBuiltBeforeInitIsSafe(t *testing.T) {
	t.Setenv(telemetry.EnvLogsEnabled, "true")
	l := telemetry.New("t")
	l.Info().Msg("before init")
}

func TestExportErrorsLeaveOutTheirText(t *testing.T) {
	const secret = "collector.example.org:4317 authorization=abc"
	var buf bytes.Buffer
	telemetry.HandleExportErrors("https://collector.example.org:4317", log.NewLoggerWithOptions("t", log.WithOutput(&buf)))
	sdkotel.Handle(errors.New(secret))
	if !strings.Contains(buf.String(), "otlp export failed") {
		t.Fatalf("no line: %q", buf.String())
	}
	if strings.Contains(buf.String(), "authorization") || strings.Contains(buf.String(), "collector.example.org") {
		t.Fatalf("error text logged: %q", buf.String())
	}
}
