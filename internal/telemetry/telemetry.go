// Copyright 2026 The Sneakers-PAM Authors
// SPDX-License-Identifier: Apache-2.0

// Package telemetry holds the broker's OTLP settings: the environment
// switches, the log export filters, the logger output, the handler for
// export errors and the optional otlp health dependency.
package telemetry

import (
	"context"
	"errors"
	"io"
	"os"
	"regexp"

	"github.com/Bugs5382/go-buildinfo/health"
	log "github.com/Bugs5382/go-log"
	otel "github.com/Bugs5382/go-otel"
	"github.com/rs/zerolog"
	sdkotel "go.opentelemetry.io/otel"
	"google.golang.org/grpc/status"
)

const (
	// EnvInsecureSkipVerify turns off collector certificate validation when
	// it is exactly "true".
	EnvInsecureSkipVerify = "OTLP_INSECURE_SKIP_VERIFY"
	// EnvLogsEnabled turns on log export when it is exactly "true".
	EnvLogsEnabled = "OTLP_LOGS_ENABLED"
	// DependencyName is the name of the optional health dependency.
	DependencyName = "otlp"
)

// allowedLogFields are the only fields, beyond time, level, service and
// message, a log record may carry to a collector. A new log field exports
// nothing until it is added here. Keep this list to ids, counts, durations,
// classes, states and short enums.
var allowedLogFields = []string{
	"trace_id", "span_id",
	"actor_user_id", "target_id", "secret_id",
	"attempt", "attempts", "keys", "kept_keys", "pinned_keys",
	"took", "retry_in", "elapsed", "duration", "step_ms", "elapsed_ms", "duration_ms",
	"step", "outcome", "error_class", "code", "action", "principal_kind", "reference",
	"dependency", "required", "from", "to", "method", "caller",
	"error", "reason",
}

// classOnlyLogFields can hold a target system's own text, which can echo a
// credential, so they export as "[string]" and never as text. "step",
// "outcome" and "error_class" carry the stable class instead.
var classOnlyLogFields = []string{"error", "reason"}

// tokenPattern matches a Sneakers API token wherever it appears.
var tokenPattern = regexp.MustCompile(`\bsnk_[A-Za-z0-9_\-]+`)

// Options are the go-otel options the environment selects. The log filters
// are always set, so turning logs on can never run without them.
func Options(getenv func(string) string) []otel.Option {
	return []otel.Option{
		otel.WithInsecureSkipVerify(getenv(EnvInsecureSkipVerify) == "true"),
		otel.WithLogs(getenv(EnvLogsEnabled) == "true"),
		otel.WithLogAllowFields(allowedLogFields...),
		otel.WithLogClassOnlyFields(classOnlyLogFields...),
		otel.WithLogRedactPatterns(tokenPattern),
	}
}

// Output is what a logger writes to: stdout, plus the OTLP log writer when
// logs are on. The writer needs JSON lines, so LOG_FORMAT=console exports
// nothing.
func Output(getenv func(string) string) io.Writer {
	if getenv(EnvLogsEnabled) != "true" {
		return os.Stdout
	}
	return io.MultiWriter(os.Stdout, otel.LogWriter())
}

// NewLogger is go-log's NewLogger with Output.
func NewLogger(service string) log.Logger {
	return log.NewLoggerWithOptions(service, log.WithOutput(Output(os.Getenv)))
}

// New is go-log's New with Output. go-log's New takes no options, and Ctx with
// no span hands back the logger NewLoggerWithOptions just built.
func New(service string) zerolog.Logger {
	NewLogger(service)
	return log.Ctx(context.Background()) //nolint:staticcheck // the logger built on the line above
}

// HandleExportErrors sends the OTLP SDK's errors to lg in place of the default
// raw lines on stderr. Only the gRPC code is logged: the error text can name
// the endpoint and its headers. With no endpoint nothing changes.
func HandleExportErrors(endpoint string, lg log.Logger) {
	if endpoint == "" {
		return
	}
	sdkotel.SetErrorHandler(sdkotel.ErrorHandlerFunc(func(err error) {
		lg.Warn("otlp export failed", log.F("error_class", status.Code(err).String()))
	}))
}

// errExportFailing is the otlp dependency's error. It carries no export error
// text, because the health report leaves the process.
var errExportFailing = errors.New("otlp export failing")

// Dependencies is the optional otlp health dependency, present only with an
// endpoint. Required stays false, so export trouble never fails readiness.
func Dependencies(endpoint string, getenv func(string) string) []health.Dependency {
	if endpoint == "" {
		return nil
	}
	logsOn := getenv(EnvLogsEnabled) == "true"
	return []health.Dependency{{
		Name: DependencyName,
		Check: func(context.Context) error {
			s := otel.ExportState()
			if failing(s.Traces) || failing(s.Metrics) || (logsOn && s.Logs.Disabled == "" && failing(s.Logs)) {
				return errExportFailing
			}
			return nil
		},
	}}
}

func failing(s otel.SignalStatus) bool {
	return s.LastErrorAt.After(s.LastSuccess)
}
