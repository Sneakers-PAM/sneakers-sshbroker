// Copyright 2026 The Sneakers-PAM Authors
// SPDX-License-Identifier: Apache-2.0

package main

import (
	"context"
	"errors"
	"net/http"
	"os"
	"os/signal"
	"syscall"
	"time"

	log "github.com/Bugs5382/go-log"
	otel "github.com/Bugs5382/go-otel"
	bredis "github.com/Bugs5382/go-redis"
	auditv1 "github.com/Sneakers-PAM/sneakers-sshbroker/gen/go/thirdparty/audit/v1"
	vaultv1 "github.com/Sneakers-PAM/sneakers-sshbroker/gen/go/thirdparty/vault/v1"
	goredis "github.com/redis/go-redis/v9"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials/insecure"
	healthpb "google.golang.org/grpc/health/grpc_health_v1"

	workloadauth "github.com/Bugs5382/go-workload-identity"
	"github.com/Sneakers-PAM/sneakers-sshbroker/internal/audit"
	"github.com/Sneakers-PAM/sneakers-sshbroker/internal/grpcsvc"
	"github.com/Sneakers-PAM/sneakers-sshbroker/internal/server"
	"github.com/Sneakers-PAM/sneakers-sshbroker/internal/session"
	"github.com/Sneakers-PAM/sneakers-sshbroker/internal/vault"
	"github.com/Sneakers-PAM/sneakers-sshbroker/internal/wsproxy"
)

const serviceName = "sshbroker"

func env(k, def string) string {
	if v := os.Getenv(k); v != "" {
		return v
	}
	return def
}

// otlpEndpoint reads OTEL_EXPORTER_OTLP_ENDPOINT with no default: unset or
// empty means no collector, which go-otel's Init treats as export-off
// (local-only providers, no exporter, no periodic export errors).
func otlpEndpoint(getenv func(string) string) string {
	return getenv("OTEL_EXPORTER_OTLP_ENDPOINT")
}

// redisOptionsFrom turns a parsed REDIS_URL into bredis.Options, honouring
// every field go-redis's ParseURL populates that bredis can express:
// address, DB, password and TLS (rediss://, or the sentinel/cluster
// variants' tls query params). Username has no WithUsername counterpart in
// go-redis (the owner's helper package), so rather than silently drop it
// and connect with the wrong identity, an error is returned instead.
func redisOptionsFrom(opt *goredis.Options) ([]bredis.Option, error) {
	if opt.Username != "" {
		return nil, errors.New("REDIS_URL sets a username, which this broker can't honour")
	}
	ropts := []bredis.Option{bredis.WithAddr(opt.Addr), bredis.WithDB(opt.DB)}
	if opt.Password != "" {
		ropts = append(ropts, bredis.WithPassword(opt.Password))
	}
	if opt.TLSConfig != nil {
		ropts = append(ropts, bredis.WithTLS(opt.TLSConfig))
	}
	return ropts, nil
}

// newTicketStore builds the ticket store from REDIS_URL.
//
//   - Unset: in-memory tickets only, so run one replica. The broker is ready
//     at once.
//   - Set: every reference ticket goes to Redis, never to memory. If Redis
//     isn't answering yet the broker keeps trying in the background and stays
//     not ready (readiness follows the valkey dependency; CreateSession
//     answers Unavailable) until it does, so no replica mints a ticket the
//     others can't redeem.
//   - Malformed: the start fails, so a typo can't quietly split the replicas.
//
// The *bredis.Client is never closed: the process holds it for its lifetime.
func newTicketStore(ctx context.Context, local *session.Store, onReady func()) *session.Composite {
	logger := log.New(serviceName)

	redisURL := os.Getenv("REDIS_URL")
	if redisURL == "" {
		logger.Warn().Msg("REDIS_URL unset; sshbroker ticket store is in-memory only (single-replica)")
		onReady()
		return session.NewComposite(local, nil)
	}

	opt, err := goredis.ParseURL(redisURL)
	if err != nil {
		logger.Fatal().Err(err).Msg("REDIS_URL invalid")
	}
	ropts, err := redisOptionsFrom(opt)
	if err != nil {
		logger.Fatal().Err(err).Msg("REDIS_URL option unsupported")
	}
	connect := func(ctx context.Context) (session.TicketStore, error) {
		dctx, cancel := context.WithTimeout(ctx, 5*time.Second)
		defer cancel()
		rc, err := bredis.Connect(dctx, ropts...)
		if err != nil {
			return nil, err
		}
		return session.NewRedisStore(rc), nil
	}

	store := session.NewRequiredComposite(local)
	logger.Info().Str("addr", opt.Addr).Msg("REDIS_URL set; reference tickets use the shared redis store only")
	go func() {
		if err := store.ConnectShared(ctx, connect, session.DefaultBackoff); err == nil {
			onReady()
		}
	}()
	return store
}

// allowedOrigins reads SSHBROKER_ALLOWED_ORIGINS, or when it's unset, the
// origin of the public WebSocket URL (the UI served from the same host). A
// malformed value stops the start.
func allowedOrigins(wsBase string) []string {
	logger := log.New(serviceName)
	if raw := os.Getenv("SSHBROKER_ALLOWED_ORIGINS"); raw != "" {
		origins, err := wsproxy.ParseOrigins(raw)
		if err != nil {
			logger.Fatal().Err(err).Msg("SSHBROKER_ALLOWED_ORIGINS invalid")
		}
		return origins
	}
	origin, err := wsproxy.OriginFromWSURL(wsBase)
	if err != nil {
		logger.Fatal().Err(err).Msg("SSHBROKER_ALLOWED_ORIGINS unset and SSHBROKER_PUBLIC_WS_URL has no usable origin")
	}
	return []string{origin}
}

// callerDialOptions are the options for the broker's own calls (vault and
// audit): plaintext, traced, and carrying the broker's workload token from
// WORKLOAD_TOKEN_FILE when it is set. A set path that can't be read stops the
// start.
func callerDialOptions() []grpc.DialOption {
	logger := log.New(serviceName)
	opts := []grpc.DialOption{grpc.WithTransportCredentials(insecure.NewCredentials()), server.ClientStatsHandler()}
	tok, ok, err := workloadauth.DialOptionFromEnv(os.Getenv)
	if err != nil {
		logger.Fatal().Err(err).Msg("workload token")
	}
	if !ok {
		logger.Warn().Msg(workloadauth.EnvTokenFile + " unset; calls to the vault and audit carry no workload token")
		return opts
	}
	logger.Info().Msg("calls to the vault and audit carry the workload token")
	return append(opts, tok)
}

// workloadAuth returns the verifier it built (nil when authentication is
// disabled, for readiness) and the gRPC server options that check each
// caller's workload token against grpcsvc.CallerPolicy (only the gateway may
// call CreateSession). It fails closed: with no WORKLOAD_OIDC_ISSUER the
// start fails unless WORKLOAD_AUTH=disabled, which trusts every caller and is
// for local development only.
func workloadAuth(ctx context.Context, aud *audit.Emitter) (*workloadauth.Verifier, []grpc.ServerOption) {
	logger := log.New(serviceName)
	lg := log.NewLogger(serviceName)
	cfg, enabled, err := server.WorkloadConfigFromEnv(os.Getenv)
	if err != nil {
		logger.Fatal().Err(err).Msg("workload authentication")
	}
	if !enabled {
		go workloadauth.WarnDisabled(ctx, lg, workloadauth.DisabledWarnInterval)
		return nil, nil
	}
	v, err := workloadauth.NewVerifier(cfg, lg)
	if err != nil {
		logger.Fatal().Err(err).Msg("workload verifier")
	}
	go v.Run(ctx)
	logger.Info().Str("issuer", cfg.Issuer).Strs("allowed", cfg.AllowedServiceAccounts).
		Msg("workload authentication on; CreateSession takes the gateway only")
	return v, grpcsvc.AuthServerOptions(v, aud, lg)
}

func main() {
	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer stop()

	logger := log.New(serviceName)
	grpcPort := env("GRPC_PORT", "9096")
	httpPort := env("HTTP_PORT", "9097")

	otelShutdown, err := otel.Init(ctx, serviceName, otlpEndpoint(os.Getenv))
	if err != nil {
		logger.Fatal().Err(err).Msg("otel init")
	}
	defer func() {
		if err := otelShutdown(context.Background()); err != nil {
			logger.Warn().Err(err).Msg("otel shutdown")
		}
	}()

	onReady := func() { logger.Info().Msg("sshbroker ticket store ready") }

	// Ticket store. The pod-local in-memory store always exists (it holds
	// inline-key sessions, and every ticket when REDIS_URL is unset). With
	// REDIS_URL set, reference tickets go to Redis only, so any replica can
	// redeem them (HA).
	local := session.NewStore()
	defer local.Close()
	store := newTicketStore(ctx, local, onReady)
	defer store.Close()

	dialOpts := callerDialOptions()

	auditAddr := env("AUDIT_ADDR", "localhost:9194")
	auditConn, err := grpc.NewClient(auditAddr, dialOpts...)
	if err != nil {
		logger.Fatal().Err(err).Str("audit", auditAddr).Msg("dial audit")
	}
	defer func() { _ = auditConn.Close() }()
	auditEmitter := audit.New(auditv1.NewAuditServiceClient(auditConn))

	// Built before the checker so a non-nil verifier can be followed by
	// readiness too; the options are reused when the server starts.
	workloadVerifier, authOpts := workloadAuth(ctx, auditEmitter)

	// Vault client for the reference path: the redeeming pod reveals the SSH key
	// from the vault (RevealSecretField, audited) with the ticket's actor at
	// connect time, so key material is never carried in the shared ticket store.
	vaultAddr := env("VAULT_ADDR", "localhost:9091")
	vaultConn, err := grpc.NewClient(vaultAddr, dialOpts...)
	if err != nil {
		logger.Fatal().Err(err).Str("vault", vaultAddr).Msg("dial vault")
	}
	defer func() { _ = vaultConn.Close() }()
	keyFetcher := vault.New(vaultv1.NewVaultServiceClient(vaultConn))

	// Readiness: the gRPC health check (service "") and /readyz follow these;
	// service "liveness" and /livez check the process only.
	checker, err := server.NewChecker(log.NewLogger(serviceName), readinessDeps(store, os.Getenv("REDIS_URL") != "",
		healthpb.NewHealthClient(vaultConn), healthpb.NewHealthClient(auditConn), workloadVerifier))
	if err != nil {
		logger.Fatal().Err(err).Msg("health checker")
	}

	wsBase := env("SSHBROKER_PUBLIC_WS_URL", "ws://localhost:9097/ssh/session")
	origins := allowedOrigins(wsBase)
	logger.Info().Strs("origins", origins).Msg("websocket origins allowed")

	// HTTP server: health check plus the WS session endpoint, sharing the
	// same store instance as the gRPC CreateSession call.
	mux := http.NewServeMux()
	if err := server.RegisterHTTPHealth(mux, checker); err != nil {
		logger.Fatal().Err(err).Msg("http health")
	}
	// Serve the WS endpoint at both the bare path (dev/local defaults) and the
	// protocol-namespaced path. An ingress that routes /proto to this service
	// WITHOUT stripping the prefix delivers a browser connecting to
	// SSHBROKER_PUBLIC_WS_URL (…/proto/ssh/session) here as
	// /proto/ssh/session; register both so either edge works.
	wsHandler := wsproxy.HandlerWithConfig(store, auditEmitter, keyFetcher, wsproxy.Config{AllowedOrigins: origins})
	mux.HandleFunc("/ssh/session", wsHandler)
	mux.HandleFunc("/proto/ssh/session", wsHandler)
	httpSrv := &http.Server{Addr: ":" + httpPort, Handler: mux, ReadHeaderTimeout: 5 * time.Second}
	go func() {
		logger.Info().Str("http", httpPort).Msg("ws http listening")
		if err := httpSrv.ListenAndServe(); err != nil && !errors.Is(err, http.ErrServerClosed) {
			// A failed listener (a bind error, for example) must not leave
			// the process running on gRPC alone: gRPC health checks would
			// keep passing while no WebSocket session could ever open.
			logger.Fatal().Err(err).Msg("http server")
		}
	}()
	go func() {
		<-ctx.Done()
		sctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer cancel()
		_ = httpSrv.Shutdown(sctx)
	}()

	broker := grpcsvc.NewBroker(store, auditEmitter, wsBase)

	logger.Info().Str("grpc", grpcPort).Msg("starting sshbroker")
	if err := server.RunWithHealth(ctx, grpcPort, checker, func(gs *grpc.Server) {
		grpcsvc.RegisterServer(gs, broker)
	}, authOpts...); err != nil {
		logger.Fatal().Err(err).Msg("server exited")
	}
}
