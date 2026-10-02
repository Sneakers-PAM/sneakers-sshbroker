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

// newSharedStore builds the shared, Redis-backed reference ticket store, or
// returns nil (degrading to single-replica in-memory) if REDIS_URL is unset,
// malformed, or the server is unreachable. Redis is best-effort here: the
// broker must still boot and serve single-replica when Redis is down, so any
// failure is logged once as a warning rather than being fatal.
//
// Note the returned *bredis.Client's own Close is not wired to a defer: the
// process holds the shared store for its whole lifetime, and letting it go with
// the process is fine for a best-effort dependency.
func newSharedStore(ctx context.Context) session.TicketStore {
	logger := log.New(serviceName)

	redisURL := os.Getenv("REDIS_URL")
	if redisURL == "" {
		logger.Warn().Msg("REDIS_URL unset; sshbroker ticket store is in-memory only (single-replica)")
		return nil
	}

	opt, err := goredis.ParseURL(redisURL)
	if err != nil {
		logger.Warn().Err(err).Msg("REDIS_URL invalid; sshbroker ticket store is in-memory only (single-replica)")
		return nil
	}

	dctx, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()
	ropts := []bredis.Option{bredis.WithAddr(opt.Addr), bredis.WithDB(opt.DB)}
	if opt.Password != "" {
		ropts = append(ropts, bredis.WithPassword(opt.Password))
	}
	rc, err := bredis.Connect(dctx, ropts...)
	if err != nil {
		logger.Warn().Err(err).Msg("redis unreachable; sshbroker ticket store is in-memory only (single-replica)")
		return nil
	}

	logger.Info().Str("addr", opt.Addr).Msg("shared redis ticket store enabled (HA)")
	return session.NewRedisStore(rc)
}

func main() {
	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer stop()

	logger := log.New(serviceName)
	grpcPort := env("GRPC_PORT", "9096")
	httpPort := env("HTTP_PORT", "9097")

	otelShutdown, err := otel.Init(ctx, serviceName, env("OTEL_EXPORTER_OTLP_ENDPOINT", "localhost:4317"))
	if err != nil {
		logger.Fatal().Err(err).Msg("otel init")
	}
	defer func() {
		if err := otelShutdown(context.Background()); err != nil {
			logger.Warn().Err(err).Msg("otel shutdown")
		}
	}()

	// Ticket store. The pod-local in-memory store always exists (it holds
	// inline-key sessions and is the fallback when Redis is absent). When
	// REDIS_URL points at a reachable Redis, a shared reference store is added
	// so >1 replica can redeem each other's reference tickets (HA).
	// Redis is best-effort: an unreachable server degrades to single-replica
	// (in-memory) with a single warning rather than failing to boot.
	local := session.NewStore()
	defer local.Close()
	store := session.NewComposite(local, newSharedStore(ctx))
	defer store.Close()

	auditAddr := env("AUDIT_ADDR", "localhost:9194")
	auditConn, err := grpc.NewClient(auditAddr, grpc.WithTransportCredentials(insecure.NewCredentials()), server.ClientStatsHandler())
	if err != nil {
		logger.Fatal().Err(err).Str("audit", auditAddr).Msg("dial audit")
	}
	defer func() { _ = auditConn.Close() }()
	auditEmitter := audit.New(auditv1.NewAuditServiceClient(auditConn))

	// Vault client for the reference path: the redeeming pod reveals the SSH key
	// from the vault (RevealSecretField, audited) with the ticket's actor at
	// connect time, so key material is never carried in the shared ticket store.
	vaultAddr := env("VAULT_ADDR", "localhost:9091")
	vaultConn, err := grpc.NewClient(vaultAddr, grpc.WithTransportCredentials(insecure.NewCredentials()), server.ClientStatsHandler())
	if err != nil {
		logger.Fatal().Err(err).Str("vault", vaultAddr).Msg("dial vault")
	}
	defer func() { _ = vaultConn.Close() }()
	keyFetcher := vault.New(vaultv1.NewVaultServiceClient(vaultConn))

	wsBase := env("SSHBROKER_PUBLIC_WS_URL", "ws://localhost:9097/ssh/session")

	// HTTP server: health check plus the WS session endpoint, sharing the
	// same store instance as the gRPC CreateSession call.
	mux := http.NewServeMux()
	mux.HandleFunc("/health", func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte("ok"))
	})
	// Serve the WS endpoint at both the bare path (dev/local defaults) and the
	// protocol-namespaced path. An ingress that routes /proto to this service
	// WITHOUT stripping the prefix delivers a browser connecting to
	// SSHBROKER_PUBLIC_WS_URL (…/proto/ssh/session) here as
	// /proto/ssh/session; register both so either edge works.
	wsHandler := wsproxy.Handler(store, auditEmitter, keyFetcher)
	mux.HandleFunc("/ssh/session", wsHandler)
	mux.HandleFunc("/proto/ssh/session", wsHandler)
	httpSrv := &http.Server{Addr: ":" + httpPort, Handler: mux, ReadHeaderTimeout: 5 * time.Second}
	go func() {
		logger.Info().Str("http", httpPort).Msg("ws http listening")
		if err := httpSrv.ListenAndServe(); err != nil && !errors.Is(err, http.ErrServerClosed) {
			logger.Error().Err(err).Msg("http server")
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
	if err := server.Run(ctx, grpcPort, func(gs *grpc.Server) {
		grpcsvc.RegisterServer(gs, broker)
	}); err != nil {
		logger.Fatal().Err(err).Msg("server exited")
	}
}
