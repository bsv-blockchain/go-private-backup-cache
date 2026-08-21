// Command server runs the private backup cache.
//
// An append-only, zero-knowledge store for encrypted wallet-backup blobs. Clients
// authenticate with BRC-103/104 under a pseudonym derived from their wallet seed, and the
// blobs arrive encrypted to that same seed. This process holds no key that can read them.
package main

import (
	"context"
	"errors"
	"log/slog"
	"net/http"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/joho/godotenv"

	"github.com/bsv-blockchain/go-private-backup-cache/internal/blobstore"
	"github.com/bsv-blockchain/go-private-backup-cache/internal/config"
	"github.com/bsv-blockchain/go-private-backup-cache/internal/logger"
	"github.com/bsv-blockchain/go-private-backup-cache/internal/nonce"
	otelsetup "github.com/bsv-blockchain/go-private-backup-cache/internal/otel"
	"github.com/bsv-blockchain/go-private-backup-cache/internal/server"
	walletpkg "github.com/bsv-blockchain/go-private-backup-cache/internal/wallet"
)

func main() {
	_ = godotenv.Load()

	cfg, err := config.Load()
	if err != nil {
		slog.Error("failed to load config", "error", err)
		os.Exit(1)
	}
	log := logger.Configure(cfg.LogLevel, cfg.LogFormat)

	otelShutdown, err := otelsetup.Setup(context.Background(), cfg.OTelEndpoint, "private-backup-cache")
	if err != nil {
		log.Error("failed to set up telemetry", "error", err)
		os.Exit(1)
	}
	if cfg.OTelEndpoint != "" {
		log.Info("telemetry export enabled", "endpoint", cfg.OTelEndpoint)
	}

	srvWallet, err := walletpkg.NewServerIdentity(cfg.ServerPrivateKey)
	if err != nil {
		log.Error("failed to build server identity", "error", err)
		os.Exit(1)
	}

	store, nonces, closeStore, err := openStore(cfg, log)
	if err != nil {
		log.Error("failed to open store", "error", err)
		os.Exit(1)
	}
	defer closeStore()

	srv, err := server.New(server.Deps{
		Wallet:       srvWallet,
		Store:        store,
		Nonces:       nonces,
		Logger:       log,
		MaxBlobBytes: cfg.MaxBlobBytes,
		Port:         cfg.Port,
	})
	if err != nil {
		log.Error("failed to build server", "error", err)
		os.Exit(1)
	}

	go func() {
		log.Info("listening", "port", cfg.Port, "maxBlobBytes", cfg.MaxBlobBytes)
		if err := srv.ListenAndServe(); err != nil && !errors.Is(err, http.ErrServerClosed) {
			log.Error("server failed", "error", err)
			os.Exit(1)
		}
	}()

	stop := make(chan os.Signal, 1)
	signal.Notify(stop, os.Interrupt, syscall.SIGTERM)
	<-stop

	log.Info("shutting down")
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()
	if err := srv.Shutdown(ctx); err != nil {
		log.Error("graceful shutdown failed", "error", err)
	}
	if err := otelShutdown(ctx); err != nil {
		log.Error("telemetry flush failed", "error", err)
	}
}

// openStore selects the backing store.
//
// Without DATABASE_URL the service runs on in-memory stores. That is useful for local
// development and integration tests, and it is announced loudly because everything is lost
// on restart — which for a backup service would be a bad surprise in production. The nonce
// store rides the same switch: replay protection must live in the shared database once
// there is one, or two replicas would each accept the same proof.
func openStore(cfg *config.Config, log *slog.Logger) (blobstore.BlobStore, nonce.Store, func(), error) {
	if cfg.DatabaseURL == "" {
		log.Warn("DATABASE_URL is not set — using an in-memory store; ALL DATA IS LOST ON RESTART")
		return blobstore.WithTracing(blobstore.NewMemoryStore()), nonce.NewMemoryStore(), func() {}, nil
	}

	pg, err := blobstore.NewPostgresStore(cfg.DatabaseURL)
	if err != nil {
		return nil, nil, nil, err
	}
	nonces, err := nonce.NewPostgresStore(pg.DB())
	if err != nil {
		return nil, nil, nil, err
	}
	return blobstore.WithTracing(pg), nonces, func() {
		if cerr := pg.Close(); cerr != nil {
			log.Error("failed to close store", "error", cerr)
		}
	}, nil
}
