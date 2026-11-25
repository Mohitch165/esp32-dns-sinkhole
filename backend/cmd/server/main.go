package main

import (
	"context"
	"errors"
	"log/slog"
	"net/http"
	"os"
	"os/signal"
	"path/filepath"
	"strings"
	"syscall"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"

	"local/esp32-sinkhole/backend/internal/api"
	"local/esp32-sinkhole/backend/internal/store"
)

func main() {
	logger := slog.New(slog.NewJSONHandler(os.Stdout, nil))
	databaseURL := strings.TrimSpace(os.Getenv("DATABASE_URL"))
	apiToken := strings.TrimSpace(os.Getenv("DEVICE_API_TOKEN"))
	listenAddr := strings.TrimSpace(os.Getenv("LISTEN_ADDR"))
	certFile := strings.TrimSpace(os.Getenv("TLS_CERT_FILE"))
	keyFile := strings.TrimSpace(os.Getenv("TLS_KEY_FILE"))
	blocklistDir := strings.TrimSpace(os.Getenv("BLOCKLIST_UPDATE_DIR"))
	if blocklistDir == "" {
		blocklistDir = filepath.Join("..", "outputs", "runtime", "blocklist-ota")
	}
	if listenAddr == "" {
		listenAddr = "127.0.0.1:8443"
	}
	if databaseURL == "" || len(apiToken) < 32 || certFile == "" || keyFile == "" {
		logger.Error("required configuration missing", "required", "DATABASE_URL, DEVICE_API_TOKEN (32+ characters), TLS_CERT_FILE, TLS_KEY_FILE")
		os.Exit(2)
	}

	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()

	pool, err := pgxpool.New(ctx, databaseURL)
	if err != nil {
		logger.Error("create postgres pool", "error", err)
		os.Exit(1)
	}
	defer pool.Close()

	startupCtx, cancel := context.WithTimeout(ctx, 10*time.Second)
	defer cancel()
	if err := pool.Ping(startupCtx); err != nil {
		logger.Error("connect to postgres", "error", err)
		os.Exit(1)
	}
	if err := store.Migrate(startupCtx, pool); err != nil {
		logger.Error("apply database schema", "error", err)
		os.Exit(1)
	}

	blocklistDir, err = filepath.Abs(blocklistDir)
	if err != nil {
		logger.Error("resolve blocklist update directory", "error", err)
		os.Exit(2)
	}
	service := api.NewServer(pool, apiToken, logger, blocklistDir)
	httpServer := &http.Server{
		Addr:              listenAddr,
		Handler:           service.Handler(),
		ReadHeaderTimeout: 5 * time.Second,
		ReadTimeout:       10 * time.Second,
		WriteTimeout:      15 * time.Second,
		IdleTimeout:       60 * time.Second,
		MaxHeaderBytes:    16 << 10,
		TLSConfig:         api.TLSConfig(),
	}

	serverErrors := make(chan error, 1)
	go func() {
		logger.Info("telemetry API listening with TLS", "address", listenAddr)
		serverErrors <- httpServer.ListenAndServeTLS(certFile, keyFile)
	}()

	select {
	case err := <-serverErrors:
		if !errors.Is(err, http.ErrServerClosed) {
			logger.Error("HTTP server stopped", "error", err)
			os.Exit(1)
		}
	case <-ctx.Done():
		shutdownCtx, shutdownCancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer shutdownCancel()
		if err := httpServer.Shutdown(shutdownCtx); err != nil {
			logger.Error("graceful shutdown failed", "error", err)
			_ = httpServer.Close()
		}
	}
}
