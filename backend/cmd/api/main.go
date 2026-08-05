// Command api is the entry point for the United Pass API service. Phase 0
// scaffold: loads typed configuration, sets up structured logging, starts an
// http.Server with configured timeouts and a minimal health endpoint, and
// performs graceful shutdown on operating-system signals. The Chi router,
// middleware and full HTTP adapter layer are introduced in the next commit.
package main

import (
	"context"
	"errors"
	"log/slog"
	"net/http"
	"os"
	"os/signal"
	"syscall"

	"github.com/GravelEvolution/united-pass/backend/internal/config"
	"github.com/GravelEvolution/united-pass/backend/internal/platform/observability"
)

func main() {
	if err := run(); err != nil {
		os.Exit(1)
	}
}

func run() error {
	cfg, err := config.Load()
	if err != nil {
		slog.New(slog.NewTextHandler(os.Stderr, nil)).Error("configuration invalid", "error", err)
		return err
	}

	level, err := cfg.LogLevelValue()
	if err != nil {
		slog.New(slog.NewTextHandler(os.Stderr, nil)).Error("log level invalid", "error", err)
		return err
	}
	logger := observability.NewLogger(level, string(cfg.Environment), os.Stdout)

	mux := http.NewServeMux()
	mux.HandleFunc("/healthz", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json; charset=utf-8")
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte(`{"status":"ok"}`))
	})

	srv := &http.Server{
		Addr:              cfg.HTTPAddr,
		Handler:           mux,
		ReadHeaderTimeout: cfg.ReadHeaderTimeout,
		ReadTimeout:       cfg.ReadTimeout,
		WriteTimeout:      cfg.WriteTimeout,
		IdleTimeout:       cfg.IdleTimeout,
	}

	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer stop()

	serveErr := make(chan error, 1)
	go func() {
		logger.Info("http server starting", "addr", cfg.HTTPAddr, "environment", string(cfg.Environment))
		if err := srv.ListenAndServe(); err != nil && !errors.Is(err, http.ErrServerClosed) {
			serveErr <- err
		}
	}()

	select {
	case err := <-serveErr:
		logger.Error("http server stopped unexpectedly", "error", err)
		return err
	case <-ctx.Done():
		logger.Info("shutdown signal received")
		stop()
	}

	shutdownCtx, cancel := context.WithTimeout(context.Background(), cfg.ShutdownTimeout)
	defer cancel()
	if err := srv.Shutdown(shutdownCtx); err != nil && !errors.Is(err, http.ErrServerClosed) {
		logger.Error("graceful shutdown failed", "error", err)
		return err
	}
	logger.Info("http server stopped")
	return nil
}
