//
// Copyright (c) 2026 Chen Jiajie(Ariakage)
//
// Author: Chen Jiajie(Ariakage) <ariakage233@gmail.com>
// Date: 2026-08-05
// Description: API service entry point: loads configuration, assembles dependencies and starts the HTTP server
//

// Command api is the entry point for the United Pass API service. It loads
// configuration, constructs structured logging, builds the HTTP server, starts
// it, and performs graceful shutdown on operating-system signals. Business
// logic lives in internal packages; main only wires them together.
package main

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"net/http"
	"os"
	"os/signal"
	"syscall"

	"github.com/GravelEvolution/united-pass/backend/internal/bootstrap"
	"github.com/GravelEvolution/united-pass/backend/internal/config"
	"github.com/GravelEvolution/united-pass/backend/internal/platform/observability"
)

func main() {
	if len(os.Args) == 2 && os.Args[1] == "--build-info" {
		if err := writeBuildInformation(os.Stdout); err != nil {
			_, _ = fmt.Fprintln(os.Stderr, "build metadata invalid")
			os.Exit(1)
		}
		return
	}
	if err := run(); err != nil {
		os.Exit(1)
	}
}

func run() error {
	if err := loadLocalEnvironment(); err != nil {
		return err
	}
	cfg, err := config.Load()
	if err != nil {
		// Logging is not yet configured; write to stderr so startup failures
		// are visible before the structured logger exists.
		slog.New(slog.NewTextHandler(os.Stderr, nil)).Error("configuration invalid", "error", err)
		return err
	}
	if err := validateBuildInformation(string(cfg.Environment)); err != nil {
		slog.New(slog.NewTextHandler(os.Stderr, nil)).Error("build metadata invalid")
		return err
	}

	level, err := cfg.LogLevelValue()
	if err != nil {
		slog.New(slog.NewTextHandler(os.Stderr, nil)).Error("log level invalid", "error", err)
		return err
	}
	logger := observability.NewLogger(level, string(cfg.Environment), os.Stdout)

	server, err := bootstrap.NewServer(cfg, logger)
	if err != nil {
		logger.Error("server bootstrap failed", "error", err)
		return err
	}

	// Listen for termination signals. SIGINT (Ctrl-C) and SIGTERM (container
	// orchestrator shutdown) both trigger graceful shutdown.
	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer stop()

	// Start serving in a goroutine so the main goroutine can wait for signals.
	serveErr := make(chan error, 1)
	go func() {
		if err := server.Run(); err != nil {
			serveErr <- err
		}
	}()

	select {
	case err := <-serveErr:
		logger.Error("http server stopped unexpectedly", "error", err)
		return err
	case <-ctx.Done():
		logger.Info("shutdown signal received")
		// Restore default signal behavior so a second signal forces an exit.
		stop()
	}

	// Graceful shutdown: stop accepting new requests and wait for in-flight
	// handlers within the configured timeout.
	shutdownCtx := context.Background()
	if err := server.Shutdown(shutdownCtx); err != nil && !errors.Is(err, http.ErrServerClosed) {
		logger.Error("shutdown completed with error", "error", err)
		return err
	}

	return nil
}

func loadLocalEnvironment() error {
	// Local-only credentials live in ignored files. A production process must
	// receive every value from its process manager and must never fall back to
	// files in its working directory. The explicit environment selector is
	// supplied by production process management before this program starts.
	if os.Getenv("UP_ENVIRONMENT") == "production" {
		return nil
	}
	// Load the more specific override first so it wins over shared local
	// development defaults. Process environment values still take priority.
	if _, err := config.LoadDotEnv(".env.local"); err != nil {
		return err
	}
	if _, err := config.LoadDotEnv(".env"); err != nil {
		return err
	}
	return nil
}
