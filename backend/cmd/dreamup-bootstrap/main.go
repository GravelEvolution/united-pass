//
// Copyright (c) 2026 Chen Jiajie(Ariakage)
//
// Description: Idempotent MoonStone DreamUP OAuth client bootstrap command
//

// Command dreamup-bootstrap creates or verifies the single DreamUP OAuth
// application/client pair through the existing United Pass application
// service and ZITADEL provisioner. It never prints the one-time client secret.
package main

import (
	"context"
	"flag"
	"io"
	"log/slog"
	"os"
	"time"

	"github.com/GravelEvolution/united-pass/backend/internal/adapters/postgres"
	"github.com/GravelEvolution/united-pass/backend/internal/adapters/zitadel"
	"github.com/GravelEvolution/united-pass/backend/internal/applications"
	"github.com/GravelEvolution/united-pass/backend/internal/config"
	"github.com/GravelEvolution/united-pass/backend/internal/dreamupbootstrap"
	"github.com/GravelEvolution/united-pass/backend/internal/identity"
)

const bootstrapTimeout = 10 * time.Minute

func main() {
	os.Exit(run(os.Args[1:], os.Stdout, os.Stderr))
}

func run(args []string, stdout, stderr io.Writer) int {
	flags := flag.NewFlagSet("dreamup-bootstrap", flag.ContinueOnError)
	flags.SetOutput(stderr)
	secretOutput := flags.String("secret-output", "", "absolute path for the first-run one-time client secret")
	if err := flags.Parse(args); err != nil || flags.NArg() != 0 {
		return 2
	}
	logger := slog.New(slog.NewTextHandler(stderr, nil))

	if _, err := config.LoadDotEnv(".env"); err != nil {
		logger.Error("DreamUP bootstrap could not load environment")
		return 1
	}
	cfg, err := config.Load()
	if err != nil {
		logger.Error("DreamUP bootstrap configuration is invalid")
		return 1
	}
	if cfg.Auth.Provider != zitadel.ProviderName || !cfg.HasAuthProvider() ||
		cfg.Auth.ProjectID == "" || cfg.Auth.ServiceAccountKeyFile == "" ||
		cfg.OAuth.InteractionBaseURI() == "" {
		logger.Error("DreamUP bootstrap requires complete ZITADEL and OAuth topology configuration")
		return 1
	}
	if !cfg.HasDatabase() || cfg.Session.EncryptionKey == "" {
		logger.Error("DreamUP bootstrap requires PostgreSQL and the session encryption key")
		return 1
	}
	if cfg.DreamUPBootstrap.OwnerUserID == "" {
		logger.Error("DreamUP bootstrap requires UP_DREAMUP_OWNER_USER_ID")
		return 1
	}

	ctx, cancel := context.WithTimeout(context.Background(), bootstrapTimeout)
	defer cancel()

	pool, err := postgres.NewPool(ctx, cfg)
	if err != nil {
		logger.Error("DreamUP bootstrap could not initialize PostgreSQL")
		return 1
	}
	defer pool.Close()
	if err := pool.Ping(ctx, cfg.Database.ConnectTimeout); err != nil {
		logger.Error("DreamUP bootstrap could not verify PostgreSQL")
		return 1
	}

	sdk, err := zitadel.NewSDKClient(ctx, cfg.Auth)
	if err != nil {
		logger.Error("DreamUP bootstrap could not initialize ZITADEL")
		return 1
	}
	defer sdk.Close()
	provisioner, err := zitadel.NewProvisioner(
		sdk.ManagementService(),
		cfg.Auth.ProjectID,
		cfg.OAuth.InteractionBaseURI(),
		logger,
	)
	if err != nil {
		logger.Error("DreamUP bootstrap could not initialize the provisioner")
		return 1
	}
	if err := provisioner.VerifyProject(ctx); err != nil {
		logger.Error("DreamUP bootstrap could not verify the ZITADEL project")
		return 1
	}

	applicationRepo, err := postgres.NewApplicationRepository(pool.PgxPool(), cfg.Session.EncryptionKey)
	if err != nil {
		logger.Error("DreamUP bootstrap could not initialize application storage")
		return 1
	}
	users := postgres.NewUserRepository(pool.PgxPool())
	events := postgres.NewSecurityEventStore(pool.PgxPool())
	applicationService := applications.NewService(
		applicationRepo,
		provisioner,
		events,
		events,
		users,
		zitadel.ProviderName,
		cfg.Auth.ProjectID,
		cfg.Rotation.GracePeriod,
	)
	bootstrapService := dreamupbootstrap.NewService(
		applicationService,
		applicationRepo,
		provisioner,
		dreamupbootstrap.ProviderExpectations{
			ProviderName:       zitadel.ProviderName,
			ProjectID:          cfg.Auth.ProjectID,
			InteractionBaseURI: cfg.OAuth.InteractionBaseURI(),
		},
	)
	return bootstrapService.Execute(ctx, dreamupbootstrap.Options{
		OwnerUserID:  identity.UserID(cfg.DreamUPBootstrap.OwnerUserID),
		SecretOutput: *secretOutput,
	}, stdout, stderr)
}
