//
// Copyright (c) 2026 Chen Jiajie(Ariakage)
//
// Author: Chen Jiajie(Ariakage) <ariakage233@gmail.com>
// Date: 2026-08-07
// Description: One-time LoginV2 interaction configuration backfill for
//              pre-Phase-3 ZITADEL OIDC applications (ADR-0005 §1)
//

// Command oauth-topology-backfill is the explicit one-time migration the
// Phase 3.6 rollout runbook requires: it enforces LoginVersion =
// LoginV2{BaseURI = the derived Interaction Base URI} on every OIDC
// application of the shared ZITADEL project, including pre-Phase-3 apps that
// will never pass through ProvisionClient or UpdateClient again.
//
// The job reuses the provisioning adapter, so the repair is the exact same
// preserving read-modify-write the live paths use; every repaired app is
// read back live and must match exactly. The report is printed per app; the
// process exits non-zero when any application failed or any precondition is
// missing. The rollout must not cut public OAuth traffic while the job does
// not succeed (docs/topology-runbook.md step 4).
//
// Required configuration (same environment as the API service):
//
//	UP_AUTH_PROVIDER=zitadel
//	UP_AUTH_PROVIDER_BASE_URL / UP_AUTH_PROVIDER_SERVICE_ACCOUNT_KEY_FILE / UP_AUTH_PROVIDER_PROJECT_ID
//	UP_OAUTH_PUBLIC_ORIGIN     (the interaction base is derived from it)
//
// Usage:
//
//	go run ./cmd/oauth-topology-backfill
package main

import (
	"context"
	"fmt"
	"log/slog"
	"os"
	"time"

	"github.com/GravelEvolution/united-pass/backend/internal/adapters/zitadel"
	"github.com/GravelEvolution/united-pass/backend/internal/config"
)

// backfillTimeout bounds the whole run; the job is safe to re-run after a
// timeout (it is idempotent).
const backfillTimeout = 10 * time.Minute

func main() {
	os.Exit(run())
}

func run() int {
	logger := slog.New(slog.NewTextHandler(os.Stderr, nil))

	if _, err := config.LoadDotEnv(".env"); err != nil {
		logger.Error("loading .env failed", "error", err)
		return 1
	}
	cfg, err := config.Load()
	if err != nil {
		logger.Error("configuration invalid", "error", err)
		return 1
	}

	// Preconditions: the backfill is meaningful only for a real ZITADEL
	// provider with a derived interaction base. Fail closed on anything less.
	if cfg.Auth.Provider != zitadel.ProviderName || !cfg.HasAuthProvider() {
		logger.Error("backfill requires UP_AUTH_PROVIDER=zitadel and UP_AUTH_PROVIDER_BASE_URL")
		return 1
	}
	if cfg.Auth.ServiceAccountKeyFile == "" || cfg.Auth.ProjectID == "" {
		logger.Error("backfill requires UP_AUTH_PROVIDER_SERVICE_ACCOUNT_KEY_FILE and UP_AUTH_PROVIDER_PROJECT_ID")
		return 1
	}
	if cfg.OAuth.PublicOrigin == "" {
		logger.Error("backfill requires UP_OAUTH_PUBLIC_ORIGIN (the interaction base is derived from it)")
		return 1
	}
	interactionBase := cfg.OAuth.InteractionBaseURI()

	ctx, cancel := context.WithTimeout(context.Background(), backfillTimeout)
	defer cancel()

	sdk, err := zitadel.NewSDKClient(ctx, cfg.Auth)
	if err != nil {
		logger.Error("provider connection failed", "error", err)
		return 1
	}
	defer sdk.Close()

	prov, err := zitadel.NewProvisioner(sdk.ManagementService(), cfg.Auth.ProjectID, interactionBase, logger)
	if err != nil {
		logger.Error("provisioner construction failed", "error", err)
		return 1
	}

	logger.Info("login version backfill starting",
		"project_id", cfg.Auth.ProjectID,
		"interaction_base", interactionBase,
	)
	report, err := prov.BackfillLoginVersions(ctx)

	// The report is the audit trail: print it even when the job failed.
	for _, entry := range report.Entries {
		fmt.Fprintf(os.Stdout, "%s\t%s\t%s\n", entry.Outcome, entry.ApplicationID, entry.Name)
	}
	fmt.Fprintf(os.Stdout, "verified=%d repaired=%d skipped=%d failed=%d total=%d\n",
		report.Verified, report.Repaired, report.Skipped, report.Failed, len(report.Entries))

	if err != nil || !report.Success() {
		logger.Error("login version backfill NOT successful; rollout must not proceed to cutover", "error", err)
		return 1
	}
	logger.Info("login version backfill complete: every OIDC application carries the desired LoginV2 configuration")
	return 0
}
