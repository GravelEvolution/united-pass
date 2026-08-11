//
// Copyright (c) 2026 Chen Jiajie(Ariakage)
//
// Author: Chen Jiajie(Ariakage) <ariakage233@gmail.com>
// Date: 2026-08-11
// Description: Explicit, approval-bound Phase 8 legal publication command
//

// Command legal-publish records an externally approved legal document as the
// current effective version. It deliberately has no web/UI equivalent: the
// operator must supply the approval reference, approver and exact effective
// time and explicitly confirm that the immutable frontend artifact was
// reviewed. Running this command is an operational/legal sign-off, not a build
// step.
package main

import (
	"context"
	"encoding/json"
	"flag"
	"fmt"
	"log/slog"
	"os"
	"path/filepath"
	"time"

	"github.com/GravelEvolution/united-pass/backend/internal/adapters/postgres"
	"github.com/GravelEvolution/united-pass/backend/internal/config"
	"github.com/GravelEvolution/united-pass/backend/internal/identity"
	"github.com/GravelEvolution/united-pass/backend/internal/privacy"
)

func main() {
	kind := flag.String("kind", "", "Document kind: privacy or terms")
	effective := flag.String("effective-at", "", "RFC3339 effective timestamp")
	approval := flag.String("approval-reference", "", "External legal approval/ticket reference")
	approvedBy := flag.String("approved-by", "", "Legal approver name or team")
	actor := flag.String("actor-user-id", "", "Existing United Pass operator user ID")
	confirm := flag.Bool("confirm-approved", false, "Confirm legal approval covers the exact built-in content digest")
	flag.Parse()
	if !*confirm {
		fatal("--confirm-approved is required; this command must not substitute for legal approval")
	}
	supported, ok := privacy.SupportedDocument(*kind)
	if !ok {
		fatal("--kind must be privacy or terms")
	}
	effectiveAt, err := time.Parse(time.RFC3339, *effective)
	if err != nil {
		fatal("--effective-at must be RFC3339: %v", err)
	}
	if *approval == "" || *approvedBy == "" || *actor == "" {
		fatal("--approval-reference, --approved-by and --actor-user-id are required")
	}

	if _, err := os.Stat(".env"); err == nil {
		if _, err := config.LoadDotEnv(filepath.Join(".", ".env")); err != nil {
			fatal("load .env: %v", err)
		}
	}
	cfg, err := config.Load()
	if err != nil {
		fatal("config: %v", err)
	}
	if !cfg.HasDatabase() {
		fatal("UP_DATABASE_URL is required")
	}
	pool, err := postgres.NewPool(context.Background(), cfg)
	if err != nil {
		fatal("database: %v", err)
	}
	defer pool.Close()

	repo := postgres.NewPrivacyRepository(pool.PgxPool(), cfg.Auth.Provider)
	service := privacy.NewService(repo, nil, nil, slog.Default())
	result, err := service.PublishLegalDocument(context.Background(), privacy.LegalPublicationInput{
		DocumentKind: supported.Kind, Version: supported.Version,
		ContentSHA256: supported.ContentSHA256, EffectiveAt: effectiveAt.UTC(),
		ApprovalReference: *approval, ApprovedBy: *approvedBy,
		PublishedBy: identity.UserID(*actor), RequestID: "legal-publish-cli",
	})
	if err != nil {
		fatal("publish: %v", err)
	}
	encoded, _ := json.MarshalIndent(result, "", "  ")
	fmt.Println(string(encoded))
}

func fatal(format string, args ...any) {
	fmt.Fprintf(os.Stderr, format+"\n", args...)
	os.Exit(1)
}
