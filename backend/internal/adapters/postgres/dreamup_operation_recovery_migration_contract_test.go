package postgres

import (
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"testing"
)

func TestDreamUPOperationRecoveryMigrationContract(t *testing.T) {
	path := filepath.Join(findBackendRoot(t), "migrations", "00015_dreamup_operation_recovery.sql")
	raw, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	sql := string(raw)
	for _, fragment := range []string{
		"operation.pending", "operation.settled", "operation.failed",
		"operation_request_id", "actor_id", "response_status", "result_version",
		"receipt_action", "receipt_target_type", "receipt_target_id",
		"delivery_state IN ('succeeded', 'failed', 'needs_operator') AND terminal_at IS NOT NULL",
		"idx_admin_operation_outbox_receipt_due", "SET LOCAL lock_timeout = '5s'", "SET LOCAL statement_timeout = '2min'",
	} {
		if !strings.Contains(sql, fragment) {
			t.Fatalf("recovery migration missing %q", fragment)
		}
	}
	for _, forbidden := range []string{"response_body", "receipt_hash", "FLUSHDB", "FLUSHALL"} {
		if strings.Contains(sql, forbidden) {
			t.Fatalf("recovery migration persists forbidden material %q", forbidden)
		}
	}
	if strings.Count(sql, "-- +goose Up") != 1 || strings.Count(sql, "-- +goose Down") != 1 || strings.Count(sql, "-- +goose StatementBegin") != 2 || strings.Count(sql, "-- +goose StatementEnd") != 2 {
		t.Fatal("migration must have one transaction-bounded Goose Up and one forward-only aborting Down section")
	}
	down := strings.SplitN(sql, "-- +goose Down", 2)[1]
	if !strings.Contains(down, "RAISE EXCEPTION") || regexp.MustCompile(`(?im)^\s*(ALTER|CREATE|DELETE|DROP|INSERT|TRUNCATE|UPDATE)\b`).MatchString(down) {
		t.Fatal("recovery migration Down must abort without mutating schema or data")
	}
}

func TestIntegrationFixtureDropsEveryMigrationTableNeededForFreshReinstall(t *testing.T) {
	path := filepath.Join(findBackendRoot(t), "internal", "adapters", "postgres", "integration_test.go")
	raw, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	fixture := string(raw)
	reset := regexp.MustCompile(`(?s)func resetTestSchemaData\b.*?\n}\n\nfunc cleanupSharedTestSchema`).FindString(fixture)
	drop := regexp.MustCompile(`(?s)func dropTestSchemaObjects\b.*?\n}\n\nfunc TestIntegration_MigrationCleanup`).FindString(fixture)
	if reset == "" || drop == "" {
		t.Fatal("integration fixture reset/drop functions were not found")
	}
	for _, table := range []string{"identity_access_grant_fields", "wechat_registration_provider_intents"} {
		if !strings.Contains(reset, table) || !strings.Contains(drop, table) {
			t.Fatalf("integration fixture must both reset and drop %s", table)
		}
	}
}
