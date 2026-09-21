package postgres

import (
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"testing"
)

func TestIdentityAccessWorkflowMigrationPersistsEveryGrantBinding(t *testing.T) {
	path := filepath.Join(findBackendRoot(t), "migrations", "00013_identity_access_workflow.sql")
	raw, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read migration: %v", err)
	}
	sql := string(raw)
	for _, term := range []string{
		"identity_access_grant_fields", "requester_role_binding_id", "requester_role_binding_version",
		"requester_challenge_version", "field_set_hash", "expires_at", "uq_identity_access_requests_pending_target",
		"ALTER COLUMN expires_at SET DEFAULT",
	} {
		if !strings.Contains(sql, term) {
			t.Errorf("migration missing %q", term)
		}
	}
	down := sql[strings.Index(sql, "-- +goose Down"):]
	if !strings.Contains(down, "intentionally irreversible") || regexp.MustCompile(`(?i)\b(?:DROP|DELETE|TRUNCATE|ALTER)\b`).MatchString(down) {
		t.Fatal("Down must be intentionally inert")
	}
}
