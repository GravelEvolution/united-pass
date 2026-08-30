package postgres

import (
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"testing"
)

func TestDreamUPAdministrationMigrationContract(t *testing.T) {
	path := filepath.Join(findBackendRoot(t), "migrations", "00013_production_lineage_bridge.sql")
	raw, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read migration: %v", err)
	}
	sql := string(raw)
	if strings.Count(sql, "-- +goose Up") != 1 || strings.Count(sql, "-- +goose Down") != 1 || strings.Count(sql, "-- +goose StatementBegin") != 2 || strings.Count(sql, "-- +goose StatementEnd") != 2 {
		t.Fatal("migration must have one transaction-bounded Goose Up and one aborting Down section")
	}
	down := sql[strings.Index(sql, "-- +goose Down"):]
	if !strings.Contains(down, "RAISE EXCEPTION") || regexp.MustCompile(`(?im)^\s*(?:DROP|DELETE|TRUNCATE|ALTER|CREATE|INSERT|UPDATE)\b`).MatchString(down) {
		t.Fatal("Down must abort and contain no destructive SQL")
	}
	required := []string{
		"admin_role_bindings", "dreamup_event_registry", "admin_challenges", "admin_step_up_state",
		"protected_operation_reasons", "identity_access_requests", "identity_access_request_fields", "identity_access_grants",
		"admin_operation_outbox", "admin_operator_approvals", "admin_security_event_vocabulary",
		"reject_dreamup_event_identity_change", "trg_dreamup_event_registry_immutable",
		"uq_admin_role_bindings_active_scope", "idx_admin_role_bindings_retention", "idx_protected_operation_reasons_retention",
		"idx_identity_access_requests_retention", "idx_identity_access_grants_retention", "uq_identity_access_grants_active_claim",
		"idx_admin_operation_outbox_due", "idx_admin_operation_outbox_expired_claim", "idx_admin_operation_outbox_payload_retention",
		"uq_admin_operator_approvals_request_operator", "idx_admin_operator_approvals_retention",
		"scope_key", "target_subject_user_id", "terminal_at", "audit_reconciled_at", "payload_expires_at", "payload_purged_at",
		"fk_admin_role_bindings_user", "fk_admin_challenges_user", "fk_admin_step_up_state_user",
		"fk_identity_access_requests_requester", "fk_identity_access_requests_target_subject",
		"fk_identity_access_request_fields_request", "fk_identity_access_grants_request",
		"fk_identity_access_grants_requester", "fk_identity_access_grants_target_subject",
		"fk_admin_operator_approvals_operator", "ck_admin_role_bindings_scope",
		"ck_admin_challenges_secret_lifecycle", "ck_protected_operation_reasons_crypto_lifecycle",
		"ck_identity_access_requests_actor_separation", "ck_identity_access_requests_terminal_actors", "ck_identity_access_grants_actor_separation",
		"ck_admin_operation_outbox_claim", "ck_admin_operation_outbox_result", "ck_admin_operation_outbox_result_values", "ck_admin_operation_outbox_terminal", "ck_admin_operation_outbox_payload_shape", "ck_admin_operation_outbox_payload_lifecycle",
	}
	for _, term := range required {
		if !strings.Contains(sql, term) {
			t.Errorf("migration missing %q", term)
		}
	}
	for _, term := range []string{
		"existing_tables NOT IN (0, 11)",
		"partial DreamUP v12 lineage detected",
		"DreamUP v12 lineage is incomplete or drifted",
	} {
		if !strings.Contains(sql, term) {
			t.Errorf("lineage bridge missing %q", term)
		}
	}
}

func TestDreamUPAdministrationMigrationAcceptsStepUpReceiptVocabulary(t *testing.T) {
	path := filepath.Join(findBackendRoot(t), "migrations", "00013_production_lineage_bridge.sql")
	raw, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read migration: %v", err)
	}
	sql := string(raw)
	start := strings.Index(sql, "CONSTRAINT ck_admin_operation_outbox_result CHECK")
	end := strings.Index(sql, "CONSTRAINT ck_admin_operation_outbox_terminal CHECK")
	if start < 0 || end <= start {
		t.Fatal("outbox result constraint section missing")
	}
	resultVocabulary := sql[start:end]
	for _, term := range []string{
		"'challenge.enrolled'", "'challenge.verified'", "'challenge.rotated'", "'challenge.rejected'", "'challenge.locked'",
		"'credential_version'", "'active'", "'must_rotate'", "'recovery_pending'",
	} {
		if !strings.Contains(resultVocabulary, term) {
			t.Errorf("migration result vocabulary missing %s", term)
		}
	}
}

func findBackendRoot(t *testing.T) string {
	t.Helper()
	dir, err := os.Getwd()
	if err != nil {
		t.Fatal(err)
	}
	for i := 0; i < 8; i++ {
		if info, err := os.Stat(filepath.Join(dir, "go.mod")); err == nil && !info.IsDir() {
			return dir
		}
		dir = filepath.Dir(dir)
	}
	t.Fatal("backend root not found")
	return ""
}
