package postgres

import (
	"bytes"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"testing"
)

func TestIsolatedOperationalStoreMigrationContainsNoAuthorityTables(t *testing.T) {
	path := filepath.Join(findBackendRoot(t), "isolated-migrations", "00001_dreamup_operational_store.sql")
	raw, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	sql := string(raw)
	for _, fragment := range []string{
		"CREATE TABLE wechat_registration_provider_intents",
		"CREATE TABLE admin_operation_outbox",
		"subject_hash", "cleanup_checked_at", "operation.pending", "operation.settled", "operation.failed",
		"delivery_state IN ('succeeded','failed','needs_operator') AND terminal_at IS NOT NULL",
		"isolated operational store migration is forward-only",
	} {
		if !strings.Contains(sql, fragment) {
			t.Fatalf("isolated migration missing %q", fragment)
		}
	}
	for _, forbidden := range []string{
		"CREATE TABLE users", "ALTER TABLE users", "REFERENCES users",
		"CREATE TABLE admin_role_bindings", "CREATE TABLE permission_policies",
		"provider_subject", "phone_verified", "email_verified",
	} {
		if strings.Contains(sql, forbidden) {
			t.Fatalf("isolated migration contains authority material %q", forbidden)
		}
	}
	if count := len(regexp.MustCompile(`(?im)^CREATE TABLE\s+`).FindAllString(sql, -1)); count != 2 {
		t.Fatalf("isolated migration creates %d business tables, want exactly 2", count)
	}
}

func TestIsolatedMigratorCannotSelectAuthorityDatabaseOrDestructiveCommand(t *testing.T) {
	path := filepath.Join(findBackendRoot(t), "cmd", "migrate-isolated", "main.go")
	raw, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	source := string(raw)
	for _, required := range []string{
		`command != "up" && command != "status" && command != "version"`,
		`openIsolatedDB(cfg.IsolatedDatabase)`,
		`if command == "up"`,
		`goose.SetTableName(pgx.Identifier{cfg.IsolatedDatabase.Schema, "goose_db_version"}.Sanitize())`,
	} {
		if !strings.Contains(source, required) {
			t.Fatalf("isolated migrator contract missing %q", required)
		}
	}
	for _, forbidden := range []string{
		`openIsolatedDB(cfg.Database)`, `goose.Down`, `goose.Reset`, `goose.DownTo`,
	} {
		if strings.Contains(source, forbidden) {
			t.Fatalf("isolated migrator contains unsafe authority or rollback path %q", forbidden)
		}
	}
}

func TestWeChatRegistrationSubjectDigestIsStableAndOpaque(t *testing.T) {
	first := hashWeChatRegistrationSubject("tenant-a", "subject-a")
	second := hashWeChatRegistrationSubject("tenant-a", "subject-a")
	differentTenant := hashWeChatRegistrationSubject("tenant-b", "subject-a")
	differentSubject := hashWeChatRegistrationSubject("tenant-a", "subject-b")
	if first != second || first == differentTenant || first == differentSubject {
		t.Fatal("subject digest is not stable and field-bound")
	}
	if bytes.Contains(first[:], []byte("tenant-a")) || bytes.Contains(first[:], []byte("subject-a")) {
		t.Fatal("subject digest exposed raw provider identifiers")
	}
}

func TestWeChatIntentCleanupCannotStarveBehindPendingRows(t *testing.T) {
	candidates := strings.Join(strings.Fields(weChatIntentCleanupCandidatesSQL), " ")
	for _, fragment := range []string{
		"cleanup_checked_at IS NULL OR cleanup_checked_at<=$2",
		"ORDER BY COALESCE(cleanup_checked_at,created_at),created_at,subject_hash",
		"LIMIT $3",
	} {
		if !strings.Contains(candidates, fragment) {
			t.Fatalf("cleanup candidate rotation missing %q: %s", fragment, candidates)
		}
	}
	pending := strings.Join(strings.Fields(weChatIntentCleanupPendingCheckedSQL), " ")
	if !strings.Contains(pending, "SET cleanup_checked_at=$3") || !strings.Contains(pending, "subject_hash=$1") || !strings.Contains(pending, "user_id=$2") {
		t.Fatalf("pending cleanup deferral is not exact: %s", pending)
	}
}
