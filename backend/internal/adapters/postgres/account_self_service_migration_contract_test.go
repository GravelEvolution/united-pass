package postgres

import (
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"testing"
)

func TestAuthorityMigrationVersionsAreUniqueAndContiguous(t *testing.T) {
	files, err := filepath.Glob(filepath.Join(findBackendRoot(t), "migrations", "*.sql"))
	if err != nil {
		t.Fatal(err)
	}
	versions := make(map[int]string, len(files))
	for _, path := range files {
		base := filepath.Base(path)
		if len(base) < 6 || base[5] != '_' {
			t.Fatalf("migration has invalid filename %q", base)
		}
		version, err := strconv.Atoi(base[:5])
		if err != nil {
			t.Fatalf("migration has invalid version %q: %v", base, err)
		}
		if previous, exists := versions[version]; exists {
			t.Fatalf("duplicate migration version %05d: %s and %s", version, previous, base)
		}
		versions[version] = base
	}
	ordered := make([]int, 0, len(versions))
	for version := range versions {
		ordered = append(ordered, version)
	}
	sort.Ints(ordered)
	if len(ordered) != 16 {
		t.Fatalf("migration count=%d, want 16", len(ordered))
	}
	for index, version := range ordered {
		if version != index+1 {
			t.Fatalf("migration sequence=%v, want contiguous 1..16", ordered)
		}
	}
}

func TestAccountSelfServiceLineageReconcileContract(t *testing.T) {
	path := filepath.Join(findBackendRoot(t), "migrations", "00016_account_self_service_reconcile.sql")
	raw, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	sql := string(raw)
	for _, required := range []string{
		"partial account self-service lineage detected",
		"CREATE TABLE IF NOT EXISTS user_avatars",
		"CREATE TABLE IF NOT EXISTS contact_change_requests",
		"CREATE UNIQUE INDEX IF NOT EXISTS uq_contact_change_requests_active",
		"avatar_id:text:NO:<null>",
		"request_id_hash:text:NO:<null>",
		"identity_access_grant_fields",
		"idx_admin_operation_outbox_receipt_due",
		"SET LOCAL lock_timeout = '5s'",
		"SET LOCAL statement_timeout = '2min'",
	} {
		if !strings.Contains(sql, required) {
			t.Errorf("lineage reconcile migration missing %q", required)
		}
	}
	if strings.Count(sql, "-- +goose Up") != 1 || strings.Count(sql, "-- +goose Down") != 1 || strings.Count(sql, "-- +goose StatementBegin") != 2 || strings.Count(sql, "-- +goose StatementEnd") != 2 {
		t.Fatal("lineage reconcile migration must have one transaction-bounded Up and one aborting Down")
	}
	down := strings.SplitN(sql, "-- +goose Down", 2)[1]
	if !strings.Contains(down, "RAISE EXCEPTION") || regexp.MustCompile(`(?im)^\s*(ALTER|CREATE|DELETE|DROP|INSERT|TRUNCATE|UPDATE)\b`).MatchString(down) {
		t.Fatal("lineage reconcile Down must abort without mutating schema or data")
	}
}
