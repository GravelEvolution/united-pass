package main

import (
	"os"
	"strings"
	"testing"
)

func TestAuthorityMigrationTargetCapsCurrentProductionAtV13(t *testing.T) {
	for _, current := range []int64{0, 1, 12, 13} {
		target, err := authorityMigrationTarget(current)
		if err != nil {
			t.Fatalf("current v%d: %v", current, err)
		}
		if target != 13 {
			t.Fatalf("current v%d target=%d, want 13", current, target)
		}
	}
}

func TestAuthorityMigrationTargetRejectsRetiredSharedStoreVersions(t *testing.T) {
	for _, current := range []int64{-1, 14, 15, 16} {
		if _, err := authorityMigrationTarget(current); err == nil {
			t.Fatalf("current v%d was accepted", current)
		}
	}
}

func TestAuthorityMigrationCLIUsesBoundedUpTo(t *testing.T) {
	raw, err := os.ReadFile("main.go")
	if err != nil {
		t.Fatal(err)
	}
	source := string(raw)
	for _, required := range []string{
		"const authorityMigrationCeiling int64 = 13",
		"migrateAuthorityUp(ctx, db, migrationsDir)",
		"goose.UpToContext(ctx, db, migrationsDir, target)",
		"applied != target",
	} {
		if !strings.Contains(source, required) {
			t.Fatalf("authority migration CLI contract missing %q", required)
		}
	}
	if strings.Contains(source, "goose.UpContext(ctx, db, migrationsDir)") {
		t.Fatal("authority migration CLI may not apply unbounded pending migrations")
	}
}
