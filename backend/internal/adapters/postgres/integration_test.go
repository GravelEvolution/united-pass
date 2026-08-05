//go:build integration

// Package postgres integration tests verify repository behavior against a real
// PostgreSQL instance. These tests require UP_TEST_DATABASE_URL and
// UP_TEST_DATABASE_SCHEMA to be set; they skip when the variables are absent.
// They never connect to the development schema.
//
// Run locally (through the SSH tunnel managed by scripts/tunnel.sh):
//
//	UP_TEST_DATABASE_URL=postgres://user:pass@127.0.0.1:15432/db?sslmode=disable \
//	UP_TEST_DATABASE_SCHEMA=united_pass_test \
//	go test -tags integration ./internal/adapters/postgres/...
//
// Never point these tests at a public network endpoint with plaintext. The
// tunnel keeps plaintext traffic on the loopback interface only.
package postgres

import (
	"context"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/stdlib"
	"github.com/pressly/goose/v3"

	"github.com/GravelEvolution/united-pass/backend/internal/config"
	"github.com/GravelEvolution/united-pass/backend/internal/identity"
)

func mustLoadTestDBConfig(t *testing.T) (string, string) {
	t.Helper()
	url := os.Getenv("UP_TEST_DATABASE_URL")
	schema := os.Getenv("UP_TEST_DATABASE_SCHEMA")
	if schema == "" {
		schema = "united_pass_test"
	}
	if url == "" {
		t.Skip("UP_TEST_DATABASE_URL not set; skipping PostgreSQL integration tests")
	}
	return url, schema
}

// setupTestDB runs migrations against the test schema and returns a
// UserRepository. It also registers a cleanup that drops all tables in the
// test schema — never the development or production schema.
func setupTestDB(t *testing.T) *UserRepository {
	t.Helper()
	url, schema := mustLoadTestDBConfig(t)

	// Run migrations via goose against the test schema.
	connConfig, err := pgx.ParseConfig(url)
	if err != nil {
		t.Fatalf("parse test database URL: %v", err)
	}
	if connConfig.RuntimeParams == nil {
		connConfig.RuntimeParams = make(map[string]string)
	}
	connConfig.RuntimeParams["search_path"] = schema

	db := stdlib.OpenDB(*connConfig)

	// Create the test schema if it doesn't exist. The migration no longer
	// creates the schema; the runner is responsible for creating it.
	if _, err := db.Exec(fmt.Sprintf("CREATE SCHEMA IF NOT EXISTS %s", schema)); err != nil {
		t.Fatalf("create test schema: %v", err)
	}

	goose.SetTableName(fmt.Sprintf("%s.goose_db_version", schema))
	if err := goose.SetDialect("postgres"); err != nil {
		t.Fatalf("set dialect: %v", err)
	}

	migrationsDir := findMigrationsDir(t)
	if err := goose.UpContext(context.Background(), db, migrationsDir); err != nil {
		t.Fatalf("apply migrations: %v", err)
	}

	// Clean up: drop all tables in the test schema and close the DB.
	t.Cleanup(func() {
		_, _ = db.Exec(fmt.Sprintf(
			`DROP TABLE IF EXISTS %s.user_personas, %s.identity_links, %s.users CASCADE`,
			schema, schema, schema,
		))
		_, _ = db.Exec(fmt.Sprintf(
			`DROP TABLE IF EXISTS %s.goose_db_version`,
			schema,
		))
		_ = db.Close()
	})

	// Create a pgxpool for repository tests.
	cfg := config.Config{
		Database: config.DatabaseConfig{
			URL:            url,
			Schema:         schema,
			MaxConns:       5,
			MinConns:       1,
			ConnectTimeout: 10 * time.Second,
		},
	}
	pool, err := NewPool(context.Background(), cfg)
	if err != nil {
		t.Fatalf("create pool: %v", err)
	}
	t.Cleanup(func() { pool.Close() })

	return NewUserRepository(pool.PgxPool())
}

// findMigrationsDir locates the migrations directory relative to the test file.
func findMigrationsDir(t *testing.T) string {
	t.Helper()
	dir, err := os.Getwd()
	if err != nil {
		t.Fatalf("getwd: %v", err)
	}
	for i := 0; i < 5; i++ {
		candidate := filepath.Join(dir, "migrations")
		if info, err := os.Stat(candidate); err == nil && info.IsDir() {
			return candidate
		}
		dir = filepath.Dir(dir)
	}
	t.Fatal("migrations directory not found")
	return ""
}

// --- Tests ---

func TestIntegration_UserCreateAndRead(t *testing.T) {
	repo := setupTestDB(t)
	ctx := context.Background()

	user := identity.User{
		ID:          identity.UserID("user_test_001"),
		Status:      identity.UserStatusActive,
		DisplayName: "Integration Test",
		Nickname:    "IT",
		Email:       "integration@example.com",
		Phone:       "+8613800138000",
		Version:     1,
		CreatedAt:   time.Now().UTC(),
		UpdatedAt:   time.Now().UTC(),
	}

	if err := repo.Create(ctx, user); err != nil {
		t.Fatalf("create user: %v", err)
	}

	loaded, err := repo.GetByID(ctx, user.ID)
	if err != nil {
		t.Fatalf("get user: %v", err)
	}
	if loaded.ID != user.ID {
		t.Errorf("ID: got %q, want %q", loaded.ID, user.ID)
	}
	if loaded.DisplayName != user.DisplayName {
		t.Errorf("DisplayName: got %q, want %q", loaded.DisplayName, user.DisplayName)
	}
	if loaded.Email != user.Email {
		t.Errorf("Email: got %q, want %q", loaded.Email, user.Email)
	}
	if loaded.Status != user.Status {
		t.Errorf("Status: got %q, want %q", loaded.Status, user.Status)
	}
}

func TestIntegration_GetByIDNotFound(t *testing.T) {
	repo := setupTestDB(t)
	ctx := context.Background()

	_, err := repo.GetByID(ctx, identity.UserID("nonexistent_user"))
	if !errors.Is(err, identity.ErrUserNotFound) {
		t.Fatalf("expected ErrUserNotFound, got %v", err)
	}
}

func TestIntegration_IdentityLinkUniqueness(t *testing.T) {
	repo := setupTestDB(t)
	ctx := context.Background()

	user1 := identity.User{
		ID:        identity.UserID("user_link_001"),
		Status:    identity.UserStatusActive,
		Email:     "link1@example.com",
		Version:   1,
		CreatedAt: time.Now().UTC(),
		UpdatedAt: time.Now().UTC(),
	}
	if err := repo.Create(ctx, user1); err != nil {
		t.Fatalf("create user1: %v", err)
	}

	user2 := identity.User{
		ID:        identity.UserID("user_link_002"),
		Status:    identity.UserStatusActive,
		Email:     "link2@example.com",
		Version:   1,
		CreatedAt: time.Now().UTC(),
		UpdatedAt: time.Now().UTC(),
	}
	if err := repo.Create(ctx, user2); err != nil {
		t.Fatalf("create user2: %v", err)
	}

	link1 := identity.IdentityLink{
		ID:               "link_001",
		UserID:           user1.ID,
		Provider:         "feishu",
		ProviderTenantID: "tenant_001",
		ProviderSubject:  "subject_abc",
		CreatedAt:        time.Now().UTC(),
		LastSeenAt:       time.Now().UTC(),
	}
	if err := repo.CreateIdentityLink(ctx, link1); err != nil {
		t.Fatalf("create link1: %v", err)
	}

	// The same provider subject cannot link to a different user.
	link2 := identity.IdentityLink{
		ID:               "link_002",
		UserID:           user2.ID,
		Provider:         "feishu",
		ProviderTenantID: "tenant_001",
		ProviderSubject:  "subject_abc",
		CreatedAt:        time.Now().UTC(),
		LastSeenAt:       time.Now().UTC(),
	}
	err := repo.CreateIdentityLink(ctx, link2)
	if err == nil {
		t.Fatal("expected unique constraint violation, got nil error")
	}

	// Verify the original link is intact.
	loaded, err := repo.GetIdentityLink(ctx, "feishu", "tenant_001", "subject_abc")
	if err != nil {
		t.Fatalf("get identity link: %v", err)
	}
	if loaded.UserID != user1.ID {
		t.Errorf("link UserID: got %q, want %q", loaded.UserID, user1.ID)
	}
}

func TestIntegration_DisabledUserCannotAuthenticate(t *testing.T) {
	repo := setupTestDB(t)
	ctx := context.Background()

	user := identity.User{
		ID:        identity.UserID("user_disabled_001"),
		Status:    identity.UserStatusActive,
		Email:     "disabled@example.com",
		Version:   1,
		CreatedAt: time.Now().UTC(),
		UpdatedAt: time.Now().UTC(),
	}
	if err := repo.Create(ctx, user); err != nil {
		t.Fatalf("create user: %v", err)
	}

	// Disable the user.
	if err := repo.UpdateStatus(ctx, user.ID, identity.UserStatusDisabled); err != nil {
		t.Fatalf("disable user: %v", err)
	}

	loaded, err := repo.GetByID(ctx, user.ID)
	if err != nil {
		t.Fatalf("get user: %v", err)
	}
	if loaded.Status != identity.UserStatusDisabled {
		t.Errorf("Status: got %q, want %q", loaded.Status, identity.UserStatusDisabled)
	}
	if loaded.Status.CanAuthenticate() {
		t.Error("disabled user should not be able to authenticate")
	}
}

func TestIntegration_PersonasCRUD(t *testing.T) {
	repo := setupTestDB(t)
	ctx := context.Background()

	user := identity.User{
		ID:        identity.UserID("user_persona_001"),
		Status:    identity.UserStatusActive,
		Email:     "persona@example.com",
		Version:   1,
		CreatedAt: time.Now().UTC(),
		UpdatedAt: time.Now().UTC(),
	}
	if err := repo.Create(ctx, user); err != nil {
		t.Fatalf("create user: %v", err)
	}

	// Add consumer persona.
	if err := repo.AddPersona(ctx, user.ID, identity.PersonaConsumer); err != nil {
		t.Fatalf("add persona: %v", err)
	}

	// Adding the same persona should be idempotent.
	if err := repo.AddPersona(ctx, user.ID, identity.PersonaConsumer); err != nil {
		t.Fatalf("add persona (idempotent): %v", err)
	}

	personas, err := repo.GetPersonas(ctx, user.ID)
	if err != nil {
		t.Fatalf("get personas: %v", err)
	}
	if len(personas) != 1 {
		t.Fatalf("personas count: got %d, want 1", len(personas))
	}
	if personas[0] != identity.PersonaConsumer {
		t.Errorf("persona: got %q, want %q", personas[0], identity.PersonaConsumer)
	}

	// Verify personas are loaded via GetByID.
	loaded, err := repo.GetByID(ctx, user.ID)
	if err != nil {
		t.Fatalf("get user: %v", err)
	}
	if len(loaded.Personas) != 1 {
		t.Fatalf("loaded personas: got %d, want 1", len(loaded.Personas))
	}
}

func TestIntegration_ContextCancellation(t *testing.T) {
	repo := setupTestDB(t)

	ctx, cancel := context.WithCancel(context.Background())
	cancel() // Cancel immediately.

	_, err := repo.GetByID(ctx, identity.UserID("any_user"))
	if err == nil {
		t.Fatal("expected error from cancelled context, got nil")
	}
}
