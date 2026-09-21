//
// Copyright (c) 2026 Chen Jiajie(Ariakage)
//
// Author: Chen Jiajie(Ariakage) <ariakage233@gmail.com>
// Date: 2026-08-05
// Description: Shared PostgreSQL integration test setup (test pool and schema migration)
//

//go:build integration

// Package postgres integration tests verify repository behavior against a real
// PostgreSQL instance. Destructive integration tests are accepted only when
// scripts/run-local-integration-matrix.ps1 supplies a per-run database, role,
// schema and ownership token. Missing or arbitrary configuration fails before
// any connection is opened; SSH-tunnel and shared-schema execution is refused.
package postgres

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"sync"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/stdlib"
	"github.com/pressly/goose/v3"

	"github.com/GravelEvolution/united-pass/backend/internal/applications"
	"github.com/GravelEvolution/united-pass/backend/internal/config"
	"github.com/GravelEvolution/united-pass/backend/internal/identity"
	"github.com/GravelEvolution/united-pass/backend/internal/integrationboundary"
	"github.com/GravelEvolution/united-pass/backend/internal/registration"
)

// Repository integration tests are intentionally serial and reuse one fully
// migrated dedicated test schema. Re-running nine SSH round-trip migrations
// for every top-level scenario made the package exceed Go's default 10-minute
// timeout as the migration chain grew. Each setup truncates every business
// table before returning a fresh pool; migration-path tests still build their
// own historical schemas through openMigrationTestDB.
var testSchemaMu sync.Mutex

func TestMain(m *testing.M) {
	if err := validatePostgresIntegrationBoundary(); err != nil {
		fmt.Fprintln(os.Stderr, "PostgreSQL integration boundary rejected:", err)
		os.Exit(2)
	}
	code := m.Run()
	if err := cleanupSharedTestSchema(); err != nil {
		fmt.Fprintln(os.Stderr, "PostgreSQL integration cleanup failed:", err)
		if code == 0 {
			code = 1
		}
	}
	os.Exit(code)
}

func validatePostgresIntegrationBoundary() error {
	return integrationboundary.ValidatePostgres(
		os.Getenv("UP_TEST_DATABASE_URL"),
		os.Getenv("UP_TEST_DATABASE_SCHEMA"),
		os.Getenv(integrationboundary.RunTokenEnvironment),
	)
}

func mustLoadTestDBConfig(t *testing.T) (string, string) {
	t.Helper()
	url := os.Getenv("UP_TEST_DATABASE_URL")
	schema := os.Getenv("UP_TEST_DATABASE_SCHEMA")
	if err := integrationboundary.ValidatePostgres(url, schema, os.Getenv(integrationboundary.RunTokenEnvironment)); err != nil {
		t.Fatalf("PostgreSQL integration boundary rejected: %v", err)
	}
	// The schema name is interpolated into SQL below, so it must pass strict
	// identifier validation before any statement is built.
	if !config.ValidSchemaIdentifier(schema) {
		t.Fatalf("test schema %q is not a valid PostgreSQL identifier", schema)
	}
	return url, schema
}

// setupTestDB runs migrations against the test schema and returns a
// UserRepository. It also registers a cleanup that drops all tables in the
// test schema — never the development or production schema.
func setupTestDB(t *testing.T) *UserRepository {
	return setupTestDBWithMaxConns(t, 5)
}

// setupTestDBWithMaxConns builds a test repository with a connection pool of
// the given size. MaxConns=1 is used to prove the identity linker never holds
// a transaction connection while querying the pool (no self-deadlock).
func setupTestDBWithMaxConns(t *testing.T, maxConns int32) *UserRepository {
	pool := setupTestPool(t, maxConns)
	return NewUserRepository(pool.PgxPool())
}

// setupTestPool runs migrations against the test schema and returns a test
// pool. It registers a cleanup that drops all tables in the test schema —
// never the development or production schema.
func setupTestPool(t *testing.T, maxConns int32) *Pool {
	t.Helper()
	testSchemaMu.Lock()
	// Registered first so LIFO cleanup closes the pool and database handle
	// before another test can reset the shared schema.
	t.Cleanup(testSchemaMu.Unlock)
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
	// creates the schema; the runner is responsible for creating it. The
	// schema has passed identifier validation and is quoted via
	// pgx.Identifier to prevent injection.
	quotedSchema := pgx.Identifier{schema}.Sanitize()
	if _, err := db.Exec(fmt.Sprintf("CREATE SCHEMA IF NOT EXISTS %s", quotedSchema)); err != nil {
		t.Fatalf("create test schema: %v", err)
	}
	goose.SetTableName(pgx.Identifier{schema, "goose_db_version"}.Sanitize())
	if err := goose.SetDialect("postgres"); err != nil {
		t.Fatalf("set dialect: %v", err)
	}

	migrationsDir := findMigrationsDir(t)
	if err := goose.UpContext(context.Background(), db, migrationsDir); err != nil {
		t.Fatalf("apply migrations: %v", err)
	}
	resetTestSchemaData(t, db)

	// Per-test cleanup closes only this handle. TestMain drops all objects after
	// the package; the next setup truncates data while preserving migrations.
	t.Cleanup(func() {
		_ = db.Close()
	})

	// Create a pgxpool for repository tests.
	cfg := config.Config{
		Database: config.DatabaseConfig{
			URL:            url,
			Schema:         schema,
			MaxConns:       maxConns,
			MinConns:       1,
			ConnectTimeout: 10 * time.Second,
		},
	}
	pool, err := NewPool(context.Background(), cfg)
	if err != nil {
		t.Fatalf("create pool: %v", err)
	}
	t.Cleanup(func() { pool.Close() })

	return pool
}

func resetTestSchemaData(t *testing.T, db *sql.DB) {
	t.Helper()
	statements := []string{
		`ALTER TABLE security_events DROP CONSTRAINT IF EXISTS test_reject_consent_audit`,
		`ALTER TABLE security_events DROP CONSTRAINT IF EXISTS test_reject_wechat_pending_phone_audit`,
		`ALTER TABLE security_events DROP CONSTRAINT IF EXISTS test_reject_sms_phone_audit`,
		`TRUNCATE TABLE
			admin_operator_approvals, admin_operation_outbox,
			identity_access_grant_fields, identity_access_grants, identity_access_request_fields, identity_access_requests,
			protected_operation_reasons, admin_step_up_state, admin_challenges,
			admin_role_bindings, dreamup_event_registry,
			account_deletion_requests, personal_data_export_jobs, legal_document_publications,
			audit_export_jobs, policy_publication_jobs,
			authorization_policy_versions, authorization_policies,
			provider_sync_conflicts, provider_directory_users,
			provider_directory_departments, provider_sync_jobs, identity_providers,
			access_revocation_jobs, employee_profiles, departments,
			security_events, provider_reconciliation_jobs, oauth_provider_operations,
			oauth_authorization_grant_scopes, oauth_authorization_grants,
			oauth_authorization_decision_operation_scopes,
			oauth_authorization_decision_operations,
			oauth_client_secret_records, oauth_client_scopes, oauth_client_redirect_uris,
			oauth_clients, oauth_applications,
			wechat_registration_provider_intents,
			password_mutation_intents, user_personas, identity_links, users
		 RESTART IDENTITY CASCADE`,
		`ALTER SEQUENCE password_mutation_intent_seq RESTART WITH 1`,
		`ALTER SEQUENCE employee_number_seq RESTART WITH 1`,
		`INSERT INTO identity_providers
			(provider_id, display_name, vendor, integration_label, status, login_enabled)
		 VALUES
			('provider_feishu', '飞书', 'feishu', 'OAuth 2.0 + 通讯录 OpenAPI', 'disabled', FALSE)`,
	}
	for _, statement := range statements {
		if _, err := db.Exec(statement); err != nil {
			t.Fatalf("reset test schema data: %v", err)
		}
	}
}

func cleanupSharedTestSchema() error {
	url := os.Getenv("UP_TEST_DATABASE_URL")
	schema := os.Getenv("UP_TEST_DATABASE_SCHEMA")
	if err := integrationboundary.ValidatePostgres(url, schema, os.Getenv(integrationboundary.RunTokenEnvironment)); err != nil {
		return err
	}
	connConfig, err := pgx.ParseConfig(url)
	if err != nil {
		return errors.New("parse disposable PostgreSQL cleanup connection")
	}
	if connConfig.RuntimeParams == nil {
		connConfig.RuntimeParams = make(map[string]string)
	}
	connConfig.RuntimeParams["search_path"] = schema
	db := stdlib.OpenDB(*connConfig)
	defer db.Close()
	return dropTestSchemaObjects(nil, db)
}

func dropTestSchemaObjects(t *testing.T, db *sql.DB) error {
	if t != nil {
		t.Helper()
	}
	statements := []string{
		`DROP TABLE IF EXISTS
			admin_operator_approvals, admin_operation_outbox,
			identity_access_grant_fields, identity_access_grants, identity_access_request_fields, identity_access_requests,
			protected_operation_reasons, admin_step_up_state, admin_challenges,
			admin_role_bindings, dreamup_event_registry, admin_security_event_vocabulary,
			account_deletion_requests, personal_data_export_jobs, legal_document_publications,
			audit_export_jobs, policy_publication_jobs,
			authorization_policy_versions, authorization_policies,
			provider_sync_conflicts, provider_directory_users,
			provider_directory_departments, provider_sync_jobs, identity_providers,
			access_revocation_jobs, employee_profiles, departments,
			security_events, provider_reconciliation_jobs, oauth_provider_operations,
			oauth_authorization_grant_scopes, oauth_authorization_grants,
			oauth_authorization_decision_operation_scopes,
			oauth_authorization_decision_operations,
			oauth_client_secret_records, oauth_client_scopes, oauth_client_redirect_uris,
			oauth_clients, oauth_applications,
			wechat_registration_provider_intents,
			password_mutation_intents,
			user_personas, identity_links, users CASCADE`,
		`DROP SEQUENCE IF EXISTS password_mutation_intent_seq, employee_number_seq`,
		`DROP FUNCTION IF EXISTS reject_dreamup_event_identity_change()`,
		`DROP TABLE IF EXISTS goose_db_version`,
	}
	for _, statement := range statements {
		if _, err := db.Exec(statement); err != nil {
			if t != nil {
				t.Fatalf("clean test schema: %v", err)
			}
			return errors.New("drop disposable PostgreSQL schema objects")
		}
	}
	return nil
}

func TestIntegration_MigrationCleanupSupportsSecondFreshInstallInSameSchema(t *testing.T) {
	db := openMigrationTestDB(t)
	ctx := context.Background()
	migrations := findMigrationsDir(t)
	if err := goose.UpContext(ctx, db, migrations); err != nil {
		t.Fatalf("first fresh migration: %v", err)
	}
	if !tableExists(t, db, "wechat_registration_provider_intents") || !tableExists(t, db, "admin_operation_outbox") {
		t.Fatal("first fresh migration did not reach head")
	}
	dropTestSchemaObjects(t, db)
	if err := goose.UpContext(ctx, db, migrations); err != nil {
		t.Fatalf("second fresh migration in same schema: %v", err)
	}
	if !tableExists(t, db, "wechat_registration_provider_intents") || !tableExists(t, db, "admin_operation_outbox") {
		t.Fatal("second fresh migration did not recreate head tables")
	}
	version, err := goose.GetDBVersion(db)
	if err != nil || version != 15 {
		t.Fatalf("second fresh migration version=%d err=%v", version, err)
	}
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

// TestIntegration_FirstLoginCreatesUserWithProfile verifies that the
// transactional identity linker creates the user, identity link and consumer
// persona on first login, with the provider profile persisted.
func TestIntegration_FirstLoginCreatesUserWithProfile(t *testing.T) {
	repo := setupTestDB(t)
	ctx := context.Background()

	user, err := repo.GetOrCreateUserByProviderSubject(ctx, "zitadel", "tenant_e2e", identity.ProviderUserInfo{
		Subject:       "zitadel-subject-001",
		DisplayName:   "Zhixing Lin",
		Email:         "zhixing@example.com",
		EmailVerified: true,
		Phone:         "+8613800000000",
	})
	if err != nil {
		t.Fatalf("first login linking: %v", err)
	}
	if user.Status != identity.UserStatusActive {
		t.Errorf("status = %q, want active", user.Status)
	}
	if user.Email != "zhixing@example.com" || !user.EmailVerified {
		t.Errorf("email = %q verified=%v, want zhixing@example.com verified", user.Email, user.EmailVerified)
	}
	if user.DisplayName != "Zhixing Lin" {
		t.Errorf("display name = %q, want Zhixing Lin", user.DisplayName)
	}
	if user.Phone != "+8613800000000" {
		t.Errorf("phone = %q, want +8613800000000", user.Phone)
	}
	if len(user.Personas) != 1 || user.Personas[0] != identity.PersonaConsumer {
		t.Errorf("personas = %v, want [consumer]", user.Personas)
	}

	// A second login with the same provider subject resolves to the same user.
	again, err := repo.GetOrCreateUserByProviderSubject(ctx, "zitadel", "tenant_e2e", identity.ProviderUserInfo{
		Subject: "zitadel-subject-001",
	})
	if err != nil {
		t.Fatalf("second login linking: %v", err)
	}
	if again.ID != user.ID {
		t.Errorf("second login user = %q, want %q (same user)", again.ID, user.ID)
	}
}

func TestIntegration_UnverifiedFirstLoginCannotCreateActiveUser(t *testing.T) {
	repo := setupTestDB(t)
	user, err := repo.GetOrCreateUserByProviderSubject(context.Background(), "zitadel", "tenant_unverified", identity.ProviderUserInfo{
		Subject: "unverified-provider-subject", Email: "pending@example.com", EmailVerified: false,
	})
	if err != nil {
		t.Fatalf("first login linking: %v", err)
	}
	if user.Status != identity.UserStatusPending || user.Status.CanAuthenticate() || user.EmailVerified {
		t.Fatalf("unverified first login created authenticatable user: %#v", user)
	}
}

// TestIntegration_ConcurrentFirstLoginSingleWinner verifies that concurrent
// first logins for the same provider subject produce exactly one user and no
// orphan rows: all callers resolve to the same local user.
func TestIntegration_ConcurrentFirstLoginSingleWinner(t *testing.T) {
	repo := setupTestDB(t)
	ctx := context.Background()

	const workers = 8
	results := make(chan identity.UserID, workers)
	errs := make(chan error, workers)

	for i := 0; i < workers; i++ {
		go func() {
			u, err := repo.GetOrCreateUserByProviderSubject(ctx, "zitadel", "tenant_concurrent", identity.ProviderUserInfo{
				Subject:     "zitadel-subject-concurrent",
				DisplayName: "Concurrent User",
			})
			if err != nil {
				errs <- err
				return
			}
			results <- u.ID
		}()
	}

	var got []identity.UserID
	for i := 0; i < workers; i++ {
		select {
		case id := <-results:
			got = append(got, id)
		case err := <-errs:
			t.Fatalf("concurrent linking error: %v", err)
		}
	}

	// Every caller must resolve to the same user.
	if len(got) != workers {
		t.Fatalf("got %d results, want %d", len(got), workers)
	}
	first := got[0]
	for _, id := range got[1:] {
		if id != first {
			t.Errorf("different users resolved for the same provider subject: %v", got)
		}
	}

	// Exactly one identity link and exactly one user row must exist.
	loaded, err := repo.GetIdentityLink(ctx, "zitadel", "tenant_concurrent", "zitadel-subject-concurrent")
	if err != nil {
		t.Fatalf("get identity link: %v", err)
	}
	if loaded.UserID != first {
		t.Errorf("link user = %q, want %q", loaded.UserID, first)
	}
}

// TestIntegration_ConcurrentFirstLoginSingleConnection verifies that
// concurrent first logins for the same provider subject complete without
// deadlock on a connection pool of size 1. The losing transaction must
// release its only connection before re-reading the winner through the pool;
// otherwise the pool acquisition waits on itself until the context deadline.
func TestIntegration_ConcurrentFirstLoginSingleConnection(t *testing.T) {
	repo := setupTestDBWithMaxConns(t, 1)
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()

	const workers = 6
	results := make(chan identity.UserID, workers)
	errs := make(chan error, workers)

	for i := 0; i < workers; i++ {
		go func() {
			u, err := repo.GetOrCreateUserByProviderSubject(ctx, "zitadel", "tenant_single_conn", identity.ProviderUserInfo{
				Subject: "zitadel-subject-single-conn",
			})
			if err != nil {
				errs <- err
				return
			}
			results <- u.ID
		}()
	}

	var got []identity.UserID
	for i := 0; i < workers; i++ {
		select {
		case id := <-results:
			got = append(got, id)
		case err := <-errs:
			t.Fatalf("concurrent linking error: %v", err)
		case <-ctx.Done():
			t.Fatalf("pool self-deadlock detected: %v", ctx.Err())
		}
	}

	// Every caller must resolve to the same user.
	first := got[0]
	for _, id := range got[1:] {
		if id != first {
			t.Errorf("different users resolved for the same provider subject: %v", got)
		}
	}

	// Exactly one identity link must exist.
	loaded, err := repo.GetIdentityLink(ctx, "zitadel", "tenant_single_conn", "zitadel-subject-single-conn")
	if err != nil {
		t.Fatalf("get identity link: %v", err)
	}
	if loaded.UserID != first {
		t.Errorf("link user = %q, want %q", loaded.UserID, first)
	}
}

func TestIntegration_RegistrationPendingIdentityActivatesIdempotently(t *testing.T) {
	users := setupTestDB(t)
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()
	repo := NewRegistrationRepository(users.pool, "zitadel", "project_registration")
	const userID = "user_0123456789abcdef0123456789abcdef"
	if err := repo.CreatePending(ctx, registration.PendingUser{
		UserID: userID, DisplayName: "月石选手", Email: "player@example.com",
		Status: registration.StatusPending, EmailVerified: false,
	}); err != nil {
		t.Fatalf("create pending registration: %v", err)
	}

	pending, err := users.GetByID(ctx, identity.UserID(userID))
	if err != nil {
		t.Fatalf("get pending user: %v", err)
	}
	if pending.Status != identity.UserStatusPending || pending.EmailVerified || pending.Status.CanAuthenticate() {
		t.Fatalf("pending user = %#v", pending)
	}
	if len(pending.Personas) != 1 || pending.Personas[0] != identity.PersonaConsumer {
		t.Fatalf("pending personas = %v", pending.Personas)
	}
	if isPending, err := repo.IsPending(ctx, userID); err != nil || !isPending {
		t.Fatalf("local pending guard=%v err=%v, want true", isPending, err)
	}
	if isPending, err := repo.IsPending(ctx, "user_ffffffffffffffffffffffffffffffff"); err != nil || isPending {
		t.Fatalf("unknown pending guard=%v err=%v, want false", isPending, err)
	}
	link, err := users.GetIdentityLink(ctx, "zitadel", "project_registration", userID)
	if err != nil || string(link.UserID) != userID || link.ProviderSubject != userID {
		t.Fatalf("exact identity link = %#v err=%v", link, err)
	}

	if err := repo.ActivateVerified(ctx, userID); err != nil {
		t.Fatalf("activate verified registration: %v", err)
	}
	active, err := users.GetByID(ctx, identity.UserID(userID))
	if err != nil || !active.Status.CanAuthenticate() || !active.EmailVerified {
		t.Fatalf("active user = %#v err=%v", active, err)
	}
	if isPending, err := repo.IsPending(ctx, userID); err != nil || isPending {
		t.Fatalf("active account remained pending=%v err=%v", isPending, err)
	}
	version := active.Version
	if err := repo.ActivateVerified(ctx, userID); err != nil {
		t.Fatalf("idempotent activation: %v", err)
	}
	again, err := users.GetByID(ctx, identity.UserID(userID))
	if err != nil || again.Version != version {
		t.Fatalf("idempotent activation changed version: before=%d after=%d err=%v", version, again.Version, err)
	}
}

// TestIntegration_SecurityEventStoreSessionRevocationPayload verifies the
// durable audit row for a session revocation actually persists the target
// session ID and the provider-cleanup failure class inside the JSONB payload
// (ADR-0006 §2). Targeted regression for the payload seam; no user row is
// required because security_events carries no FK on actor_user_id.
func TestIntegration_SecurityEventStoreSessionRevocationPayload(t *testing.T) {
	pool := setupTestPool(t, 4)
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()

	store := NewSecurityEventStore(pool.PgxPool())
	ev := applications.SecurityEvent{
		EventID:      applications.NewSecurityEventID(),
		EventType:    "session.revoked_other",
		ActorUserID:  identity.UserID("user_audit_it"),
		RequestID:    "req-it-1",
		Operation:    "session.revoke",
		Result:       applications.SecurityEventSuccess,
		FailureClass: "network",
		TargetKey:    "session_id",
		TargetID:     "sess_target_it",
		Extra: map[string]string{
			"revoked_count":          "2",
			"provider_failure_class": "timeout",
		},
		OccurredAt: time.Now().UTC(),
	}
	if err := store.Record(ctx, ev); err != nil {
		t.Fatalf("record security event: %v", err)
	}

	var payload map[string]string
	if err := pool.PgxPool().QueryRow(ctx,
		`SELECT payload FROM security_events WHERE event_id = $1`,
		string(ev.EventID)).Scan(&payload); err != nil {
		t.Fatalf("read back security event: %v", err)
	}
	if payload["session_id"] != "sess_target_it" {
		t.Errorf("payload session_id = %q, want sess_target_it (payload=%v)", payload["session_id"], payload)
	}
	if payload["failure_class"] != "network" {
		t.Errorf("payload failure_class = %q, want network (payload=%v)", payload["failure_class"], payload)
	}
	if payload["revoked_count"] != "2" || payload["provider_failure_class"] != "timeout" {
		t.Errorf("payload missing P4.8 forensic extras: %v", payload)
	}
	if len(payload) != 4 {
		t.Errorf("payload = %v, want session_id, failure_class and two P4.8 extras", payload)
	}
}
