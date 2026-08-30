package postgres

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"os"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"

	"github.com/GravelEvolution/united-pass/backend/internal/adminstore"
	"github.com/GravelEvolution/united-pass/backend/internal/config"
	"github.com/GravelEvolution/united-pass/backend/internal/integrationboundary"
	"github.com/GravelEvolution/united-pass/backend/internal/registration"
	"github.com/GravelEvolution/united-pass/backend/internal/wechatregistration"
)

func TestIntegration_IsolatedOperationalStore(t *testing.T) {
	rawURL := os.Getenv("UP_TEST_ISOLATED_DATABASE_URL")
	schema := os.Getenv("UP_TEST_ISOLATED_DATABASE_SCHEMA")
	runToken := os.Getenv(integrationboundary.RunTokenEnvironment)
	if rawURL == "" || schema == "" || runToken == "" {
		t.Skip("disposable isolated PostgreSQL target is not configured")
	}
	if err := integrationboundary.ValidateIsolatedPostgres(rawURL, schema, runToken); err != nil {
		t.Fatal(err)
	}
	database := config.DatabaseConfig{URL: rawURL, Schema: schema, MaxConns: 4, MinConns: 0, ConnectTimeout: 5 * time.Second}
	pool, err := NewPoolFromConfig(context.Background(), database)
	if err != nil {
		t.Fatal(err)
	}
	defer pool.Close()
	if err := ValidateIsolatedOperationalStore(context.Background(), pool.PgxPool()); err != nil {
		t.Fatal(err)
	}
	unexpectedView := pgx.Identifier{"unexpected_operational_view_" + runToken}.Sanitize()
	if _, err := pool.PgxPool().Exec(context.Background(), "CREATE VIEW "+unexpectedView+" AS SELECT 1 AS value"); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		_, _ = pool.PgxPool().Exec(context.Background(), "DROP VIEW IF EXISTS "+unexpectedView)
	})
	if err := ValidateIsolatedOperationalStore(context.Background(), pool.PgxPool()); err == nil || !strings.Contains(err.Error(), "unrelated table") {
		t.Fatalf("isolated store accepted an unrelated relation: %v", err)
	}
	if _, err := pool.PgxPool().Exec(context.Background(), "DROP VIEW "+unexpectedView); err != nil {
		t.Fatal(err)
	}
	unexpectedColumn := pgx.Identifier{"unexpected_metadata_" + runToken}.Sanitize()
	if _, err := pool.PgxPool().Exec(context.Background(), "ALTER TABLE wechat_registration_provider_intents ADD COLUMN "+unexpectedColumn+" TEXT"); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		_, _ = pool.PgxPool().Exec(context.Background(), "ALTER TABLE wechat_registration_provider_intents DROP COLUMN IF EXISTS "+unexpectedColumn)
	})
	if err := ValidateIsolatedOperationalStore(context.Background(), pool.PgxPool()); err == nil || !strings.Contains(err.Error(), "column contract drifted") {
		t.Fatalf("isolated store accepted an unrelated column: %v", err)
	}
	if _, err := pool.PgxPool().Exec(context.Background(), "ALTER TABLE wechat_registration_provider_intents DROP COLUMN "+unexpectedColumn); err != nil {
		t.Fatal(err)
	}
	if err := ValidateIsolatedOperationalStore(context.Background(), pool.PgxPool()); err != nil {
		t.Fatalf("isolated store did not recover after exact drift removal: %v", err)
	}

	digest := sha256.Sum256([]byte(runToken + "/wechat-user"))
	proposedUserID := "user_" + hex.EncodeToString(digest[:16])
	intent := wechatregistration.ProviderIntent{
		Username: "isolated-" + runToken, DisplayName: "Isolated Test", Email: runToken + "@example.test", Password: "Correct-Horse-Battery-Staple9!",
	}
	store := NewWeChatRegistrationIntentStore(pool.PgxPool())
	reservedUserID, err := store.ReserveNew(context.Background(), "tenant-"+runToken, "subject-"+runToken, proposedUserID, intent)
	if err != nil || reservedUserID != proposedUserID {
		t.Fatalf("reserve isolated intent user=%q err=%v", reservedUserID, err)
	}
	replayedUserID, err := store.ReserveNew(context.Background(), "tenant-"+runToken, "subject-"+runToken, "user_"+strings.Repeat("f", 32), intent)
	if err != nil || replayedUserID != proposedUserID {
		t.Fatalf("replay did not retain stable user: user=%q err=%v", replayedUserID, err)
	}
	drifted := intent
	drifted.Password = "Different-Strong-Password-Number2!"
	if _, err := store.ReserveNew(context.Background(), "tenant-"+runToken, "subject-"+runToken, proposedUserID, drifted); !errors.Is(err, registration.ErrConflict) {
		t.Fatalf("drifted provider intent error=%v", err)
	}
	if err := store.VerifyExisting(context.Background(), "tenant-"+runToken, "subject-"+runToken, proposedUserID, intent); err != nil {
		t.Fatalf("verify existing intent: %v", err)
	}
	if err := store.Clear(context.Background(), proposedUserID); err != nil {
		t.Fatal(err)
	}
	if err := store.VerifyExisting(context.Background(), "tenant-"+runToken, "subject-"+runToken, proposedUserID, intent); !errors.Is(err, registration.ErrConflict) {
		t.Fatalf("cleared intent remained usable: %v", err)
	}

	uow := NewAdminOutboxUnitOfWork(pool.PgxPool())
	now := time.Now().UTC().Truncate(time.Microsecond)
	key := "isolated-idempotency-" + runToken
	if _, err := pool.PgxPool().Exec(context.Background(), `DELETE FROM admin_operation_outbox WHERE idempotency_key=$1`, key); err != nil {
		t.Fatal(err)
	}
	item := adminstore.OutboxItem{
		ID: "aop_" + runToken, Kind: adminstore.OperationCrossSystem, IdempotencyKey: key,
		Fingerprint: adminstore.Fingerprint{Version: adminstore.FingerprintVersion, KeyID: "isolated-test-key", Digest: strings.Repeat("a", 43)},
		Result: adminstore.AllowlistedResult{Code: "operation.pending", Payload: map[string]string{
			"event_id": "evt_" + runToken, "operation_request_id": "request_" + runToken,
			"actor_id": "user_" + strings.Repeat("a", 32), "receipt_action": "application.review_saved",
			"receipt_target_type": "application", "receipt_target_id": "application_" + runToken,
		}},
		State: "pending", DeliveryPhase: adminstore.DeliveryPhaseNotSent, Version: 1,
		NextAttemptAt: now, CreatedAt: now, UpdatedAt: now,
	}
	var claimed adminstore.OutboxItem
	err = uow.Within(context.Background(), func(repositories adminstore.Repositories) error {
		stored, replay, err := repositories.Outbox.CreateOrReplay(context.Background(), item)
		if err != nil || replay {
			return err
		}
		claimed, err = repositories.Outbox.ClaimExact(context.Background(), stored.ID, stored.Version, now, 30*time.Second)
		if err != nil {
			return err
		}
		if err := repositories.Outbox.MarkDeliveryPhase(context.Background(), claimed.ID, claimed.Version, claimed.ClaimToken, adminstore.DeliveryPhaseIndeterminate, now); err != nil {
			return err
		}
		claimed.Version++
		claimed.DeliveryPhase = adminstore.DeliveryPhaseIndeterminate
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
	err = uow.Within(context.Background(), func(repositories adminstore.Repositories) error {
		if err := repositories.Outbox.MarkDeliveryPhase(context.Background(), claimed.ID, claimed.Version, claimed.ClaimToken, adminstore.DeliveryPhaseSent, now.Add(time.Second)); err != nil {
			return err
		}
		result := adminstore.AllowlistedResult{Code: "operation.settled", Digest: strings.Repeat("b", 64), Payload: map[string]string{
			"event_id": "evt_" + runToken, "operation_request_id": "request_" + runToken,
			"actor_id": "user_" + strings.Repeat("a", 32), "receipt_action": "application.review_saved",
			"receipt_target_type": "application", "receipt_target_id": "application_" + runToken,
			"response_status": "200", "result_version": "2",
		}}
		return repositories.Outbox.Settle(context.Background(), claimed.ID, claimed.Version+1, claimed.ClaimToken, result, now.Add(time.Second))
	})
	if err != nil {
		t.Fatal(err)
	}
	err = uow.Within(context.Background(), func(repositories adminstore.Repositories) error {
		settled, err := repositories.Outbox.GetByIdempotencyKey(context.Background(), key)
		if err != nil {
			return err
		}
		if settled.State != "succeeded" || settled.Result.Code != "operation.settled" || settled.TerminalAt == nil || settled.Result.Payload["result_version"] != "2" {
			t.Fatalf("settled isolated outbox=%+v", settled)
		}
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
}

func TestIntegration_V13AuthorityUsesIsolatedWeChatIntentStore(t *testing.T) {
	mainURL := os.Getenv("UP_TEST_DATABASE_URL")
	mainSchema := os.Getenv("UP_TEST_DATABASE_SCHEMA")
	isolatedURL := os.Getenv("UP_TEST_ISOLATED_DATABASE_URL")
	isolatedSchema := os.Getenv("UP_TEST_ISOLATED_DATABASE_SCHEMA")
	runToken := os.Getenv(integrationboundary.RunTokenEnvironment)
	if mainURL == "" || mainSchema == "" || isolatedURL == "" || isolatedSchema == "" || runToken == "" {
		t.Skip("disposable v13 authority and isolated PostgreSQL targets are not configured")
	}
	if err := integrationboundary.ValidatePostgres(mainURL, mainSchema, runToken); err != nil {
		t.Fatal(err)
	}
	if err := integrationboundary.ValidateIsolatedPostgres(isolatedURL, isolatedSchema, runToken); err != nil {
		t.Fatal(err)
	}
	mainPool, err := NewPoolFromConfig(context.Background(), config.DatabaseConfig{
		URL: mainURL, Schema: mainSchema, MaxConns: 4, MinConns: 0, ConnectTimeout: 5 * time.Second,
	})
	if err != nil {
		t.Fatal(err)
	}
	defer mainPool.Close()
	isolatedPool, err := NewPoolFromConfig(context.Background(), config.DatabaseConfig{
		URL: isolatedURL, Schema: isolatedSchema, MaxConns: 4, MinConns: 0, ConnectTimeout: 5 * time.Second,
	})
	if err != nil {
		t.Fatal(err)
	}
	defer isolatedPool.Close()
	if err := ValidateIsolatedOperationalStore(context.Background(), isolatedPool.PgxPool()); err != nil {
		t.Fatal(err)
	}
	var authorityVersion int64
	var mainIntentTable *string
	if err := mainPool.PgxPool().QueryRow(context.Background(), `SELECT COALESCE(MAX(version_id) FILTER (WHERE is_applied),0) FROM goose_db_version`).Scan(&authorityVersion); err != nil {
		t.Fatal(err)
	}
	if err := mainPool.PgxPool().QueryRow(context.Background(), `SELECT to_regclass('wechat_registration_provider_intents')::text`).Scan(&mainIntentTable); err != nil {
		t.Fatal(err)
	}
	if authorityVersion != 13 || mainIntentTable != nil {
		t.Fatalf("authority schema version=%d mainIntentTable=%v", authorityVersion, mainIntentTable)
	}

	digest := sha256.Sum256([]byte(runToken + "/v13-authority-user"))
	userID := "user_" + hex.EncodeToString(digest[:16])
	pendingDigest := sha256.Sum256([]byte(runToken + "/v13-pending-cleanup-user"))
	pendingUserID := "user_" + hex.EncodeToString(pendingDigest[:16])
	orphanDigest := sha256.Sum256([]byte(runToken + "/v13-orphan-cleanup-user"))
	orphanUserID := "user_" + hex.EncodeToString(orphanDigest[:16])
	standardDigest := sha256.Sum256([]byte(runToken + "/v13-standard-registration-user"))
	standardUserID := "user_" + hex.EncodeToString(standardDigest[:16])
	// The integration boundary above proves both schemas are disposable and
	// token-scoped. Remove only this test's deterministic identity so a rerun
	// exercises the complete reservation path instead of inheriting state from
	// an earlier local run.
	for _, cleanupUserID := range []string{userID, pendingUserID, standardUserID} {
		for _, statement := range []string{
			`DELETE FROM user_personas WHERE user_id=$1`,
			`DELETE FROM identity_links WHERE user_id=$1`,
			`DELETE FROM users WHERE id=$1`,
		} {
			if _, err := mainPool.PgxPool().Exec(context.Background(), statement, cleanupUserID); err != nil {
				t.Fatal(err)
			}
		}
	}
	if _, err := isolatedPool.PgxPool().Exec(context.Background(), `DELETE FROM wechat_registration_provider_intents WHERE user_id IN($1,$2,$3)`, userID, pendingUserID, orphanUserID); err != nil {
		t.Fatal(err)
	}
	standardRepository := NewRegistrationRepository(mainPool.PgxPool(), "zitadel", "project-"+runToken)
	if err := standardRepository.CreatePending(context.Background(), registration.PendingUser{
		UserID: standardUserID, DisplayName: "V13 Standard User", Email: "standard-" + runToken + "@v13.example.test",
		Status: registration.StatusPending,
	}); err != nil {
		t.Fatal(err)
	}
	if err := standardRepository.ActivateVerified(context.Background(), standardUserID); err != nil {
		t.Fatalf("standard registration activation against v13: %v", err)
	}
	input := wechatregistration.PendingUser{
		User: registration.PendingUser{
			UserID: userID, DisplayName: "V13 Isolated User", Email: runToken + "@v13.example.test",
			EmailVerified: false, Status: registration.StatusPending,
		},
		Phone: "+8613800000000", TenantID: "mini-" + runToken, Subject: "subject-v13-" + runToken,
		ProviderIntent: wechatregistration.ProviderIntent{
			Username: "v13-" + runToken, DisplayName: "V13 Isolated User", Email: runToken + "@v13.example.test",
			Password: "Correct-Horse-Battery-Staple9!",
		},
	}
	repository := NewRegistrationRepositoryWithIntentStore(
		mainPool.PgxPool(), "zitadel", "project-"+runToken,
		NewWeChatRegistrationIntentStore(isolatedPool.PgxPool()),
	)
	reservedUserID, err := repository.ReservePendingWithWeChat(context.Background(), input)
	if err != nil || reservedUserID != userID {
		t.Fatalf("v13 isolated reservation user=%q err=%v", reservedUserID, err)
	}
	retry := input
	retry.User.UserID = "user_" + strings.Repeat("f", 32)
	retry.ExpectedUserID = userID
	replayedUserID, err := repository.ReservePendingWithWeChat(context.Background(), retry)
	if err != nil || replayedUserID != userID {
		t.Fatalf("v13 isolated replay user=%q err=%v", replayedUserID, err)
	}
	wrongTarget := retry
	wrongTarget.ExpectedUserID = "user_" + strings.Repeat("e", 32)
	if _, err := repository.ReservePendingWithWeChat(context.Background(), wrongTarget); !errors.Is(err, registration.ErrConflict) {
		t.Fatalf("v13 isolated wrong recovery target error=%v", err)
	}
	drifted := retry
	drifted.ProviderIntent.Password = "Different-Strong-Password-Number2!"
	if _, err := repository.ReservePendingWithWeChat(context.Background(), drifted); !errors.Is(err, registration.ErrConflict) {
		t.Fatalf("v13 isolated drift error=%v", err)
	}
	var status, phone string
	var phoneVerified bool
	if err := mainPool.PgxPool().QueryRow(context.Background(), `SELECT status,phone,phone_verified FROM users WHERE id=$1`, userID).Scan(&status, &phone, &phoneVerified); err != nil {
		t.Fatal(err)
	}
	if status != registration.StatusPending || phone != input.Phone || !phoneVerified {
		t.Fatalf("pending authority identity status=%q phoneBound=%v verified=%v", status, phone == input.Phone, phoneVerified)
	}
	if err := repository.ActivateVerified(context.Background(), userID); err != nil {
		t.Fatal(err)
	}
	var isolatedIntents int
	if err := isolatedPool.PgxPool().QueryRow(context.Background(), `SELECT COUNT(*) FROM wechat_registration_provider_intents WHERE user_id=$1`, userID).Scan(&isolatedIntents); err != nil {
		t.Fatal(err)
	}
	if isolatedIntents != 0 {
		t.Fatalf("activated user retained %d isolated intent rows", isolatedIntents)
	}
	if err := mainPool.PgxPool().QueryRow(context.Background(), `SELECT status FROM users WHERE id=$1`, userID).Scan(&status); err != nil {
		t.Fatal(err)
	}
	if status != "active" {
		t.Fatalf("authority identity status=%q after activation", status)
	}

	// Migration 15 only repairs cross-system recovery metadata. Those writes
	// now use the isolated outbox, while the authority schema at v13 must still
	// accept every representative local role, step-up and identity-access
	// receipt used by the current admin services.
	authorityUOW := NewAdminUnitOfWork(mainPool.PgxPool(), nil)
	authorityNow := time.Now().UTC().Truncate(time.Microsecond)
	authorityResults := []adminstore.AllowlistedResult{
		{Code: "role.created", Payload: map[string]string{"binding_id": "arb_" + runToken, "version": "1"}},
		{Code: "challenge.verified", Payload: map[string]string{"event_id": "evt_" + runToken, "version": "1", "credential_version": "1"}},
		{Code: "identity_access.settled", Payload: map[string]string{"request_id": "iar_" + runToken, "grant_id": "iag_" + runToken, "status": "settled", "version": "1"}},
	}
	for index, result := range authorityResults {
		key := fmt.Sprintf("v13-local-receipt-%s-%d", runToken, index)
		if _, err := mainPool.PgxPool().Exec(context.Background(), `DELETE FROM admin_operation_outbox WHERE idempotency_key=$1`, key); err != nil {
			t.Fatal(err)
		}
		err := authorityUOW.Within(context.Background(), func(repositories adminstore.Repositories) error {
			stored, replay, err := repositories.Outbox.CreateOrReplay(context.Background(), adminstore.OutboxItem{
				ID: "aop_v13_" + runToken + "_" + strconv.Itoa(index), Kind: adminstore.OperationLocal,
				IdempotencyKey: key,
				Fingerprint:    adminstore.Fingerprint{Version: adminstore.FingerprintVersion, KeyID: "v13-local", Digest: strings.Repeat("c", 43)},
				State:          "pending", DeliveryPhase: adminstore.DeliveryPhaseNotSent, Version: 1,
				NextAttemptAt: authorityNow, CreatedAt: authorityNow, UpdatedAt: authorityNow,
			})
			if err != nil || replay {
				return err
			}
			return repositories.Outbox.CompleteLocal(context.Background(), stored.ID, stored.Version, result, authorityNow)
		})
		if err != nil {
			t.Fatalf("v13 authority local receipt %s: %v", result.Code, err)
		}
	}

	// A detached cleanup sweep removes only old active or orphaned sidecar
	// intents. A pending identity remains retryable even after the grace period.
	intentStore := NewWeChatRegistrationIntentStore(isolatedPool.PgxPool())
	if _, err := intentStore.ReserveNew(context.Background(), input.TenantID, "cleanup-active-"+runToken, userID, input.ProviderIntent); err != nil {
		t.Fatal(err)
	}
	orphanIntent := input.ProviderIntent
	orphanIntent.Username = "orphan-" + runToken
	orphanIntent.Email = "orphan-" + runToken + "@v13.example.test"
	if _, err := intentStore.ReserveNew(context.Background(), input.TenantID, "cleanup-orphan-"+runToken, orphanUserID, orphanIntent); err != nil {
		t.Fatal(err)
	}
	pendingInput := input
	pendingInput.User.UserID = pendingUserID
	pendingInput.User.Email = "pending-" + runToken + "@v13.example.test"
	pendingInput.TenantID = "mini-pending-" + runToken
	pendingInput.Subject = "cleanup-pending-" + runToken
	pendingInput.ProviderIntent.Username = "pending-" + runToken
	pendingInput.ProviderIntent.Email = pendingInput.User.Email
	if _, err := repository.ReservePendingWithWeChat(context.Background(), pendingInput); err != nil {
		t.Fatal(err)
	}
	createdAt := time.Now().UTC().Add(-2 * time.Hour)
	if _, err := isolatedPool.PgxPool().Exec(context.Background(), `UPDATE wechat_registration_provider_intents SET created_at=$1 WHERE user_id IN($2,$3,$4)`, createdAt, userID, pendingUserID, orphanUserID); err != nil {
		t.Fatal(err)
	}
	now := time.Now().UTC()
	removed, err := intentStore.CleanupCompleted(context.Background(), mainPool.PgxPool(), now.Add(-time.Hour), now, 100)
	if err != nil {
		t.Fatal(err)
	}
	if removed != 2 {
		t.Fatalf("completed intent cleanup removed=%d, want active and orphan only", removed)
	}
	var activeOrOrphan, pending int
	if err := isolatedPool.PgxPool().QueryRow(context.Background(), `SELECT COUNT(*) FROM wechat_registration_provider_intents WHERE user_id IN($1,$2)`, userID, orphanUserID).Scan(&activeOrOrphan); err != nil {
		t.Fatal(err)
	}
	if err := isolatedPool.PgxPool().QueryRow(context.Background(), `SELECT COUNT(*) FROM wechat_registration_provider_intents WHERE user_id=$1`, pendingUserID).Scan(&pending); err != nil {
		t.Fatal(err)
	}
	if activeOrOrphan != 0 || pending != 1 {
		t.Fatalf("cleanup activeOrOrphan=%d pending=%d", activeOrOrphan, pending)
	}
}
