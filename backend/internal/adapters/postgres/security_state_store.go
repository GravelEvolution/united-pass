//
// Copyright (c) 2026 Chen Jiajie(Ariakage)
//
// Author: Chen Jiajie(Ariakage) <ariakage233@gmail.com>
// Date: 2026-08-06
// Description: PostgreSQL adapter for the authoritative security state (ADR-0007)
//

package postgres

import (
	"context"
	"errors"
	"fmt"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/GravelEvolution/united-pass/backend/internal/identity"
	"github.com/GravelEvolution/united-pass/backend/internal/securitystate"
)

// SecurityStateStore is the PostgreSQL implementation of
// securitystate.Ledger: the single authority for the per-user security epoch
// and the durable password mutation intent lifecycle (ADR-0007 Decisions 1
// and 3). Every transition is CAS-fenced on (user_id, intent_id, status);
// Redis never decides here.
type SecurityStateStore struct {
	pool *pgxpool.Pool
}

// NewSecurityStateStore constructs the security-state store over the given
// pool. The pool's search_path runtime parameter must already be set to the
// configured schema (see NewPool).
func NewSecurityStateStore(pool *pgxpool.Pool) *SecurityStateStore {
	return &SecurityStateStore{pool: pool}
}

// intentColumns lists the password_mutation_intents columns in the fixed
// scan order used by scanIntent.
const intentColumns = `intent_id, status, epoch_at_acquire, provider_outcome,
       settlement_outcome, lease_expires_at, settlement_attempts`

// GetSecurityState returns the user's current epoch and non-terminal intent
// (nil when none exists). A missing user fails closed with
// identity.ErrUserNotFound.
func (s *SecurityStateStore) GetSecurityState(ctx context.Context, userID identity.UserID) (securitystate.State, error) {
	row := s.pool.QueryRow(ctx,
		`SELECT u.security_epoch,
		        i.intent_id, i.status, i.epoch_at_acquire, i.provider_outcome,
		        i.settlement_outcome, i.lease_expires_at, i.settlement_attempts
           FROM users u
           LEFT JOIN password_mutation_intents i
             ON i.user_id = u.id AND i.status <> 'settled'
          WHERE u.id = $1`, string(userID))

	var epoch int64
	var (
		intentID           *int64
		status             *string
		epochAtAcquire     *int
		providerOutcome    *string
		settlementOutcome  *string
		leaseExpiresAt     *time.Time
		settlementAttempts *int
	)
	if err := row.Scan(&epoch, &intentID, &status, &epochAtAcquire,
		&providerOutcome, &settlementOutcome, &leaseExpiresAt, &settlementAttempts); err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return securitystate.State{}, identity.ErrUserNotFound
		}
		return securitystate.State{}, fmt.Errorf("postgres: get security state: %w", err)
	}

	state := securitystate.State{Epoch: securitystate.Epoch(epoch)}
	if intentID != nil {
		intent := securitystate.Intent{
			UserID:             userID,
			IntentID:           *intentID,
			Status:             securitystate.IntentStatus(deref(status)),
			EpochAtAcquire:     securitystate.Epoch(int64(deref(epochAtAcquire))),
			ProviderOutcome:    securitystate.ProviderOutcome(deref(providerOutcome)),
			SettlementOutcome:  securitystate.SettlementOutcome(deref(settlementOutcome)),
			SettlementAttempts: deref(settlementAttempts),
		}
		if leaseExpiresAt != nil {
			intent.LeaseExpiresAt = *leaseExpiresAt
		}
		state.Intent = &intent
	}
	return state, nil
}

// CurrentEpoch returns the user's authoritative epoch — a single indexed
// point lookup used to stamp newly created sessions. A missing user fails
// closed with identity.ErrUserNotFound.
func (s *SecurityStateStore) CurrentEpoch(ctx context.Context, userID identity.UserID) (securitystate.Epoch, error) {
	var epoch int64
	err := s.pool.QueryRow(ctx,
		`SELECT security_epoch FROM users WHERE id = $1`, string(userID)).Scan(&epoch)
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return 0, identity.ErrUserNotFound
		}
		return 0, fmt.Errorf("postgres: current epoch: %w", err)
	}
	return securitystate.Epoch(epoch), nil
}

// AcquireIntent draws the next monotonic intent id and transitions the
// user's row to active in a single statement: the primary key serializes
// concurrent acquirers and exactly one wins. It fails closed with
// securitystate.ErrIntentHeld while any non-terminal intent exists,
// stamping epoch_at_acquire from the users row in the same statement.
func (s *SecurityStateStore) AcquireIntent(ctx context.Context, userID identity.UserID, leaseTTL time.Duration) (securitystate.Intent, error) {
	row := s.pool.QueryRow(ctx,
		`INSERT INTO password_mutation_intents
                (user_id, intent_id, status, epoch_at_acquire, lease_expires_at)
         SELECT $1, nextval('password_mutation_intent_seq'), 'active',
                u.security_epoch, NOW() + $2
           FROM users u
          WHERE u.id = $1
         ON CONFLICT (user_id) DO UPDATE
            SET intent_id = EXCLUDED.intent_id,
                status = 'active',
                epoch_at_acquire = EXCLUDED.epoch_at_acquire,
                lease_expires_at = EXCLUDED.lease_expires_at,
                provider_outcome = '',
                settlement_outcome = '',
                settlement_attempts = 0,
                created_at = NOW(),
                updated_at = NOW(),
                settled_at = NULL
          WHERE password_mutation_intents.status = 'settled'
         RETURNING `+intentColumns,
		string(userID), leaseTTL)

	var (
		intentID           int64
		status             string
		epochAtAcquire     int
		providerOutcome    string
		settlementOutcome  string
		leaseExpiresAt     *time.Time
		settlementAttempts int
	)
	err := row.Scan(&intentID, &status, &epochAtAcquire, &providerOutcome,
		&settlementOutcome, &leaseExpiresAt, &settlementAttempts)
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return securitystate.Intent{}, s.acquireNoRow(ctx, userID)
		}
		return securitystate.Intent{}, fmt.Errorf("postgres: acquire intent: %w", err)
	}
	intent := securitystate.Intent{
		UserID:             userID,
		IntentID:           intentID,
		Status:             securitystate.IntentStatus(status),
		EpochAtAcquire:     securitystate.Epoch(int64(epochAtAcquire)),
		ProviderOutcome:    securitystate.ProviderOutcome(providerOutcome),
		SettlementOutcome:  securitystate.SettlementOutcome(settlementOutcome),
		SettlementAttempts: settlementAttempts,
	}
	if leaseExpiresAt != nil {
		intent.LeaseExpiresAt = *leaseExpiresAt
	}
	return intent, nil
}

// acquireNoRow classifies an AcquireIntent that returned no row: the user
// does not exist (fail closed, ErrUserNotFound) or a non-terminal intent is
// held (fail closed, ErrIntentHeld).
func (s *SecurityStateStore) acquireNoRow(ctx context.Context, userID identity.UserID) error {
	var exists bool
	err := s.pool.QueryRow(ctx,
		`SELECT EXISTS (SELECT 1 FROM users WHERE id = $1)`, string(userID)).Scan(&exists)
	if err != nil {
		return fmt.Errorf("postgres: acquire intent existence check: %w", err)
	}
	if !exists {
		return identity.ErrUserNotFound
	}
	return securitystate.ErrIntentHeld
}

// SettleConfirmedFailure CAS-transitions the active intent straight to
// settled with provider_outcome confirmed_failure; the epoch is never
// touched (frozen §6 zero-side-effect semantics — the old generation
// resumes validity).
func (s *SecurityStateStore) SettleConfirmedFailure(ctx context.Context, userID identity.UserID, intentID int64) error {
	tag, err := s.pool.Exec(ctx,
		`UPDATE password_mutation_intents
            SET status = 'settled',
                provider_outcome = 'confirmed_failure',
                updated_at = NOW(),
                settled_at = NOW()
          WHERE user_id = $1 AND intent_id = $2 AND status = 'active'`,
		string(userID), intentID)
	if err != nil {
		return fmt.Errorf("postgres: settle confirmed failure: %w", err)
	}
	if tag.RowsAffected() == 0 {
		return securitystate.ErrFenceLost
	}
	return nil
}

// RecordOutcomeAdvanceEpoch records the provider outcome (success/unknown)
// and advances the epoch by exactly one in the same transaction, CAS-fenced
// from active. A fence loser never advances the epoch (ErrFenceLost).
func (s *SecurityStateStore) RecordOutcomeAdvanceEpoch(ctx context.Context, userID identity.UserID, intentID int64, outcome securitystate.ProviderOutcome) (securitystate.Epoch, error) {
	return s.advanceEpoch(ctx, userID, intentID, outcome, "")
}

// TakeoverExpiredAdvanceEpoch is the active-past-lease-expiry takeover: CAS
// from an active intent whose lease has expired, record outcome unknown and
// advance the epoch exactly once, in one transaction.
func (s *SecurityStateStore) TakeoverExpiredAdvanceEpoch(ctx context.Context, userID identity.UserID, intentID int64, now time.Time) (securitystate.Epoch, error) {
	return s.advanceEpoch(ctx, userID, intentID, securitystate.ProviderOutcomeUnknown,
		" AND lease_expires_at < $4", now)
}

// advanceEpoch runs the fenced outcome-record + epoch-advancement
// transaction. leaseFence is empty for the ordinary path or an extra AND
// clause (with $4 bound via fenceArgs) for the expiry takeover.
func (s *SecurityStateStore) advanceEpoch(ctx context.Context, userID identity.UserID, intentID int64, outcome securitystate.ProviderOutcome, leaseFence string, fenceArgs ...any) (securitystate.Epoch, error) {
	tx, err := s.pool.Begin(ctx)
	if err != nil {
		return 0, fmt.Errorf("postgres: begin outcome transaction: %w", err)
	}
	defer func() { _ = tx.Rollback(ctx) }()

	args := append([]any{string(userID), intentID, string(outcome)}, fenceArgs...)
	tag, err := tx.Exec(ctx,
		`UPDATE password_mutation_intents
            SET status = 'outcome_recorded',
                provider_outcome = $3,
                lease_expires_at = NULL,
                updated_at = NOW()
          WHERE user_id = $1 AND intent_id = $2 AND status = 'active'`+leaseFence,
		args...)
	if err != nil {
		return 0, fmt.Errorf("postgres: record outcome: %w", err)
	}
	if tag.RowsAffected() == 0 {
		return 0, securitystate.ErrFenceLost
	}

	var epoch int64
	if err := tx.QueryRow(ctx,
		`UPDATE users
            SET security_epoch = security_epoch + 1, updated_at = NOW()
          WHERE id = $1
          RETURNING security_epoch`, string(userID)).Scan(&epoch); err != nil {
		return 0, fmt.Errorf("postgres: advance epoch: %w", err)
	}

	if err := tx.Commit(ctx); err != nil {
		return 0, fmt.Errorf("postgres: commit outcome transaction: %w", err)
	}
	return securitystate.Epoch(epoch), nil
}

// BeginSettlement CAS-transitions outcome_recorded -> local_settlement.
func (s *SecurityStateStore) BeginSettlement(ctx context.Context, userID identity.UserID, intentID int64) error {
	tag, err := s.pool.Exec(ctx,
		`UPDATE password_mutation_intents
            SET status = 'local_settlement', updated_at = NOW()
          WHERE user_id = $1 AND intent_id = $2 AND status = 'outcome_recorded'`,
		string(userID), intentID)
	if err != nil {
		return fmt.Errorf("postgres: begin settlement: %w", err)
	}
	if tag.RowsAffected() == 0 {
		return securitystate.ErrFenceLost
	}
	return nil
}

// Settle CAS-transitions local_settlement -> settled, recording the
// settlement outcome (terminal, immutable afterwards).
func (s *SecurityStateStore) Settle(ctx context.Context, userID identity.UserID, intentID int64, outcome securitystate.SettlementOutcome) error {
	tag, err := s.pool.Exec(ctx,
		`UPDATE password_mutation_intents
            SET status = 'settled',
                settlement_outcome = $3,
                updated_at = NOW(),
                settled_at = NOW()
          WHERE user_id = $1 AND intent_id = $2 AND status = 'local_settlement'`,
		string(userID), intentID, string(outcome))
	if err != nil {
		return fmt.Errorf("postgres: settle intent: %w", err)
	}
	if tag.RowsAffected() == 0 {
		return securitystate.ErrFenceLost
	}
	return nil
}

// BumpSettlementAttempts increments and returns the settlement attempt
// counter of a non-terminal intent (bounded terminalization, F6). A terminal
// or missing intent loses the fence.
func (s *SecurityStateStore) BumpSettlementAttempts(ctx context.Context, userID identity.UserID, intentID int64) (int, error) {
	var attempts int
	err := s.pool.QueryRow(ctx,
		`UPDATE password_mutation_intents
            SET settlement_attempts = settlement_attempts + 1, updated_at = NOW()
          WHERE user_id = $1 AND intent_id = $2 AND status <> 'settled'
          RETURNING settlement_attempts`,
		string(userID), intentID).Scan(&attempts)
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return 0, securitystate.ErrFenceLost
		}
		return 0, fmt.Errorf("postgres: bump settlement attempts: %w", err)
	}
	return attempts, nil
}

// deref returns the pointed-to value or the zero value for nil pointers
// (nullable intent columns of a user without a non-terminal intent).
func deref[T any](p *T) T {
	var zero T
	if p == nil {
		return zero
	}
	return *p
}
