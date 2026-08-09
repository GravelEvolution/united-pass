//
// Copyright (c) 2026 Chen Jiajie(Ariakage)
//
// Author: Chen Jiajie(Ariakage) <ariakage233@gmail.com>
// Date: 2026-08-06
// Description: Security generation (epoch) and password mutation intent domain (ADR-0007)
//

// Package securitystate implements the authoritative local security
// boundary of ADR-0007: the per-user security generation (epoch) and the
// durable password mutation intent lifecycle. PostgreSQL is the single
// authority — Redis may mirror hot-path state at most and never decides.
package securitystate

import (
	"context"
	"errors"
	"time"

	"github.com/GravelEvolution/united-pass/backend/internal/identity"
)

// Epoch is a per-user security generation: monotonic, starting at 1. Every
// session, reauth challenge/grant and enrollment token is stamped with the
// user's epoch at mint time; anything stamped with an epoch lower than the
// user's current epoch is treated exactly as if it did not exist.
type Epoch int64

// IntentStatus is one state of the four-state mutation intent lifecycle
// (ADR-0007 Decision 3): active -> outcome_recorded -> local_settlement ->
// settled.
type IntentStatus string

const (
	// IntentActive: lease acquired, provider call pending or in flight.
	// Pre-outcome barrier: every session promotion, reauth grant
	// consumption, enrollment confirmation and further password mutation
	// fails closed.
	IntentActive IntentStatus = "active"
	// IntentOutcomeRecorded: the provider outcome is recorded and, for
	// success/unknown, the epoch advanced in the same transaction. The
	// barrier narrows: current-epoch sessions ordinarily promote;
	// sensitive consumption and further mutations stay denied.
	IntentOutcomeRecorded IntentStatus = "outcome_recorded"
	// IntentLocalSettlement: rotation and generation-scoped cleanup in
	// progress (degradable). Same narrowed barrier as outcome_recorded.
	IntentLocalSettlement IntentStatus = "local_settlement"
	// IntentSettled: terminal, immutable. No barrier.
	IntentSettled IntentStatus = "settled"
)

// Terminal reports whether the status is the terminal state.
func (s IntentStatus) Terminal() bool { return s == IntentSettled }

// PostEpoch reports whether the status is a post-epoch non-terminal phase:
// the atomic outcome-record + epoch advancement has already established the
// credential boundary, so current-epoch ordinary promotion is allowed while
// sensitive consumption stays denied until settled (ADR-0007 F6, Option B).
func (s IntentStatus) PostEpoch() bool {
	return s == IntentOutcomeRecorded || s == IntentLocalSettlement
}

// ProviderOutcome is the Decision 4 classification of the provider call.
type ProviderOutcome string

const (
	// ProviderOutcomeNone: no outcome recorded yet (active intent).
	ProviderOutcomeNone ProviderOutcome = ""
	// ProviderOutcomeSuccess: the provider confirmed the change.
	ProviderOutcomeSuccess ProviderOutcome = "success"
	// ProviderOutcomeConfirmedFailure: the provider definitively rejected
	// the change; zero local settlement, epoch unchanged.
	ProviderOutcomeConfirmedFailure ProviderOutcome = "confirmed_failure"
	// ProviderOutcomeUnknown: transport failure / timeout / ambiguous
	// response — treated as committed for boundary purposes (fail closed).
	ProviderOutcomeUnknown ProviderOutcome = "unknown"
)

// AdvancesEpoch reports whether this provider outcome advances the security
// epoch in the same transaction that records it (success or unknown, never
// confirmed failure).
func (o ProviderOutcome) AdvancesEpoch() bool {
	return o == ProviderOutcomeSuccess || o == ProviderOutcomeUnknown
}

// SettlementOutcome is the terminal local-settlement classification.
type SettlementOutcome string

const (
	// SettlementOutcomeNone: settlement not (yet) performed.
	SettlementOutcomeNone SettlementOutcome = ""
	// SettlementOutcomeSettled: full settlement — current session rotated
	// and re-stamped, every pre-change generation session revoked.
	SettlementOutcomeSettled SettlementOutcome = "settled"
	// SettlementOutcomeSettledRelogin: the epoch advanced but the current
	// session vanished (concurrent logout/revoke won) — every pre-change
	// session and capability is invalid regardless of Redis state; the
	// caller must log in again.
	SettlementOutcomeSettledRelogin SettlementOutcome = "settled_relogin"
	// SettlementOutcomeDegraded: settlement could not complete (Redis
	// cleanup failure or provider outcome unknown). The epoch boundary
	// still holds; the response never reports success.
	SettlementOutcomeDegraded SettlementOutcome = "degraded"
)

// Intent is one durable password mutation intent row.
type Intent struct {
	UserID             identity.UserID
	IntentID           int64
	Status             IntentStatus
	EpochAtAcquire     Epoch
	ProviderOutcome    ProviderOutcome
	SettlementOutcome  SettlementOutcome
	LeaseExpiresAt     time.Time
	SettlementAttempts int
}

// State is the authoritative security state of one user: the pair
// (current epoch, mutation-intent phase) of ADR-0007 Decision 1.
type State struct {
	Epoch Epoch
	// Intent is the user's non-terminal intent, or nil when none exists
	// (no intent ever, or the last one settled).
	Intent *Intent
}

// ErrIntentHeld is returned when a mutation lease is acquired while a
// non-terminal intent already exists: the concurrent requester fails closed
// before the provider call (stable password.change_in_progress, B4).
var ErrIntentHeld = errors.New("securitystate: mutation intent already held")

// ErrFenceLost is returned when a CAS-fenced intent transition matches no
// row: another worker owns the intent. A fence loser must never advance the
// epoch, overwrite a recorded outcome or perform authoritative settlement.
var ErrFenceLost = errors.New("securitystate: intent fence lost")

// ErrEpochStale is returned when a stamped capability (grant, enrollment)
// carries an epoch behind the user's current epoch: an authoritative,
// permanent death — the capability is treated exactly as if it did not exist.
var ErrEpochStale = errors.New("securitystate: stamped epoch is behind the current epoch")

// ErrBarrierHeld is returned when a non-terminal mutation intent denies a
// sensitive consumption: grants and enrollments stay unusable until the
// intent settles (pre-outcome denies everything; post-epoch denies only
// sensitive consumption).
var ErrBarrierHeld = errors.New("securitystate: mutation intent barrier held")

// Ledger is the durable per-user mutation intent store port. The PostgreSQL
// adapter satisfies it; it is the single authority (ADR-0007 Decision 3 —
// Redis may mirror hot-path fencing at most).
type Ledger interface {
	// GetSecurityState returns the user's current epoch and non-terminal
	// intent (nil when none). A missing user fails closed.
	GetSecurityState(ctx context.Context, userID identity.UserID) (State, error)
	// CurrentEpoch returns the user's authoritative epoch (single indexed
	// point lookup).
	CurrentEpoch(ctx context.Context, userID identity.UserID) (Epoch, error)
	// AcquireIntent transitions the user's lease to active with a fresh
	// monotonic intent id and returns it. It fails closed with
	// ErrIntentHeld while any non-terminal intent exists, stamping
	// epoch_at_acquire from the users row in the same statement.
	AcquireIntent(ctx context.Context, userID identity.UserID, leaseTTL time.Duration) (Intent, error)
	// SettleConfirmedFailure CAS-transitions the active intent straight to
	// settled with provider_outcome confirmed_failure; the epoch is never
	// touched (frozen §6 zero-side-effect semantics).
	SettleConfirmedFailure(ctx context.Context, userID identity.UserID, intentID int64) error
	// RecordOutcomeAdvanceEpoch records the provider outcome and advances
	// the epoch by exactly one in the same transaction, CAS-fenced from
	// active. It returns the new epoch. Epoch advancement is idempotent
	// per intent: a lost fence (ErrFenceLost) never advances the epoch.
	RecordOutcomeAdvanceEpoch(ctx context.Context, userID identity.UserID, intentID int64, outcome ProviderOutcome) (Epoch, error)
	// TakeoverExpiredAdvanceEpoch is the active-past-lease-expiry takeover:
	// CAS from active whose lease has expired, record outcome unknown and
	// advance the epoch exactly once, in one transaction. Recovery never
	// re-invokes the provider.
	TakeoverExpiredAdvanceEpoch(ctx context.Context, userID identity.UserID, intentID int64, now time.Time) (Epoch, error)
	// BeginSettlement CAS-transitions outcome_recorded -> local_settlement.
	BeginSettlement(ctx context.Context, userID identity.UserID, intentID int64) error
	// Settle CAS-transitions local_settlement -> settled, recording the
	// settlement outcome (terminal, immutable afterwards).
	Settle(ctx context.Context, userID identity.UserID, intentID int64, outcome SettlementOutcome) error
	// BumpSettlementAttempts increments and returns the settlement attempt
	// counter of a non-terminal intent (bounded terminalization, F6).
	BumpSettlementAttempts(ctx context.Context, userID identity.UserID, intentID int64) (int, error)
}

// SettlementCleaner is the generation-scoped post-settlement cleanup seam
// (ADR-0007 F4): it physically removes only sessions stamped before the
// new epoch and never touches a session already stamped with it. Satisfied
// by the session service.
type SettlementCleaner interface {
	// RevokeSessionsBeforeEpoch revokes every session of the user whose
	// stamped epoch is lower than newEpoch and returns the revoked count.
	// Infrastructure failures propagate (settlement degrades, never a
	// false success).
	RevokeSessionsBeforeEpoch(ctx context.Context, userID identity.UserID, newEpoch Epoch) (int, error)
}
