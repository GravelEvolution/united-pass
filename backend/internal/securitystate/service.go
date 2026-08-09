//
// Copyright (c) 2026 Chen Jiajie(Ariakage)
//
// Author: Chen Jiajie(Ariakage) <ariakage233@gmail.com>
// Date: 2026-08-06
// Description: Security-state validator, mutation lifecycle and takeover/recovery (ADR-0007)
//

package securitystate

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"sync"
	"time"

	"github.com/GravelEvolution/united-pass/backend/internal/identity"
)

// PromotionVerdict is the outcome of the shared authoritative
// security-state validation applied by every session-to-principal
// promotion path (ADR-0007 F1). The epoch read, the active-intent check
// and their fail-closed semantics live here exactly once.
type PromotionVerdict int

const (
	// PromotionAllowed: the session is stamped with the current epoch and
	// no pre-outcome barrier stands in the way; the path may promote.
	PromotionAllowed PromotionVerdict = iota
	// PromotionEpochStale: the session's stamped epoch is lower than the
	// user's current epoch — an authoritative, permanent death. This is
	// the single pinned exception to the frozen "authentication failure
	// does not clear cookies" rule: both cookies are cleared on both
	// promotion paths.
	PromotionEpochStale
	// PromotionDeniedTransient: fail-closed denial without cookie
	// clearing — either a pre-outcome active intent (the pending mutation
	// is itself the barrier; on confirmed failure the old generation
	// resumes validity) or an authoritative-lookup failure (PostgreSQL
	// outage). Tokens that may still be valid are never destroyed.
	PromotionDeniedTransient
)

// BarrierActive reports whether the state carries a pre-outcome active
// intent (all promotion denied, sensitive consumption denied, further
// mutations denied).
func BarrierActive(state State) bool {
	return state.Intent != nil && state.Intent.Status == IntentActive
}

// BarrierSensitive reports whether a non-terminal intent exists in any
// phase: grant consumption, enrollment confirmation and further password
// mutations stay denied until settled (pre-outcome denies everything,
// post-epoch denies only sensitive consumption).
func BarrierSensitive(state State) bool {
	return state.Intent != nil && !state.Intent.Status.Terminal()
}

// Service orchestrates the authoritative security boundary: promotion
// validation, the single-winner mutation lifecycle and opportunistic
// takeover/recovery of abandoned intents (ADR-0007 Decision 3, F6).
type Service struct {
	ledger                Ledger
	cleaner               SettlementCleaner
	now                   func() time.Time
	leaseTTL              time.Duration
	maxSettlementAttempts int
	recoveryTimeout       time.Duration
	logger                *slog.Logger

	// inFlight dedupes concurrent opportunistic recovery triggers per
	// user; the recovery itself is CAS-fenced and idempotent either way.
	inFlight sync.Map // identity.UserID -> struct{}
}

// Option customizes optional Service parameters.
type Option func(*Service)

// WithClock replaces the wall clock (tests).
func WithClock(now func() time.Time) Option {
	return func(s *Service) { s.now = now }
}

// WithLogger wires the structured logger.
func WithLogger(l *slog.Logger) Option {
	return func(s *Service) { s.logger = l }
}

// WithMaxSettlementAttempts bounds takeover settlement retries before the
// intent is force-settled degraded (F6 bounded terminalization).
func WithMaxSettlementAttempts(n int) Option {
	return func(s *Service) {
		if n > 0 {
			s.maxSettlementAttempts = n
		}
	}
}

// WithRecoveryTimeout bounds each detached opportunistic recovery run.
func WithRecoveryTimeout(d time.Duration) Option {
	return func(s *Service) {
		if d > 0 {
			s.recoveryTimeout = d
		}
	}
}

// NewService builds the security-state service. cleaner may only be nil in
// tests that never exercise settlement; production wiring always provides
// the session service.
func NewService(ledger Ledger, cleaner SettlementCleaner, leaseTTL time.Duration, opts ...Option) *Service {
	s := &Service{
		ledger:                ledger,
		cleaner:               cleaner,
		now:                   func() time.Time { return time.Now() },
		leaseTTL:              leaseTTL,
		maxSettlementAttempts: 3,
		recoveryTimeout:       15 * time.Second,
	}
	for _, opt := range opts {
		opt(s)
	}
	return s
}

// SetCleaner wires the settlement cleaner after construction. The session
// service depends on this service for epoch stamping while this service
// depends on the session service for generation-scoped cleanup; the
// composition root resolves that cycle here, before the server accepts
// traffic. Settlement fails closed while the cleaner is unset.
func (s *Service) SetCleaner(cleaner SettlementCleaner) {
	s.cleaner = cleaner
}

// CurrentEpoch returns the user's authoritative security generation — a
// single indexed point lookup used to stamp newly created sessions.
func (s *Service) CurrentEpoch(ctx context.Context, userID identity.UserID) (Epoch, error) {
	return s.ledger.CurrentEpoch(ctx, userID)
}

// SecurityState returns the authoritative (epoch, intent phase) pair.
func (s *Service) SecurityState(ctx context.Context, userID identity.UserID) (State, error) {
	return s.ledger.GetSecurityState(ctx, userID)
}

// EvaluatePromotion is the one shared security-state validation applied by
// every session-to-principal promotion path (RequireSession and
// OptionalSession both invoke it; no path promotes without it). recordEpoch
// is the session's stamped epoch. The second return reports whether a
// non-terminal intent was observed — callers fire an opportunistic recovery
// trigger on it.
//
// Post-epoch phases (outcome_recorded / local_settlement) allow ordinary
// promotion of current-epoch sessions: the atomic outcome-record + epoch
// advancement has already established the credential boundary (F6, Option
// B). Pre-outcome active intents deny everything; an expired active lease
// still denies until takeover completes (the barrier never weakens early).
func (s *Service) EvaluatePromotion(ctx context.Context, userID identity.UserID, recordEpoch Epoch) (PromotionVerdict, bool) {
	state, err := s.ledger.GetSecurityState(ctx, userID)
	if err != nil {
		// Fail closed, no cookie clearing: a transient lookup failure must
		// not destroy tokens that may still be valid.
		return PromotionDeniedTransient, false
	}
	if state.Intent == nil {
		if recordEpoch < state.Epoch {
			return PromotionEpochStale, false
		}
		return PromotionAllowed, false
	}
	if state.Intent.Status == IntentActive {
		// Pre-outcome barrier: all promotion denied (fail closed); the
		// executing mutation request completed validation before acquiring
		// the intent and never re-enters the middleware, so it is not
		// caught by its own barrier.
		return PromotionDeniedTransient, true
	}
	// Post-epoch phase: old-epoch sessions stay denied (stale rule);
	// current-epoch sessions ordinarily promote. Settlement is resumed
	// opportunistically.
	if recordEpoch < state.Epoch {
		return PromotionEpochStale, true
	}
	return PromotionAllowed, true
}

// AllowSensitiveConsumption validates the consumption of a sensitive
// capability (reauth grant, enrollment token) stamped with stampedEpoch
// against the user's authoritative state (ADR-0007 Decision 5, two-phase
// barrier): the stamp must not be behind the current epoch, and no
// non-terminal intent may exist — sensitive consumption stays denied until
// settled in every barrier phase. Lookup failures fail closed.
func (s *Service) AllowSensitiveConsumption(ctx context.Context, userID identity.UserID, stampedEpoch Epoch) error {
	state, err := s.ledger.GetSecurityState(ctx, userID)
	if err != nil {
		return fmt.Errorf("securitystate: consumption gate state read: %w", err)
	}
	if stampedEpoch < state.Epoch {
		return ErrEpochStale
	}
	if BarrierSensitive(state) {
		return ErrBarrierHeld
	}
	return nil
}

// Acquire establishes the durable, per-user, fail-closed mutation intent
// before any provider call (single-winner gate, closes B4). An abandoned
// intent is opportunistically recovered first so a crashed predecessor
// never blocks a legitimate new mutation past its bounded takeover.
func (s *Service) Acquire(ctx context.Context, userID identity.UserID) (Intent, error) {
	if err := s.Recover(ctx, userID); err != nil {
		s.lg().Warn("opportunistic intent recovery before acquisition failed",
			"userId", string(userID),
			"error", err.Error(),
		)
		// Fall through: acquisition still fails closed against any
		// surviving non-terminal intent.
	}
	return s.ledger.AcquireIntent(ctx, userID, s.leaseTTL)
}

// SettleConfirmedFailure settles the active intent with the epoch
// unchanged after a confirmed provider failure: zero local side effects,
// the old generation resumes validity (frozen §6 semantics).
func (s *Service) SettleConfirmedFailure(ctx context.Context, userID identity.UserID, intentID int64) error {
	return s.ledger.SettleConfirmedFailure(ctx, userID, intentID)
}

// RecordOutcome records the provider outcome and — for success/unknown —
// advances the epoch by exactly one in the same CAS-fenced transaction
// (the ordering invariant: epoch advancement is the first local effect
// after the provider outcome is known). It returns the new epoch. Callers
// must run this under a detached, bounded context.
func (s *Service) RecordOutcome(ctx context.Context, userID identity.UserID, intentID int64, outcome ProviderOutcome) (Epoch, error) {
	if !outcome.AdvancesEpoch() {
		return 0, errors.New("securitystate: record outcome requires success or unknown")
	}
	return s.ledger.RecordOutcomeAdvanceEpoch(ctx, userID, intentID, outcome)
}

// RotateFunc runs the current-session rotation inside the settlement
// fence. vanished reports a session that disappeared (a concurrent
// logout/revocation won the race); a non-nil error is an infrastructure
// failure. Recovery passes nil: it holds no raw token and the crashed
// request's client is gone.
type RotateFunc func(ctx context.Context) (vanished bool, err error)

// SettlementResult carries the terminal settlement classification and
// whether the rotation succeeded (so the caller can re-issue rotated
// credentials and not strand the user).
type SettlementResult struct {
	Outcome SettlementOutcome
	Rotated bool
}

// SettleIntent drives the local_settlement phase of one intent whose
// outcome was already recorded: CAS into local_settlement, rotate (when a
// rotate function is supplied), generation-scoped cleanup of pre-epoch
// sessions only, then the terminal CAS into settled. Every branch resolves
// to exactly one matrix row; cleanup failures degrade the settlement but
// never undo the epoch boundary.
func (s *Service) SettleIntent(ctx context.Context, intent Intent, newEpoch Epoch, rotate RotateFunc) (SettlementResult, error) {
	if s.cleaner == nil {
		return SettlementResult{}, errors.New("securitystate: settlement cleaner not configured")
	}
	if intent.Status != IntentOutcomeRecorded && intent.Status != IntentLocalSettlement {
		return SettlementResult{}, fmt.Errorf("securitystate: cannot settle intent in status %q", intent.Status)
	}
	userID := intent.UserID

	// Claim the settlement phase. Recovery resuming an intent already in
	// local_settlement skips this step.
	if intent.Status == IntentOutcomeRecorded {
		if err := s.ledger.BeginSettlement(ctx, userID, intent.IntentID); err != nil {
			return SettlementResult{}, err
		}
	}

	var rotated, vanished, rotateFailed bool
	if rotate != nil {
		gone, err := rotate(ctx)
		switch {
		case err != nil:
			rotateFailed = true
		case gone:
			vanished = true
		default:
			rotated = true
		}
	}

	// Generation-scoped cleanup (F4): only sessions stamped before the new
	// epoch are ever touched; a fresh new-generation login survives.
	if _, err := s.cleaner.RevokeSessionsBeforeEpoch(ctx, userID, newEpoch); err != nil {
		// Settle degraded so the intent still terminalizes; the error is
		// returned afterwards so the caller reports a degraded settlement.
		if serr := s.ledger.Settle(ctx, userID, intent.IntentID, SettlementOutcomeDegraded); serr != nil && !errors.Is(serr, ErrFenceLost) {
			s.lg().Error("settlement degrade transition failed",
				"userId", string(userID),
				"intentId", intent.IntentID,
				"error", serr.Error(),
			)
		}
		return SettlementResult{Outcome: SettlementOutcomeDegraded, Rotated: rotated}, err
	}

	outcome := SettlementOutcomeSettled
	switch {
	case intent.ProviderOutcome == ProviderOutcomeUnknown:
		// Unknown is treated as committed: the response never reports
		// success and re-login is forced (matrix row 5).
		outcome = SettlementOutcomeDegraded
	case rotateFailed:
		outcome = SettlementOutcomeDegraded
	case rotate != nil && vanished:
		outcome = SettlementOutcomeSettledRelogin
	}

	if err := s.ledger.Settle(ctx, userID, intent.IntentID, outcome); err != nil {
		return SettlementResult{}, err
	}
	return SettlementResult{Outcome: outcome, Rotated: rotated}, nil
}

// Recover drives the post-provider takeover/recovery matrix (F6): every
// non-terminal state gets a CAS-fenced exit to settled. Recovery never
// re-invokes the provider, never rewrites a recorded provider outcome and
// never advances the epoch twice. It is idempotent: concurrent invocations
// race through the same CAS fences and exactly one wins each transition.
func (s *Service) Recover(ctx context.Context, userID identity.UserID) error {
	state, err := s.ledger.GetSecurityState(ctx, userID)
	if err != nil {
		return fmt.Errorf("securitystate: recovery state read: %w", err)
	}
	if state.Intent == nil {
		return nil
	}
	intent := *state.Intent

	switch intent.Status {
	case IntentSettled:
		return nil
	case IntentActive:
		// Only an expired lease may be taken over: a live provider call
		// still owns its fence (lease expiry strictly outlives the
		// provider deadline plus the frozen safety margin).
		if s.now().Before(intent.LeaseExpiresAt) {
			return nil
		}
		newEpoch, err := s.ledger.TakeoverExpiredAdvanceEpoch(ctx, userID, intent.IntentID, s.now())
		if errors.Is(err, ErrFenceLost) {
			return nil // another worker won the takeover
		}
		if err != nil {
			return fmt.Errorf("securitystate: takeover expired intent: %w", err)
		}
		state.Epoch = newEpoch
		intent.Status = IntentOutcomeRecorded
		intent.ProviderOutcome = ProviderOutcomeUnknown
	case IntentOutcomeRecorded, IntentLocalSettlement:
		// Resume: the recorded providerOutcome is never changed and the
		// epoch never advances again.
	}

	// Bounded terminalization: after bounded attempts the intent settles
	// degraded — terminalization can never stall.
	attempts, err := s.ledger.BumpSettlementAttempts(ctx, userID, intent.IntentID)
	if errors.Is(err, ErrFenceLost) {
		return nil
	}
	if err != nil {
		return fmt.Errorf("securitystate: bump settlement attempts: %w", err)
	}
	if attempts > s.maxSettlementAttempts {
		return s.forceDegrade(ctx, intent)
	}

	result, err := s.SettleIntent(ctx, intent, state.Epoch, nil)
	if err != nil {
		if errors.Is(err, ErrFenceLost) {
			return nil
		}
		// Cleanup degraded the settlement (already settled degraded in the
		// ledger) or a transition failed transiently: surface for the next
		// bounded attempt.
		return err
	}
	_ = result
	return nil
}

// forceDegrade settles an intent degraded when bounded settlement attempts
// are exhausted, handling whichever non-terminal phase it is in.
func (s *Service) forceDegrade(ctx context.Context, intent Intent) error {
	if intent.Status == IntentOutcomeRecorded {
		if err := s.ledger.BeginSettlement(ctx, intent.UserID, intent.IntentID); err != nil && !errors.Is(err, ErrFenceLost) {
			return fmt.Errorf("securitystate: force-degrade begin settlement: %w", err)
		} else if errors.Is(err, ErrFenceLost) {
			return nil
		}
	}
	if err := s.ledger.Settle(ctx, intent.UserID, intent.IntentID, SettlementOutcomeDegraded); err != nil && !errors.Is(err, ErrFenceLost) {
		return fmt.Errorf("securitystate: force-degrade settle: %w", err)
	}
	s.lg().Warn("abandoned mutation intent force-settled degraded after bounded attempts",
		"userId", string(intent.UserID),
		"intentId", intent.IntentID,
	)
	return nil
}

// TriggerRecovery fires an opportunistic, detached, bounded recovery run
// for the user in a background goroutine. Concurrent triggers are deduped
// per user; every takeover path is CAS-fenced and bounded, so a stale or
// duplicate trigger can never corrupt the ledger.
func (s *Service) TriggerRecovery(userID identity.UserID) {
	if _, loaded := s.inFlight.LoadOrStore(userID, struct{}{}); loaded {
		return
	}
	go func() {
		defer s.inFlight.Delete(userID)
		ctx, cancel := context.WithTimeout(context.WithoutCancel(context.Background()), s.recoveryTimeout)
		defer cancel()
		if err := s.Recover(ctx, userID); err != nil {
			s.lg().Warn("opportunistic intent recovery failed",
				"userId", string(userID),
				"error", err.Error(),
			)
		}
	}()
}

// lg returns the configured logger or the slog default.
func (s *Service) lg() *slog.Logger {
	if s.logger != nil {
		return s.logger
	}
	return slog.Default()
}
