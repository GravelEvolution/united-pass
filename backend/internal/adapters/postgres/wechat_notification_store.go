package postgres

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/GravelEvolution/united-pass/backend/internal/identity"
)

var (
	ErrWeChatNotificationBusy     = errors.New("postgres: WeChat notification is already being dispatched")
	ErrWeChatNotificationNotReady = errors.New("postgres: WeChat notification target is not ready")
	// ErrWeChatNotificationTransient intentionally discards the transport's
	// raw error because provider errors can contain a destination or token.
	ErrWeChatNotificationTransient = errors.New("postgres: transient WeChat notification delivery failure")
	// ErrWeChatNotificationTargetLookup is also deliberately opaque: a scan
	// or driver error for the email column must not be propagated into logs.
	ErrWeChatNotificationTargetLookup = errors.New("postgres: WeChat notification target lookup failed")
)

// WeChatNotificationIntent is a durable, append-only notification intent
// reconstructed from security_events. It contains no contact destination or
// provider identifier.
type WeChatNotificationIntent struct {
	PendingEventID string
	OperationID    string
	RequestID      string
	NotificationID string
	Fingerprint    string
	EffectKind     WeChatAuthorityEffectKind
	TargetUserID   identity.UserID
	OccurredAt     time.Time
}

// WeChatNotificationDelivery exists only in worker memory. Destination must
// never be logged or copied into security_events. NotificationID is the
// mandatory downstream idempotency key (or deterministic RFC Message-ID).
type WeChatNotificationDelivery struct {
	NotificationID string
	Kind           WeChatAuthorityEffectKind
	TargetUserID   identity.UserID
	Destination    string
}

type WeChatNotificationSender interface {
	Send(context.Context, WeChatNotificationDelivery) error
}

// WeChatNotificationSendFailure lets a transport expose only a fixed safe
// failure class. Transient failures leave the pending intent open for retry;
// permanent failures append notification.failed.
type WeChatNotificationSendFailure interface {
	error
	Permanent() bool
	SafeFailureClass() string
}

type weChatNotificationDB interface {
	Query(context.Context, string, ...any) (pgx.Rows, error)
	BeginTx(context.Context, pgx.TxOptions) (pgx.Tx, error)
}

// WeChatNotificationStore treats security_events as an append-only outbox.
// It does not mutate audit rows and requires no authority migration past v13.
type WeChatNotificationStore struct {
	db weChatNotificationDB
}

func NewWeChatNotificationStore(pool *pgxpool.Pool) *WeChatNotificationStore {
	return &WeChatNotificationStore{db: pool}
}

const listPendingWeChatNotificationsSQL = `
SELECT p.event_id,p.operation,p.request_id,p.target_id,
       p.payload->>'notification_id',p.payload->>'operation_fingerprint',
       p.payload->>'effect_kind',p.occurred_at
  FROM security_events AS p
  LEFT JOIN users AS target ON target.id=p.target_id
 WHERE p.event_type='notification.pending'
   AND p.result='success'
   AND p.target_kind='user_id'
   AND NOT EXISTS (
       SELECT 1
         FROM security_events AS terminal
        WHERE terminal.operation=p.operation
          AND terminal.event_type IN ('notification.delivered','notification.failed')
          AND terminal.payload->>'notification_id'=p.payload->>'notification_id'
          AND terminal.payload->>'operation_fingerprint'=p.payload->>'operation_fingerprint'
          AND terminal.payload->>'effect_kind'=p.payload->>'effect_kind'
          AND terminal.target_kind=p.target_kind
          AND terminal.target_id=p.target_id
   )
   AND (
       target.id IS NULL
       OR target.status='disabled'
       OR (target.status='active' AND target.email_verified AND target.email<>'')
   )
 ORDER BY p.occurred_at,p.event_id
 LIMIT $1`

// ListPending returns immutable candidates. Dispatch rechecks each candidate
// under an advisory transaction lock, so this read never acts as a claim.
func (s *WeChatNotificationStore) ListPending(ctx context.Context, limit int) ([]WeChatNotificationIntent, error) {
	if s == nil || s.db == nil || limit < 1 || limit > 200 {
		return nil, ErrWeChatAuthorityEffectInvalid
	}
	rows, err := s.db.Query(ctx, listPendingWeChatNotificationsSQL, limit)
	if err != nil {
		return nil, fmt.Errorf("postgres: list pending WeChat notifications: %w", err)
	}
	defer rows.Close()
	intents := make([]WeChatNotificationIntent, 0, limit)
	for rows.Next() {
		var intent WeChatNotificationIntent
		if err := rows.Scan(&intent.PendingEventID, &intent.OperationID, &intent.RequestID,
			&intent.TargetUserID, &intent.NotificationID, &intent.Fingerprint,
			&intent.EffectKind, &intent.OccurredAt); err != nil {
			return nil, fmt.Errorf("postgres: scan pending WeChat notification: %w", err)
		}
		if !validWeChatNotificationIntent(intent) {
			return nil, ErrWeChatAuthorityEffectReplayConflict
		}
		intents = append(intents, intent)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("postgres: iterate pending WeChat notifications: %w", err)
	}
	return intents, nil
}

const loadPendingWeChatNotificationSQL = `
SELECT p.event_id,p.operation,p.request_id,p.target_id,
       p.payload->>'notification_id',p.payload->>'operation_fingerprint',
       p.payload->>'effect_kind',p.occurred_at
  FROM security_events AS p
 WHERE p.event_id=$1
   AND p.event_type='notification.pending'
   AND p.result='success'
   AND p.target_kind='user_id'
   AND NOT EXISTS (
       SELECT 1
         FROM security_events AS terminal
        WHERE terminal.operation=p.operation
          AND terminal.event_type IN ('notification.delivered','notification.failed')
          AND terminal.payload->>'notification_id'=p.payload->>'notification_id'
          AND terminal.payload->>'operation_fingerprint'=p.payload->>'operation_fingerprint'
          AND terminal.payload->>'effect_kind'=p.payload->>'effect_kind'
          AND terminal.target_kind=p.target_kind
          AND terminal.target_id=p.target_id
   )`

// Dispatch rechecks one pending intent while holding a PostgreSQL advisory
// transaction lock. The external sender must honor NotificationID as an
// idempotency key. A process crash after Send succeeds but before the
// delivered event commits can otherwise cause an at-least-once duplicate.
func (s *WeChatNotificationStore) Dispatch(ctx context.Context, candidate WeChatNotificationIntent, sender WeChatNotificationSender, now time.Time) error {
	if s == nil || s.db == nil || sender == nil || now.IsZero() || !validWeChatNotificationIntent(candidate) {
		return ErrWeChatAuthorityEffectInvalid
	}
	tx, err := s.db.BeginTx(ctx, pgx.TxOptions{IsoLevel: pgx.ReadCommitted})
	if err != nil {
		return fmt.Errorf("postgres: begin WeChat notification dispatch: %w", err)
	}
	defer func() { _ = tx.Rollback(ctx) }()

	var locked bool
	if err := tx.QueryRow(ctx, `SELECT pg_try_advisory_xact_lock(hashtextextended($1,0))`, candidate.OperationID).Scan(&locked); err != nil {
		return fmt.Errorf("postgres: lock WeChat notification: %w", err)
	}
	if !locked {
		return ErrWeChatNotificationBusy
	}

	current, err := scanWeChatNotificationIntent(tx.QueryRow(ctx, loadPendingWeChatNotificationSQL, candidate.PendingEventID))
	if errors.Is(err, pgx.ErrNoRows) {
		// Another worker already appended a terminal event. This is an
		// idempotent no-op, not a delivery failure.
		return nil
	}
	if err != nil {
		return fmt.Errorf("postgres: recheck WeChat notification: %w", err)
	}
	if !sameWeChatNotificationIntent(current, candidate) || !validWeChatNotificationIntent(current) {
		return ErrWeChatAuthorityEffectReplayConflict
	}

	var status, destination string
	var emailVerified bool
	err = tx.QueryRow(ctx, `SELECT status,email,email_verified FROM users WHERE id=$1`, string(current.TargetUserID)).Scan(&status, &destination, &emailVerified)
	if errors.Is(err, pgx.ErrNoRows) {
		if err := appendWeChatNotificationTerminal(ctx, tx, current, wechatNotificationFailedEvent, "target_missing", now); err != nil {
			return err
		}
		return tx.Commit(ctx)
	}
	if err != nil {
		return ErrWeChatNotificationTargetLookup
	}
	// A new pending reservation becomes deliverable only after its existing
	// email-verification lifecycle activates the account. The outbox never
	// stores the email while it waits.
	if status == "disabled" {
		if err := appendWeChatNotificationTerminal(ctx, tx, current, wechatNotificationFailedEvent, "target_ineligible", now); err != nil {
			return err
		}
		return tx.Commit(ctx)
	}
	if destination == "" || !emailVerified || status != "active" {
		return ErrWeChatNotificationNotReady
	}

	delivery := WeChatNotificationDelivery{
		NotificationID: current.NotificationID,
		Kind:           current.EffectKind,
		TargetUserID:   current.TargetUserID,
		Destination:    destination,
	}
	if sendErr := sender.Send(ctx, delivery); sendErr != nil {
		var classified WeChatNotificationSendFailure
		if !errors.As(sendErr, &classified) || !classified.Permanent() {
			return ErrWeChatNotificationTransient
		}
		failureClass := classified.SafeFailureClass()
		if !validWeChatNotificationFailureClass(failureClass) {
			failureClass = "transport_rejected"
		}
		if err := appendWeChatNotificationTerminal(ctx, tx, current, wechatNotificationFailedEvent, failureClass, now); err != nil {
			return err
		}
		return tx.Commit(ctx)
	}
	if err := appendWeChatNotificationTerminal(ctx, tx, current, wechatNotificationDeliveredEvent, "", now); err != nil {
		return err
	}
	return tx.Commit(ctx)
}

func scanWeChatNotificationIntent(row pgx.Row) (WeChatNotificationIntent, error) {
	var intent WeChatNotificationIntent
	err := row.Scan(&intent.PendingEventID, &intent.OperationID, &intent.RequestID,
		&intent.TargetUserID, &intent.NotificationID, &intent.Fingerprint,
		&intent.EffectKind, &intent.OccurredAt)
	return intent, err
}

func validWeChatNotificationIntent(intent WeChatNotificationIntent) bool {
	if intent.OperationID == "" || intent.RequestID == "" || intent.NotificationID == "" || intent.PendingEventID == "" || intent.TargetUserID == "" || intent.OccurredAt.IsZero() {
		return false
	}
	if intent.PendingEventID != deterministicWeChatID("evt_", wechatNotificationPendingEvent, []byte(intent.OperationID)) ||
		intent.RequestID != deterministicWeChatID("wxr_", "request", []byte(intent.OperationID)) ||
		intent.NotificationID != deterministicWeChatID("wxn_", "notification", []byte(intent.OperationID)) ||
		intent.Fingerprint != weChatAuthorityEffectFingerprint(intent.OperationID, intent.EffectKind, intent.TargetUserID) {
		return false
	}
	if !strings.HasPrefix(intent.OperationID, "wxo_") || len(intent.OperationID) != len("wxo_")+32 {
		return false
	}
	switch intent.EffectKind {
	case WeChatAuthorityEffectExistingLink, WeChatAuthorityEffectExistingPhone, WeChatAuthorityEffectExistingLinkPhone, WeChatAuthorityEffectPendingReserved, WeChatAuthorityEffectPendingPhoneVerified:
		return true
	default:
		return false
	}
}

func sameWeChatNotificationIntent(left, right WeChatNotificationIntent) bool {
	return left.PendingEventID == right.PendingEventID &&
		left.OperationID == right.OperationID && left.RequestID == right.RequestID &&
		left.NotificationID == right.NotificationID && left.Fingerprint == right.Fingerprint &&
		left.EffectKind == right.EffectKind && left.TargetUserID == right.TargetUserID
}

func appendWeChatNotificationTerminal(ctx context.Context, tx weChatAuthorityEventTx, intent WeChatNotificationIntent, eventType, failureClass string, at time.Time) error {
	if eventType != wechatNotificationDeliveredEvent && eventType != wechatNotificationFailedEvent {
		return ErrWeChatAuthorityEffectInvalid
	}
	_, err := appendDeterministicWeChatEvent(ctx, tx, terminalWeChatNotificationEvent(intent, eventType, failureClass, at))
	return err
}

func validWeChatNotificationFailureClass(value string) bool {
	switch value {
	case "target_missing", "target_ineligible", "transport_rejected", "provider_rejected":
		return true
	default:
		return false
	}
}
