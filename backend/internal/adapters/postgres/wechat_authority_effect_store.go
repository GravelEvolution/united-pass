package postgres

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"strconv"
	"strings"
	"time"
	"unicode/utf8"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"

	"github.com/GravelEvolution/united-pass/backend/internal/identity"
)

// WeChatAuthorityFlow identifies the authority mutation family whose replay
// material is being digested. The raw provider tenant and subject are used
// only in memory by DeriveWeChatAuthorityReplayDigest and are never persisted.
type WeChatAuthorityFlow string

const (
	WeChatAuthorityFlowExisting             WeChatAuthorityFlow = "existing"
	WeChatAuthorityFlowPending              WeChatAuthorityFlow = "pending"
	WeChatAuthorityFlowPendingPhoneVerified WeChatAuthorityFlow = "pending_phone_verified"
	// WeChatAuthorityFlowSMSPhoneVerified reuses the existing append-only
	// security notification outbox for an SMS-verified account phone change.
	// Unlike the WeChat flows it has no provider tenant or subject material.
	WeChatAuthorityFlowSMSPhoneVerified WeChatAuthorityFlow = "sms_phone_verified"
)

// WeChatAuthorityEffectKind is a fixed, non-PII description of the authority
// facts committed by one onboarding transaction.
type WeChatAuthorityEffectKind string

const (
	WeChatAuthorityEffectExistingLink         WeChatAuthorityEffectKind = "wechat.existing_linked"
	WeChatAuthorityEffectExistingPhone        WeChatAuthorityEffectKind = "wechat.existing_phone_verified"
	WeChatAuthorityEffectExistingLinkPhone    WeChatAuthorityEffectKind = "wechat.existing_linked_phone_verified"
	WeChatAuthorityEffectPendingReserved      WeChatAuthorityEffectKind = "wechat.pending_reserved"
	WeChatAuthorityEffectPendingPhoneVerified WeChatAuthorityEffectKind = "wechat.pending_phone_verified"
	WeChatAuthorityEffectSMSPhoneVerified     WeChatAuthorityEffectKind = "account.phone_verified"
)

const (
	wechatNotificationPendingEvent   = "notification.pending"
	wechatNotificationDeliveredEvent = "notification.delivered"
	wechatNotificationFailedEvent    = "notification.failed"
)

var (
	// ErrWeChatAuthorityEffectInvalid rejects incomplete or unsafe effect
	// descriptions before any SQL is attempted.
	ErrWeChatAuthorityEffectInvalid = errors.New("postgres: invalid WeChat authority effect")
	// ErrWeChatAuthorityEffectReplayConflict means a deterministic identifier
	// already names different durable facts. Callers must roll back the whole
	// authority transaction; treating this as a successful replay is unsafe.
	ErrWeChatAuthorityEffectReplayConflict = errors.New("postgres: WeChat authority effect replay conflict")
)

// WeChatAuthorityReplayDigest is the only replay material accepted by the
// persistence seam. Its fields are private so callers cannot manufacture a
// digest without DeriveWeChatAuthorityReplayDigest. The safe flow/target
// binding lets RecordTx reject a digest accidentally reused for another user
// or mutation family without retaining raw provider identifiers.
type WeChatAuthorityReplayDigest struct {
	sum    [sha256.Size]byte
	flow   WeChatAuthorityFlow
	target identity.UserID
}

// WeChatAuthorityReplayMaterial is hashed with length-delimited fields. The
// authority revision is the revision observed before an existing-account or
// pending-phone mutation. Initial pending reservations use zero revisions
// because their generated user ID is already a one-lifetime reservation
// identity.
type WeChatAuthorityReplayMaterial struct {
	Flow             WeChatAuthorityFlow
	TenantID         string
	Subject          string
	TargetUserID     identity.UserID
	AuthorityVersion int64
	SecurityEpoch    int64
}

// DeriveWeChatAuthorityReplayDigest returns a stable one-way digest. Phone,
// email, password, provider session and native session material are
// deliberately absent from the input contract.
func DeriveWeChatAuthorityReplayDigest(material WeChatAuthorityReplayMaterial) (WeChatAuthorityReplayDigest, error) {
	if !validWeChatAuthorityFlow(material.Flow) || material.TargetUserID == "" || material.AuthorityVersion < 0 || material.SecurityEpoch < 0 {
		return WeChatAuthorityReplayDigest{}, ErrWeChatAuthorityEffectInvalid
	}
	switch material.Flow {
	case WeChatAuthorityFlowSMSPhoneVerified:
		if material.TenantID != "" || material.Subject != "" || material.AuthorityVersion == 0 || material.SecurityEpoch == 0 {
			return WeChatAuthorityReplayDigest{}, ErrWeChatAuthorityEffectInvalid
		}
	case WeChatAuthorityFlowPending:
		if material.TenantID == "" || material.Subject == "" {
			return WeChatAuthorityReplayDigest{}, ErrWeChatAuthorityEffectInvalid
		}
		if material.AuthorityVersion != 0 || material.SecurityEpoch != 0 {
			return WeChatAuthorityReplayDigest{}, ErrWeChatAuthorityEffectInvalid
		}
	case WeChatAuthorityFlowPendingPhoneVerified:
		if material.TenantID == "" || material.Subject == "" {
			return WeChatAuthorityReplayDigest{}, ErrWeChatAuthorityEffectInvalid
		}
		if material.AuthorityVersion == 0 || material.SecurityEpoch == 0 {
			return WeChatAuthorityReplayDigest{}, ErrWeChatAuthorityEffectInvalid
		}
	default:
		if material.TenantID == "" || material.Subject == "" {
			return WeChatAuthorityReplayDigest{}, ErrWeChatAuthorityEffectInvalid
		}
	}
	hash := sha256.New()
	writeDigestField(hash, "united-pass/wechat-authority-replay/v1")
	writeDigestField(hash, string(material.Flow))
	writeDigestField(hash, material.TenantID)
	writeDigestField(hash, material.Subject)
	writeDigestField(hash, string(material.TargetUserID))
	writeDigestField(hash, strconv.FormatInt(material.AuthorityVersion, 10))
	writeDigestField(hash, strconv.FormatInt(material.SecurityEpoch, 10))
	var sum [sha256.Size]byte
	copy(sum[:], hash.Sum(nil))
	return WeChatAuthorityReplayDigest{sum: sum, flow: material.Flow, target: material.TargetUserID}, nil
}

type digestWriter interface {
	Write([]byte) (int, error)
}

func writeDigestField(hash digestWriter, value string) {
	_, _ = hash.Write([]byte(strconv.Itoa(len(value))))
	_, _ = hash.Write([]byte{':'})
	_, _ = hash.Write([]byte(value))
	_, _ = hash.Write([]byte{'\n'})
}

// WeChatAuthorityEffect is intentionally narrow: it cannot carry provider or
// contact PII. OccurredAt is the first-attempt audit timestamp and is not part
// of replay equality, so a retry with a later clock still resolves to the
// original durable receipt.
type WeChatAuthorityEffect struct {
	ReplayDigest WeChatAuthorityReplayDigest
	Kind         WeChatAuthorityEffectKind
	TargetUserID identity.UserID
	OccurredAt   time.Time
}

// WeChatAuthorityEffectReceipt names the append-only audit and notification
// intent rows. Replayed is true only when both rows already existed; Repaired
// is true when one matching row existed and the other was forward-repaired.
type WeChatAuthorityEffectReceipt struct {
	OperationID     string
	RequestID       string
	Fingerprint     string
	AuditEventID    string
	PendingEventID  string
	NotificationID  string
	Replayed        bool
	ForwardRepaired bool
}

type weChatAuthorityEventTx interface {
	Exec(context.Context, string, ...any) (pgconn.CommandTag, error)
	QueryRow(context.Context, string, ...any) pgx.Row
}

// WeChatAuthorityEffectStore appends the success audit and notification
// intent through the caller's pgx transaction. The caller owns commit and
// MUST roll back the entire authority mutation if this method returns an
// error. No standalone/pool Record method exists by design.
type WeChatAuthorityEffectStore struct{}

func NewWeChatAuthorityEffectStore() *WeChatAuthorityEffectStore {
	return &WeChatAuthorityEffectStore{}
}

func (s *WeChatAuthorityEffectStore) RecordTx(ctx context.Context, tx weChatAuthorityEventTx, effect WeChatAuthorityEffect) (WeChatAuthorityEffectReceipt, error) {
	if s == nil || tx == nil || !validWeChatAuthorityEffect(effect) {
		return WeChatAuthorityEffectReceipt{}, ErrWeChatAuthorityEffectInvalid
	}
	receipt := deriveWeChatAuthorityEffectReceipt(effect)
	audit := durableWeChatAuthorityEvent{
		EventID: receipt.AuditEventID, EventType: string(effect.Kind),
		ActorUserID: effectActor(effect.Kind, effect.TargetUserID),
		RequestID:   receipt.RequestID, OperationID: receipt.OperationID,
		TargetUserID: effect.TargetUserID, Fingerprint: receipt.Fingerprint,
		EffectKind: effect.Kind, NotificationID: receipt.NotificationID,
		Result: "success", OccurredAt: effect.OccurredAt.UTC(),
	}
	pending := durableWeChatAuthorityEvent{
		EventID: receipt.PendingEventID, EventType: wechatNotificationPendingEvent,
		ActorUserID: audit.ActorUserID, RequestID: receipt.RequestID,
		OperationID: receipt.OperationID, TargetUserID: effect.TargetUserID,
		Fingerprint: receipt.Fingerprint, EffectKind: effect.Kind,
		NotificationID: receipt.NotificationID, Result: "success",
		OccurredAt: effect.OccurredAt.UTC(),
	}
	auditInserted, err := appendDeterministicWeChatEvent(ctx, tx, audit)
	if err != nil {
		return WeChatAuthorityEffectReceipt{}, err
	}
	pendingInserted, err := appendDeterministicWeChatEvent(ctx, tx, pending)
	if err != nil {
		return WeChatAuthorityEffectReceipt{}, err
	}
	receipt.Replayed = !auditInserted && !pendingInserted
	receipt.ForwardRepaired = auditInserted != pendingInserted
	return receipt, nil
}

func validWeChatAuthorityFlow(flow WeChatAuthorityFlow) bool {
	return flow == WeChatAuthorityFlowExisting || flow == WeChatAuthorityFlowPending || flow == WeChatAuthorityFlowPendingPhoneVerified || flow == WeChatAuthorityFlowSMSPhoneVerified
}

func validWeChatAuthorityEffect(effect WeChatAuthorityEffect) bool {
	if effect.TargetUserID == "" || effect.OccurredAt.IsZero() || effect.ReplayDigest.sum == ([sha256.Size]byte{}) || effect.ReplayDigest.target != effect.TargetUserID {
		return false
	}
	if !utf8.ValidString(string(effect.TargetUserID)) || len(effect.TargetUserID) > 160 || strings.IndexFunc(string(effect.TargetUserID), func(r rune) bool { return r < 0x20 || r == 0x7f }) >= 0 {
		return false
	}
	switch effect.Kind {
	case WeChatAuthorityEffectExistingLink, WeChatAuthorityEffectExistingPhone, WeChatAuthorityEffectExistingLinkPhone:
		return effect.ReplayDigest.flow == WeChatAuthorityFlowExisting
	case WeChatAuthorityEffectPendingReserved:
		return effect.ReplayDigest.flow == WeChatAuthorityFlowPending
	case WeChatAuthorityEffectPendingPhoneVerified:
		return effect.ReplayDigest.flow == WeChatAuthorityFlowPendingPhoneVerified
	case WeChatAuthorityEffectSMSPhoneVerified:
		return effect.ReplayDigest.flow == WeChatAuthorityFlowSMSPhoneVerified
	default:
		return false
	}
}

func effectActor(kind WeChatAuthorityEffectKind, target identity.UserID) identity.UserID {
	if kind == WeChatAuthorityEffectPendingReserved || kind == WeChatAuthorityEffectPendingPhoneVerified {
		return ""
	}
	return target
}

func deriveWeChatAuthorityEffectReceipt(effect WeChatAuthorityEffect) WeChatAuthorityEffectReceipt {
	operationID := deterministicWeChatID("wxo_", "operation", effect.ReplayDigest.sum[:])
	requestID := deterministicWeChatID("wxr_", "request", []byte(operationID))
	notificationID := deterministicWeChatID("wxn_", "notification", []byte(operationID))
	return WeChatAuthorityEffectReceipt{
		OperationID: operationID, RequestID: requestID,
		Fingerprint:    weChatAuthorityEffectFingerprint(operationID, effect.Kind, effect.TargetUserID),
		AuditEventID:   deterministicWeChatID("evt_", "audit", []byte(operationID)),
		PendingEventID: deterministicWeChatID("evt_", wechatNotificationPendingEvent, []byte(operationID)),
		NotificationID: notificationID,
	}
}

func weChatAuthorityEffectFingerprint(operationID string, kind WeChatAuthorityEffectKind, target identity.UserID) string {
	fingerprintHash := sha256.New()
	writeDigestField(fingerprintHash, "united-pass/wechat-authority-effect-fingerprint/v1")
	writeDigestField(fingerprintHash, operationID)
	writeDigestField(fingerprintHash, string(kind))
	writeDigestField(fingerprintHash, string(target))
	return hex.EncodeToString(fingerprintHash.Sum(nil))
}

func deterministicWeChatID(prefix, scope string, material []byte) string {
	hash := sha256.New()
	writeDigestField(hash, "united-pass/wechat-authority-id/v1")
	writeDigestField(hash, scope)
	_, _ = hash.Write(material)
	return prefix + hex.EncodeToString(hash.Sum(nil)[:16])
}

type durableWeChatAuthorityEvent struct {
	EventID        string
	EventType      string
	ActorUserID    identity.UserID
	RequestID      string
	OperationID    string
	TargetUserID   identity.UserID
	Fingerprint    string
	EffectKind     WeChatAuthorityEffectKind
	NotificationID string
	FailureClass   string
	Result         string
	OccurredAt     time.Time
}

const insertDeterministicWeChatEventSQL = `
INSERT INTO security_events
       (event_id,event_type,actor_user_id,application_id,client_id,request_id,
        operation,result,payload,occurred_at,target_kind,target_id)
VALUES ($1,$2,$3,'','',$4,$5,$6,$7,$8,'user_id',$9)
ON CONFLICT(event_id) DO NOTHING`

const selectDeterministicWeChatEventSQL = `
SELECT event_type,actor_user_id,request_id,operation,result,target_kind,target_id,
       payload->>'operation_fingerprint',payload->>'effect_kind',
       payload->>'notification_id',COALESCE(payload->>'failure_class','')
  FROM security_events
 WHERE event_id=$1`

func appendDeterministicWeChatEvent(ctx context.Context, tx weChatAuthorityEventTx, event durableWeChatAuthorityEvent) (bool, error) {
	payload := map[string]string{
		"operation_fingerprint": event.Fingerprint,
		"effect_kind":           string(event.EffectKind),
		"notification_id":       event.NotificationID,
	}
	if event.FailureClass != "" {
		payload["failure_class"] = event.FailureClass
	}
	rawPayload, err := json.Marshal(payload)
	if err != nil {
		return false, fmt.Errorf("postgres: encode deterministic WeChat event: %w", err)
	}
	tag, err := tx.Exec(ctx, insertDeterministicWeChatEventSQL,
		event.EventID, event.EventType, string(event.ActorUserID), event.RequestID,
		event.OperationID, event.Result, rawPayload, event.OccurredAt, string(event.TargetUserID),
	)
	if err != nil {
		return false, fmt.Errorf("postgres: append deterministic WeChat event: %w", err)
	}
	inserted := tag.RowsAffected() == 1
	var stored durableWeChatAuthorityEvent
	var targetKind string
	err = tx.QueryRow(ctx, selectDeterministicWeChatEventSQL, event.EventID).Scan(
		&stored.EventType, &stored.ActorUserID, &stored.RequestID, &stored.OperationID,
		&stored.Result, &targetKind, &stored.TargetUserID, &stored.Fingerprint,
		&stored.EffectKind, &stored.NotificationID, &stored.FailureClass,
	)
	if err != nil {
		return false, fmt.Errorf("postgres: verify deterministic WeChat event: %w", err)
	}
	if targetKind != "user_id" || !sameDurableWeChatAuthorityEvent(stored, event) {
		return false, ErrWeChatAuthorityEffectReplayConflict
	}
	return inserted, nil
}

func sameDurableWeChatAuthorityEvent(stored, expected durableWeChatAuthorityEvent) bool {
	return stored.EventType == expected.EventType &&
		stored.ActorUserID == expected.ActorUserID &&
		stored.RequestID == expected.RequestID &&
		stored.OperationID == expected.OperationID &&
		stored.TargetUserID == expected.TargetUserID &&
		stored.Fingerprint == expected.Fingerprint &&
		stored.EffectKind == expected.EffectKind &&
		stored.NotificationID == expected.NotificationID &&
		stored.FailureClass == expected.FailureClass &&
		stored.Result == expected.Result
}

func terminalWeChatNotificationEvent(pending WeChatNotificationIntent, eventType, failureClass string, at time.Time) durableWeChatAuthorityEvent {
	return durableWeChatAuthorityEvent{
		EventID:     deterministicWeChatID("evt_", eventType, []byte(pending.OperationID)),
		EventType:   eventType,
		ActorUserID: effectActor(pending.EffectKind, pending.TargetUserID),
		RequestID:   pending.RequestID,
		OperationID: pending.OperationID, TargetUserID: pending.TargetUserID,
		Fingerprint: pending.Fingerprint, EffectKind: pending.EffectKind,
		NotificationID: pending.NotificationID, FailureClass: failureClass,
		Result: func() string {
			if eventType == wechatNotificationFailedEvent {
				return "denied"
			}
			return "success"
		}(),
		OccurredAt: at.UTC(),
	}
}
