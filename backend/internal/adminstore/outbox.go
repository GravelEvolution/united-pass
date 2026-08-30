package adminstore

import (
	"context"
	"encoding/json"
	"errors"
	"regexp"
	"strconv"
	"strings"
	"time"
)

type OperationKind string

const (
	OperationLocal       OperationKind = "local"
	OperationCrossSystem OperationKind = "cross_system"
	OperationRedisPurge  OperationKind = "redis_purge"
)

type DeliveryPhase string

const (
	DeliveryPhaseNotSent       DeliveryPhase = "not_sent"
	DeliveryPhaseIndeterminate DeliveryPhase = "indeterminate"
	DeliveryPhaseSent          DeliveryPhase = "sent"
)

func (p DeliveryPhase) Valid() bool {
	return p == DeliveryPhaseNotSent || p == DeliveryPhaseIndeterminate || p == DeliveryPhaseSent
}

var (
	ErrIdempotencyConflict    = errors.New("adminstore: idempotency conflict")
	ErrInvalidOperationResult = errors.New("adminstore: invalid operation result")
	ErrOperationNotFound      = errors.New("adminstore: operation not found")
	operationRequestIDPattern = regexp.MustCompile(`^[A-Za-z0-9._:-]{8,128}$`)
	receiptMetadataPattern    = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9._:-]{0,254}$`)
)

type AllowlistedResult struct {
	Code    string
	Digest  string
	Payload map[string]string
}

func (r AllowlistedResult) Validate() error {
	allowedCodes := map[string]bool{
		"role.created": true, "role.updated": true, "role.disabled": true,
		"registry.updated": true, "challenge.updated": true,
		"challenge.enrolled": true, "challenge.verified": true,
		"challenge.rotated": true, "challenge.rejected": true, "challenge.locked": true,
		"identity_access.requested": true, "identity_access.decided": true,
		"identity_access.claimed": true, "identity_access.settled": true,
		"operation.pending": true, "operation.settled": true, "operation.failed": true, "redis.purged": true,
	}
	if !allowedCodes[r.Code] {
		return ErrInvalidOperationResult
	}
	if r.Digest != "" && !regexp.MustCompile(`^[A-Za-z0-9_-]{8,240}$`).MatchString(r.Digest) {
		return ErrInvalidOperationResult
	}
	for key, value := range r.Payload {
		valid := false
		switch key {
		case "binding_id":
			valid = validResultID(value, "arb_")
		case "request_id":
			valid = validResultID(value, "iar_")
		case "operation_request_id":
			valid = operationRequestIDPattern.MatchString(value)
		case "grant_id":
			valid = validResultID(value, "iag_")
		case "event_id":
			valid = validResultID(value, "evt_")
		case "actor_id":
			valid = validResultID(value, "user_")
		case "response_status":
			status, err := strconv.ParseInt(value, 10, 16)
			valid = err == nil && status >= 200 && status <= 599
		case "result_version":
			version, err := strconv.ParseInt(value, 10, 64)
			valid = err == nil && version > 0
		case "receipt_action", "receipt_target_type", "receipt_target_id":
			valid = receiptMetadataPattern.MatchString(value)
		case "status":
			valid = map[string]bool{"pending": true, "approved": true, "rejected": true, "revoked": true, "claimed": true, "settled": true, "disabled": true, "enabled": true, "active": true, "must_rotate": true, "recovery_pending": true}[value]
		case "version", "credential_version":
			version, err := strconv.ParseInt(value, 10, 64)
			valid = err == nil && version > 0
		}
		if !valid {
			return ErrInvalidOperationResult
		}
	}
	return nil
}

func ValidateOptionalAllowlistedResult(result AllowlistedResult) error {
	if result.Code == "" && result.Digest == "" && len(result.Payload) == 0 {
		return nil
	}
	return result.Validate()
}

func EncodeAllowlistedPayload(payload map[string]string) ([]byte, error) {
	if payload == nil {
		return []byte("{}"), nil
	}
	return json.Marshal(payload)
}

func validResultID(value, prefix string) bool {
	return strings.HasPrefix(value, prefix) && len(value) > len(prefix) && len(value) <= 160 && regexp.MustCompile(`^[A-Za-z0-9_-]+$`).MatchString(value)
}

type OperationReceipt struct {
	ID             string
	IdempotencyKey string
	Fingerprint    Fingerprint
	Result         AllowlistedResult
	CreatedAt      time.Time
	TerminalAt     *time.Time
}

func ResolveIdempotentReplay(existing OperationReceipt, incoming Fingerprint) (OperationReceipt, error) {
	if existing.Fingerprint != incoming {
		return OperationReceipt{}, ErrIdempotencyConflict
	}
	if err := existing.Result.Validate(); err != nil {
		return OperationReceipt{}, err
	}
	return existing, nil
}

type OutboxItem struct {
	ID                string
	Kind              OperationKind
	IdempotencyKey    string
	Fingerprint       Fingerprint
	PayloadKeyID      string
	PayloadNonce      []byte
	PayloadCiphertext []byte
	Result            AllowlistedResult
	State             string
	DeliveryPhase     DeliveryPhase
	Version           int64
	ClaimTokenHash    string
	ClaimToken        string
	ClaimLeaseUntil   *time.Time
	Attempts          int
	NextAttemptAt     time.Time
	TerminalAt        *time.Time
	AuditReconciledAt *time.Time
	PayloadExpiresAt  *time.Time
	PayloadPurgedAt   *time.Time
	CreatedAt         time.Time
	UpdatedAt         time.Time
}

func SanitizeOutboxReplay(item OutboxItem) OutboxItem {
	item.PayloadKeyID = ""
	item.PayloadNonce = nil
	item.PayloadCiphertext = nil
	item.ClaimTokenHash = ""
	item.ClaimToken = ""
	item.ClaimLeaseUntil = nil
	return item
}

func PayloadRetentionDeadline(reconciledAt time.Time) time.Time {
	return reconciledAt.Add(90 * 24 * time.Hour)
}

type OutboxRepository interface {
	CreateOrReplay(context.Context, OutboxItem) (OutboxItem, bool, error)
	GetByIdempotencyKey(context.Context, string) (OutboxItem, error)
	CompleteLocal(context.Context, string, int64, AllowlistedResult, time.Time) error
	ClaimDue(context.Context, time.Time, int) ([]OutboxItem, error)
	ClaimExact(context.Context, string, int64, time.Time, time.Duration) (OutboxItem, error)
	ClaimReceiptsDue(context.Context, time.Time, int, time.Duration) ([]OutboxItem, error)
	MarkDeliveryPhase(context.Context, string, int64, string, DeliveryPhase, time.Time) error
	DeferReceipt(context.Context, string, int64, string, time.Time, time.Time) error
	MarkNeedsOperator(context.Context, string, int64, string, time.Time) error
	Settle(context.Context, string, int64, string, AllowlistedResult, time.Time) error
	Fail(context.Context, string, int64, string, AllowlistedResult, time.Time) error
	MarkAuditReconciled(context.Context, string, int64, time.Time) error
	ReleaseExpiredClaim(context.Context, string, int64, time.Time) error
	PurgePayload(context.Context, string, int64, time.Time) error
}

type OperatorApproval struct {
	ID          string
	RequestHash string
	OperatorID  string
	KeyID       string
	Signature   []byte
	ExpiresAt   time.Time
	TerminalAt  *time.Time
	CreatedAt   time.Time
}

type OperatorApprovalRepository interface {
	Create(context.Context, OperatorApproval) error
	ListActive(context.Context, string, time.Time) ([]OperatorApproval, error)
	MarkTerminal(context.Context, string, time.Time) error
}

type ProtectedReasonRepository interface {
	Create(context.Context, string, string, string, []byte, []byte, time.Time) error
	MarkTerminal(context.Context, string, time.Time, time.Time) error
	PurgeExpired(context.Context, time.Time, int) (int, error)
}
