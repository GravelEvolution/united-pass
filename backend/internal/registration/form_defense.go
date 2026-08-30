package registration

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"time"

	"github.com/GravelEvolution/united-pass/backend/internal/session"
)

var (
	ErrFormIntentInvalid  = errors.New("registration: form intent invalid")
	ErrFormIntentTooYoung = errors.New("registration: form intent too young")
)

type HoneypotReason string

const (
	HoneypotMissing   HoneypotReason = "honeypot_missing"
	HoneypotFilled    HoneypotReason = "honeypot_filled"
	HoneypotOversized HoneypotReason = "honeypot_oversized"
)

type FormIntentRecord struct {
	UserAgentHash     string    `json:"userAgentHash"`
	ClientNetworkHash string    `json:"clientNetworkHash"`
	DeviceIDHash      string    `json:"deviceIdHash,omitempty"`
	NotBefore         time.Time `json:"notBefore"`
	ExpiresAt         time.Time `json:"expiresAt"`
}

type FormIntentBinding struct {
	UserAgentHash     string
	ClientNetworkHash string
	DeviceIDHash      string
}

type FormIntentResult struct {
	Token     string
	ExpiresAt time.Time
}

// AbuseFingerprint contains source digests only. Raw addresses, device
// cookies, and user agents must be hashed at the HTTP boundary before use.
// An unverified registration email is deliberately not a block dimension.
type AbuseFingerprint struct {
	ClientIPHash          string
	ClientIPBlockEligible bool
	DeviceIDHash          string
	UserAgentHash         string
}

type AbusePolicy struct {
	DeviceBlockTTL   time.Duration
	IPStrikeWindow   time.Duration
	IPBlockAfter     int
	IPBlockTTL       time.Duration
	IPLongBlockAfter int
	IPLongBlockTTL   time.Duration
}

type AbuseDisposition struct {
	IPStrikeCount int
	IPBlocked     bool
	LongIPBlock   bool
}

type AbuseAuditEvent struct {
	Reason      HoneypotReason
	RequestID   string
	Fingerprint AbuseFingerprint
	Disposition AbuseDisposition
	OccurredAt  time.Time
}

type FormDefenseStore interface {
	CreateFormIntent(context.Context, string, FormIntentRecord, time.Duration) error
	ConsumeFormIntent(context.Context, string, FormIntentBinding, time.Time) error
	IsRegistrationBlocked(context.Context, AbuseFingerprint) (bool, error)
	RecordRegistrationHoneypot(context.Context, AbuseFingerprint, AbusePolicy) (AbuseDisposition, error)
}

type AbuseAuditor interface {
	RecordRegistrationAbuse(context.Context, AbuseAuditEvent) error
}

type FormDefenseConfig struct {
	IntentTTL       time.Duration
	MinimumFormAge  time.Duration
	MaxHoneypotSize int
	Policy          AbusePolicy
	Now             func() time.Time
	GenerateToken   func() (string, error)
}

type FormDefense struct {
	store   FormDefenseStore
	auditor AbuseAuditor
	cfg     FormDefenseConfig
}

func NewFormDefense(store FormDefenseStore, auditor AbuseAuditor, cfg FormDefenseConfig) (*FormDefense, error) {
	if cfg.Now == nil {
		cfg.Now = time.Now
	}
	if cfg.GenerateToken == nil {
		cfg.GenerateToken = session.GenerateToken
	}
	if store == nil || cfg.IntentTTL <= 0 || cfg.MinimumFormAge < 0 || cfg.MinimumFormAge >= cfg.IntentTTL || cfg.MaxHoneypotSize <= 0 || !validAbusePolicy(cfg.Policy) {
		return nil, ErrUnavailable
	}
	return &FormDefense{store: store, auditor: auditor, cfg: cfg}, nil
}

func (d *FormDefense) Issue(ctx context.Context, binding FormIntentBinding) (FormIntentResult, error) {
	if d == nil || !validFormIntentBinding(binding) {
		return FormIntentResult{}, ErrUnavailable
	}
	token, err := d.cfg.GenerateToken()
	if err != nil || token == "" {
		return FormIntentResult{}, ErrUnavailable
	}
	now := d.cfg.Now().UTC()
	record := FormIntentRecord{
		UserAgentHash: binding.UserAgentHash, ClientNetworkHash: binding.ClientNetworkHash, DeviceIDHash: binding.DeviceIDHash,
		NotBefore: now.Add(d.cfg.MinimumFormAge), ExpiresAt: now.Add(d.cfg.IntentTTL),
	}
	if err := d.store.CreateFormIntent(ctx, token, record, d.cfg.IntentTTL); err != nil {
		return FormIntentResult{}, ErrUnavailable
	}
	return FormIntentResult{Token: token, ExpiresAt: record.ExpiresAt}, nil
}

func (d *FormDefense) Consume(ctx context.Context, rawToken string, binding FormIntentBinding) error {
	if d == nil || rawToken == "" || len(rawToken) > 512 || !validFormIntentBinding(binding) {
		return ErrFormIntentInvalid
	}
	err := d.store.ConsumeFormIntent(ctx, rawToken, binding, d.cfg.Now().UTC())
	switch {
	case err == nil:
		return nil
	case errors.Is(err, ErrFormIntentInvalid), errors.Is(err, ErrFormIntentTooYoung):
		return err
	default:
		return ErrUnavailable
	}
}

func (d *FormDefense) IsBlocked(ctx context.Context, fingerprint AbuseFingerprint) (bool, error) {
	if d == nil || !validFingerprint(fingerprint) {
		return false, ErrUnavailable
	}
	blocked, err := d.store.IsRegistrationBlocked(ctx, fingerprint)
	if err != nil {
		return false, ErrUnavailable
	}
	return blocked, nil
}

func (d *FormDefense) RecordHit(ctx context.Context, fingerprint AbuseFingerprint, reason HoneypotReason, requestID string) (AbuseDisposition, error) {
	if d == nil || !validFingerprint(fingerprint) || !validHoneypotReason(reason) {
		return AbuseDisposition{}, ErrUnavailable
	}
	disposition, err := d.store.RecordRegistrationHoneypot(ctx, fingerprint, d.cfg.Policy)
	if err != nil {
		return AbuseDisposition{}, ErrUnavailable
	}
	if d.auditor != nil {
		audit := AbuseAuditEvent{Reason: reason, RequestID: requestID, Fingerprint: fingerprint, Disposition: disposition, OccurredAt: d.cfg.Now().UTC()}
		if err := d.auditor.RecordRegistrationAbuse(ctx, audit); err != nil {
			return disposition, ErrUnavailable
		}
	}
	return disposition, nil
}

func (d *FormDefense) Decoy() (FormIntentResult, error) {
	if d == nil {
		return FormIntentResult{}, ErrUnavailable
	}
	token, err := d.cfg.GenerateToken()
	if err != nil || token == "" {
		return FormIntentResult{}, ErrUnavailable
	}
	return FormIntentResult{Token: token, ExpiresAt: d.cfg.Now().UTC().Add(d.cfg.IntentTTL)}, nil
}

func (d *FormDefense) ClassifyHoneypot(value *string) HoneypotReason {
	if d == nil {
		return HoneypotMissing
	}
	return ClassifyHoneypot(value, d.cfg.MaxHoneypotSize)
}

func ClassifyHoneypot(value *string, maxSize int) HoneypotReason {
	if value == nil {
		return HoneypotMissing
	}
	if len(*value) > maxSize {
		return HoneypotOversized
	}
	if *value != "" {
		return HoneypotFilled
	}
	return ""
}

func HashAbuseValue(value string) string {
	digest := sha256.Sum256([]byte(value))
	return hex.EncodeToString(digest[:])
}

func validAbusePolicy(policy AbusePolicy) bool {
	return policy.DeviceBlockTTL > 0 && policy.IPStrikeWindow > 0 && policy.IPBlockAfter > 1 && policy.IPBlockTTL > 0 && policy.IPLongBlockAfter > policy.IPBlockAfter && policy.IPLongBlockTTL >= policy.IPBlockTTL
}

func validFingerprint(value AbuseFingerprint) bool {
	return validDigest(value.ClientIPHash) && validDigest(value.UserAgentHash) && (value.DeviceIDHash == "" || validDigest(value.DeviceIDHash))
}

func validFormIntentBinding(value FormIntentBinding) bool {
	return validDigest(value.UserAgentHash) && validDigest(value.ClientNetworkHash) && (value.DeviceIDHash == "" || validDigest(value.DeviceIDHash))
}

func validDigest(value string) bool {
	decoded, err := hex.DecodeString(value)
	return err == nil && len(decoded) == sha256.Size
}

func validHoneypotReason(reason HoneypotReason) bool {
	switch reason {
	case HoneypotFilled, HoneypotOversized:
		return true
	default:
		return false
	}
}

func (r HoneypotReason) String() string { return string(r) }

func (f AbuseFingerprint) Validate() error {
	if !validFingerprint(f) {
		return fmt.Errorf("%w: abuse fingerprint", ErrInvalidInput)
	}
	return nil
}
