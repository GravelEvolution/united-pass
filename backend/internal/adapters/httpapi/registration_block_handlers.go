package httpapi

import (
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"log/slog"
	"net/http"
	"net/netip"
	"strings"
	"time"

	"github.com/GravelEvolution/united-pass/backend/internal/adapters/httpapi/request"
	"github.com/GravelEvolution/united-pass/backend/internal/adminroles"
	"github.com/GravelEvolution/united-pass/backend/internal/applications"
	"github.com/GravelEvolution/united-pass/backend/internal/auth"
	"github.com/GravelEvolution/united-pass/backend/internal/identity"
	"github.com/GravelEvolution/united-pass/backend/internal/permissions"
	"github.com/GravelEvolution/united-pass/backend/internal/registration"
	"github.com/GravelEvolution/united-pass/backend/internal/session"
)

const (
	maxRegistrationBlockBodyBytes = 4 << 10
	registrationBlockAuditTimeout = 3 * time.Second
	registrationBlockAuditPurpose = "united-pass/registration-defense/audit-target/v1"
)

type RegistrationBlockStore interface {
	UnblockRegistrationHash(context.Context, registration.AbuseBlockDimension, string) error
}

type SystemAdminRoleReader interface {
	GetForScope(context.Context, identity.UserID, adminroles.Scope) (adminroles.Binding, error)
}

type RegistrationBlockRateChecker interface {
	CheckRegistrationBlockRevoke(context.Context, string, int, time.Duration) (bool, time.Duration, error)
}

// RegistrationBlockAuditTargets creates correlatable audit identifiers without
// exposing the low-entropy SHA-256 of an IPv4 address. The HMAC key is derived
// once with a fixed purpose string so it is not reused by another protocol.
type RegistrationBlockAuditTargets struct {
	key   []byte
	keyID string
}

func NewRegistrationBlockAuditTargets(rootKey []byte, keyID string) (*RegistrationBlockAuditTargets, error) {
	if len(rootKey) != 32 {
		return nil, errors.New("httpapi: invalid registration block audit key")
	}
	keyID = normalizedRegistrationBlockKeyID(keyID)
	derive := hmac.New(sha256.New, rootKey)
	_, _ = derive.Write([]byte(registrationBlockAuditPurpose))
	return &RegistrationBlockAuditTargets{key: derive.Sum(nil), keyID: keyID}, nil
}

func (p *RegistrationBlockAuditTargets) pseudonym(dimension registration.AbuseBlockDimension, digest string) (string, string, bool) {
	if p == nil || len(p.key) != sha256.Size || !dimension.Valid() || !validRegistrationBlockSHA256(digest) {
		return "", "", false
	}
	mac := hmac.New(sha256.New, p.key)
	_, _ = mac.Write([]byte(dimension))
	_, _ = mac.Write([]byte{0})
	_, _ = mac.Write([]byte(digest))
	targetKey := "device_id_hmac"
	if dimension == registration.AbuseBlockIP {
		targetKey = "client_ip_hmac"
	}
	return targetKey, hex.EncodeToString(mac.Sum(nil)), true
}

type RegistrationBlockControls struct {
	Reauth       ReauthVerifier
	Rates        RegistrationBlockRateChecker
	AuditTargets *RegistrationBlockAuditTargets
	RateLimit    int
	RateWindow   time.Duration
}

type RegistrationBlockHandlers struct {
	store    RegistrationBlockStore
	roles    SystemAdminRoleReader
	people   permissions.PrincipalContextReader
	access   permissions.Resolver
	auditor  applications.SecurityEventRecorder
	controls RegistrationBlockControls
	now      func() time.Time
	logger   *slog.Logger
}

func NewRegistrationBlockHandlers(store RegistrationBlockStore, roles SystemAdminRoleReader, people permissions.PrincipalContextReader, access permissions.Resolver, auditor applications.SecurityEventRecorder, controls RegistrationBlockControls, logger *slog.Logger) *RegistrationBlockHandlers {
	if logger == nil {
		logger = slog.New(slog.DiscardHandler)
	}
	return &RegistrationBlockHandlers{store: store, roles: roles, people: people, access: access, auditor: auditor, controls: controls, now: time.Now, logger: logger}
}

type registrationBlockRevokeRequest struct {
	Dimension  registration.AbuseBlockDimension `json:"dimension"`
	Value      string                           `json:"value"`
	Encoding   string                           `json:"valueEncoding"`
	ReasonCode string                           `json:"reasonCode"`
}

// Revoke handles POST /api/v1/admin/registration-defense/blocks/revoke.
// Session and CSRF are enforced by the shared admin router. This handler then
// requires an active system super/top administrator binding and hashes the
// canonical raw fingerprint at the HTTP boundary.
func (h *RegistrationBlockHandlers) Revoke(w http.ResponseWriter, r *http.Request) {
	principal, ok := h.authorize(w, r)
	if !ok {
		return
	}
	var body registrationBlockRevokeRequest
	if !decodeRegistrationBlockRequest(w, r, &body) {
		return
	}
	digest, targetKey, ok := canonicalRegistrationBlockDigest(body.Dimension, body.Value, body.Encoding)
	if !ok || !validRegistrationBlockReason(body.ReasonCode) {
		WriteValidation(w, r, "解封指纹或原因不正确。", nil)
		return
	}
	auditTargetKey, auditTargetID, ok := h.controls.AuditTargets.pseudonym(body.Dimension, digest)
	if !ok {
		WriteInternalError(w, r)
		return
	}
	if !h.allowRecoveryOperation(w, r, principal.UserID) {
		return
	}
	if !h.requireRecoveryReauthentication(w, r, principal, body.Dimension, digest, auditTargetKey, auditTargetID) {
		return
	}

	auditBase := applications.SecurityEvent{
		ActorUserID: principal.UserID,
		RequestID:   request.ID(r.Context()),
		Operation:   "registration.abuse.unblock",
		TargetKey:   auditTargetKey,
		TargetID:    auditTargetID,
		Extra: map[string]string{
			"fingerprint_dimension": string(body.Dimension),
			"value_encoding":        body.Encoding,
			"reason_code":           body.ReasonCode,
			"audit_target_version":  "hmac-sha256-v1",
			"audit_target_key_id":   h.controls.AuditTargets.keyID,
			"source_target_key":     targetKey,
		},
		OccurredAt: h.now().UTC(),
	}
	requested := auditBase
	requested.EventID = applications.NewSecurityEventID()
	requested.EventType = "registration.abuse_unblock_requested"
	requested.Result = applications.SecurityEventSuccess
	// Persist the actor, purpose-keyed target pseudonym and reason before
	// mutating Redis. If durable audit is unavailable, the unblock fails closed.
	if h.auditor == nil || h.auditor.Record(r.Context(), requested) != nil {
		WriteInternalError(w, r)
		return
	}
	if h.store == nil || h.store.UnblockRegistrationHash(r.Context(), body.Dimension, digest) != nil {
		auditContext, cancel := context.WithTimeout(context.WithoutCancel(r.Context()), registrationBlockAuditTimeout)
		h.recordOutcome(auditContext, auditBase, "registration.abuse_unblock_failed", applications.SecurityEventDenied, "state_store")
		cancel()
		WriteInternalError(w, r)
		return
	}
	auditContext, cancel := context.WithTimeout(context.WithoutCancel(r.Context()), registrationBlockAuditTimeout)
	audited := h.recordOutcome(auditContext, auditBase, "registration.abuse_unblocked", applications.SecurityEventSuccess, "")
	cancel()
	if !audited {
		// The request audit is already durable and the Redis mutation is
		// idempotent. Report failure so the operator can safely retry and
		// obtain a completed outcome record.
		WriteInternalError(w, r)
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

func (h *RegistrationBlockHandlers) allowRecoveryOperation(w http.ResponseWriter, r *http.Request, actor identity.UserID) bool {
	if h.controls.Rates == nil || h.controls.RateLimit <= 0 || h.controls.RateWindow <= 0 {
		WriteRateLimited(w, r, int(h.controls.RateWindow.Seconds()))
		return false
	}
	allowed, retryAfter, err := h.controls.Rates.CheckRegistrationBlockRevoke(
		r.Context(), registration.HashAbuseValue(string(actor)), h.controls.RateLimit, h.controls.RateWindow)
	if err != nil {
		h.logger.Error("registration abuse unblock rate limit failed", "requestId", request.ID(r.Context()))
		WriteRateLimited(w, r, int(h.controls.RateWindow.Seconds()))
		return false
	}
	if !allowed {
		WriteRateLimited(w, r, int(retryAfter.Seconds()))
		return false
	}
	return true
}

func (h *RegistrationBlockHandlers) requireRecoveryReauthentication(w http.ResponseWriter, r *http.Request, principal session.Principal, dimension registration.AbuseBlockDimension, digest, auditTargetKey, auditTargetID string) bool {
	token := r.Header.Get("X-Reauthentication-Token")
	target := registrationBlockReauthTarget(dimension, digest)
	if h.controls.Reauth != nil && token != "" && h.controls.Reauth.VerifyAndConsume(
		r.Context(), token, auth.ReauthActionRegistrationAbuseUnblock,
		string(principal.SessionID), target, "", "") == nil {
		return true
	}
	h.recordRecoveryDenied(r.Context(), principal.UserID, auditTargetKey, auditTargetID, "reauthentication")
	writeError(w, r, http.StatusForbidden, CodeReauthenticationReq, "该操作需要重新认证。", nil)
	return false
}

func registrationBlockReauthTarget(dimension registration.AbuseBlockDimension, digest string) string {
	return string(dimension) + "_" + digest
}

func (h *RegistrationBlockHandlers) recordRecoveryDenied(ctx context.Context, actor identity.UserID, targetKey, targetID, failureClass string) {
	if h.auditor == nil {
		return
	}
	auditContext, cancel := context.WithTimeout(context.WithoutCancel(ctx), registrationBlockAuditTimeout)
	defer cancel()
	_ = h.auditor.Record(auditContext, applications.SecurityEvent{
		EventID: applications.NewSecurityEventID(), EventType: "registration.abuse_unblock_denied",
		ActorUserID: actor, RequestID: request.ID(ctx), Operation: auth.ReauthActionRegistrationAbuseUnblock,
		Result: applications.SecurityEventDenied, FailureClass: failureClass,
		TargetKey: targetKey, TargetID: targetID,
		Extra: map[string]string{
			"audit_target_version": "hmac-sha256-v1",
			"audit_target_key_id":  h.controls.AuditTargets.keyID,
		},
		OccurredAt: h.now().UTC(),
	})
}

func (h *RegistrationBlockHandlers) authorize(w http.ResponseWriter, r *http.Request) (session.Principal, bool) {
	principal, ok := PrincipalFromContext(r.Context())
	if !ok {
		WriteUnauthorized(w, r)
		return session.Principal{}, false
	}
	if h.roles == nil || h.people == nil || h.access == nil {
		WriteInternalError(w, r)
		return session.Principal{}, false
	}
	systemScope := adminroles.Scope{Kind: adminroles.ScopeSystem}
	binding, err := h.roles.GetForScope(r.Context(), principal.UserID, systemScope)
	if err != nil {
		if errors.Is(err, adminroles.ErrBindingNotFound) {
			h.recordAuthorizationDenied(r.Context(), principal.UserID)
			WriteForbidden(w, r)
		} else {
			WriteInternalError(w, r)
		}
		return session.Principal{}, false
	}
	allowedRole := binding.Role == adminroles.RoleSuperAdmin || binding.Role == adminroles.RoleTopAdmin
	validBinding := binding.ID != "" && binding.UserID == principal.UserID && binding.Scope == systemScope && binding.Version > 0 && binding.Enabled && binding.DisabledAt == nil && adminroles.ValidateRoleScope(binding.Role, binding.Scope) == nil
	if !allowedRole || !validBinding {
		h.recordAuthorizationDenied(r.Context(), principal.UserID)
		WriteForbidden(w, r)
		return session.Principal{}, false
	}
	person, err := h.people.GetPermissionPrincipal(r.Context(), principal.UserID)
	if err != nil {
		WriteInternalError(w, r)
		return session.Principal{}, false
	}
	accountStatus, _ := person.Attributes["accountStatus"].(string)
	employeeStatus, _ := person.Attributes["employeeStatus"].(string)
	if accountStatus != string(identity.UserStatusActive) || employeeStatus == "offboarding" {
		h.recordAuthorizationDenied(r.Context(), principal.UserID)
		WriteForbidden(w, r)
		return session.Principal{}, false
	}
	capabilities, err := h.access.Resolve(r.Context(), principal.UserID)
	if err != nil {
		WriteInternalError(w, r)
		return session.Principal{}, false
	}
	// There is no public registration-defense capability in the frozen
	// account contract. Require both existing policy-management authority and
	// audit visibility, in addition to the exact system role above. This keeps
	// Cerbos explicit deny and workforce guards authoritative without widening
	// the frontend capability surface for an internal recovery endpoint.
	if !capabilities.PolicyManage || !capabilities.AuditRead {
		h.recordAuthorizationDenied(r.Context(), principal.UserID)
		WriteForbidden(w, r)
		return session.Principal{}, false
	}
	return principal, true
}

func (h *RegistrationBlockHandlers) recordAuthorizationDenied(ctx context.Context, actor identity.UserID) {
	if h.auditor == nil {
		return
	}
	auditContext, cancel := context.WithTimeout(context.WithoutCancel(ctx), registrationBlockAuditTimeout)
	defer cancel()
	_ = h.auditor.Record(auditContext, applications.SecurityEvent{
		EventID: applications.NewSecurityEventID(), EventType: "authorization.denied",
		ActorUserID: actor, RequestID: request.ID(ctx), Operation: "registration.abuse.unblock",
		Result: applications.SecurityEventDenied, FailureClass: "authorization",
		TargetKey: "action", TargetID: "registration.abuse.unblock", OccurredAt: h.now().UTC(),
	})
}

func (h *RegistrationBlockHandlers) recordOutcome(ctx context.Context, base applications.SecurityEvent, eventType string, result applications.SecurityEventResult, failureClass string) bool {
	if h.auditor == nil {
		return false
	}
	base.EventID = applications.NewSecurityEventID()
	base.EventType = eventType
	base.Result = result
	base.FailureClass = failureClass
	base.OccurredAt = h.now().UTC()
	if err := h.auditor.Record(ctx, base); err != nil {
		h.logger.Error("registration abuse unblock audit failed", "requestId", base.RequestID, "eventType", eventType)
		return false
	}
	return true
}

func decodeRegistrationBlockRequest(w http.ResponseWriter, r *http.Request, target any) bool {
	r.Body = http.MaxBytesReader(w, r.Body, maxRegistrationBlockBodyBytes)
	decoder := json.NewDecoder(r.Body)
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(target); err != nil {
		var maxBytesErr *http.MaxBytesError
		if errors.As(err, &maxBytesErr) {
			WriteRequestBodyTooLarge(w, r)
		} else {
			WriteBadRequest(w, r, "请求体格式不正确。")
		}
		return false
	}
	if err := decoder.Decode(&struct{}{}); !errors.Is(err, io.EOF) {
		WriteBadRequest(w, r, "请求体包含多余的数据。")
		return false
	}
	return true
}

func canonicalRegistrationBlockDigest(dimension registration.AbuseBlockDimension, raw, encoding string) (string, string, bool) {
	if raw == "" || raw != strings.TrimSpace(raw) {
		return "", "", false
	}
	if encoding == "sha256" {
		// Only the HttpOnly device cookie needs digest-mode recovery: operators
		// can copy its safe digest from the existing abuse audit. IP recovery
		// intentionally remains raw -> canonical netip -> boundary hash.
		if dimension != registration.AbuseBlockDevice || !validRegistrationBlockSHA256(raw) {
			return "", "", false
		}
		return raw, "device_id_hash", true
	}
	if encoding != "raw" {
		return "", "", false
	}
	switch dimension {
	case registration.AbuseBlockIP:
		address, err := netip.ParseAddr(raw)
		if err != nil || address.Zone() != "" {
			return "", "", false
		}
		return registration.HashAbuseValue(address.Unmap().String()), "client_ip_hash", true
	case registration.AbuseBlockDevice:
		decoded, err := base64.RawURLEncoding.DecodeString(raw)
		if err != nil || len(decoded) != session.TokenBytes || base64.RawURLEncoding.EncodeToString(decoded) != raw {
			return "", "", false
		}
		return registration.HashAbuseValue(raw), "device_id_hash", true
	default:
		return "", "", false
	}
}

func validRegistrationBlockSHA256(value string) bool {
	decoded, err := hex.DecodeString(value)
	return err == nil && len(decoded) == 32 && value == hex.EncodeToString(decoded)
}

func validRegistrationBlockReason(value string) bool {
	switch value {
	case "false_positive", "support_verified", "test_cleanup", "incident_response":
		return true
	default:
		return false
	}
}

func validRegistrationBlockKeyID(value string) bool {
	if value == "" || len(value) > 96 {
		return false
	}
	for _, char := range value {
		if (char < 'a' || char > 'z') && (char < 'A' || char > 'Z') &&
			(char < '0' || char > '9') && char != '_' && char != '-' && char != '.' {
			return false
		}
	}
	return true
}

// normalizedRegistrationBlockKeyID mirrors the session cipher's empty-ID
// default. Historical session key IDs were allowed to contain characters that
// are unsuitable for audit dimensions; those remain valid deployments and are
// represented by a stable SHA-256 alias instead of causing a startup failure.
func normalizedRegistrationBlockKeyID(value string) string {
	if value == "" {
		return "v1"
	}
	if validRegistrationBlockKeyID(value) {
		return value
	}
	digest := sha256.Sum256([]byte(value))
	return "sha256-" + hex.EncodeToString(digest[:])
}
