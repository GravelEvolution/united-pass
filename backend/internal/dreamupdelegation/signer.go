package dreamupdelegation

import (
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"net/url"
	"regexp"
	"sort"
	"strings"
	"time"
	"unicode/utf16"
	"unicode/utf8"

	"github.com/GravelEvolution/united-pass/backend/internal/adminroles"
	"github.com/GravelEvolution/united-pass/backend/internal/identity"
	"github.com/GravelEvolution/united-pass/backend/internal/identityaccess"
	"github.com/GravelEvolution/united-pass/backend/internal/permissions"
)

const (
	Issuer                   = "https://auth.moonstone.org.cn"
	ReconcilerServiceSubject = "united-pass:dreamup-reconciler"
	MaxOrdinaryTTL           = 25 * time.Second
	MaxOATTL                 = 10 * time.Second
	MaxClockSkew             = 5 * time.Second
	// MaxAdministratorLoginAge bounds the provider-backed primary login behind
	// every cross-service administrator assertion. The HTTP step-up boundary
	// performs the same check before accepting a security answer so stale
	// sessions fail with a stable reauthentication response.
	MaxAdministratorLoginAge       = 30 * time.Minute
	MaxHighRiskStepUpAge           = 5 * time.Minute
	maxJSONSafeInteger       int64 = 1<<53 - 1
)

var (
	ErrInvalidSignerConfig = errors.New("dreamup delegation: invalid signer configuration")
	ErrInvalidAssertion    = errors.New("dreamup delegation: invalid assertion")
	hexDigestPattern       = regexp.MustCompile(`^[a-f0-9]{64}$`)
	entityTagPattern       = regexp.MustCompile(`^"(0|[1-9][0-9]*)"$`)
	safeIDPattern          = regexp.MustCompile(`^[A-Za-z0-9._:-]{1,255}$`)
	requestIDPattern       = regexp.MustCompile(`^[A-Za-z0-9._:-]{8,128}$`)
)

type AdministratorCapability string

const (
	AdministratorCapabilityDashboardRead           AdministratorCapability = "event.dashboard.read"
	AdministratorCapabilityApplicationRead         AdministratorCapability = "event.application.read_basic"
	AdministratorCapabilityApplicationReview       AdministratorCapability = "event.application.review"
	AdministratorCapabilityApproveAdmission        AdministratorCapability = "event.application.approve_admission"
	AdministratorCapabilityApplicationDecide       AdministratorCapability = "event.application.decide"
	AdministratorCapabilityRegistrationManage      AdministratorCapability = "event.registration.manage"
	AdministratorCapabilityCheckinScan             AdministratorCapability = "event.checkin.scan"
	AdministratorCapabilityCheckinWindowManage     AdministratorCapability = "event.checkin.manage_window"
	AdministratorCapabilityIdentityTargetValidate  AdministratorCapability = "event.identity_access.validate_target"
	AdministratorCapabilityIdentityAccessConsume   AdministratorCapability = "event.identity_access.consume"
	AdministratorCapabilityRestrictedIdentityRead  AdministratorCapability = "event.identity.read_restricted"
	AdministratorCapabilityLegalRead               AdministratorCapability = "event.legal.read"
	AdministratorCapabilityApplicationExport       AdministratorCapability = "event.application.export"
	AdministratorCapabilityAuditRead               AdministratorCapability = "event.audit.read"
	AdministratorCapabilityContactSubmissionManage AdministratorCapability = "event.contact_submission.manage"
	AdministratorCapabilityContentManage           AdministratorCapability = "event.content.manage"
	AdministratorCapabilityRoleMigrationRead       AdministratorCapability = "system.role_migration.read"
)

type ServiceCapability string

const (
	ServiceCapabilityOperationReceiptRead ServiceCapability = "system.operation_receipt.read"
)

var administratorCapabilities = map[AdministratorCapability]permissions.Action{
	AdministratorCapabilityDashboardRead:           permissions.ActionDashboardRead,
	AdministratorCapabilityApplicationRead:         permissions.ActionApplicationReadBasic,
	AdministratorCapabilityApplicationReview:       permissions.ActionApplicationReview,
	AdministratorCapabilityApproveAdmission:        permissions.ActionApplicationApproveAdmission,
	AdministratorCapabilityApplicationDecide:       permissions.ActionApplicationDecide,
	AdministratorCapabilityRegistrationManage:      permissions.ActionRegistrationManage,
	AdministratorCapabilityCheckinScan:             permissions.ActionCheckinScan,
	AdministratorCapabilityCheckinWindowManage:     permissions.ActionCheckinManageWindow,
	AdministratorCapabilityIdentityTargetValidate:  permissions.ActionIdentityTargetValidate,
	AdministratorCapabilityIdentityAccessConsume:   permissions.ActionIdentityGrantConsume,
	AdministratorCapabilityRestrictedIdentityRead:  permissions.ActionIdentityReadRestricted,
	AdministratorCapabilityLegalRead:               permissions.ActionLegalRead,
	AdministratorCapabilityApplicationExport:       permissions.ActionApplicationExport,
	AdministratorCapabilityAuditRead:               permissions.ActionAuditRead,
	AdministratorCapabilityContactSubmissionManage: permissions.ActionContactSubmissionManage,
	AdministratorCapabilityContentManage:           permissions.ActionContentManage,
	AdministratorCapabilityRoleMigrationRead:       permissions.ActionRoleMigrationRead,
}

// IsHighRiskAdministratorCapability reports whether the assertion must carry
// a fresh, durable session-bound step-up proof identifier.
func IsHighRiskAdministratorCapability(capability AdministratorCapability) bool {
	action, ok := administratorCapabilities[capability]
	return ok && permissions.IsDreamUPHighRiskDelegatedAdministratorAction(action)
}

// RequiresFreshAdministratorProof is deliberately method-aware so a future
// mutation cannot silently inherit the longer read-only proof lifetime merely
// because its capability was omitted from the named high-risk set.
func RequiresFreshAdministratorProof(capability AdministratorCapability, method string) bool {
	return mutationMethod(method) || IsHighRiskAdministratorCapability(capability)
}

type SignerConfig struct {
	Issuer    string
	Audience  string
	TTL       time.Duration
	ClockSkew time.Duration
	Now       func() time.Time
}

type AdministratorSigner struct {
	keyring *Keyring
	config  SignerConfig
}

type ServiceSigner struct {
	keyring *Keyring
	config  SignerConfig
}

// SignedAssertion carries the compact JWS and its authoritative time bounds.
// Internal clients use ExpiresAt to cap their outbound request deadline
// without reparsing untrusted token text.
type SignedAssertion struct {
	Token     string
	NotBefore time.Time
	ExpiresAt time.Time
}

func NewAdministratorSigner(keyring *Keyring, config SignerConfig) (*AdministratorSigner, error) {
	if err := validateSignerConfig(keyring, config); err != nil {
		return nil, err
	}
	return &AdministratorSigner{keyring: keyring, config: config}, nil
}

func NewServiceSigner(keyring *Keyring, config SignerConfig) (*ServiceSigner, error) {
	if err := validateSignerConfig(keyring, config); err != nil {
		return nil, err
	}
	return &ServiceSigner{keyring: keyring, config: config}, nil
}

func validateSignerConfig(keyring *Keyring, config SignerConfig) error {
	issuer, err := url.Parse(config.Issuer)
	if err != nil || issuer.Scheme != "https" || issuer.Host == "" || issuer.User != nil || issuer.Path != "" || issuer.RawQuery != "" || issuer.Fragment != "" || config.Issuer != strings.TrimSpace(config.Issuer) {
		return ErrInvalidSignerConfig
	}
	if keyring == nil || keyring.CurrentKeyID() == "" || strings.TrimSpace(config.Audience) == "" || config.Audience != strings.TrimSpace(config.Audience) || config.TTL < time.Second || config.TTL > MaxOrdinaryTTL || config.TTL%time.Second != 0 || config.ClockSkew < 0 || config.ClockSkew > MaxClockSkew || config.ClockSkew%time.Second != 0 || config.Now == nil {
		return ErrInvalidSignerConfig
	}
	return nil
}

// OAClaim is the one-time identity access lease returned by Task 8. The signer
// verifies its internal binding and translates only the exact fields
// understood by the DreamUP verifier.
type OAClaim = identityaccess.Claim

type AdministratorAssertion struct {
	Subject          identity.UserID
	JWTID            string
	Capability       AdministratorCapability
	Method           string
	PathAndQuery     string
	BodySHA256       string
	IfMatch          string
	EventID          string
	Role             adminroles.Role
	RoleBindingID    string
	RoleVersion      int64
	ChallengeVersion int64
	AuthTime         time.Time
	StepUpAt         time.Time
	ReauthGrantID    string
	IdempotencyKey   string
	OA               *OAClaim
}

type ServiceAssertion struct {
	Subject            string
	ServiceVersion     int64
	JWTID              string
	Capability         ServiceCapability
	Method             string
	PathAndQuery       string
	BodySHA256         string
	EventID            string
	OutboxID           string
	OperationRequestID string
	IdempotencyKey     string
}

type registeredClaims struct {
	Issuer    string `json:"iss"`
	Audience  string `json:"aud"`
	Subject   string `json:"sub"`
	IssuedAt  int64  `json:"iat"`
	NotBefore int64  `json:"nbf"`
	ExpiresAt int64  `json:"exp"`
	JWTID     string `json:"jti"`
}

type commonClaims struct {
	ActorKind      string `json:"actor_kind"`
	EventID        string `json:"event_id"`
	Capability     string `json:"capability"`
	RequestID      string `json:"request_id"`
	Method         string `json:"htm"`
	PathAndQuery   string `json:"htu"`
	BodySHA256     string `json:"body_sha256"`
	HeadersSHA256  string `json:"headers_sha256,omitempty"`
	IdempotencyKey string `json:"idempotency_key,omitempty"`
}

type administratorClaims struct {
	registeredClaims
	commonClaims
	RoleBindingID       string   `json:"role_binding_id"`
	RoleVersion         int64    `json:"role_version"`
	ChallengeVersion    int64    `json:"challenge_version"`
	AuthTime            int64    `json:"auth_time"`
	StepUpAt            int64    `json:"step_up_at"`
	ReauthGrantID       string   `json:"reauth_grant_id,omitempty"`
	GrantID             string   `json:"grant_id,omitempty"`
	GrantVersion        int64    `json:"grant_version,omitempty"`
	RequesterUserID     string   `json:"requester_user_id,omitempty"`
	TargetType          string   `json:"target_type,omitempty"`
	TargetID            string   `json:"target_id,omitempty"`
	TargetSubjectUserID string   `json:"target_subject_user_id,omitempty"`
	ApprovedFields      []string `json:"approved_fields,omitempty"`
	FieldSetHash        string   `json:"field_set_hash,omitempty"`
	ClaimNonce          string   `json:"claim_nonce,omitempty"`
}

type serviceClaims struct {
	registeredClaims
	commonClaims
	ServiceVersion     int64  `json:"service_version"`
	OutboxID           string `json:"outbox_id"`
	OperationRequestID string `json:"operation_request_id"`
}

func (s *AdministratorSigner) SignAdministrator(input AdministratorAssertion) (SignedAssertion, error) {
	if s == nil || s.keyring == nil || s.config.Now == nil {
		return SignedAssertion{}, ErrInvalidSignerConfig
	}
	now := s.config.Now().UTC().Truncate(time.Second)
	if !validIssuedAt(now.Unix()) {
		return SignedAssertion{}, ErrInvalidAssertion
	}
	if err := validateAdministratorAssertion(input, now, s.config.ClockSkew); err != nil {
		return SignedAssertion{}, err
	}
	ttl := s.config.TTL
	if input.OA != nil {
		if ttl > MaxOATTL {
			ttl = MaxOATTL
		}
		if remaining := input.OA.LeaseExpiresAt.UTC().Truncate(time.Second).Sub(now); remaining < ttl {
			ttl = remaining
		}
	}
	if ttl < time.Second {
		return SignedAssertion{}, ErrInvalidAssertion
	}
	claims := administratorClaims{
		registeredClaims: newRegisteredClaims(s.config, string(input.Subject), input.JWTID, now, ttl),
		commonClaims: commonClaims{
			ActorKind: "administrator", EventID: input.EventID, Capability: string(input.Capability), RequestID: input.JWTID,
			Method: input.Method, PathAndQuery: input.PathAndQuery, BodySHA256: input.BodySHA256, HeadersSHA256: AdministratorHeadersSHA256(input.IfMatch, input.IdempotencyKey), IdempotencyKey: input.IdempotencyKey,
		},
		RoleBindingID: input.RoleBindingID, RoleVersion: input.RoleVersion, ChallengeVersion: input.ChallengeVersion,
		AuthTime: input.AuthTime.UTC().Unix(), StepUpAt: input.StepUpAt.UTC().Unix(), ReauthGrantID: input.ReauthGrantID,
	}
	if input.OA != nil {
		populateOAClaims(&claims, *input.OA)
	}
	return s.keyring.signedAssertion(claims)
}

func (s *ServiceSigner) SignService(input ServiceAssertion) (SignedAssertion, error) {
	if s == nil || s.keyring == nil || s.config.Now == nil {
		return SignedAssertion{}, ErrInvalidSignerConfig
	}
	now := s.config.Now().UTC().Truncate(time.Second)
	if !validIssuedAt(now.Unix()) || validateServiceAssertion(input) != nil {
		return SignedAssertion{}, ErrInvalidAssertion
	}
	claims := serviceClaims{
		registeredClaims: newRegisteredClaims(s.config, input.Subject, input.JWTID, now, s.config.TTL),
		commonClaims: commonClaims{
			ActorKind: "service", EventID: input.EventID, Capability: string(input.Capability), RequestID: input.JWTID,
			Method: input.Method, PathAndQuery: input.PathAndQuery, BodySHA256: input.BodySHA256, HeadersSHA256: AdministratorHeadersSHA256("", input.IdempotencyKey), IdempotencyKey: input.IdempotencyKey,
		},
		ServiceVersion: input.ServiceVersion, OutboxID: input.OutboxID, OperationRequestID: input.OperationRequestID,
	}
	return s.keyring.signedAssertion(claims)
}

func newRegisteredClaims(config SignerConfig, subject, jwtID string, now time.Time, ttl time.Duration) registeredClaims {
	return registeredClaims{
		Issuer: config.Issuer, Audience: config.Audience, Subject: subject, JWTID: jwtID,
		IssuedAt: now.Unix(), NotBefore: now.Add(-config.ClockSkew).Unix(), ExpiresAt: now.Add(ttl).Unix(),
	}
}

func validateAdministratorAssertion(input AdministratorAssertion, now time.Time, skew time.Duration) error {
	if !safeIDPattern.MatchString(string(input.Subject)) || !requestIDPattern.MatchString(input.JWTID) || !safeIDPattern.MatchString(input.EventID) || !safeIDPattern.MatchString(input.RoleBindingID) || !positiveJSONSafeInteger(input.RoleVersion) || !positiveJSONSafeInteger(input.ChallengeVersion) || !validRequestBinding(input.Method, input.PathAndQuery, input.BodySHA256) || input.AuthTime.IsZero() || input.StepUpAt.IsZero() {
		return ErrInvalidAssertion
	}
	action, allowed := administratorCapabilities[input.Capability]
	if allowed {
		allowed = permissions.IsDreamUPDelegatedAdministratorAction(action) && permissions.FixedRoleAllows(input.Role, action)
	}
	if !allowed {
		return ErrInvalidAssertion
	}
	authTime, stepUpAt := input.AuthTime.UTC().Unix(), input.StepUpAt.UTC().Unix()
	nowUnix, skewSeconds := now.Unix(), int64(skew/time.Second)
	if !jsonSafeInteger(authTime) || !jsonSafeInteger(stepUpAt) || authTime > nowUnix+skewSeconds || nowUnix-authTime > int64(MaxAdministratorLoginAge/time.Second) || stepUpAt > nowUnix+skewSeconds || stepUpAt < authTime-skewSeconds {
		return ErrInvalidAssertion
	}
	highRisk := RequiresFreshAdministratorProof(input.Capability, input.Method)
	if highRisk {
		if !safeIDPattern.MatchString(input.ReauthGrantID) || nowUnix-stepUpAt > int64(MaxHighRiskStepUpAge/time.Second) {
			return ErrInvalidAssertion
		}
	} else if input.ReauthGrantID != "" {
		return ErrInvalidAssertion
	}
	if mutationMethod(input.Method) {
		if !safeIDPattern.MatchString(input.IdempotencyKey) || !entityTagPattern.MatchString(input.IfMatch) {
			return ErrInvalidAssertion
		}
	} else if input.IdempotencyKey != "" || input.IfMatch != "" {
		return ErrInvalidAssertion
	}
	if input.Capability == AdministratorCapabilityIdentityAccessConsume {
		if input.OA == nil || validateOAClaim(input, now) != nil {
			return ErrInvalidAssertion
		}
	} else if input.OA != nil {
		return ErrInvalidAssertion
	}
	return nil
}

func validateServiceAssertion(input ServiceAssertion) error {
	if input.Subject != ReconcilerServiceSubject || !positiveJSONSafeInteger(input.ServiceVersion) || !requestIDPattern.MatchString(input.JWTID) || !safeIDPattern.MatchString(input.EventID) || !safeIDPattern.MatchString(input.OutboxID) || !safeIDPattern.MatchString(input.OperationRequestID) || !safeIDPattern.MatchString(input.IdempotencyKey) || !validRequestBinding(input.Method, input.PathAndQuery, input.BodySHA256) {
		return ErrInvalidAssertion
	}
	expectedPath := "/internal/v1/events/" + input.EventID
	switch input.Capability {
	case ServiceCapabilityOperationReceiptRead:
		if input.Method != "GET" || input.PathAndQuery != expectedPath+"/operation-receipts/"+input.OperationRequestID || input.BodySHA256 != SHA256Digest(nil) {
			return ErrInvalidAssertion
		}
	default:
		return ErrInvalidAssertion
	}
	return nil
}

func validIssuedAt(seconds int64) bool {
	return seconds >= 0 && seconds <= maxJSONSafeInteger-int64(MaxOrdinaryTTL/time.Second)
}

func positiveJSONSafeInteger(value int64) bool {
	return value > 0 && value <= maxJSONSafeInteger
}

func jsonSafeInteger(value int64) bool {
	return value >= -maxJSONSafeInteger && value <= maxJSONSafeInteger
}

func validRequestBinding(method, pathAndQuery, bodyHash string) bool {
	switch method {
	case "GET", "HEAD", "POST", "PUT", "PATCH", "DELETE":
	default:
		return false
	}
	return hexDigestPattern.MatchString(bodyHash) && validCanonicalPathAndQuery(pathAndQuery)
}

func mutationMethod(method string) bool {
	return method == "POST" || method == "PUT" || method == "PATCH" || method == "DELETE"
}

// AdministratorHeadersSHA256 binds the concurrency and idempotency headers
// forwarded with an administrator assertion. Header names, ordering and NUL
// separators are fixed so United Pass and DreamUP cannot disagree about the
// signed representation.
func AdministratorHeadersSHA256(ifMatch, idempotencyKey string) string {
	return requestHeadersSHA256(ifMatch, idempotencyKey)
}

func requestHeadersSHA256(ifMatch, idempotencyKey string) string {
	input := "if-match\x00" + ifMatch + "\x00idempotency-key\x00" + idempotencyKey
	digest := sha256.Sum256([]byte(input))
	return hex.EncodeToString(digest[:])
}

func validCanonicalPathAndQuery(value string) bool {
	parsed, err := url.ParseRequestURI(value)
	if err != nil || !strings.HasPrefix(value, "/") || parsed.IsAbs() || parsed.Fragment != "" {
		return false
	}
	rawPath := value
	if index := strings.IndexByte(value, '?'); index >= 0 {
		rawPath = value[:index]
	}
	if parsed.EscapedPath() != rawPath {
		return false
	}
	query, err := url.ParseQuery(parsed.RawQuery)
	if err != nil {
		return false
	}
	canonical, err := CanonicalPathAndQuery(rawPath, query)
	return err == nil && canonical == value
}

// CanonicalPathAndQuery matches the worker verifier: decoded query entries
// are ordered by key then value and encoded with application/x-www-form-urlencoded.
func CanonicalPathAndQuery(path string, query url.Values) (string, error) {
	parsed, err := url.ParseRequestURI(path)
	if err != nil || !strings.HasPrefix(path, "/") || parsed.RawQuery != "" || parsed.Fragment != "" || parsed.EscapedPath() != path {
		return "", ErrInvalidAssertion
	}
	type entry struct{ key, value string }
	entries := make([]entry, 0)
	for key, values := range query {
		if !utf8.ValidString(key) {
			return "", ErrInvalidAssertion
		}
		for _, value := range values {
			if !utf8.ValidString(value) {
				return "", ErrInvalidAssertion
			}
			entries = append(entries, entry{key: key, value: value})
		}
	}
	sort.Slice(entries, func(i, j int) bool {
		if entries[i].key == entries[j].key {
			return javascriptStringLess(entries[i].value, entries[j].value)
		}
		return javascriptStringLess(entries[i].key, entries[j].key)
	})
	parts := make([]string, len(entries))
	for index, item := range entries {
		parts[index] = whatwgFormEncode(item.key) + "=" + whatwgFormEncode(item.value)
	}
	if len(parts) == 0 {
		return path, nil
	}
	return path + "?" + strings.Join(parts, "&"), nil
}

func javascriptStringLess(left, right string) bool {
	leftUnits := utf16.Encode([]rune(left))
	rightUnits := utf16.Encode([]rune(right))
	limit := len(leftUnits)
	if len(rightUnits) < limit {
		limit = len(rightUnits)
	}
	for index := 0; index < limit; index++ {
		if leftUnits[index] != rightUnits[index] {
			return leftUnits[index] < rightUnits[index]
		}
	}
	return len(leftUnits) < len(rightUnits)
}

func whatwgFormEncode(value string) string {
	const upperHex = "0123456789ABCDEF"
	var encoded strings.Builder
	encoded.Grow(len(value))
	for _, valueByte := range []byte(value) {
		switch {
		case valueByte >= 'A' && valueByte <= 'Z', valueByte >= 'a' && valueByte <= 'z', valueByte >= '0' && valueByte <= '9', valueByte == '*', valueByte == '-', valueByte == '.', valueByte == '_':
			encoded.WriteByte(valueByte)
		case valueByte == ' ':
			encoded.WriteByte('+')
		default:
			encoded.WriteByte('%')
			encoded.WriteByte(upperHex[valueByte>>4])
			encoded.WriteByte(upperHex[valueByte&0x0f])
		}
	}
	return encoded.String()
}

func validateOAClaim(input AdministratorAssertion, now time.Time) error {
	claim := input.OA
	if claim == nil || !safeIDPattern.MatchString(claim.GrantID) || claim.EventID != input.EventID || claim.RequesterID != input.Subject || !safeIDPattern.MatchString(string(claim.TargetSubject)) || claim.TargetSubject == input.Subject || !safeIDPattern.MatchString(claim.TargetID) || claim.RoleBindingID != input.RoleBindingID || claim.RoleBindingVersion != input.RoleVersion || claim.ChallengeVersion != input.ChallengeVersion || !safeIDPattern.MatchString(claim.ClaimNonce) || !claim.LeaseExpiresAt.UTC().Truncate(time.Second).After(now) || !positiveJSONSafeInteger(claim.Version) {
		return ErrInvalidAssertion
	}
	if claim.TargetType != identityaccess.TargetApplication && claim.TargetType != identityaccess.TargetCheckIn {
		return ErrInvalidAssertion
	}
	if !validIdentityFields(claim.Fields) || claim.FieldSetHash != IdentityFieldSetHash(claim.Fields) {
		return ErrInvalidAssertion
	}
	return nil
}

func validIdentityFields(fields []identityaccess.Field) bool {
	if len(fields) == 0 {
		return false
	}
	for index, field := range fields {
		switch field {
		case identityaccess.FieldLegalName, identityaccess.FieldIdentityNumber, identityaccess.FieldIdentityPhoto, identityaccess.FieldContactEmail, identityaccess.FieldContactMobile:
		default:
			return false
		}
		if index > 0 && fields[index-1] >= field {
			return false
		}
	}
	return true
}

func populateOAClaims(output *administratorClaims, claim OAClaim) {
	fields, targetType := approvedIdentityFields(claim.Fields), string(claim.TargetType)
	if claim.TargetType == identityaccess.TargetCheckIn {
		targetType = "participant"
	}
	output.GrantID = claim.GrantID
	output.GrantVersion = claim.Version
	output.RequesterUserID = string(claim.RequesterID)
	output.TargetType = targetType
	output.TargetID = claim.TargetID
	output.TargetSubjectUserID = string(claim.TargetSubject)
	output.ApprovedFields = fields
	output.FieldSetHash = hashApprovedFields(fields)
	output.ClaimNonce = claim.ClaimNonce
}

func approvedIdentityFields(fields []identityaccess.Field) []string {
	mapped := make([]string, 0, len(fields))
	for _, field := range fields {
		switch field {
		case identityaccess.FieldLegalName:
			mapped = append(mapped, "legal_name")
		case identityaccess.FieldIdentityNumber:
			mapped = append(mapped, "identity_document_number")
		case identityaccess.FieldIdentityPhoto:
			mapped = append(mapped, "portrait")
		case identityaccess.FieldContactEmail:
			mapped = append(mapped, "email")
		case identityaccess.FieldContactMobile:
			mapped = append(mapped, "mobile")
		}
	}
	sort.Strings(mapped)
	return mapped
}

// SHA256Digest returns the lowercase hexadecimal representation required by
// the DreamUP request verifier.
func SHA256Digest(value []byte) string {
	digest := sha256.Sum256(value)
	return hex.EncodeToString(digest[:])
}

// IdentityFieldSetHash matches the Task 8 grant binding, which uses raw URL
// base64 over NUL-delimited internal field names.
func IdentityFieldSetHash(fields []identityaccess.Field) string {
	values := make([]string, len(fields))
	for index, field := range fields {
		values[index] = string(field)
	}
	sort.Strings(values)
	digest := sha256.Sum256([]byte(strings.Join(values, "\x00")))
	return base64.RawURLEncoding.EncodeToString(digest[:])
}

// ApprovedIdentityFieldSetHash matches SHA-256(JSON.stringify(approvedFields))
// in the DreamUP verifier after mapping Task 8 names to worker names.
func ApprovedIdentityFieldSetHash(fields []identityaccess.Field) string {
	return hashApprovedFields(approvedIdentityFields(fields))
}

func hashApprovedFields(fields []string) string {
	canonical, _ := json.Marshal(fields)
	return SHA256Digest(canonical)
}

func (k *Keyring) signedAssertion(claims any) (SignedAssertion, error) {
	token, times, err := k.signJWT(claims)
	if err != nil {
		return SignedAssertion{}, err
	}
	return SignedAssertion{
		Token: token, NotBefore: time.Unix(times.NotBefore, 0).UTC(), ExpiresAt: time.Unix(times.ExpiresAt, 0).UTC(),
	}, nil
}

func (k *Keyring) signJWT(claims any) (string, registeredClaims, error) {
	header, err := json.Marshal(struct {
		Alg string `json:"alg"`
		Kid string `json:"kid"`
		Typ string `json:"typ"`
	}{Alg: "EdDSA", Kid: k.CurrentKeyID(), Typ: "JWT"})
	if err != nil {
		return "", registeredClaims{}, fmt.Errorf("dreamup delegation: encode header: %w", err)
	}
	payload, err := json.Marshal(claims)
	if err != nil {
		return "", registeredClaims{}, fmt.Errorf("dreamup delegation: encode claims: %w", err)
	}
	var times registeredClaims
	if err := json.Unmarshal(payload, &times); err != nil {
		return "", registeredClaims{}, fmt.Errorf("dreamup delegation: recover time bounds: %w", err)
	}
	unsigned := base64.RawURLEncoding.EncodeToString(header) + "." + base64.RawURLEncoding.EncodeToString(payload)
	signature, err := k.sign([]byte(unsigned))
	if err != nil {
		return "", registeredClaims{}, err
	}
	return unsigned + "." + base64.RawURLEncoding.EncodeToString(signature), times, nil
}
