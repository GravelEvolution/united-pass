// Package wechatonboarding coordinates the explicit WeChat Mini Program
// onboarding flow. It keeps provider proofs, account lookup, password/MFA
// verification, account linking and short-lived challenges behind narrow
// ports so the flow can be tested without Redis, PostgreSQL or ZITADEL.
package wechatonboarding

import (
	"context"
	"encoding/json"
	"errors"
	"time"

	"github.com/GravelEvolution/united-pass/backend/internal/auth"
	"github.com/GravelEvolution/united-pass/backend/internal/identity"
	"github.com/GravelEvolution/united-pass/backend/internal/registration"
	"github.com/GravelEvolution/united-pass/backend/internal/securitystate"
	"github.com/GravelEvolution/united-pass/backend/internal/wechat"
	"github.com/GravelEvolution/united-pass/backend/internal/wechatregistration"
)

const (
	// ChallengePurpose is embedded in every encrypted onboarding payload. A
	// store must reject ciphertext whose purpose or token binding differs.
	ChallengePurpose = "wechat_onboarding_v2"
	// MFAChallengePurpose separates password-completion state from the first
	// WeChat onboarding proof even though both use the same Redis primitive.
	MFAChallengePurpose = "wechat_onboarding_mfa_v2"
)

type ChallengeKind string

const (
	ChallengeKindOnboarding ChallengeKind = "onboarding"
	ChallengeKindMFA        ChallengeKind = "mfa"
)

var (
	ErrInvalidInput       = errors.New("wechat onboarding: invalid input")
	ErrUnavailable        = errors.New("wechat onboarding: unavailable")
	ErrChallengeNotFound  = errors.New("wechat onboarding: challenge not found")
	ErrChallengeClaimed   = errors.New("wechat onboarding: challenge already claimed")
	ErrChallengeNotHeld   = errors.New("wechat onboarding: challenge claim not held")
	ErrChallengeInvalid   = errors.New("wechat onboarding: challenge invalid")
	ErrMaxAttempts        = errors.New("wechat onboarding: maximum attempts exceeded")
	ErrRateLimited        = errors.New("wechat onboarding: rate limited")
	ErrPasswordMismatch   = errors.New("wechat onboarding: existing account password mismatch")
	ErrAccountInactive    = errors.New("wechat onboarding: account inactive")
	ErrAccountChanged     = errors.New("wechat onboarding: account changed during authentication")
	ErrEmailAmbiguous     = errors.New("wechat onboarding: email is ambiguous")
	ErrIdentityConflict   = errors.New("wechat onboarding: identity conflict")
	ErrPhoneConflict      = errors.New("wechat onboarding: phone conflict")
	ErrAuthenticationFail = errors.New("wechat onboarding: authentication failed")
)

type Status string

const (
	StatusAuthenticated      Status = "authenticated"
	StatusOnboardingRequired Status = "onboarding_required"
	StatusMFARequired        Status = "mfa_required"
	StatusVerificationNeeded Status = "verification_required"
)

// ChallengeData is encrypted as a single payload before it reaches Redis.
// TokenHash binds the ciphertext to its Redis key and prevents a valid
// ciphertext from being moved to another challenge key.
type ChallengeData struct {
	Purpose               string              `json:"purpose"`
	Kind                  ChallengeKind       `json:"kind"`
	TokenHash             string              `json:"tokenHash"`
	TenantID              string              `json:"tenantId"`
	Subject               string              `json:"subject"`
	Phone                 string              `json:"phone,omitempty"`
	TargetUserID          identity.UserID     `json:"targetUserId,omitempty"`
	NormalizedEmail       string              `json:"normalizedEmail,omitempty"`
	ExpectedVersion       int                 `json:"expectedVersion,omitempty"`
	ExpectedSecurityEpoch securitystate.Epoch `json:"expectedSecurityEpoch,omitempty"`
	Provider              string              `json:"provider,omitempty"`
	ProviderSessionID     string              `json:"providerSessionId,omitempty"`
	AvailableMethods      []auth.MFAMethod    `json:"availableMethods,omitempty"`
	PasskeyRequestOptions json.RawMessage     `json:"passkeyRequestOptions,omitempty"`
	CreatedAt             time.Time           `json:"createdAt"`
}

// ChallengeStore owns raw-token hashing. Implementations must use
// session.HashToken internally and must never persist or log the raw token.
type ChallengeStore interface {
	Create(context.Context, string, ChallengeData, time.Duration) error
	Claim(context.Context, string, string) (ChallengeData, error)
	Release(context.Context, string, string) error
	Consume(context.Context, string, string) error
	IncrementAttempts(context.Context, string, int) (int, error)
}

// ProofVerifier performs the server-to-server wx.login exchange and treats
// phone authorization as optional. A phone-code failure must not invalidate a
// successfully proven WeChat identity.
type ProofVerifier interface {
	VerifyOnboarding(context.Context, string, string) (wechat.IdentityProof, error)
}

// BindingReader is the existing explicit WeChat-link read model. It is used
// only to restore an already-linked account; it never creates an account.
type BindingReader interface {
	GetIdentityLink(context.Context, string, string, string) (identity.IdentityLink, error)
	GetByID(context.Context, identity.UserID) (identity.User, error)
}

// AccountRepository performs the only existing-account authority mutation.
// BindExistingWithWeChat must be one transaction: add the WeChat link, and
// add the verified phone only when the target phone is empty or identical.
// It must never overwrite a different phone or any profile/role data.
type AccountRepository interface {
	FindByNormalizedEmail(context.Context, string) (AccountSnapshot, error)
	BindExistingWithWeChat(context.Context, BindExistingInput) (BindExistingResult, error)
}

// AccountSnapshot binds an authentication attempt to the exact authority row
// that owned the normalized email before password verification began.
type AccountSnapshot struct {
	User            identity.User
	NormalizedEmail string
	Version         int
	SecurityEpoch   securitystate.Epoch
}

type BindExistingInput struct {
	UserID                identity.UserID
	TenantID              string
	Subject               string
	Phone                 string
	NormalizedEmail       string
	ExpectedVersion       int
	ExpectedSecurityEpoch securitystate.Epoch
}

type BindExistingResult struct {
	UserID        identity.UserID
	Version       int
	SecurityEpoch securitystate.Epoch
	Linked        bool
	PhoneAdded    bool
}

// PasswordAuthenticator deliberately addresses an already-resolved stable
// user ID. It must not fall back to the caller-provided email or username.
type PasswordAuthenticator interface {
	VerifyUserPassword(context.Context, identity.UserID, string) (auth.AuthenticationResult, error)
	CompleteMFA(context.Context, auth.MFAChallengeInput) (auth.AuthenticationResult, error)
	RevokeProviderSession(context.Context, string) error
}

type NewAccountCreator interface {
	CreateVerified(context.Context, wechatregistration.CreateVerifiedInput) (registration.CreateResult, error)
}

// RateChecker reuses the fixed-window MFA limiter, but is called only after a
// valid challenge has been atomically claimed. This ordering is what permits
// the complete endpoint to return the requested stable password-mismatch code
// without turning arbitrary requests into an email-existence oracle.
type RateChecker interface {
	CheckMFA(context.Context, string, string, int, time.Duration) (bool, time.Duration, error)
}

// CompletionRateChecker applies the ordinary registration abuse buckets only
// after the onboarding challenge has been atomically claimed. Calling it in
// an unauthenticated HTTP adapter would let forged requests exhaust a victim
// email's global bucket without possessing a valid WeChat proof.
type CompletionRateChecker interface {
	CheckRegistrationCreate(context.Context, string, string, string, registration.CreateRatePolicy) (bool, time.Duration, error)
}

type BeginInput struct {
	LoginCode string
	PhoneCode string
}

type BeginResult struct {
	Status          Status
	UserID          identity.UserID
	OnboardingToken string
	ExpiresAt       time.Time
}

type CompleteInput struct {
	OnboardingToken string
	Email           string
	Password        string
	Username        string
	DisplayName     string
	AcceptedTerms   bool
	RequestID       string
	ClientIP        string
	ClientNetwork   string
}

type MFAInput struct {
	MFAToken         string
	Method           auth.MFAMethod
	Code             string
	PasskeyAssertion json.RawMessage
	ClientIP         string
}

type CompleteResult struct {
	Status                Status
	Authentication        auth.AuthenticationResult
	MFAToken              string
	AvailableMethods      []auth.MFAMethod
	PasskeyRequestOptions json.RawMessage
	RegistrationToken     string
	ExpiresAt             time.Time
}

// RateLimitError retains the server-side retry hint while still matching the
// stable ErrRateLimited sentinel.
type RateLimitError struct{ RetryAfter time.Duration }

func (e *RateLimitError) Error() string { return ErrRateLimited.Error() }
func (e *RateLimitError) Unwrap() error { return ErrRateLimited }
