// Package wechat defines the narrow, provider-neutral boundary for proving a
// WeChat Mini Program identity. It deliberately contains no HTTP, SQL, Redis,
// session, or logging implementation.
package wechat

import (
	"context"
	"errors"
	"strings"
	"unicode"
)

var (
	// ErrInvalidCode is returned before making any provider call.
	ErrInvalidCode = errors.New("wechat: invalid code")
	// ErrRejected covers consumed, invalid or platform-rejected one-time codes.
	// Callers must keep this response non-enumerating.
	ErrRejected = errors.New("wechat: proof rejected")
	// ErrUnavailable covers provider transport and server failures. Raw
	// provider messages must never escape this package.
	ErrUnavailable = errors.New("wechat: provider unavailable")
	// ErrPhoneRequired marks a missing or failed getPhoneNumber proof in a
	// flow that must never downgrade to identity-only authentication.
	ErrPhoneRequired = errors.New("wechat: verified phone proof is required")
)

const (
	ProviderName = "provider_wechat_miniprogram"
	maxCodeBytes = 2048
)

// IdentityProof is the minimum set of verified information needed by the
// onboarding or login use case. Subject is stable only within TenantID. Phone
// is present exclusively after a successful getPhoneNumber verification.
type IdentityProof struct {
	TenantID string
	Subject  string
	Phone    string
}

// Verifier owns the server-to-server WeChat protocol exchange. Neither the
// raw login code, phone code nor session_key cross this interface boundary.
type Verifier interface {
	VerifyLogin(context.Context, string) (IdentityProof, error)
	VerifyRegistration(context.Context, string, string) (IdentityProof, error)
}

// OnboardingVerifier proves both wx.login and getPhoneNumber. Phone-code
// absence, rejection or provider failure returns ErrPhoneRequired and no
// partial proof; onboarding cannot downgrade to identity-only authentication.
type OnboardingVerifier interface {
	VerifyOnboarding(context.Context, string, string) (IdentityProof, error)
}

// ValidateCode rejects blank, control-character and unreasonably long codes
// before they can reach logs, persistence, a rate-limit key or WeChat.
func ValidateCode(code string) error {
	if code == "" || len(code) > maxCodeBytes || strings.TrimSpace(code) != code {
		return ErrInvalidCode
	}
	for _, r := range code {
		if unicode.IsControl(r) {
			return ErrInvalidCode
		}
	}
	return nil
}

// Subject always chooses the Mini Program app-scoped OpenID. TenantID is the
// AppID, so (TenantID, OpenID) remains stable whether UnionID is absent today
// or appears later. UnionID is deliberately not an automatic fallback or
// replacement: any future cross-application migration must reconcile existing
// links explicitly and atomically. Identity is never derived from display
// data, email or phone number.
func Subject(unionID, openID string) (string, error) {
	_ = unionID // auxiliary provider fact; never the app-scoped primary key
	subject := strings.TrimSpace(openID)
	if subject == "" || len(subject) > 512 {
		return "", ErrRejected
	}
	for _, r := range subject {
		if unicode.IsControl(r) {
			return "", ErrRejected
		}
	}
	return subject, nil
}
