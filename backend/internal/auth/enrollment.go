//
// Copyright (c) 2026 Chen Jiajie(Ariakage)
//
// Author: Chen Jiajie(Ariakage) <ariakage233@gmail.com>
// Date: 2026-08-06
// Description: Security factor enrollment challenge data (ADR-0006 §7/§8)
//

package auth

import (
	"errors"

	"github.com/GravelEvolution/united-pass/backend/internal/identity"
	"github.com/GravelEvolution/united-pass/backend/internal/securitystate"
)

// ErrEnrollmentNotFound is returned when an enrollment challenge expired,
// was already consumed, or never existed. Consumed enrollments can never be
// reused, so retries must start a fresh enrollment (and reauthentication).
var ErrEnrollmentNotFound = errors.New("auth: enrollment not found")

// ErrEnrollmentClaimed is returned when another request already holds the
// claim lock of an enrollment challenge (concurrent confirmation race).
var ErrEnrollmentClaimed = errors.New("auth: enrollment already claimed")

// ErrEnrollmentNotHeld is returned when a release/consume call no longer
// holds the claim lock (expired or taken over); nothing is created.
var ErrEnrollmentNotHeld = errors.New("auth: enrollment claim not held")

// EnrollmentKind identifies which factor an enrollment challenge belongs to.
type EnrollmentKind string

const (
	// EnrollmentTOTP is a TOTP enrollment challenge.
	EnrollmentTOTP EnrollmentKind = "totp"
	// EnrollmentPasskey is a passkey registration challenge.
	EnrollmentPasskey EnrollmentKind = "passkey"
)

// EnrollmentData is the server-side record of a factor enrollment challenge.
// It follows the MFA/reauth token pattern (ADR-0006 §7): short-lived,
// single-use, keyed by the SHA-256 hash of the raw token in Redis, and bound
// to the user and session that began it, so the confirm step needs no second
// reauthentication ceremony and a stolen token cannot be redeemed by another
// account or session.
type EnrollmentData struct {
	UserID    identity.UserID `json:"userId"`
	SessionID string          `json:"sessionId"`
	Kind      EnrollmentKind  `json:"kind"`
	// Target binds the provider-issued passkey ID for passkey enrollments
	// (empty for TOTP). The confirm step must present the same enrollment
	// that minted the passkey being verified; an enrollment for passkey A
	// can never confirm passkey B (ADR-0006 §4 Target semantics).
	Target string `json:"target,omitempty"`
	// SecurityEpoch stamps the enrollment with the issuing session's
	// security generation (ADR-0007 Decision 1). Confirmation must
	// additionally verify the user's authoritative state against this
	// stamp. Legacy records decode as 0 and are normalized to 1 (F2).
	SecurityEpoch securitystate.Epoch `json:"securityEpoch,omitempty"`
}
