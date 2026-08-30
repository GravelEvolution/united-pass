// Package adminstepup defines persistence contracts for the administrator
// challenge factor and authoritative security epoch.
package adminstepup

import (
	"context"
	"errors"
	"time"

	"github.com/GravelEvolution/united-pass/backend/internal/identity"
)

type ChallengeStatus string

const (
	ChallengeActive          ChallengeStatus = "active"
	ChallengeRecoveryPending ChallengeStatus = "recovery_pending"
	ChallengeRevoked         ChallengeStatus = "revoked"
)

var (
	ErrNotFound = errors.New("adminstepup: challenge not found")
	ErrConflict = errors.New("adminstepup: challenge conflict")
)

type Challenge struct {
	UserID                 identity.UserID
	Status                 ChallengeStatus
	MustRotate             bool
	CredentialVersion      int64
	SecurityEpoch          int64
	FailureCount           int
	FailureWindowStartedAt *time.Time
	LockedUntil            *time.Time
	Version                int64
	CreatedAt              time.Time
	UpdatedAt              time.Time
}

// CredentialMaterial is restricted to the verification/enrollment service.
// HTTP response DTOs must use Challenge and cannot access this type through a
// general read model.
type CredentialMaterial struct {
	Challenge          Challenge
	QuestionKeyID      string
	QuestionNonce      []byte
	QuestionCiphertext []byte
	AnswerPHC          string
	AnswerPepperKeyID  string
}

type StepUpState struct {
	ID               string
	SessionID        string
	UserID           identity.UserID
	ChallengeVersion int64
	SecurityEpoch    int64
	VerifiedAt       time.Time
	ExpiresAt        time.Time
	RevokedAt        *time.Time
}

type Repository interface {
	Get(context.Context, identity.UserID) (Challenge, error)
	GetCredentialForVerification(context.Context, identity.UserID) (CredentialMaterial, error)
	PutCredential(context.Context, CredentialMaterial, int64) (Challenge, error)
	RecordFailure(context.Context, identity.UserID, int64, time.Time) (Challenge, error)
	PutStepUp(context.Context, StepUpState) error
	RevokeForUser(context.Context, identity.UserID, time.Time) error
}

type SecurityEpochRepository interface {
	Get(context.Context, identity.UserID) (int64, error)
	Increment(context.Context, identity.UserID, int64) (int64, error)
}
