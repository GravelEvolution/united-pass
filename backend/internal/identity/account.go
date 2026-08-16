//
// Copyright (c) 2026 Chen Jiajie(Ariakage)
//
// Author: Chen Jiajie(Ariakage) <ariakage233@gmail.com>
// Date: 2026-08-16
// Description: Account self-service domain types and provider port
//

package identity

import (
	"context"
	"errors"
	"time"
)

// ContactKind identifies a security contact maintained by the identity
// provider and mirrored locally only after provider verification succeeds.
type ContactKind string

const (
	ContactKindEmail ContactKind = "email"
	ContactKindPhone ContactKind = "phone"
)

// ContactChangeRequest is the durable server-side state behind the opaque
// request capability returned to the browser. The raw capability is never
// persisted; RequestIDHash is its SHA-256 digest.
type ContactChangeRequest struct {
	RequestIDHash string
	UserID        UserID
	SessionID     string
	Kind          ContactKind
	Value         string
	Attempts      int
	ExpiresAt     time.Time
}

var (
	ErrContactRequestNotFound = errors.New("contact change request not found")
	ErrContactRequestClaimed  = errors.New("contact change request already claimed")
	ErrContactCodeInvalid     = errors.New("contact verification code invalid")
	ErrContactConflict        = errors.New("contact value already in use")
	ErrAccountProvider        = errors.New("account identity provider unavailable")
)

// AccountContactProvider owns the authoritative email and phone verification
// lifecycle. United Pass never invents or validates provider codes itself.
type AccountContactProvider interface {
	BeginEmailChange(ctx context.Context, userID UserID, email string) error
	VerifyEmailChange(ctx context.Context, userID UserID, email, code string) error
	BeginPhoneChange(ctx context.Context, userID UserID, phone string) error
	VerifyPhoneChange(ctx context.Context, userID UserID, phone, code string) error
}
