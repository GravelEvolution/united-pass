// Package qrauth owns the cross-device QR login handshake. A scanned QR ID
// can only approve a waiting browser; a distinct HttpOnly receiver secret is
// required to consume the resulting login and no session token crosses the QR.
package qrauth

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"time"

	"github.com/GravelEvolution/united-pass/backend/internal/identity"
	"github.com/GravelEvolution/united-pass/backend/internal/session"
)

var (
	ErrNotFound    = errors.New("qr auth: challenge not found")
	ErrExpired     = errors.New("qr auth: challenge expired")
	ErrConsumed    = errors.New("qr auth: challenge already consumed")
	ErrPending     = errors.New("qr auth: challenge pending approval")
	ErrDenied      = errors.New("qr auth: receiver proof invalid")
	ErrUnavailable = errors.New("qr auth: unavailable")
)

type Store interface {
	Create(context.Context, string, string, time.Duration) error
	Approve(context.Context, string, identity.UserID) error
	Consume(context.Context, string, string) (identity.UserID, error)
}

type Service struct {
	store    Store
	ttl      time.Duration
	generate func() (string, error)
}

func NewService(store Store, ttl time.Duration, generate func() (string, error)) *Service {
	if generate == nil {
		generate = session.GenerateToken
	}
	return &Service{store: store, ttl: ttl, generate: generate}
}

// Begin returns the QR-visible challenge ID and a browser-only receiver
// secret. Only the latter may be sent as a protected cookie.
func (s *Service) Begin(ctx context.Context) (challengeID, receiverSecret string, err error) {
	if s == nil || s.store == nil || s.ttl <= 0 || s.generate == nil {
		return "", "", ErrUnavailable
	}
	challengeID, err = s.generate()
	if err != nil || challengeID == "" {
		return "", "", ErrUnavailable
	}
	receiverSecret, err = s.generate()
	if err != nil || receiverSecret == "" || receiverSecret == challengeID {
		return "", "", ErrUnavailable
	}
	if err := s.store.Create(ctx, hash(challengeID), hash(receiverSecret), s.ttl); err != nil {
		return "", "", ErrUnavailable
	}
	return challengeID, receiverSecret, nil
}

func (s *Service) Approve(ctx context.Context, challengeID string, userID identity.UserID) error {
	if s == nil || s.store == nil || challengeID == "" || userID == "" {
		return ErrUnavailable
	}
	return s.store.Approve(ctx, hash(challengeID), userID)
}

func (s *Service) Consume(ctx context.Context, challengeID, receiverSecret string) (identity.UserID, error) {
	if s == nil || s.store == nil || challengeID == "" || receiverSecret == "" {
		return "", ErrDenied
	}
	return s.store.Consume(ctx, hash(challengeID), hash(receiverSecret))
}

func hash(value string) string {
	sum := sha256.Sum256([]byte(value))
	return hex.EncodeToString(sum[:])
}

// AuditChallengeReference returns the one-way correlation value permitted in
// durable audit events. The QR-visible challenge itself is a bearer-like
// handoff value and must never enter a database audit record, log, or metric.
// The same value is already used internally as the Redis key suffix, but this
// exported seam keeps HTTP adapters from reimplementing its security rule.
func AuditChallengeReference(challengeID string) string {
	if challengeID == "" {
		return ""
	}
	return hash(challengeID)
}
