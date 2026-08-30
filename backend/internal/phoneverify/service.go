//
// Copyright (c) 2026 Chen Jiajie(Ariakage)
//
// Author: Chen Jiajie(Ariakage) <ariakage233@gmail.com>
// Date: 2026-08-20
// Description: Phone verification domain service (SMS code + binding)
//

// Package phoneverify coordinates phone number binding through an
// out-of-band SMS verification code. United Pass issues the code itself,
// sends it through a configurable SMS provider and stores it in a short-lived
// single-use record; the verified phone is then written back to the local
// user record. The provider is never a United Pass identity authority.
package phoneverify

import (
	"context"
	"crypto/rand"
	"errors"
	"fmt"
	"regexp"
	"strings"
	"time"

	"github.com/GravelEvolution/united-pass/backend/internal/identity"
)

var (
	ErrInvalidInput       = errors.New("phoneverify: invalid input")
	ErrVerificationFailed = errors.New("phoneverify: verification failed")
	ErrUnavailable        = errors.New("phoneverify: unavailable")
)

// phonePattern accepts a +CC number (10–15 digits).
var phonePattern = regexp.MustCompile(`^\+[1-9][0-9]{6,14}$`)

// cnMobilePattern accepts an 11-digit mainland China mobile number without a
// country code; the canonical +86 prefix is added during normalization so the
// user does not need to type the international prefix.
var cnMobilePattern = regexp.MustCompile(`^1[3-9][0-9]{9}$`)

// Store persists verification records so a code can be consumed exactly once.
type Store interface {
	Create(ctx context.Context, requestID, phone, code string, ttl time.Duration) error
	Consume(ctx context.Context, requestID string) (phone, code string, ok bool, err error)
}

// Sender delivers the verification code through an SMS provider.
type Sender interface {
	SendCode(ctx context.Context, phone, code string) error
}

// Repository persists the verified phone on the local user record.
type Repository interface {
	UpdatePhone(ctx context.Context, userID identity.UserID, phone string) error
}

// Config tunes code generation and expiry.
type Config struct {
	CodeLength int
	TTL        time.Duration
}

// RequestInput begins a phone binding: the target phone receives a code.
type RequestInput struct {
	UserID identity.UserID
	Phone  string
}

// VerifyInput finishes a phone binding with the code sent to the phone.
type VerifyInput struct {
	UserID    identity.UserID
	RequestID string
	Code      string
}

// RequestResult is the outcome of Request.
type RequestResult struct{ RequestID string }

// Service implements the phone binding flow.
type Service struct {
	store  Store
	sender Sender
	repo   Repository
	cfg    Config
	now    func() time.Time
	random func([]byte) (int, error)
}

// NewService builds the phone verification service. Defaults are applied for
// missing configuration knobs.
func NewService(store Store, sender Sender, repo Repository, cfg Config) (*Service, error) {
	if store == nil || sender == nil || repo == nil {
		return nil, errors.New("phoneverify: store, sender and repository are required")
	}
	if cfg.CodeLength <= 0 {
		cfg.CodeLength = 6
	}
	if cfg.TTL <= 0 {
		cfg.TTL = 5 * time.Minute
	}
	return &Service{
		store: store, sender: sender, repo: repo, cfg: cfg,
		now:    time.Now,
		random: rand.Read,
	}, nil
}

// Request generates a code, persists it and sends it to the given phone.
func (s *Service) Request(ctx context.Context, input RequestInput) (RequestResult, error) {
	if s == nil || input.UserID == "" {
		return RequestResult{}, ErrUnavailable
	}
	phone, err := NormalizePhone(input.Phone)
	if err != nil {
		return RequestResult{}, err
	}
	code, err := s.generateCode()
	if err != nil {
		return RequestResult{}, ErrUnavailable
	}
	requestID, err := s.generateRequestID()
	if err != nil {
		return RequestResult{}, ErrUnavailable
	}
	if err := s.store.Create(ctx, requestID, phone, code, s.cfg.TTL); err != nil {
		return RequestResult{}, ErrUnavailable
	}
	if err := s.sender.SendCode(ctx, phone, code); err != nil {
		return RequestResult{}, ErrUnavailable
	}
	return RequestResult{RequestID: requestID}, nil
}

// Verify consumes the code and, on success, binds the phone to the user.
func (s *Service) Verify(ctx context.Context, input VerifyInput) (string, error) {
	if s == nil || input.UserID == "" || input.RequestID == "" || input.Code == "" {
		return "", ErrVerificationFailed
	}
	phone, code, ok, err := s.store.Consume(ctx, input.RequestID)
	if err != nil {
		return "", ErrUnavailable
	}
	if !ok || !constantTimeEqual(code, strings.TrimSpace(input.Code)) {
		return "", ErrVerificationFailed
	}
	if err := s.repo.UpdatePhone(ctx, input.UserID, phone); err != nil {
		if errors.Is(err, identity.ErrUserNotFound) {
			return "", ErrVerificationFailed
		}
		return "", ErrUnavailable
	}
	return phone, nil
}

func (s *Service) generateCode() (string, error) {
	random := make([]byte, s.cfg.CodeLength)
	if _, err := s.random(random); err != nil {
		return "", err
	}
	code := make([]byte, s.cfg.CodeLength)
	for i, b := range random {
		code[i] = '0' + (b % 10)
	}
	return string(code), nil
}

func (s *Service) generateRequestID() (string, error) {
	random := make([]byte, 16)
	if _, err := s.random(random); err != nil {
		return "", err
	}
	return "phone_verify_" + fmt.Sprintf("%x", random), nil
}

// NormalizePhone validates a phone number and returns it in canonical form.
// An 11-digit mainland China mobile number is normalized to +86<number> so the
// user only needs to type the local number.
func NormalizePhone(value string) (string, error) {
	value = strings.TrimSpace(value)
	value = strings.ReplaceAll(value, " ", "")
	value = strings.ReplaceAll(value, "-", "")
	if phonePattern.MatchString(value) {
		return value, nil
	}
	if cnMobilePattern.MatchString(value) {
		return "+86" + value, nil
	}
	return "", fmt.Errorf("%w: phone", ErrInvalidInput)
}

func constantTimeEqual(a, b string) bool {
	if len(a) != len(b) {
		return false
	}
	var diff byte
	for i := range a {
		diff |= a[i] ^ b[i]
	}
	return diff == 0
}
