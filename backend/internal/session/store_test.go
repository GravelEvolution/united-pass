//
// Copyright (c) 2026 Chen Jiajie(Ariakage)
//
// Author: Chen Jiajie(Ariakage) <ariakage233@gmail.com>
// Date: 2026-08-05
// Description: Unit tests for the session store contracts
//

package session

import (
	"context"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/GravelEvolution/united-pass/backend/internal/auth"
	"github.com/GravelEvolution/united-pass/backend/internal/identity"
)

// fakeStore is an in-memory session Store for unit tests.
type fakeStore struct {
	mu       sync.Mutex
	sessions map[string]SessionRecord
}

func newFakeStore() *fakeStore {
	return &fakeStore{sessions: make(map[string]SessionRecord)}
}

func (s *fakeStore) Create(_ context.Context, tokenHash string, record SessionRecord, _ time.Duration) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.sessions[tokenHash] = record
	return nil
}

func (s *fakeStore) Get(_ context.Context, tokenHash string) (SessionRecord, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	r, ok := s.sessions[tokenHash]
	if !ok {
		return SessionRecord{}, ErrSessionNotFound
	}
	return r, nil
}

func (s *fakeStore) Delete(_ context.Context, tokenHash string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	delete(s.sessions, tokenHash)
	return nil
}

func (s *fakeStore) Touch(_ context.Context, tokenHash string, lastSeenAt time.Time, _ time.Duration) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	r, ok := s.sessions[tokenHash]
	if !ok {
		return ErrSessionNotFound
	}
	r.LastSeenAt = lastSeenAt
	s.sessions[tokenHash] = r
	return nil
}

func (s *fakeStore) Rotate(_ context.Context, oldHash, newHash string, newRecord SessionRecord, _ time.Duration) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.sessions[newHash] = newRecord
	delete(s.sessions, oldHash)
	return nil
}

func newTestService(encryptor Encryptor) *Service {
	return NewService(newFakeStore(), SystemClock{}, time.Hour, 30*time.Hour, 15*time.Minute, 5*time.Minute, encryptor)
}

func inputWithReference() CreateSessionInput {
	return CreateSessionInput{
		UserID:                   identity.UserID("user_enc_test"),
		Provider:                 "fake",
		ProviderSessionReference: "provider-session-ref-secret",
		AuthenticationMethods:    []auth.AuthenticationMethod{auth.MethodPassword},
	}
}

func TestCreateSessionEncryptsProviderReference(t *testing.T) {
	svc := newTestService(testEncryptor())
	store := svc.store.(*fakeStore)

	result, err := svc.CreateSession(context.Background(), inputWithReference())
	if err != nil {
		t.Fatalf("CreateSession: %v", err)
	}

	// The stored reference must be ciphertext, not the plaintext.
	stored := store.sessions[result.TokenHash]
	if stored.ProviderSessionReference == "provider-session-ref-secret" {
		t.Fatal("provider session reference stored in plaintext")
	}
	if stored.ProviderSessionReference == "" {
		t.Fatal("provider session reference missing after encryption")
	}

	// Decryption must recover the original value.
	decrypted, err := svc.DecryptProviderSessionReference(context.Background(), stored.ProviderSessionReference)
	if err != nil {
		t.Fatalf("DecryptProviderSessionReference: %v", err)
	}
	if decrypted != "provider-session-ref-secret" {
		t.Errorf("decrypted = %q, want original reference", decrypted)
	}
}

func TestCreateSessionRefusesPlaintextWithoutEncryptor(t *testing.T) {
	svc := newTestService(nil)

	_, err := svc.CreateSession(context.Background(), inputWithReference())
	if err == nil {
		t.Fatal("expected error when provider reference present but no encryptor configured")
	}
	if !strings.Contains(err.Error(), "encryption key not configured") {
		t.Errorf("error = %v, want missing encryption key", err)
	}
}

func TestCreateSessionAllowsEmptyReferenceWithoutEncryptor(t *testing.T) {
	svc := newTestService(nil)

	input := inputWithReference()
	input.ProviderSessionReference = ""

	result, err := svc.CreateSession(context.Background(), input)
	if err != nil {
		t.Fatalf("CreateSession without reference: %v", err)
	}
	if result.Record.ProviderSessionReference != "" {
		t.Error("expected empty stored reference")
	}
}

func testEncryptor() Encryptor {
	enc, err := NewAESGCMEncryptor("MDEyMzQ1Njc4OWFiY2RlZjAxMjM0NTY3ODlhYmNkZWY=", "test-v1")
	if err != nil {
		panic(err)
	}
	return enc
}
