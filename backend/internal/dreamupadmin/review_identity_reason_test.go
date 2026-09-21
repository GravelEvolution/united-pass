package dreamupadmin

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"testing"
	"time"

	"github.com/GravelEvolution/united-pass/backend/internal/adminstepup"
	"github.com/GravelEvolution/united-pass/backend/internal/adminstore"
	"github.com/GravelEvolution/united-pass/backend/internal/permissions"
)

type reviewReasonCipherStub struct {
	encryptCalls int
	decryptCalls int
	plaintexts   []string
}

func (c *reviewReasonCipherStub) Encrypt(purpose adminstepup.EncryptionPurpose, owner, record string, version int64, plaintext string) (adminstepup.EncryptedValue, error) {
	c.encryptCalls++
	if purpose != adminstepup.PurposeProtectedReason || owner == "" || record == "" || version != 1 || plaintext == "" {
		return adminstepup.EncryptedValue{}, errors.New("unexpected encryption binding")
	}
	c.plaintexts = append(c.plaintexts, plaintext)
	return adminstepup.EncryptedValue{KeyID: "reason-v1", Nonce: []byte("nonce"), Ciphertext: []byte("sealed:" + plaintext)}, nil
}

func (c *reviewReasonCipherStub) Decrypt(purpose adminstepup.EncryptionPurpose, owner, record string, version int64, value adminstepup.EncryptedValue) (string, error) {
	c.decryptCalls++
	if purpose != adminstepup.PurposeProtectedReason || owner == "" || record == "" || version != 1 || value.KeyID != "reason-v1" || string(value.Nonce) != "nonce" {
		return "", errors.New("unexpected decryption binding")
	}
	const prefix = "sealed:"
	if len(value.Ciphertext) <= len(prefix) || string(value.Ciphertext[:len(prefix)]) != prefix {
		return "", errors.New("invalid ciphertext")
	}
	return string(value.Ciphertext[len(prefix):]), nil
}

type reviewReasonRepositoryStub struct {
	record      *adminstore.ProtectedReason
	createCalls int
	markCalls   int
}

func (r *reviewReasonRepositoryStub) Create(context.Context, string, string, string, []byte, []byte, time.Time) error {
	panic("legacy create must not be used")
}

func (r *reviewReasonRepositoryStub) CreateOrReplay(_ context.Context, incoming adminstore.ProtectedReason) (adminstore.ProtectedReason, bool, error) {
	r.createCalls++
	if r.record == nil {
		stored := cloneProtectedReason(incoming)
		r.record = &stored
		return cloneProtectedReason(stored), false, nil
	}
	return cloneProtectedReason(*r.record), true, nil
}

func (r *reviewReasonRepositoryStub) MarkTerminal(_ context.Context, id string, terminal, expires time.Time) error {
	r.markCalls++
	if r.record == nil || r.record.ID != id || !expires.After(terminal) {
		return adminstore.ErrIdempotencyConflict
	}
	if r.record.TerminalAt != nil {
		if r.record.ConsumedAt == nil || r.record.ExpiresAt == nil || !r.record.ConsumedAt.Equal(terminal) || !r.record.TerminalAt.Equal(terminal) || !r.record.ExpiresAt.Equal(expires) {
			return adminstore.ErrIdempotencyConflict
		}
		return nil
	}
	r.record.ConsumedAt = timePointer(terminal)
	r.record.TerminalAt = timePointer(terminal)
	r.record.ExpiresAt = timePointer(expires)
	return nil
}

func (*reviewReasonRepositoryStub) PurgeExpired(context.Context, time.Time, int) (int, error) {
	panic("unexpected purge")
}

type reviewReasonUOWStub struct{ repository *reviewReasonRepositoryStub }

func (u reviewReasonUOWStub) Within(ctx context.Context, fn func(adminstore.Repositories) error) error {
	if u.repository == nil {
		return errors.New("authority reason store unavailable")
	}
	return fn(adminstore.Repositories{Reasons: u.repository})
}

func cloneProtectedReason(value adminstore.ProtectedReason) adminstore.ProtectedReason {
	value.Nonce = append([]byte(nil), value.Nonce...)
	value.Ciphertext = append([]byte(nil), value.Ciphertext...)
	return value
}

func timePointer(value time.Time) *time.Time { return &value }

func reviewIdentityReasonProxyRequest(requestID string) ProxyRequest {
	return ProxyRequest{
		EventID: "evt_shanghai", Capability: permissions.ActionIdentityReadRestricted,
		ResourceKind: "application", ResourceID: "app_1", Method: http.MethodPost,
		Path:      "/internal/v1/events/evt_shanghai/applications/app_1/review-identity",
		Body:      []byte(`{"protectedReasonId":"` + ReviewIdentityProtectedReasonID(requestID) + `"}`),
		RequestID: requestID, IdempotencyKey: "0123456789abcdef0123456789abcdef", IfMatch: `"1"`,
	}
}

func TestPersistReviewIdentityReasonEncryptsTerminalizesAndReplaysForTwentyFourMonths(t *testing.T) {
	now := time.Date(2026, 9, 4, 8, 30, 0, 123456000, time.UTC)
	repository := &reviewReasonRepositoryStub{}
	cipher := &reviewReasonCipherStub{}
	service := &Service{reasonUOW: reviewReasonUOWStub{repository}, reasonCipher: cipher, now: func() time.Time { return now }}
	actor := Actor{UserID: "user_reviewer"}
	input := reviewIdentityReasonProxyRequest("req_review_identity_1")

	if err := service.persistReviewIdentityReason(context.Background(), actor, input); err != nil {
		t.Fatal(err)
	}
	if repository.record == nil || repository.record.OwnerUserID != "user_reviewer" || repository.record.OperationKind != "direct_read" || repository.record.ID != ReviewIdentityProtectedReasonID(input.RequestID) {
		t.Fatalf("record=%+v", repository.record)
	}
	if string(repository.record.Ciphertext) == ReviewIdentityProtectedReason || repository.record.TerminalAt == nil || repository.record.ConsumedAt == nil || repository.record.ExpiresAt == nil {
		t.Fatalf("unencrypted or incomplete reason lifecycle: %+v", repository.record)
	}
	var payload reviewIdentityProtectedReasonPayload
	if err := json.Unmarshal([]byte(cipher.plaintexts[0]), &payload); err != nil {
		t.Fatal(err)
	}
	if payload.Schema != reviewIdentityReasonSchema || payload.Reason != ReviewIdentityProtectedReason || payload.Action != "identity.read_restricted" ||
		payload.EventID != "evt_shanghai" || payload.TargetType != "application" || payload.TargetID != "app_1" || len(payload.RequestFingerprint) != 64 {
		t.Fatalf("protected payload=%+v", payload)
	}
	if !repository.record.ConsumedAt.Equal(now) || !repository.record.TerminalAt.Equal(now) || !repository.record.ExpiresAt.Equal(now.AddDate(2, 0, 0)) {
		t.Fatalf("reason retention mismatch: %+v", repository.record)
	}

	// A transport or client retry with the same request identity reuses and
	// verifies the authority record rather than creating a second reason.
	service.now = func() time.Time { return now.Add(time.Hour) }
	if err := service.persistReviewIdentityReason(context.Background(), actor, input); err != nil {
		t.Fatalf("idempotent replay failed: %v", err)
	}
	if repository.createCalls != 2 || repository.markCalls != 1 || cipher.encryptCalls != 2 || cipher.decryptCalls != 2 || !repository.record.TerminalAt.Equal(now) {
		t.Fatalf("create=%d mark=%d encrypt=%d decrypt=%d record=%+v", repository.createCalls, repository.markCalls, cipher.encryptCalls, cipher.decryptCalls, repository.record)
	}
}

func TestPersistReviewIdentityReasonRejectsRequestIDRebindingToAnotherApplication(t *testing.T) {
	now := time.Date(2026, 9, 4, 8, 30, 0, 0, time.UTC)
	repository := &reviewReasonRepositoryStub{}
	service := &Service{reasonUOW: reviewReasonUOWStub{repository}, reasonCipher: &reviewReasonCipherStub{}, now: func() time.Time { return now }}
	actor := Actor{UserID: "user_reviewer"}
	input := reviewIdentityReasonProxyRequest("req_review_identity_bound")
	if err := service.persistReviewIdentityReason(context.Background(), actor, input); err != nil {
		t.Fatal(err)
	}
	input.ResourceID = "app_2"
	input.Path = "/internal/v1/events/evt_shanghai/applications/app_2/review-identity"
	if err := service.persistReviewIdentityReason(context.Background(), actor, input); !errors.Is(err, ErrUpstream) {
		t.Fatalf("rebound reason error=%v", err)
	}
}

func TestPersistReviewIdentityReasonRejectsCallerControlledOrMismatchedReason(t *testing.T) {
	now := time.Date(2026, 9, 4, 8, 30, 0, 0, time.UTC)
	for _, test := range []struct {
		name string
		body []byte
	}{
		{name: "plaintext reason is never accepted by the data-plane contract", body: []byte(`{"protectedReasonId":"review_identity_req_review_identity_2","reason":"` + ReviewIdentityProtectedReason + `"}`)},
		{name: "reason id must be bound to request id", body: []byte(`{"protectedReasonId":"review_identity_other"}`)},
	} {
		t.Run(test.name, func(t *testing.T) {
			repository := &reviewReasonRepositoryStub{}
			service := &Service{reasonUOW: reviewReasonUOWStub{repository}, reasonCipher: &reviewReasonCipherStub{}, now: func() time.Time { return now }}
			input := reviewIdentityReasonProxyRequest("req_review_identity_2")
			input.Body = test.body
			if err := service.persistReviewIdentityReason(context.Background(), Actor{UserID: "user_reviewer"}, input); !errors.Is(err, ErrInvalidRequest) || repository.createCalls != 0 {
				t.Fatalf("error=%v createCalls=%d", err, repository.createCalls)
			}
		})
	}
}

func TestPersistReviewIdentityReasonFailsClosedWithoutAuthorityStorage(t *testing.T) {
	now := time.Date(2026, 9, 4, 8, 30, 0, 0, time.UTC)
	service := &Service{reasonCipher: &reviewReasonCipherStub{}, now: func() time.Time { return now }}
	if err := service.persistReviewIdentityReason(context.Background(), Actor{UserID: "user_reviewer"}, reviewIdentityReasonProxyRequest("req_review_identity_storage")); !errors.Is(err, ErrUpstream) {
		t.Fatalf("error=%v", err)
	}
}

func TestNewServiceRequiresAuthorityReasonDependenciesInDurableMode(t *testing.T) {
	dependencies := ServiceDependencies{
		Authorizer: &serviceAuthorizerStub{}, Registry: serviceRegistryStub{}, StepUps: serviceStepUpStub{},
		Signer: &serviceSignerStub{}, Client: &serviceClientStub{}, UnitOfWork: serviceUOWStub{&serviceOutboxStub{}},
		Fingerprinter: &serviceFingerprinterStub{},
	}
	if _, err := NewService(dependencies, ServiceConfig{RequireDurableMutations: true}); !errors.Is(err, ErrInvalidRequest) {
		t.Fatalf("missing authority reason dependencies error=%v", err)
	}
	dependencies.ReasonUnitOfWork = reviewReasonUOWStub{&reviewReasonRepositoryStub{}}
	if _, err := NewService(dependencies, ServiceConfig{RequireDurableMutations: true}); !errors.Is(err, ErrInvalidRequest) {
		t.Fatalf("missing authority reason cipher error=%v", err)
	}
	dependencies.ReasonCipher = &reviewReasonCipherStub{}
	if _, err := NewService(dependencies, ServiceConfig{RequireDurableMutations: true}); err != nil {
		t.Fatalf("complete durable dependencies rejected: %v", err)
	}
}

func TestPersistReviewIdentityReasonFailsClosedForAuthorityReplayMismatch(t *testing.T) {
	now := time.Date(2026, 9, 4, 8, 30, 0, 0, time.UTC)
	repository := &reviewReasonRepositoryStub{record: &adminstore.ProtectedReason{
		ID: ReviewIdentityProtectedReasonID("req_review_identity_3"), OwnerUserID: "user_other", OperationKind: "direct_read",
		KeyID: "reason-v1", Nonce: []byte("nonce"), Ciphertext: []byte("sealed:" + ReviewIdentityProtectedReason), CreatedAt: now,
	}}
	service := &Service{reasonUOW: reviewReasonUOWStub{repository}, reasonCipher: &reviewReasonCipherStub{}, now: func() time.Time { return now }}
	if err := service.persistReviewIdentityReason(context.Background(), Actor{UserID: "user_reviewer"}, reviewIdentityReasonProxyRequest("req_review_identity_3")); !errors.Is(err, ErrUpstream) || repository.markCalls != 0 {
		t.Fatalf("error=%v markCalls=%d", err, repository.markCalls)
	}
}
