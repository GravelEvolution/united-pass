package registration

import (
	"context"
	"errors"
	"testing"
	"time"
)

type providerStub struct {
	created   ProviderUser
	deleted   string
	verified  VerifyEmailInput
	resent    ResendEmailInput
	createErr error
	verifyErr error
}

func (p *providerStub) CreateUser(_ context.Context, input ProviderUser) error {
	p.created = input
	return p.createErr
}
func (p *providerStub) DeleteUser(_ context.Context, userID string) error {
	p.deleted = userID
	return nil
}
func (p *providerStub) VerifyEmail(_ context.Context, input VerifyEmailInput) error {
	p.verified = input
	return p.verifyErr
}
func (p *providerStub) ResendEmail(_ context.Context, input ResendEmailInput) error {
	p.resent = input
	return nil
}

type repositoryStub struct {
	created        PendingUser
	deleted        string
	activated      string
	createErr      error
	deleteErr      error
	activateErr    error
	pendingErr     error
	pendingMissing bool
}

func (r *repositoryStub) CreatePending(_ context.Context, user PendingUser) error {
	r.created = user
	return r.createErr
}
func (r *repositoryStub) DeletePending(_ context.Context, userID string) error {
	r.deleted = userID
	return r.deleteErr
}
func (r *repositoryStub) IsPending(_ context.Context, _ string) (bool, error) {
	return !r.pendingMissing, r.pendingErr
}
func (r *repositoryStub) ActivateVerified(_ context.Context, userID string) error {
	r.activated = userID
	return r.activateErr
}

type tokenStoreStub struct {
	record    TokenRecord
	rawToken  string
	deleted   string
	createErr error
	getErr    error
}

func (s *tokenStoreStub) Create(_ context.Context, rawToken string, record TokenRecord, _ time.Duration) error {
	s.rawToken, s.record = rawToken, record
	return s.createErr
}
func (s *tokenStoreStub) Get(_ context.Context, rawToken string) (TokenRecord, error) {
	s.rawToken = rawToken
	return s.record, s.getErr
}
func (s *tokenStoreStub) Delete(_ context.Context, rawToken string) error {
	s.deleted = rawToken
	return nil
}

func newTestService(provider *providerStub, repo *repositoryStub, tokens *tokenStoreStub) *Service {
	return NewService(provider, repo, tokens, Config{
		PublicOrigin: "https://auth.moonstone.org.cn",
		TokenTTL:     30 * time.Minute,
		Now:          func() time.Time { return time.Date(2026, 8, 18, 12, 0, 0, 0, time.UTC) },
		GenerateUserID: func() (string, error) {
			return "user_0123456789abcdef0123456789abcdef", nil
		},
		GenerateToken: func() (string, error) { return "opaque-registration-token", nil },
	})
}

func TestCreatePrecreatesMatchingPendingIdentityAndSendsFragmentVerification(t *testing.T) {
	provider := &providerStub{}
	repo := &repositoryStub{}
	tokens := &tokenStoreStub{}
	service := newTestService(provider, repo, tokens)

	result, err := service.Create(t.Context(), CreateInput{
		Username: "moonstone.user", DisplayName: "月石选手", Email: "player@example.com",
		Password: "Correct-Horse-Battery-Staple9!", AcceptedTerms: true, RequestID: "auth_request-123",
	})
	if err != nil {
		t.Fatalf("Create: %v", err)
	}
	if provider.created.UserID != "user_0123456789abcdef0123456789abcdef" || repo.created.UserID != provider.created.UserID {
		t.Fatalf("provider/local IDs drifted: provider=%q local=%q", provider.created.UserID, repo.created.UserID)
	}
	if repo.created.EmailVerified || repo.created.Status != StatusPending {
		t.Fatalf("pending row = %#v", repo.created)
	}
	wantTemplate := "https://auth.moonstone.org.cn/verify-email#userId={{.UserID}}&code={{.Code}}&requestId=auth_request-123"
	if provider.created.VerificationURLTemplate != wantTemplate {
		t.Fatalf("verification template = %q, want %q", provider.created.VerificationURLTemplate, wantTemplate)
	}
	if result.RegistrationToken != "opaque-registration-token" || tokens.record.UserID != provider.created.UserID {
		t.Fatalf("result/token record mismatch: %#v %#v", result, tokens.record)
	}
	if provider.created.Password != "Correct-Horse-Battery-Staple9!" {
		t.Fatal("password was not delivered to provider")
	}
}

func TestCreateDoesNotContactProviderWhenLocalPendingWriteFails(t *testing.T) {
	provider := &providerStub{}
	repo := &repositoryStub{createErr: errors.New("postgres unavailable")}
	tokens := &tokenStoreStub{}
	service := newTestService(provider, repo, tokens)

	_, err := service.Create(t.Context(), CreateInput{
		Username: "moonstone", DisplayName: "Moonstone", Email: "player@example.com",
		Password: "Correct-Horse-Battery-Staple9!", AcceptedTerms: true,
	})
	if !errors.Is(err, ErrUnavailable) {
		t.Fatalf("Create error = %v, want ErrUnavailable", err)
	}
	if provider.created.UserID != "" || provider.deleted != "" {
		t.Fatalf("provider was contacted before local reservation: created=%q deleted=%q", provider.created.UserID, provider.deleted)
	}
	if tokens.deleted != "opaque-registration-token" {
		t.Fatalf("token cleanup = %q", tokens.deleted)
	}
}

func TestCreateKnownEmailConflictStopsBeforeProviderOrMail(t *testing.T) {
	provider := &providerStub{}
	repo := &repositoryStub{createErr: ErrConflict}
	tokens := &tokenStoreStub{}
	service := newTestService(provider, repo, tokens)

	_, err := service.Create(t.Context(), CreateInput{
		Username: "moonstone", DisplayName: "Moonstone", Email: "existing@example.com",
		Password: "Correct-Horse-Battery-Staple9!", AcceptedTerms: true,
	})
	if !errors.Is(err, ErrConflict) {
		t.Fatalf("Create error = %v, want ErrConflict", err)
	}
	if provider.created.UserID != "" || provider.deleted != "" {
		t.Fatalf("provider was contacted for known email: created=%q deleted=%q", provider.created.UserID, provider.deleted)
	}
	if tokens.deleted != "opaque-registration-token" {
		t.Fatalf("registration token cleanup = %q", tokens.deleted)
	}
}

func TestCreateCompensatesLocalReservationWhenProviderFails(t *testing.T) {
	provider := &providerStub{createErr: ErrUnavailable}
	repo := &repositoryStub{}
	tokens := &tokenStoreStub{}
	service := newTestService(provider, repo, tokens)

	_, err := service.Create(t.Context(), CreateInput{
		Username: "moonstone", DisplayName: "Moonstone", Email: "player@example.com",
		Password: "Correct-Horse-Battery-Staple9!", AcceptedTerms: true,
	})
	if !errors.Is(err, ErrUnavailable) {
		t.Fatalf("Create error = %v, want ErrUnavailable", err)
	}
	if repo.deleted != repo.created.UserID {
		t.Fatalf("local compensation deleted %q, want %q", repo.deleted, repo.created.UserID)
	}
	if provider.deleted != provider.created.UserID {
		t.Fatalf("provider compensation deleted %q, want %q", provider.deleted, provider.created.UserID)
	}
	if tokens.deleted != "opaque-registration-token" {
		t.Fatalf("token cleanup = %q", tokens.deleted)
	}
}

func TestVerifyActivatesOnlyAfterProviderVerification(t *testing.T) {
	provider := &providerStub{}
	repo := &repositoryStub{}
	service := newTestService(provider, repo, &tokenStoreStub{})
	input := VerifyInput{UserID: "user_0123456789abcdef0123456789abcdef", Code: "provider-code", RequestID: "request-1"}

	result, err := service.Verify(t.Context(), input)
	if err != nil {
		t.Fatalf("Verify: %v", err)
	}
	if provider.verified.UserID != input.UserID || provider.verified.Code != input.Code {
		t.Fatalf("provider input = %#v", provider.verified)
	}
	if repo.activated != input.UserID || result.RequestID != input.RequestID {
		t.Fatalf("activation/result mismatch: activated=%q result=%#v", repo.activated, result)
	}

	provider.verifyErr = ErrVerificationFailed
	repo.activated = ""
	if _, err := service.Verify(t.Context(), input); !errors.Is(err, ErrVerificationFailed) {
		t.Fatalf("Verify error = %v", err)
	}
	if repo.activated != "" {
		t.Fatal("local account activated after provider rejected the code")
	}
}

func TestVerifyDoesNotContactProviderForUnknownLocalPendingUser(t *testing.T) {
	provider := &providerStub{}
	repo := &repositoryStub{pendingMissing: true}
	service := newTestService(provider, repo, &tokenStoreStub{})
	input := VerifyInput{UserID: "user_0123456789abcdef0123456789abcdef", Code: "provider-code"}
	if _, err := service.Verify(t.Context(), input); !errors.Is(err, ErrVerificationFailed) {
		t.Fatalf("Verify error=%v, want generic verification failure", err)
	}
	if provider.verified != (VerifyEmailInput{}) || repo.activated != "" {
		t.Fatalf("unknown pending user reached provider or activation: provider=%#v activated=%q", provider.verified, repo.activated)
	}
}

func TestResendResolvesUserAndRequestOnlyFromOpaqueToken(t *testing.T) {
	provider := &providerStub{}
	tokens := &tokenStoreStub{record: TokenRecord{UserID: "user_0123456789abcdef0123456789abcdef", RequestID: "request-2"}}
	service := newTestService(provider, &repositoryStub{}, tokens)

	if err := service.Resend(t.Context(), "opaque-token"); err != nil {
		t.Fatalf("Resend: %v", err)
	}
	if provider.resent.UserID != tokens.record.UserID || provider.resent.VerificationURLTemplate == "" {
		t.Fatalf("provider resend = %#v", provider.resent)
	}
	if tokens.rawToken != "opaque-token" {
		t.Fatalf("looked up token %q", tokens.rawToken)
	}
}

func TestValidateCreateRejectsWeakOrAmbiguousInputs(t *testing.T) {
	base := CreateInput{Username: "moonstone", DisplayName: "Moonstone", Email: "player@example.com", Password: "Correct-Horse-Battery-Staple9!", AcceptedTerms: true}
	cases := []struct {
		name string
		edit func(*CreateInput)
	}{
		{name: "username whitespace", edit: func(v *CreateInput) { v.Username = " moonstone" }},
		{name: "username unicode", edit: func(v *CreateInput) { v.Username = "月石" }},
		{name: "display name empty", edit: func(v *CreateInput) { v.DisplayName = "" }},
		{name: "email display address", edit: func(v *CreateInput) { v.Email = "Player <player@example.com>" }},
		{name: "password short", edit: func(v *CreateInput) { v.Password = "short" }},
		{name: "password missing uppercase", edit: func(v *CreateInput) { v.Password = "lowercase-password9!" }},
		{name: "password missing lowercase", edit: func(v *CreateInput) { v.Password = "UPPERCASE-PASSWORD9!" }},
		{name: "password missing number", edit: func(v *CreateInput) { v.Password = "No-Number-Password!" }},
		{name: "password missing symbol", edit: func(v *CreateInput) { v.Password = "NoSymbolPassword9" }},
		{name: "terms missing", edit: func(v *CreateInput) { v.AcceptedTerms = false }},
		{name: "request too long", edit: func(v *CreateInput) { v.RequestID = string(make([]byte, 201)) }},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			input := base
			tc.edit(&input)
			if err := ValidateCreate(input); !errors.Is(err, ErrInvalidInput) {
				t.Fatalf("ValidateCreate error = %v", err)
			}
		})
	}
}
