package wechatregistration

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/GravelEvolution/united-pass/backend/internal/registration"
	"github.com/GravelEvolution/united-pass/backend/internal/wechat"
)

type verifierStub struct {
	proof wechat.IdentityProof
	err   error
}

func (v verifierStub) VerifyLogin(context.Context, string) (wechat.IdentityProof, error) {
	return wechat.IdentityProof{}, errors.New("unused")
}

func (v verifierStub) VerifyRegistration(context.Context, string, string) (wechat.IdentityProof, error) {
	return v.proof, v.err
}

type providerStub struct {
	created registration.ProviderUser
	deleted string
	err     error
	errors  []error
	calls   int
}

func (p *providerStub) CreateUser(_ context.Context, in registration.ProviderUser) error {
	p.created = in
	p.calls++
	if len(p.errors) > 0 {
		err := p.errors[0]
		p.errors = p.errors[1:]
		return err
	}
	return p.err
}
func (p *providerStub) DeleteUser(_ context.Context, id string) error                    { p.deleted = id; return nil }
func (p *providerStub) VerifyEmail(context.Context, registration.VerifyEmailInput) error { return nil }
func (p *providerStub) ResendEmail(context.Context, registration.ResendEmailInput) error { return nil }

type repoStub struct {
	created    PendingUser
	reservedID string
	intent     ProviderIntent
	err        error
	calls      int
}

func (r *repoStub) ReservePendingWithWeChat(_ context.Context, in PendingUser) (string, error) {
	r.created = in
	r.calls++
	if r.err != nil {
		return "", r.err
	}
	if r.calls == 1 {
		r.intent = in.ProviderIntent
	} else if r.intent != in.ProviderIntent {
		return "", registration.ErrConflict
	}
	if r.reservedID == "" {
		r.reservedID = in.User.UserID
	}
	return r.reservedID, nil
}

type tokenStub struct {
	created string
	record  registration.TokenRecord
	deleted string
	err     error
}

func (s *tokenStub) Create(_ context.Context, token string, record registration.TokenRecord, _ time.Duration) error {
	s.created, s.record = token, record
	return s.err
}
func (s *tokenStub) Get(context.Context, string) (registration.TokenRecord, error) {
	return registration.TokenRecord{}, registration.ErrTokenNotFound
}
func (s *tokenStub) Delete(_ context.Context, token string) error { s.deleted = token; return nil }

func TestCreateRequiresServerVerifiedWeChatIdentityAndPhone(t *testing.T) {
	provider, repo, tokens := &providerStub{}, &repoStub{}, &tokenStub{}
	service := NewService(verifierStub{proof: wechat.IdentityProof{TenantID: "wx-app", Subject: "union:subject", Phone: "+8613812345678"}}, provider, repo, tokens, Config{
		PublicOrigin: "https://auth.example.test", TokenTTL: time.Minute,
		Now:            func() time.Time { return time.Date(2026, 8, 24, 0, 0, 0, 0, time.UTC) },
		GenerateUserID: func() (string, error) { return "user_0123456789abcdef0123456789abcdef", nil },
		GenerateToken:  func() (string, error) { return "opaque-registration-token", nil },
	})
	result, err := service.Create(t.Context(), CreateInput{
		Registration: registration.CreateInput{Username: "moonstone", DisplayName: "Moonstone", Email: "player@example.com", Password: "Correct-Horse-Battery-Staple9!", AcceptedTerms: true},
		LoginCode:    "login-code", PhoneCode: "phone-code",
	})
	if err != nil {
		t.Fatalf("Create: %v", err)
	}
	if result.RegistrationToken != "opaque-registration-token" || tokens.record.UserID != repo.created.User.UserID {
		t.Fatalf("token/user mismatch: %#v %#v", result, tokens.record)
	}
	if repo.created.TenantID != "wx-app" || repo.created.Subject != "union:subject" || repo.created.Phone != "+8613812345678" || repo.created.User.Status != registration.StatusPending || repo.created.User.EmailVerified {
		t.Fatalf("pending proof not retained: %#v", repo.created)
	}
	if provider.created.UserID != repo.created.User.UserID || provider.created.Password == "" {
		t.Fatalf("provider input=%#v", provider.created)
	}
}

func TestLegacyCreateStillRejectsMissingPhoneProof(t *testing.T) {
	provider, repo, tokens := &providerStub{}, &repoStub{}, &tokenStub{}
	service := NewService(verifierStub{proof: wechat.IdentityProof{TenantID: "wx-app", Subject: "openid-subject"}}, provider, repo, tokens, Config{TokenTTL: time.Minute})
	_, err := service.Create(t.Context(), CreateInput{
		Registration: registration.CreateInput{Username: "moonstone", DisplayName: "Moonstone", Email: "player@example.com", Password: "Correct-Horse-Battery-Staple9!", AcceptedTerms: true},
		LoginCode:    "login-code", PhoneCode: "phone-code",
	})
	if !errors.Is(err, registration.ErrInvalidInput) || repo.calls != 0 || provider.calls != 0 || tokens.created != "" {
		t.Fatalf("err=%v repo=%#v provider=%#v tokens=%#v", err, repo, provider, tokens)
	}
}

func TestVerifyRegistrationValidatesAndNormalizesProviderFailuresWithoutCreating(t *testing.T) {
	validProof := wechat.IdentityProof{TenantID: "wx-app", Subject: "openid-subject", Phone: "+8613812345678"}
	for _, test := range []struct {
		name      string
		loginCode string
		phoneCode string
		verifier  verifierStub
		wantErr   error
	}{
		{name: "success", loginCode: "login-code", phoneCode: "phone-code", verifier: verifierStub{proof: validProof}},
		{name: "malformed code", loginCode: " login-code", phoneCode: "phone-code", verifier: verifierStub{proof: validProof}, wantErr: registration.ErrInvalidInput},
		{name: "provider rejection", loginCode: "login-code", phoneCode: "phone-code", verifier: verifierStub{err: wechat.ErrRejected}, wantErr: registration.ErrInvalidInput},
		{name: "provider outage", loginCode: "login-code", phoneCode: "phone-code", verifier: verifierStub{err: errors.New("provider unavailable")}, wantErr: registration.ErrUnavailable},
		{name: "missing phone", loginCode: "login-code", phoneCode: "phone-code", verifier: verifierStub{proof: wechat.IdentityProof{TenantID: "wx-app", Subject: "openid-subject"}}, wantErr: registration.ErrInvalidInput},
		{name: "untrimmed subject", loginCode: "login-code", phoneCode: "phone-code", verifier: verifierStub{proof: wechat.IdentityProof{TenantID: "wx-app", Subject: " openid-subject", Phone: "+8613812345678"}}, wantErr: registration.ErrInvalidInput},
	} {
		t.Run(test.name, func(t *testing.T) {
			provider, repo, tokens := &providerStub{}, &repoStub{}, &tokenStub{}
			service := NewService(test.verifier, provider, repo, tokens, Config{TokenTTL: time.Minute})
			proof, err := service.VerifyRegistration(t.Context(), test.loginCode, test.phoneCode)
			if test.wantErr == nil {
				if err != nil || proof != validProof {
					t.Fatalf("proof=%#v err=%v", proof, err)
				}
			} else if !errors.Is(err, test.wantErr) || proof != (wechat.IdentityProof{}) {
				t.Fatalf("proof=%#v err=%v want=%v", proof, err, test.wantErr)
			}
			if repo.calls != 0 || provider.calls != 0 || tokens.created != "" {
				t.Fatalf("proof verification created state: repo=%d provider=%d token=%q", repo.calls, provider.calls, tokens.created)
			}
		})
	}
}

func TestCreateVerifiedRejectsIdentityOnlyProofWithoutCreatingAccount(t *testing.T) {
	provider, repo, tokens := &providerStub{}, &repoStub{}, &tokenStub{}
	service := NewService(nil, provider, repo, tokens, Config{
		PublicOrigin: "https://auth.example.test", TokenTTL: time.Minute,
		Now:            func() time.Time { return time.Date(2026, 8, 28, 0, 0, 0, 0, time.UTC) },
		GenerateUserID: func() (string, error) { return "user_0123456789abcdef0123456789abcdef", nil },
		GenerateToken:  func() (string, error) { return "opaque-registration-token", nil },
	})
	result, err := service.CreateVerified(t.Context(), CreateVerifiedInput{
		Registration: registration.CreateInput{Username: "moonstone", DisplayName: "Moonstone", Email: "player@example.com", Password: "Correct-Horse-Battery-Staple9!", AcceptedTerms: true},
		Proof:        wechat.IdentityProof{TenantID: "wx-app", Subject: "openid-subject"},
	})
	if !errors.Is(err, registration.ErrInvalidInput) || result.RegistrationToken != "" || repo.calls != 0 || provider.calls != 0 || tokens.created != "" {
		t.Fatalf("result=%#v err=%v repo=%#v provider=%#v tokens=%#v", result, err, repo, provider, tokens)
	}
}

func TestCreateVerifiedRejectsMissingStableWeChatIdentity(t *testing.T) {
	provider, repo, tokens := &providerStub{}, &repoStub{}, &tokenStub{}
	service := NewService(nil, provider, repo, tokens, Config{TokenTTL: time.Minute})
	_, err := service.CreateVerified(t.Context(), CreateVerifiedInput{
		Registration: registration.CreateInput{Username: "moonstone", DisplayName: "Moonstone", Email: "player@example.com", Password: "Correct-Horse-Battery-Staple9!", AcceptedTerms: true},
		Proof:        wechat.IdentityProof{TenantID: "wx-app"},
	})
	if !errors.Is(err, registration.ErrInvalidInput) || repo.calls != 0 || provider.calls != 0 || tokens.created != "" {
		t.Fatalf("err=%v repo=%#v provider=%#v tokens=%#v", err, repo, provider, tokens)
	}
}

func TestCreateVerifiedPendingRecoveryRequiresExactExpectedUserID(t *testing.T) {
	expectedID := "user_aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
	input := CreateVerifiedInput{
		Registration:   registration.CreateInput{Username: "moonstone", DisplayName: "Moonstone", Email: "player@example.com", Password: "Correct-Horse-Battery-Staple9!", AcceptedTerms: true},
		Proof:          wechat.IdentityProof{TenantID: "wx-app", Subject: "openid-subject", Phone: "+8613812345678"},
		ExpectedUserID: expectedID,
	}
	newService := func(repo *repoStub, provider *providerStub, tokens *tokenStub) *Service {
		return NewService(nil, provider, repo, tokens, Config{
			PublicOrigin: "https://auth.example.test", TokenTTL: time.Minute,
			GenerateUserID: func() (string, error) { return "user_bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb", nil },
			GenerateToken:  func() (string, error) { return "opaque-registration-token", nil },
		})
	}

	t.Run("matching durable reservation", func(t *testing.T) {
		provider, repo, tokens := &providerStub{}, &repoStub{reservedID: expectedID}, &tokenStub{}
		result, err := newService(repo, provider, tokens).CreateVerified(t.Context(), input)
		if err != nil || result.RegistrationToken == "" || provider.created.UserID != expectedID || tokens.record.UserID != expectedID || repo.created.ExpectedUserID != expectedID || repo.created.User.UserID != expectedID {
			t.Fatalf("result=%#v err=%v repo=%#v provider=%#v tokens=%#v", result, err, repo, provider, tokens)
		}
	})

	t.Run("mismatched durable reservation", func(t *testing.T) {
		provider, repo, tokens := &providerStub{}, &repoStub{reservedID: "user_cccccccccccccccccccccccccccccccc"}, &tokenStub{}
		_, err := newService(repo, provider, tokens).CreateVerified(t.Context(), input)
		if !errors.Is(err, registration.ErrConflict) || provider.calls != 0 || tokens.created != "" || repo.created.ExpectedUserID != expectedID {
			t.Fatalf("err=%v repo=%#v provider=%#v tokens=%#v", err, repo, provider, tokens)
		}
	})
}

func TestCreateDoesNotReserveAccountWhenWeChatProofFails(t *testing.T) {
	provider, repo, tokens := &providerStub{}, &repoStub{}, &tokenStub{}
	service := NewService(verifierStub{err: wechat.ErrRejected}, provider, repo, tokens, Config{TokenTTL: time.Minute})
	_, err := service.Create(t.Context(), CreateInput{Registration: registration.CreateInput{Username: "moonstone", DisplayName: "Moonstone", Email: "player@example.com", Password: "Correct-Horse-Battery-Staple9!", AcceptedTerms: true}, LoginCode: "login-code", PhoneCode: "phone-code"})
	if !errors.Is(err, registration.ErrInvalidInput) || repo.created.User.UserID != "" || provider.created.UserID != "" || tokens.created != "" {
		t.Fatalf("err=%v repo=%#v provider=%#v token=%#v", err, repo.created, provider.created, tokens)
	}
}

func TestCreateKeepsRetryablePendingReservationWhenProviderFails(t *testing.T) {
	provider, repo, tokens := &providerStub{err: registration.ErrUnavailable}, &repoStub{}, &tokenStub{}
	service := NewService(verifierStub{proof: wechat.IdentityProof{TenantID: "wx-app", Subject: "union:subject", Phone: "+8613812345678"}}, provider, repo, tokens, Config{
		PublicOrigin: "https://auth.example.test", TokenTTL: time.Minute,
		GenerateUserID: func() (string, error) { return "user_0123456789abcdef0123456789abcdef", nil },
		GenerateToken:  func() (string, error) { return "opaque-registration-token", nil },
	})
	_, err := service.Create(t.Context(), CreateInput{Registration: registration.CreateInput{Username: "moonstone", DisplayName: "Moonstone", Email: "player@example.com", Password: "Correct-Horse-Battery-Staple9!", AcceptedTerms: true}, LoginCode: "login-code", PhoneCode: "phone-code"})
	if !errors.Is(err, registration.ErrUnavailable) || repo.calls != 1 || provider.deleted != "" || tokens.created != "" {
		t.Fatalf("err=%v repo=%#v provider=%#v tokens=%#v", err, repo, provider, tokens)
	}
}

func TestCreateRetriesSameDurableUserAfterAmbiguousProviderFailure(t *testing.T) {
	durableID := "user_aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
	provider := &providerStub{errors: []error{registration.ErrUnavailable, nil}}
	repo := &repoStub{reservedID: durableID}
	tokens := &tokenStub{}
	service := NewService(verifierStub{proof: wechat.IdentityProof{TenantID: "wx-app", Subject: "union:subject", Phone: "+8613812345678"}}, provider, repo, tokens, Config{
		PublicOrigin: "https://auth.example.test", TokenTTL: time.Minute,
		GenerateUserID: func() (string, error) { return "user_0123456789abcdef0123456789abcdef", nil },
		GenerateToken:  func() (string, error) { return "opaque-registration-token", nil },
	})
	input := CreateInput{Registration: registration.CreateInput{Username: "moonstone", DisplayName: "Moonstone", Email: "player@example.com", Password: "Correct-Horse-Battery-Staple9!", AcceptedTerms: true}, LoginCode: "login-code", PhoneCode: "phone-code"}
	if _, err := service.Create(t.Context(), input); !errors.Is(err, registration.ErrUnavailable) {
		t.Fatalf("first Create error=%v", err)
	}
	result, err := service.Create(t.Context(), input)
	if err != nil {
		t.Fatalf("retry Create: %v", err)
	}
	if repo.calls != 2 || provider.calls != 2 || provider.created.UserID != durableID || tokens.record.UserID != durableID || result.RegistrationToken == "" {
		t.Fatalf("retry did not reuse reservation: repo=%#v provider=%#v tokens=%#v result=%#v", repo, provider, tokens, result)
	}
}

func TestCreateRejectsProviderIntentDriftAfterAmbiguousFailure(t *testing.T) {
	provider := &providerStub{errors: []error{registration.ErrUnavailable, nil}}
	repo := &repoStub{reservedID: "user_aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"}
	service := NewService(verifierStub{proof: wechat.IdentityProof{TenantID: "wx-app", Subject: "union:subject", Phone: "+8613812345678"}}, provider, repo, &tokenStub{}, Config{
		PublicOrigin: "https://auth.example.test", TokenTTL: time.Minute,
		GenerateUserID: func() (string, error) { return "user_0123456789abcdef0123456789abcdef", nil },
		GenerateToken:  func() (string, error) { return "opaque-registration-token", nil },
	})
	input := CreateInput{Registration: registration.CreateInput{Username: "moonstone", DisplayName: "Moonstone", Email: "player@example.com", Password: "Correct-Horse-Battery-Staple9!", AcceptedTerms: true}, LoginCode: "login-code", PhoneCode: "phone-code"}
	if _, err := service.Create(t.Context(), input); !errors.Is(err, registration.ErrUnavailable) {
		t.Fatalf("first Create error=%v", err)
	}
	input.Registration.Password = "Different-Strong-Password-Number2!"
	if _, err := service.Create(t.Context(), input); !errors.Is(err, registration.ErrConflict) {
		t.Fatalf("drifted retry error=%v, want conflict", err)
	}
	if provider.calls != 1 {
		t.Fatalf("provider calls=%d, drifted retry must stop at durable reservation", provider.calls)
	}
}

func TestCreateTokenStoreFailureLeavesProviderReservationRetryable(t *testing.T) {
	provider, repo := &providerStub{}, &repoStub{}
	tokens := &tokenStub{err: errors.New("redis unavailable")}
	service := NewService(verifierStub{proof: wechat.IdentityProof{TenantID: "wx-app", Subject: "union:subject", Phone: "+8613812345678"}}, provider, repo, tokens, Config{
		PublicOrigin: "https://auth.example.test", TokenTTL: time.Minute,
		GenerateUserID: func() (string, error) { return "user_0123456789abcdef0123456789abcdef", nil },
		GenerateToken:  func() (string, error) { return "opaque-registration-token", nil },
	})
	_, err := service.Create(t.Context(), CreateInput{Registration: registration.CreateInput{Username: "moonstone", DisplayName: "Moonstone", Email: "player@example.com", Password: "Correct-Horse-Battery-Staple9!", AcceptedTerms: true}, LoginCode: "login-code", PhoneCode: "phone-code"})
	if !errors.Is(err, registration.ErrUnavailable) || provider.calls != 1 || repo.calls != 1 || provider.deleted != "" {
		t.Fatalf("err=%v repo=%#v provider=%#v", err, repo, provider)
	}
}
