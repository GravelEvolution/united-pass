package accountcontact

import (
	"context"
	"errors"
	"testing"

	"github.com/GravelEvolution/united-pass/backend/internal/identity"
)

type providerStub struct {
	begin       BeginProviderInput
	beginCalls  int
	beginErr    error
	email       string
	verify      VerifyInput
	verifyCalls int
	verifyErr   error
}

func (p *providerStub) BeginEmailChange(_ context.Context, input BeginProviderInput) error {
	p.begin = input
	p.beginCalls++
	return p.beginErr
}

func (p *providerStub) VerifyEmailChange(_ context.Context, userID identity.UserID, code string) (string, error) {
	p.verify.UserID, p.verify.Code = userID, code
	p.verifyCalls++
	return p.email, p.verifyErr
}

type repositoryStub struct {
	userID      identity.UserID
	email       string
	updateCalls int
	updateErr   error
}

func (r *repositoryStub) UpdateVerifiedEmail(_ context.Context, userID identity.UserID, email string) error {
	r.userID, r.email = userID, email
	r.updateCalls++
	return r.updateErr
}

type emailValidatorStub struct {
	emails []string
	err    error
}

func (v *emailValidatorStub) Validate(_ context.Context, email string) error {
	v.emails = append(v.emails, email)
	return v.err
}

func TestBeginAndVerifyEmailChange(t *testing.T) {
	provider := &providerStub{email: "new@example.com"}
	repo := &repositoryStub{}
	validator := &emailValidatorStub{}
	service := NewService(provider, repo, Config{
		PublicOrigin:   "https://auth.moonstone.org.cn",
		EmailValidator: validator,
		GenerateRequestID: func() (string, error) {
			return "email_change_0123456789abcdef0123456789abcdef", nil
		},
	})

	begin, err := service.Begin(t.Context(), BeginInput{UserID: "user_1", Email: "New@Example.com"})
	if err != nil {
		t.Fatal(err)
	}
	if begin.RequestID == "" || provider.begin.Email != "new@example.com" || provider.begin.UserID != "user_1" {
		t.Fatalf("begin=%+v provider=%+v", begin, provider.begin)
	}
	if provider.begin.VerificationURLTemplate != "https://auth.moonstone.org.cn/account#emailChangeRequestId=email_change_0123456789abcdef0123456789abcdef&code={{.Code}}" {
		t.Fatalf("url template=%q", provider.begin.VerificationURLTemplate)
	}

	result, err := service.Verify(t.Context(), VerifyInput{UserID: "user_1", RequestID: begin.RequestID, Code: "A1B2C3"})
	if err != nil {
		t.Fatal(err)
	}
	if result.Email != "new@example.com" || repo.userID != "user_1" || repo.email != "new@example.com" {
		t.Fatalf("result=%+v repo=%+v", result, repo)
	}
	if len(validator.emails) != 1 || validator.emails[0] != "new@example.com" {
		t.Fatalf("delivery validation emails = %#v, want one normalized Begin email", validator.emails)
	}
	if provider.verify.Code != "A1B2C3" {
		t.Fatalf("provider verification code = %q, want exact case-sensitive code", provider.verify.Code)
	}
}

func TestVerifyRejectsUnboundRequestShape(t *testing.T) {
	service := NewService(&providerStub{}, &repositoryStub{}, Config{PublicOrigin: "https://auth.moonstone.org.cn"})
	if _, err := service.Verify(t.Context(), VerifyInput{UserID: "user_1", RequestID: "other", Code: "123456"}); err != ErrVerificationFailed {
		t.Fatalf("err=%v", err)
	}
}

func TestVerifyEmailChangeCodeFormatAndCase(t *testing.T) {
	t.Parallel()

	const requestID = "email_change_0123456789abcdef0123456789abcdef"
	for _, code := range []string{"A1B2C3", "123456", "ABCDEF"} {
		code := code
		t.Run("accept_"+code, func(t *testing.T) {
			t.Parallel()
			provider := &providerStub{email: "new@example.com"}
			service := NewService(provider, &repositoryStub{}, Config{})

			if _, err := service.Verify(t.Context(), VerifyInput{UserID: "user_1", RequestID: requestID, Code: code}); err != nil {
				t.Fatalf("Verify(%q): %v", code, err)
			}
			if provider.verify.Code != code {
				t.Fatalf("provider code = %q, want %q", provider.verify.Code, code)
			}
		})
	}

	for _, code := range []string{"a1B2C3", "A1B2C", "A1B2C34", "A1B2C!", " A1B2C", "A1B2C "} {
		code := code
		t.Run("reject_"+code, func(t *testing.T) {
			t.Parallel()
			provider := &providerStub{email: "new@example.com"}
			repo := &repositoryStub{}
			service := NewService(provider, repo, Config{})

			_, err := service.Verify(t.Context(), VerifyInput{UserID: "user_1", RequestID: requestID, Code: code})
			if !errors.Is(err, ErrVerificationFailed) {
				t.Fatalf("Verify(%q) error = %v, want ErrVerificationFailed", code, err)
			}
			if provider.verifyCalls != 0 || repo.updateCalls != 0 {
				t.Fatalf("invalid code caused side effects: provider=%d repo=%d", provider.verifyCalls, repo.updateCalls)
			}
		})
	}
}

func TestBeginEmailChangeRejectsDisposableDeliveryBeforeProviderSideEffects(t *testing.T) {
	t.Parallel()

	for _, email := range []string{
		"person@emalupe.com",
		"person@future-mail-tm-domain.example",
	} {
		email := email
		t.Run(email, func(t *testing.T) {
			t.Parallel()
			provider := &providerStub{}
			validator := &emailValidatorStub{err: ErrInvalidInput}
			service := NewService(provider, &repositoryStub{}, Config{
				PublicOrigin:   "https://auth.moonstone.org.cn",
				EmailValidator: validator,
			})

			_, err := service.Begin(t.Context(), BeginInput{UserID: "user_1", Email: email})
			if !errors.Is(err, ErrInvalidInput) {
				t.Fatalf("Begin error = %v, want ErrInvalidInput", err)
			}
			if provider.beginCalls != 0 {
				t.Fatalf("provider Begin calls = %d, want 0", provider.beginCalls)
			}
			if len(validator.emails) != 1 || validator.emails[0] != email {
				t.Fatalf("delivery validation emails = %#v, want [%q]", validator.emails, email)
			}
		})
	}
}

func TestBeginEmailChangeFailsClosedOnDeliveryPolicyUnavailable(t *testing.T) {
	t.Parallel()

	provider := &providerStub{}
	service := NewService(provider, &repositoryStub{}, Config{
		PublicOrigin:   "https://auth.moonstone.org.cn",
		EmailValidator: &emailValidatorStub{err: ErrUnavailable},
	})

	_, err := service.Begin(t.Context(), BeginInput{UserID: "user_1", Email: "person@example.com"})
	if !errors.Is(err, ErrUnavailable) {
		t.Fatalf("Begin error = %v, want ErrUnavailable", err)
	}
	if provider.beginCalls != 0 {
		t.Fatalf("provider Begin calls = %d, want 0", provider.beginCalls)
	}
}

func TestVerifyDoesNotRequeryDeliveryPolicyAfterProviderVerifiedEmail(t *testing.T) {
	t.Parallel()

	provider := &providerStub{email: "new@example.com"}
	repo := &repositoryStub{}
	validator := &emailValidatorStub{}
	service := NewService(provider, repo, Config{
		PublicOrigin:   "https://auth.moonstone.org.cn",
		EmailValidator: validator,
		GenerateRequestID: func() (string, error) {
			return "email_change_0123456789abcdef0123456789abcdef", nil
		},
	})

	begin, err := service.Begin(t.Context(), BeginInput{UserID: "user_1", Email: "new@example.com"})
	if err != nil {
		t.Fatal(err)
	}
	// A resolver outage after the provider accepted the pending address must
	// not split the provider's verified address from the local mirror.
	validator.err = ErrUnavailable
	result, err := service.Verify(t.Context(), VerifyInput{UserID: "user_1", RequestID: begin.RequestID, Code: "A1B2C3"})
	if err != nil {
		t.Fatalf("Verify: %v", err)
	}
	if result.Email != "new@example.com" || repo.updateCalls != 1 || repo.email != "new@example.com" {
		t.Fatalf("result=%+v repo=%+v", result, repo)
	}
	if len(validator.emails) != 1 {
		t.Fatalf("delivery validator calls = %d, want Begin only", len(validator.emails))
	}
}
