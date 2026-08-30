package registration

import (
	"context"
	"errors"
	"net"
	"strconv"
	"testing"
	"time"
)

type mailResolverStub struct {
	mx         []*net.MX
	mxErr      error
	addresses  []net.IPAddr
	addressErr error
	mxCalls    int
}

func (s *mailResolverStub) LookupMX(context.Context, string) ([]*net.MX, error) {
	s.mxCalls++
	return s.mx, s.mxErr
}

func (s *mailResolverStub) LookupIPAddr(context.Context, string) ([]net.IPAddr, error) {
	return s.addresses, s.addressErr
}

func TestEmailDeliveryValidatorRejectsObservedDisposableMX(t *testing.T) {
	t.Parallel()
	resolver := &mailResolverStub{mx: []*net.MX{{Host: "publicmx.agenticlab.sh.", Pref: 10}}}
	validator := newEmailDeliveryValidator(resolver, time.Second, time.Minute)
	if err := validator.Validate(t.Context(), "person@fresh-domain.example"); !errors.Is(err, ErrInvalidInput) {
		t.Fatalf("Validate error = %v, want ErrInvalidInput", err)
	}
}

func TestEmailDeliveryValidatorRejectsMailTMOperatorAcrossRotatingDomains(t *testing.T) {
	t.Parallel()
	resolver := &mailResolverStub{mx: []*net.MX{{Host: "in.mail.tm.", Pref: 10}}}
	validator := newEmailDeliveryValidator(resolver, time.Second, time.Minute)
	if err := validator.Validate(t.Context(), "person@future-rotated-domain.example"); !errors.Is(err, ErrInvalidInput) {
		t.Fatalf("Validate error = %v, want ErrInvalidInput", err)
	}
}

func TestEmailDeliveryValidatorAcceptsNormalMXAndCachesResult(t *testing.T) {
	t.Parallel()
	resolver := &mailResolverStub{mx: []*net.MX{{Host: "mx.example.net.", Pref: 10}}}
	validator := newEmailDeliveryValidator(resolver, time.Second, time.Minute)
	for range 2 {
		if err := validator.Validate(t.Context(), "person@example.net"); err != nil {
			t.Fatalf("Validate: %v", err)
		}
	}
	if resolver.mxCalls != 1 {
		t.Fatalf("LookupMX calls = %d, want cached single lookup", resolver.mxCalls)
	}
}

func TestEmailDeliveryValidatorAllowsRFCFallbackAddress(t *testing.T) {
	t.Parallel()
	resolver := &mailResolverStub{
		mxErr:     &net.DNSError{IsNotFound: true},
		addresses: []net.IPAddr{{IP: net.ParseIP("192.0.2.10")}},
	}
	validator := newEmailDeliveryValidator(resolver, time.Second, time.Minute)
	if err := validator.Validate(t.Context(), "person@example.net"); err != nil {
		t.Fatalf("Validate: %v", err)
	}
}

func TestEmailDeliveryValidatorFailsClosedOnTemporaryDNSFailure(t *testing.T) {
	t.Parallel()
	resolver := &mailResolverStub{mxErr: &net.DNSError{IsTimeout: true, IsTemporary: true}}
	validator := newEmailDeliveryValidator(resolver, time.Second, time.Minute)
	if err := validator.Validate(t.Context(), "person@example.net"); !errors.Is(err, ErrUnavailable) {
		t.Fatalf("Validate error = %v, want ErrUnavailable", err)
	}
}

func TestEmailDeliveryValidatorRejectsNoDeliveryRoute(t *testing.T) {
	t.Parallel()
	resolver := &mailResolverStub{
		mxErr:      &net.DNSError{IsNotFound: true},
		addressErr: &net.DNSError{IsNotFound: true},
	}
	validator := newEmailDeliveryValidator(resolver, time.Second, time.Minute)
	if err := validator.Validate(t.Context(), "person@example.net"); !errors.Is(err, ErrInvalidInput) {
		t.Fatalf("Validate error = %v, want ErrInvalidInput", err)
	}
}

func TestEmailDeliveryValidatorBoundsCacheUnderRotatingDomains(t *testing.T) {
	t.Parallel()
	resolver := &mailResolverStub{mx: []*net.MX{{Host: "mx.example.net.", Pref: 10}}}
	validator := newEmailDeliveryValidator(resolver, time.Second, time.Minute)
	now := validator.now().UTC()
	for index := range maxEmailDeliveryCacheEntries {
		validator.cache["old-"+strconv.Itoa(index)+".example"] = emailDeliveryCacheEntry{
			expiresAt: now.Add(time.Minute),
		}
	}
	if err := validator.Validate(t.Context(), "person@new-domain.example"); err != nil {
		t.Fatalf("Validate: %v", err)
	}
	if len(validator.cache) > maxEmailDeliveryCacheEntries {
		t.Fatalf("cache size = %d, max = %d", len(validator.cache), maxEmailDeliveryCacheEntries)
	}
}

type emailValidatorStub struct {
	err   error
	email string
}

func (s *emailValidatorStub) Validate(_ context.Context, email string) error {
	s.email = email
	return s.err
}

func TestCreateChecksDeliveryBeforeAllocatingRegistrationState(t *testing.T) {
	t.Parallel()
	provider := &providerStub{}
	repo := &repositoryStub{}
	tokens := &tokenStoreStub{}
	validator := &emailValidatorStub{err: ErrInvalidInput}
	service := NewService(provider, repo, tokens, Config{
		PublicOrigin:   "https://auth.moonstone.org.cn",
		TokenTTL:       30 * time.Minute,
		EmailValidator: validator,
		GenerateUserID: func() (string, error) { t.Fatal("user ID allocated before email validation"); return "", nil },
		GenerateToken:  func() (string, error) { t.Fatal("token allocated before email validation"); return "", nil },
	})
	_, err := service.Create(t.Context(), CreateInput{
		Username: "person", DisplayName: "Person", Email: "person@example.net",
		Password: "Correct-Horse-9!", AcceptedTerms: true,
	})
	if !errors.Is(err, ErrInvalidInput) {
		t.Fatalf("Create error = %v, want ErrInvalidInput", err)
	}
	if validator.email != "person@example.net" || provider.created.UserID != "" || repo.created.UserID != "" || tokens.rawToken != "" {
		t.Fatalf("side effect before validation: validator=%q provider=%#v repo=%#v token=%q", validator.email, provider.created, repo.created, tokens.rawToken)
	}
}
