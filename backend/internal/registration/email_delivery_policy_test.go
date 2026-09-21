package registration

import (
	"context"
	"errors"
	"net"
	"strconv"
	"strings"
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

func TestEmailDeliveryAssessmentCacheDoesNotExposeMutableMXGroups(t *testing.T) {
	t.Parallel()
	resolver := &mailResolverStub{mx: []*net.MX{{Host: "mx.original-provider.net.", Pref: 10}}}
	validator := newEmailDeliveryValidator(resolver, time.Second, time.Minute)
	first, err := validator.Assess(t.Context(), "person@rare.example")
	if err != nil || len(first.MXGroups) != 1 {
		t.Fatalf("first assessment=%#v err=%v", first, err)
	}
	first.MXGroups[0] = "attacker-controlled.example"
	second, err := validator.Assess(t.Context(), "person@rare.example")
	if err != nil || len(second.MXGroups) != 1 || second.MXGroups[0] != "original-provider.net" {
		t.Fatalf("cached assessment=%#v err=%v", second, err)
	}
	if resolver.mxCalls != 1 {
		t.Fatalf("LookupMX calls=%d, want one cached lookup", resolver.mxCalls)
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

func TestEmailDeliveryAssessmentUsesIndependentUnfamiliarMXOperators(t *testing.T) {
	t.Parallel()
	resolver := &mailResolverStub{mx: []*net.MX{
		{Host: "mx.two-provider.org.", Pref: 20},
		{Host: "backup.one-provider.net.", Pref: 30},
		{Host: "mx.one-provider.net.", Pref: 10},
	}}
	validator := newEmailDeliveryValidator(resolver, time.Second, time.Minute)
	assessment, err := validator.Assess(t.Context(), "person@rare.example")
	if err != nil {
		t.Fatal(err)
	}
	want := []string{"one-provider.net", "two-provider.org"}
	if strings.Join(assessment.MXGroups, ",") != strings.Join(want, ",") || assessment.MXEstablished {
		t.Fatalf("assessment = %#v, want independent MX groups %#v", assessment, want)
	}
}

func TestEmailDeliveryAssessmentDoesNotPenalizeEstablishedRecipientForMXRouting(t *testing.T) {
	t.Parallel()
	resolver := &mailResolverStub{mx: []*net.MX{{Host: "mx.unlisted-provider.net.", Pref: 10}}}
	validator := newEmailDeliveryValidator(resolver, time.Second, time.Minute)
	assessment, err := validator.Assess(t.Context(), "person@163.com")
	if err != nil {
		t.Fatal(err)
	}
	if !assessment.DomainEstablished || !assessment.MXEstablished || len(assessment.MXGroups) != 0 {
		t.Fatalf("established recipient assessment = %#v", assessment)
	}
}

func TestEmailDeliveryAssessmentRejectsExcessiveIndependentMXOperators(t *testing.T) {
	t.Parallel()
	mx := make([]*net.MX, 0, MaxCreateRateMXCohorts+1)
	for index := 0; index <= MaxCreateRateMXCohorts; index++ {
		mx = append(mx, &net.MX{Host: "mx.provider-" + strconv.Itoa(index) + ".net.", Pref: uint16(index)})
	}
	validator := newEmailDeliveryValidator(&mailResolverStub{mx: mx}, time.Second, time.Minute)
	if _, err := validator.Assess(t.Context(), "person@rare.example"); !errors.Is(err, ErrInvalidInput) {
		t.Fatalf("excessive MX assessment error = %v, want ErrInvalidInput", err)
	}
}

func TestEmailDeliveryAssessmentFallbackUsesRegistrableRecipientDomain(t *testing.T) {
	t.Parallel()
	resolver := &mailResolverStub{
		mxErr:     &net.DNSError{IsNotFound: true},
		addresses: []net.IPAddr{{IP: net.ParseIP("192.0.2.10")}},
	}
	validator := newEmailDeliveryValidator(resolver, time.Second, time.Minute)
	assessment, err := validator.Assess(t.Context(), "person@mail.dept.example.com")
	if err != nil {
		t.Fatal(err)
	}
	if assessment.DomainGroup != "example.com" || len(assessment.MXGroups) != 1 || assessment.MXGroups[0] != "example.com" {
		t.Fatalf("fallback assessment = %#v, want registrable domain grouping", assessment)
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
