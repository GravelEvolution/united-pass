package registration

import (
	"context"
	"errors"
	"fmt"
	"net"
	"sort"
	"strings"
	"sync"
	"time"

	"golang.org/x/net/publicsuffix"
)

const (
	defaultEmailLookupTimeout    = 2 * time.Second
	defaultEmailCacheTTL         = 15 * time.Minute
	maxEmailDeliveryCacheEntries = 2048
	maxEmailLookupsInFlight      = 8
	maxEmailLookupsQueued        = 32
)

var blockedRegistrationMXDomains = []string{
	"agenticlab.sh",
	// Mail.tm publishes rotating recipient domains behind in.mail.tm. Match
	// the operator's MX suffix instead of chasing each temporary domain.
	"mail.tm",
}

type EmailValidator interface {
	Validate(context.Context, string) error
}

type EmailDomainProfile struct {
	Domain      string
	Established bool
}

// EmailAssessment contains only normalized routing domains. Callers must hash
// these values before using them as distributed rate-limit identifiers.
type EmailAssessment struct {
	Domain            string
	DomainGroup       string
	DomainEstablished bool
	MXGroups          []string
	MXEstablished     bool
}

type EmailRiskAssessor interface {
	EmailValidator
	Profile(string) (EmailDomainProfile, error)
	Assess(context.Context, string) (EmailAssessment, error)
}

type mailResolver interface {
	LookupMX(context.Context, string) ([]*net.MX, error)
	LookupIPAddr(context.Context, string) ([]net.IPAddr, error)
}

type emailDeliveryCacheEntry struct {
	assessment EmailAssessment
	err        error
	expiresAt  time.Time
}

type emailLookupCall struct {
	done       chan struct{}
	assessment EmailAssessment
	err        error
}

// EmailDeliveryValidator verifies that a registration address has a usable
// delivery route and that its MX operator is not part of the observed
// disposable-mail infrastructure. It never performs an SMTP probe.
type EmailDeliveryValidator struct {
	resolver mailResolver
	timeout  time.Duration
	cacheTTL time.Duration
	now      func() time.Time
	policy   *emailDomainPolicy

	mu              sync.Mutex
	cache           map[string]emailDeliveryCacheEntry
	inflight        map[string]*emailLookupCall
	lookupSemaphore chan struct{}
	lookupSlots     chan struct{}
}

func NewDefaultEmailDeliveryValidator() *EmailDeliveryValidator {
	validator, err := NewEmailDeliveryValidator(EmailDeliveryPolicyConfig{})
	if err != nil {
		return nil
	}
	return validator
}

func NewEmailDeliveryValidator(cfg EmailDeliveryPolicyConfig) (*EmailDeliveryValidator, error) {
	policy, err := newEmailDomainPolicy(cfg)
	if err != nil {
		return nil, err
	}
	return newEmailDeliveryValidatorWithPolicy(net.DefaultResolver, defaultEmailLookupTimeout, defaultEmailCacheTTL, policy), nil
}

func newEmailDeliveryValidator(resolver mailResolver, timeout, cacheTTL time.Duration) *EmailDeliveryValidator {
	policy, _ := newEmailDomainPolicy(EmailDeliveryPolicyConfig{})
	return newEmailDeliveryValidatorWithPolicy(resolver, timeout, cacheTTL, policy)
}

func newEmailDeliveryValidatorWithPolicy(resolver mailResolver, timeout, cacheTTL time.Duration, policy *emailDomainPolicy) *EmailDeliveryValidator {
	return &EmailDeliveryValidator{
		resolver:        resolver,
		timeout:         timeout,
		cacheTTL:        cacheTTL,
		now:             time.Now,
		policy:          policy,
		cache:           make(map[string]emailDeliveryCacheEntry),
		inflight:        make(map[string]*emailLookupCall),
		lookupSemaphore: make(chan struct{}, maxEmailLookupsInFlight),
		lookupSlots:     make(chan struct{}, maxEmailLookupsInFlight+maxEmailLookupsQueued),
	}
}

func (v *EmailDeliveryValidator) Validate(ctx context.Context, email string) error {
	_, err := v.Assess(ctx, email)
	return err
}

func (v *EmailDeliveryValidator) Profile(email string) (EmailDomainProfile, error) {
	if v == nil || v.policy == nil {
		return EmailDomainProfile{}, ErrUnavailable
	}
	return v.policy.profile(email)
}

func (v *EmailDeliveryValidator) Assess(ctx context.Context, email string) (EmailAssessment, error) {
	if v == nil || v.resolver == nil || v.timeout <= 0 || v.cacheTTL <= 0 || v.policy == nil {
		return EmailAssessment{}, ErrUnavailable
	}
	profile, err := v.Profile(email)
	if err != nil {
		return EmailAssessment{}, err
	}
	domain := profile.Domain

	now := v.now().UTC()
	v.mu.Lock()
	entry, cached := v.cache[domain]
	if cached && now.Before(entry.expiresAt) {
		v.mu.Unlock()
		return cloneEmailAssessment(entry.assessment), entry.err
	}
	if cached {
		delete(v.cache, domain)
	}
	if call := v.inflight[domain]; call != nil {
		v.mu.Unlock()
		select {
		case <-call.done:
			return cloneEmailAssessment(call.assessment), call.err
		case <-ctx.Done():
			return EmailAssessment{}, ErrUnavailable
		}
	}
	call := &emailLookupCall{done: make(chan struct{})}
	v.inflight[domain] = call
	v.mu.Unlock()

	assessment, result := v.performBoundedLookup(ctx, profile)
	if errors.Is(result, ErrInvalidInput) || result == nil {
		v.storeCache(domain, assessment, result, now)
	}
	v.mu.Lock()
	call.assessment = cloneEmailAssessment(assessment)
	call.err = result
	delete(v.inflight, domain)
	close(call.done)
	v.mu.Unlock()
	return assessment, result
}

func (v *EmailDeliveryValidator) performBoundedLookup(ctx context.Context, profile EmailDomainProfile) (EmailAssessment, error) {
	select {
	case v.lookupSlots <- struct{}{}:
		defer func() { <-v.lookupSlots }()
	default:
		return EmailAssessment{}, ErrUnavailable
	}
	lookupCtx, cancel := context.WithTimeout(context.WithoutCancel(ctx), v.timeout)
	defer cancel()
	select {
	case v.lookupSemaphore <- struct{}{}:
		defer func() { <-v.lookupSemaphore }()
	case <-lookupCtx.Done():
		return EmailAssessment{}, ErrUnavailable
	}
	return v.validateDomain(lookupCtx, profile)
}

func (v *EmailDeliveryValidator) storeCache(domain string, assessment EmailAssessment, result error, now time.Time) {
	v.mu.Lock()
	defer v.mu.Unlock()
	if len(v.cache) >= maxEmailDeliveryCacheEntries {
		for key, entry := range v.cache {
			if !now.Before(entry.expiresAt) {
				delete(v.cache, key)
			}
		}
	}
	if len(v.cache) >= maxEmailDeliveryCacheEntries {
		for key := range v.cache {
			delete(v.cache, key)
			break
		}
	}
	v.cache[domain] = emailDeliveryCacheEntry{assessment: cloneEmailAssessment(assessment), err: result, expiresAt: now.Add(v.cacheTTL)}
}

func cloneEmailAssessment(assessment EmailAssessment) EmailAssessment {
	assessment.MXGroups = append([]string(nil), assessment.MXGroups...)
	return assessment
}

func (v *EmailDeliveryValidator) validateDomain(ctx context.Context, profile EmailDomainProfile) (EmailAssessment, error) {
	assessment := EmailAssessment{
		Domain:            profile.Domain,
		DomainGroup:       registrableMailDomain(profile.Domain),
		DomainEstablished: profile.Established,
	}
	mxRecords, err := v.resolver.LookupMX(ctx, profile.Domain)
	if err == nil && len(mxRecords) > 0 {
		unfamiliarOperators := make(map[string]struct{}, len(mxRecords))
		for _, record := range mxRecords {
			host := strings.TrimSuffix(strings.ToLower(strings.TrimSpace(record.Host)), ".")
			if host == "" {
				return EmailAssessment{}, fmt.Errorf("%w: email", ErrInvalidInput)
			}
			if domainInSet(host, v.policy.blockedMXDomains) {
				return EmailAssessment{}, fmt.Errorf("%w: email", ErrInvalidInput)
			}
			operator := registrableMailDomain(host)
			if !domainInSet(host, v.policy.establishedMXDomains) && !domainInSet(operator, v.policy.establishedMXDomains) {
				unfamiliarOperators[operator] = struct{}{}
			}
		}
		// A reviewed recipient domain is already a large shared namespace.
		// Its provider's current routing must not accidentally turn all of its
		// unrelated users into one unfamiliar-MX cohort. Blocked-MX checks above
		// still apply before this exemption.
		if profile.Established {
			assessment.MXEstablished = true
			return assessment, nil
		}
		if len(unfamiliarOperators) > MaxCreateRateMXCohorts {
			return EmailAssessment{}, fmt.Errorf("%w: email", ErrInvalidInput)
		}
		ordered := make([]string, 0, len(unfamiliarOperators))
		for operator := range unfamiliarOperators {
			ordered = append(ordered, operator)
		}
		sort.Strings(ordered)
		assessment.MXGroups = ordered
		assessment.MXEstablished = len(ordered) == 0
		return assessment, nil
	}
	if err != nil && !isDNSNotFound(err) {
		return EmailAssessment{}, ErrUnavailable
	}

	addresses, addressErr := v.resolver.LookupIPAddr(ctx, profile.Domain)
	if addressErr != nil {
		if isDNSNotFound(addressErr) {
			return EmailAssessment{}, fmt.Errorf("%w: email", ErrInvalidInput)
		}
		return EmailAssessment{}, ErrUnavailable
	}
	if len(addresses) == 0 {
		return EmailAssessment{}, fmt.Errorf("%w: email", ErrInvalidInput)
	}
	assessment.MXEstablished = profile.Established
	if !profile.Established {
		assessment.MXGroups = []string{assessment.DomainGroup}
	}
	return assessment, nil
}

func registrableMailDomain(host string) string {
	operator, err := publicsuffix.EffectiveTLDPlusOne(host)
	if err != nil || operator == "" {
		return host
	}
	return strings.ToLower(operator)
}

func isDNSNotFound(err error) bool {
	var dnsErr *net.DNSError
	return errors.As(err, &dnsErr) && dnsErr.IsNotFound
}

func domainMatches(candidate, blocked string) bool {
	candidate = strings.TrimSuffix(strings.ToLower(strings.TrimSpace(candidate)), ".")
	blocked = strings.TrimSuffix(strings.ToLower(strings.TrimSpace(blocked)), ".")
	return candidate == blocked || strings.HasSuffix(candidate, "."+blocked)
}
