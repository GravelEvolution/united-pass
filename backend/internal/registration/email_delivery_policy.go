package registration

import (
	"context"
	"errors"
	"fmt"
	"net"
	"strings"
	"sync"
	"time"
)

const (
	defaultEmailLookupTimeout    = 2 * time.Second
	defaultEmailCacheTTL         = 15 * time.Minute
	maxEmailDeliveryCacheEntries = 2048
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

type mailResolver interface {
	LookupMX(context.Context, string) ([]*net.MX, error)
	LookupIPAddr(context.Context, string) ([]net.IPAddr, error)
}

type emailDeliveryCacheEntry struct {
	err       error
	expiresAt time.Time
}

// EmailDeliveryValidator verifies that a registration address has a usable
// delivery route and that its MX operator is not part of the observed
// disposable-mail infrastructure. It never performs an SMTP probe.
type EmailDeliveryValidator struct {
	resolver mailResolver
	timeout  time.Duration
	cacheTTL time.Duration
	now      func() time.Time

	mu    sync.Mutex
	cache map[string]emailDeliveryCacheEntry
}

func NewDefaultEmailDeliveryValidator() *EmailDeliveryValidator {
	return newEmailDeliveryValidator(net.DefaultResolver, defaultEmailLookupTimeout, defaultEmailCacheTTL)
}

func newEmailDeliveryValidator(resolver mailResolver, timeout, cacheTTL time.Duration) *EmailDeliveryValidator {
	return &EmailDeliveryValidator{
		resolver: resolver,
		timeout:  timeout,
		cacheTTL: cacheTTL,
		now:      time.Now,
		cache:    make(map[string]emailDeliveryCacheEntry),
	}
}

func (v *EmailDeliveryValidator) Validate(ctx context.Context, email string) error {
	if v == nil || v.resolver == nil || v.timeout <= 0 || v.cacheTTL <= 0 {
		return ErrUnavailable
	}
	domain := registrationEmailDomain(email)
	if domain == "" || isBlockedRegistrationEmail(email) {
		return fmt.Errorf("%w: email", ErrInvalidInput)
	}

	now := v.now().UTC()
	v.mu.Lock()
	entry, cached := v.cache[domain]
	if cached && now.Before(entry.expiresAt) {
		v.mu.Unlock()
		return entry.err
	}
	if cached {
		delete(v.cache, domain)
	}
	v.mu.Unlock()

	lookupCtx, cancel := context.WithTimeout(ctx, v.timeout)
	defer cancel()
	result := v.validateDomain(lookupCtx, domain)
	if errors.Is(result, ErrInvalidInput) || result == nil {
		v.storeCache(domain, result, now)
	}
	return result
}

func (v *EmailDeliveryValidator) storeCache(domain string, result error, now time.Time) {
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
	v.cache[domain] = emailDeliveryCacheEntry{err: result, expiresAt: now.Add(v.cacheTTL)}
}

func (v *EmailDeliveryValidator) validateDomain(ctx context.Context, domain string) error {
	mxRecords, err := v.resolver.LookupMX(ctx, domain)
	if err == nil && len(mxRecords) > 0 {
		for _, record := range mxRecords {
			host := strings.TrimSuffix(strings.ToLower(strings.TrimSpace(record.Host)), ".")
			if host == "" {
				return fmt.Errorf("%w: email", ErrInvalidInput)
			}
			for _, blocked := range blockedRegistrationMXDomains {
				if domainMatches(host, blocked) {
					return fmt.Errorf("%w: email", ErrInvalidInput)
				}
			}
		}
		return nil
	}
	if err != nil && !isDNSNotFound(err) {
		return ErrUnavailable
	}

	addresses, addressErr := v.resolver.LookupIPAddr(ctx, domain)
	if addressErr != nil {
		if isDNSNotFound(addressErr) {
			return fmt.Errorf("%w: email", ErrInvalidInput)
		}
		return ErrUnavailable
	}
	if len(addresses) == 0 {
		return fmt.Errorf("%w: email", ErrInvalidInput)
	}
	return nil
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
