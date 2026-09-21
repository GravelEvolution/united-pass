package registration

import (
	"fmt"
	"strings"

	"golang.org/x/net/idna"
	"golang.org/x/net/publicsuffix"
)

// blockedRegistrationEmailDomains is intentionally small and evidence based.
// It is not a generic TLD denylist: each entry was observed in the confirmed
// automated-registration wave. Subdomains are rejected as well so rotating a
// mailbox host underneath the same disposable domain cannot bypass the rule.
var blockedRegistrationEmailDomains = map[string]struct{}{
	"agibar.icu": {},
	// Mail.tm rotates public mailbox domains. The MX-operator rule in
	// email_delivery_policy.go is authoritative across rotations; retaining
	// the currently observed domain here also fails closed if its DNS route is
	// temporarily changed or removed.
	"emalupe.com":      {},
	"rickroll.icu":     {},
	"teensintimes.icu": {},
	"trinity3.icu":     {},
}

// establishedRegistrationEmailDomains are large consumer providers where one
// exact domain naturally represents many unrelated people. Unlisted domains
// are not rejected; they receive tighter aggregate admission and rate budgets.
var establishedRegistrationEmailDomains = map[string]struct{}{
	"126.com":        {},
	"163.com":        {},
	"aliyun.com":     {},
	"foxmail.com":    {},
	"gmail.com":      {},
	"googlemail.com": {},
	"hotmail.com":    {},
	"icloud.com":     {},
	"live.com":       {},
	"mac.com":        {},
	"me.com":         {},
	"msn.com":        {},
	"outlook.com":    {},
	"proton.me":      {},
	"protonmail.com": {},
	"qq.com":         {},
	"sina.cn":        {},
	"sina.com":       {},
	"yeah.net":       {},
}

var establishedRegistrationMXDomains = map[string]struct{}{
	"aliyun.com":     {},
	"apple.com":      {},
	"google.com":     {},
	"googlemail.com": {},
	"outlook.com":    {},
	"protonmail.ch":  {},
	"qq.com":         {},
	"163.com":        {},
}

// EmailDeliveryPolicyConfig extends the reviewed built-in policy. Entries are
// exact domains or parent domains; wildcards and public-suffix-wide bans are
// deliberately unsupported.
type EmailDeliveryPolicyConfig struct {
	AdditionalBlockedDomains       []string
	AdditionalBlockedMXDomains     []string
	AdditionalEstablishedDomains   []string
	AdditionalEstablishedMXDomains []string
}

type emailDomainPolicy struct {
	blockedDomains       map[string]struct{}
	blockedMXDomains     map[string]struct{}
	establishedDomains   map[string]struct{}
	establishedMXDomains map[string]struct{}
}

func newEmailDomainPolicy(cfg EmailDeliveryPolicyConfig) (*emailDomainPolicy, error) {
	policy := &emailDomainPolicy{
		blockedDomains:       cloneDomainSet(blockedRegistrationEmailDomains),
		blockedMXDomains:     sliceDomainSet(blockedRegistrationMXDomains),
		establishedDomains:   cloneDomainSet(establishedRegistrationEmailDomains),
		establishedMXDomains: cloneDomainSet(establishedRegistrationMXDomains),
	}
	inputs := []struct {
		label  string
		values []string
		target map[string]struct{}
	}{
		{"blocked email domain", cfg.AdditionalBlockedDomains, policy.blockedDomains},
		{"blocked MX domain", cfg.AdditionalBlockedMXDomains, policy.blockedMXDomains},
		{"established email domain", cfg.AdditionalEstablishedDomains, policy.establishedDomains},
		{"established MX domain", cfg.AdditionalEstablishedMXDomains, policy.establishedMXDomains},
	}
	for _, input := range inputs {
		if len(input.values) > 4096 {
			return nil, fmt.Errorf("%w: too many %s entries", ErrUnavailable, input.label)
		}
		for _, raw := range input.values {
			domain, err := normalizePolicyDomain(raw)
			if err != nil {
				return nil, fmt.Errorf("%w: invalid %s", ErrUnavailable, input.label)
			}
			input.target[domain] = struct{}{}
		}
	}
	return policy, nil
}

func cloneDomainSet(source map[string]struct{}) map[string]struct{} {
	result := make(map[string]struct{}, len(source))
	for domain := range source {
		result[domain] = struct{}{}
	}
	return result
}

func sliceDomainSet(source []string) map[string]struct{} {
	result := make(map[string]struct{}, len(source))
	for _, domain := range source {
		result[domain] = struct{}{}
	}
	return result
}

func normalizePolicyDomain(raw string) (string, error) {
	if raw != strings.TrimSpace(raw) || raw == "" || strings.ContainsAny(raw, "*@/:") {
		return "", ErrInvalidInput
	}
	domain, err := normalizeEmailDomain(raw)
	if err != nil || !strings.Contains(domain, ".") {
		return "", ErrInvalidInput
	}
	// Reject ICANN and private public suffixes (for example com.cn and
	// github.io). A suffix-wide block or trust entry would affect unrelated
	// tenants and turn an operator typo into a broad registration outage.
	if suffix, _ := publicsuffix.PublicSuffix(domain); suffix == domain {
		return "", ErrInvalidInput
	}
	return domain, nil
}

func normalizeEmailDomain(raw string) (string, error) {
	raw = strings.TrimSuffix(strings.ToLower(strings.TrimSpace(raw)), ".")
	if raw == "" || len(raw) > 253 {
		return "", ErrInvalidInput
	}
	ascii, err := idna.Lookup.ToASCII(raw)
	if err != nil || ascii == "" || len(ascii) > 253 {
		return "", ErrInvalidInput
	}
	for _, label := range strings.Split(ascii, ".") {
		if label == "" || len(label) > 63 || label[0] == '-' || label[len(label)-1] == '-' {
			return "", ErrInvalidInput
		}
		for _, character := range label {
			if (character < 'a' || character > 'z') && (character < '0' || character > '9') && character != '-' {
				return "", ErrInvalidInput
			}
		}
	}
	return ascii, nil
}

func registrationEmailDomain(email string) string {
	at := strings.LastIndexByte(email, '@')
	if at < 1 || at == len(email)-1 {
		return ""
	}
	domain, err := normalizeEmailDomain(email[at+1:])
	if err != nil {
		return ""
	}
	return domain
}

// MailboxFamilyRateIdentity returns a reviewed provider-specific identity for
// aliases that are known to deliver to the same inbox. It deliberately does
// not apply plus stripping or dot folding to arbitrary domains because those
// characters can name distinct mailboxes on other providers.
func MailboxFamilyRateIdentity(email string) string {
	at := strings.LastIndexByte(email, '@')
	if at < 1 || at == len(email)-1 {
		return ""
	}
	local := strings.ToLower(email[:at])
	domain, err := normalizeEmailDomain(email[at+1:])
	if err != nil {
		return ""
	}
	stripPlus := func(value string) string {
		if plus := strings.IndexByte(value, '+'); plus >= 0 {
			return value[:plus]
		}
		return value
	}
	switch domain {
	case "gmail.com", "googlemail.com":
		local = strings.ReplaceAll(stripPlus(local), ".", "")
		domain = "gmail.com"
	case "outlook.com", "hotmail.com", "live.com", "msn.com":
		local = stripPlus(local)
	default:
		return ""
	}
	if local == "" {
		return ""
	}
	return local + "@" + domain
}

func isBlockedRegistrationEmail(email string) bool {
	domain := registrationEmailDomain(email)
	if domain == "" {
		return false
	}
	for blockedDomain := range blockedRegistrationEmailDomains {
		if domainMatches(domain, blockedDomain) {
			return true
		}
	}
	return false
}

func (p *emailDomainPolicy) profile(email string) (EmailDomainProfile, error) {
	domain := registrationEmailDomain(email)
	if p == nil || domain == "" {
		return EmailDomainProfile{}, fmt.Errorf("%w: email", ErrInvalidInput)
	}
	if domainInSet(domain, p.blockedDomains) {
		return EmailDomainProfile{}, fmt.Errorf("%w: email", ErrInvalidInput)
	}
	return EmailDomainProfile{Domain: domain, Established: domainInSet(domain, p.establishedDomains)}, nil
}

func domainInSet(candidate string, domains map[string]struct{}) bool {
	for domain := range domains {
		if domainMatches(candidate, domain) {
			return true
		}
	}
	return false
}
