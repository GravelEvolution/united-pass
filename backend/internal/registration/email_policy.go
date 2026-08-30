package registration

import "strings"

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

func registrationEmailDomain(email string) string {
	at := strings.LastIndexByte(email, '@')
	if at < 1 || at == len(email)-1 {
		return ""
	}
	return strings.TrimSuffix(strings.ToLower(email[at+1:]), ".")
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
