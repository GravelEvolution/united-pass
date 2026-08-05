package applications

import (
	"fmt"
	"net/url"
	"strings"
)

// FieldError is one field-level validation failure. Messages are safe for
// user display and never contain secrets or provider detail.
type FieldError struct {
	Field   string
	Message string
}

// ValidationErrors aggregates field errors for one request.
type ValidationErrors struct {
	Errors []FieldError
}

// Error implements error.
func (v *ValidationErrors) Error() string {
	parts := make([]string, len(v.Errors))
	for i, fe := range v.Errors {
		parts[i] = fe.Field + ": " + fe.Message
	}
	return "applications: validation failed: " + strings.Join(parts, "; ")
}

// Add appends a field error.
func (v *ValidationErrors) Add(field, message string) {
	v.Errors = append(v.Errors, FieldError{Field: field, Message: message})
}

// Addf appends a formatted field error.
func (v *ValidationErrors) Addf(field, format string, args ...any) {
	v.Add(field, fmt.Sprintf(format, args...))
}

// ErrOrNil returns nil when no errors were collected.
func (v *ValidationErrors) ErrOrNil() error {
	if len(v.Errors) == 0 {
		return nil
	}
	return v
}

// ApplicationInput carries validated application metadata. OwnerID is the
// authoritative field (G1); ownership is never derived from a display name.
type ApplicationInput struct {
	Name        string
	Description string
	Audience    ApplicationAudience
	OwnerID     string
}

// ValidateApplicationInput checks application metadata fields. Owner
// existence is verified by the use-case layer against the user store.
func ValidateApplicationInput(in ApplicationInput) error {
	var errs ValidationErrors
	name := strings.TrimSpace(in.Name)
	if len([]rune(name)) < ApplicationNameMin {
		errs.Add("name", "应用名称至少需要 2 个字符。")
	}
	if len([]rune(name)) > ApplicationNameMax {
		errs.Add("name", "应用名称不能超过 80 个字符。")
	}
	if len([]rune(in.Description)) > ApplicationDescMax {
		errs.Add("description", "应用说明不能超过 500 个字符。")
	}
	if !in.Audience.IsValid() {
		errs.Add("audience", "未知的应用受众类型。")
	}
	if strings.TrimSpace(in.OwnerID) == "" {
		errs.Add("ownerId", "请选择应用负责人。")
	}
	return errs.ErrOrNil()
}

// ClientInput carries a client creation request. GrantTypes and
// TokenEndpointAuthMethod are optional submissions validated against the
// profile; the profile is the stored authority and submitted values are
// never silently mutated (ADR-0004 §3).
type ClientInput struct {
	Name              string
	Profile           ClientProfile
	RedirectURIs      []string
	LogoutURI         string
	Scopes            []string
	ConsentMode       ConsentMode
	GrantTypes        []OAuthGrantType
	TokenEndpointAuth *TokenEndpointAuthMethod
}

// ValidateClientInput validates a client creation request against the scope
// catalog and the profile rules. It collects all field errors instead of
// stopping at the first one.
func ValidateClientInput(in ClientInput) error {
	var errs ValidationErrors

	name := strings.TrimSpace(in.Name)
	if len([]rune(name)) < ClientNameMin {
		errs.Add("name", "客户端名称至少需要 2 个字符。")
	}
	if len([]rune(name)) > ClientNameMax {
		errs.Add("name", "客户端名称不能超过 64 个字符。")
	}

	rules, ok := in.Profile.Rules()
	if !ok {
		errs.Add("profile", "未知的客户端 Profile。")
		// Without rules the remaining profile-dependent checks cannot run.
		return &errs
	}

	validateRedirectURIs(&errs, in.RedirectURIs, rules)
	validateLogoutURI(&errs, in.LogoutURI)
	validateScopes(&errs, in.Scopes, rules)
	validateConsentMode(&errs, in.ConsentMode, rules)
	validateSubmittedGrantTypes(&errs, in.GrantTypes, rules)
	validateSubmittedTokenAuth(&errs, in.TokenEndpointAuth, rules)

	return errs.ErrOrNil()
}

func validateRedirectURIs(errs *ValidationErrors, uris []string, rules ProfileRules) {
	if len(uris) == 0 && rules.RedirectURIRequired {
		errs.Add("redirectUris", "该 Profile 至少需要一个 Redirect URI。")
		return
	}
	if len(uris) > 0 && !rules.RedirectURIRequired {
		errs.Add("redirectUris", "该 Profile 不需要 Redirect URI。")
		return
	}
	if len(uris) > MaxRedirectURIs {
		errs.Addf("redirectUris", "Redirect URI 数量不能超过 %d 个。", MaxRedirectURIs)
	}
	seen := make(map[string]struct{}, len(uris))
	for i, uri := range uris {
		field := fmt.Sprintf("redirectUris[%d]", i)
		_, _, ok := checkRedirectURI(uri)
		if !ok {
			errs.Add(field, "Redirect URI 格式无效。仅接受 https:// 或本地回环 http:// 地址。")
			continue
		}
		if _, dup := seen[uri]; dup {
			errs.Add(field, "Redirect URI 重复。")
			continue
		}
		seen[uri] = struct{}{}
	}
}

// checkRedirectURI enforces the exact-match security semantics of ADR-0004
// §4. It returns whether the URI is a loopback address and never modifies
// the value. The stored URI must always be the exact submitted string.
func checkRedirectURI(uri string) (isLoopback bool, normalized string, ok bool) {
	if uri == "" || len(uri) > MaxRedirectURILen {
		return false, "", false
	}
	if strings.TrimSpace(uri) != uri {
		// Reject surrounding whitespace instead of trimming it.
		return false, "", false
	}
	parsed, err := url.Parse(uri)
	if err != nil {
		return false, "", false
	}
	if !parsed.IsAbs() {
		return false, "", false
	}
	if parsed.Fragment != "" {
		return false, "", false
	}
	if parsed.User != nil {
		return false, "", false
	}
	if strings.ContainsAny(uri, "*") {
		return false, "", false
	}
	host := parsed.Hostname()
	if host == "" {
		return false, "", false
	}
	switch parsed.Scheme {
	case "https":
		return false, uri, true
	case "http":
		// RFC 8252 §7.1 loopback exception only. Loopback ports are dynamic
		// and not a prefix-matching risk; any port is accepted on loopback.
		if host == "localhost" || host == "127.0.0.1" || host == "::1" {
			return true, uri, true
		}
		return false, "", false
	default:
		// Custom schemes (native apps) are not supported in MVP.
		return false, "", false
	}
}

// ValidateRedirectURI is the exported single-URI check used when updating a
// client's redirect URI set.
func ValidateRedirectURI(uri string) (isLoopback bool, ok bool) {
	lb, _, valid := checkRedirectURI(uri)
	return lb, valid
}

func validateLogoutURI(errs *ValidationErrors, uri string) {
	if uri == "" {
		return
	}
	if _, _, ok := checkRedirectURI(uri); !ok {
		errs.Add("logoutUri", "Logout URI 格式无效。仅接受 https:// 或本地回环 http:// 地址。")
	}
}

func validateScopes(errs *ValidationErrors, scopes []string, rules ProfileRules) {
	seen := make(map[string]struct{}, len(scopes))
	hasRefresh := rules.HasGrantType(GrantTypeRefreshToken)
	for _, scope := range scopes {
		if _, dup := seen[scope]; dup {
			errs.Addf("allowedScopes", "Scope 重复: %s。", scope)
			continue
		}
		seen[scope] = struct{}{}
		if !KnownScope(scope) {
			errs.Addf("allowedScopes", "未知的 Scope: %s。请使用已登记的 Scope。", scope)
			continue
		}
		if scope == "openid" && !rules.OpenIDAllowed {
			errs.Add("allowedScopes", "该 Profile 不支持 openid Scope。openid 仅适用于需要用户交互的客户端。")
		}
		if scope == "offline_access" && !hasRefresh {
			errs.Add("allowedScopes", "offline_access 仅在使用 Refresh Token 的客户端上可用。")
		}
	}
}

func validateConsentMode(errs *ValidationErrors, mode ConsentMode, rules ProfileRules) {
	switch mode {
	case ConsentModeAlways:
		// Always accepted; for non-consent profiles it is not-applicable
		// metadata (G4).
	case ConsentModeFirstAuthorization:
		if !rules.ConsentApplicable {
			errs.Add("consentMode", "该 Profile 无用户交互，同意模式必须为 always。")
		}
	default:
		errs.Add("consentMode", "未知的同意模式。trusted_first_party 暂不支持。")
	}
}

func validateSubmittedGrantTypes(errs *ValidationErrors, submitted []OAuthGrantType, rules ProfileRules) {
	if len(submitted) == 0 {
		return
	}
	if len(submitted) != len(rules.GrantTypes) {
		errs.Add("grantTypes", "提交的 Grant Types 与所选 Profile 不一致。")
		return
	}
	for i, gt := range submitted {
		if !rules.HasGrantType(gt) {
			errs.Addf(fmt.Sprintf("grantTypes[%d]", i), "该 Profile 不支持 Grant Type: %s。", string(gt))
		}
	}
}

func validateSubmittedTokenAuth(errs *ValidationErrors, submitted *TokenEndpointAuthMethod, rules ProfileRules) {
	if submitted == nil {
		return
	}
	// client_secret_post and private_key_jwt have no verified provider
	// support or reviewed security model in Phase 2 and are rejected.
	if *submitted != rules.TokenEndpointAuth {
		errs.Add("tokenEndpointAuthMethod",
			fmt.Sprintf("该 Profile 的 Token Endpoint 认证方式必须为 %s。", string(rules.TokenEndpointAuth)))
	}
}
