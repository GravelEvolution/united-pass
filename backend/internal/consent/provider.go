package consent

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"time"
)

// MaxAuthRequestIDLen bounds the provider auth request ID at every entry
// point. It mirrors the provider's own field limits (1..200); values are
// opaque and never structurally parsed (ADR-0005 §2).
const MaxAuthRequestIDLen = 200

// Prompt mirrors the OIDC prompt values the provider can attach to an auth
// request. Interaction semantics are decided by the resolution domain and
// the interaction gateway (ADR-0005 §9, §12), never here.
type Prompt int

// Prompt values. Unknown provider values map to PromptUnspecified so the
// resolution domain can apply its invalid-combination rules instead of
// silently accepting them.
const (
	PromptUnspecified Prompt = iota
	PromptNone
	PromptLogin
	PromptConsent
	PromptSelectAccount
	PromptCreate
)

func (p Prompt) String() string {
	switch p {
	case PromptNone:
		return "none"
	case PromptLogin:
		return "login"
	case PromptConsent:
		return "consent"
	case PromptSelectAccount:
		return "select_account"
	case PromptCreate:
		return "create"
	default:
		return "unspecified"
	}
}

// AuthRequestView is the provider-side authorization request as read by
// GetAuthRequest: protocol facts only (ADR-0005 §4). It carries no state
// or nonce (the provider echoes both back in the callback URL itself) and
// it is never persisted.
type AuthRequestView struct {
	ID          string
	ClientID    string
	Scopes      []string
	RedirectURI string
	Prompts     []Prompt
	// MaxAge is nil when the RP did not send max_age. A present zero means
	// forced re-authentication (OIDC Core).
	MaxAge *time.Duration
	// LoginHint and HintUserID are empty when absent.
	LoginHint  string
	HintUserID string
	CreatedAt  time.Time
}

// HasPrompt reports whether the request carries the given prompt value.
func (v *AuthRequestView) HasPrompt(p Prompt) bool {
	for _, got := range v.Prompts {
		if got == p {
			return true
		}
	}
	return false
}

// SessionHandle carries the provider session identity needed to complete an
// auth request with Allow (session ID + token on v2.71). It is transient
// bearer material: never logged, persisted or rendered into errors. The
// encrypted, versioned at-rest form is the session package's
// ProviderSessionCredential (ADR-0005 §3); this handle is the narrow
// in-flight value handed to the adapter.
type SessionHandle struct {
	SessionID    string
	SessionToken string
}

// Validate rejects handles the provider would refuse anyway (both fields
// are required, proto-validated min_len=1 on v2.71).
func (s SessionHandle) Validate() error {
	if s.SessionID == "" || s.SessionToken == "" {
		return errors.New("consent: session handle requires session id and token")
	}
	return nil
}

// CallbackErrorReason is the OIDC error the provider should deliver to the
// RP through the error callback (ADR-0005 §9, §12). Deny uses
// ReasonAccessDenied; the non-interactive gateway uses the *_required
// reasons; gateway-side faults that can still safely reach the RP use
// ReasonServerError / ReasonTemporarilyUnavailable.
type CallbackErrorReason int

// Callback error reasons supported by the provider (all verified present in
// the v2.71 ErrorReason enum and its OIDC mapping).
const (
	ReasonAccessDenied CallbackErrorReason = iota + 1
	ReasonLoginRequired
	ReasonConsentRequired
	ReasonAccountSelectionRequired
	ReasonServerError
	ReasonTemporarilyUnavailable
)

func (r CallbackErrorReason) String() string {
	switch r {
	case ReasonAccessDenied:
		return "access_denied"
	case ReasonLoginRequired:
		return "login_required"
	case ReasonConsentRequired:
		return "consent_required"
	case ReasonAccountSelectionRequired:
		return "account_selection_required"
	case ReasonServerError:
		return "server_error"
	case ReasonTemporarilyUnavailable:
		return "temporarily_unavailable"
	default:
		return "unknown"
	}
}

// CallbackResult wraps the provider-generated callback URL returned by a
// completion call. The URL is credential-grade (it contains the code or the
// error for the RP): the value is only ever forwarded to the browser as the
// Location header (gateway) or as the frozen redirectUrl field (decision
// API), never persisted, logged, audited or parsed for code/state
// (ADR-0005 §3). The redacting String method keeps accidental %s/%v
// rendering safe.
type CallbackResult struct {
	url string
}

// NewCallbackResult validates and wraps a provider callback URL.
func NewCallbackResult(url string) (CallbackResult, error) {
	if strings.TrimSpace(url) == "" {
		return CallbackResult{}, errors.New("consent: provider returned an empty callback url")
	}
	return CallbackResult{url: url}, nil
}

// Raw returns the callback URL for forwarding. Callers must treat the
// returned string as credentials (see the type documentation).
func (r CallbackResult) Raw() string { return r.url }

// String redacts the URL; the raw value is only reachable through Raw.
func (r CallbackResult) String() string {
	if r.url == "" {
		return "[no callback]"
	}
	return "[redacted provider callback]"
}

// AuthRequestProvider is the provider seam for the OAuth authorization
// loop. Implementations: the ZITADEL oidc.v2 adapter (production) and the
// fake provider (tests). All methods return *ProviderError-classified
// failures; the one-shot completion semantics of the provider are exposed
// as ClassAlreadyCompleted (ADR-0005 §5).
type AuthRequestProvider interface {
	// GetAuthRequest reads the provider authorization request. It is
	// idempotent and side-effect free; it must never complete or mutate
	// the request (ADR-0005 §12 keeps the resolution GET side-effect
	// free by routing execution through the interaction gateway).
	GetAuthRequest(ctx context.Context, authRequestID string) (*AuthRequestView, error)

	// CompleteWithSession links the verified provider session to the auth
	// request (Allow) and returns the code/token callback URL. One-shot:
	// a second completion of the same request fails with
	// ClassAlreadyCompleted.
	CompleteWithSession(ctx context.Context, authRequestID string, session SessionHandle) (CallbackResult, error)

	// CompleteWithError fails the auth request with an OIDC error callback
	// (Deny and the non-interactive *_required paths) and returns the
	// provider-verified error callback URL. One-shot, same as above.
	CompleteWithError(ctx context.Context, authRequestID string, reason CallbackErrorReason) (CallbackResult, error)
}

// ValidateAuthRequestID enforces the opaque-ID input limits at the adapter
// boundary (ADR-0005 §2): non-empty, decoded length at most 200 bytes.
// Entry points validate earlier; this is the last line of defense before
// the value is composed into provider requests.
func ValidateAuthRequestID(id string) error {
	if id == "" {
		return errors.New("consent: empty auth request id")
	}
	if len(id) > MaxAuthRequestIDLen {
		return fmt.Errorf("consent: auth request id exceeds %d bytes", MaxAuthRequestIDLen)
	}
	return nil
}
