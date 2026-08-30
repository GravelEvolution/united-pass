// Package dreamupadmin coordinates the United Pass control plane with the
// private DreamUP event administration data plane.
package dreamupadmin

import (
	"context"
	"encoding/json"
	"errors"
	"net/url"
	"time"

	"github.com/GravelEvolution/united-pass/backend/internal/adminpagination"
	"github.com/GravelEvolution/united-pass/backend/internal/adminroles"
	"github.com/GravelEvolution/united-pass/backend/internal/adminstepup"
	"github.com/GravelEvolution/united-pass/backend/internal/adminstore"
	"github.com/GravelEvolution/united-pass/backend/internal/applications"
	"github.com/GravelEvolution/united-pass/backend/internal/auth"
	"github.com/GravelEvolution/united-pass/backend/internal/dreamupdelegation"
	"github.com/GravelEvolution/united-pass/backend/internal/identity"
	"github.com/GravelEvolution/united-pass/backend/internal/permissions"
	"github.com/GravelEvolution/united-pass/backend/internal/securitystate"
)

var (
	ErrInvalidRequest = errors.New("dreamupadmin: invalid request")
	ErrForbidden      = errors.New("dreamupadmin: forbidden")
	ErrNotFound       = errors.New("dreamupadmin: not found")
	ErrStepUpRequired = errors.New("dreamupadmin: administrator step-up required")
	ErrConflict       = errors.New("dreamupadmin: conflict")
	ErrUpstream       = errors.New("dreamupadmin: upstream unavailable")
)

type Actor struct {
	UserID          identity.UserID
	SessionID       string
	AuthenticatedAt time.Time
	// SecurityEpoch is copied from the already validated server-side session
	// record. Native Mini Program administrator authorization compares it with
	// the authoritative account epoch before every privileged request, so a
	// password or account-security change still invalidates the bearer even
	// though the Mini Program no longer asks a separate security question.
	SecurityEpoch securitystate.Epoch
	// AuthenticationTransport is set by the HTTP boundary after it has
	// validated the request credential and client shape. It prevents either
	// browser compatibility behavior or native session authorization from being
	// selected by a caller-controlled header alone.
	AuthenticationTransport AuthenticationTransport
}

// AuthenticationTransport records the already-authenticated HTTP transport
// used for one DreamUP administrator request. It is authority-relevant only
// for the narrow legacy cookie compatibility path; unknown transports never
// receive that fallback.
type AuthenticationTransport string

const (
	AuthenticationTransportBrowserCookie           AuthenticationTransport = "browser_cookie"
	AuthenticationTransportNativeMiniProgramBearer AuthenticationTransport = "native_miniprogram_bearer"
)

type EventSummary struct {
	EventID     string          `json:"eventId"`
	DisplayName string          `json:"displayName"`
	Slug        string          `json:"slug,omitempty"`
	Role        adminroles.Role `json:"role,omitempty"`
	Counts      EventCounts     `json:"counts"`
}

// EventCounts is the admission-count summary shown on the admin dashboard.
// Pending counts submitted + under_review (not yet decided) applications.
type EventCounts struct {
	Total    int64 `json:"total"`
	Pending  int64 `json:"pending"`
	Accepted int64 `json:"accepted"`
	Rejected int64 `json:"rejected"`
}

type ProxyRequest struct {
	EventID        string
	Capability     permissions.Action
	ResourceKind   string
	ResourceID     string
	Method         string
	Path           string
	Query          url.Values
	Body           json.RawMessage
	RequestID      string
	IdempotencyKey string
	IfMatch        string
	// ReauthenticationToken is the opaque, single-use bearer supplied only
	// for a high-risk administrator request. It is consumed before signing and
	// is never persisted, logged, forwarded, or included in an assertion.
	ReauthenticationToken string
}

type ProxyResponse struct {
	StatusCode int
	Body       json.RawMessage
	RequestID  string
	ETag       string
}

type MutationStatus struct {
	Status         string    `json:"status"`
	RequestID      string    `json:"requestId"`
	ResponseStatus *int      `json:"responseStatus"`
	ResultVersion  *int64    `json:"resultVersion"`
	UpdatedAt      time.Time `json:"updatedAt"`
}

// UpstreamRequest is the exact request-bound transport contract implemented
// by the private DreamUP client adapter.
type UpstreamRequest struct {
	Method         string
	Path           string
	Query          url.Values
	Body           json.RawMessage
	Assertion      dreamupdelegation.SignedAssertion
	RequestID      string
	IdempotencyKey string
	IfMatch        string
}

type UpstreamResponse struct {
	StatusCode int
	Body       json.RawMessage
	RequestID  string
	ETag       string
}

type UpstreamClient interface {
	Execute(context.Context, UpstreamRequest) (UpstreamResponse, error)
}

type AdministratorSigner interface {
	SignAdministrator(dreamupdelegation.AdministratorAssertion) (dreamupdelegation.SignedAssertion, error)
}

type ServiceSigner interface {
	SignService(dreamupdelegation.ServiceAssertion) (dreamupdelegation.SignedAssertion, error)
}

type StepUpReader interface {
	GetActiveForSession(context.Context, string, identity.UserID, time.Time) (adminstepup.StepUpState, error)
}

// AccountSecurityEpochReader reads the current account-wide
// users.security_epoch. The durable cookie compatibility proof must match it
// exactly; a password or other account-security change invalidates the proof
// even if its administrator challenge generation did not change.
type AccountSecurityEpochReader interface {
	CurrentEpoch(context.Context, identity.UserID) (securitystate.Epoch, error)
}

// ReauthGrantVerifier atomically consumes an opaque grant and returns only
// its server-authored binding data. The concrete United Pass verifier also
// enforces the authoritative account security epoch before returning.
type ReauthGrantVerifier interface {
	VerifyAndConsumeData(context.Context, string, string, string, string, applications.ApplicationID, applications.OAuthClientID) (auth.ReauthGrantData, error)
}

type EventRegistry interface {
	GetExact(context.Context, string) (adminroles.RegisteredEvent, error)
	ListEnabled(context.Context, adminpagination.Query) (adminpagination.Page[adminroles.RegisteredEvent], error)
}

type OperationFingerprinter interface {
	Fingerprint(string, []byte) (adminstore.Fingerprint, error)
}
