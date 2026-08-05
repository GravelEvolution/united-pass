package applications

import (
	"errors"
	"time"

	"github.com/GravelEvolution/united-pass/backend/internal/identity"
)

// ErrDuplicateName is the domain sentinel for unique live-name conflicts.
// Persistence adapters map their unique-violation errors onto it.
var ErrDuplicateName = errors.New("applications: duplicate name")

// ErrOwnerNotFound is returned when a submitted owner user ID does not
// resolve to an existing user. Ownership is always resolved from the stable
// user ID, never from a display name (ADR-0004 G1).
var ErrOwnerNotFound = errors.New("applications: owner not found")

// ErrInvalidCursor is returned for tampered, malformed or state-mismatched
// list cursors. HTTP adapters map it to a 400 response; raw offsets are
// never exposed (ADR-0004 §9).
var ErrInvalidCursor = errors.New("applications: invalid cursor")

// ListQuery is the validated application list request. All fields are
// optional; Sort defaults to "-updatedAt" and Limit to 20 (1–100) in the
// repository.
type ListQuery struct {
	Cursor   string
	Limit    int
	Query    string
	Sort     string
	Status   string
	Audience string
	OwnerID  string
}

// ListResult is one page plus continuation state.
type ListResult struct {
	Items      []ApplicationSummary
	NextCursor string
	HasMore    bool
}

// ApplicationUpdate carries the merged target values for an application
// PATCH. All fields are applied together; the caller validates them
// beforehand.
type ApplicationUpdate struct {
	Name        string
	Description string
	Audience    ApplicationAudience
	OwnerID     identity.UserID
}

// ApplicationPatch is the partial-update input. Nil pointers mean "not
// submitted"; submitted values replace the stored ones.
type ApplicationPatch struct {
	Name        *string
	Description *string
	Audience    *ApplicationAudience
	OwnerID     *identity.UserID
}

// ClientPatch is the partial-update input for an OAuth client. Nil pointers
// mean "not submitted"; submitted values replace the stored ones. Profile is
// immutable and never part of a patch. RedirectURIs and AllowedScopes
// replace the stored sets wholesale when present.
type ClientPatch struct {
	Name          *string
	RedirectURIs  *[]string
	LogoutURI     *string
	AllowedScopes *[]string
	ConsentMode   *ConsentMode
}

// ClientConfigUpdate carries the merged mutable client settings for a PATCH.
// RedirectURIs and Scopes replace the stored sets wholesale when non-nil;
// profile is immutable and never part of an update.
type ClientConfigUpdate struct {
	Name         string
	LogoutURI    string
	ConsentMode  ConsentMode
	RedirectURIs []RedirectURI
	Scopes       []string
}

// AuditEntry is the detail-view projection of a recorded security event.
// ActorName is derived display text joined server-side; it is never used for
// authorization decisions.
type AuditEntry struct {
	EventID    SecurityEventID
	EventType  string
	ActorName  string
	OccurredAt time.Time
	Result     SecurityEventResult
}
