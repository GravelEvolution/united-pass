// Package identityaccess defines the OA-style restricted identity access
// workflow. It intentionally models only opaque targets and fixed fields.
package identityaccess

import (
	"context"
	"errors"
	"time"

	"github.com/GravelEvolution/united-pass/backend/internal/adminpagination"
	"github.com/GravelEvolution/united-pass/backend/internal/identity"
)

type TargetType string

const (
	TargetApplication TargetType = "application"
	TargetCheckIn     TargetType = "check_in"
)

type Field string

const (
	FieldLegalName      Field = "legal_name"
	FieldIdentityNumber Field = "identity_number"
	FieldIdentityPhoto  Field = "identity_photo"
	FieldContactEmail   Field = "contact_email"
	FieldContactMobile  Field = "contact_mobile"
)

type Status string

const (
	ListKindOwn           = "identity_access_own"
	ListKindApprovalQueue = "identity_access_approval_queue"
)

const (
	StatusPending  Status = "pending"
	StatusApproved Status = "approved"
	StatusRejected Status = "rejected"
	StatusRevoked  Status = "revoked"
	StatusExpired  Status = "expired"
)

var (
	ErrInvalidRequest        = errors.New("identityaccess: invalid request")
	ErrInvalidDecision       = errors.New("identityaccess: invalid decision")
	ErrNotFound              = errors.New("identityaccess: not found")
	ErrConflict              = errors.New("identityaccess: conflict")
	ErrForbidden             = errors.New("identityaccess: forbidden")
	ErrInvalidReason         = errors.New("identityaccess: invalid reason")
	ErrInvalidIdempotencyKey = errors.New("identityaccess: globally random idempotency key required")
	ErrIfMatchRequired       = errors.New("identityaccess: If-Match version required")
	ErrIdempotencyConflict   = errors.New("identityaccess: idempotency conflict")
	ErrInvalidStoredResult   = errors.New("identityaccess: invalid stored receipt result")
	ErrStepUpRequired        = errors.New("identityaccess: fresh administrator step-up required")
)

type Request struct {
	ID            string
	EventID       string
	RequesterID   identity.UserID
	TargetSubject identity.UserID
	ApproverID    identity.UserID
	TargetType    TargetType
	TargetID      string
	Fields        []Field
	Status        Status
	ReasonID      string
	Version       int64
	CreatedAt     time.Time
	UpdatedAt     time.Time
	ExpiresAt     time.Time
	TerminalAt    *time.Time
}

type ProtectedReason struct {
	ID         string
	OwnerID    identity.UserID
	KeyID      string
	Nonce      []byte
	Ciphertext []byte
	ExpiresAt  *time.Time
	PurgedAt   *time.Time
	CreatedAt  time.Time
}

type Decision struct {
	ApproverID identity.UserID
	Approved   bool
	RequestID  string
	DecidedAt  time.Time
}

type GrantStatus string

const (
	GrantActive  GrantStatus = "active"
	GrantClaimed GrantStatus = "claimed"
	GrantSettled GrantStatus = "settled"
	GrantRevoked GrantStatus = "revoked"
	GrantExpired GrantStatus = "expired"
)

type GrantAuthorization struct {
	RoleBindingID      string
	RoleBindingVersion int64
	ChallengeVersion   int64
	FieldSetHash       string
}

type Audit struct {
	ActorID   identity.UserID
	ReasonID  string
	RequestID string
	Action    string
}

type Grant struct {
	ID            string
	RequestID     string
	EventID       string
	RequesterID   identity.UserID
	TargetSubject identity.UserID
	TargetType    TargetType
	TargetID      string
	ApprovedBy    identity.UserID
	Fields        []Field
	Status        GrantStatus
	Authorization GrantAuthorization
	ExpiresAt     time.Time
	Version       int64
	TerminalAt    *time.Time
}

type Claim struct {
	GrantID            string
	EventID            string
	RequesterID        identity.UserID
	TargetSubject      identity.UserID
	TargetType         TargetType
	TargetID           string
	Fields             []Field
	FieldSetHash       string
	RoleBindingID      string
	RoleBindingVersion int64
	ChallengeVersion   int64
	ClaimNonce         string
	LeaseExpiresAt     time.Time
	Version            int64
}

type DecisionOutcome struct {
	Request Request
	Grant   *Grant
}

type Page = adminpagination.Page[Request]

func ValidateRequest(request Request) error {
	if request.EventID == "" || request.RequesterID == "" || request.TargetSubject == "" || request.RequesterID == request.TargetSubject || request.TargetID == "" || len(request.Fields) == 0 {
		return ErrInvalidRequest
	}
	if request.TargetType != TargetApplication && request.TargetType != TargetCheckIn {
		return ErrInvalidRequest
	}
	seen := make(map[Field]struct{}, len(request.Fields))
	for _, field := range request.Fields {
		switch field {
		case FieldLegalName, FieldIdentityNumber, FieldIdentityPhoto, FieldContactEmail, FieldContactMobile:
		default:
			return ErrInvalidRequest
		}
		if _, exists := seen[field]; exists {
			return ErrInvalidRequest
		}
		seen[field] = struct{}{}
	}
	return nil
}

func ValidateDecision(request Request, decision Decision) error {
	if decision.ApproverID == "" || decision.ApproverID == request.RequesterID || decision.ApproverID == request.TargetSubject {
		return ErrInvalidDecision
	}
	return nil
}

func ValidateDecisionAudit(decision Decision, audit Audit) error {
	if audit.ActorID == "" || audit.ActorID != decision.ApproverID || audit.ReasonID == "" || audit.RequestID == "" || audit.Action == "" {
		return ErrInvalidDecision
	}
	return nil
}

func ValidateOwnListQuery(query adminpagination.Query) error {
	return validateListQuery(query, ListKindOwn)
}

func ValidateApprovalListQuery(query adminpagination.Query) error {
	return validateListQuery(query, ListKindApprovalQueue)
}

func validateListQuery(query adminpagination.Query, listKind string) error {
	if query.ScopeKind != "event" || query.EventID == "" || query.ListKind != listKind {
		return ErrInvalidRequest
	}
	return nil
}

type Repository interface {
	CreateRequest(context.Context, Request, ProtectedReason, Audit) (Request, error)
	GetRequest(context.Context, string, string) (Request, error)
	ListOwn(context.Context, identity.UserID, adminpagination.Query) (Page, error)
	ListApprovalQueue(context.Context, adminpagination.Query) (Page, error)
	Decide(context.Context, string, string, int64, Decision, []Field, GrantAuthorization, Audit) (DecisionOutcome, error)
	Claim(context.Context, string, string, identity.UserID, int64, AuthorizationEvidence, time.Time, Audit) (Claim, error)
	Settle(context.Context, string, string, identity.UserID, int64, string, string, AuthorizationEvidence, time.Time, Audit) (int64, error)
	ReleaseExpiredClaim(context.Context, string, string, int64, Audit) error
	RevokeForUser(context.Context, identity.UserID, Audit) error
}
