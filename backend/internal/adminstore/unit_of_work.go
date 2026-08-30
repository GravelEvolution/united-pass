package adminstore

import (
	"context"

	"github.com/GravelEvolution/united-pass/backend/internal/adminroles"
	"github.com/GravelEvolution/united-pass/backend/internal/adminstepup"
	"github.com/GravelEvolution/united-pass/backend/internal/applications"
	"github.com/GravelEvolution/united-pass/backend/internal/identityaccess"
)

type SecurityEventStore interface {
	Record(context.Context, applications.SecurityEvent) error
}

type Repositories struct {
	Roles             adminroles.Repository
	EventRegistry     adminroles.EventRegistry
	Challenges        adminstepup.Repository
	SecurityEpoch     adminstepup.SecurityEpochRepository
	IdentityAccess    identityaccess.Repository
	Reasons           ProtectedReasonRepository
	Outbox            OutboxRepository
	OperatorApprovals OperatorApprovalRepository
	SecurityEvents    SecurityEventStore
}

type UnitOfWork interface {
	Within(context.Context, func(Repositories) error) error
}
