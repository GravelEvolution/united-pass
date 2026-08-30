package adminroles

import (
	"context"

	"github.com/GravelEvolution/united-pass/backend/internal/adminpagination"
)

type EventRegistry interface {
	GetExact(context.Context, string) (RegisteredEvent, error)
	ListEnabled(context.Context, adminpagination.Query) (adminpagination.Page[RegisteredEvent], error)
	PutExact(context.Context, RegisteredEvent, MutationAudit) (RegisteredEvent, error)
	SetEnabled(context.Context, string, bool, int64, MutationAudit) (RegisteredEvent, error)
}
