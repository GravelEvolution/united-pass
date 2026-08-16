//
// Copyright (c) 2026 Chen Jiajie(Ariakage)
//
// Author: Chen Jiajie(Ariakage) <ariakage233@gmail.com>
// Date: 2026-08-16
// Description: Permission-scoped administration dashboard snapshot contract
//

// Package dashboard defines the read model used by the administration
// overview. It contains only aggregate counts and already-redacted audit
// events; authorization remains the HTTP use-case boundary's responsibility.
package dashboard

import (
	"context"

	"github.com/GravelEvolution/united-pass/backend/internal/audit"
)

// Access selects which independently-authorized aggregates a repository may
// read. A false field must not be treated as permission to query that domain.
type Access struct {
	Users        bool
	Applications bool
	Audit        bool
}

type Snapshot struct {
	ActiveUsers          int64
	PendingUsers         int64
	ActiveEmployees      int64
	OffboardingEmployees int64
	Applications         int64
	ActiveApplications   int64
	DeniedEvents30Days   int64
	RecentEvents         []audit.Event
}

type Repository interface {
	Load(context.Context, Access) (Snapshot, error)
}
