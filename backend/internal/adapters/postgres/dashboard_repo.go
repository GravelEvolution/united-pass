//
// Copyright (c) 2026 Chen Jiajie(Ariakage)
//
// Author: Chen Jiajie(Ariakage) <ariakage233@gmail.com>
// Date: 2026-08-16
// Description: PostgreSQL administration dashboard read model
//

package postgres

import (
	"context"
	"fmt"

	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/GravelEvolution/united-pass/backend/internal/audit"
	"github.com/GravelEvolution/united-pass/backend/internal/dashboard"
)

type DashboardRepository struct {
	pool  *pgxpool.Pool
	audit *AuditRepository
}

func NewDashboardRepository(pool *pgxpool.Pool) *DashboardRepository {
	return &DashboardRepository{pool: pool, audit: NewAuditRepository(pool)}
}

func (r *DashboardRepository) Load(ctx context.Context, access dashboard.Access) (dashboard.Snapshot, error) {
	var snapshot dashboard.Snapshot
	if access.Users {
		if err := r.pool.QueryRow(ctx, `
			SELECT COUNT(*) FILTER (WHERE status='active'),
			       COUNT(*) FILTER (WHERE status='pending')
			  FROM users`).Scan(&snapshot.ActiveUsers, &snapshot.PendingUsers); err != nil {
			return dashboard.Snapshot{}, fmt.Errorf("postgres: dashboard user counts: %w", err)
		}
		if err := r.pool.QueryRow(ctx, `
			SELECT COUNT(*) FILTER (WHERE status='active'),
			       COUNT(*) FILTER (WHERE status='offboarding')
			  FROM employee_profiles`).Scan(&snapshot.ActiveEmployees, &snapshot.OffboardingEmployees); err != nil {
			return dashboard.Snapshot{}, fmt.Errorf("postgres: dashboard employee counts: %w", err)
		}
	}
	if access.Applications {
		if err := r.pool.QueryRow(ctx, `
			SELECT COUNT(*) FILTER (
			           WHERE deleted_at IS NULL AND provisioning_status='provisioned'),
			       COUNT(*) FILTER (
			           WHERE deleted_at IS NULL AND provisioning_status='provisioned' AND status='active')
			  FROM oauth_applications`).Scan(&snapshot.Applications, &snapshot.ActiveApplications); err != nil {
			return dashboard.Snapshot{}, fmt.Errorf("postgres: dashboard application counts: %w", err)
		}
	}
	if access.Audit {
		if err := r.pool.QueryRow(ctx, `
			SELECT COUNT(*)
			  FROM security_events
			 WHERE result='denied' AND occurred_at >= NOW()-INTERVAL '30 days'`).Scan(&snapshot.DeniedEvents30Days); err != nil {
			return dashboard.Snapshot{}, fmt.Errorf("postgres: dashboard denied event count: %w", err)
		}
		page, err := r.audit.List(ctx, audit.Query{Limit: 3})
		if err != nil {
			return dashboard.Snapshot{}, fmt.Errorf("postgres: dashboard recent events: %w", err)
		}
		snapshot.RecentEvents = page.Items
	}
	if snapshot.RecentEvents == nil {
		snapshot.RecentEvents = []audit.Event{}
	}
	return snapshot, nil
}
