//
// Copyright (c) 2026 Chen Jiajie(Ariakage)
//
// Author: Chen Jiajie(Ariakage) <ariakage233@gmail.com>
// Date: 2026-08-16
// Description: Permission-scoped administration dashboard HTTP API
//

package httpapi

import (
	"context"
	"net/http"
	"strconv"

	"github.com/GravelEvolution/united-pass/backend/internal/adapters/httpapi/request"
	"github.com/GravelEvolution/united-pass/backend/internal/audit"
	"github.com/GravelEvolution/united-pass/backend/internal/dashboard"
	"github.com/GravelEvolution/united-pass/backend/internal/permissions"
)

type DashboardHandlers struct {
	repository  dashboard.Repository
	permissions permissions.Resolver
	audit       *audit.Service
}

func NewDashboardHandlers(repository dashboard.Repository, resolver permissions.Resolver, auditService *audit.Service) *DashboardHandlers {
	return &DashboardHandlers{repository: repository, permissions: resolver, audit: auditService}
}

type dashboardMetricResponse struct {
	Label  string `json:"label"`
	Value  string `json:"value"`
	Change string `json:"change"`
	Tone   string `json:"tone"`
}

type dashboardResponse struct {
	Metrics      []dashboardMetricResponse `json:"metrics"`
	RecentEvents []audit.Event             `json:"recentEvents"`
}

func hasAdminCapability(caps permissions.Capabilities) bool {
	return caps.UserRead || caps.UserDisable || caps.EmployeeManage || caps.EmployeeOffboard ||
		caps.DepartmentManage || caps.ApplicationRead || caps.ApplicationManage ||
		caps.ApplicationSecretRotate || caps.PolicyRead || caps.PolicyManage ||
		caps.PolicyPublish || caps.AuditRead || caps.AuditExport || caps.ProviderRead ||
		caps.ProviderManage
}

func metricTone(attention bool) string {
	if attention {
		return "attention"
	}
	return "neutral"
}

func formatCount(value int64) string { return strconv.FormatInt(value, 10) }

func (h *DashboardHandlers) Get(w http.ResponseWriter, r *http.Request) {
	principal, ok := PrincipalFromContext(r.Context())
	if !ok {
		WriteUnauthorized(w, r)
		return
	}
	caps, err := h.permissions.Resolve(r.Context(), principal.UserID)
	if err != nil {
		WriteInternalError(w, r)
		return
	}
	if !hasAdminCapability(caps) {
		if h.audit != nil {
			h.audit.RecordAuthorizationDenied(context.WithoutCancel(r.Context()), principal.UserID, "admin.dashboard.read", request.ID(r.Context()))
		}
		WriteForbidden(w, r)
		return
	}
	access := dashboard.Access{
		Users:        caps.UserRead,
		Applications: caps.ApplicationRead,
		Audit:        caps.AuditRead,
	}
	snapshot, err := h.repository.Load(r.Context(), access)
	if err != nil {
		WriteInternalError(w, r)
		return
	}
	recentEvents := snapshot.RecentEvents
	if recentEvents == nil {
		recentEvents = []audit.Event{}
	}
	response := dashboardResponse{
		Metrics:      []dashboardMetricResponse{},
		RecentEvents: recentEvents,
	}
	if access.Users {
		response.Metrics = append(response.Metrics,
			dashboardMetricResponse{Label: "活跃用户", Value: formatCount(snapshot.ActiveUsers), Change: formatCount(snapshot.PendingUsers) + " 个待激活", Tone: metricTone(snapshot.PendingUsers > 0)},
			dashboardMetricResponse{Label: "员工账户", Value: formatCount(snapshot.ActiveEmployees), Change: formatCount(snapshot.OffboardingEmployees) + " 个离职处理中", Tone: metricTone(snapshot.OffboardingEmployees > 0)},
		)
	}
	if access.Applications {
		response.Metrics = append(response.Metrics, dashboardMetricResponse{
			Label: "OAuth 应用", Value: formatCount(snapshot.Applications),
			Change: formatCount(snapshot.ActiveApplications) + " 个处于启用状态", Tone: "neutral",
		})
	}
	if access.Audit {
		response.Metrics = append(response.Metrics, dashboardMetricResponse{
			Label: "拒绝事件（30 天）", Value: formatCount(snapshot.DeniedEvents30Days),
			Change: "来自真实安全审计记录", Tone: metricTone(snapshot.DeniedEvents30Days > 0),
		})
	}
	writeJSONNoStore(w, r, http.StatusOK, response)
}
