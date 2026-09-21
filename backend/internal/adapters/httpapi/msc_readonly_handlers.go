package httpapi

import (
	"context"
	"errors"
	"log/slog"
	"net/http"
	"time"

	"github.com/GravelEvolution/united-pass/backend/internal/adapters/httpapi/request"
	"github.com/GravelEvolution/united-pass/backend/internal/audit"
	"github.com/GravelEvolution/united-pass/backend/internal/identity"
	"github.com/GravelEvolution/united-pass/backend/internal/mscaccess"
	"github.com/GravelEvolution/united-pass/backend/internal/platform/observability"
	"github.com/GravelEvolution/united-pass/backend/internal/workforce"
)

type MSCWorkforceSource interface {
	ListUsers(ctx context.Context, query workforce.UserListQuery) (workforce.CursorPage[workforce.UserSummary], error)
	GetUserDetail(ctx context.Context, userID identity.UserID) (workforce.UserDetail, error)
	ListEmployees(ctx context.Context, query workforce.EmployeeListQuery) (workforce.CursorPage[workforce.EmployeeSummary], error)
	ListDepartments(ctx context.Context, query string, limit int) ([]workforce.DepartmentSummary, error)
	GetDepartment(ctx context.Context, departmentID workforce.DepartmentID) (workforce.DepartmentDetail, error)
}

type MSCAuditSource interface {
	List(ctx context.Context, query audit.Query) (audit.Page, error)
}

type MSCReadonlyHandlers struct {
	verifier  *mscaccess.Verifier
	workforce MSCWorkforceSource
	audit     MSCAuditSource
	logger    *slog.Logger
}

func NewMSCReadonlyHandlers(verifier *mscaccess.Verifier, workforceSource MSCWorkforceSource,
	auditSource MSCAuditSource, logger *slog.Logger,
) *MSCReadonlyHandlers {
	return &MSCReadonlyHandlers{verifier: verifier, workforce: workforceSource, audit: auditSource, logger: logger}
}

func (h *MSCReadonlyHandlers) authorize(w http.ResponseWriter, r *http.Request, capability string) bool {
	if h.verifier == nil || h.workforce == nil {
		WriteNotFound(w, r)
		return false
	}
	if _, err := h.verifier.Verify(r, capability, nil); err != nil {
		writeError(w, r, http.StatusUnauthorized, CodeUnauthorized, "未授权。", nil)
		return false
	}
	return true
}

func (h *MSCReadonlyHandlers) writeSourceError(w http.ResponseWriter, r *http.Request, err error) {
	switch {
	case errors.Is(err, workforce.ErrInvalidCursor):
		WriteBadRequest(w, r, "cursor 无效或与当前筛选条件不匹配。")
	case errors.Is(err, workforce.ErrInvalidInput), errors.Is(err, audit.ErrValidation):
		WriteBadRequest(w, r, "请求参数校验失败。")
	case errors.Is(err, workforce.ErrNotFound):
		WriteNotFound(w, r)
	default:
		if h.logger != nil {
			h.logger.Error("msc read-only query failed",
				"requestId", request.ID(r.Context()),
				"errorClass", observability.ClassifyError(err),
				"errorDetail", observability.RedactedError(err, 256))
		}
		WriteInternalError(w, r)
	}
}

func (h *MSCReadonlyHandlers) ListUsers(w http.ResponseWriter, r *http.Request) {
	if !h.authorize(w, r, mscaccess.CapabilityUserRead) {
		return
	}
	query, ok := parseUserListQuery(w, r)
	if !ok {
		return
	}
	page, err := h.workforce.ListUsers(r.Context(), query)
	if err != nil {
		h.writeSourceError(w, r, err)
		return
	}
	items := make([]managedUserResponse, 0, len(page.Items))
	for _, item := range page.Items {
		items = append(items, managedUserResponse{
			UserID: string(item.UserID), DisplayName: item.DisplayName, Email: item.Email,
			PersonaLabel: item.PersonaLabel, Status: string(item.Status), LastActiveAt: item.LastActiveAt,
		})
	}
	writeJSONNoStore(w, r, http.StatusOK, cursorResponse[managedUserResponse]{
		Items: items, Page: cursorPageResponse{NextCursor: nullableString(page.NextCursor), HasMore: page.HasMore},
	})
}

type mscUserDetailResponse struct {
	UserID          string                          `json:"userId"`
	DisplayName     string                          `json:"displayName"`
	Email           string                          `json:"email"`
	PersonaLabel    string                          `json:"personaLabel"`
	Status          string                          `json:"status"`
	LastActiveAt    time.Time                       `json:"lastActiveAt"`
	EmployeeProfile *employeeProfileSummaryResponse `json:"employeeProfile,omitempty"`
}

func (h *MSCReadonlyHandlers) GetUser(w http.ResponseWriter, r *http.Request) {
	if !h.authorize(w, r, mscaccess.CapabilityUserRead) {
		return
	}
	userID, valid := managedUserID(r)
	if !valid {
		WriteNotFound(w, r)
		return
	}
	detail, err := h.workforce.GetUserDetail(r.Context(), userID)
	if err != nil {
		h.writeSourceError(w, r, err)
		return
	}
	response := mscUserDetailResponse{
		UserID: string(detail.User.ID), DisplayName: detail.User.DisplayName,
		Email: detail.User.Email, PersonaLabel: personaDisplayLabel(detail.User.Personas),
		Status: string(detail.User.Status), LastActiveAt: detail.LastActiveAt,
	}
	if detail.EmployeeProfile != nil {
		response.EmployeeProfile = &employeeProfileSummaryResponse{
			EmployeeID:     detail.EmployeeProfile.EmployeeNumber,
			DepartmentName: detail.EmployeeProfile.DepartmentName,
			Title:          detail.EmployeeProfile.Title,
		}
	}
	writeJSONNoStore(w, r, http.StatusOK, response)
}

func (h *MSCReadonlyHandlers) ListEmployees(w http.ResponseWriter, r *http.Request) {
	if !h.authorize(w, r, mscaccess.CapabilityEmployeeRead) {
		return
	}
	query := workforce.EmployeeListQuery{
		Cursor: r.URL.Query().Get("cursor"), Query: r.URL.Query().Get("query"),
		Sort: r.URL.Query().Get("sort"), Status: r.URL.Query().Get("status"),
	}
	if !parseOptionalLimit(w, r, &query.Limit) {
		return
	}
	page, err := h.workforce.ListEmployees(r.Context(), query)
	if err != nil {
		h.writeSourceError(w, r, err)
		return
	}
	items := make([]employeeSummaryResponse, 0, len(page.Items))
	for _, item := range page.Items {
		items = append(items, employeeSummaryResponse{
			UserID: string(item.UserID), DisplayName: item.DisplayName,
			EmployeeID: item.EmployeeNumber, DepartmentName: item.DepartmentName,
			Title: item.Title, Status: string(item.Status),
		})
	}
	writeJSONNoStore(w, r, http.StatusOK, cursorResponse[employeeSummaryResponse]{
		Items: items, Page: cursorPageResponse{NextCursor: nullableString(page.NextCursor), HasMore: page.HasMore},
	})
}

func (h *MSCReadonlyHandlers) ListDepartments(w http.ResponseWriter, r *http.Request) {
	if !h.authorize(w, r, mscaccess.CapabilityDepartmentRead) {
		return
	}
	limit := 0
	if !parseOptionalLimit(w, r, &limit) {
		return
	}
	items, err := h.workforce.ListDepartments(r.Context(), r.URL.Query().Get("query"), limit)
	if err != nil {
		h.writeSourceError(w, r, err)
		return
	}
	responses := make([]departmentSummaryResponse, 0, len(items))
	for _, item := range items {
		responses = append(responses, departmentSummaryResponse{
			DepartmentID: string(item.DepartmentID), Name: item.Name,
			ParentName: item.ParentName, MemberCount: item.MemberCount, OwnerName: item.OwnerName,
		})
	}
	writeJSONNoStore(w, r, http.StatusOK, responses)
}

func (h *MSCReadonlyHandlers) GetDepartment(w http.ResponseWriter, r *http.Request) {
	if !h.authorize(w, r, mscaccess.CapabilityDepartmentRead) {
		return
	}
	departmentID, valid := departmentIDFromPath(r)
	if !valid {
		WriteNotFound(w, r)
		return
	}
	detail, err := h.workforce.GetDepartment(r.Context(), departmentID)
	if err != nil {
		h.writeSourceError(w, r, err)
		return
	}
	writeJSONNoStore(w, r, http.StatusOK, toDepartmentDetailResponse(detail))
}

func (h *MSCReadonlyHandlers) ListAuditEvents(w http.ResponseWriter, r *http.Request) {
	if !h.authorize(w, r, mscaccess.CapabilityAuditRead) {
		return
	}
	if h.audit == nil {
		WriteNotFound(w, r)
		return
	}
	query, err := parseAuditQuery(r)
	if err != nil {
		WriteBadRequest(w, r, "审计筛选参数不正确。")
		return
	}
	page, err := h.audit.List(r.Context(), query)
	if err != nil {
		h.writeSourceError(w, r, err)
		return
	}
	items := make([]auditEventResponse, 0, len(page.Items))
	for _, item := range page.Items {
		items = append(items, auditEventResponse{
			EventID: item.EventID, EventType: item.EventType, ActorName: item.ActorName,
			ActorID: item.ActorID, TargetLabel: item.TargetLabel, TargetID: item.TargetID,
			OccurredAt: item.OccurredAt, Result: item.Result, RequestID: item.RequestID, Details: "",
		})
	}
	writeJSONNoStore(w, r, http.StatusOK, cursorResponse[auditEventResponse]{
		Items: items, Page: cursorPageResponse{NextCursor: nullableString(page.NextCursor), HasMore: page.HasMore},
	})
}
