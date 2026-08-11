//
// Copyright (c) 2026 Chen Jiajie(Ariakage)
//
// Author: Chen Jiajie(Ariakage) <ariakage233@gmail.com>
// Date: 2026-08-11
// Description: Phase 5 user, employee and department administration handlers
//

package httpapi

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"log/slog"
	"net/http"
	"strconv"
	"time"

	"github.com/go-chi/chi/v5"

	"github.com/GravelEvolution/united-pass/backend/internal/adapters/httpapi/request"
	"github.com/GravelEvolution/united-pass/backend/internal/auth"
	"github.com/GravelEvolution/united-pass/backend/internal/identity"
	"github.com/GravelEvolution/united-pass/backend/internal/permissions"
	"github.com/GravelEvolution/united-pass/backend/internal/platform/observability"
	"github.com/GravelEvolution/united-pass/backend/internal/session"
	"github.com/GravelEvolution/united-pass/backend/internal/workforce"
)

type WorkforceSessionInventory interface {
	ListUserSessions(ctx context.Context, userID identity.UserID) ([]session.SessionRecord, error)
}

type workforceCapability int

const (
	workforceUserRead workforceCapability = iota
	workforceUserDisable
	workforceEmployeeManage
	workforceEmployeeOffboard
	workforceDepartmentManage
)

type WorkforceHandlers struct {
	service     *workforce.Service
	permissions permissions.Resolver
	reauth      ReauthVerifier
	sessions    WorkforceSessionInventory
	logger      *slog.Logger
}

func NewWorkforceHandlers(service *workforce.Service, resolver permissions.Resolver,
	reauth ReauthVerifier, sessions WorkforceSessionInventory, logger *slog.Logger,
) *WorkforceHandlers {
	return &WorkforceHandlers{service: service, permissions: resolver, reauth: reauth, sessions: sessions, logger: logger}
}

func (h *WorkforceHandlers) authorize(w http.ResponseWriter, r *http.Request,
	required workforceCapability, targetKey, targetID, eventType, operation string,
) (session.Principal, bool) {
	principal, ok := PrincipalFromContext(r.Context())
	if !ok {
		WriteUnauthorized(w, r)
		return session.Principal{}, false
	}
	caps, err := h.permissions.Resolve(r.Context(), principal.UserID)
	if err != nil {
		WriteInternalError(w, r)
		return session.Principal{}, false
	}
	granted := false
	switch required {
	case workforceUserRead:
		granted = caps.UserRead
	case workforceUserDisable:
		granted = caps.UserDisable
	case workforceEmployeeManage:
		granted = caps.EmployeeManage
	case workforceEmployeeOffboard:
		granted = caps.EmployeeOffboard
	case workforceDepartmentManage:
		granted = caps.DepartmentManage
	}
	if !granted {
		h.service.RecordAuthorizationDenied(context.WithoutCancel(r.Context()), principal.UserID,
			targetKey, targetID, eventType, operation, request.ID(r.Context()))
		WriteForbidden(w, r)
		return session.Principal{}, false
	}
	return principal, true
}

func (h *WorkforceHandlers) requireTargetReauthentication(w http.ResponseWriter, r *http.Request,
	principal session.Principal, action, target string,
) bool {
	if h.reauth == nil {
		writeError(w, r, http.StatusForbidden, CodeReauthenticationReq, "该操作需要重新认证。", nil)
		return false
	}
	token := r.Header.Get("X-Reauthentication-Token")
	err := h.reauth.VerifyAndConsume(r.Context(), token, action, string(principal.SessionID), target, "", "")
	if err != nil {
		writeError(w, r, http.StatusForbidden, CodeReauthenticationReq, "该操作需要重新认证。", nil)
		return false
	}
	return true
}

func managedUserID(r *http.Request) (identity.UserID, bool) {
	raw := chi.URLParam(r, "userId")
	if raw == "" || len(raw) > 128 {
		return "", false
	}
	for _, value := range raw {
		if !(value >= 'a' && value <= 'z') && !(value >= 'A' && value <= 'Z') &&
			!(value >= '0' && value <= '9') && value != '_' && value != '-' {
			return "", false
		}
	}
	return identity.UserID(raw), true
}

// ---- Users ----

func (h *WorkforceHandlers) ListUsers(w http.ResponseWriter, r *http.Request) {
	if _, ok := h.authorize(w, r, workforceUserRead, "", "", "", "user.list"); !ok {
		return
	}
	query, ok := parseUserListQuery(w, r)
	if !ok {
		return
	}
	page, err := h.service.ListUsers(r.Context(), query)
	if err != nil {
		h.writeWorkforceError(w, r, err)
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

type managedUserResponse struct {
	UserID       string    `json:"userId"`
	DisplayName  string    `json:"displayName"`
	Email        string    `json:"email"`
	PersonaLabel string    `json:"personaLabel"`
	Status       string    `json:"status"`
	LastActiveAt time.Time `json:"lastActiveAt"`
}

type cursorPageResponse struct {
	NextCursor *string `json:"nextCursor"`
	HasMore    bool    `json:"hasMore"`
}

type cursorResponse[T any] struct {
	Items []T                `json:"items"`
	Page  cursorPageResponse `json:"page"`
}

func parseUserListQuery(w http.ResponseWriter, r *http.Request) (workforce.UserListQuery, bool) {
	query := workforce.UserListQuery{
		Cursor: r.URL.Query().Get("cursor"), Query: r.URL.Query().Get("query"),
		Sort: r.URL.Query().Get("sort"), Status: r.URL.Query().Get("status"),
	}
	if !parseOptionalLimit(w, r, &query.Limit) {
		return workforce.UserListQuery{}, false
	}
	return query, true
}

func parseOptionalLimit(w http.ResponseWriter, r *http.Request, destination *int) bool {
	raw := r.URL.Query().Get("limit")
	if raw == "" {
		return true
	}
	value, err := strconv.Atoi(raw)
	if err != nil || value < 1 || value > 100 {
		WriteBadRequest(w, r, "limit 参数必须为 1 至 100 的整数。")
		return false
	}
	*destination = value
	return true
}

func (h *WorkforceHandlers) GetUser(w http.ResponseWriter, r *http.Request) {
	userID, valid := managedUserID(r)
	if !valid {
		WriteNotFound(w, r)
		return
	}
	principal, ok := h.authorize(w, r, workforceUserRead, "user_id", string(userID), "", "user.read")
	if !ok {
		return
	}
	detail, err := h.service.GetUserDetail(r.Context(), userID)
	if err != nil {
		h.writeWorkforceError(w, r, err)
		return
	}
	if h.sessions == nil {
		WriteInternalError(w, r)
		return
	}
	records, err := h.sessions.ListUserSessions(r.Context(), userID)
	if err != nil {
		h.logError(r, "admin session inventory failed", err)
		WriteInternalError(w, r)
		return
	}
	writeJSONNoStore(w, r, http.StatusOK, toUserDetailResponse(detail, records, principal))
}

type adminSessionResponse struct {
	SessionID    string    `json:"sessionId"`
	DeviceName   string    `json:"deviceName"`
	LastActiveAt time.Time `json:"lastActiveAt"`
	IsCurrent    bool      `json:"isCurrent"`
}

type employeeProfileSummaryResponse struct {
	EmployeeID     string `json:"employeeId"`
	DepartmentName string `json:"departmentName"`
	Title          string `json:"title"`
}

type linkedIdentityResponse struct {
	ProviderID      string    `json:"providerId"`
	ProviderName    string    `json:"providerName"`
	ExternalSubject string    `json:"externalSubject"`
	LinkedAt        time.Time `json:"linkedAt"`
}

type userAuthorizationResponse struct {
	ApplicationName string    `json:"applicationName"`
	Scopes          []string  `json:"scopes"`
	GrantedAt       time.Time `json:"grantedAt"`
	Status          string    `json:"status"`
}

type auditEventResponse struct {
	EventID     string    `json:"eventId"`
	EventType   string    `json:"eventType"`
	ActorName   string    `json:"actorName"`
	ActorID     string    `json:"actorId"`
	TargetLabel string    `json:"targetLabel"`
	TargetID    string    `json:"targetId"`
	OccurredAt  time.Time `json:"occurredAt"`
	Result      string    `json:"result"`
	RequestID   string    `json:"requestId"`
	Details     string    `json:"details"`
}

type userDetailResponse struct {
	UserID                 string                          `json:"userId"`
	DisplayName            string                          `json:"displayName"`
	Email                  string                          `json:"email"`
	PhoneMasked            string                          `json:"phoneMasked"`
	PersonaLabel           string                          `json:"personaLabel"`
	Status                 string                          `json:"status"`
	LastActiveAt           time.Time                       `json:"lastActiveAt"`
	Personas               []string                        `json:"personas"`
	EmployeeProfile        *employeeProfileSummaryResponse `json:"employeeProfile,omitempty"`
	LinkedIdentities       []linkedIdentityResponse        `json:"linkedIdentities"`
	ActiveSessions         []adminSessionResponse          `json:"activeSessions"`
	AuthorizedApplications []userAuthorizationResponse     `json:"authorizedApplications"`
	RecentAuditEvents      []auditEventResponse            `json:"recentAuditEvents"`
}

func toUserDetailResponse(detail workforce.UserDetail, records []session.SessionRecord, principal session.Principal) userDetailResponse {
	personas := make([]string, 0, len(detail.User.Personas))
	for _, persona := range detail.User.Personas {
		personas = append(personas, string(persona))
	}
	response := userDetailResponse{
		UserID: string(detail.User.ID), DisplayName: detail.User.DisplayName,
		Email: detail.User.Email, PhoneMasked: identity.MaskPhone(detail.User.Phone),
		PersonaLabel: personaDisplayLabel(detail.User.Personas), Status: string(detail.User.Status),
		LastActiveAt: detail.LastActiveAt, Personas: personas,
		LinkedIdentities:       make([]linkedIdentityResponse, 0, len(detail.LinkedIdentities)),
		ActiveSessions:         make([]adminSessionResponse, 0, len(records)),
		AuthorizedApplications: make([]userAuthorizationResponse, 0, len(detail.AuthorizedApplications)),
		RecentAuditEvents:      make([]auditEventResponse, 0, len(detail.RecentAuditEvents)),
	}
	if detail.EmployeeProfile != nil {
		response.EmployeeProfile = &employeeProfileSummaryResponse{
			EmployeeID:     detail.EmployeeProfile.EmployeeNumber,
			DepartmentName: detail.EmployeeProfile.DepartmentName,
			Title:          detail.EmployeeProfile.Title,
		}
	}
	for _, item := range detail.LinkedIdentities {
		response.LinkedIdentities = append(response.LinkedIdentities, linkedIdentityResponse{
			ProviderID: item.ProviderID, ProviderName: item.ProviderName,
			ExternalSubject: item.ExternalSubject, LinkedAt: item.LinkedAt,
		})
	}
	for _, record := range records {
		response.ActiveSessions = append(response.ActiveSessions, adminSessionResponse{
			SessionID: string(record.SessionID), DeviceName: record.DeviceDisplay,
			LastActiveAt: record.LastSeenAt,
			IsCurrent:    detail.User.ID == principal.UserID && record.SessionID == principal.SessionID,
		})
	}
	for _, item := range detail.AuthorizedApplications {
		response.AuthorizedApplications = append(response.AuthorizedApplications, userAuthorizationResponse(item))
	}
	for _, item := range detail.RecentAuditEvents {
		response.RecentAuditEvents = append(response.RecentAuditEvents, auditEventResponse{
			EventID: item.EventID, EventType: item.EventType, ActorName: item.ActorName,
			ActorID: string(item.ActorID), TargetLabel: detail.User.DisplayName,
			TargetID: item.TargetID, OccurredAt: item.OccurredAt, Result: item.Result,
			RequestID: item.RequestID, Details: "",
		})
	}
	return response
}

func personaDisplayLabel(personas []identity.Persona) string {
	consumer, employee := false, false
	for _, persona := range personas {
		consumer = consumer || persona == identity.PersonaConsumer
		employee = employee || persona == identity.PersonaEmployee
	}
	if consumer && employee {
		return "外部用户 · 员工"
	}
	if employee {
		return "员工"
	}
	return "外部用户"
}

type disableUserRequest struct {
	RevokeSessions bool `json:"revokeSessions"`
}

func (h *WorkforceHandlers) DisableUser(w http.ResponseWriter, r *http.Request) {
	userID, valid := managedUserID(r)
	if !valid {
		WriteNotFound(w, r)
		return
	}
	principal, ok := h.authorize(w, r, workforceUserDisable, "user_id", string(userID),
		workforce.EventUserDisabled, "user.disable")
	if !ok || !h.requireTargetReauthentication(w, r, principal, auth.ReauthActionUserDisable, string(userID)) {
		return
	}
	var body disableUserRequest
	if err := decodeJSONBody(w, r, &body, "disable user"); err != nil {
		return
	}
	pending, err := h.service.ChangeUserStatus(r.Context(), workforce.UserStatusMutation{
		ActorUserID: principal.UserID, TargetUserID: userID,
		Status: identity.UserStatusDisabled, RevokeSessions: body.RevokeSessions,
		RequestID: request.ID(r.Context()),
	})
	if err != nil {
		h.writeWorkforceError(w, r, err)
		return
	}
	if pending {
		writeJSONNoStore(w, r, http.StatusAccepted, map[string]any{"status": "disabled", "sessionCleanupPending": true})
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

func (h *WorkforceHandlers) EnableUser(w http.ResponseWriter, r *http.Request) {
	userID, valid := managedUserID(r)
	if !valid {
		WriteNotFound(w, r)
		return
	}
	principal, ok := h.authorize(w, r, workforceUserDisable, "user_id", string(userID),
		workforce.EventUserEnabled, "user.enable")
	if !ok {
		return
	}
	_, err := h.service.ChangeUserStatus(r.Context(), workforce.UserStatusMutation{
		ActorUserID: principal.UserID, TargetUserID: userID,
		Status: identity.UserStatusActive, RequestID: request.ID(r.Context()),
	})
	if err != nil {
		h.writeWorkforceError(w, r, err)
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

func (h *WorkforceHandlers) RevokeUserSession(w http.ResponseWriter, r *http.Request) {
	userID, valid := managedUserID(r)
	sessionID := chi.URLParam(r, "sessionId")
	if !valid || sessionID == "" || len(sessionID) > 128 {
		WriteNotFound(w, r)
		return
	}
	principal, ok := h.authorize(w, r, workforceUserDisable, "user_id", string(userID),
		workforce.EventUserSessionRevoked, "user.session.revoke")
	if !ok {
		return
	}
	if err := h.service.RevokeUserSession(r.Context(), principal.UserID, userID, sessionID, request.ID(r.Context())); err != nil {
		h.writeWorkforceError(w, r, err)
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

func (h *WorkforceHandlers) RevokeUserSessions(w http.ResponseWriter, r *http.Request) {
	userID, valid := managedUserID(r)
	if !valid {
		WriteNotFound(w, r)
		return
	}
	principal, ok := h.authorize(w, r, workforceUserDisable, "user_id", string(userID),
		workforce.EventUserSessionsRevokeRequested, "user.sessions.revoke")
	if !ok || !h.requireTargetReauthentication(w, r, principal, auth.ReauthActionUserSessionsRevoke, string(userID)) {
		return
	}
	if err := h.service.RevokeUserSessions(r.Context(), principal.UserID, userID, request.ID(r.Context())); err != nil {
		h.writeWorkforceError(w, r, err)
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

// ---- Employees ----

func (h *WorkforceHandlers) ListEmployees(w http.ResponseWriter, r *http.Request) {
	if _, ok := h.authorize(w, r, workforceUserRead, "", "", "", "employee.list"); !ok {
		return
	}
	query := workforce.EmployeeListQuery{
		Cursor: r.URL.Query().Get("cursor"), Query: r.URL.Query().Get("query"),
		Sort: r.URL.Query().Get("sort"), Status: r.URL.Query().Get("status"),
	}
	if !parseOptionalLimit(w, r, &query.Limit) {
		return
	}
	page, err := h.service.ListEmployees(r.Context(), query)
	if err != nil {
		h.writeWorkforceError(w, r, err)
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

type employeeSummaryResponse struct {
	UserID         string `json:"userId"`
	DisplayName    string `json:"displayName"`
	EmployeeID     string `json:"employeeId"`
	DepartmentName string `json:"departmentName"`
	Title          string `json:"title"`
	Status         string `json:"status"`
}

type employeeProfileRequest struct {
	UserID           string `json:"userId"`
	DepartmentID     string `json:"departmentId"`
	Title            string `json:"title"`
	SupervisorUserID string `json:"supervisorUserId"`
}

func (h *WorkforceHandlers) LinkEmployee(w http.ResponseWriter, r *http.Request) {
	principal, ok := h.authorize(w, r, workforceEmployeeManage, "", "",
		workforce.EventEmployeeLinked, "employee.link")
	if !ok {
		return
	}
	var body employeeProfileRequest
	if err := decodeJSONBody(w, r, &body, "link employee"); err != nil {
		return
	}
	profile, err := h.service.LinkEmployee(r.Context(), principal.UserID, workforce.EmployeeProfileInput{
		UserID: identity.UserID(body.UserID), DepartmentID: workforce.DepartmentID(body.DepartmentID),
		Title: body.Title, SupervisorUserID: identity.UserID(body.SupervisorUserID),
	}, request.ID(r.Context()))
	if err != nil {
		h.writeWorkforceError(w, r, err)
		return
	}
	writeJSONNoStore(w, r, http.StatusCreated, toEmployeeMutationResponse(profile))
}

func (h *WorkforceHandlers) GetEmployee(w http.ResponseWriter, r *http.Request) {
	userID, valid := managedUserID(r)
	if !valid {
		WriteNotFound(w, r)
		return
	}
	if _, ok := h.authorize(w, r, workforceUserRead, "employee_user_id", string(userID), "", "employee.read"); !ok {
		return
	}
	detail, err := h.service.GetUserDetail(r.Context(), userID)
	if err != nil {
		h.writeWorkforceError(w, r, err)
		return
	}
	if detail.EmployeeProfile == nil {
		WriteNotFound(w, r)
		return
	}
	consumer := false
	for _, persona := range detail.User.Personas {
		consumer = consumer || persona == identity.PersonaConsumer
	}
	writeJSONNoStore(w, r, http.StatusOK,
		toEmployeeProfileResponse(*detail.EmployeeProfile, detail.User.DisplayName, detail.User.Email, consumer))
}

func (h *WorkforceHandlers) UpdateEmployee(w http.ResponseWriter, r *http.Request) {
	userID, valid := managedUserID(r)
	if !valid {
		WriteNotFound(w, r)
		return
	}
	principal, ok := h.authorize(w, r, workforceEmployeeManage, "employee_user_id", string(userID),
		workforce.EventEmployeeUpdated, "employee.update")
	if !ok {
		return
	}
	var body employeeProfileRequest
	if err := decodeJSONBody(w, r, &body, "update employee"); err != nil {
		return
	}
	profile, err := h.service.UpdateEmployee(r.Context(), principal.UserID, workforce.EmployeeProfileInput{
		UserID: userID, DepartmentID: workforce.DepartmentID(body.DepartmentID),
		Title: body.Title, SupervisorUserID: identity.UserID(body.SupervisorUserID),
	}, request.ID(r.Context()))
	if err != nil {
		h.writeWorkforceError(w, r, err)
		return
	}
	writeJSONNoStore(w, r, http.StatusOK, toEmployeeMutationResponse(profile))
}

type employeeDetailResponse struct {
	UserID                string    `json:"userId"`
	DisplayName           string    `json:"displayName"`
	Email                 string    `json:"email"`
	EmployeeID            string    `json:"employeeId"`
	DepartmentName        string    `json:"departmentName"`
	DepartmentID          string    `json:"departmentId"`
	Title                 string    `json:"title"`
	Status                string    `json:"status"`
	SupervisorUserID      *string   `json:"supervisorUserId"`
	SupervisorName        *string   `json:"supervisorName"`
	OnboardedAt           time.Time `json:"onboardedAt"`
	LinkedConsumerAccount bool      `json:"linkedConsumerAccount"`
}

type employeeMutationResponse struct {
	UserID         string    `json:"userId"`
	EmployeeID     string    `json:"employeeId"`
	DepartmentName string    `json:"departmentName"`
	DepartmentID   string    `json:"departmentId"`
	Title          string    `json:"title"`
	Status         string    `json:"status"`
	SupervisorName *string   `json:"supervisorName"`
	OnboardedAt    time.Time `json:"onboardedAt"`
}

func toEmployeeMutationResponse(profile workforce.EmployeeProfile) employeeMutationResponse {
	return employeeMutationResponse{
		UserID: string(profile.UserID), EmployeeID: profile.EmployeeNumber,
		DepartmentName: profile.DepartmentName, DepartmentID: string(profile.DepartmentID),
		Title: profile.Title, Status: string(profile.Status),
		SupervisorName: nullableString(profile.SupervisorName), OnboardedAt: profile.OnboardedAt,
	}
}

func toEmployeeProfileResponse(profile workforce.EmployeeProfile, displayName, email string, consumer bool) employeeDetailResponse {
	return employeeDetailResponse{
		UserID: string(profile.UserID), DisplayName: displayName, Email: email,
		EmployeeID: profile.EmployeeNumber, DepartmentName: profile.DepartmentName,
		DepartmentID: string(profile.DepartmentID), Title: profile.Title,
		Status: string(profile.Status), SupervisorName: nullableString(profile.SupervisorName),
		SupervisorUserID: nullableString(string(profile.SupervisorUserID)),
		OnboardedAt:      profile.OnboardedAt, LinkedConsumerAccount: consumer,
	}
}

func (h *WorkforceHandlers) OffboardEmployee(w http.ResponseWriter, r *http.Request) {
	userID, valid := managedUserID(r)
	if !valid {
		WriteNotFound(w, r)
		return
	}
	principal, ok := h.authorize(w, r, workforceEmployeeOffboard, "employee_user_id", string(userID),
		workforce.EventEmployeeOffboarded, "employee.offboard")
	if !ok || !h.requireTargetReauthentication(w, r, principal, auth.ReauthActionEmployeeOffboard, string(userID)) {
		return
	}
	result, err := h.service.OffboardEmployee(r.Context(), principal.UserID, userID, request.ID(r.Context()))
	if err != nil {
		h.writeWorkforceError(w, r, err)
		return
	}
	writeJSONNoStore(w, r, http.StatusAccepted, map[string]any{
		"status": string(result.Status), "sessionCleanupPending": result.CleanupPending,
	})
}

// ---- Departments ----

func (h *WorkforceHandlers) ListDepartments(w http.ResponseWriter, r *http.Request) {
	if _, ok := h.authorize(w, r, workforceUserRead, "", "", "", "department.list"); !ok {
		return
	}
	limit := 0
	if !parseOptionalLimit(w, r, &limit) {
		return
	}
	items, err := h.service.ListDepartments(r.Context(), r.URL.Query().Get("query"), limit)
	if err != nil {
		h.writeWorkforceError(w, r, err)
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

type departmentSummaryResponse struct {
	DepartmentID string `json:"departmentId"`
	Name         string `json:"name"`
	ParentName   string `json:"parentName"`
	MemberCount  int    `json:"memberCount"`
	OwnerName    string `json:"ownerName"`
}

func departmentIDFromPath(r *http.Request) (workforce.DepartmentID, bool) {
	raw := chi.URLParam(r, "departmentId")
	return workforce.DepartmentID(raw), workforce.HasDepartmentIDPrefix(raw) && len(raw) <= 128
}

func (h *WorkforceHandlers) GetDepartment(w http.ResponseWriter, r *http.Request) {
	departmentID, valid := departmentIDFromPath(r)
	if !valid {
		WriteNotFound(w, r)
		return
	}
	if _, ok := h.authorize(w, r, workforceUserRead, "department_id", string(departmentID), "", "department.read"); !ok {
		return
	}
	detail, err := h.service.GetDepartment(r.Context(), departmentID)
	if err != nil {
		h.writeWorkforceError(w, r, err)
		return
	}
	writeJSONNoStore(w, r, http.StatusOK, toDepartmentDetailResponse(detail))
}

type departmentMutationRequest struct {
	Name               string `json:"name"`
	ParentDepartmentID string `json:"parentDepartmentId"`
	OwnerUserID        string `json:"ownerUserId"`
}

func (h *WorkforceHandlers) CreateDepartment(w http.ResponseWriter, r *http.Request) {
	principal, ok := h.authorize(w, r, workforceDepartmentManage, "", "",
		workforce.EventDepartmentCreated, "department.create")
	if !ok {
		return
	}
	var body departmentMutationRequest
	if err := decodeJSONBody(w, r, &body, "create department"); err != nil {
		return
	}
	detail, err := h.service.CreateDepartment(r.Context(), principal.UserID, workforce.DepartmentInput{
		Name: body.Name, ParentDepartmentID: workforce.DepartmentID(body.ParentDepartmentID),
		OwnerUserID: identity.UserID(body.OwnerUserID),
	}, request.ID(r.Context()))
	if err != nil {
		h.writeWorkforceError(w, r, err)
		return
	}
	writeJSONNoStore(w, r, http.StatusCreated, toDepartmentDetailResponse(detail))
}

type optionalNullableString struct {
	Set   bool
	Value string
}

func (value *optionalNullableString) UnmarshalJSON(raw []byte) error {
	value.Set = true
	if bytes.Equal(bytes.TrimSpace(raw), []byte("null")) {
		value.Value = ""
		return nil
	}
	return json.Unmarshal(raw, &value.Value)
}

type departmentPatchRequest struct {
	Name               *string                `json:"name"`
	ParentDepartmentID optionalNullableString `json:"parentDepartmentId"`
	OwnerUserID        optionalNullableString `json:"ownerUserId"`
}

func (h *WorkforceHandlers) UpdateDepartment(w http.ResponseWriter, r *http.Request) {
	departmentID, valid := departmentIDFromPath(r)
	if !valid {
		WriteNotFound(w, r)
		return
	}
	principal, ok := h.authorize(w, r, workforceDepartmentManage, "department_id", string(departmentID),
		workforce.EventDepartmentUpdated, "department.update")
	if !ok {
		return
	}
	var body departmentPatchRequest
	if err := decodeJSONBody(w, r, &body, "update department"); err != nil {
		return
	}
	patch := workforce.DepartmentPatch{Name: body.Name}
	if body.ParentDepartmentID.Set {
		value := workforce.DepartmentID(body.ParentDepartmentID.Value)
		patch.ParentDepartmentID = &value
	}
	if body.OwnerUserID.Set {
		value := identity.UserID(body.OwnerUserID.Value)
		patch.OwnerUserID = &value
	}
	detail, err := h.service.UpdateDepartment(r.Context(), principal.UserID, departmentID, patch, request.ID(r.Context()))
	if err != nil {
		h.writeWorkforceError(w, r, err)
		return
	}
	writeJSONNoStore(w, r, http.StatusOK, toDepartmentDetailResponse(detail))
}

func (h *WorkforceHandlers) DeleteDepartment(w http.ResponseWriter, r *http.Request) {
	departmentID, valid := departmentIDFromPath(r)
	if !valid {
		WriteNotFound(w, r)
		return
	}
	principal, ok := h.authorize(w, r, workforceDepartmentManage, "department_id", string(departmentID),
		workforce.EventDepartmentDeleted, "department.delete")
	if !ok {
		return
	}
	if err := h.service.DeleteDepartment(r.Context(), principal.UserID, departmentID, request.ID(r.Context())); err != nil {
		h.writeWorkforceError(w, r, err)
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

type departmentDetailResponse struct {
	DepartmentID       string                     `json:"departmentId"`
	Name               string                     `json:"name"`
	ParentDepartmentID *string                    `json:"parentDepartmentId"`
	ParentName         *string                    `json:"parentName"`
	OwnerUserID        *string                    `json:"ownerUserId"`
	OwnerName          string                     `json:"ownerName"`
	MemberCount        int                        `json:"memberCount"`
	ChildDepartments   []departmentChildResponse  `json:"childDepartments"`
	Members            []departmentMemberResponse `json:"members"`
}

type departmentChildResponse struct {
	DepartmentID string `json:"departmentId"`
	Name         string `json:"name"`
	MemberCount  int    `json:"memberCount"`
}

type departmentMemberResponse struct {
	UserID      string `json:"userId"`
	DisplayName string `json:"displayName"`
	Title       string `json:"title"`
	EmployeeID  string `json:"employeeId"`
}

func toDepartmentDetailResponse(detail workforce.DepartmentDetail) departmentDetailResponse {
	response := departmentDetailResponse{
		DepartmentID: string(detail.DepartmentID), Name: detail.Name,
		ParentDepartmentID: nullableString(string(detail.ParentDepartmentID)),
		ParentName:         nullableString(detail.ParentName),
		OwnerUserID:        nullableString(string(detail.OwnerUserID)), OwnerName: detail.OwnerName,
		MemberCount:      detail.MemberCount,
		ChildDepartments: make([]departmentChildResponse, 0, len(detail.ChildDepartments)),
		Members:          make([]departmentMemberResponse, 0, len(detail.Members)),
	}
	for _, child := range detail.ChildDepartments {
		response.ChildDepartments = append(response.ChildDepartments, departmentChildResponse{
			DepartmentID: string(child.DepartmentID), Name: child.Name, MemberCount: child.MemberCount,
		})
	}
	for _, member := range detail.Members {
		response.Members = append(response.Members, departmentMemberResponse{
			UserID: string(member.UserID), DisplayName: member.DisplayName,
			Title: member.Title, EmployeeID: member.EmployeeNumber,
		})
	}
	return response
}

func (h *WorkforceHandlers) writeWorkforceError(w http.ResponseWriter, r *http.Request, err error) {
	switch {
	case errors.Is(err, workforce.ErrInvalidCursor):
		WriteBadRequest(w, r, "cursor 无效或与当前筛选条件不匹配。")
	case errors.Is(err, workforce.ErrInvalidInput):
		WriteValidation(w, r, "请求参数校验失败。", nil)
	case errors.Is(err, workforce.ErrNotFound), errors.Is(err, session.ErrSessionNotFound):
		WriteNotFound(w, r)
	case errors.Is(err, workforce.ErrConflict):
		writeError(w, r, http.StatusConflict, CodeConflict, "资源状态已变化，请刷新后重试。", nil)
	case errors.Is(err, workforce.ErrDepartmentCycle):
		writeError(w, r, http.StatusConflict, CodeConflict, "部门层级不能形成循环。", nil)
	case errors.Is(err, workforce.ErrDepartmentNotEmpty):
		writeError(w, r, http.StatusConflict, CodeConflict, "仅可删除没有成员和子部门的空部门。", nil)
	case errors.Is(err, workforce.ErrEmployeeNotActive):
		writeError(w, r, http.StatusConflict, CodeConflict, "员工已进入离职流程，不能继续修改。", nil)
	case errors.Is(err, workforce.ErrSupervisorNotActive):
		WriteValidation(w, r, "主管或负责人必须是有效在职员工。", nil)
	case errors.Is(err, workforce.ErrUserNotActive):
		WriteValidation(w, r, "仅可为有效用户关联员工档案。", nil)
	default:
		h.logError(r, "workforce operation failed", err)
		WriteInternalError(w, r)
	}
}

func (h *WorkforceHandlers) logError(r *http.Request, message string, err error) {
	h.logger.Error(message,
		"requestId", request.ID(r.Context()),
		"errorClass", observability.ClassifyError(err),
		"errorDetail", observability.RedactedError(err, 256))
}
