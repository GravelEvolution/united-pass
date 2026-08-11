//
// Copyright (c) 2026 Chen Jiajie(Ariakage)
//
// Author: Chen Jiajie(Ariakage) <ariakage233@gmail.com>
// Date: 2026-08-05
// Description: HTTP handlers for the account self-service endpoints
//

package httpapi

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"

	"github.com/GravelEvolution/united-pass/backend/internal/identity"
	"github.com/GravelEvolution/united-pass/backend/internal/permissions"
	"github.com/GravelEvolution/united-pass/backend/internal/workforce"
)

// UserReader loads user data for the current-user endpoints. The PostgreSQL
// UserRepository satisfies this interface. It is defined here (close to the
// consumer) per AGENTS.md §8.
type UserReader interface {
	// GetByID loads a user by stable United Pass user ID, including personas.
	// Returns identity.ErrUserNotFound when no row matches.
	GetByID(ctx context.Context, userID identity.UserID) (identity.User, error)
}

// AccountHandlers serves the current-user endpoints: GET /me and
// GET /me/permissions.
type AccountHandlers struct {
	userReader   UserReader
	permResolver permissions.Resolver
	employees    interface {
		GetEmployeeProfile(ctx context.Context, userID identity.UserID) (workforce.EmployeeProfile, error)
	}
}

// NewAccountHandlers builds AccountHandlers from the given dependencies.
func NewAccountHandlers(userReader UserReader, permResolver permissions.Resolver, employeeReaders ...interface {
	GetEmployeeProfile(ctx context.Context, userID identity.UserID) (workforce.EmployeeProfile, error)
}) *AccountHandlers {
	handler := &AccountHandlers{
		userReader:   userReader,
		permResolver: permResolver,
	}
	if len(employeeReaders) > 0 {
		handler.employees = employeeReaders[0]
	}
	return handler
}

// currentUserResponse is the JSON response for GET /api/v1/me. Field names
// match the frontend CurrentUser type exactly.
// See ../frontend/src/types/identity.ts.
type currentUserResponse struct {
	UserID          string                          `json:"userId"`
	DisplayName     string                          `json:"displayName"`
	Nickname        string                          `json:"nickname"`
	AvatarURL       *string                         `json:"avatarUrl"`
	Email           string                          `json:"email"`
	PhoneMasked     string                          `json:"phoneMasked"`
	Personas        []string                        `json:"personas"`
	EmployeeProfile *currentEmployeeProfileResponse `json:"employeeProfile"`
}

type currentEmployeeProfileResponse struct {
	EmployeeID     string `json:"employeeId"`
	DepartmentName string `json:"departmentName"`
	Title          string `json:"title"`
}

// GetCurrentUser handles GET /api/v1/me.
//
// Returns the current session user's profile. The response uses the stable
// United Pass user ID and never includes provider subjects, tokens, or the raw
// phone number. EmployeeProfile is null in Phase 1 (employee profiles are a
// Phase 5 feature).
func (h *AccountHandlers) GetCurrentUser(w http.ResponseWriter, r *http.Request) {
	principal, ok := PrincipalFromContext(r.Context())
	if !ok {
		WriteUnauthorized(w, r)
		return
	}

	user, err := h.userReader.GetByID(r.Context(), principal.UserID)
	if err != nil {
		writeUserLookupError(w, r, err)
		return
	}

	// Verify the user is still active. A disabled user should not receive
	// profile data even if the session has not been cleaned up yet.
	if !user.Status.CanAuthenticate() {
		WriteUnauthorized(w, r)
		return
	}

	personas := make([]string, len(user.Personas))
	for i, p := range user.Personas {
		personas[i] = string(p)
	}
	if len(personas) == 0 {
		personas = []string{}
	}

	var employeeProfile *currentEmployeeProfileResponse
	if h.employees != nil {
		profile, err := h.employees.GetEmployeeProfile(r.Context(), principal.UserID)
		if err == nil {
			employeeProfile = &currentEmployeeProfileResponse{
				EmployeeID: profile.EmployeeNumber, DepartmentName: profile.DepartmentName,
				Title: profile.Title,
			}
		} else if !errors.Is(err, workforce.ErrNotFound) {
			WriteInternalError(w, r)
			return
		}
	}

	resp := currentUserResponse{
		UserID:          string(user.ID),
		DisplayName:     user.DisplayName,
		Nickname:        user.Nickname,
		AvatarURL:       nullableString(user.AvatarURL),
		Email:           user.Email,
		PhoneMasked:     identity.MaskPhone(user.Phone),
		Personas:        personas,
		EmployeeProfile: employeeProfile,
	}

	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	w.Header().Set("Cache-Control", "no-store")
	w.WriteHeader(http.StatusOK)
	_ = json.NewEncoder(w).Encode(resp)
}

// GetPermissions handles GET /api/v1/me/permissions.
//
// Returns the permission capabilities for the current session user. In Phase 1,
// the resolver is a temporary fail-closed implementation. Phase 7 replaces it
// with Cerbos without changing the API contract.
func (h *AccountHandlers) GetPermissions(w http.ResponseWriter, r *http.Request) {
	principal, ok := PrincipalFromContext(r.Context())
	if !ok {
		WriteUnauthorized(w, r)
		return
	}

	caps, err := h.permResolver.Resolve(r.Context(), principal.UserID)
	if err != nil {
		WriteInternalError(w, r)
		return
	}

	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	w.Header().Set("Cache-Control", "no-store")
	w.WriteHeader(http.StatusOK)
	_ = json.NewEncoder(w).Encode(caps)
}

// writeUserLookupError maps user lookup errors to appropriate HTTP responses.
func writeUserLookupError(w http.ResponseWriter, r *http.Request, err error) {
	if err == identity.ErrUserNotFound {
		WriteUnauthorized(w, r)
		return
	}
	WriteInternalError(w, r)
}

// nullableString returns a pointer to the string when non-empty, or nil when
// empty. This ensures the JSON response uses null for absent optional string
// fields (matching the frontend type which uses `string | null`).
func nullableString(s string) *string {
	if s == "" {
		return nil
	}
	return &s
}
