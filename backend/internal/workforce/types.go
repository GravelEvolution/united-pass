//
// Copyright (c) 2026 Chen Jiajie(Ariakage)
//
// Author: Chen Jiajie(Ariakage) <ariakage233@gmail.com>
// Date: 2026-08-11
// Description: Phase 5 identity and workforce domain contracts
//

// Package workforce defines the Phase 5 user-administration, employee and
// department domain. It contains no HTTP, SQL, Redis or provider SDK code.
package workforce

import (
	"crypto/rand"
	"encoding/hex"
	"errors"
	"fmt"
	"strings"
	"time"
	"unicode/utf8"

	"github.com/GravelEvolution/united-pass/backend/internal/identity"
)

type DepartmentID string
type AccessRevocationJobID string

type EmployeeStatus string

const (
	EmployeeStatusActive      EmployeeStatus = "active"
	EmployeeStatusOffboarding EmployeeStatus = "offboarding"
)

type AccessRevocationReason string

const (
	RevocationUserDisabled       AccessRevocationReason = "user_disabled"
	RevocationEmployeeOffboarded AccessRevocationReason = "employee_offboarded"
	RevocationAdminSession       AccessRevocationReason = "admin_session_revoke"
)

const (
	EventUserEnabled                 = "user.enabled"
	EventUserDisabled                = "user.disabled"
	EventUserSessionRevoked          = "user.session_revoked"
	EventUserSessionsRevokeRequested = "user.sessions_revoke_requested"
	EventAccessRevocationCompleted   = "access_revocation.completed"
	EventAccessRevocationDegraded    = "access_revocation.degraded"
	EventEmployeeLinked              = "employee.linked"
	EventEmployeeUpdated             = "employee.updated"
	EventEmployeeOffboarded          = "employee.offboarded"
	EventDepartmentCreated           = "department.created"
	EventDepartmentUpdated           = "department.updated"
	EventDepartmentDeleted           = "department.deleted"
)

var (
	ErrNotFound            = errors.New("workforce: resource not found")
	ErrConflict            = errors.New("workforce: state conflict")
	ErrInvalidCursor       = errors.New("workforce: invalid cursor")
	ErrDepartmentCycle     = errors.New("workforce: department cycle")
	ErrDepartmentNotEmpty  = errors.New("workforce: department not empty")
	ErrEmployeeNotActive   = errors.New("workforce: employee not active")
	ErrSupervisorNotActive = errors.New("workforce: supervisor not active")
	ErrUserNotActive       = errors.New("workforce: user not active")
	ErrInvalidInput        = errors.New("workforce: invalid input")
)

type UserListQuery struct {
	Cursor string
	Limit  int
	Query  string
	Sort   string
	Status string
}

type EmployeeListQuery struct {
	Cursor string
	Limit  int
	Query  string
	Sort   string
	Status string
}

type UserSummary struct {
	UserID       identity.UserID
	DisplayName  string
	Email        string
	PersonaLabel string
	Status       identity.UserStatus
	LastActiveAt time.Time
}

type EmployeeSummary struct {
	UserID         identity.UserID
	DisplayName    string
	EmployeeNumber string
	DepartmentName string
	Title          string
	Status         EmployeeStatus
	UpdatedAt      time.Time
}

type CursorPage[T any] struct {
	Items      []T
	NextCursor string
	HasMore    bool
}

type EmployeeProfile struct {
	UserID           identity.UserID
	EmployeeNumber   string
	DepartmentID     DepartmentID
	DepartmentName   string
	Title            string
	Status           EmployeeStatus
	SupervisorUserID identity.UserID
	SupervisorName   string
	OnboardedAt      time.Time
	OffboardedAt     *time.Time
	Version          int
}

type LinkedIdentity struct {
	ProviderID      string
	Provider        string
	ProviderName    string
	ExternalSubject string
	LinkedAt        time.Time
}

type AuthorizedApplication struct {
	ApplicationName string
	Scopes          []string
	GrantedAt       time.Time
	Status          string
}

type AuditEvent struct {
	EventID    string
	EventType  string
	ActorName  string
	ActorID    identity.UserID
	TargetID   string
	OccurredAt time.Time
	Result     string
	RequestID  string
}

type UserDetail struct {
	User                   identity.User
	LastActiveAt           time.Time
	EmployeeProfile        *EmployeeProfile
	LinkedIdentities       []LinkedIdentity
	AuthorizedApplications []AuthorizedApplication
	RecentAuditEvents      []AuditEvent
}

type DepartmentSummary struct {
	DepartmentID DepartmentID
	Name         string
	ParentName   string
	MemberCount  int
	OwnerName    string
	UpdatedAt    time.Time
}

type DepartmentMember struct {
	UserID         identity.UserID
	DisplayName    string
	Title          string
	EmployeeNumber string
}

type DepartmentChild struct {
	DepartmentID DepartmentID
	Name         string
	MemberCount  int
}

type DepartmentDetail struct {
	DepartmentID       DepartmentID
	Name               string
	ParentDepartmentID DepartmentID
	ParentName         string
	OwnerUserID        identity.UserID
	OwnerName          string
	MemberCount        int
	ChildDepartments   []DepartmentChild
	Members            []DepartmentMember
	Version            int
	CreatedAt          time.Time
	UpdatedAt          time.Time
}

type EmployeeProfileInput struct {
	UserID           identity.UserID
	DepartmentID     DepartmentID
	Title            string
	SupervisorUserID identity.UserID
}

type DepartmentInput struct {
	Name               string
	ParentDepartmentID DepartmentID
	OwnerUserID        identity.UserID
}

type DepartmentPatch struct {
	Name               *string
	ParentDepartmentID *DepartmentID
	OwnerUserID        *identity.UserID
}

type UserStatusMutation struct {
	ActorUserID    identity.UserID
	TargetUserID   identity.UserID
	Status         identity.UserStatus
	RevokeSessions bool
	RequestID      string
}

type AccessRevocationJob struct {
	JobID       AccessRevocationJobID
	ActorUserID identity.UserID
	UserID      identity.UserID
	Reason      AccessRevocationReason
	RequestID   string
	Attempts    int
	CreatedAt   time.Time
}

type OffboardingResult struct {
	Status         EmployeeStatus
	CleanupPending bool
}

func NewDepartmentID() DepartmentID {
	return DepartmentID("dep_" + randomHex(16))
}

func NewAccessRevocationJobID() AccessRevocationJobID {
	return AccessRevocationJobID("arj_" + randomHex(16))
}

func HasDepartmentIDPrefix(raw string) bool {
	return strings.HasPrefix(raw, "dep_") && len(raw) > len("dep_")
}

func NormalizeEmployeeInput(input EmployeeProfileInput) (EmployeeProfileInput, error) {
	input.Title = strings.TrimSpace(input.Title)
	if input.UserID == "" || !HasDepartmentIDPrefix(string(input.DepartmentID)) ||
		input.Title == "" || utf8.RuneCountInString(input.Title) > 120 ||
		(input.SupervisorUserID != "" && input.SupervisorUserID == input.UserID) {
		return EmployeeProfileInput{}, ErrInvalidInput
	}
	return input, nil
}

func NormalizeDepartmentInput(input DepartmentInput) (DepartmentInput, error) {
	input.Name = strings.TrimSpace(input.Name)
	if input.Name == "" || utf8.RuneCountInString(input.Name) > 120 ||
		(input.ParentDepartmentID != "" && !HasDepartmentIDPrefix(string(input.ParentDepartmentID))) {
		return DepartmentInput{}, ErrInvalidInput
	}
	return input, nil
}

func randomHex(size int) string {
	buf := make([]byte, size)
	if _, err := rand.Read(buf); err != nil {
		panic(fmt.Sprintf("workforce: generate random id: %v", err))
	}
	return hex.EncodeToString(buf)
}
