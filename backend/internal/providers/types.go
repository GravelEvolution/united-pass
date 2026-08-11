//
// Copyright (c) 2026 Chen Jiajie(Ariakage)
//
// Author: Chen Jiajie(Ariakage) <ariakage233@gmail.com>
// Date: 2026-08-11
// Description: Phase 6 identity Provider and directory synchronization contracts
//

// Package providers owns the Phase 6 identity Provider domain. Provider
// payloads are normalized at the adapter boundary; this package never imports
// an SDK, HTTP type, SQL type, Redis type or provider credential.
package providers

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"errors"
	"fmt"
	"strings"
	"time"
	"unicode/utf8"

	"github.com/GravelEvolution/united-pass/backend/internal/identity"
)

type ProviderID string
type SyncID string
type ConflictID string

const FeishuProviderID ProviderID = "provider_feishu"

type ProviderStatus string

const (
	ProviderStatusPlanned  ProviderStatus = "planned"
	ProviderStatusActive   ProviderStatus = "active"
	ProviderStatusDisabled ProviderStatus = "disabled"
)

type SyncStatus string

const (
	SyncStatusPending SyncStatus = "pending"
	SyncStatusRunning SyncStatus = "running"
	SyncStatusSuccess SyncStatus = "success"
	SyncStatusPartial SyncStatus = "partial"
	SyncStatusFailed  SyncStatus = "failed"
)

type ConflictStatus string

const (
	ConflictStatusPending  ConflictStatus = "pending"
	ConflictStatusResolved ConflictStatus = "resolved"
	ConflictStatusIgnored  ConflictStatus = "ignored"
)

type MatchReason string

const (
	MatchReasonEmail  MatchReason = "email"
	MatchReasonName   MatchReason = "name"
	MatchReasonManual MatchReason = "manual"
)

const (
	EventProviderEnabled          = "provider.enabled"
	EventProviderDisabled         = "provider.disabled"
	EventDirectorySyncRequested   = "provider.directory_sync_requested"
	EventDirectorySyncCompleted   = "provider.directory_sync_completed"
	EventDirectorySyncFailed      = "provider.directory_sync_failed"
	EventIdentityConflictResolved = "provider.identity_conflict_resolved"
	EventIdentityConflictIgnored  = "provider.identity_conflict_ignored"
)

var (
	ErrNotFound           = errors.New("providers: resource not found")
	ErrConflict           = errors.New("providers: state conflict")
	ErrInvalidInput       = errors.New("providers: invalid input")
	ErrNotConfigured      = errors.New("providers: credentials not configured")
	ErrProviderDisabled   = errors.New("providers: login disabled")
	ErrIdentityUnlinked   = errors.New("providers: external identity is not linked")
	ErrProviderFailure    = errors.New("providers: provider failure")
	ErrTenantMismatch     = errors.New("providers: tenant mismatch")
	ErrDirectoryTooLarge  = errors.New("providers: directory exceeds safety budget")
	ErrOAuthStateNotFound = errors.New("providers: OAuth state not found")
)

type ListQuery struct {
	Cursor string
	Limit  int
	Query  string
	Status string
}

type CursorPage[T any] struct {
	Items      []T
	NextCursor string
	HasMore    bool
}

type ProviderSummary struct {
	ProviderID       ProviderID
	DisplayName      string
	Vendor           string
	IntegrationLabel string
	Status           ProviderStatus
	LoginEnabled     bool
	LinkedUserCount  int
	UpdatedAt        time.Time
}

type RuntimeMetadata struct {
	AppID            string
	RedirectURL      string
	ContactScope     string
	TenantID         string
	SecretConfigured bool
}

type ProviderDetail struct {
	ProviderSummary
	AppID            string
	SecretConfigured bool
	CallbackURL      string
	ContactScope     string
	LastValidatedAt  *time.Time
	LastSyncAt       *time.Time
	LastSyncResult   *SyncJob
}

type SyncJob struct {
	SyncID              SyncID
	ProviderID          ProviderID
	ActorUserID         identity.UserID
	RequestID           string
	Status              SyncStatus
	StartedAt           time.Time
	CompletedAt         *time.Time
	DepartmentsAdded    int
	DepartmentsUpdated  int
	EmployeesAdded      int
	EmployeesUpdated    int
	EmployeesOffboarded int
	ConflictsDetected   int
	Attempts            int
	FailureClass        string
}

type SyncHistoryEntry struct {
	SyncJob
	Summary string
}

type SyncConflict struct {
	ConflictID      ConflictID
	ProviderID      ProviderID
	TenantID        string
	ExternalSubject string
	ExternalName    string
	ExternalEmail   string
	MatchedUserID   identity.UserID
	MatchedUserName string
	MatchReason     MatchReason
	Status          ConflictStatus
	DetectedAt      time.Time
}

type ExternalDepartment struct {
	ExternalID       string
	ParentExternalID string
	Name             string
	LeaderSubject    string
}

type ExternalUser struct {
	Subject        string
	UnionID        string
	TenantUserID   string
	Name           string
	Email          string
	EmployeeNumber string
	Title          string
	DepartmentIDs  []string
	Active         bool
}

// DirectorySnapshot is a bounded, normalized provider observation. It is
// stored in provider staging tables. It never grants employee status,
// department membership or permissions in the United Pass authority plane.
type DirectorySnapshot struct {
	ProviderID   ProviderID
	TenantID     string
	Departments  []ExternalDepartment
	Users        []ExternalUser
	Partial      bool
	FailureClass string
}

type OAuthUserInfo struct {
	Subject  string
	UnionID  string
	TenantID string
	Name     string
	Email    string
}

type OAuthState struct {
	ResumeRequestID string    `json:"resumeRequestId,omitempty"`
	Remember        bool      `json:"remember"`
	CreatedAt       time.Time `json:"createdAt"`
}

type Repository interface {
	ListProviders(ctx context.Context, query ListQuery) (CursorPage[ProviderSummary], error)
	GetProvider(ctx context.Context, providerID ProviderID) (ProviderDetail, error)
	SetProviderEnabled(ctx context.Context, actor identity.UserID, providerID ProviderID, enabled bool, requestID string) (ProviderDetail, error)

	EnqueueSync(ctx context.Context, actor identity.UserID, providerID ProviderID, requestID string) (SyncJob, error)
	ClaimSync(ctx context.Context, staleBefore time.Time) (*SyncJob, error)
	ApplySnapshot(ctx context.Context, job SyncJob, snapshot DirectorySnapshot) (SyncJob, error)
	FailSync(ctx context.Context, job SyncJob, failureClass string) error
	ListSyncHistory(ctx context.Context, providerID ProviderID, limit int) ([]SyncHistoryEntry, error)
	ListConflicts(ctx context.Context, providerID ProviderID, limit int) ([]SyncConflict, error)
	ResolveConflict(ctx context.Context, actor identity.UserID, conflictID ConflictID, userID identity.UserID, requestID string) error
	IgnoreConflict(ctx context.Context, actor identity.UserID, conflictID ConflictID, requestID string) error
	RecordUnlinkedIdentity(ctx context.Context, providerID ProviderID, tenantID string, info OAuthUserInfo) error
	LinkedUser(ctx context.Context, providerID ProviderID, tenantID, subject string) (identity.User, error)
	RecordAuthorizationDenied(ctx context.Context, actor identity.UserID, targetKey, targetID, eventType, operation, requestID string) error
}

type DirectorySource interface {
	Validate(ctx context.Context) error
	FetchDirectory(ctx context.Context) (DirectorySnapshot, error)
}

type OAuthSource interface {
	AuthorizationURL(state string) (string, error)
	ExchangeCode(ctx context.Context, code string) (OAuthUserInfo, error)
}

type OAuthStateStore interface {
	Create(ctx context.Context, stateHash string, state OAuthState, ttl time.Duration) error
	Consume(ctx context.Context, stateHash string) (OAuthState, error)
}

func NewSyncID() SyncID         { return SyncID("sync_" + randomHex(16)) }
func NewConflictID() ConflictID { return ConflictID("conflict_" + randomHex(16)) }

func HasProviderIDPrefix(value string) bool {
	return strings.HasPrefix(value, "provider_") && len(value) > len("provider_") && len(value) <= 128
}

func HasSyncIDPrefix(value string) bool {
	return strings.HasPrefix(value, "sync_") && len(value) > len("sync_") && len(value) <= 128
}

func HasConflictIDPrefix(value string) bool {
	return strings.HasPrefix(value, "conflict_") && len(value) > len("conflict_") && len(value) <= 128
}

func ValidateSnapshot(snapshot DirectorySnapshot) error {
	if !HasProviderIDPrefix(string(snapshot.ProviderID)) || strings.TrimSpace(snapshot.TenantID) == "" || len(snapshot.TenantID) > 256 {
		return ErrInvalidInput
	}
	if len(snapshot.Departments) > 2_000 || len(snapshot.Users) > 50_000 {
		return ErrDirectoryTooLarge
	}
	departmentIDs := make(map[string]struct{}, len(snapshot.Departments))
	for _, item := range snapshot.Departments {
		if item.ExternalID == "" || len(item.ExternalID) > 256 || strings.TrimSpace(item.Name) == "" || utf8.RuneCountInString(item.Name) > 256 {
			return ErrInvalidInput
		}
		if _, exists := departmentIDs[item.ExternalID]; exists {
			return ErrConflict
		}
		departmentIDs[item.ExternalID] = struct{}{}
	}
	userSubjects := make(map[string]struct{}, len(snapshot.Users))
	for _, item := range snapshot.Users {
		if item.Subject == "" || len(item.Subject) > 256 || strings.TrimSpace(item.Name) == "" || utf8.RuneCountInString(item.Name) > 256 || len(item.Email) > 320 {
			return ErrInvalidInput
		}
		if _, exists := userSubjects[item.Subject]; exists {
			return ErrConflict
		}
		userSubjects[item.Subject] = struct{}{}
	}
	return nil
}

func randomHex(bytes int) string {
	buffer := make([]byte, bytes)
	if _, err := rand.Read(buffer); err != nil {
		panic(fmt.Sprintf("providers: generate random identifier: %v", err))
	}
	return hex.EncodeToString(buffer)
}
