//
// Copyright (c) 2026 Chen Jiajie(Ariakage)
//
// Author: Chen Jiajie(Ariakage) <ariakage233@gmail.com>
// Date: 2026-08-11
// Description: Phase 8 privacy-rights and legal-publication domain types
//

// Package privacy implements the launch-phase personal-data export, account
// deletion and legal-publication lifecycles. It never owns authentication
// credentials or raw session/provider tokens.
package privacy

import (
	"context"
	"errors"
	"time"

	"github.com/GravelEvolution/united-pass/backend/internal/identity"
)

type ExportID string
type DeletionID string

type Export struct {
	ExportID      ExportID        `json:"exportId"`
	Status        string          `json:"status"`
	RequestedAt   time.Time       `json:"requestedAt"`
	CompletedAt   *time.Time      `json:"completedAt"`
	ExpiresAt     *time.Time      `json:"expiresAt"`
	DownloadURL   *string         `json:"downloadUrl"`
	UserID        identity.UserID `json:"-"`
	Content       []byte          `json:"-"`
	TotalSections int             `json:"totalSections"`
}

type ExportDocument struct {
	SchemaVersion             string                   `json:"schemaVersion"`
	GeneratedAt               time.Time                `json:"generatedAt"`
	Profile                   ExportProfile            `json:"profile"`
	Personas                  []string                 `json:"personas"`
	IdentityLinks             []ExportLink             `json:"identityLinks"`
	ProviderDirectoryProfiles []ExportDirectoryProfile `json:"providerDirectoryProfiles"`
	Employee                  *ExportEmployee          `json:"employeeProfile"`
	Authorizations            []ExportGrant            `json:"authorizedApplications"`
	Deletion                  *Deletion                `json:"accountDeletionRequest"`
}

type ExportProfile struct {
	UserID        string    `json:"userId"`
	Status        string    `json:"status"`
	DisplayName   string    `json:"displayName"`
	Nickname      string    `json:"nickname"`
	AvatarURL     string    `json:"avatarUrl"`
	Email         string    `json:"email"`
	EmailVerified bool      `json:"emailVerified"`
	Phone         string    `json:"phone"`
	PhoneVerified bool      `json:"phoneVerified"`
	CreatedAt     time.Time `json:"createdAt"`
	UpdatedAt     time.Time `json:"updatedAt"`
}

type ExportLink struct {
	Provider         string    `json:"provider"`
	ProviderTenantID string    `json:"providerTenantId"`
	ProviderSubject  string    `json:"providerSubject"`
	CreatedAt        time.Time `json:"createdAt"`
	LastSeenAt       time.Time `json:"lastSeenAt"`
}

type ExportDirectoryProfile struct {
	ProviderID       string    `json:"providerId"`
	ProviderTenantID string    `json:"providerTenantId"`
	ExternalSubject  string    `json:"externalSubject"`
	UnionID          string    `json:"unionId"`
	TenantUserID     string    `json:"tenantUserId"`
	DisplayName      string    `json:"displayName"`
	Email            string    `json:"email"`
	EmployeeNumber   string    `json:"employeeNumber"`
	Title            string    `json:"title"`
	DepartmentIDs    []string  `json:"departmentIds"`
	Active           bool      `json:"active"`
	UpdatedAt        time.Time `json:"updatedAt"`
}

type ExportEmployee struct {
	EmployeeNumber string     `json:"employeeNumber"`
	DepartmentID   string     `json:"departmentId"`
	DepartmentName string     `json:"departmentName"`
	Title          string     `json:"title"`
	SupervisorID   *string    `json:"supervisorUserId"`
	Status         string     `json:"status"`
	OnboardedAt    time.Time  `json:"onboardedAt"`
	OffboardedAt   *time.Time `json:"offboardedAt"`
}

type ExportGrant struct {
	GrantID         string     `json:"grantId"`
	ApplicationID   string     `json:"applicationId"`
	ApplicationName string     `json:"applicationName"`
	ClientID        string     `json:"clientId"`
	ClientName      string     `json:"clientName"`
	Status          string     `json:"status"`
	Scopes          []string   `json:"scopes"`
	GrantedAt       time.Time  `json:"grantedAt"`
	RevokedAt       *time.Time `json:"revokedAt"`
}

type Deletion struct {
	DeletionID      DeletionID      `json:"deletionId"`
	Status          string          `json:"status"`
	RequestedAt     time.Time       `json:"requestedAt"`
	ExecuteAfter    time.Time       `json:"executeAfter"`
	CancelledAt     *time.Time      `json:"cancelledAt"`
	CompletedAt     *time.Time      `json:"completedAt"`
	UserID          identity.UserID `json:"-"`
	ProviderSubject string          `json:"-"`
}

type LegalPublication struct {
	DocumentKind      string          `json:"documentKind"`
	Version           string          `json:"version"`
	ContentSHA256     string          `json:"contentSha256"`
	EffectiveAt       time.Time       `json:"effectiveAt"`
	ApprovalReference string          `json:"approvalReference,omitempty"`
	ApprovedBy        string          `json:"approvedBy,omitempty"`
	PublishedAt       time.Time       `json:"publishedAt"`
	PublishedBy       identity.UserID `json:"-"`
}

type LegalPublicationInput struct {
	DocumentKind      string
	Version           string
	ContentSHA256     string
	EffectiveAt       time.Time
	ApprovalReference string
	ApprovedBy        string
	PublishedBy       identity.UserID
	RequestID         string
}

type Repository interface {
	BeginExport(context.Context, identity.UserID, string) (Export, error)
	GetExport(context.Context, ExportID) (Export, error)
	ClaimExports(context.Context, int) ([]Export, error)
	BuildExportDocument(context.Context, identity.UserID, time.Time) (ExportDocument, error)
	CompleteExport(context.Context, ExportID, []byte, int, time.Time) error
	FailExport(context.Context, ExportID, string) error

	GetDeletion(context.Context, identity.UserID) (*Deletion, error)
	RequestDeletion(context.Context, identity.UserID, string, time.Time) (Deletion, error)
	CancelDeletion(context.Context, identity.UserID, string) (Deletion, error)
	ClaimDeletions(context.Context, int) ([]Deletion, error)
	MarkProviderDeleted(context.Context, DeletionID) error
	CompleteDeletion(context.Context, DeletionID) error
	FailDeletionAttempt(context.Context, DeletionID, string) error

	ListLegalPublications(context.Context) ([]LegalPublication, error)
	PublishLegalDocument(context.Context, LegalPublicationInput) (LegalPublication, error)
}

var (
	ErrNotFound       = errors.New("privacy resource not found")
	ErrConflict       = errors.New("privacy resource conflict")
	ErrNotReady       = errors.New("privacy export not ready")
	ErrExpired        = errors.New("privacy export expired")
	ErrValidation     = errors.New("privacy input validation failed")
	ErrProviderDelete = errors.New("privacy provider deletion failed")
)
