package applications

import (
	"errors"
	"time"

	"github.com/GravelEvolution/united-pass/backend/internal/identity"
)

// ErrNotFound is returned when an application or client lookup yields no
// result. Inaccessible resources produce the same error (anti-enumeration).
var ErrNotFound = errors.New("applications: resource not found")

// ErrConflict is returned on optimistic-concurrency or duplicate conflicts.
var ErrConflict = errors.New("applications: state conflict")

// ErrInvalidStateTransition is returned when a lifecycle operation is not
// permitted from the current status.
var ErrInvalidStateTransition = errors.New("applications: invalid state transition")

// Name and description limits mirror the frozen frontend contract.
const (
	ApplicationNameMin = 2
	ApplicationNameMax = 80
	ApplicationDescMax = 500

	ClientNameMin = 2
	ClientNameMax = 64

	MaxRedirectURIs   = 20
	MaxRedirectURILen = 2048
)

// Application is the OAuth application aggregate root. OwnerID is the
// authoritative ownership reference; OwnerName is derived display text that
// is never used for authorization decisions (ADR-0004 G1). Provisioning
// tracks cross-store consistency and is never exposed in API responses.
type Application struct {
	ID           ApplicationID
	Name         string
	Description  string
	LogoURL      string
	Audience     ApplicationAudience
	OwnerID      identity.UserID
	OwnerName    string
	Status       Status
	Provisioning ProvisioningStatus
	Version      int
	CreatedAt    time.Time
	UpdatedAt    time.Time
}

// ApplicationSummary is the list-view projection: the application plus the
// number of provisioned, live clients it owns.
type ApplicationSummary struct {
	Application
	ClientCount int
}

// OAuthClient is an OAuth client belonging to an application. Provider
// identifiers are mapping columns only and never act as United Pass
// identities (ADR-0004 §1).
type OAuthClient struct {
	ID                    OAuthClientID
	ApplicationID         ApplicationID
	Name                  string
	Profile               ClientProfile
	ClientType            ClientType
	TokenEndpointAuth     TokenEndpointAuthMethod
	ConsentMode           ConsentMode
	Status                Status
	RedirectURIs          []RedirectURI
	LogoutURI             string
	Scopes                []string
	Provider              string
	ProviderProjectID     string
	ProviderApplicationID string
	ProviderClientID      string
	Provisioning          ProvisioningStatus
	// SecretRecords is secret metadata only; never secret values.
	SecretRecords []ClientSecretRecord
	Version       int
	CreatedAt     time.Time
	UpdatedAt     time.Time
}

// RedirectURI is a registered redirect URI, stored exactly as submitted.
// No normalization is ever applied (ADR-0004 §4).
type RedirectURI struct {
	URI        string
	IsLoopback bool
	AddedAt    time.Time
}

// ClientSecretRecord is secret metadata only. The raw secret value is never
// persisted or represented in the domain, storage, logs or audit.
type ClientSecretRecord struct {
	ID            ClientSecretID
	ClientID      OAuthClientID
	Label         string
	CreatedAt     time.Time
	LastRotatedAt *time.Time
}

// CanEnable reports whether a transition to active is permitted.
func (s Status) CanEnable() bool { return s == StatusDisabled }

// CanDisable reports whether a transition to disabled is permitted.
func (s Status) CanDisable() bool { return s == StatusActive }

// Enable returns the application's state after enabling.
func (a *Application) Enable() error {
	if !a.Status.CanEnable() {
		return ErrInvalidStateTransition
	}
	a.Status = StatusActive
	return nil
}

// Disable returns the application's state after disabling.
func (a *Application) Disable() error {
	if !a.Status.CanDisable() {
		return ErrInvalidStateTransition
	}
	a.Status = StatusDisabled
	return nil
}

// Enable returns the client's state after enabling.
func (c *OAuthClient) Enable() error {
	if !c.Status.CanEnable() {
		return ErrInvalidStateTransition
	}
	c.Status = StatusActive
	return nil
}

// Disable returns the client's state after disabling.
func (c *OAuthClient) Disable() error {
	if !c.Status.CanDisable() {
		return ErrInvalidStateTransition
	}
	c.Status = StatusDisabled
	return nil
}

// CanRotateSecret reports whether secret rotation is permitted for this
// client. Public clients never have secrets (ADR-0004 §6).
func (c *OAuthClient) CanRotateSecret() bool {
	return c.ClientType == ClientTypeConfidential && c.Status == StatusActive
}

// EffectiveClientActive computes the client's effective active state: a
// client is effectively active only when BOTH the parent application and the
// client itself are active. The application-level kill switch is
// authoritative; disabling an application must disable all of its clients at
// the provider and cannot be bypassed by re-enabling an individual client.
func EffectiveClientActive(appStatus, clientStatus Status) bool {
	return appStatus == StatusActive && clientStatus == StatusActive
}

// ScopeDefinition is one entry of the backend-authoritative scope catalog.
type ScopeDefinition struct {
	Scope       string
	Label       string
	Description string
	Required    bool
}

// ScopeCatalog is the authoritative OAuth scope catalog served by
// GET /api/v1/admin/scopes. It mirrors the frozen frontend catalog; OAuth
// scopes are delegated-access descriptors only and never grant backend
// management permissions (ADR-0004 §5).
var ScopeCatalog = []ScopeDefinition{
	{Scope: "openid", Label: "OpenID", Description: "获取基本身份标识", Required: false},
	{Scope: "profile", Label: "基本资料", Description: "读取姓名、头像等基本资料", Required: false},
	{Scope: "email", Label: "邮箱", Description: "读取邮箱地址及验证状态", Required: false},
	{Scope: "phone", Label: "手机号", Description: "读取手机号及验证状态", Required: false},
	{Scope: "offline_access", Label: "离线访问", Description: "获取 Refresh Token 以离线访问", Required: false},
	{Scope: "reporting:read", Label: "报表读取", Description: "读取报表数据", Required: false},
}

// KnownScope reports whether scope is registered in the catalog.
func KnownScope(scope string) bool {
	for _, def := range ScopeCatalog {
		if def.Scope == scope {
			return true
		}
	}
	return false
}
