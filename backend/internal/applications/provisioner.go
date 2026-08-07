//
// Copyright (c) 2026 Chen Jiajie(Ariakage)
//
// Author: Chen Jiajie(Ariakage) <ariakage233@gmail.com>
// Date: 2026-08-06
// Description: Provider provisioning port contracts for the applications domain
//

package applications

import (
	"context"
	"errors"
)

// Provider provisioning contracts live in this package so the domain never
// depends on a provider SDK. Adapters (ZITADEL, fake) implement these
// interfaces; use cases program against them (ADR-0004, taskbook §10).

// ErrProviderUnavailable is the stable internal error for provider call
// failures. Adapters map raw provider errors to this class; raw provider
// detail never reaches callers, logs beyond error class, or API responses.
var ErrProviderUnavailable = errors.New("applications: provider unavailable")

// ErrProviderConflict indicates the provider reported a duplicate or state
// conflict (e.g. retry after an unconfirmed success).
var ErrProviderConflict = errors.New("applications: provider conflict")

// ErrProviderOutcomeUnknown indicates the provider call's result cannot be
// determined (deadline, cancellation, transport loss). For non-idempotent
// operations such as secret rotation the caller must assume the mutation may
// have happened and enter reconciliation instead of retrying blindly.
var ErrProviderOutcomeUnknown = errors.New("applications: provider outcome unknown")

// ClientProvisionSpec is everything the provider needs to create an OAuth
// client. It carries no secrets and no United Pass internal IDs beyond what
// the mapping requires.
type ClientProvisionSpec struct {
	// DisplayName is the client name registered at the provider. It must
	// be globally unique within the shared provider project; use
	// ProviderDisplayName to build it.
	DisplayName string
	// LocalClientID is the United Pass client ID being provisioned. It is
	// embedded into the provider display name so an ambiguously created
	// provider app can be recovered deterministically on retry — never via
	// a user-chosen name alone.
	LocalClientID OAuthClientID
	// Profile determines the provider-side app type, auth method and grant
	// types mapping (ADR-0004 §1).
	Profile ClientProfile
	// RedirectURIs are exact registered strings; empty for
	// server_to_server clients.
	RedirectURIs []string
	// LogoutURI is optional; empty when unset.
	LogoutURI string
	// Scopes are the registered scope IDs granted to the client.
	Scopes []string
}

// ClientProvisionResult is the provider outcome of creating a client. The
// secret is handed back exactly once and must never be persisted by any
// layer; it travels only into the one-time API response.
type ClientProvisionResult struct {
	ProviderApplicationID string
	ProviderClientID      string
	// ClientSecret is non-empty only for confidential clients.
	ClientSecret string
}

// ClientUpdateSpec carries the mutable provider-side client settings.
type ClientUpdateSpec struct {
	DisplayName  string
	RedirectURIs []string
	LogoutURI    string
}

// ClientSecretRotation is the provider outcome of a rotation. Against
// ZITADEL v2.71 the previous secret is invalidated immediately; the grace
// period is a United Pass configuration for providers that support overlap
// (ADR-0004 §6).
type ClientSecretRotation struct {
	NewSecret string
}

// OAuthClientProvisioner provisions OAuth clients at the identity provider.
// Implementations must be safe to retry with the same idempotency key and
// must never log secret material.
type OAuthClientProvisioner interface {
	// ProvisionClient creates the provider-side OAuth application for a
	// United Pass client. idempotencyKey lets retries avoid duplicates.
	// When a provider app already exists for this spec's globally unique
	// display name (an ambiguously succeeded earlier attempt), the
	// implementation must recover and return that app instead of reporting
	// a conflict.
	ProvisionClient(ctx context.Context, idempotencyKey string, spec ClientProvisionSpec) (ClientProvisionResult, error)

	// UpdateClient synchronizes mutable settings to the provider.
	UpdateClient(ctx context.Context, providerApplicationID string, spec ClientUpdateSpec) error

	// EnableClient reactivates a disabled provider application.
	EnableClient(ctx context.Context, providerApplicationID string) error

	// DisableClient deactivates the provider application.
	DisableClient(ctx context.Context, providerApplicationID string) error

	// DeleteClient removes the provider application. Implementations treat
	// an already-removed application as success (idempotent delete).
	DeleteClient(ctx context.Context, providerApplicationID string) error

	// RotateClientSecret regenerates the secret at the provider. The
	// previous secret handling is provider-defined; see ADR-0004 §6.
	// Ambiguous failures (timeout, cancellation, transport loss) must wrap
	// ErrProviderOutcomeUnknown because rotation is non-idempotent: the
	// provider may already have revoked the previous secret.
	RotateClientSecret(ctx context.Context, providerApplicationID string) (ClientSecretRotation, error)
}

// ProviderOperationType classifies recorded provider operations.
type ProviderOperationType string

const (
	ProviderOperationProvision    ProviderOperationType = "provision_client"
	ProviderOperationUpdate       ProviderOperationType = "update_client"
	ProviderOperationEnable       ProviderOperationType = "enable_client"
	ProviderOperationDisable      ProviderOperationType = "disable_client"
	ProviderOperationDelete       ProviderOperationType = "delete_client"
	ProviderOperationRotateSecret ProviderOperationType = "rotate_client_secret"
)

// ProviderOperationStatus is the recorded outcome state.
type ProviderOperationStatus string

const (
	ProviderOperationPending   ProviderOperationStatus = "pending"
	ProviderOperationSucceeded ProviderOperationStatus = "succeeded"
	ProviderOperationFailed    ProviderOperationStatus = "failed"
)

// ProviderOperation is the durable record of one provider call, used for
// idempotent retries and reconciliation (ADR-0004 §2).
type ProviderOperation struct {
	ID             ProviderOperationID
	Type           ProviderOperationType
	ApplicationID  ApplicationID
	ClientID       OAuthClientID
	IdempotencyKey string
	Status         ProviderOperationStatus
	ErrorClass     string
}

// ReconciliationJob records provider-side cleanup that could not be
// completed inline (e.g. compensation failure). It is a recoverable,
// auditable work item — never a silent leak. DesiredStatus carries the
// expected provider status ("active"/"disabled") for status-transition
// drift; it stays empty for non-status jobs (e.g. deletion cleanup).
type ReconciliationJob struct {
	ID                    ProviderOperationID
	ApplicationID         ApplicationID
	ClientID              OAuthClientID
	ProviderApplicationID string
	Reason                string
	DesiredStatus         string
}
