package applications

import (
	"context"
	"errors"
	"strings"
	"time"

	"github.com/GravelEvolution/united-pass/backend/internal/identity"
)

// ApplicationStore is the persistence contract consumed by the use cases.
// The PostgreSQL ApplicationRepository satisfies it. It is defined here
// (close to the consumer) per AGENTS.md §8.
type ApplicationStore interface {
	CreateApplicationWithInitialClient(ctx context.Context, app Application, client OAuthClient, op ProviderOperation) error
	CompleteInitialProvisioning(ctx context.Context, appID ApplicationID, clientID OAuthClientID, provider, providerProjectID, providerApplicationID, providerClientID string, opID ProviderOperationID, secret *ClientSecretRecord) error
	MarkInitialProvisioningFailed(ctx context.Context, appID ApplicationID, clientID OAuthClientID, opID ProviderOperationID, errorClass string) error
	GetApplication(ctx context.Context, appID ApplicationID) (Application, error)
	UpdateApplication(ctx context.Context, appID ApplicationID, upd ApplicationUpdate, expectedVersion int) error
	SetApplicationStatus(ctx context.Context, appID ApplicationID, status Status, expectedVersion int) error
	DeleteApplication(ctx context.Context, appID ApplicationID, expectedVersion int) error
	ListApplications(ctx context.Context, q ListQuery) (ListResult, error)

	ListClientsByApplication(ctx context.Context, appID ApplicationID) ([]OAuthClient, error)
	ListLiveClientsByApplication(ctx context.Context, appID ApplicationID) ([]OAuthClient, error)
	GetClient(ctx context.Context, appID ApplicationID, clientID OAuthClientID) (OAuthClient, error)
	CreateClientWithOperation(ctx context.Context, client OAuthClient, op ProviderOperation) error
	CompleteClientProvisioning(ctx context.Context, clientID OAuthClientID, provider, providerProjectID, providerApplicationID, providerClientID string, opID ProviderOperationID, secret *ClientSecretRecord) error
	MarkClientProvisioningFailed(ctx context.Context, clientID OAuthClientID, opID ProviderOperationID, errorClass string) error
	UpdateClientConfig(ctx context.Context, clientID OAuthClientID, upd ClientConfigUpdate, expectedVersion int) error
	SetClientStatus(ctx context.Context, clientID OAuthClientID, status Status, expectedVersion int) error
	MarkClientDeleting(ctx context.Context, clientID OAuthClientID, op ProviderOperation) error
	MarkClientDeletingRetry(ctx context.Context, clientID OAuthClientID, op ProviderOperation) error
	CompleteClientDeletion(ctx context.Context, clientID OAuthClientID, opID ProviderOperationID) error
	MarkClientDeleteFailed(ctx context.Context, clientID OAuthClientID, opID ProviderOperationID, errorClass string) error

	CreateSecretRecord(ctx context.Context, rec ClientSecretRecord) error
	MarkSecretRotated(ctx context.Context, secretID ClientSecretID, rotatedAt time.Time) error
	GetClientSecretRecords(ctx context.Context, clientID OAuthClientID) ([]ClientSecretRecord, error)
	// BeginSecretRotation acquires the single-winner rotation gate by bumping
	// the client's optimistic-concurrency version before any provider call.
	// A concurrent rotation (or any other concurrent client write) makes the
	// version match fail and returns ErrConflict.
	BeginSecretRotation(ctx context.Context, clientID OAuthClientID, expectedVersion int) error

	GetOperationByIdempotencyKey(ctx context.Context, key string) (ProviderOperation, error)
	CreateReconciliationJob(ctx context.Context, job ReconciliationJob) error
	SetClientReconciliationRequired(ctx context.Context, clientID OAuthClientID) error
}

// SecurityEventRecorder persists durable audit rows. Log-based audit is not
// a substitute (ADR-0004 §8). The PostgreSQL SecurityEventStore satisfies it.
type SecurityEventRecorder interface {
	Record(ctx context.Context, ev SecurityEvent) error
}

// AuditReader loads recorded security events for API projections.
type AuditReader interface {
	ListByApplication(ctx context.Context, appID ApplicationID) ([]AuditEntry, error)
}

// UserLookup resolves owner user IDs. Ownership must always be resolved from
// the stable user ID, never from a display name (ADR-0004 G1).
type UserLookup interface {
	GetByID(ctx context.Context, userID identity.UserID) (identity.User, error)
}

// CreateResult is the outcome of creating an application with its initial
// client. ClientSecret is non-empty only for confidential clients; it is
// shown exactly once and never persisted.
type CreateResult struct {
	ApplicationID ApplicationID
	ClientID      OAuthClientID
	ClientSecret  string
}

// ClientCreateResult is the outcome of adding a client to an existing
// application. ClientSecret is non-empty only for confidential clients; it
// is shown exactly once and never persisted.
type ClientCreateResult struct {
	ClientID     OAuthClientID
	ClientSecret string
}

// SecretRotationResult is the outcome of a successful secret rotation. The
// new secret appears exactly once and is never persisted; the secret ID and
// the previous-secret expiry are durable metadata (ADR-0004 §6).
type SecretRotationResult struct {
	SecretID                ClientSecretID
	ClientSecret            string
	PreviousSecretExpiresAt time.Time
}

// Detail is the application detail projection: the application, its fully
// provisioned clients and the audit trail actually recorded for it.
type Detail struct {
	Application
	Clients      []OAuthClient
	AuditEntries []AuditEntry
}

// Service orchestrates the OAuth application management plane use cases.
// It owns the cross-store sequencing rules of ADR-0004 §2: local rows are
// committed before provider calls, provider calls run outside any database
// transaction, and partial failures enter compensation or reconciliation.
type Service struct {
	store             ApplicationStore
	provisioner       OAuthClientProvisioner
	events            SecurityEventRecorder
	audits            AuditReader
	users             UserLookup
	providerName      string
	providerProjectID string
	// rotationGracePeriod is the overlap window added to the rotation
	// timestamp for previousSecretExpiresAt. Against ZITADEL v2.71 the
	// effective grace period is zero (ADR-0004 §6).
	rotationGracePeriod time.Duration
	now                 func() time.Time
}

// NewService builds the application management service. providerName and
// providerProjectID are recorded on provisioned clients as mapping columns;
// rotationGracePeriod shapes previousSecretExpiresAt on secret rotation.
func NewService(
	store ApplicationStore,
	provisioner OAuthClientProvisioner,
	events SecurityEventRecorder,
	audits AuditReader,
	users UserLookup,
	providerName, providerProjectID string,
	rotationGracePeriod time.Duration,
) *Service {
	return &Service{
		store:               store,
		provisioner:         provisioner,
		events:              events,
		audits:              audits,
		users:               users,
		providerName:        providerName,
		providerProjectID:   providerProjectID,
		rotationGracePeriod: rotationGracePeriod,
		now: func() time.Time {
			return time.Now().UTC()
		},
	}
}

// ErrorClassFor maps a use-case error onto the safe, stable failure class
// recorded in operations and audit rows. Raw provider detail is never used.
func ErrorClassFor(err error) string {
	switch {
	case errors.Is(err, ErrProviderConflict):
		return "provider_conflict"
	case errors.Is(err, ErrProviderUnavailable):
		return "provider_unavailable"
	case errors.Is(err, ErrNotFound):
		return "not_found"
	case errors.Is(err, ErrConflict):
		return "state_conflict"
	case errors.Is(err, ErrInvalidStateTransition):
		return "invalid_state_transition"
	default:
		return "internal"
	}
}

// CreateWithInitialClient creates an application together with its initial
// OAuth client — the only creation path in Phase 2. Local rows are committed
// first (provisioning), the provider call runs outside any transaction, and
// provider identifiers plus secret metadata are recorded afterwards. The raw
// secret is returned exactly once and never persisted.
func (s *Service) CreateWithInitialClient(
	ctx context.Context,
	actor identity.UserID,
	requestID string,
	appIn ApplicationInput,
	clientIn ClientInput,
) (CreateResult, error) {
	// Ownership is resolved from the stable user ID only (G1).
	if _, err := s.users.GetByID(ctx, identity.UserID(appIn.OwnerID)); err != nil {
		if errors.Is(err, identity.ErrUserNotFound) {
			return CreateResult{}, ErrOwnerNotFound
		}
		return CreateResult{}, err
	}

	rules, ok := clientIn.Profile.Rules()
	if !ok {
		return CreateResult{}, ErrInvalidStateTransition
	}

	now := s.now()
	appID := NewApplicationID()
	clientID := NewOAuthClientID()
	opID := NewProviderOperationID()

	uris := make([]RedirectURI, len(clientIn.RedirectURIs))
	for i, u := range clientIn.RedirectURIs {
		isLoopback, _ := ValidateRedirectURI(u)
		uris[i] = RedirectURI{URI: u, IsLoopback: isLoopback, AddedAt: now}
	}

	app := Application{
		ID:           appID,
		Name:         strings.TrimSpace(appIn.Name),
		Description:  appIn.Description,
		Audience:     appIn.Audience,
		OwnerID:      identity.UserID(appIn.OwnerID),
		Status:       StatusActive,
		Provisioning: ProvisioningStatusProvisioning,
		Version:      1,
		CreatedAt:    now,
		UpdatedAt:    now,
	}
	client := OAuthClient{
		ID:                clientID,
		ApplicationID:     appID,
		Name:              strings.TrimSpace(clientIn.Name),
		Profile:           clientIn.Profile,
		ClientType:        rules.ClientType,
		TokenEndpointAuth: rules.TokenEndpointAuth,
		ConsentMode:       clientIn.ConsentMode,
		Status:            StatusActive,
		RedirectURIs:      uris,
		LogoutURI:         clientIn.LogoutURI,
		Scopes:            clientIn.Scopes,
		Provisioning:      ProvisioningStatusProvisioning,
		Version:           1,
		CreatedAt:         now,
		UpdatedAt:         now,
	}
	op := ProviderOperation{
		ID:             opID,
		Type:           ProviderOperationProvision,
		ApplicationID:  appID,
		ClientID:       clientID,
		IdempotencyKey: "provision:" + string(clientID),
		Status:         ProviderOperationPending,
	}

	if err := s.store.CreateApplicationWithInitialClient(ctx, app, client, op); err != nil {
		return CreateResult{}, err
	}

	// Provider call outside any database transaction.
	result, err := s.provisioner.ProvisionClient(ctx, op.IdempotencyKey, ClientProvisionSpec{
		DisplayName:  client.Name,
		Profile:      client.Profile,
		RedirectURIs: clientIn.RedirectURIs,
		LogoutURI:    clientIn.LogoutURI,
		Scopes:       clientIn.Scopes,
	})
	if err != nil {
		// Failed rows stay hidden from all listings; the failure class is
		// the only recorded detail.
		_ = s.store.MarkInitialProvisioningFailed(ctx, appID, clientID, opID, ErrorClassFor(err))
		if errors.Is(err, ErrProviderConflict) {
			return CreateResult{}, ErrProviderConflict
		}
		return CreateResult{}, ErrProviderUnavailable
	}

	var secret *ClientSecretRecord
	if result.ClientSecret != "" {
		secret = &ClientSecretRecord{
			ID:        NewClientSecretID(),
			ClientID:  clientID,
			Label:     "初始 Secret",
			CreatedAt: now,
		}
	}
	if err := s.store.CompleteInitialProvisioning(ctx, appID, clientID,
		s.providerName, s.providerProjectID,
		result.ProviderApplicationID, result.ProviderClientID, opID, secret); err != nil {
		// Provider succeeded but the local completion failed: compensate by
		// removing the provider resource, or hand it to reconciliation.
		s.compensateProvision(ctx, actor, appID, clientID, result.ProviderApplicationID, requestID)
		return CreateResult{}, err
	}

	s.RecordEvent(ctx, EventApplicationCreated, actor, appID, "", requestID,
		"application.create", SecurityEventSuccess, "")
	s.RecordEvent(ctx, EventOAuthClientCreated, actor, appID, clientID, requestID,
		"client.create", SecurityEventSuccess, "")

	return CreateResult{
		ApplicationID: appID,
		ClientID:      clientID,
		ClientSecret:  result.ClientSecret,
	}, nil
}

// compensateProvision removes a provider resource whose local completion
// failed. When the compensation itself fails, a reconciliation job is
// recorded — never a silent leak.
func (s *Service) compensateProvision(
	ctx context.Context,
	actor identity.UserID,
	appID ApplicationID,
	clientID OAuthClientID,
	providerApplicationID string,
	requestID string,
) {
	if providerApplicationID == "" {
		return
	}
	if err := s.provisioner.DeleteClient(ctx, providerApplicationID); err != nil {
		_ = s.store.SetClientReconciliationRequired(ctx, clientID)
		_ = s.store.CreateReconciliationJob(ctx, ReconciliationJob{
			ID:                    NewProviderOperationID(),
			ApplicationID:         appID,
			ClientID:              clientID,
			ProviderApplicationID: providerApplicationID,
			Reason:                ErrorClassFor(err),
		})
		s.RecordEvent(ctx, EventProviderReconciliationNeed, actor, appID, clientID, requestID,
			"client.provision_compensation", SecurityEventSuccess, ErrorClassFor(err))
	}
}

// List returns one page of fully provisioned applications.
func (s *Service) List(ctx context.Context, q ListQuery) (ListResult, error) {
	return s.store.ListApplications(ctx, q)
}

// CreateClient adds a new OAuth client to an existing, fully provisioned
// application. It follows the same cross-store sequence as the initial
// client: local row first (provisioning), provider call outside any
// transaction, then completion or compensation. The raw secret is returned
// exactly once and never persisted.
func (s *Service) CreateClient(
	ctx context.Context,
	actor identity.UserID,
	appID ApplicationID,
	requestID string,
	clientIn ClientInput,
) (ClientCreateResult, error) {
	// Applications that never finished provisioning are invisible
	// (anti-enumeration); GetApplication yields ErrNotFound for them.
	if _, err := s.store.GetApplication(ctx, appID); err != nil {
		return ClientCreateResult{}, err
	}

	rules, ok := clientIn.Profile.Rules()
	if !ok {
		return ClientCreateResult{}, ErrInvalidStateTransition
	}

	now := s.now()
	clientID := NewOAuthClientID()
	opID := NewProviderOperationID()

	uris := make([]RedirectURI, len(clientIn.RedirectURIs))
	for i, u := range clientIn.RedirectURIs {
		isLoopback, _ := ValidateRedirectURI(u)
		uris[i] = RedirectURI{URI: u, IsLoopback: isLoopback, AddedAt: now}
	}

	client := OAuthClient{
		ID:                clientID,
		ApplicationID:     appID,
		Name:              strings.TrimSpace(clientIn.Name),
		Profile:           clientIn.Profile,
		ClientType:        rules.ClientType,
		TokenEndpointAuth: rules.TokenEndpointAuth,
		ConsentMode:       clientIn.ConsentMode,
		Status:            StatusActive,
		RedirectURIs:      uris,
		LogoutURI:         clientIn.LogoutURI,
		Scopes:            clientIn.Scopes,
		Provisioning:      ProvisioningStatusProvisioning,
		Version:           1,
		CreatedAt:         now,
		UpdatedAt:         now,
	}
	op := ProviderOperation{
		ID:             opID,
		Type:           ProviderOperationProvision,
		ApplicationID:  appID,
		ClientID:       clientID,
		IdempotencyKey: "provision:" + string(clientID),
		Status:         ProviderOperationPending,
	}

	if err := s.store.CreateClientWithOperation(ctx, client, op); err != nil {
		return ClientCreateResult{}, err
	}

	// Provider call outside any database transaction.
	result, err := s.provisioner.ProvisionClient(ctx, op.IdempotencyKey, ClientProvisionSpec{
		DisplayName:  client.Name,
		Profile:      client.Profile,
		RedirectURIs: clientIn.RedirectURIs,
		LogoutURI:    clientIn.LogoutURI,
		Scopes:       clientIn.Scopes,
	})
	if err != nil {
		_ = s.store.MarkClientProvisioningFailed(ctx, clientID, opID, ErrorClassFor(err))
		if errors.Is(err, ErrProviderConflict) {
			return ClientCreateResult{}, ErrProviderConflict
		}
		return ClientCreateResult{}, ErrProviderUnavailable
	}

	var secret *ClientSecretRecord
	if result.ClientSecret != "" {
		secret = &ClientSecretRecord{
			ID:        NewClientSecretID(),
			ClientID:  clientID,
			Label:     "初始 Secret",
			CreatedAt: now,
		}
	}
	if err := s.store.CompleteClientProvisioning(ctx, clientID,
		s.providerName, s.providerProjectID,
		result.ProviderApplicationID, result.ProviderClientID, opID, secret); err != nil {
		s.compensateProvision(ctx, actor, appID, clientID, result.ProviderApplicationID, requestID)
		return ClientCreateResult{}, err
	}

	s.RecordEvent(ctx, EventOAuthClientCreated, actor, appID, clientID, requestID,
		"client.create", SecurityEventSuccess, "")

	return ClientCreateResult{
		ClientID:     clientID,
		ClientSecret: result.ClientSecret,
	}, nil
}

// GetClient loads one fully provisioned client bound to the application.
// Missing, unbound or not yet provisioned clients yield ErrNotFound
// (anti-enumeration).
func (s *Service) GetClient(ctx context.Context, appID ApplicationID, clientID OAuthClientID) (OAuthClient, error) {
	return s.store.GetClient(ctx, appID, clientID)
}

// UpdateClient applies a partial client configuration update. Submitted
// fields are merged onto the stored client and validated against the
// immutable profile (ADR-0004 §3). Provider-owned settings (name, redirect
// URIs, logout URI) are synchronized to the provider first: on provider
// failure the local state is left unchanged (fail closed). A local write
// failure after provider success is handed to reconciliation.
func (s *Service) UpdateClient(
	ctx context.Context,
	actor identity.UserID,
	appID ApplicationID,
	clientID OAuthClientID,
	requestID string,
	patch ClientPatch,
) (OAuthClient, error) {
	client, err := s.store.GetClient(ctx, appID, clientID)
	if err != nil {
		return OAuthClient{}, err
	}

	name := client.Name
	logoutURI := client.LogoutURI
	consentMode := client.ConsentMode
	uriStrings := make([]string, len(client.RedirectURIs))
	for i, u := range client.RedirectURIs {
		uriStrings[i] = u.URI
	}
	scopes := append([]string(nil), client.Scopes...)

	if patch.Name != nil {
		name = strings.TrimSpace(*patch.Name)
	}
	if patch.RedirectURIs != nil {
		uriStrings = *patch.RedirectURIs
	}
	if patch.LogoutURI != nil {
		logoutURI = *patch.LogoutURI
	}
	if patch.AllowedScopes != nil {
		scopes = *patch.AllowedScopes
	}
	if patch.ConsentMode != nil {
		consentMode = *patch.ConsentMode
	}

	// The merged result is validated against the stored profile; submitted
	// values are never silently mutated.
	if err := ValidateClientInput(ClientInput{
		Name:         name,
		Profile:      client.Profile,
		RedirectURIs: uriStrings,
		LogoutURI:    logoutURI,
		Scopes:       scopes,
		ConsentMode:  consentMode,
	}); err != nil {
		return OAuthClient{}, err
	}

	providerSync := patch.Name != nil || patch.RedirectURIs != nil || patch.LogoutURI != nil
	if providerSync && client.ProviderApplicationID != "" {
		if err := s.provisioner.UpdateClient(ctx, client.ProviderApplicationID, ClientUpdateSpec{
			DisplayName:  name,
			RedirectURIs: uriStrings,
			LogoutURI:    logoutURI,
		}); err != nil {
			return OAuthClient{}, err
		}
	}

	upd := ClientConfigUpdate{
		Name:        name,
		LogoutURI:   logoutURI,
		ConsentMode: consentMode,
	}
	if patch.RedirectURIs != nil {
		now := s.now()
		upd.RedirectURIs = make([]RedirectURI, len(uriStrings))
		for i, u := range uriStrings {
			isLoopback, _ := ValidateRedirectURI(u)
			upd.RedirectURIs[i] = RedirectURI{URI: u, IsLoopback: isLoopback, AddedAt: now}
		}
	}
	if patch.AllowedScopes != nil {
		upd.Scopes = scopes
	}

	if err := s.store.UpdateClientConfig(ctx, clientID, upd, client.Version); err != nil {
		if providerSync && client.ProviderApplicationID != "" {
			// The provider already has the new settings; record the drift
			// instead of leaking it silently.
			_ = s.store.SetClientReconciliationRequired(ctx, clientID)
			_ = s.store.CreateReconciliationJob(ctx, ReconciliationJob{
				ID:                    NewProviderOperationID(),
				ApplicationID:         appID,
				ClientID:              clientID,
				ProviderApplicationID: client.ProviderApplicationID,
				Reason:                ErrorClassFor(err),
			})
			s.RecordEvent(ctx, EventProviderReconciliationNeed, actor, appID, clientID, requestID,
				"client.update", SecurityEventSuccess, ErrorClassFor(err))
		}
		return OAuthClient{}, err
	}

	s.RecordEvent(ctx, EventOAuthClientUpdated, actor, appID, clientID, requestID,
		"client.update", SecurityEventSuccess, "")

	return s.store.GetClient(ctx, appID, clientID)
}

// SetClientStatus enables or disables one client. The provider-side state is
// synchronized first; on provider failure the local status is left unchanged
// (fail closed).
func (s *Service) SetClientStatus(
	ctx context.Context,
	actor identity.UserID,
	appID ApplicationID,
	clientID OAuthClientID,
	requestID string,
	enable bool,
) (OAuthClient, error) {
	client, err := s.store.GetClient(ctx, appID, clientID)
	if err != nil {
		return OAuthClient{}, err
	}

	target := StatusDisabled
	eventType := EventOAuthClientDisabled
	operation := "client.disable"
	if enable {
		if err := client.Enable(); err != nil {
			return OAuthClient{}, err
		}
		target = StatusActive
		eventType = EventOAuthClientEnabled
		operation = "client.enable"
	} else {
		if err := client.Disable(); err != nil {
			return OAuthClient{}, err
		}
	}

	if client.ProviderApplicationID != "" {
		if enable {
			err = s.provisioner.EnableClient(ctx, client.ProviderApplicationID)
		} else {
			err = s.provisioner.DisableClient(ctx, client.ProviderApplicationID)
		}
		if err != nil {
			return OAuthClient{}, err
		}
	}

	if err := s.store.SetClientStatus(ctx, clientID, target, client.Version); err != nil {
		return OAuthClient{}, err
	}

	s.RecordEvent(ctx, eventType, actor, appID, clientID, requestID, operation,
		SecurityEventSuccess, "")

	return s.store.GetClient(ctx, appID, clientID)
}

// DeleteClient removes one client using the delete state machine: local row
// marked deleting, provider removal (idempotent), then local deletion. A
// provider failure aborts the deletion and leaves a reconciliation trail.
func (s *Service) DeleteClient(
	ctx context.Context,
	actor identity.UserID,
	appID ApplicationID,
	clientID OAuthClientID,
	requestID string,
) error {
	// The live lookup includes deleting/delete_failed rows so failed
	// deletions can be retried; fully provisioned lookups hide them.
	clients, err := s.store.ListLiveClientsByApplication(ctx, appID)
	if err != nil {
		return err
	}
	for _, c := range clients {
		if c.ID == clientID {
			return s.deleteClient(ctx, actor, appID, c, requestID)
		}
	}
	return ErrNotFound
}

// Get loads the application detail projection. Missing or not yet
// provisioned applications yield ErrNotFound (anti-enumeration).
func (s *Service) Get(ctx context.Context, appID ApplicationID) (Detail, error) {
	app, err := s.store.GetApplication(ctx, appID)
	if err != nil {
		return Detail{}, err
	}
	clients, err := s.store.ListClientsByApplication(ctx, appID)
	if err != nil {
		return Detail{}, err
	}
	audits, err := s.audits.ListByApplication(ctx, appID)
	if err != nil {
		return Detail{}, err
	}
	return Detail{Application: app, Clients: clients, AuditEntries: audits}, nil
}

// UpdateApplication applies a partial metadata update with optimistic
// concurrency. It performs a read-modify-write cycle: submitted fields are
// merged onto the loaded application, validated, then written conditionally
// on the loaded version.
func (s *Service) UpdateApplication(
	ctx context.Context,
	actor identity.UserID,
	appID ApplicationID,
	requestID string,
	patch ApplicationPatch,
) (Application, error) {
	app, err := s.store.GetApplication(ctx, appID)
	if err != nil {
		return Application{}, err
	}

	name := app.Name
	description := app.Description
	audience := app.Audience
	ownerID := app.OwnerID
	if patch.Name != nil {
		name = strings.TrimSpace(*patch.Name)
	}
	if patch.Description != nil {
		description = *patch.Description
	}
	if patch.Audience != nil {
		audience = *patch.Audience
	}
	if patch.OwnerID != nil {
		ownerID = *patch.OwnerID
		if _, err := s.users.GetByID(ctx, ownerID); err != nil {
			if errors.Is(err, identity.ErrUserNotFound) {
				return Application{}, ErrOwnerNotFound
			}
			return Application{}, err
		}
	}

	if err := ValidateApplicationInput(ApplicationInput{
		Name:        name,
		Description: description,
		Audience:    audience,
		OwnerID:     string(ownerID),
	}); err != nil {
		return Application{}, err
	}

	err = s.store.UpdateApplication(ctx, appID, ApplicationUpdate{
		Name:        name,
		Description: description,
		Audience:    audience,
		OwnerID:     ownerID,
	}, app.Version)
	if err != nil {
		return Application{}, err
	}

	s.RecordEvent(ctx, EventApplicationUpdated, actor, appID, "", requestID,
		"application.update", SecurityEventSuccess, "")

	return s.store.GetApplication(ctx, appID)
}

// SetStatus enables or disables an application. The provider-side state is
// synchronized first for every provisioned client: on provider failure the
// local status is left unchanged (fail closed). Disabling disables all
// clients at the provider; enabling re-enables only clients whose local
// status is active.
func (s *Service) SetStatus(
	ctx context.Context,
	actor identity.UserID,
	appID ApplicationID,
	requestID string,
	enable bool,
) error {
	app, err := s.store.GetApplication(ctx, appID)
	if err != nil {
		return err
	}
	target := StatusDisabled
	eventType := EventApplicationDisabled
	operation := "application.disable"
	if enable {
		if err := app.Enable(); err != nil {
			return err
		}
		target = StatusActive
		eventType = EventApplicationEnabled
		operation = "application.enable"
	} else {
		if err := app.Disable(); err != nil {
			return err
		}
	}

	clients, err := s.store.ListClientsByApplication(ctx, appID)
	if err != nil {
		return err
	}
	for _, c := range clients {
		if c.ProviderApplicationID == "" {
			continue
		}
		if enable {
			// Clients individually disabled stay disabled.
			if c.Status != StatusActive {
				continue
			}
			err = s.provisioner.EnableClient(ctx, c.ProviderApplicationID)
		} else {
			err = s.provisioner.DisableClient(ctx, c.ProviderApplicationID)
		}
		if err != nil {
			return err
		}
	}

	if err := s.store.SetApplicationStatus(ctx, appID, target, app.Version); err != nil {
		return err
	}

	s.RecordEvent(ctx, eventType, actor, appID, "", requestID, operation,
		SecurityEventSuccess, "")
	return nil
}

// Delete removes an application and all of its clients. Every live client is
// deleted at the provider first (idempotent); a provider failure aborts the
// application deletion and leaves a reconciliation trail. Already deleted
// clients never block the application deletion.
func (s *Service) Delete(
	ctx context.Context,
	actor identity.UserID,
	appID ApplicationID,
	requestID string,
) error {
	app, err := s.store.GetApplication(ctx, appID)
	if err != nil {
		return err
	}
	clients, err := s.store.ListLiveClientsByApplication(ctx, appID)
	if err != nil {
		return err
	}
	for _, c := range clients {
		if err := s.deleteClient(ctx, actor, appID, c, requestID); err != nil {
			return err
		}
	}
	if err := s.store.DeleteApplication(ctx, appID, app.Version); err != nil {
		return err
	}
	s.RecordEvent(ctx, EventApplicationDeleted, actor, appID, "", requestID,
		"application.delete", SecurityEventSuccess, "")
	return nil
}

// deleteClient runs the delete state machine for one client. It is shared
// by standalone client deletion and application deletion. Clients whose
// provisioning never completed are deleted idempotently too: their provider
// resource may exist after an ambiguous timeout.
func (s *Service) deleteClient(
	ctx context.Context,
	actor identity.UserID,
	appID ApplicationID,
	c OAuthClient,
	requestID string,
) error {
	opID := NewProviderOperationID()
	op := ProviderOperation{
		ID:             opID,
		Type:           ProviderOperationDelete,
		ApplicationID:  appID,
		ClientID:       c.ID,
		IdempotencyKey: "delete:" + string(opID),
		Status:         ProviderOperationPending,
	}

	switch c.Provisioning {
	case ProvisioningStatusDeleting:
		// Another deletion is already in flight.
		return ErrConflict
	case ProvisioningStatusDeleteFailed:
		if err := s.store.MarkClientDeletingRetry(ctx, c.ID, op); err != nil {
			return err
		}
	default:
		if err := s.store.MarkClientDeleting(ctx, c.ID, op); err != nil {
			return err
		}
	}

	if c.ProviderApplicationID != "" {
		if err := s.provisioner.DeleteClient(ctx, c.ProviderApplicationID); err != nil {
			_ = s.store.MarkClientDeleteFailed(ctx, c.ID, opID, ErrorClassFor(err))
			_ = s.store.SetClientReconciliationRequired(ctx, c.ID)
			_ = s.store.CreateReconciliationJob(ctx, ReconciliationJob{
				ID:                    NewProviderOperationID(),
				ApplicationID:         appID,
				ClientID:              c.ID,
				ProviderApplicationID: c.ProviderApplicationID,
				Reason:                ErrorClassFor(err),
			})
			s.RecordEvent(ctx, EventProviderReconciliationNeed, actor, appID, c.ID, requestID,
				"client.delete", SecurityEventSuccess, ErrorClassFor(err))
			return err
		}
	}

	if err := s.store.CompleteClientDeletion(ctx, c.ID, opID); err != nil {
		return err
	}
	s.RecordEvent(ctx, EventOAuthClientDeleted, actor, appID, c.ID, requestID,
		"client.delete", SecurityEventSuccess, "")
	return nil
}

// RotateClientSecret regenerates a confidential client's secret at the
// provider (ADR-0004 §6). The single-winner gate is acquired locally before
// any provider call; a provider failure never revokes the previous secret.
// If the provider succeeds but local metadata cannot be updated, a
// reconciliation trail is left and the error is surfaced. The new secret is
// returned exactly once and never persisted.
func (s *Service) RotateClientSecret(
	ctx context.Context,
	actor identity.UserID,
	appID ApplicationID,
	clientID OAuthClientID,
	requestID string,
) (SecretRotationResult, error) {
	c, err := s.store.GetClient(ctx, appID, clientID)
	if err != nil {
		return SecretRotationResult{}, err
	}
	if !c.CanRotateSecret() {
		s.RecordEvent(ctx, EventSecretRotationFailed, actor, appID, clientID, requestID,
			"client.secret.rotate", SecurityEventDenied, "invalid_state_transition")
		return SecretRotationResult{}, ErrSecretRotationNotAllowed
	}
	if c.ProviderApplicationID == "" {
		// Fail closed: a provisioned confidential client must always have a
		// provider resource before its secret can be rotated.
		s.RecordEvent(ctx, EventSecretRotationFailed, actor, appID, clientID, requestID,
			"client.secret.rotate", SecurityEventDenied, "internal")
		return SecretRotationResult{}, ErrSecretRotationNotAllowed
	}

	// Single-winner gate: bump the optimistic-concurrency version before any
	// provider call. Concurrent rotations (or other client writes) lose here.
	if err := s.store.BeginSecretRotation(ctx, clientID, c.Version); err != nil {
		if errors.Is(err, ErrConflict) {
			s.RecordEvent(ctx, EventSecretRotationFailed, actor, appID, clientID, requestID,
				"client.secret.rotate", SecurityEventDenied, "state_conflict")
		}
		return SecretRotationResult{}, err
	}

	// Provider call outside any database transaction.
	rotation, err := s.provisioner.RotateClientSecret(ctx, c.ProviderApplicationID)
	if err != nil {
		s.RecordEvent(ctx, EventSecretRotationFailed, actor, appID, clientID, requestID,
			"client.secret.rotate", SecurityEventDenied, ErrorClassFor(err))
		if errors.Is(err, ErrProviderConflict) {
			return SecretRotationResult{}, ErrProviderConflict
		}
		return SecretRotationResult{}, ErrProviderUnavailable
	}

	now := s.now()
	// Stamp the currently active secret record (records are returned newest
	// first; the active one has no rotation timestamp yet).
	records, err := s.store.GetClientSecretRecords(ctx, clientID)
	if err != nil {
		s.recordRotationReconciliation(ctx, actor, appID, c, requestID, "internal")
		return SecretRotationResult{}, err
	}
	for _, rec := range records {
		if rec.LastRotatedAt == nil {
			if err := s.store.MarkSecretRotated(ctx, rec.ID, now); err != nil {
				s.recordRotationReconciliation(ctx, actor, appID, c, requestID, "internal")
				return SecretRotationResult{}, err
			}
			break
		}
	}

	newRec := ClientSecretRecord{
		ID:        NewClientSecretID(),
		ClientID:  clientID,
		Label:     "轮转 Secret",
		CreatedAt: now,
	}
	if err := s.store.CreateSecretRecord(ctx, newRec); err != nil {
		s.recordRotationReconciliation(ctx, actor, appID, c, requestID, "internal")
		return SecretRotationResult{}, err
	}

	s.RecordEvent(ctx, EventSecretRotated, actor, appID, clientID, requestID,
		"client.secret.rotate", SecurityEventSuccess, "")
	return SecretRotationResult{
		SecretID:     newRec.ID,
		ClientSecret: rotation.NewSecret,
		// ZITADEL v2.71 has no grace period; the expiry is the rotation
		// timestamp plus the configured overlap window (default zero).
		PreviousSecretExpiresAt: now.Add(s.rotationGracePeriod),
	}, nil
}

// recordRotationReconciliation leaves a reconciliation trail after the
// provider rotation succeeded but local secret metadata could not be
// updated (ADR-0004 §6).
func (s *Service) recordRotationReconciliation(
	ctx context.Context,
	actor identity.UserID,
	appID ApplicationID,
	c OAuthClient,
	requestID, reason string,
) {
	_ = s.store.SetClientReconciliationRequired(ctx, c.ID)
	_ = s.store.CreateReconciliationJob(ctx, ReconciliationJob{
		ID:                    NewProviderOperationID(),
		ApplicationID:         appID,
		ClientID:              c.ID,
		ProviderApplicationID: c.ProviderApplicationID,
		Reason:                reason,
	})
	s.RecordEvent(ctx, EventProviderReconciliationNeed, actor, appID, c.ID, requestID,
		"client.secret.rotate", SecurityEventSuccess, reason)
}

// RecordEvent persists one audit row. Audit recording is best-effort at the
// call site: a failure here must not mask the real operation outcome, and
// the event payload never contains secrets or raw provider detail.
func (s *Service) RecordEvent(
	ctx context.Context,
	eventType string,
	actor identity.UserID,
	appID ApplicationID,
	clientID OAuthClientID,
	requestID, operation string,
	result SecurityEventResult,
	failureClass string,
) {
	if s.events == nil {
		return
	}
	_ = s.events.Record(ctx, SecurityEvent{
		EventID:       NewSecurityEventID(),
		EventType:     eventType,
		ActorUserID:   actor,
		ApplicationID: appID,
		ClientID:      clientID,
		RequestID:     requestID,
		Operation:     operation,
		Result:        result,
		FailureClass:  failureClass,
		OccurredAt:    s.now(),
	})
}
