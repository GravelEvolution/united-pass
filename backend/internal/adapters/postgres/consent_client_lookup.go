package postgres

import (
	"context"
	"errors"
	"fmt"

	"github.com/jackc/pgx/v5"

	"github.com/GravelEvolution/united-pass/backend/internal/applications"
	"github.com/GravelEvolution/united-pass/backend/internal/consent"
	"github.com/GravelEvolution/united-pass/backend/internal/identity"
)

// ResolveConsentClient maps a provider client identity to the local client
// + application records for consent resolution (ADR-0005 §4, §7). The
// unique partial index uq_oauth_clients_provider_client makes this an
// index lookup; both records must be live (not soft-deleted) and fully
// provisioned, otherwise the request is indistinguishable from an unknown
// client (anti-enumeration). Effective status (application × client) is
// validated by the resolution service so the precise denial reason stays
// available to audit in later milestones.
func (r *ApplicationRepository) ResolveConsentClient(
	ctx context.Context,
	provider, providerClientID string,
) (consent.ConsentClientFacts, error) {
	if provider == "" || providerClientID == "" {
		return consent.ConsentClientFacts{}, consent.ErrClientUnknown
	}
	row := r.pool.QueryRow(ctx,
		`SELECT c.client_id, c.application_id, c.name, c.profile, c.client_type,
		        c.token_endpoint_auth_method, c.consent_mode, c.logout_uri, c.status,
		        c.provider, c.provider_project_id, c.provider_application_id,
		        c.provider_client_id, c.provisioning_status, c.version, c.created_at, c.updated_at,
		        a.application_id, a.name, a.description, a.logo_url, a.audience,
		        a.owner_user_id, u.display_name, a.status, a.provisioning_status,
		        a.version, a.created_at, a.updated_at
		   FROM oauth_clients c
		   JOIN oauth_applications a ON a.application_id = c.application_id
		   JOIN users u ON u.id = a.owner_user_id
		  WHERE c.provider = $1 AND c.provider_client_id = $2
		    AND c.deleted_at IS NULL AND c.provisioning_status = 'provisioned'
		    AND a.deleted_at IS NULL AND a.provisioning_status = 'provisioned'`,
		provider, providerClientID)

	var (
		client                                                      applications.OAuthClient
		app                                                         applications.Application
		clientID, appID, profile, clientType, tokenAuth             string
		consentMode, clientStatus, provName, provProject, provAppID string
		clientProvisioning                                          string
		appID2, audience, ownerID, ownerName, appStatus, appProv    string
	)
	err := row.Scan(
		&clientID, &appID, &client.Name, &profile, &clientType,
		&tokenAuth, &consentMode, &client.LogoutURI, &clientStatus,
		&provName, &provProject, &provAppID, &client.ProviderClientID,
		&clientProvisioning, &client.Version, &client.CreatedAt, &client.UpdatedAt,
		&appID2, &app.Name, &app.Description, &app.LogoURL, &audience,
		&ownerID, &ownerName, &appStatus, &appProv,
		&app.Version, &app.CreatedAt, &app.UpdatedAt,
	)
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return consent.ConsentClientFacts{}, consent.ErrClientUnknown
		}
		return consent.ConsentClientFacts{}, fmt.Errorf("postgres: resolve consent client: %w", err)
	}

	client.ID = applications.OAuthClientID(clientID)
	client.ApplicationID = applications.ApplicationID(appID)
	client.Profile = applications.ClientProfile(profile)
	client.ClientType = applications.ClientType(clientType)
	client.TokenEndpointAuth = applications.TokenEndpointAuthMethod(tokenAuth)
	client.ConsentMode = applications.ConsentMode(consentMode)
	client.Status = applications.Status(clientStatus)
	client.Provider = provName
	client.ProviderProjectID = provProject
	client.ProviderApplicationID = provAppID
	client.Provisioning = applications.ProvisioningStatus(clientProvisioning)

	app.ID = applications.ApplicationID(appID2)
	app.Audience = applications.ApplicationAudience(audience)
	app.OwnerID = identity.UserID(ownerID)
	app.OwnerName = ownerName
	app.Status = applications.Status(appStatus)
	app.Provisioning = applications.ProvisioningStatus(appProv)

	if err := r.hydrateClient(ctx, &client); err != nil {
		return consent.ConsentClientFacts{}, err
	}

	return consent.ConsentClientFacts{Client: client, Application: app}, nil
}
