package zitadel

import (
	"context"
	"errors"
	"fmt"
	"log/slog"

	"github.com/GravelEvolution/united-pass/backend/internal/applications"

	appv1 "github.com/zitadel/zitadel-go/v3/pkg/client/zitadel/app"
	management "github.com/zitadel/zitadel-go/v3/pkg/client/zitadel/management"
	objectv1 "github.com/zitadel/zitadel-go/v3/pkg/client/zitadel/object"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

// managementService is the subset of the ZITADEL Management API (v1) the
// provisioner uses. It is an interface so tests can substitute a stub. All
// calls operate on the shared ZITADEL project configured via
// UP_AUTH_PROVIDER_PROJECT_ID (ADR-0004 §1).
type managementService interface {
	GetProjectByID(ctx context.Context, in *management.GetProjectByIDRequest, opts ...grpc.CallOption) (*management.GetProjectByIDResponse, error)
	ListApps(ctx context.Context, in *management.ListAppsRequest, opts ...grpc.CallOption) (*management.ListAppsResponse, error)
	GetAppByID(ctx context.Context, in *management.GetAppByIDRequest, opts ...grpc.CallOption) (*management.GetAppByIDResponse, error)
	AddOIDCApp(ctx context.Context, in *management.AddOIDCAppRequest, opts ...grpc.CallOption) (*management.AddOIDCAppResponse, error)
	UpdateApp(ctx context.Context, in *management.UpdateAppRequest, opts ...grpc.CallOption) (*management.UpdateAppResponse, error)
	UpdateOIDCAppConfig(ctx context.Context, in *management.UpdateOIDCAppConfigRequest, opts ...grpc.CallOption) (*management.UpdateOIDCAppConfigResponse, error)
	DeactivateApp(ctx context.Context, in *management.DeactivateAppRequest, opts ...grpc.CallOption) (*management.DeactivateAppResponse, error)
	ReactivateApp(ctx context.Context, in *management.ReactivateAppRequest, opts ...grpc.CallOption) (*management.ReactivateAppResponse, error)
	RemoveApp(ctx context.Context, in *management.RemoveAppRequest, opts ...grpc.CallOption) (*management.RemoveAppResponse, error)
	RegenerateOIDCClientSecret(ctx context.Context, in *management.RegenerateOIDCClientSecretRequest, opts ...grpc.CallOption) (*management.RegenerateOIDCClientSecretResponse, error)
}

// Provisioner implements applications.OAuthClientProvisioner against the
// ZITADEL Management API.
//
// SECURITY: client secrets returned by the provider travel straight into the
// one-time API response; they are never logged, persisted or included in
// errors (ADR-0004 §6). Provider errors are reduced to stable error classes
// before leaving the adapter.
type Provisioner struct {
	mgmt      managementService
	projectID string
	logger    *slog.Logger
}

// NewProvisioner builds the provisioner. projectID must be the configured
// shared ZITADEL project; an empty value fails closed.
func NewProvisioner(mgmt managementService, projectID string, logger *slog.Logger) (*Provisioner, error) {
	if projectID == "" {
		return nil, errors.New("zitadel: provisioner requires UP_AUTH_PROVIDER_PROJECT_ID")
	}
	if logger == nil {
		logger = slog.Default()
	}
	return &Provisioner{mgmt: mgmt, projectID: projectID, logger: logger}, nil
}

// VerifyProject confirms the configured project is readable with the service
// account's permissions. Wire it into readiness so a misconfigured provisioner
// fails closed instead of surfacing as 5xx on first use (ADR-0004 §1).
func (p *Provisioner) VerifyProject(ctx context.Context) error {
	if _, err := p.mgmt.GetProjectByID(ctx, &management.GetProjectByIDRequest{Id: p.projectID}); err != nil {
		return fmt.Errorf("%w: verify project: %s", applications.ErrProviderUnavailable, provisioningErrorClass(err))
	}
	return nil
}

// ProvisionClient creates one ZITADEL OIDC application for a United Pass
// client. The Management API has no idempotency key, so retries are guarded
// two ways: a pre-check rejects an app that already carries the display name
// (a retried create must never produce a duplicate), and AlreadyExists is
// mapped to applications.ErrProviderConflict.
func (p *Provisioner) ProvisionClient(ctx context.Context, idempotencyKey string, spec applications.ClientProvisionSpec) (applications.ClientProvisionResult, error) {
	rules, ok := spec.Profile.Rules()
	if !ok {
		return applications.ClientProvisionResult{}, fmt.Errorf("%w: unknown profile", applications.ErrProviderConflict)
	}

	// Duplicate guard for idempotent retries: an app with this name already
	// in the project means a previous attempt may have succeeded.
	exists, err := p.appExistsByName(ctx, spec.DisplayName)
	if err != nil {
		return applications.ClientProvisionResult{}, err
	}
	if exists {
		p.logFailure("provision_client", "already_exists")
		return applications.ClientProvisionResult{}, fmt.Errorf("%w: provider app name already provisioned", applications.ErrProviderConflict)
	}

	req, err := addOIDCAppRequest(p.projectID, spec, rules)
	if err != nil {
		return applications.ClientProvisionResult{}, err
	}
	resp, err := p.mgmt.AddOIDCApp(ctx, req)
	if err != nil {
		return applications.ClientProvisionResult{}, p.mapError("provision_client", err)
	}

	// Defensive: never surface a secret for a public client even if the
	// provider returns one.
	secret := resp.GetClientSecret()
	if rules.ClientType == applications.ClientTypePublic {
		secret = ""
	}
	return applications.ClientProvisionResult{
		ProviderApplicationID: resp.GetAppId(),
		ProviderClientID:      resp.GetClientId(),
		ClientSecret:          secret,
	}, nil
}

// UpdateClient synchronizes the display name and the redirect/logout URIs to
// the provider. The OIDC config update is read-modify-write: the current
// provider config is fetched first and every field this adapter does not own
// is preserved verbatim.
func (p *Provisioner) UpdateClient(ctx context.Context, providerApplicationID string, spec applications.ClientUpdateSpec) error {
	if spec.DisplayName != "" {
		if _, err := p.mgmt.UpdateApp(ctx, &management.UpdateAppRequest{
			ProjectId: p.projectID,
			AppId:     providerApplicationID,
			Name:      spec.DisplayName,
		}); err != nil {
			return p.mapError("update_client_name", err)
		}
	}

	appResp, err := p.mgmt.GetAppByID(ctx, &management.GetAppByIDRequest{
		ProjectId: p.projectID,
		AppId:     providerApplicationID,
	})
	if err != nil {
		return p.mapError("update_client_read", err)
	}
	cfg := appResp.GetApp().GetOidcConfig()
	if cfg == nil {
		// The provider app is not an OIDC app; updating it would be unsafe.
		p.logFailure("update_client", "unexpected_app_type")
		return fmt.Errorf("%w: provider app is not an OIDC application", applications.ErrProviderConflict)
	}

	postLogout := []string{}
	if spec.LogoutURI != "" {
		postLogout = []string{spec.LogoutURI}
	}
	if _, err := p.mgmt.UpdateOIDCAppConfig(ctx, &management.UpdateOIDCAppConfigRequest{
		ProjectId:              p.projectID,
		AppId:                  providerApplicationID,
		RedirectUris:           spec.RedirectURIs,
		ResponseTypes:          cfg.GetResponseTypes(),
		GrantTypes:             cfg.GetGrantTypes(),
		AppType:                cfg.GetAppType(),
		AuthMethodType:         cfg.GetAuthMethodType(),
		PostLogoutRedirectUris: postLogout,
		DevMode:                cfg.GetDevMode(),
		AccessTokenType:        cfg.GetAccessTokenType(),
	}); err != nil {
		return p.mapError("update_client_config", err)
	}
	return nil
}

// EnableClient reactivates the provider app. Already-active apps are a
// no-op so retries stay idempotent.
func (p *Provisioner) EnableClient(ctx context.Context, providerApplicationID string) error {
	state, err := p.appState(ctx, providerApplicationID)
	if err != nil {
		return err
	}
	if state == appv1.AppState_APP_STATE_ACTIVE {
		return nil
	}
	if _, err := p.mgmt.ReactivateApp(ctx, &management.ReactivateAppRequest{
		ProjectId: p.projectID,
		AppId:     providerApplicationID,
	}); err != nil {
		return p.mapError("enable_client", err)
	}
	return nil
}

// DisableClient deactivates the provider app. Already-inactive apps are a
// no-op so retries stay idempotent.
func (p *Provisioner) DisableClient(ctx context.Context, providerApplicationID string) error {
	state, err := p.appState(ctx, providerApplicationID)
	if err != nil {
		return err
	}
	if state == appv1.AppState_APP_STATE_INACTIVE {
		return nil
	}
	if _, err := p.mgmt.DeactivateApp(ctx, &management.DeactivateAppRequest{
		ProjectId: p.projectID,
		AppId:     providerApplicationID,
	}); err != nil {
		return p.mapError("disable_client", err)
	}
	return nil
}

// DeleteClient removes the provider app. An already-removed app counts as
// success (idempotent delete).
func (p *Provisioner) DeleteClient(ctx context.Context, providerApplicationID string) error {
	if _, err := p.mgmt.RemoveApp(ctx, &management.RemoveAppRequest{
		ProjectId: p.projectID,
		AppId:     providerApplicationID,
	}); err != nil {
		if st, ok := status.FromError(err); ok && st.Code() == codes.NotFound {
			return nil
		}
		return p.mapError("delete_client", err)
	}
	return nil
}

// RotateClientSecret regenerates the secret at the provider. Against
// ZITADEL v2.71 the previous secret is invalidated immediately (ADR-0004
// §6). The new secret is returned exactly once and never logged.
func (p *Provisioner) RotateClientSecret(ctx context.Context, providerApplicationID string) (applications.ClientSecretRotation, error) {
	resp, err := p.mgmt.RegenerateOIDCClientSecret(ctx, &management.RegenerateOIDCClientSecretRequest{
		ProjectId: p.projectID,
		AppId:     providerApplicationID,
	})
	if err != nil {
		return applications.ClientSecretRotation{}, p.mapError("rotate_client_secret", err)
	}
	if resp.GetClientSecret() == "" {
		p.logFailure("rotate_client_secret", "empty_secret")
		return applications.ClientSecretRotation{}, fmt.Errorf("%w: provider returned no secret", applications.ErrProviderUnavailable)
	}
	return applications.ClientSecretRotation{NewSecret: resp.GetClientSecret()}, nil
}

// --- helpers ---

// addOIDCAppRequest maps a United Pass client profile to the ZITADEL
// AddOIDCApp parameters (ADR-0004 §1). Redirect URIs are passed through
// verbatim; no normalization is ever applied.
func addOIDCAppRequest(projectID string, spec applications.ClientProvisionSpec, rules applications.ProfileRules) (*management.AddOIDCAppRequest, error) {
	req := &management.AddOIDCAppRequest{
		ProjectId:     projectID,
		Name:          spec.DisplayName,
		RedirectUris:  spec.RedirectURIs,
		ResponseTypes: []appv1.OIDCResponseType{appv1.OIDCResponseType_OIDC_RESPONSE_TYPE_CODE},
		GrantTypes:    grantTypesFor(rules),
		Version:       appv1.OIDCVersion_OIDC_VERSION_1_0,
	}
	if spec.LogoutURI != "" {
		req.PostLogoutRedirectUris = []string{spec.LogoutURI}
	}
	switch spec.Profile {
	case applications.ClientProfileWebServer, applications.ClientProfileServerToServer:
		req.AppType = appv1.OIDCAppType_OIDC_APP_TYPE_WEB
		req.AuthMethodType = appv1.OIDCAuthMethodType_OIDC_AUTH_METHOD_TYPE_BASIC
	case applications.ClientProfileSPAMobile:
		req.AppType = appv1.OIDCAppType_OIDC_APP_TYPE_USER_AGENT
		req.AuthMethodType = appv1.OIDCAuthMethodType_OIDC_AUTH_METHOD_TYPE_NONE
	default:
		return nil, fmt.Errorf("%w: unknown profile", applications.ErrProviderConflict)
	}
	if rules.RedirectURIRequired && len(spec.RedirectURIs) == 0 {
		return nil, fmt.Errorf("%w: profile requires redirect uris", applications.ErrProviderConflict)
	}
	return req, nil
}

// grantTypesFor maps domain grant types onto the ZITADEL app.v1 enum. The
// pinned enum has no client_credentials value; server_to_server clients are
// registered with the authorization_code grant set and rely on ZITADEL v2
// serving client_credentials at the token endpoint for confidential apps
// (ADR-0004 §1, to be confirmed in P2.8 acceptance).
func grantTypesFor(rules applications.ProfileRules) []appv1.OIDCGrantType {
	grants := make([]appv1.OIDCGrantType, 0, len(rules.GrantTypes))
	for _, gt := range rules.GrantTypes {
		switch gt {
		case applications.GrantTypeAuthorizationCode, applications.GrantTypeClientCredentials:
			grants = append(grants, appv1.OIDCGrantType_OIDC_GRANT_TYPE_AUTHORIZATION_CODE)
		case applications.GrantTypeRefreshToken:
			grants = append(grants, appv1.OIDCGrantType_OIDC_GRANT_TYPE_REFRESH_TOKEN)
		}
	}
	if len(grants) == 0 {
		grants = []appv1.OIDCGrantType{appv1.OIDCGrantType_OIDC_GRANT_TYPE_AUTHORIZATION_CODE}
	}
	return grants
}

// appExistsByName reports whether the shared project already contains an app
// with exactly this name.
func (p *Provisioner) appExistsByName(ctx context.Context, name string) (bool, error) {
	resp, err := p.mgmt.ListApps(ctx, &management.ListAppsRequest{
		ProjectId: p.projectID,
		Queries: []*appv1.AppQuery{{
			Query: &appv1.AppQuery_NameQuery{
				NameQuery: &appv1.AppNameQuery{
					Name:   name,
					Method: objectv1.TextQueryMethod_TEXT_QUERY_METHOD_EQUALS,
				},
			},
		}},
	})
	if err != nil {
		return false, p.mapError("provision_client_precheck", err)
	}
	return len(resp.GetResult()) > 0, nil
}

// appState reads the provider app state.
func (p *Provisioner) appState(ctx context.Context, providerApplicationID string) (appv1.AppState, error) {
	resp, err := p.mgmt.GetAppByID(ctx, &management.GetAppByIDRequest{
		ProjectId: p.projectID,
		AppId:     providerApplicationID,
	})
	if err != nil {
		return appv1.AppState_APP_STATE_UNSPECIFIED, p.mapError("read_app_state", err)
	}
	return resp.GetApp().GetState(), nil
}

// mapError reduces any provider error to a stable internal error class. Raw
// provider detail never reaches callers; only the class is logged.
func (p *Provisioner) mapError(operation string, err error) error {
	if err == nil {
		return nil
	}
	class := provisioningErrorClass(err)
	p.logFailure(operation, class)

	st, ok := status.FromError(err)
	if !ok {
		// Non-gRPC failures (network, token minting) are unavailability.
		return fmt.Errorf("%w: %s", applications.ErrProviderUnavailable, operation)
	}
	switch st.Code() {
	case codes.AlreadyExists:
		return fmt.Errorf("%w: %s", applications.ErrProviderConflict, operation)
	case codes.NotFound, codes.FailedPrecondition, codes.InvalidArgument, codes.Aborted:
		// State or argument mismatches: the local and provider state do not
		// line up; the use case reconciles rather than retrying blindly.
		return fmt.Errorf("%w: %s", applications.ErrProviderConflict, operation)
	default:
		return fmt.Errorf("%w: %s", applications.ErrProviderUnavailable, operation)
	}
}

// provisioningErrorClass extracts a safe, stable failure category. It never
// includes the provider error message.
func provisioningErrorClass(err error) string {
	if errors.Is(err, context.DeadlineExceeded) {
		return "deadline_exceeded"
	}
	if errors.Is(err, context.Canceled) {
		return "canceled"
	}
	st, ok := status.FromError(err)
	if !ok {
		return "transport"
	}
	return st.Code().String()
}

// logFailure records operation + error class only. Never provider messages,
// never secrets.
func (p *Provisioner) logFailure(operation, class string) {
	p.logger.Warn("zitadel provisioning failure",
		"operation", operation,
		"error_class", class,
	)
}
