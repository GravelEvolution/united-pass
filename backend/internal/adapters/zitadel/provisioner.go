//
// Copyright (c) 2026 Chen Jiajie(Ariakage)
//
// Author: Chen Jiajie(Ariakage) <ariakage233@gmail.com>
// Date: 2026-08-06
// Description: ZITADEL project, application and client provisioning adapter
//

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
//
// Every OIDC app is created with LoginVersion = LoginV2{BaseURI = the
// derived Interaction Base URI} and every read-modify-write enforces that
// configuration (ADR-0005 §1): ZITADEL must generate
// <interaction-base>/login?authRequest=… for the gateway, never fall back to
// its own LoginV1 UI.
type Provisioner struct {
	mgmt               managementService
	projectID          string
	interactionBaseURI string
	logger             *slog.Logger
}

// NewProvisioner builds the provisioner. projectID must be the configured
// shared ZITADEL project; an empty value fails closed. interactionBaseURI is
// the ZITADEL LoginV2 Interaction Base URI derived from
// UP_OAUTH_PUBLIC_ORIGIN (config.OAuthConfig.InteractionBaseURI); an empty
// value keeps the legacy behavior (no LoginVersion management), which
// production validation never allows.
func NewProvisioner(mgmt managementService, projectID, interactionBaseURI string, logger *slog.Logger) (*Provisioner, error) {
	if projectID == "" {
		return nil, errors.New("zitadel: provisioner requires UP_AUTH_PROVIDER_PROJECT_ID")
	}
	if logger == nil {
		logger = slog.Default()
	}
	return &Provisioner{mgmt: mgmt, projectID: projectID, interactionBaseURI: interactionBaseURI, logger: logger}, nil
}

// VerifyProject confirms the configured project is readable with the service
// account's permissions. Bootstrap registers it as a readiness check so a
// misconfigured provisioner fails closed instead of surfacing as 5xx on first
// use (ADR-0004 §1).
func (p *Provisioner) VerifyProject(ctx context.Context) error {
	if _, err := p.mgmt.GetProjectByID(ctx, &management.GetProjectByIDRequest{Id: p.projectID}); err != nil {
		return fmt.Errorf("%w: verify project: %s", applications.ErrProviderUnavailable, provisioningErrorClass(err))
	}
	return nil
}

// ProvisionClient creates one ZITADEL OIDC application for a United Pass
// client. The Management API has no idempotency key, so retries rely on the
// globally unique display name (application · client · short client ID,
// ADR-0004 §1): an exact-name match is this client's own previously created
// app and is recovered instead of rejected. Ambiguous failures surface as
// ErrProviderOutcomeUnknown so the caller leaves a reconciliation trail.
func (p *Provisioner) ProvisionClient(ctx context.Context, idempotencyKey string, spec applications.ClientProvisionSpec) (applications.ClientProvisionResult, error) {
	rules, ok := spec.Profile.Rules()
	if !ok {
		return applications.ClientProvisionResult{}, fmt.Errorf("%w: unknown profile", applications.ErrProviderConflict)
	}

	// Recovery for idempotent retries: an app carrying this globally unique
	// display name was created by an earlier attempt whose response was lost.
	existing, err := p.appIDByName(ctx, spec.DisplayName)
	if err != nil {
		return applications.ClientProvisionResult{}, err
	}
	if existing != "" {
		return p.recoverExistingApp(ctx, existing, rules)
	}

	req, err := addOIDCAppRequest(p.projectID, p.desiredLoginVersion(), spec, rules)
	if err != nil {
		return applications.ClientProvisionResult{}, err
	}
	resp, err := p.mgmt.AddOIDCApp(ctx, req)
	if err != nil {
		if st, ok := status.FromError(err); ok && st.Code() == codes.AlreadyExists {
			// Lost race: another attempt created the app between the
			// pre-check and the add. Recover it instead of duplicating.
			if existing, ferr := p.appIDByName(ctx, spec.DisplayName); ferr == nil && existing != "" {
				return p.recoverExistingApp(ctx, existing, rules)
			}
		}
		return applications.ClientProvisionResult{}, p.mapProvisionError("provision_client", err)
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

// recoverExistingApp returns the provider identifiers of an app created by
// an ambiguously succeeded earlier attempt. The original secret is
// unreachable at this point, so confidential clients get a fresh rotation
// and a valid one-time secret; public clients need none. The adopted app is
// also repaired: a pre-Phase-3.6 app or one left behind by an abnormal
// creation path may still lack the LoginV2 interaction configuration and
// must never be treated as usable without it.
func (p *Provisioner) recoverExistingApp(ctx context.Context, providerApplicationID string, rules applications.ProfileRules) (applications.ClientProvisionResult, error) {
	appResp, err := p.mgmt.GetAppByID(ctx, &management.GetAppByIDRequest{
		ProjectId: p.projectID,
		AppId:     providerApplicationID,
	})
	if err != nil {
		return applications.ClientProvisionResult{}, p.mapError("provision_client_recover", err)
	}
	cfg := appResp.GetApp().GetOidcConfig()
	if cfg == nil {
		// The matched app is not an OIDC app; adopting it would be unsafe.
		p.logFailure("provision_client_recover", "unexpected_app_type")
		return applications.ClientProvisionResult{}, fmt.Errorf("%w: recovered app is not an OIDC application", applications.ErrProviderConflict)
	}
	if err := p.ensureLoginVersion(ctx, providerApplicationID, cfg); err != nil {
		return applications.ClientProvisionResult{}, err
	}
	result := applications.ClientProvisionResult{
		ProviderApplicationID: providerApplicationID,
		ProviderClientID:      cfg.GetClientId(),
	}
	if rules.ClientType == applications.ClientTypePublic {
		return result, nil
	}
	rotation, err := p.RotateClientSecret(ctx, providerApplicationID)
	if err != nil {
		return applications.ClientProvisionResult{}, err
	}
	result.ClientSecret = rotation.NewSecret
	return result, nil
}

// UpdateClient synchronizes the display name and the redirect/logout URIs to
// the provider. The OIDC config update is read-modify-write: the current
// provider config is fetched first and every field this adapter does not own
// is preserved verbatim — the request is built from the full provider config,
// never from a hand-picked subset. United Pass then overwrites the fields it
// owns (redirect URIs, post-logout URIs) and enforces LoginVersion = the
// desired LoginV2 interaction configuration (ADR-0005 §1).
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
	req := preservedOIDCConfigUpdate(p.projectID, providerApplicationID, cfg)
	req.RedirectUris = spec.RedirectURIs
	req.PostLogoutRedirectUris = postLogout
	if desired := p.desiredLoginVersion(); desired != nil {
		req.LoginVersion = desired
	}
	if _, err := p.mgmt.UpdateOIDCAppConfig(ctx, req); err != nil {
		return p.mapError("update_client_config", err)
	}
	return nil
}

// ensureLoginVersion forces the desired LoginV2 interaction configuration on
// an existing app while preserving every other provider-owned field. It is a
// no-op when no interaction base is configured (legacy behavior) or the app
// already carries the exact desired configuration.
func (p *Provisioner) ensureLoginVersion(ctx context.Context, providerApplicationID string, cfg *appv1.OIDCConfig) error {
	desired := p.desiredLoginVersion()
	if desired == nil || loginVersionMatches(cfg.GetLoginVersion(), desired) {
		return nil
	}
	req := preservedOIDCConfigUpdate(p.projectID, providerApplicationID, cfg)
	req.LoginVersion = desired
	if _, err := p.mgmt.UpdateOIDCAppConfig(ctx, req); err != nil {
		return p.mapError("ensure_login_version", err)
	}
	return nil
}

// BackfillOutcome classifies one application in the LoginVersion backfill
// report.
type BackfillOutcome string

const (
	// BackfillVerified: the app already carries the exact desired LoginV2
	// interaction configuration; nothing was written.
	BackfillVerified BackfillOutcome = "verified"
	// BackfillRepaired: a missing or stale LoginVersion was rewritten and the
	// authoritative read-back confirmed the exact desired configuration.
	BackfillRepaired BackfillOutcome = "repaired"
	// BackfillSkipped: the app is not an OIDC application and has no
	// LoginVersion to manage.
	BackfillSkipped BackfillOutcome = "skipped"
	// BackfillFailed: repair or authoritative read-back failed; the rollout
	// must not proceed to cutover while any entry carries this outcome.
	BackfillFailed BackfillOutcome = "failed"
)

// BackfillEntry is the per-application result of one backfill pass.
type BackfillEntry struct {
	ApplicationID string
	Name          string
	Outcome       BackfillOutcome
}

// BackfillReport is the auditable result of BackfillLoginVersions.
type BackfillReport struct {
	Entries  []BackfillEntry
	Verified int
	Repaired int
	Skipped  int
	Failed   int
}

// Success reports whether every application is on the desired configuration.
// Any failure makes the whole job non-successful: the rollout runbook blocks
// the public OAuth cutover on it (ADR-0005 §1).
func (r BackfillReport) Success() bool { return r.Failed == 0 }

// backfillPageLimit / backfillMaxPages bound the application listing. The
// project must never be assumed to fit in a single page, but a provider that
// keeps returning full pages past the reported total must not loop forever.
const (
	backfillPageLimit = 100
	backfillMaxPages  = 1000
)

// BackfillLoginVersions enforces the LoginV2 interaction configuration on
// every OIDC application of the shared project. It is the explicit one-time
// migration for pre-Phase-3 applications that never pass through
// ProvisionClient or UpdateClient again: list every app, repair a missing or
// stale LoginVersion with the same preserving read-modify-write every other
// path uses, then read the configuration back live and require an exact
// match — never trust the write response alone. Any repair or read-back
// failure marks the application failed and makes the whole job
// non-successful. The job is idempotent: a second run verifies everything
// and writes nothing.
func (p *Provisioner) BackfillLoginVersions(ctx context.Context) (BackfillReport, error) {
	report := BackfillReport{}
	if p.interactionBaseURI == "" {
		// Fail closed: a backfill without a derived interaction base would
		// "verify" apps into the legacy LoginV1 state. Production validation
		// never allows an empty UP_OAUTH_PUBLIC_ORIGIN.
		return report, errors.New("zitadel: login version backfill requires the derived interaction base URI (UP_OAUTH_PUBLIC_ORIGIN)")
	}
	apps, err := p.listAllApps(ctx)
	if err != nil {
		return report, err
	}
	desired := p.desiredLoginVersion()
	for _, app := range apps {
		entry := BackfillEntry{ApplicationID: app.GetId(), Name: app.GetName()}
		entry.Outcome = p.backfillApp(ctx, app.GetId(), desired)
		switch entry.Outcome {
		case BackfillVerified:
			report.Verified++
		case BackfillRepaired:
			report.Repaired++
		case BackfillSkipped:
			report.Skipped++
		case BackfillFailed:
			report.Failed++
		}
		report.Entries = append(report.Entries, entry)
	}
	if !report.Success() {
		// The per-app report is the audit trail; the error is the rollout
		// gate. Raw provider detail never leaves the adapter.
		return report, fmt.Errorf("%w: backfill_login_versions (%d of %d applications failed)",
			applications.ErrProviderUnavailable, report.Failed, len(report.Entries))
	}
	return report, nil
}

// backfillApp enforces the desired LoginVersion on one application and
// returns its outcome. Non-OIDC apps are skipped; every repaired app gets an
// authoritative read-back that must match exactly.
func (p *Provisioner) backfillApp(ctx context.Context, providerApplicationID string, desired *appv1.LoginVersion) BackfillOutcome {
	appResp, err := p.mgmt.GetAppByID(ctx, &management.GetAppByIDRequest{
		ProjectId: p.projectID,
		AppId:     providerApplicationID,
	})
	if err != nil {
		p.mapError("backfill_read_app", err)
		return BackfillFailed
	}
	cfg := appResp.GetApp().GetOidcConfig()
	if cfg == nil {
		// API or SAML apps have no LoginVersion to manage.
		return BackfillSkipped
	}
	if loginVersionMatches(cfg.GetLoginVersion(), desired) {
		return BackfillVerified
	}
	if err := p.ensureLoginVersion(ctx, providerApplicationID, cfg); err != nil {
		return BackfillFailed
	}
	// Authoritative read-back: the write response is never trusted alone.
	read, err := p.mgmt.GetAppByID(ctx, &management.GetAppByIDRequest{
		ProjectId: p.projectID,
		AppId:     providerApplicationID,
	})
	if err != nil {
		p.mapError("backfill_read_back", err)
		return BackfillFailed
	}
	if !loginVersionMatches(read.GetApp().GetOidcConfig().GetLoginVersion(), desired) {
		p.logFailure("backfill_login_version", "read_back_mismatch")
		return BackfillFailed
	}
	return BackfillRepaired
}

// listAllApps walks every page of the project application listing.
func (p *Provisioner) listAllApps(ctx context.Context) ([]*appv1.App, error) {
	var all []*appv1.App
	var offset uint64
	for page := 0; page < backfillMaxPages; page++ {
		resp, err := p.mgmt.ListApps(ctx, &management.ListAppsRequest{
			ProjectId: p.projectID,
			Query:     &objectv1.ListQuery{Offset: offset, Limit: backfillPageLimit},
		})
		if err != nil {
			return nil, p.mapError("backfill_list_apps", err)
		}
		result := resp.GetResult()
		all = append(all, result...)
		total := resp.GetDetails().GetTotalResult()
		if total > 0 {
			// The provider reports the total: it is authoritative, so a short
			// page (e.g. a server-side limit below the requested one) never
			// terminates the walk early.
			if len(result) == 0 || uint64(len(all)) >= total {
				return all, nil
			}
			offset += uint64(len(result))
			continue
		}
		// No reported total: fall back to the short-page heuristic.
		if len(result) == 0 || len(result) < backfillPageLimit {
			return all, nil
		}
		offset += uint64(len(result))
	}
	return nil, fmt.Errorf("%w: backfill_list_apps", applications.ErrProviderUnavailable)
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
		return applications.ClientSecretRotation{}, p.mapRotationError("rotate_client_secret", err)
	}
	if resp.GetClientSecret() == "" {
		p.logFailure("rotate_client_secret", "empty_secret")
		return applications.ClientSecretRotation{}, fmt.Errorf("%w: provider returned no secret", applications.ErrProviderUnavailable)
	}
	return applications.ClientSecretRotation{NewSecret: resp.GetClientSecret()}, nil
}

// --- helpers ---

// desiredLoginVersion builds the LoginVersion United Pass enforces on every
// OIDC app: LoginV2 with the derived Interaction Base URI. It returns nil
// when no interaction base is configured; callers treat nil as "no
// LoginVersion management" (production validation never allows that state).
func (p *Provisioner) desiredLoginVersion() *appv1.LoginVersion {
	if p.interactionBaseURI == "" {
		return nil
	}
	base := p.interactionBaseURI
	return &appv1.LoginVersion{
		Version: &appv1.LoginVersion_LoginV2{
			LoginV2: &appv1.LoginV2{BaseUri: &base},
		},
	}
}

// loginVersionMatches reports whether the provider config already carries
// exactly the desired LoginV2 interaction configuration. Any other state —
// LoginV1, LoginV2 without a base URI, or a different base URI — needs
// repair.
func loginVersionMatches(current, desired *appv1.LoginVersion) bool {
	return current.GetLoginV2().GetBaseUri() == desired.GetLoginV2().GetBaseUri()
}

// preservedOIDCConfigUpdate copies every field of the current provider OIDC
// config verbatim into an UpdateOIDCAppConfigRequest. Callers then overwrite
// only the fields United Pass owns. Building from the full provider config —
// never a hand-picked subset — is what makes the read-modify-write contract
// honest: no provider-owned field may ever be reset to a zero value by an
// update.
func preservedOIDCConfigUpdate(projectID, appID string, cfg *appv1.OIDCConfig) *management.UpdateOIDCAppConfigRequest {
	return &management.UpdateOIDCAppConfigRequest{
		ProjectId:                projectID,
		AppId:                    appID,
		RedirectUris:             cfg.GetRedirectUris(),
		ResponseTypes:            cfg.GetResponseTypes(),
		GrantTypes:               cfg.GetGrantTypes(),
		AppType:                  cfg.GetAppType(),
		AuthMethodType:           cfg.GetAuthMethodType(),
		PostLogoutRedirectUris:   cfg.GetPostLogoutRedirectUris(),
		DevMode:                  cfg.GetDevMode(),
		AccessTokenType:          cfg.GetAccessTokenType(),
		AccessTokenRoleAssertion: cfg.GetAccessTokenRoleAssertion(),
		IdTokenRoleAssertion:     cfg.GetIdTokenRoleAssertion(),
		IdTokenUserinfoAssertion: cfg.GetIdTokenUserinfoAssertion(),
		ClockSkew:                cfg.GetClockSkew(),
		AdditionalOrigins:        cfg.GetAdditionalOrigins(),
		SkipNativeAppSuccessPage: cfg.GetSkipNativeAppSuccessPage(),
		BackChannelLogoutUri:     cfg.GetBackChannelLogoutUri(),
		LoginVersion:             cfg.GetLoginVersion(),
	}
}

// addOIDCAppRequest maps a United Pass client profile to the ZITADEL
// AddOIDCApp parameters (ADR-0004 §1). Redirect URIs are passed through
// verbatim; no normalization is ever applied. LoginVersion is submitted with
// the same request — atomically at creation — so a crash between create and
// any follow-up update can never leave an app behind on LoginV1 (ADR-0005
// §1).
func addOIDCAppRequest(projectID string, loginVersion *appv1.LoginVersion, spec applications.ClientProvisionSpec, rules applications.ProfileRules) (*management.AddOIDCAppRequest, error) {
	req := &management.AddOIDCAppRequest{
		ProjectId:     projectID,
		Name:          spec.DisplayName,
		RedirectUris:  spec.RedirectURIs,
		ResponseTypes: []appv1.OIDCResponseType{appv1.OIDCResponseType_OIDC_RESPONSE_TYPE_CODE},
		GrantTypes:    grantTypesFor(rules),
		Version:       appv1.OIDCVersion_OIDC_VERSION_1_0,
		LoginVersion:  loginVersion,
	}
	if spec.LogoutURI != "" {
		req.PostLogoutRedirectUris = []string{spec.LogoutURI}
	}
	switch spec.Profile {
	case applications.ClientProfileWebServer:
		req.AppType = appv1.OIDCAppType_OIDC_APP_TYPE_WEB
		req.AuthMethodType = appv1.OIDCAuthMethodType_OIDC_AUTH_METHOD_TYPE_BASIC
	case applications.ClientProfileSPAMobile:
		req.AppType = appv1.OIDCAppType_OIDC_APP_TYPE_USER_AGENT
		req.AuthMethodType = appv1.OIDCAuthMethodType_OIDC_AUTH_METHOD_TYPE_NONE
	default:
		// server_to_server is rejected by domain validation (ZITADEL v2.71
		// cannot serve client_credentials for provisioned OIDC apps); fail
		// closed here so no unsupported profile ever reaches the provider.
		return nil, fmt.Errorf("%w: unsupported profile %q", applications.ErrProviderConflict, string(spec.Profile))
	}
	if rules.RedirectURIRequired && len(spec.RedirectURIs) == 0 {
		return nil, fmt.Errorf("%w: profile requires redirect uris", applications.ErrProviderConflict)
	}
	return req, nil
}

// grantTypesFor maps domain grant types onto the ZITADEL app.v1 enum. The
// pinned enum has no client_credentials value. server_to_server clients are
// rejected at input validation (ZITADEL v2.71 serves client_credentials only
// for machine users, so a provisioned app could never execute the grant);
// the client_credentials case stays mapped defensively should a machine-user
// backed profile ever be introduced.
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

// appIDByName returns the ID of the project app carrying exactly this name,
// or an empty string when no such app exists.
func (p *Provisioner) appIDByName(ctx context.Context, name string) (string, error) {
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
		return "", p.mapError("provision_client_precheck", err)
	}
	for _, app := range resp.GetResult() {
		if app.GetName() == name {
			return app.GetId(), nil
		}
	}
	return "", nil
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

// mapProvisionError classifies provisioning failures. Ambiguous outcomes
// (deadline, cancellation, transport loss, Unknown/Unavailable/Internal)
// surface as outcome-unknown: the provider app may already exist and the
// caller must leave a reconciliation trail instead of assuming failure.
// Definitive rejections keep the standard mapping.
func (p *Provisioner) mapProvisionError(operation string, err error) error {
	class := provisioningErrorClass(err)
	switch class {
	case "deadline_exceeded", "canceled", "DeadlineExceeded", "Canceled", "transport", "Unknown", "Unavailable", "Internal":
		p.logFailure(operation, class)
		return fmt.Errorf("%w: %s", applications.ErrProviderOutcomeUnknown, operation)
	}
	return p.mapError(operation, err)
}

// mapRotationError classifies rotation failures. Rotation is non-idempotent
// at the provider (v2.71 revokes the previous secret immediately, no grace
// period), so any ambiguous outcome — deadline, cancellation, transport loss,
// Unknown/Unavailable/Internal — must surface as outcome-unknown. The caller
// then parks the client instead of assuming the old secret survived
// (ADR-0004 §6). Definitive rejections keep the standard mapping.
func (p *Provisioner) mapRotationError(operation string, err error) error {
	class := provisioningErrorClass(err)
	p.logFailure(operation, class)
	switch class {
	case "deadline_exceeded", "canceled", "DeadlineExceeded", "Canceled", "transport", "Unknown", "Unavailable", "Internal":
		return fmt.Errorf("%w: %s", applications.ErrProviderOutcomeUnknown, operation)
	}
	st, ok := status.FromError(err)
	if !ok {
		return fmt.Errorf("%w: %s", applications.ErrProviderOutcomeUnknown, operation)
	}
	switch st.Code() {
	case codes.AlreadyExists, codes.NotFound, codes.FailedPrecondition, codes.InvalidArgument, codes.Aborted:
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
