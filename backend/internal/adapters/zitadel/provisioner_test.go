//
// Copyright (c) 2026 Chen Jiajie(Ariakage)
//
// Author: Chen Jiajie(Ariakage) <ariakage233@gmail.com>
// Date: 2026-08-06
// Description: Unit tests for the ZITADEL provisioning adapter
//

package zitadel

import (
	"context"
	"errors"
	"log/slog"
	"testing"
	"time"

	"github.com/GravelEvolution/united-pass/backend/internal/applications"

	appv1 "github.com/zitadel/zitadel-go/v3/pkg/client/zitadel/app"
	management "github.com/zitadel/zitadel-go/v3/pkg/client/zitadel/management"
	objectv1 "github.com/zitadel/zitadel-go/v3/pkg/client/zitadel/object"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
	"google.golang.org/protobuf/types/known/durationpb"
)

// stubManagement is a scripted Management API for adapter tests.
type stubManagement struct {
	projectErr error

	listResp *management.ListAppsResponse
	listErr  error

	getResp *management.GetAppByIDResponse
	getErr  error

	addResp *management.AddOIDCAppResponse
	addErr  error
	addReq  *management.AddOIDCAppRequest
	added   int

	updateAppReq  *management.UpdateAppRequest
	updateAppErr  error
	updateCfgReq  *management.UpdateOIDCAppConfigRequest
	updateCfgErr  error
	deactivateErr error
	deactivated   int
	reactivateErr error
	reactivated   int
	removeErr     error
	removed       int
	rotateResp    *management.RegenerateOIDCClientSecretResponse
	rotateErr     error

	// Backfill hooks. listFn scripts the paginated app listing; getByApp
	// serves per-app reads; applyLoginVersion makes the stub behave like the
	// real provider: a successful UpdateOIDCAppConfig persists the submitted
	// LoginVersion into the stored config, so a read-back observes it.
	listFn            func(offset uint64, limit uint32) (*management.ListAppsResponse, error)
	listCalls         int
	getByApp          map[string]*management.GetAppByIDResponse
	applyLoginVersion bool
	updateCfgCount    int
}

func (s *stubManagement) GetProjectByID(ctx context.Context, in *management.GetProjectByIDRequest, opts ...grpc.CallOption) (*management.GetProjectByIDResponse, error) {
	return &management.GetProjectByIDResponse{}, s.projectErr
}

func (s *stubManagement) ListApps(ctx context.Context, in *management.ListAppsRequest, opts ...grpc.CallOption) (*management.ListAppsResponse, error) {
	if s.listFn != nil {
		s.listCalls++
		return s.listFn(in.GetQuery().GetOffset(), in.GetQuery().GetLimit())
	}
	if s.listErr != nil {
		return nil, s.listErr
	}
	if s.listResp != nil {
		return s.listResp, nil
	}
	return &management.ListAppsResponse{}, nil
}

func (s *stubManagement) GetAppByID(ctx context.Context, in *management.GetAppByIDRequest, opts ...grpc.CallOption) (*management.GetAppByIDResponse, error) {
	if s.getByApp != nil {
		return s.getByApp[in.GetAppId()], s.getErr
	}
	return s.getResp, s.getErr
}

func (s *stubManagement) AddOIDCApp(ctx context.Context, in *management.AddOIDCAppRequest, opts ...grpc.CallOption) (*management.AddOIDCAppResponse, error) {
	s.addReq = in
	s.added++
	return s.addResp, s.addErr
}

func (s *stubManagement) UpdateApp(ctx context.Context, in *management.UpdateAppRequest, opts ...grpc.CallOption) (*management.UpdateAppResponse, error) {
	s.updateAppReq = in
	return &management.UpdateAppResponse{}, s.updateAppErr
}

func (s *stubManagement) UpdateOIDCAppConfig(ctx context.Context, in *management.UpdateOIDCAppConfigRequest, opts ...grpc.CallOption) (*management.UpdateOIDCAppConfigResponse, error) {
	s.updateCfgReq = in
	s.updateCfgCount++
	if s.updateCfgErr != nil {
		return nil, s.updateCfgErr
	}
	if s.applyLoginVersion {
		if resp, ok := s.getByApp[in.GetAppId()]; ok {
			resp.GetApp().GetOidcConfig().LoginVersion = in.GetLoginVersion()
		}
	}
	return &management.UpdateOIDCAppConfigResponse{}, nil
}

func (s *stubManagement) DeactivateApp(ctx context.Context, in *management.DeactivateAppRequest, opts ...grpc.CallOption) (*management.DeactivateAppResponse, error) {
	s.deactivated++
	return &management.DeactivateAppResponse{}, s.deactivateErr
}

func (s *stubManagement) ReactivateApp(ctx context.Context, in *management.ReactivateAppRequest, opts ...grpc.CallOption) (*management.ReactivateAppResponse, error) {
	s.reactivated++
	return &management.ReactivateAppResponse{}, s.reactivateErr
}

func (s *stubManagement) RemoveApp(ctx context.Context, in *management.RemoveAppRequest, opts ...grpc.CallOption) (*management.RemoveAppResponse, error) {
	s.removed++
	return &management.RemoveAppResponse{}, s.removeErr
}

func (s *stubManagement) RegenerateOIDCClientSecret(ctx context.Context, in *management.RegenerateOIDCClientSecretRequest, opts ...grpc.CallOption) (*management.RegenerateOIDCClientSecretResponse, error) {
	return s.rotateResp, s.rotateErr
}

const testInteractionBase = "https://id.example.com/_interaction"

func newTestProvisioner(t *testing.T, stub *stubManagement) *Provisioner {
	t.Helper()
	p, err := NewProvisioner(stub, "proj-test", testInteractionBase, slog.New(slog.DiscardHandler))
	if err != nil {
		t.Fatalf("new provisioner: %v", err)
	}
	return p
}

// newLegacyProvisioner builds a provisioner with no interaction base: the
// pre-Phase-3.6 behavior where LoginVersion is never managed.
func newLegacyProvisioner(t *testing.T, stub *stubManagement) *Provisioner {
	t.Helper()
	p, err := NewProvisioner(stub, "proj-test", "", slog.New(slog.DiscardHandler))
	if err != nil {
		t.Fatalf("new legacy provisioner: %v", err)
	}
	return p
}

func wantLoginV2(t *testing.T, got *appv1.LoginVersion, base string) {
	t.Helper()
	if got.GetLoginV2().GetBaseUri() != base {
		t.Fatalf("LoginVersion = %+v, want LoginV2{BaseUri=%q}", got, base)
	}
}

func webServerSpec() applications.ClientProvisionSpec {
	return applications.ClientProvisionSpec{
		DisplayName:  "Web Server Client",
		Profile:      applications.ClientProfileWebServer,
		RedirectURIs: []string{"https://app.example.com/callback", "https://app.example.com/cb2/"},
		LogoutURI:    "https://app.example.com/logout",
		Scopes:       []string{"openid"},
	}
}

func TestProvisioner_WebServerMapping(t *testing.T) {
	stub := &stubManagement{addResp: &management.AddOIDCAppResponse{
		AppId: "prov-app-1", ClientId: "prov-client-1", ClientSecret: "s3cret",
	}}
	p := newTestProvisioner(t, stub)

	res, err := p.ProvisionClient(context.Background(), "idem-1", webServerSpec())
	if err != nil {
		t.Fatalf("provision: %v", err)
	}
	if res.ProviderApplicationID != "prov-app-1" || res.ProviderClientID != "prov-client-1" || res.ClientSecret != "s3cret" {
		t.Errorf("result: %+v", res)
	}

	req := stub.addReq
	if req == nil {
		t.Fatal("AddOIDCApp not called")
	}
	if req.ProjectId != "proj-test" {
		t.Errorf("ProjectId: %q", req.ProjectId)
	}
	if req.AppType != appv1.OIDCAppType_OIDC_APP_TYPE_WEB {
		t.Errorf("AppType: %v", req.AppType)
	}
	if req.AuthMethodType != appv1.OIDCAuthMethodType_OIDC_AUTH_METHOD_TYPE_BASIC {
		t.Errorf("AuthMethodType: %v", req.AuthMethodType)
	}
	if len(req.GrantTypes) != 2 ||
		req.GrantTypes[0] != appv1.OIDCGrantType_OIDC_GRANT_TYPE_AUTHORIZATION_CODE ||
		req.GrantTypes[1] != appv1.OIDCGrantType_OIDC_GRANT_TYPE_REFRESH_TOKEN {
		t.Errorf("GrantTypes: %v", req.GrantTypes)
	}
	if len(req.ResponseTypes) != 1 || req.ResponseTypes[0] != appv1.OIDCResponseType_OIDC_RESPONSE_TYPE_CODE {
		t.Errorf("ResponseTypes: %v", req.ResponseTypes)
	}
	// Redirect URIs must pass through verbatim (no normalization, trailing
	// slash preserved).
	if len(req.RedirectUris) != 2 || req.RedirectUris[1] != "https://app.example.com/cb2/" {
		t.Errorf("RedirectUris: %v", req.RedirectUris)
	}
	if len(req.PostLogoutRedirectUris) != 1 || req.PostLogoutRedirectUris[0] != "https://app.example.com/logout" {
		t.Errorf("PostLogoutRedirectUris: %v", req.PostLogoutRedirectUris)
	}
	// LoginVersion must be submitted atomically with the creation request
	// (ADR-0005 §1): no follow-up update may be required for the app to be
	// usable by the gateway.
	wantLoginV2(t, req.LoginVersion, testInteractionBase)
	if stub.updateCfgReq != nil {
		t.Error("creation must not issue a follow-up OIDC config update")
	}
}

func TestProvisioner_SPAMobileMappingSuppressesSecret(t *testing.T) {
	stub := &stubManagement{addResp: &management.AddOIDCAppResponse{
		AppId: "prov-app-2", ClientId: "prov-client-2",
		ClientSecret: "must-not-leak", // a public client must never surface a secret
	}}
	p := newTestProvisioner(t, stub)

	res, err := p.ProvisionClient(context.Background(), "idem-2", applications.ClientProvisionSpec{
		DisplayName:  "SPA Client",
		Profile:      applications.ClientProfileSPAMobile,
		RedirectURIs: []string{"http://127.0.0.1:3000/callback"},
	})
	if err != nil {
		t.Fatalf("provision: %v", err)
	}
	if res.ClientSecret != "" {
		t.Errorf("public client secret must be suppressed, got %q", res.ClientSecret)
	}
	if stub.addReq.AppType != appv1.OIDCAppType_OIDC_APP_TYPE_USER_AGENT {
		t.Errorf("AppType: %v", stub.addReq.AppType)
	}
	if stub.addReq.AuthMethodType != appv1.OIDCAuthMethodType_OIDC_AUTH_METHOD_TYPE_NONE {
		t.Errorf("AuthMethodType: %v", stub.addReq.AuthMethodType)
	}
}

func TestProvisioner_ServerToServerRejected(t *testing.T) {
	// server_to_server is rejected by domain validation, but the adapter
	// must fail closed too so an unsupported profile never reaches ZITADEL.
	stub := &stubManagement{}
	p := newTestProvisioner(t, stub)

	_, err := p.ProvisionClient(context.Background(), "idem-3", applications.ClientProvisionSpec{
		DisplayName: "S2S Client",
		Profile:     applications.ClientProfileServerToServer,
	})
	if err == nil {
		t.Fatal("expected server_to_server provisioning to fail")
	}
	if stub.added != 0 {
		t.Error("AddOIDCApp must not be called for unsupported profiles")
	}
}

func TestProvisioner_WebServerRequiresRedirectURIs(t *testing.T) {
	stub := &stubManagement{}
	p := newTestProvisioner(t, stub)

	_, err := p.ProvisionClient(context.Background(), "idem-4", applications.ClientProvisionSpec{
		DisplayName: "No URIs",
		Profile:     applications.ClientProfileWebServer,
	})
	if !errors.Is(err, applications.ErrProviderConflict) {
		t.Fatalf("got %v, want ErrProviderConflict", err)
	}
	if stub.added != 0 {
		t.Error("AddOIDCApp must not be called for an invalid spec")
	}
}

// TestProvisioner_ProvisionRecoversExistingApp verifies idempotent recovery:
// an app carrying the spec's globally unique display name (created by an
// ambiguously succeeded earlier attempt) is adopted instead of rejected, and
// a confidential client gets a fresh one-time secret via rotation.
func TestProvisioner_ProvisionRecoversExistingApp(t *testing.T) {
	spec := webServerSpec()
	recovered := oidcAppFixture(appv1.AppState_APP_STATE_ACTIVE)
	recovered.GetApp().GetOidcConfig().ClientId = "prov-client-existing"
	stub := &stubManagement{
		listResp:   &management.ListAppsResponse{Result: []*appv1.App{{Id: "existing", Name: spec.DisplayName}}},
		getResp:    recovered,
		addResp:    &management.AddOIDCAppResponse{},
		rotateResp: &management.RegenerateOIDCClientSecretResponse{ClientSecret: "recovered-secret"},
	}
	p := newTestProvisioner(t, stub)

	res, err := p.ProvisionClient(context.Background(), "idem-5", spec)
	if err != nil {
		t.Fatalf("recover: %v", err)
	}
	if res.ProviderApplicationID != "existing" || res.ProviderClientID != "prov-client-existing" || res.ClientSecret != "recovered-secret" {
		t.Fatalf("result: %+v", res)
	}
	if stub.added != 0 {
		t.Error("recovery must never create a duplicate app")
	}
}

func TestProvisioner_ProvisionErrorMapping(t *testing.T) {
	cases := []struct {
		name string
		err  error
		want error
	}{
		{"already_exists", status.Error(codes.AlreadyExists, "APP-m92Jx"), applications.ErrProviderConflict},
		{"not_found", status.Error(codes.NotFound, "QUERY-xxx"), applications.ErrProviderConflict},
		{"failed_precondition", status.Error(codes.FailedPrecondition, "COMMAND-xxx"), applications.ErrProviderConflict},
		// Ambiguous outcomes: the app may already exist, so the caller must
		// reconcile instead of assuming failure.
		{"unavailable", status.Error(codes.Unavailable, "transport"), applications.ErrProviderOutcomeUnknown},
		{"permission", status.Error(codes.NotFound, "AUTHZ-xxx"), applications.ErrProviderConflict},
		{"internal", status.Error(codes.Internal, "boom"), applications.ErrProviderOutcomeUnknown},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			stub := &stubManagement{
				addResp: &management.AddOIDCAppResponse{},
				addErr:  tc.err,
			}
			p := newTestProvisioner(t, stub)
			_, err := p.ProvisionClient(context.Background(), "idem-"+tc.name, webServerSpec())
			if !errors.Is(err, tc.want) {
				t.Fatalf("got %v, want %v", err, tc.want)
			}
			// Errors must never carry raw provider detail.
			if tc.err != nil && errors.Is(err, tc.want) && err.Error() == tc.err.Error() {
				t.Error("provider error detail leaked verbatim")
			}
		})
	}
}

func oidcAppFixture(state appv1.AppState) *management.GetAppByIDResponse {
	return &management.GetAppByIDResponse{
		App: &appv1.App{
			Id:    "prov-app-1",
			State: state,
			Config: &appv1.App_OidcConfig{
				OidcConfig: &appv1.OIDCConfig{
					RedirectUris:    []string{"https://old.example.com/cb"},
					ResponseTypes:   []appv1.OIDCResponseType{appv1.OIDCResponseType_OIDC_RESPONSE_TYPE_CODE},
					GrantTypes:      []appv1.OIDCGrantType{appv1.OIDCGrantType_OIDC_GRANT_TYPE_AUTHORIZATION_CODE},
					AppType:         appv1.OIDCAppType_OIDC_APP_TYPE_WEB,
					AuthMethodType:  appv1.OIDCAuthMethodType_OIDC_AUTH_METHOD_TYPE_BASIC,
					Version:         appv1.OIDCVersion_OIDC_VERSION_1_0,
					DevMode:         true,
					AccessTokenType: appv1.OIDCTokenType_OIDC_TOKEN_TYPE_JWT,
				},
			},
		},
	}
}

// richOIDCAppFixture seeds every provider-owned field the read-modify-write
// must carry back, including a stale LoginV1 configuration that must be
// replaced by the enforced LoginV2.
func richOIDCAppFixture() *management.GetAppByIDResponse {
	return &management.GetAppByIDResponse{
		App: &appv1.App{
			Id:    "prov-app-rich",
			State: appv1.AppState_APP_STATE_ACTIVE,
			Config: &appv1.App_OidcConfig{
				OidcConfig: &appv1.OIDCConfig{
					RedirectUris:             []string{"https://old.example.com/cb"},
					ResponseTypes:            []appv1.OIDCResponseType{appv1.OIDCResponseType_OIDC_RESPONSE_TYPE_CODE},
					GrantTypes:               []appv1.OIDCGrantType{appv1.OIDCGrantType_OIDC_GRANT_TYPE_AUTHORIZATION_CODE},
					AppType:                  appv1.OIDCAppType_OIDC_APP_TYPE_WEB,
					AuthMethodType:           appv1.OIDCAuthMethodType_OIDC_AUTH_METHOD_TYPE_BASIC,
					PostLogoutRedirectUris:   []string{"https://old.example.com/logout"},
					Version:                  appv1.OIDCVersion_OIDC_VERSION_1_0,
					DevMode:                  true,
					AccessTokenType:          appv1.OIDCTokenType_OIDC_TOKEN_TYPE_JWT,
					AccessTokenRoleAssertion: true,
					IdTokenRoleAssertion:     true,
					IdTokenUserinfoAssertion: true,
					ClockSkew:                durationpb.New(5 * time.Minute),
					AdditionalOrigins:        []string{"https://extra.example.com"},
					SkipNativeAppSuccessPage: true,
					BackChannelLogoutUri:     "https://old.example.com/backchannel",
					LoginVersion:             &appv1.LoginVersion{Version: &appv1.LoginVersion_LoginV1{LoginV1: &appv1.LoginV1{}}},
				},
			},
		},
	}
}

func TestProvisioner_UpdatePreservesProviderConfig(t *testing.T) {
	stub := &stubManagement{getResp: richOIDCAppFixture()}
	p := newTestProvisioner(t, stub)

	err := p.UpdateClient(context.Background(), "prov-app-rich", applications.ClientUpdateSpec{
		DisplayName:  "Renamed",
		RedirectURIs: []string{"https://new.example.com/cb"},
		LogoutURI:    "https://new.example.com/logout",
	})
	if err != nil {
		t.Fatalf("update: %v", err)
	}
	if stub.updateAppReq == nil || stub.updateAppReq.Name != "Renamed" {
		t.Errorf("name update: %+v", stub.updateAppReq)
	}
	cfg := stub.updateCfgReq
	if cfg == nil {
		t.Fatal("UpdateOIDCAppConfig not called")
	}
	// Owned fields take the spec values.
	if len(cfg.RedirectUris) != 1 || cfg.RedirectUris[0] != "https://new.example.com/cb" {
		t.Errorf("RedirectUris: %v", cfg.RedirectUris)
	}
	if len(cfg.PostLogoutRedirectUris) != 1 || cfg.PostLogoutRedirectUris[0] != "https://new.example.com/logout" {
		t.Errorf("PostLogout: %v", cfg.PostLogoutRedirectUris)
	}
	// Every field the adapter does not own must come back verbatim from the
	// provider read — the RMW contract must hold for the full config, not a
	// hand-picked subset.
	if !cfg.DevMode || cfg.AccessTokenType != appv1.OIDCTokenType_OIDC_TOKEN_TYPE_JWT ||
		cfg.AppType != appv1.OIDCAppType_OIDC_APP_TYPE_WEB ||
		cfg.AuthMethodType != appv1.OIDCAuthMethodType_OIDC_AUTH_METHOD_TYPE_BASIC {
		t.Errorf("provider config not preserved: %+v", cfg)
	}
	if !cfg.AccessTokenRoleAssertion || !cfg.IdTokenRoleAssertion || !cfg.IdTokenUserinfoAssertion {
		t.Error("role/userinfo assertions not preserved")
	}
	if cfg.ClockSkew.AsDuration() != 5*time.Minute {
		t.Errorf("ClockSkew not preserved: %v", cfg.ClockSkew)
	}
	if len(cfg.AdditionalOrigins) != 1 || cfg.AdditionalOrigins[0] != "https://extra.example.com" {
		t.Errorf("AdditionalOrigins not preserved: %v", cfg.AdditionalOrigins)
	}
	if !cfg.SkipNativeAppSuccessPage {
		t.Error("SkipNativeAppSuccessPage not preserved")
	}
	if cfg.BackChannelLogoutUri != "https://old.example.com/backchannel" {
		t.Errorf("BackChannelLogoutUri not preserved: %q", cfg.BackChannelLogoutUri)
	}
	if len(cfg.ResponseTypes) != 1 || len(cfg.GrantTypes) != 1 {
		t.Errorf("response/grant types not preserved: %+v", cfg)
	}
	// LoginVersion is enforced to the desired LoginV2 even though the app
	// still carries LoginV1 (the production backfill path).
	wantLoginV2(t, cfg.LoginVersion, testInteractionBase)
}

// TestProvisioner_RecoverRepairsLoginVersion verifies that adopting an app
// from an ambiguously succeeded creation repairs a missing or stale
// LoginVersion before the app is treated as usable.
func TestProvisioner_RecoverRepairsLoginVersion(t *testing.T) {
	spec := webServerSpec()
	recovered := oidcAppFixture(appv1.AppState_APP_STATE_ACTIVE) // LoginVersion absent
	recovered.GetApp().GetOidcConfig().ClientId = "prov-client-existing"
	stub := &stubManagement{
		listResp:   &management.ListAppsResponse{Result: []*appv1.App{{Id: "existing", Name: spec.DisplayName}}},
		getResp:    recovered,
		addResp:    &management.AddOIDCAppResponse{},
		rotateResp: &management.RegenerateOIDCClientSecretResponse{ClientSecret: "recovered-secret"},
	}
	p := newTestProvisioner(t, stub)

	res, err := p.ProvisionClient(context.Background(), "idem-repair", spec)
	if err != nil {
		t.Fatalf("recover: %v", err)
	}
	if res.ProviderApplicationID != "existing" || res.ClientSecret != "recovered-secret" {
		t.Fatalf("result: %+v", res)
	}
	if stub.updateCfgReq == nil {
		t.Fatal("recovery must repair the missing LoginVersion via UpdateOIDCAppConfig")
	}
	wantLoginV2(t, stub.updateCfgReq.LoginVersion, testInteractionBase)
	// The repair preserves the adopted app's existing config.
	if len(stub.updateCfgReq.RedirectUris) != 1 || stub.updateCfgReq.RedirectUris[0] != "https://old.example.com/cb" {
		t.Errorf("repair must preserve redirect uris: %v", stub.updateCfgReq.RedirectUris)
	}
}

// TestProvisioner_RecoverSkipsRepairWhenAlreadyDesired verifies recovery is
// idempotent: an app already carrying the exact LoginV2 configuration is
// adopted without a redundant config write.
func TestProvisioner_RecoverSkipsRepairWhenAlreadyDesired(t *testing.T) {
	spec := webServerSpec()
	recovered := oidcAppFixture(appv1.AppState_APP_STATE_ACTIVE)
	recovered.GetApp().GetOidcConfig().ClientId = "prov-client-existing"
	base := testInteractionBase
	recovered.GetApp().GetOidcConfig().LoginVersion = &appv1.LoginVersion{
		Version: &appv1.LoginVersion_LoginV2{LoginV2: &appv1.LoginV2{BaseUri: &base}},
	}
	stub := &stubManagement{
		listResp:   &management.ListAppsResponse{Result: []*appv1.App{{Id: "existing", Name: spec.DisplayName}}},
		getResp:    recovered,
		rotateResp: &management.RegenerateOIDCClientSecretResponse{ClientSecret: "recovered-secret"},
	}
	p := newTestProvisioner(t, stub)

	if _, err := p.ProvisionClient(context.Background(), "idem-already", spec); err != nil {
		t.Fatalf("recover: %v", err)
	}
	if stub.updateCfgReq != nil {
		t.Error("an app already on the desired LoginVersion must not be rewritten")
	}
}

// TestProvisioner_RecoverFailsClosedWhenRepairFails verifies a failed
// LoginVersion repair blocks adoption: a bad app must never be surfaced as a
// successful provision.
func TestProvisioner_RecoverFailsClosedWhenRepairFails(t *testing.T) {
	spec := webServerSpec()
	recovered := oidcAppFixture(appv1.AppState_APP_STATE_ACTIVE)
	recovered.GetApp().GetOidcConfig().ClientId = "prov-client-existing"
	stub := &stubManagement{
		listResp:     &management.ListAppsResponse{Result: []*appv1.App{{Id: "existing", Name: spec.DisplayName}}},
		getResp:      recovered,
		updateCfgErr: status.Error(codes.Unavailable, "down"),
		rotateResp:   &management.RegenerateOIDCClientSecretResponse{ClientSecret: "must-not-surface"},
	}
	p := newTestProvisioner(t, stub)

	res, err := p.ProvisionClient(context.Background(), "idem-broken", spec)
	if err == nil {
		t.Fatalf("repair failure must block adoption, got result %+v", res)
	}
	if res.ClientSecret != "" {
		t.Error("a failed repair must never surface a secret")
	}
}

// TestProvisioner_EmptyInteractionBaseKeepsLegacyBehavior verifies that
// without a configured public origin the provisioner keeps the pre-Phase-3.6
// behavior: LoginVersion is neither submitted nor enforced. Production
// validation never allows this state (UP_OAUTH_PUBLIC_ORIGIN is mandatory).
func TestProvisioner_EmptyInteractionBaseKeepsLegacyBehavior(t *testing.T) {
	stub := &stubManagement{addResp: &management.AddOIDCAppResponse{
		AppId: "prov-app-legacy", ClientId: "prov-client-legacy", ClientSecret: "s",
	}}
	p := newLegacyProvisioner(t, stub)

	if _, err := p.ProvisionClient(context.Background(), "idem-legacy", webServerSpec()); err != nil {
		t.Fatalf("provision: %v", err)
	}
	if stub.addReq.LoginVersion != nil {
		t.Error("legacy creation must not submit a LoginVersion")
	}

	// Update preserves the provider's existing LoginVersion instead of
	// forcing one.
	stub2 := &stubManagement{getResp: richOIDCAppFixture()}
	p2 := newLegacyProvisioner(t, stub2)
	err := p2.UpdateClient(context.Background(), "prov-app-rich", applications.ClientUpdateSpec{
		RedirectURIs: []string{"https://new.example.com/cb"},
	})
	if err != nil {
		t.Fatalf("update: %v", err)
	}
	if stub2.updateCfgReq.LoginVersion.GetLoginV1() == nil {
		t.Errorf("legacy update must preserve the existing LoginVersion, got %+v", stub2.updateCfgReq.LoginVersion)
	}
}

func TestProvisioner_UpdateRejectsNonOIDCApp(t *testing.T) {
	stub := &stubManagement{getResp: &management.GetAppByIDResponse{
		App: &appv1.App{Id: "prov-app-1", Config: &appv1.App_ApiConfig{ApiConfig: &appv1.APIConfig{}}},
	}}
	p := newTestProvisioner(t, stub)

	err := p.UpdateClient(context.Background(), "prov-app-1", applications.ClientUpdateSpec{DisplayName: "x"})
	if !errors.Is(err, applications.ErrProviderConflict) {
		t.Fatalf("got %v, want ErrProviderConflict", err)
	}
}

func TestProvisioner_EnableDisableIdempotent(t *testing.T) {
	stub := &stubManagement{getResp: oidcAppFixture(appv1.AppState_APP_STATE_ACTIVE)}
	p := newTestProvisioner(t, stub)

	if err := p.EnableClient(context.Background(), "prov-app-1"); err != nil {
		t.Fatalf("enable: %v", err)
	}
	if stub.reactivated != 0 {
		t.Error("already-active app must not be reactivated")
	}
	if err := p.DisableClient(context.Background(), "prov-app-1"); err != nil {
		t.Fatalf("disable: %v", err)
	}
	if stub.deactivated != 1 {
		t.Errorf("deactivate calls: %d, want 1", stub.deactivated)
	}

	// Inactive app: enable acts, disable is a no-op.
	stub2 := &stubManagement{getResp: oidcAppFixture(appv1.AppState_APP_STATE_INACTIVE)}
	p2 := newTestProvisioner(t, stub2)
	if err := p2.DisableClient(context.Background(), "prov-app-1"); err != nil {
		t.Fatalf("disable inactive: %v", err)
	}
	if stub2.deactivated != 0 {
		t.Error("already-inactive app must not be deactivated again")
	}
	if err := p2.EnableClient(context.Background(), "prov-app-1"); err != nil {
		t.Fatalf("enable inactive: %v", err)
	}
	if stub2.reactivated != 1 {
		t.Errorf("reactivate calls: %d, want 1", stub2.reactivated)
	}
}

func TestProvisioner_DeleteIdempotent(t *testing.T) {
	stub := &stubManagement{removeErr: status.Error(codes.NotFound, "APP-gone")}
	p := newTestProvisioner(t, stub)

	if err := p.DeleteClient(context.Background(), "prov-app-1"); err != nil {
		t.Fatalf("delete of removed app must succeed, got %v", err)
	}

	stub2 := &stubManagement{removeErr: status.Error(codes.Unavailable, "down")}
	p2 := newTestProvisioner(t, stub2)
	if err := p2.DeleteClient(context.Background(), "prov-app-1"); !errors.Is(err, applications.ErrProviderUnavailable) {
		t.Fatalf("got %v, want ErrProviderUnavailable", err)
	}
}

func TestProvisioner_RotateClientSecret(t *testing.T) {
	stub := &stubManagement{rotateResp: &management.RegenerateOIDCClientSecretResponse{ClientSecret: "new-secret"}}
	p := newTestProvisioner(t, stub)

	rot, err := p.RotateClientSecret(context.Background(), "prov-app-1")
	if err != nil {
		t.Fatalf("rotate: %v", err)
	}
	if rot.NewSecret != "new-secret" {
		t.Errorf("secret: %q", rot.NewSecret)
	}

	// An empty secret is a provider fault, fail closed.
	stub2 := &stubManagement{rotateResp: &management.RegenerateOIDCClientSecretResponse{}}
	p2 := newTestProvisioner(t, stub2)
	if _, err := p2.RotateClientSecret(context.Background(), "prov-app-1"); !errors.Is(err, applications.ErrProviderUnavailable) {
		t.Fatalf("empty secret: got %v, want ErrProviderUnavailable", err)
	}

	// Ambiguous provider outcomes (Unavailable, DeadlineExceeded) map to
	// outcome-unknown: rotation is non-idempotent, the old secret may
	// already be revoked (ADR-0004 §6).
	stub3 := &stubManagement{rotateErr: status.Error(codes.Unavailable, "down")}
	p3 := newTestProvisioner(t, stub3)
	if _, err := p3.RotateClientSecret(context.Background(), "prov-app-1"); !errors.Is(err, applications.ErrProviderOutcomeUnknown) {
		t.Fatalf("rotate unavailable: got %v, want ErrProviderOutcomeUnknown", err)
	}
	stub4 := &stubManagement{rotateErr: status.Error(codes.DeadlineExceeded, "slow")}
	p4 := newTestProvisioner(t, stub4)
	if _, err := p4.RotateClientSecret(context.Background(), "prov-app-1"); !errors.Is(err, applications.ErrProviderOutcomeUnknown) {
		t.Fatalf("rotate deadline: got %v, want ErrProviderOutcomeUnknown", err)
	}

	// Definitive rejections keep their stable classes.
	stub5 := &stubManagement{rotateErr: status.Error(codes.NotFound, "APP-gone")}
	p5 := newTestProvisioner(t, stub5)
	if _, err := p5.RotateClientSecret(context.Background(), "prov-app-1"); !errors.Is(err, applications.ErrProviderConflict) {
		t.Fatalf("rotate not found: got %v, want ErrProviderConflict", err)
	}
}

func TestProvisioner_VerifyProject(t *testing.T) {
	stub := &stubManagement{}
	p := newTestProvisioner(t, stub)
	if err := p.VerifyProject(context.Background()); err != nil {
		t.Fatalf("verify: %v", err)
	}

	stub2 := &stubManagement{projectErr: status.Error(codes.NotFound, "AUTHZ-x")}
	p2 := newTestProvisioner(t, stub2)
	if err := p2.VerifyProject(context.Background()); !errors.Is(err, applications.ErrProviderUnavailable) {
		t.Fatalf("verify failed: got %v, want ErrProviderUnavailable", err)
	}
}

func TestNewProvisioner_FailsClosedWithoutProject(t *testing.T) {
	if _, err := NewProvisioner(&stubManagement{}, "", testInteractionBase, nil); err == nil {
		t.Fatal("empty project id must fail closed")
	}
}

// --- LoginVersion backfill (ADR-0005 §1 rollout step 4) ---

// backfillAppFixture builds a stored app with an OIDC config carrying the
// given LoginVersion (nil = unset, the pre-Phase-3 state).
func backfillAppFixture(appID, name string, loginVersion *appv1.LoginVersion) *management.GetAppByIDResponse {
	return &management.GetAppByIDResponse{
		App: &appv1.App{
			Id:   appID,
			Name: name,
			Config: &appv1.App_OidcConfig{
				OidcConfig: &appv1.OIDCConfig{
					ClientId:       "client-" + appID,
					RedirectUris:   []string{"https://legacy.example.com/cb"},
					ResponseTypes:  []appv1.OIDCResponseType{appv1.OIDCResponseType_OIDC_RESPONSE_TYPE_CODE},
					GrantTypes:     []appv1.OIDCGrantType{appv1.OIDCGrantType_OIDC_GRANT_TYPE_AUTHORIZATION_CODE},
					AppType:        appv1.OIDCAppType_OIDC_APP_TYPE_WEB,
					AuthMethodType: appv1.OIDCAuthMethodType_OIDC_AUTH_METHOD_TYPE_BASIC,
					DevMode:        true,
					LoginVersion:   loginVersion,
				},
			},
		},
	}
}

func loginV2Fixture(base string) *appv1.LoginVersion {
	return &appv1.LoginVersion{
		Version: &appv1.LoginVersion_LoginV2{LoginV2: &appv1.LoginV2{BaseUri: &base}},
	}
}

// singleAppList scripts a one-page ListApps containing the given apps.
func singleAppList(apps ...*appv1.App) func(uint64, uint32) (*management.ListAppsResponse, error) {
	return func(offset uint64, _ uint32) (*management.ListAppsResponse, error) {
		if offset > 0 {
			return &management.ListAppsResponse{}, nil
		}
		return &management.ListAppsResponse{
			Result: apps,
		}, nil
	}
}

func TestBackfill_AlreadyCorrectWritesNothing(t *testing.T) {
	stub := &stubManagement{
		listFn:   singleAppList(&appv1.App{Id: "app-1", Name: "Correct App"}),
		getByApp: map[string]*management.GetAppByIDResponse{"app-1": backfillAppFixture("app-1", "Correct App", loginV2Fixture(testInteractionBase))},
	}
	p := newTestProvisioner(t, stub)

	report, err := p.BackfillLoginVersions(context.Background())
	if err != nil {
		t.Fatalf("backfill: %v", err)
	}
	if !report.Success() || report.Verified != 1 || report.Repaired != 0 || stub.updateCfgCount != 0 {
		t.Fatalf("report: %+v, updates: %d", report, stub.updateCfgCount)
	}
}

func TestBackfill_RepairsMissingLoginVersionAndReadsBack(t *testing.T) {
	stub := &stubManagement{
		listFn:            singleAppList(&appv1.App{Id: "app-1", Name: "Legacy App"}),
		getByApp:          map[string]*management.GetAppByIDResponse{"app-1": backfillAppFixture("app-1", "Legacy App", nil)},
		applyLoginVersion: true,
	}
	p := newTestProvisioner(t, stub)

	report, err := p.BackfillLoginVersions(context.Background())
	if err != nil {
		t.Fatalf("backfill: %v", err)
	}
	if !report.Success() || report.Repaired != 1 || stub.updateCfgCount != 1 {
		t.Fatalf("report: %+v, updates: %d", report, stub.updateCfgCount)
	}
	wantLoginV2(t, stub.updateCfgReq.LoginVersion, testInteractionBase)
	// The repair preserves the app's existing config.
	if len(stub.updateCfgReq.RedirectUris) != 1 || stub.updateCfgReq.RedirectUris[0] != "https://legacy.example.com/cb" {
		t.Errorf("repair must preserve redirect uris: %v", stub.updateCfgReq.RedirectUris)
	}
}

func TestBackfill_RepairsWrongBaseURI(t *testing.T) {
	stub := &stubManagement{
		listFn:            singleAppList(&appv1.App{Id: "app-1", Name: "Wrong Base"}),
		getByApp:          map[string]*management.GetAppByIDResponse{"app-1": backfillAppFixture("app-1", "Wrong Base", loginV2Fixture("https://stale.example.com/_interaction"))},
		applyLoginVersion: true,
	}
	p := newTestProvisioner(t, stub)

	report, err := p.BackfillLoginVersions(context.Background())
	if err != nil || !report.Success() || report.Repaired != 1 {
		t.Fatalf("report: %+v, err: %v", report, err)
	}
	wantLoginV2(t, stub.updateCfgReq.LoginVersion, testInteractionBase)
}

func TestBackfill_RepairsLoginV1PreservingConfig(t *testing.T) {
	fixture := richOIDCAppFixture()
	fixture.GetApp().Name = "LoginV1 App"
	stub := &stubManagement{
		listFn:            singleAppList(&appv1.App{Id: "prov-app-rich", Name: "LoginV1 App"}),
		getByApp:          map[string]*management.GetAppByIDResponse{"prov-app-rich": fixture},
		applyLoginVersion: true,
	}
	p := newTestProvisioner(t, stub)

	report, err := p.BackfillLoginVersions(context.Background())
	if err != nil || !report.Success() || report.Repaired != 1 {
		t.Fatalf("report: %+v, err: %v", report, err)
	}
	cfg := stub.updateCfgReq
	wantLoginV2(t, cfg.LoginVersion, testInteractionBase)
	// Full-config preservation holds on the backfill path too.
	if !cfg.AccessTokenRoleAssertion || !cfg.IdTokenRoleAssertion || !cfg.IdTokenUserinfoAssertion {
		t.Error("role/userinfo assertions not preserved")
	}
	if cfg.ClockSkew.AsDuration() != 5*time.Minute || !cfg.SkipNativeAppSuccessPage {
		t.Error("clock skew / native success page not preserved")
	}
	if cfg.BackChannelLogoutUri != "https://old.example.com/backchannel" {
		t.Errorf("back-channel logout not preserved: %q", cfg.BackChannelLogoutUri)
	}
}

func TestBackfill_SkipsNonOIDCApp(t *testing.T) {
	stub := &stubManagement{
		listFn: singleAppList(
			&appv1.App{Id: "app-api", Name: "API App"},
			&appv1.App{Id: "app-oidc", Name: "OIDC App"},
		),
		getByApp: map[string]*management.GetAppByIDResponse{
			"app-api":  {App: &appv1.App{Id: "app-api", Name: "API App", Config: &appv1.App_ApiConfig{ApiConfig: &appv1.APIConfig{}}}},
			"app-oidc": backfillAppFixture("app-oidc", "OIDC App", loginV2Fixture(testInteractionBase)),
		},
	}
	p := newTestProvisioner(t, stub)

	report, err := p.BackfillLoginVersions(context.Background())
	if err != nil {
		t.Fatalf("backfill: %v", err)
	}
	if !report.Success() || report.Skipped != 1 || report.Verified != 1 || stub.updateCfgCount != 0 {
		t.Fatalf("report: %+v, updates: %d", report, stub.updateCfgCount)
	}
}

func TestBackfill_FailsClosedWithoutInteractionBase(t *testing.T) {
	p := newLegacyProvisioner(t, &stubManagement{})
	if _, err := p.BackfillLoginVersions(context.Background()); err == nil {
		t.Fatal("backfill without an interaction base must fail closed")
	}
}

func TestBackfill_RepairFailureFailsJob(t *testing.T) {
	stub := &stubManagement{
		listFn:       singleAppList(&appv1.App{Id: "app-1", Name: "Legacy App"}),
		getByApp:     map[string]*management.GetAppByIDResponse{"app-1": backfillAppFixture("app-1", "Legacy App", nil)},
		updateCfgErr: status.Error(codes.Unavailable, "down"),
	}
	p := newTestProvisioner(t, stub)

	report, err := p.BackfillLoginVersions(context.Background())
	if err == nil || report.Success() || report.Failed != 1 {
		t.Fatalf("report: %+v, err: %v", report, err)
	}
}

func TestBackfill_ReadBackMismatchFailsJob(t *testing.T) {
	// The provider acknowledges the update but the read-back still shows the
	// stale configuration: the job must fail instead of trusting the write.
	stub := &stubManagement{
		listFn:            singleAppList(&appv1.App{Id: "app-1", Name: "Legacy App"}),
		getByApp:          map[string]*management.GetAppByIDResponse{"app-1": backfillAppFixture("app-1", "Legacy App", nil)},
		applyLoginVersion: false,
	}
	p := newTestProvisioner(t, stub)

	report, err := p.BackfillLoginVersions(context.Background())
	if err == nil || report.Success() || report.Failed != 1 {
		t.Fatalf("report: %+v, err: %v", report, err)
	}
}

func TestBackfill_ReadFailureFailsJob(t *testing.T) {
	stub := &stubManagement{
		listFn: singleAppList(&appv1.App{Id: "app-1", Name: "Legacy App"}),
		getErr: status.Error(codes.NotFound, "AUTHZ-x"),
	}
	p := newTestProvisioner(t, stub)

	report, err := p.BackfillLoginVersions(context.Background())
	if err == nil || report.Success() || report.Failed != 1 {
		t.Fatalf("report: %+v, err: %v", report, err)
	}
}

func TestBackfill_PaginatesAllPages(t *testing.T) {
	apps := []*appv1.App{
		{Id: "app-1", Name: "One"},
		{Id: "app-2", Name: "Two"},
		{Id: "app-3", Name: "Three"},
	}
	var offsets []uint64
	stub := &stubManagement{
		listFn: func(offset uint64, limit uint32) (*management.ListAppsResponse, error) {
			offsets = append(offsets, offset)
			// Page size 2 forces a second page for 3 apps. The provider
			// reports the total (ZITADEL always does), which is authoritative:
			// the short final page must not end the walk early.
			start := int(offset)
			end := start + 2
			if end > len(apps) {
				end = len(apps)
			}
			if start >= len(apps) {
				return &management.ListAppsResponse{Details: &objectv1.ListDetails{TotalResult: uint64(len(apps))}}, nil
			}
			return &management.ListAppsResponse{
				Details: &objectv1.ListDetails{TotalResult: uint64(len(apps))},
				Result:  apps[start:end],
			}, nil
		},
		getByApp: map[string]*management.GetAppByIDResponse{
			"app-1": backfillAppFixture("app-1", "One", loginV2Fixture(testInteractionBase)),
			"app-2": backfillAppFixture("app-2", "Two", loginV2Fixture(testInteractionBase)),
			"app-3": backfillAppFixture("app-3", "Three", loginV2Fixture(testInteractionBase)),
		},
	}
	p := newTestProvisioner(t, stub)

	report, err := p.BackfillLoginVersions(context.Background())
	if err != nil || !report.Success() || report.Verified != 3 {
		t.Fatalf("report: %+v, err: %v", report, err)
	}
	if len(offsets) != 2 || offsets[0] != 0 || offsets[1] != 2 {
		t.Fatalf("pagination offsets = %v, want [0 2]", offsets)
	}
}

func TestBackfill_RunTwiceSecondNoOp(t *testing.T) {
	stub := &stubManagement{
		listFn:            singleAppList(&appv1.App{Id: "app-1", Name: "Legacy App"}),
		getByApp:          map[string]*management.GetAppByIDResponse{"app-1": backfillAppFixture("app-1", "Legacy App", nil)},
		applyLoginVersion: true,
	}
	p := newTestProvisioner(t, stub)

	first, err := p.BackfillLoginVersions(context.Background())
	if err != nil || !first.Success() || first.Repaired != 1 {
		t.Fatalf("first run: %+v, err: %v", first, err)
	}
	second, err := p.BackfillLoginVersions(context.Background())
	if err != nil || !second.Success() || second.Verified != 1 || second.Repaired != 0 {
		t.Fatalf("second run: %+v, err: %v", second, err)
	}
	if stub.updateCfgCount != 1 {
		t.Fatalf("second run must be a no-op, got %d config updates", stub.updateCfgCount)
	}
}
