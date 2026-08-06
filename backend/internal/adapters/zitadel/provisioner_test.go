package zitadel

import (
	"context"
	"errors"
	"log/slog"
	"testing"

	"github.com/GravelEvolution/united-pass/backend/internal/applications"

	appv1 "github.com/zitadel/zitadel-go/v3/pkg/client/zitadel/app"
	management "github.com/zitadel/zitadel-go/v3/pkg/client/zitadel/management"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
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
}

func (s *stubManagement) GetProjectByID(ctx context.Context, in *management.GetProjectByIDRequest, opts ...grpc.CallOption) (*management.GetProjectByIDResponse, error) {
	return &management.GetProjectByIDResponse{}, s.projectErr
}

func (s *stubManagement) ListApps(ctx context.Context, in *management.ListAppsRequest, opts ...grpc.CallOption) (*management.ListAppsResponse, error) {
	if s.listErr != nil {
		return nil, s.listErr
	}
	if s.listResp != nil {
		return s.listResp, nil
	}
	return &management.ListAppsResponse{}, nil
}

func (s *stubManagement) GetAppByID(ctx context.Context, in *management.GetAppByIDRequest, opts ...grpc.CallOption) (*management.GetAppByIDResponse, error) {
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
	return &management.UpdateOIDCAppConfigResponse{}, s.updateCfgErr
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

func newTestProvisioner(t *testing.T, stub *stubManagement) *Provisioner {
	t.Helper()
	p, err := NewProvisioner(stub, "proj-test", slog.New(slog.DiscardHandler))
	if err != nil {
		t.Fatalf("new provisioner: %v", err)
	}
	return p
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

func TestProvisioner_ServerToServerMapping(t *testing.T) {
	stub := &stubManagement{addResp: &management.AddOIDCAppResponse{
		AppId: "prov-app-3", ClientId: "prov-client-3", ClientSecret: "s2s-secret",
	}}
	p := newTestProvisioner(t, stub)

	res, err := p.ProvisionClient(context.Background(), "idem-3", applications.ClientProvisionSpec{
		DisplayName: "S2S Client",
		Profile:     applications.ClientProfileServerToServer,
	})
	if err != nil {
		t.Fatalf("provision: %v", err)
	}
	if res.ClientSecret != "s2s-secret" {
		t.Errorf("secret: %q", res.ClientSecret)
	}
	if stub.addReq.AppType != appv1.OIDCAppType_OIDC_APP_TYPE_WEB ||
		stub.addReq.AuthMethodType != appv1.OIDCAuthMethodType_OIDC_AUTH_METHOD_TYPE_BASIC {
		t.Errorf("s2s mapping: app=%v auth=%v", stub.addReq.AppType, stub.addReq.AuthMethodType)
	}
	if len(stub.addReq.RedirectUris) != 0 {
		t.Errorf("s2s must not send redirect uris: %v", stub.addReq.RedirectUris)
	}
	// client_credentials has no pinned enum value; the adapter registers
	// authorization_code and relies on the token endpoint (ADR-0004 §1).
	if len(stub.addReq.GrantTypes) != 1 || stub.addReq.GrantTypes[0] != appv1.OIDCGrantType_OIDC_GRANT_TYPE_AUTHORIZATION_CODE {
		t.Errorf("s2s grants: %v", stub.addReq.GrantTypes)
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

func TestProvisioner_ProvisionDuplicatePrecheck(t *testing.T) {
	stub := &stubManagement{
		listResp: &management.ListAppsResponse{Result: []*appv1.App{{Id: "existing"}}},
		addResp:  &management.AddOIDCAppResponse{},
	}
	p := newTestProvisioner(t, stub)

	_, err := p.ProvisionClient(context.Background(), "idem-5", webServerSpec())
	if !errors.Is(err, applications.ErrProviderConflict) {
		t.Fatalf("got %v, want ErrProviderConflict", err)
	}
	if stub.added != 0 {
		t.Error("duplicate precheck must prevent AddOIDCApp")
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
		{"unavailable", status.Error(codes.Unavailable, "transport"), applications.ErrProviderUnavailable},
		{"permission", status.Error(codes.NotFound, "AUTHZ-xxx"), applications.ErrProviderConflict},
		{"internal", status.Error(codes.Internal, "boom"), applications.ErrProviderUnavailable},
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

func TestProvisioner_UpdatePreservesProviderConfig(t *testing.T) {
	stub := &stubManagement{getResp: oidcAppFixture(appv1.AppState_APP_STATE_ACTIVE)}
	p := newTestProvisioner(t, stub)

	err := p.UpdateClient(context.Background(), "prov-app-1", applications.ClientUpdateSpec{
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
	if len(cfg.RedirectUris) != 1 || cfg.RedirectUris[0] != "https://new.example.com/cb" {
		t.Errorf("RedirectUris: %v", cfg.RedirectUris)
	}
	if len(cfg.PostLogoutRedirectUris) != 1 || cfg.PostLogoutRedirectUris[0] != "https://new.example.com/logout" {
		t.Errorf("PostLogout: %v", cfg.PostLogoutRedirectUris)
	}
	// Fields the adapter does not own must be preserved verbatim.
	if !cfg.DevMode || cfg.AccessTokenType != appv1.OIDCTokenType_OIDC_TOKEN_TYPE_JWT ||
		cfg.AppType != appv1.OIDCAppType_OIDC_APP_TYPE_WEB {
		t.Errorf("provider config not preserved: %+v", cfg)
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
	if _, err := NewProvisioner(&stubManagement{}, "", nil); err == nil {
		t.Fatal("empty project id must fail closed")
	}
}
