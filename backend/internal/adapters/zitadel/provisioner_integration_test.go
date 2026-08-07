//
// Copyright (c) 2026 Chen Jiajie(Ariakage)
//
// Author: Chen Jiajie(Ariakage) <ariakage233@gmail.com>
// Date: 2026-08-07
// Description: Live LoginVersion enforcement and path-prefix probe against a
//              real ZITADEL instance (ADR-0005 §1, Phase 3.6 acceptance)
//

//go:build integration

// Live topology acceptance for Phase 3.6. Skipped unless the following
// variables are set:
//
//	UP_TEST_ZITADEL_BASE_URL     e.g. http://localhost:8080
//	UP_TEST_ZITADEL_KEY_FILE     path to the service account key.json
//	UP_TEST_ZITADEL_PROJECT_ID   the shared United Pass project
//
// The test provisions a probe app with LoginVersion = LoginV2{BaseURI =
// <origin>/_interaction} submitted atomically in AddOIDCApp, reads the
// configuration back live, forces it again through the UpdateClient
// read-modify-write, then observes the real authorize redirect to verify
// ZITADEL preserves the /_interaction path prefix (ADR-0005 §1). The probe
// app is deleted afterwards; the single pending auth request it creates is
// never completed and expires unused.
package zitadel

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/GravelEvolution/united-pass/backend/internal/applications"
	"github.com/GravelEvolution/united-pass/backend/internal/config"

	management "github.com/zitadel/zitadel-go/v3/pkg/client/zitadel/management"
)

const probeAppName = "United Pass topology probe (P3.6)"

func TestIntegration_ProvisionerLoginVersionTopology(t *testing.T) {
	cfg := testZitadelConfig(t)
	if cfg.ProjectID == "" {
		t.Skip("UP_TEST_ZITADEL_PROJECT_ID not set; skipping topology acceptance")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 120*time.Second)
	defer cancel()

	sdk, err := NewSDKClient(ctx, cfg)
	if err != nil {
		t.Fatalf("NewSDKClient: %v", err)
	}
	defer sdk.Close()

	// Local acceptance: the instance itself is the public origin, so the
	// interaction base exercises the real production derivation rule.
	interactionBase := config.OAuthConfig{PublicOrigin: cfg.BaseURL}.InteractionBaseURI()
	t.Logf("public origin: %s", cfg.BaseURL)
	t.Logf("interaction base URI (derived): %s", interactionBase)

	p, err := NewProvisioner(sdk.ManagementService(), cfg.ProjectID, interactionBase, nil)
	if err != nil {
		t.Fatalf("NewProvisioner: %v", err)
	}

	spec := applications.ClientProvisionSpec{
		DisplayName:  probeAppName,
		Profile:      applications.ClientProfileWebServer,
		RedirectURIs: []string{"https://topology-probe.example/callback"},
		LogoutURI:    "https://topology-probe.example/logout",
		Scopes:       []string{"openid"},
	}
	res, err := p.ProvisionClient(ctx, "topology-probe", spec)
	if err != nil {
		t.Fatalf("ProvisionClient: %v", err)
	}
	t.Logf("probe app: applicationId=%s clientId=%s", res.ProviderApplicationID, redactMiddle(res.ProviderClientID))
	defer func() {
		if err := p.DeleteClient(context.Background(), res.ProviderApplicationID); err != nil {
			t.Errorf("cleanup DeleteClient: %v", err)
		}
	}()

	// Live read-back 1: creation must have submitted LoginVersion atomically.
	assertLiveLoginVersion(t, ctx, sdk.ManagementService(), cfg.ProjectID, res.ProviderApplicationID, interactionBase)

	// Live read-back 2: the UpdateClient read-modify-write re-enforces the
	// configuration while preserving provider-owned fields.
	if err := p.UpdateClient(ctx, res.ProviderApplicationID, applications.ClientUpdateSpec{
		RedirectURIs: []string{"https://topology-probe.example/callback", "https://topology-probe.example/cb2"},
		LogoutURI:    "https://topology-probe.example/logout",
	}); err != nil {
		t.Fatalf("UpdateClient: %v", err)
	}
	assertLiveLoginVersion(t, ctx, sdk.ManagementService(), cfg.ProjectID, res.ProviderApplicationID, interactionBase)

	// Live discovery record for the acceptance evidence.
	recordDiscovery(t, cfg.BaseURL)

	// Live path-prefix probe: the authorize endpoint must redirect into
	// <interaction-base>/login?authRequest=…, i.e. ZITADEL's JoinPath keeps
	// the /_interaction prefix (ADR-0005 §1).
	observeAuthorizeRedirect(t, cfg.BaseURL, interactionBase, res.ProviderClientID, spec.RedirectURIs[0])
}

// assertLiveLoginVersion reads the app back from the provider and asserts the
// exact LoginV2{BaseUri} configuration. This is the live read-back
// verification the rollout runbook requires (never trust the write response
// alone).
func assertLiveLoginVersion(t *testing.T, ctx context.Context, mgmt management.ManagementServiceClient, projectID, appID, wantBase string) {
	t.Helper()
	resp, err := mgmt.GetAppByID(ctx, &management.GetAppByIDRequest{ProjectId: projectID, AppId: appID})
	if err != nil {
		t.Fatalf("read-back GetAppByID: %v", err)
	}
	got := resp.GetApp().GetOidcConfig().GetLoginVersion()
	if got.GetLoginV2().GetBaseUri() != wantBase {
		t.Fatalf("read-back LoginVersion = %+v, want LoginV2{BaseUri=%q}", got, wantBase)
	}
	t.Logf("read-back LoginVersion: LoginV2 BaseUri=%s", got.GetLoginV2().GetBaseUri())
}

// recordDiscovery fetches the discovery document and logs the issuer and the
// protocol endpoints for the acceptance record.
func recordDiscovery(t *testing.T, origin string) {
	t.Helper()
	client := &http.Client{Timeout: 15 * time.Second}
	resp, err := client.Get(origin + "/.well-known/openid-configuration")
	if err != nil {
		t.Fatalf("discovery fetch: %v", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("discovery status = %d", resp.StatusCode)
	}
	var doc struct {
		Issuer                      string `json:"issuer"`
		AuthorizationEndpoint       string `json:"authorization_endpoint"`
		TokenEndpoint               string `json:"token_endpoint"`
		JWKSURI                     string `json:"jwks_uri"`
		UserinfoEndpoint            string `json:"userinfo_endpoint"`
		EndSessionEndpoint          string `json:"end_session_endpoint"`
		DeviceAuthorizationEndpoint string `json:"device_authorization_endpoint"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&doc); err != nil {
		t.Fatalf("discovery decode: %v", err)
	}
	if doc.Issuer != origin {
		t.Errorf("discovery issuer = %q, want %q", doc.Issuer, origin)
	}
	t.Logf("discovery issuer: %s", doc.Issuer)
	t.Logf("  authorization_endpoint: %s", doc.AuthorizationEndpoint)
	t.Logf("  token_endpoint: %s", doc.TokenEndpoint)
	t.Logf("  jwks_uri: %s", doc.JWKSURI)
	t.Logf("  userinfo_endpoint: %s", doc.UserinfoEndpoint)
	t.Logf("  end_session_endpoint: %s", doc.EndSessionEndpoint)
	t.Logf("  device_authorization_endpoint: %s", doc.DeviceAuthorizationEndpoint)
}

// observeAuthorizeRedirect issues a browser-grade authorization request and
// asserts the observed redirect Location preserves the interaction base
// path prefix. The authRequest value is redacted in all log output.
func observeAuthorizeRedirect(t *testing.T, origin, interactionBase, clientID, redirectURI string) {
	t.Helper()
	query := url.Values{}
	query.Set("client_id", clientID)
	query.Set("redirect_uri", redirectURI)
	query.Set("response_type", "code")
	query.Set("scope", "openid")
	query.Set("state", fmt.Sprintf("p36-probe-%d", time.Now().Unix()))

	client := &http.Client{
		Timeout: 15 * time.Second,
		CheckRedirect: func(*http.Request, []*http.Request) error {
			return http.ErrUseLastResponse
		},
	}
	resp, err := client.Get(origin + "/oauth/v2/authorize?" + query.Encode())
	if err != nil {
		t.Fatalf("authorize request: %v", err)
	}
	defer resp.Body.Close()
	location := resp.Header.Get("Location")
	t.Logf("authorize status: %d", resp.StatusCode)
	t.Logf("observed login redirect: %s", redactAuthRequest(location))

	wantPrefix := interactionBase + "/login?authRequest="
	if !strings.HasPrefix(location, wantPrefix) {
		if strings.HasPrefix(location, origin+"/login?") {
			t.Fatalf("path prefix NOT preserved: ZITADEL fell back to the LoginV1 /login path (LoginVersion not applied?)")
		}
		t.Fatalf("path prefix NOT preserved: redirect does not start with %q", wantPrefix)
	}
	t.Log("path-prefix preserved: YES")
}

// redactAuthRequest masks the authRequest value (provider-credential-grade
// material) for logging.
func redactAuthRequest(rawURL string) string {
	u, err := url.Parse(rawURL)
	if err != nil {
		return "(unparseable location)"
	}
	id := u.Query().Get("authRequest")
	if id == "" {
		return rawURL
	}
	shown := id
	if len(shown) > 8 {
		shown = shown[:8]
	}
	q := u.Query()
	q.Set("authRequest", shown+"…(redacted)")
	u.RawQuery = q.Encode()
	return u.String()
}

// redactMiddle keeps the ends of an identifier readable while masking the
// middle, so logs stay useful without exposing full provider identifiers.
func redactMiddle(s string) string {
	if len(s) <= 8 {
		return "****"
	}
	return s[:4] + "…" + s[len(s)-4:]
}
