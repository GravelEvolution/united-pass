package httpapi

import (
	"context"
	"encoding/json"
	"errors"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/go-chi/chi/v5"

	"github.com/GravelEvolution/united-pass/backend/internal/adapters/httpapi/request"
	"github.com/GravelEvolution/united-pass/backend/internal/applications"
	"github.com/GravelEvolution/united-pass/backend/internal/identity"
	"github.com/GravelEvolution/united-pass/backend/internal/permissions"
	"github.com/GravelEvolution/united-pass/backend/internal/session"
)

// --- Test fakes ---

// fakeAppStore is an in-memory applications.ApplicationStore for handler
// tests. Only state exercised by the HTTP layer is modeled faithfully.
type fakeAppStore struct {
	mu      sync.Mutex
	apps    map[applications.ApplicationID]applications.Application
	clients map[applications.OAuthClientID]applications.OAuthClient
	deleted map[applications.OAuthClientID]bool

	createErr       error
	completeErr     error
	listErr         error
	updateErr       error
	updateClientErr error
	setStatusErr    error
	deleteErr       error
}

func newFakeAppStore() *fakeAppStore {
	return &fakeAppStore{
		apps:    make(map[applications.ApplicationID]applications.Application),
		clients: make(map[applications.OAuthClientID]applications.OAuthClient),
		deleted: make(map[applications.OAuthClientID]bool),
	}
}

func (s *fakeAppStore) CreateApplicationWithInitialClient(_ context.Context, app applications.Application, client applications.OAuthClient, op applications.ProviderOperation) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.createErr != nil {
		return s.createErr
	}
	s.apps[app.ID] = app
	s.clients[client.ID] = client
	return nil
}

func (s *fakeAppStore) CompleteInitialProvisioning(_ context.Context, appID applications.ApplicationID, clientID applications.OAuthClientID, provider, providerProjectID, providerApplicationID, providerClientID string, _ applications.ProviderOperationID, secret *applications.ClientSecretRecord) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.completeErr != nil {
		return s.completeErr
	}
	app := s.apps[appID]
	app.Provisioning = applications.ProvisioningStatusProvisioned
	s.apps[appID] = app
	c := s.clients[clientID]
	c.Provisioning = applications.ProvisioningStatusProvisioned
	c.ProviderApplicationID = providerApplicationID
	c.ProviderClientID = providerClientID
	if secret != nil {
		c.SecretRecords = append(c.SecretRecords, *secret)
	}
	s.clients[clientID] = c
	return nil
}

func (s *fakeAppStore) MarkInitialProvisioningFailed(_ context.Context, _ applications.ApplicationID, clientID applications.OAuthClientID, _ applications.ProviderOperationID, _ string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	c := s.clients[clientID]
	c.Provisioning = applications.ProvisioningStatusProvisioningFailed
	s.clients[clientID] = c
	return nil
}

func (s *fakeAppStore) GetApplication(_ context.Context, appID applications.ApplicationID) (applications.Application, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	app, ok := s.apps[appID]
	if !ok {
		return applications.Application{}, applications.ErrNotFound
	}
	return app, nil
}

func (s *fakeAppStore) UpdateApplication(_ context.Context, appID applications.ApplicationID, upd applications.ApplicationUpdate, expectedVersion int) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.updateErr != nil {
		return s.updateErr
	}
	app, ok := s.apps[appID]
	if !ok {
		return applications.ErrNotFound
	}
	if app.Version != expectedVersion {
		return applications.ErrConflict
	}
	app.Name = upd.Name
	app.Description = upd.Description
	app.Audience = upd.Audience
	app.OwnerID = upd.OwnerID
	app.Version++
	s.apps[appID] = app
	return nil
}

func (s *fakeAppStore) SetApplicationStatus(_ context.Context, appID applications.ApplicationID, status applications.Status, expectedVersion int) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.setStatusErr != nil {
		return s.setStatusErr
	}
	app, ok := s.apps[appID]
	if !ok {
		return applications.ErrNotFound
	}
	if app.Version != expectedVersion {
		return applications.ErrConflict
	}
	app.Status = status
	app.Version++
	s.apps[appID] = app
	return nil
}

func (s *fakeAppStore) DeleteApplication(_ context.Context, appID applications.ApplicationID, expectedVersion int) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.deleteErr != nil {
		return s.deleteErr
	}
	app, ok := s.apps[appID]
	if !ok {
		return applications.ErrNotFound
	}
	if app.Version != expectedVersion {
		return applications.ErrConflict
	}
	delete(s.apps, appID)
	return nil
}

func (s *fakeAppStore) ListApplications(_ context.Context, _ applications.ListQuery) (applications.ListResult, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.listErr != nil {
		return applications.ListResult{}, s.listErr
	}
	items := make([]applications.ApplicationSummary, 0, len(s.apps))
	for _, app := range s.apps {
		if app.Provisioning != applications.ProvisioningStatusProvisioned {
			continue
		}
		items = append(items, applications.ApplicationSummary{Application: app})
	}
	return applications.ListResult{Items: items}, nil
}

func (s *fakeAppStore) ListClientsByApplication(_ context.Context, appID applications.ApplicationID) ([]applications.OAuthClient, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	var out []applications.OAuthClient
	for _, c := range s.clients {
		if c.ApplicationID == appID && !s.deleted[c.ID] && c.Provisioning == applications.ProvisioningStatusProvisioned {
			out = append(out, c)
		}
	}
	return out, nil
}

func (s *fakeAppStore) ListLiveClientsByApplication(_ context.Context, appID applications.ApplicationID) ([]applications.OAuthClient, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	var out []applications.OAuthClient
	for _, c := range s.clients {
		if c.ApplicationID == appID && !s.deleted[c.ID] {
			out = append(out, c)
		}
	}
	return out, nil
}

func (s *fakeAppStore) GetClient(_ context.Context, appID applications.ApplicationID, clientID applications.OAuthClientID) (applications.OAuthClient, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	c, ok := s.clients[clientID]
	if !ok || c.ApplicationID != appID || s.deleted[clientID] {
		return applications.OAuthClient{}, applications.ErrNotFound
	}
	return c, nil
}

func (s *fakeAppStore) CreateClientWithOperation(_ context.Context, client applications.OAuthClient, _ applications.ProviderOperation) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.createErr != nil {
		return s.createErr
	}
	s.clients[client.ID] = client
	return nil
}

func (s *fakeAppStore) CompleteClientProvisioning(_ context.Context, clientID applications.OAuthClientID, provider, providerProjectID, providerApplicationID, providerClientID string, _ applications.ProviderOperationID, secret *applications.ClientSecretRecord) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	c := s.clients[clientID]
	c.Provisioning = applications.ProvisioningStatusProvisioned
	c.ProviderApplicationID = providerApplicationID
	c.ProviderClientID = providerClientID
	if secret != nil {
		c.SecretRecords = append(c.SecretRecords, *secret)
	}
	s.clients[clientID] = c
	return nil
}

func (s *fakeAppStore) MarkClientProvisioningFailed(_ context.Context, clientID applications.OAuthClientID, _ applications.ProviderOperationID, _ string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	c := s.clients[clientID]
	c.Provisioning = applications.ProvisioningStatusProvisioningFailed
	s.clients[clientID] = c
	return nil
}

func (s *fakeAppStore) UpdateClientConfig(_ context.Context, clientID applications.OAuthClientID, upd applications.ClientConfigUpdate, expectedVersion int) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.updateClientErr != nil {
		return s.updateClientErr
	}
	c, ok := s.clients[clientID]
	if !ok {
		return applications.ErrNotFound
	}
	if c.Version != expectedVersion {
		return applications.ErrConflict
	}
	c.Name = upd.Name
	c.LogoutURI = upd.LogoutURI
	c.ConsentMode = upd.ConsentMode
	if upd.RedirectURIs != nil {
		c.RedirectURIs = upd.RedirectURIs
	}
	if upd.Scopes != nil {
		c.Scopes = upd.Scopes
	}
	c.Version++
	s.clients[clientID] = c
	return nil
}

func (s *fakeAppStore) SetClientStatus(_ context.Context, clientID applications.OAuthClientID, status applications.Status, expectedVersion int) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	c, ok := s.clients[clientID]
	if !ok {
		return applications.ErrNotFound
	}
	if c.Version != expectedVersion {
		return applications.ErrConflict
	}
	c.Status = status
	c.Version++
	s.clients[clientID] = c
	return nil
}

func (s *fakeAppStore) MarkClientDeleting(_ context.Context, clientID applications.OAuthClientID, _ applications.ProviderOperation) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	c, ok := s.clients[clientID]
	if !ok {
		return applications.ErrNotFound
	}
	switch c.Provisioning {
	case applications.ProvisioningStatusProvisioned, applications.ProvisioningStatusProvisioning, applications.ProvisioningStatusProvisioningFailed:
	default:
		return applications.ErrConflict
	}
	c.Provisioning = applications.ProvisioningStatusDeleting
	s.clients[clientID] = c
	return nil
}

func (s *fakeAppStore) MarkClientDeletingRetry(_ context.Context, clientID applications.OAuthClientID, _ applications.ProviderOperation) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	c, ok := s.clients[clientID]
	if !ok {
		return applications.ErrNotFound
	}
	if c.Provisioning != applications.ProvisioningStatusDeleteFailed {
		return applications.ErrConflict
	}
	c.Provisioning = applications.ProvisioningStatusDeleting
	s.clients[clientID] = c
	return nil
}

func (s *fakeAppStore) CompleteClientDeletion(_ context.Context, clientID applications.OAuthClientID, _ applications.ProviderOperationID) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.deleted[clientID] = true
	return nil
}

func (s *fakeAppStore) MarkClientDeleteFailed(_ context.Context, clientID applications.OAuthClientID, _ applications.ProviderOperationID, _ string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	c := s.clients[clientID]
	c.Provisioning = applications.ProvisioningStatusDeleteFailed
	s.clients[clientID] = c
	return nil
}

func (s *fakeAppStore) GetClientSecretRecords(_ context.Context, _ applications.OAuthClientID) ([]applications.ClientSecretRecord, error) {
	return nil, nil
}

func (s *fakeAppStore) BeginSecretRotation(_ context.Context, clientID applications.OAuthClientID, expectedVersion int, _ applications.ProviderOperation) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	c, ok := s.clients[clientID]
	if !ok || s.deleted[clientID] {
		return applications.ErrNotFound
	}
	if c.Version != expectedVersion {
		return applications.ErrConflict
	}
	c.Version++
	s.clients[clientID] = c
	return nil
}

func (s *fakeAppStore) CompleteSecretRotation(_ context.Context, _ applications.OAuthClientID, _ applications.ProviderOperationID, _ applications.ClientSecretID, _ applications.ClientSecretRecord, _ time.Time) error {
	return nil
}

func (s *fakeAppStore) AbortSecretRotation(_ context.Context, _ applications.OAuthClientID, _ applications.ProviderOperationID, _ string) error {
	return nil
}

func (s *fakeAppStore) FailSecretRotationUnknown(_ context.Context, _ applications.OAuthClientID, _ applications.ProviderOperationID, _ string) error {
	return nil
}

func (s *fakeAppStore) GetOperationByIdempotencyKey(_ context.Context, _ string) (applications.ProviderOperation, error) {
	return applications.ProviderOperation{}, applications.ErrNotFound
}

func (s *fakeAppStore) CreateReconciliationJob(_ context.Context, _ applications.ReconciliationJob) error {
	return nil
}

func (s *fakeAppStore) SetClientReconciliationRequired(_ context.Context, _ applications.OAuthClientID) error {
	return nil
}

type captureEvents struct {
	mu     sync.Mutex
	events []applications.SecurityEvent
}

func (c *captureEvents) Record(_ context.Context, ev applications.SecurityEvent) error {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.events = append(c.events, ev)
	return nil
}

func (c *captureEvents) denied(eventType string) bool {
	c.mu.Lock()
	defer c.mu.Unlock()
	for _, ev := range c.events {
		if ev.EventType == eventType && ev.Result == applications.SecurityEventDenied {
			return true
		}
	}
	return false
}

type stubAuditReader struct{}

func (stubAuditReader) ListByApplication(_ context.Context, _ applications.ApplicationID) ([]applications.AuditEntry, error) {
	return nil, nil
}

type stubUserLookup struct {
	exists map[string]bool
}

func (s *stubUserLookup) GetByID(_ context.Context, userID identity.UserID) (identity.User, error) {
	if !s.exists[string(userID)] {
		return identity.User{}, identity.ErrUserNotFound
	}
	return identity.User{ID: userID, DisplayName: "Owner User"}, nil
}

type stubPermResolver struct {
	caps permissions.Capabilities
	err  error
}

func (s *stubPermResolver) Resolve(_ context.Context, _ identity.UserID) (permissions.Capabilities, error) {
	return s.caps, s.err
}

type fakeReauthVerifier struct {
	validToken string
	consumed   bool
}

func (f *fakeReauthVerifier) VerifyAndConsume(_ context.Context, token, _, _ string, _ applications.ApplicationID, _ applications.OAuthClientID) error {
	if f.consumed || token != f.validToken {
		return errors.New("invalid reauthentication token")
	}
	f.consumed = true
	return nil
}

// --- Test harness ---

type appEnv struct {
	store    *fakeAppStore
	prov     *applications.FakeProvisioner
	events   *captureEvents
	resolver *stubPermResolver
	reauth   ReauthVerifier
	handlers *ApplicationHandlers
}

func newAppEnv(reauth ReauthVerifier) *appEnv {
	store := newFakeAppStore()
	prov := applications.NewFakeProvisioner()
	events := &captureEvents{}
	svc := applications.NewService(store, prov, events, stubAuditReader{},
		&stubUserLookup{exists: map[string]bool{"user_owner_1": true}}, "fake", "proj_test", 0)
	resolver := &stubPermResolver{caps: permissions.AllCapabilities()}
	return &appEnv{
		store:    store,
		prov:     prov,
		events:   events,
		resolver: resolver,
		reauth:   reauth,
		handlers: NewApplicationHandlers(svc, resolver, reauth, nil, 0, 0, slog.Default()),
	}
}

// buildAppRouter mounts the application routes behind principal/session
// injection (mirroring RequireSession) and RequireCSRF, exactly like the
// bootstrap wiring. When injectSession is false the request reaches the
// handlers unauthenticated.
func buildAppRouter(env *appEnv, injectSession bool) http.Handler {
	r := chi.NewRouter()
	if injectSession {
		r.Use(func(next http.Handler) http.Handler {
			return http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) {
				ctx := WithPrincipal(req.Context(), session.Principal{UserID: identity.UserID("user_actor")})
				ctx = WithSessionRecord(ctx, session.SessionRecord{
					CSRFTokenHash: session.HashToken("csrf-token"),
				})
				ctx = request.WithID(ctx, "req-test-1")
				next.ServeHTTP(w, req.WithContext(ctx))
			})
		})
		r.Use(RequireCSRF())
	}
	r.Post("/admin/applications/with-initial-client", env.handlers.CreateWithInitialClient)
	r.Get("/admin/applications", env.handlers.ListApplications)
	r.Get("/admin/applications/{applicationId}", env.handlers.GetApplication)
	r.Patch("/admin/applications/{applicationId}", env.handlers.UpdateApplication)
	r.Post("/admin/applications/{applicationId}/enable", env.handlers.EnableApplication)
	r.Post("/admin/applications/{applicationId}/disable", env.handlers.DisableApplication)
	r.Delete("/admin/applications/{applicationId}", env.handlers.DeleteApplication)
	r.Post("/admin/applications/{applicationId}/clients", env.handlers.CreateClient)
	r.Get("/admin/applications/{applicationId}/clients/{clientId}", env.handlers.GetClient)
	r.Patch("/admin/applications/{applicationId}/clients/{clientId}", env.handlers.UpdateClient)
	r.Post("/admin/applications/{applicationId}/clients/{clientId}/enable", env.handlers.EnableClient)
	r.Post("/admin/applications/{applicationId}/clients/{clientId}/disable", env.handlers.DisableClient)
	r.Delete("/admin/applications/{applicationId}/clients/{clientId}", env.handlers.DeleteClient)
	r.Post("/admin/applications/{applicationId}/clients/{clientId}/secret-rotations", env.handlers.RotateClientSecret)
	return r
}

func doAppRequest(handler http.Handler, method, path, body string, withCSRF bool) *httptest.ResponseRecorder {
	var reader *strings.Reader
	if body != "" {
		reader = strings.NewReader(body)
	}
	var req *http.Request
	if reader != nil {
		req = httptest.NewRequest(method, path, reader)
		req.Header.Set("Content-Type", "application/json")
	} else {
		req = httptest.NewRequest(method, path, nil)
	}
	if withCSRF {
		req.AddCookie(&http.Cookie{Name: CSRFCookieName, Value: "csrf-token"})
		req.Header.Set(CSRFHeaderName, "csrf-token")
	}
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)
	return rec
}

const validCreateBody = `{
  "application": {"name": "测试应用", "audience": "internal", "ownerId": "user_owner_1"},
  "initialClient": {
    "name": "测试客户端", "profile": "web_server",
    "redirectUris": ["https://app.example.com/callback"],
    "allowedScopes": ["openid", "profile"], "consentMode": "always"
  }
}`

const validPublicCreateBody = `{
  "application": {"name": "公开应用", "audience": "external", "ownerId": "user_owner_1"},
  "initialClient": {
    "name": "SPA 客户端", "profile": "spa_mobile",
    "redirectUris": ["https://spa.example.com/callback"],
    "allowedScopes": ["openid"], "consentMode": "first_authorization"
  }
}`

// seedProvisionedApp places a fully provisioned application with one
// provisioned confidential client into the store.
func seedProvisionedApp(env *appEnv, appID applications.ApplicationID) applications.OAuthClientID {
	now := time.Now().UTC()
	env.store.apps[appID] = applications.Application{
		ID:           appID,
		Name:         "种子应用",
		Audience:     applications.AudienceInternal,
		OwnerID:      "user_owner_1",
		OwnerName:    "Owner User",
		Status:       applications.StatusActive,
		Provisioning: applications.ProvisioningStatusProvisioned,
		Version:      1,
		CreatedAt:    now,
		UpdatedAt:    now,
	}
	clientID := applications.OAuthClientID("clt_seed_1")
	env.store.clients[clientID] = applications.OAuthClient{
		ID:                    clientID,
		ApplicationID:         appID,
		Name:                  "种子客户端",
		Profile:               applications.ClientProfileWebServer,
		ClientType:            applications.ClientTypeConfidential,
		TokenEndpointAuth:     applications.TokenAuthClientSecretBasic,
		ConsentMode:           applications.ConsentModeAlways,
		Status:                applications.StatusActive,
		RedirectURIs:          []applications.RedirectURI{{URI: "https://app.example.com/callback", AddedAt: now}},
		Scopes:                []string{"openid"},
		ProviderApplicationID: "fake-app-1",
		Provisioning:          applications.ProvisioningStatusProvisioned,
		SecretRecords:         []applications.ClientSecretRecord{{ID: "sec_seed_1", ClientID: clientID, Label: "初始 Secret", CreatedAt: now}},
		Version:               1,
		CreatedAt:             now,
		UpdatedAt:             now,
	}
	return clientID
}

func decodeErrorBody(t *testing.T, rec *httptest.ResponseRecorder) ErrorBody {
	t.Helper()
	var resp ErrorResponse
	if err := json.Unmarshal(rec.Body.Bytes(), &resp); err != nil {
		t.Fatalf("decode error body: %v (body=%s)", err, rec.Body.String())
	}
	return resp.Error
}

// createAppViaAPI creates an application through the HTTP API so the fake
// provisioner also knows about the provider-side resource (seeded rows
// alone have no provider counterpart).
func createAppViaAPI(t *testing.T, env *appEnv, router http.Handler, body string) string {
	t.Helper()
	appID, _ := createAppAndClientViaAPI(t, env, router, body)
	return appID
}

// createAppAndClientViaAPI creates an application with its initial client
// through the HTTP API and returns both IDs.
func createAppAndClientViaAPI(t *testing.T, env *appEnv, router http.Handler, body string) (string, string) {
	t.Helper()
	rec := doAppRequest(router, http.MethodPost, "/admin/applications/with-initial-client", body, true)
	if rec.Code != http.StatusCreated {
		t.Fatalf("setup create: status = %d, want 201; body=%s", rec.Code, rec.Body.String())
	}
	var resp applicationWithInitialClientResponse
	if err := json.Unmarshal(rec.Body.Bytes(), &resp); err != nil {
		t.Fatalf("setup create decode: %v", err)
	}
	return resp.ApplicationID, resp.ClientID
}

// --- Authentication / CSRF / Authorization ---

func TestApplicationRoutes_RequireSession(t *testing.T) {
	env := newAppEnv(nil)
	router := buildAppRouter(env, false)

	rec := doAppRequest(router, http.MethodGet, "/admin/applications", "", false)
	if rec.Code != http.StatusUnauthorized {
		t.Fatalf("status = %d, want 401; body=%s", rec.Code, rec.Body.String())
	}
	if body := decodeErrorBody(t, rec); body.Code != CodeUnauthorized {
		t.Errorf("code = %q, want %q", body.Code, CodeUnauthorized)
	}
}

func TestApplicationRoutes_RequireCSRF(t *testing.T) {
	env := newAppEnv(nil)
	router := buildAppRouter(env, true)

	// Write without CSRF token is rejected.
	rec := doAppRequest(router, http.MethodPost, "/admin/applications/with-initial-client", validCreateBody, false)
	if rec.Code != http.StatusForbidden {
		t.Fatalf("status = %d, want 403; body=%s", rec.Code, rec.Body.String())
	}

	// Safe methods need no CSRF token.
	rec = doAppRequest(router, http.MethodGet, "/admin/applications", "", false)
	if rec.Code != http.StatusOK {
		t.Fatalf("GET status = %d, want 200; body=%s", rec.Code, rec.Body.String())
	}

	// Write with matching cookie + header passes CSRF.
	rec = doAppRequest(router, http.MethodPost, "/admin/applications/with-initial-client", validCreateBody, true)
	if rec.Code != http.StatusCreated {
		t.Fatalf("status = %d, want 201; body=%s", rec.Code, rec.Body.String())
	}
}

func TestApplicationRoutes_ForbiddenWithoutCapability(t *testing.T) {
	env := newAppEnv(nil)
	env.resolver.caps = permissions.Capabilities{} // all false, fail closed
	router := buildAppRouter(env, true)

	rec := doAppRequest(router, http.MethodPost, "/admin/applications/with-initial-client", validCreateBody, true)
	if rec.Code != http.StatusForbidden {
		t.Fatalf("status = %d, want 403; body=%s", rec.Code, rec.Body.String())
	}
	if body := decodeErrorBody(t, rec); body.Code != CodeForbidden {
		t.Errorf("code = %q, want %q", body.Code, CodeForbidden)
	}
	if !env.events.denied(applications.EventApplicationCreated) {
		t.Error("expected denied audit event for create")
	}

	// Reads require ApplicationRead.
	rec = doAppRequest(router, http.MethodGet, "/admin/applications", "", false)
	if rec.Code != http.StatusForbidden {
		t.Fatalf("GET status = %d, want 403", rec.Code)
	}
}

func TestApplicationRoutes_ResolverErrorFailsClosed(t *testing.T) {
	env := newAppEnv(nil)
	env.resolver.err = errors.New("resolver down")
	router := buildAppRouter(env, true)

	rec := doAppRequest(router, http.MethodGet, "/admin/applications", "", false)
	if rec.Code != http.StatusInternalServerError {
		t.Fatalf("status = %d, want 500", rec.Code)
	}
}

// --- Create ---

func TestCreateApplication_MalformedBody(t *testing.T) {
	env := newAppEnv(nil)
	router := buildAppRouter(env, true)

	rec := doAppRequest(router, http.MethodPost, "/admin/applications/with-initial-client", "{not-json", true)
	if rec.Code != http.StatusBadRequest {
		t.Fatalf("status = %d, want 400", rec.Code)
	}
	if body := decodeErrorBody(t, rec); body.Code != CodeBadRequest {
		t.Errorf("code = %q, want %q", body.Code, CodeBadRequest)
	}
}

func TestCreateApplication_UnknownFieldRejected(t *testing.T) {
	env := newAppEnv(nil)
	router := buildAppRouter(env, true)

	body := `{
	  "application": {"name": "测试应用", "audience": "internal", "ownerId": "user_owner_1", "bogus": 1},
	  "initialClient": {"name": "客户端", "profile": "web_server", "redirectUris": ["https://a.example.com/cb"], "allowedScopes": ["openid"], "consentMode": "always"}
	}`
	rec := doAppRequest(router, http.MethodPost, "/admin/applications/with-initial-client", body, true)
	if rec.Code != http.StatusBadRequest {
		t.Fatalf("status = %d, want 400; body=%s", rec.Code, rec.Body.String())
	}
}

func TestCreateApplication_FieldValidationErrors(t *testing.T) {
	env := newAppEnv(nil)
	router := buildAppRouter(env, true)

	body := `{
	  "application": {"name": "x", "audience": "internal", "ownerId": "user_owner_1"},
	  "initialClient": {"name": "客户端", "profile": "web_server", "redirectUris": ["not-a-uri"], "allowedScopes": ["openid"], "consentMode": "always"}
	}`
	rec := doAppRequest(router, http.MethodPost, "/admin/applications/with-initial-client", body, true)
	if rec.Code != http.StatusUnprocessableEntity {
		t.Fatalf("status = %d, want 422; body=%s", rec.Code, rec.Body.String())
	}
	var resp ErrorResponse
	if err := json.Unmarshal(rec.Body.Bytes(), &resp); err != nil {
		t.Fatalf("decode: %v", err)
	}
	if resp.Error.Code != CodeValidation {
		t.Errorf("code = %q, want %q", resp.Error.Code, CodeValidation)
	}
	fields := make(map[string]bool)
	for _, fe := range resp.Error.FieldErrors {
		fields[fe.Field] = true
	}
	if !fields["application.name"] {
		t.Errorf("missing application.name field error: %+v", resp.Error.FieldErrors)
	}
	if !fields["initialClient.redirectUris[0]"] {
		t.Errorf("missing initialClient.redirectUris[0] field error: %+v", resp.Error.FieldErrors)
	}
}

func TestCreateApplication_OwnerNotFound(t *testing.T) {
	env := newAppEnv(nil)
	router := buildAppRouter(env, true)

	body := `{
	  "application": {"name": "测试应用", "audience": "internal", "ownerId": "user_missing"},
	  "initialClient": {"name": "客户端", "profile": "web_server", "redirectUris": ["https://a.example.com/cb"], "allowedScopes": ["openid"], "consentMode": "always"}
	}`
	rec := doAppRequest(router, http.MethodPost, "/admin/applications/with-initial-client", body, true)
	if rec.Code != http.StatusUnprocessableEntity {
		t.Fatalf("status = %d, want 422; body=%s", rec.Code, rec.Body.String())
	}
	var resp ErrorResponse
	_ = json.Unmarshal(rec.Body.Bytes(), &resp)
	found := false
	for _, fe := range resp.Error.FieldErrors {
		if fe.Field == "application.ownerId" {
			found = true
		}
	}
	if !found {
		t.Errorf("missing application.ownerId field error: %+v", resp.Error.FieldErrors)
	}
}

func TestCreateApplication_DuplicateNameConflicts(t *testing.T) {
	env := newAppEnv(nil)
	env.store.createErr = applications.ErrDuplicateName
	router := buildAppRouter(env, true)

	rec := doAppRequest(router, http.MethodPost, "/admin/applications/with-initial-client", validCreateBody, true)
	if rec.Code != http.StatusConflict {
		t.Fatalf("status = %d, want 409; body=%s", rec.Code, rec.Body.String())
	}
	if body := decodeErrorBody(t, rec); body.Code != CodeConflict {
		t.Errorf("code = %q, want %q", body.Code, CodeConflict)
	}
}

func TestCreateApplication_ProviderUnavailable(t *testing.T) {
	env := newAppEnv(nil)
	env.prov.ProvisionErr = applications.ErrProviderUnavailable
	router := buildAppRouter(env, true)

	rec := doAppRequest(router, http.MethodPost, "/admin/applications/with-initial-client", validCreateBody, true)
	if rec.Code != http.StatusBadGateway {
		t.Fatalf("status = %d, want 502; body=%s", rec.Code, rec.Body.String())
	}
	if body := decodeErrorBody(t, rec); body.Code != CodeProviderUnavailable {
		t.Errorf("code = %q, want %q", body.Code, CodeProviderUnavailable)
	}
}

func TestCreateApplication_ConfidentialSecretShownOnceNoStore(t *testing.T) {
	env := newAppEnv(nil)
	router := buildAppRouter(env, true)

	rec := doAppRequest(router, http.MethodPost, "/admin/applications/with-initial-client", validCreateBody, true)
	if rec.Code != http.StatusCreated {
		t.Fatalf("status = %d, want 201; body=%s", rec.Code, rec.Body.String())
	}
	if got := rec.Header().Get("Cache-Control"); got != "no-store" {
		t.Errorf("Cache-Control = %q, want no-store", got)
	}
	if got := rec.Header().Get("X-Request-ID"); got != "req-test-1" {
		t.Errorf("X-Request-ID = %q, want req-test-1", got)
	}
	var resp applicationWithInitialClientResponse
	if err := json.Unmarshal(rec.Body.Bytes(), &resp); err != nil {
		t.Fatalf("decode: %v", err)
	}
	if resp.ApplicationID == "" || resp.ClientID == "" {
		t.Errorf("missing IDs: %+v", resp)
	}
	if resp.ClientSecret == "" {
		t.Error("confidential client response must include the one-time secret")
	}
}

func TestCreateApplication_PublicClientHasNoSecret(t *testing.T) {
	env := newAppEnv(nil)
	router := buildAppRouter(env, true)

	rec := doAppRequest(router, http.MethodPost, "/admin/applications/with-initial-client", validPublicCreateBody, true)
	if rec.Code != http.StatusCreated {
		t.Fatalf("status = %d, want 201; body=%s", rec.Code, rec.Body.String())
	}
	var raw map[string]any
	if err := json.Unmarshal(rec.Body.Bytes(), &raw); err != nil {
		t.Fatalf("decode: %v", err)
	}
	if _, present := raw["clientSecret"]; present {
		t.Error("public client response must not include clientSecret")
	}
}

// --- List ---

func TestListApplications_Success(t *testing.T) {
	env := newAppEnv(nil)
	seedProvisionedApp(env, applications.ApplicationID("app_list_1"))
	router := buildAppRouter(env, true)

	rec := doAppRequest(router, http.MethodGet, "/admin/applications", "", false)
	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200; body=%s", rec.Code, rec.Body.String())
	}
	var resp applicationListResponse
	if err := json.Unmarshal(rec.Body.Bytes(), &resp); err != nil {
		t.Fatalf("decode: %v", err)
	}
	if len(resp.Items) != 1 || resp.Items[0].ApplicationID != "app_list_1" {
		t.Errorf("items = %+v", resp.Items)
	}
	if resp.Page.NextCursor != nil || resp.Page.HasMore {
		t.Errorf("page = %+v, want null cursor and hasMore=false", resp.Page)
	}
}

func TestListApplications_RejectsInvalidParams(t *testing.T) {
	env := newAppEnv(nil)
	router := buildAppRouter(env, true)

	cases := []string{
		"/admin/applications?limit=0",
		"/admin/applications?limit=101",
		"/admin/applications?limit=abc",
		"/admin/applications?sort=bogus",
		"/admin/applications?status=bogus",
		"/admin/applications?audience=bogus",
	}
	for _, path := range cases {
		rec := doAppRequest(router, http.MethodGet, path, "", false)
		if rec.Code != http.StatusBadRequest {
			t.Errorf("%s: status = %d, want 400", path, rec.Code)
		}
	}
}

func TestListApplications_InvalidCursor(t *testing.T) {
	env := newAppEnv(nil)
	env.store.listErr = applications.ErrInvalidCursor
	router := buildAppRouter(env, true)

	rec := doAppRequest(router, http.MethodGet, "/admin/applications?cursor=tampered", "", false)
	if rec.Code != http.StatusBadRequest {
		t.Fatalf("status = %d, want 400; body=%s", rec.Code, rec.Body.String())
	}
}

// --- Get ---

func TestGetApplication_Success(t *testing.T) {
	env := newAppEnv(nil)
	seedProvisionedApp(env, applications.ApplicationID("app_detail_1"))
	router := buildAppRouter(env, true)

	rec := doAppRequest(router, http.MethodGet, "/admin/applications/app_detail_1", "", false)
	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200; body=%s", rec.Code, rec.Body.String())
	}
	var resp applicationDetailResponse
	if err := json.Unmarshal(rec.Body.Bytes(), &resp); err != nil {
		t.Fatalf("decode: %v", err)
	}
	if resp.ApplicationID != "app_detail_1" {
		t.Errorf("applicationId = %q", resp.ApplicationID)
	}
	if len(resp.Clients) != 1 {
		t.Fatalf("clients = %+v", resp.Clients)
	}
	c := resp.Clients[0]
	if c.ClientID != "clt_seed_1" || c.ClientType != "confidential" {
		t.Errorf("client = %+v", c)
	}
	if len(c.GrantTypes) != 2 || c.GrantTypes[0] != "authorization_code" {
		t.Errorf("grantTypes = %v", c.GrantTypes)
	}
	if len(c.AllowedScopes) != 1 || c.AllowedScopes[0].Scope != "openid" {
		t.Errorf("allowedScopes = %+v", c.AllowedScopes)
	}
	if len(c.ClientSecrets) != 1 || c.ClientSecrets[0].SecretID != "sec_seed_1" {
		t.Errorf("clientSecrets = %+v", c.ClientSecrets)
	}
	if resp.Grants == nil {
		t.Error("grants must be an empty array, not null")
	}
}

func TestGetApplication_NotFoundAntiEnumeration(t *testing.T) {
	env := newAppEnv(nil)
	router := buildAppRouter(env, true)

	// Unknown but well-shaped ID.
	rec := doAppRequest(router, http.MethodGet, "/admin/applications/app_missing", "", false)
	if rec.Code != http.StatusNotFound {
		t.Fatalf("status = %d, want 404", rec.Code)
	}
	// Malformed ID shape yields the identical response.
	rec = doAppRequest(router, http.MethodGet, "/admin/applications/not-an-app-id", "", false)
	if rec.Code != http.StatusNotFound {
		t.Fatalf("status = %d, want 404", rec.Code)
	}
	if body := decodeErrorBody(t, rec); body.Code != CodeNotFound {
		t.Errorf("code = %q, want %q", body.Code, CodeNotFound)
	}
}

// --- Patch ---

func TestUpdateApplication_EmptyPatchRejected(t *testing.T) {
	env := newAppEnv(nil)
	seedProvisionedApp(env, applications.ApplicationID("app_patch_1"))
	router := buildAppRouter(env, true)

	rec := doAppRequest(router, http.MethodPatch, "/admin/applications/app_patch_1", "{}", true)
	if rec.Code != http.StatusBadRequest {
		t.Fatalf("status = %d, want 400; body=%s", rec.Code, rec.Body.String())
	}
}

func TestUpdateApplication_UnknownFieldRejected(t *testing.T) {
	env := newAppEnv(nil)
	seedProvisionedApp(env, applications.ApplicationID("app_patch_2"))
	router := buildAppRouter(env, true)

	rec := doAppRequest(router, http.MethodPatch, "/admin/applications/app_patch_2", `{"name": "新名称", "bogus": true}`, true)
	if rec.Code != http.StatusBadRequest {
		t.Fatalf("status = %d, want 400; body=%s", rec.Code, rec.Body.String())
	}
}

func TestUpdateApplication_InvalidAudience(t *testing.T) {
	env := newAppEnv(nil)
	seedProvisionedApp(env, applications.ApplicationID("app_patch_3"))
	router := buildAppRouter(env, true)

	rec := doAppRequest(router, http.MethodPatch, "/admin/applications/app_patch_3", `{"audience": "bogus"}`, true)
	if rec.Code != http.StatusUnprocessableEntity {
		t.Fatalf("status = %d, want 422; body=%s", rec.Code, rec.Body.String())
	}
	var resp ErrorResponse
	_ = json.Unmarshal(rec.Body.Bytes(), &resp)
	found := false
	for _, fe := range resp.Error.FieldErrors {
		if fe.Field == "audience" {
			found = true
		}
	}
	if !found {
		t.Errorf("missing audience field error: %+v", resp.Error.FieldErrors)
	}
}

func TestUpdateApplication_InvalidName(t *testing.T) {
	env := newAppEnv(nil)
	seedProvisionedApp(env, applications.ApplicationID("app_patch_4"))
	router := buildAppRouter(env, true)

	rec := doAppRequest(router, http.MethodPatch, "/admin/applications/app_patch_4", `{"name": "x"}`, true)
	if rec.Code != http.StatusUnprocessableEntity {
		t.Fatalf("status = %d, want 422; body=%s", rec.Code, rec.Body.String())
	}
}

func TestUpdateApplication_Success(t *testing.T) {
	env := newAppEnv(nil)
	seedProvisionedApp(env, applications.ApplicationID("app_patch_5"))
	router := buildAppRouter(env, true)

	rec := doAppRequest(router, http.MethodPatch, "/admin/applications/app_patch_5", `{"name": "新名称", "description": "新的说明"}`, true)
	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200; body=%s", rec.Code, rec.Body.String())
	}
	var resp applicationDetailResponse
	if err := json.Unmarshal(rec.Body.Bytes(), &resp); err != nil {
		t.Fatalf("decode: %v", err)
	}
	if resp.Name != "新名称" || resp.Description != "新的说明" {
		t.Errorf("detail = %+v", resp)
	}
}

func TestUpdateApplication_NotFound(t *testing.T) {
	env := newAppEnv(nil)
	router := buildAppRouter(env, true)

	rec := doAppRequest(router, http.MethodPatch, "/admin/applications/app_missing", `{"name": "新名称"}`, true)
	if rec.Code != http.StatusNotFound {
		t.Fatalf("status = %d, want 404", rec.Code)
	}
}

func TestUpdateApplication_ConflictOnStaleVersion(t *testing.T) {
	env := newAppEnv(nil)
	seedProvisionedApp(env, applications.ApplicationID("app_patch_6"))
	env.store.updateErr = applications.ErrConflict
	router := buildAppRouter(env, true)

	rec := doAppRequest(router, http.MethodPatch, "/admin/applications/app_patch_6", `{"name": "新名称"}`, true)
	if rec.Code != http.StatusConflict {
		t.Fatalf("status = %d, want 409; body=%s", rec.Code, rec.Body.String())
	}
}

// --- Enable / Disable ---

func TestEnableApplication_ConflictWhenAlreadyActive(t *testing.T) {
	env := newAppEnv(nil)
	seedProvisionedApp(env, applications.ApplicationID("app_en_1"))
	router := buildAppRouter(env, true)

	rec := doAppRequest(router, http.MethodPost, "/admin/applications/app_en_1/enable", "", true)
	if rec.Code != http.StatusConflict {
		t.Fatalf("status = %d, want 409; body=%s", rec.Code, rec.Body.String())
	}
	if body := decodeErrorBody(t, rec); body.Code != CodeConflict {
		t.Errorf("code = %q, want %q", body.Code, CodeConflict)
	}
}

func TestDisableApplication_Success(t *testing.T) {
	env := newAppEnv(nil)
	router := buildAppRouter(env, true)
	appID := createAppViaAPI(t, env, router, validCreateBody)

	rec := doAppRequest(router, http.MethodPost, "/admin/applications/"+appID+"/disable", "", true)
	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200; body=%s", rec.Code, rec.Body.String())
	}
	var resp applicationDetailResponse
	if err := json.Unmarshal(rec.Body.Bytes(), &resp); err != nil {
		t.Fatalf("decode: %v", err)
	}
	if resp.Status != "disabled" {
		t.Errorf("status = %q, want disabled", resp.Status)
	}
	if env.store.apps[applications.ApplicationID(appID)].Status != applications.StatusDisabled {
		t.Error("stored status must be disabled")
	}
}

func TestDisableApplication_ProviderFailureFailsClosed(t *testing.T) {
	env := newAppEnv(nil)
	router := buildAppRouter(env, true)
	appID := createAppViaAPI(t, env, router, validCreateBody)
	env.prov.DisableErr = applications.ErrProviderUnavailable

	rec := doAppRequest(router, http.MethodPost, "/admin/applications/"+appID+"/disable", "", true)
	if rec.Code != http.StatusBadGateway {
		t.Fatalf("status = %d, want 502; body=%s", rec.Code, rec.Body.String())
	}
	if env.store.apps[applications.ApplicationID(appID)].Status != applications.StatusActive {
		t.Error("local status must stay active when the provider call fails")
	}
}

func TestEnableApplication_NotFound(t *testing.T) {
	env := newAppEnv(nil)
	router := buildAppRouter(env, true)

	rec := doAppRequest(router, http.MethodPost, "/admin/applications/app_missing/enable", "", true)
	if rec.Code != http.StatusNotFound {
		t.Fatalf("status = %d, want 404", rec.Code)
	}
}

// --- Delete + reauthentication ---

func TestDeleteApplication_FailsClosedWithoutVerifier(t *testing.T) {
	env := newAppEnv(nil) // nil reauth verifier
	seedProvisionedApp(env, applications.ApplicationID("app_del_1"))
	router := buildAppRouter(env, true)

	rec := doAppRequest(router, http.MethodDelete, "/admin/applications/app_del_1", "", true)
	if rec.Code != http.StatusForbidden {
		t.Fatalf("status = %d, want 403; body=%s", rec.Code, rec.Body.String())
	}
	if body := decodeErrorBody(t, rec); body.Code != CodeReauthenticationReq {
		t.Errorf("code = %q, want %q", body.Code, CodeReauthenticationReq)
	}
	if _, ok := env.store.apps["app_del_1"]; !ok {
		t.Error("application must not be deleted without reauthentication")
	}
}

func TestDeleteApplication_RequiresToken(t *testing.T) {
	env := newAppEnv(&fakeReauthVerifier{validToken: "reauth-token"})
	seedProvisionedApp(env, applications.ApplicationID("app_del_2"))
	router := buildAppRouter(env, true)

	// No header.
	rec := doAppRequest(router, http.MethodDelete, "/admin/applications/app_del_2", "", true)
	if rec.Code != http.StatusForbidden {
		t.Fatalf("no header: status = %d, want 403", rec.Code)
	}

	// Wrong token.
	req := httptest.NewRequest(http.MethodDelete, "/admin/applications/app_del_2", nil)
	req.AddCookie(&http.Cookie{Name: CSRFCookieName, Value: "csrf-token"})
	req.Header.Set(CSRFHeaderName, "csrf-token")
	req.Header.Set("X-Reauthentication-Token", "wrong-token")
	rec2 := httptest.NewRecorder()
	router.ServeHTTP(rec2, req)
	if rec2.Code != http.StatusForbidden {
		t.Fatalf("wrong token: status = %d, want 403", rec2.Code)
	}
	if body := decodeErrorBody(t, rec2); body.Code != CodeReauthenticationReq {
		t.Errorf("code = %q, want %q", body.Code, CodeReauthenticationReq)
	}
	if env.events.denied(applications.EventApplicationDeleted) == false {
		t.Error("expected denied audit event for delete")
	}
}

func TestDeleteApplication_SuccessAndTokenConsumed(t *testing.T) {
	verifier := &fakeReauthVerifier{validToken: "reauth-token"}
	env := newAppEnv(verifier)
	router := buildAppRouter(env, true)
	appID1 := createAppViaAPI(t, env, router, validCreateBody)
	seedProvisionedApp(env, applications.ApplicationID("app_del_4"))

	req := httptest.NewRequest(http.MethodDelete, "/admin/applications/"+appID1, nil)
	req.AddCookie(&http.Cookie{Name: CSRFCookieName, Value: "csrf-token"})
	req.Header.Set(CSRFHeaderName, "csrf-token")
	req.Header.Set("X-Reauthentication-Token", "reauth-token")
	rec := httptest.NewRecorder()
	router.ServeHTTP(rec, req)
	if rec.Code != http.StatusNoContent {
		t.Fatalf("status = %d, want 204; body=%s", rec.Code, rec.Body.String())
	}
	if _, ok := env.store.apps[applications.ApplicationID(appID1)]; ok {
		t.Error("application still present after delete")
	}

	// The consumed token must not authorize a second deletion.
	req2 := httptest.NewRequest(http.MethodDelete, "/admin/applications/app_del_4", nil)
	req2.AddCookie(&http.Cookie{Name: CSRFCookieName, Value: "csrf-token"})
	req2.Header.Set(CSRFHeaderName, "csrf-token")
	req2.Header.Set("X-Reauthentication-Token", "reauth-token")
	rec2 := httptest.NewRecorder()
	router.ServeHTTP(rec2, req2)
	if rec2.Code != http.StatusForbidden {
		t.Fatalf("reused token: status = %d, want 403", rec2.Code)
	}
	if _, ok := env.store.apps["app_del_4"]; !ok {
		t.Error("second application must survive a reused token")
	}
}

func TestDeleteApplication_NotFound(t *testing.T) {
	env := newAppEnv(&fakeReauthVerifier{validToken: "reauth-token"})
	router := buildAppRouter(env, true)

	req := httptest.NewRequest(http.MethodDelete, "/admin/applications/app_missing", nil)
	req.AddCookie(&http.Cookie{Name: CSRFCookieName, Value: "csrf-token"})
	req.Header.Set(CSRFHeaderName, "csrf-token")
	req.Header.Set("X-Reauthentication-Token", "reauth-token")
	rec := httptest.NewRecorder()
	router.ServeHTTP(rec, req)
	if rec.Code != http.StatusNotFound {
		t.Fatalf("status = %d, want 404", rec.Code)
	}
}
