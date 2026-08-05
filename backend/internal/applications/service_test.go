package applications

import (
	"context"
	"errors"
	"sync"
	"testing"
	"time"

	"github.com/GravelEvolution/united-pass/backend/internal/identity"
)

// --- Test fakes ---

// fakeStore is an in-memory ApplicationStore. It is intentionally minimal:
// only the state needed by the orchestration tests is tracked.
type fakeStore struct {
	mu      sync.Mutex
	apps    map[ApplicationID]Application
	clients map[OAuthClientID]OAuthClient
	deleted map[OAuthClientID]bool
	ops     map[ProviderOperationID]ProviderOperation
	secrets []ClientSecretRecord
	jobs    []ReconciliationJob
	seq     *[]string

	createAppErr     error
	completeAppErr   error
	updateAppErr     error
	setAppStatusErr  error
	deleteAppErr     error
	listErr          error
	markDeletingErr  error
	completeDelErr   error
	reconcileMarkErr error
}

func newFakeStore(seq *[]string) *fakeStore {
	return &fakeStore{
		apps:    make(map[ApplicationID]Application),
		clients: make(map[OAuthClientID]OAuthClient),
		deleted: make(map[OAuthClientID]bool),
		ops:     make(map[ProviderOperationID]ProviderOperation),
		seq:     seq,
	}
}

func (s *fakeStore) note(step string) {
	if s.seq != nil {
		*s.seq = append(*s.seq, step)
	}
}

func (s *fakeStore) CreateApplicationWithInitialClient(_ context.Context, app Application, client OAuthClient, op ProviderOperation) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.createAppErr != nil {
		return s.createAppErr
	}
	s.apps[app.ID] = app
	s.clients[client.ID] = client
	s.ops[op.ID] = op
	return nil
}

func (s *fakeStore) CompleteInitialProvisioning(_ context.Context, appID ApplicationID, clientID OAuthClientID, provider, providerProjectID, providerApplicationID, providerClientID string, _ ProviderOperationID, secret *ClientSecretRecord) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.completeAppErr != nil {
		return s.completeAppErr
	}
	app := s.apps[appID]
	app.Provisioning = ProvisioningStatusProvisioned
	s.apps[appID] = app
	client := s.clients[clientID]
	client.Provisioning = ProvisioningStatusProvisioned
	client.Provider = provider
	client.ProviderProjectID = providerProjectID
	client.ProviderApplicationID = providerApplicationID
	client.ProviderClientID = providerClientID
	s.clients[clientID] = client
	if secret != nil {
		s.secrets = append(s.secrets, *secret)
	}
	return nil
}

func (s *fakeStore) MarkInitialProvisioningFailed(_ context.Context, _ ApplicationID, clientID OAuthClientID, _ ProviderOperationID, _ string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	client := s.clients[clientID]
	client.Provisioning = ProvisioningStatusProvisioningFailed
	s.clients[clientID] = client
	return nil
}

func (s *fakeStore) GetApplication(_ context.Context, appID ApplicationID) (Application, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	app, ok := s.apps[appID]
	if !ok {
		return Application{}, ErrNotFound
	}
	return app, nil
}

func (s *fakeStore) UpdateApplication(_ context.Context, appID ApplicationID, upd ApplicationUpdate, expectedVersion int) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.updateAppErr != nil {
		return s.updateAppErr
	}
	app, ok := s.apps[appID]
	if !ok {
		return ErrNotFound
	}
	if app.Version != expectedVersion {
		return ErrConflict
	}
	app.Name = upd.Name
	app.Description = upd.Description
	app.Audience = upd.Audience
	app.OwnerID = upd.OwnerID
	app.Version++
	s.apps[appID] = app
	return nil
}

func (s *fakeStore) SetApplicationStatus(_ context.Context, appID ApplicationID, status Status, expectedVersion int) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.setAppStatusErr != nil {
		return s.setAppStatusErr
	}
	s.note("store:set-app-status")
	app, ok := s.apps[appID]
	if !ok {
		return ErrNotFound
	}
	if app.Version != expectedVersion {
		return ErrConflict
	}
	app.Status = status
	app.Version++
	s.apps[appID] = app
	return nil
}

func (s *fakeStore) DeleteApplication(_ context.Context, appID ApplicationID, expectedVersion int) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.deleteAppErr != nil {
		return s.deleteAppErr
	}
	app, ok := s.apps[appID]
	if !ok {
		return ErrNotFound
	}
	if app.Version != expectedVersion {
		return ErrConflict
	}
	delete(s.apps, appID)
	return nil
}

func (s *fakeStore) ListApplications(_ context.Context, _ ListQuery) (ListResult, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.listErr != nil {
		return ListResult{}, s.listErr
	}
	items := make([]ApplicationSummary, 0, len(s.apps))
	for _, app := range s.apps {
		items = append(items, ApplicationSummary{Application: app})
	}
	return ListResult{Items: items}, nil
}

func (s *fakeStore) ListClientsByApplication(_ context.Context, appID ApplicationID) ([]OAuthClient, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	var out []OAuthClient
	for _, c := range s.clients {
		if c.ApplicationID == appID && !s.deleted[c.ID] && c.Provisioning == ProvisioningStatusProvisioned {
			out = append(out, c)
		}
	}
	return out, nil
}

func (s *fakeStore) ListLiveClientsByApplication(_ context.Context, appID ApplicationID) ([]OAuthClient, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	var out []OAuthClient
	for _, c := range s.clients {
		if c.ApplicationID == appID && !s.deleted[c.ID] {
			out = append(out, c)
		}
	}
	return out, nil
}

func (s *fakeStore) GetClient(_ context.Context, appID ApplicationID, clientID OAuthClientID) (OAuthClient, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	c, ok := s.clients[clientID]
	if !ok || c.ApplicationID != appID || s.deleted[clientID] {
		return OAuthClient{}, ErrNotFound
	}
	return c, nil
}

func (s *fakeStore) CreateClientWithOperation(_ context.Context, client OAuthClient, op ProviderOperation) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.clients[client.ID] = client
	s.ops[op.ID] = op
	return nil
}

func (s *fakeStore) CompleteClientProvisioning(_ context.Context, clientID OAuthClientID, provider, providerProjectID, providerApplicationID, providerClientID string, _ ProviderOperationID, secret *ClientSecretRecord) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	c := s.clients[clientID]
	c.Provisioning = ProvisioningStatusProvisioned
	c.Provider = provider
	c.ProviderProjectID = providerProjectID
	c.ProviderApplicationID = providerApplicationID
	c.ProviderClientID = providerClientID
	s.clients[clientID] = c
	if secret != nil {
		s.secrets = append(s.secrets, *secret)
	}
	return nil
}

func (s *fakeStore) MarkClientProvisioningFailed(_ context.Context, clientID OAuthClientID, _ ProviderOperationID, _ string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	c := s.clients[clientID]
	c.Provisioning = ProvisioningStatusProvisioningFailed
	s.clients[clientID] = c
	return nil
}

func (s *fakeStore) UpdateClientConfig(_ context.Context, clientID OAuthClientID, upd ClientConfigUpdate, expectedVersion int) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	c, ok := s.clients[clientID]
	if !ok {
		return ErrNotFound
	}
	if c.Version != expectedVersion {
		return ErrConflict
	}
	c.Name = upd.Name
	c.LogoutURI = upd.LogoutURI
	c.ConsentMode = upd.ConsentMode
	c.RedirectURIs = upd.RedirectURIs
	c.Scopes = upd.Scopes
	c.Version++
	s.clients[clientID] = c
	return nil
}

func (s *fakeStore) SetClientStatus(_ context.Context, clientID OAuthClientID, status Status, expectedVersion int) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	c, ok := s.clients[clientID]
	if !ok {
		return ErrNotFound
	}
	if c.Version != expectedVersion {
		return ErrConflict
	}
	c.Status = status
	c.Version++
	s.clients[clientID] = c
	return nil
}

func (s *fakeStore) MarkClientDeleting(_ context.Context, clientID OAuthClientID, op ProviderOperation) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.markDeletingErr != nil {
		return s.markDeletingErr
	}
	c, ok := s.clients[clientID]
	if !ok {
		return ErrNotFound
	}
	switch c.Provisioning {
	case ProvisioningStatusProvisioned, ProvisioningStatusProvisioning, ProvisioningStatusProvisioningFailed:
	default:
		return ErrConflict
	}
	c.Provisioning = ProvisioningStatusDeleting
	s.clients[clientID] = c
	s.ops[op.ID] = op
	return nil
}

func (s *fakeStore) MarkClientDeletingRetry(_ context.Context, clientID OAuthClientID, op ProviderOperation) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	c, ok := s.clients[clientID]
	if !ok {
		return ErrNotFound
	}
	if c.Provisioning != ProvisioningStatusDeleteFailed {
		return ErrConflict
	}
	c.Provisioning = ProvisioningStatusDeleting
	s.clients[clientID] = c
	s.ops[op.ID] = op
	return nil
}

func (s *fakeStore) CompleteClientDeletion(_ context.Context, clientID OAuthClientID, _ ProviderOperationID) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.completeDelErr != nil {
		return s.completeDelErr
	}
	s.deleted[clientID] = true
	return nil
}

func (s *fakeStore) MarkClientDeleteFailed(_ context.Context, clientID OAuthClientID, _ ProviderOperationID, _ string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	c := s.clients[clientID]
	c.Provisioning = ProvisioningStatusDeleteFailed
	s.clients[clientID] = c
	return nil
}

func (s *fakeStore) CreateSecretRecord(_ context.Context, rec ClientSecretRecord) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.secrets = append(s.secrets, rec)
	return nil
}

func (s *fakeStore) MarkSecretRotated(_ context.Context, secretID ClientSecretID, rotatedAt time.Time) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	for i := range s.secrets {
		if s.secrets[i].ID == secretID {
			s.secrets[i].LastRotatedAt = &rotatedAt
		}
	}
	return nil
}

func (s *fakeStore) GetClientSecretRecords(_ context.Context, clientID OAuthClientID) ([]ClientSecretRecord, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	var out []ClientSecretRecord
	for _, rec := range s.secrets {
		if rec.ClientID == clientID {
			out = append(out, rec)
		}
	}
	return out, nil
}

func (s *fakeStore) GetOperationByIdempotencyKey(_ context.Context, key string) (ProviderOperation, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	for _, op := range s.ops {
		if op.IdempotencyKey == key {
			return op, nil
		}
	}
	return ProviderOperation{}, ErrNotFound
}

func (s *fakeStore) CreateReconciliationJob(_ context.Context, job ReconciliationJob) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.reconcileMarkErr != nil {
		return s.reconcileMarkErr
	}
	s.jobs = append(s.jobs, job)
	return nil
}

func (s *fakeStore) SetClientReconciliationRequired(_ context.Context, clientID OAuthClientID) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.reconcileMarkErr != nil {
		return s.reconcileMarkErr
	}
	return nil
}

type fakeEvents struct {
	mu     sync.Mutex
	events []SecurityEvent
	err    error
}

func (f *fakeEvents) Record(_ context.Context, ev SecurityEvent) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.err != nil {
		return f.err
	}
	f.events = append(f.events, ev)
	return nil
}

type fakeAudits struct {
	entries []AuditEntry
}

func (f *fakeAudits) ListByApplication(_ context.Context, _ ApplicationID) ([]AuditEntry, error) {
	return f.entries, nil
}

type fakeUsers struct {
	ids map[identity.UserID]bool
}

func (f *fakeUsers) GetByID(_ context.Context, userID identity.UserID) (identity.User, error) {
	if !f.ids[userID] {
		return identity.User{}, identity.ErrUserNotFound
	}
	return identity.User{ID: userID}, nil
}

// seqProvisioner wraps FakeProvisioner and records provider calls into the
// shared sequence so provider-first ordering can be asserted.
type seqProvisioner struct {
	*FakeProvisioner
	seq *[]string
}

func (p *seqProvisioner) ProvisionClient(ctx context.Context, key string, spec ClientProvisionSpec) (ClientProvisionResult, error) {
	*p.seq = append(*p.seq, "provider:provision")
	return p.FakeProvisioner.ProvisionClient(ctx, key, spec)
}

func (p *seqProvisioner) DeleteClient(ctx context.Context, providerApplicationID string) error {
	*p.seq = append(*p.seq, "provider:delete")
	return p.FakeProvisioner.DeleteClient(ctx, providerApplicationID)
}

func (p *seqProvisioner) EnableClient(ctx context.Context, providerApplicationID string) error {
	*p.seq = append(*p.seq, "provider:enable")
	return p.FakeProvisioner.EnableClient(ctx, providerApplicationID)
}

func (p *seqProvisioner) DisableClient(ctx context.Context, providerApplicationID string) error {
	*p.seq = append(*p.seq, "provider:disable")
	return p.FakeProvisioner.DisableClient(ctx, providerApplicationID)
}

func newTestService(t *testing.T) (*Service, *fakeStore, *FakeProvisioner, *fakeEvents, *[]string) {
	t.Helper()
	seq := &[]string{}
	store := newFakeStore(seq)
	fakeProv := NewFakeProvisioner()
	prov := &seqProvisioner{FakeProvisioner: fakeProv, seq: seq}
	events := &fakeEvents{}
	svc := NewService(store, prov, events, &fakeAudits{}, &fakeUsers{ids: map[identity.UserID]bool{"user_owner_1": true}}, "fake", "proj_test")
	return svc, store, fakeProv, events, seq
}

func confidentialAppInput() ApplicationInput {
	return ApplicationInput{Name: "Test App", Description: "", Audience: AudienceInternal, OwnerID: "user_owner_1"}
}

func confidentialClientInput() ClientInput {
	return ClientInput{
		Name:         "Test Client",
		Profile:      ClientProfileWebServer,
		RedirectURIs: []string{"https://app.example.com/callback"},
		Scopes:       []string{"openid", "profile"},
		ConsentMode:  ConsentModeAlways,
	}
}

// --- Create with initial client ---

func TestCreateWithInitialClient_ConfidentialSuccess(t *testing.T) {
	svc, store, _, events, _ := newTestService(t)
	ctx := context.Background()

	res, err := svc.CreateWithInitialClient(ctx, "user_actor", "req-1", confidentialAppInput(), confidentialClientInput())
	if err != nil {
		t.Fatalf("create: %v", err)
	}
	if res.ApplicationID == "" || res.ClientID == "" {
		t.Fatal("expected generated IDs")
	}
	if res.ClientSecret == "" {
		t.Fatal("confidential client must return the one-time secret")
	}

	app, err := store.GetApplication(ctx, res.ApplicationID)
	if err != nil {
		t.Fatalf("get app: %v", err)
	}
	if app.Provisioning != ProvisioningStatusProvisioned || app.Status != StatusActive {
		t.Errorf("app state = %s/%s, want provisioned/active", app.Provisioning, app.Status)
	}

	secrets, _ := store.GetClientSecretRecords(ctx, res.ClientID)
	if len(secrets) != 1 {
		t.Fatalf("secret records = %d, want 1", len(secrets))
	}

	// Success events recorded for both the application and the client.
	var types []string
	for _, ev := range events.events {
		types = append(types, ev.EventType)
	}
	if len(types) != 2 || types[0] != EventApplicationCreated || types[1] != EventOAuthClientCreated {
		t.Errorf("event types = %v", types)
	}
}

func TestCreateWithInitialClient_PublicClientHasNoSecret(t *testing.T) {
	svc, store, _, _, _ := newTestService(t)

	in := confidentialClientInput()
	in.Profile = ClientProfileSPAMobile
	res, err := svc.CreateWithInitialClient(context.Background(), "user_actor", "req-1", confidentialAppInput(), in)
	if err != nil {
		t.Fatalf("create: %v", err)
	}
	if res.ClientSecret != "" {
		t.Fatal("public client must never return a secret")
	}
	secrets, _ := store.GetClientSecretRecords(context.Background(), res.ClientID)
	if len(secrets) != 0 {
		t.Fatalf("secret records = %d, want 0", len(secrets))
	}
}

func TestCreateWithInitialClient_OwnerNotFound(t *testing.T) {
	svc, _, _, _, _ := newTestService(t)

	in := confidentialAppInput()
	in.OwnerID = "user_missing"
	_, err := svc.CreateWithInitialClient(context.Background(), "user_actor", "req-1", in, confidentialClientInput())
	if !errors.Is(err, ErrOwnerNotFound) {
		t.Fatalf("err = %v, want ErrOwnerNotFound", err)
	}
}

func TestCreateWithInitialClient_ProviderFailureMarksFailed(t *testing.T) {
	svc, store, prov, _, _ := newTestService(t)
	prov.ProvisionErr = ErrProviderUnavailable

	_, err := svc.CreateWithInitialClient(context.Background(), "user_actor", "req-1", confidentialAppInput(), confidentialClientInput())
	if !errors.Is(err, ErrProviderUnavailable) {
		t.Fatalf("err = %v, want ErrProviderUnavailable", err)
	}
	// Failed rows exist but are not provisioned.
	for _, c := range store.clients {
		if c.Provisioning != ProvisioningStatusProvisioningFailed {
			t.Errorf("client provisioning = %s, want provisioning_failed", c.Provisioning)
		}
	}
}

func TestCreateWithInitialClient_ProviderConflict(t *testing.T) {
	svc, _, prov, _, _ := newTestService(t)
	prov.ProvisionErr = ErrProviderConflict

	_, err := svc.CreateWithInitialClient(context.Background(), "user_actor", "req-1", confidentialAppInput(), confidentialClientInput())
	if !errors.Is(err, ErrProviderConflict) {
		t.Fatalf("err = %v, want ErrProviderConflict", err)
	}
}

func TestCreateWithInitialClient_CompleteFailureCompensates(t *testing.T) {
	svc, store, _, _, _ := newTestService(t)
	store.completeAppErr = errors.New("db down")

	_, err := svc.CreateWithInitialClient(context.Background(), "user_actor", "req-1", confidentialAppInput(), confidentialClientInput())
	if err == nil {
		t.Fatal("expected error when completion fails")
	}
	// Compensation removed the provider resource; no reconciliation needed.
	if len(store.jobs) != 0 {
		t.Errorf("reconciliation jobs = %d, want 0 (compensation succeeded)", len(store.jobs))
	}
}

func TestCreateWithInitialClient_CompleteFailureCompensationFailsReconciles(t *testing.T) {
	svc, store, prov, events, _ := newTestService(t)
	store.completeAppErr = errors.New("db down")
	prov.DeleteErr = ErrProviderUnavailable

	_, err := svc.CreateWithInitialClient(context.Background(), "user_actor", "req-1", confidentialAppInput(), confidentialClientInput())
	if err == nil {
		t.Fatal("expected error when completion fails")
	}
	if len(store.jobs) != 1 {
		t.Fatalf("reconciliation jobs = %d, want 1", len(store.jobs))
	}
	found := false
	for _, ev := range events.events {
		if ev.EventType == EventProviderReconciliationNeed {
			found = true
		}
	}
	if !found {
		t.Error("expected reconciliation audit event")
	}
}

// --- Get ---

func TestGetAssemblesDetail(t *testing.T) {
	svc, _, _, _, _ := newTestService(t)
	ctx := context.Background()

	res, err := svc.CreateWithInitialClient(ctx, "user_actor", "req-1", confidentialAppInput(), confidentialClientInput())
	if err != nil {
		t.Fatalf("create: %v", err)
	}
	detail, err := svc.Get(ctx, res.ApplicationID)
	if err != nil {
		t.Fatalf("get: %v", err)
	}
	if len(detail.Clients) != 1 || detail.Clients[0].ID != res.ClientID {
		t.Errorf("detail clients = %+v", detail.Clients)
	}

	if _, err := svc.Get(ctx, ApplicationID("app_missing")); !errors.Is(err, ErrNotFound) {
		t.Errorf("err = %v, want ErrNotFound", err)
	}
}

// --- Update ---

func TestUpdateApplicationMergesPatch(t *testing.T) {
	svc, store, _, _, _ := newTestService(t)
	ctx := context.Background()

	res, err := svc.CreateWithInitialClient(ctx, "user_actor", "req-1", confidentialAppInput(), confidentialClientInput())
	if err != nil {
		t.Fatalf("create: %v", err)
	}
	newName := "Renamed App"
	updated, err := svc.UpdateApplication(ctx, "user_actor", res.ApplicationID, "req-2", ApplicationPatch{Name: &newName})
	if err != nil {
		t.Fatalf("update: %v", err)
	}
	if updated.Name != newName {
		t.Errorf("name = %q, want %q", updated.Name, newName)
	}
	// Unsubmitted fields are preserved.
	if updated.Audience != AudienceInternal || updated.OwnerID != "user_owner_1" {
		t.Errorf("unrelated fields changed: %+v", updated)
	}
	if store.apps[res.ApplicationID].Version != 2 {
		t.Errorf("version = %d, want 2", store.apps[res.ApplicationID].Version)
	}
}

func TestUpdateApplicationRejectsUnknownOwner(t *testing.T) {
	svc, _, _, _, _ := newTestService(t)
	ctx := context.Background()

	res, err := svc.CreateWithInitialClient(ctx, "user_actor", "req-1", confidentialAppInput(), confidentialClientInput())
	if err != nil {
		t.Fatalf("create: %v", err)
	}
	bad := identity.UserID("user_missing")
	_, err = svc.UpdateApplication(ctx, "user_actor", res.ApplicationID, "req-2", ApplicationPatch{OwnerID: &bad})
	if !errors.Is(err, ErrOwnerNotFound) {
		t.Fatalf("err = %v, want ErrOwnerNotFound", err)
	}
}

func TestUpdateApplicationValidatesMergedInput(t *testing.T) {
	svc, _, _, _, _ := newTestService(t)
	ctx := context.Background()

	res, err := svc.CreateWithInitialClient(ctx, "user_actor", "req-1", confidentialAppInput(), confidentialClientInput())
	if err != nil {
		t.Fatalf("create: %v", err)
	}
	short := "x"
	_, err = svc.UpdateApplication(ctx, "user_actor", res.ApplicationID, "req-2", ApplicationPatch{Name: &short})
	var verr *ValidationErrors
	if !errors.As(err, &verr) {
		t.Fatalf("err = %v, want ValidationErrors", err)
	}
}

// --- Enable / Disable ---

func TestSetStatusDisablesProviderFirst(t *testing.T) {
	svc, store, _, _, seq := newTestService(t)
	ctx := context.Background()

	res, err := svc.CreateWithInitialClient(ctx, "user_actor", "req-1", confidentialAppInput(), confidentialClientInput())
	if err != nil {
		t.Fatalf("create: %v", err)
	}
	if err := svc.SetStatus(ctx, "user_actor", res.ApplicationID, "req-2", false); err != nil {
		t.Fatalf("disable: %v", err)
	}
	if store.apps[res.ApplicationID].Status != StatusDisabled {
		t.Error("application not disabled")
	}
	// Provider call must precede the local status change.
	var providerIdx, storeIdx = -1, -1
	for i, step := range *seq {
		if step == "provider:disable" && providerIdx == -1 {
			providerIdx = i
		}
		if step == "store:set-app-status" && storeIdx == -1 {
			storeIdx = i
		}
	}
	if providerIdx == -1 || storeIdx == -1 || providerIdx > storeIdx {
		t.Errorf("provider call must precede local update: %v", *seq)
	}
}

func TestSetStatusProviderFailureLeavesLocalUnchanged(t *testing.T) {
	svc, store, prov, _, _ := newTestService(t)
	ctx := context.Background()

	res, err := svc.CreateWithInitialClient(ctx, "user_actor", "req-1", confidentialAppInput(), confidentialClientInput())
	if err != nil {
		t.Fatalf("create: %v", err)
	}
	prov.DisableErr = ErrProviderUnavailable

	err = svc.SetStatus(ctx, "user_actor", res.ApplicationID, "req-2", false)
	if !errors.Is(err, ErrProviderUnavailable) {
		t.Fatalf("err = %v, want ErrProviderUnavailable", err)
	}
	if store.apps[res.ApplicationID].Status != StatusActive {
		t.Error("local status must stay unchanged on provider failure")
	}
}

func TestSetStatusEnableSkipsDisabledClients(t *testing.T) {
	svc, store, _, _, seq := newTestService(t)
	ctx := context.Background()

	res, err := svc.CreateWithInitialClient(ctx, "user_actor", "req-1", confidentialAppInput(), confidentialClientInput())
	if err != nil {
		t.Fatalf("create: %v", err)
	}
	// Disable the client individually, then the application.
	for id := range store.clients {
		c := store.clients[id]
		c.Status = StatusDisabled
		store.clients[id] = c
	}
	if err := svc.SetStatus(ctx, "user_actor", res.ApplicationID, "req-2", false); err != nil {
		t.Fatalf("disable: %v", err)
	}

	*seq = (*seq)[:0]
	if err := svc.SetStatus(ctx, "user_actor", res.ApplicationID, "req-3", true); err != nil {
		t.Fatalf("enable: %v", err)
	}
	for _, step := range *seq {
		if step == "provider:enable" {
			t.Error("individually disabled clients must not be re-enabled at the provider")
		}
	}
	if store.apps[res.ApplicationID].Status != StatusActive {
		t.Error("application not re-enabled")
	}
}

func TestSetStatusInvalidTransition(t *testing.T) {
	svc, _, _, _, _ := newTestService(t)
	ctx := context.Background()

	res, err := svc.CreateWithInitialClient(ctx, "user_actor", "req-1", confidentialAppInput(), confidentialClientInput())
	if err != nil {
		t.Fatalf("create: %v", err)
	}
	// Enabling an already-active application is rejected.
	if err := svc.SetStatus(ctx, "user_actor", res.ApplicationID, "req-2", true); !errors.Is(err, ErrInvalidStateTransition) {
		t.Fatalf("err = %v, want ErrInvalidStateTransition", err)
	}
}

// --- Delete ---

func TestDeleteRemovesClientsThenApplication(t *testing.T) {
	svc, store, _, _, _ := newTestService(t)
	ctx := context.Background()

	res, err := svc.CreateWithInitialClient(ctx, "user_actor", "req-1", confidentialAppInput(), confidentialClientInput())
	if err != nil {
		t.Fatalf("create: %v", err)
	}
	if err := svc.Delete(ctx, "user_actor", res.ApplicationID, "req-2"); err != nil {
		t.Fatalf("delete: %v", err)
	}
	if _, ok := store.apps[res.ApplicationID]; ok {
		t.Error("application still present")
	}
	if !store.deleted[res.ClientID] {
		t.Error("client not marked deleted")
	}
}

func TestDeleteProviderFailureAbortsAndReconciles(t *testing.T) {
	svc, store, prov, events, _ := newTestService(t)
	ctx := context.Background()

	res, err := svc.CreateWithInitialClient(ctx, "user_actor", "req-1", confidentialAppInput(), confidentialClientInput())
	if err != nil {
		t.Fatalf("create: %v", err)
	}
	prov.DeleteErr = ErrProviderUnavailable

	err = svc.Delete(ctx, "user_actor", res.ApplicationID, "req-2")
	if !errors.Is(err, ErrProviderUnavailable) {
		t.Fatalf("err = %v, want ErrProviderUnavailable", err)
	}
	if _, ok := store.apps[res.ApplicationID]; !ok {
		t.Error("application must survive a failed client deletion")
	}
	if len(store.jobs) != 1 {
		t.Errorf("reconciliation jobs = %d, want 1", len(store.jobs))
	}
	found := false
	for _, ev := range events.events {
		if ev.EventType == EventProviderReconciliationNeed {
			found = true
		}
	}
	if !found {
		t.Error("expected reconciliation audit event")
	}
}

func TestDeleteConcurrentDeletionConflicts(t *testing.T) {
	svc, store, _, _, _ := newTestService(t)
	ctx := context.Background()

	res, err := svc.CreateWithInitialClient(ctx, "user_actor", "req-1", confidentialAppInput(), confidentialClientInput())
	if err != nil {
		t.Fatalf("create: %v", err)
	}
	for id := range store.clients {
		c := store.clients[id]
		c.Provisioning = ProvisioningStatusDeleting
		store.clients[id] = c
	}
	if err := svc.Delete(ctx, "user_actor", res.ApplicationID, "req-2"); !errors.Is(err, ErrConflict) {
		t.Fatalf("err = %v, want ErrConflict", err)
	}
}

func TestErrorClassFor(t *testing.T) {
	cases := []struct {
		err  error
		want string
	}{
		{ErrProviderConflict, "provider_conflict"},
		{ErrProviderUnavailable, "provider_unavailable"},
		{ErrNotFound, "not_found"},
		{ErrConflict, "state_conflict"},
		{ErrInvalidStateTransition, "invalid_state_transition"},
		{errors.New("boom"), "internal"},
	}
	for _, tc := range cases {
		if got := ErrorClassFor(tc.err); got != tc.want {
			t.Errorf("ErrorClassFor(%v) = %q, want %q", tc.err, got, tc.want)
		}
	}
}
