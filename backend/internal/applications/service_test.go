package applications

import (
	"context"
	"errors"
	"fmt"
	"sync"
	"testing"
	"time"

	"github.com/GravelEvolution/united-pass/backend/internal/identity"
)

// --- Test fakes ---

// fakeStore is an in-memory ApplicationStore. It is intentionally minimal:
// only the state needed by the orchestration tests is tracked.
type fakeStore struct {
	mu        sync.Mutex
	apps      map[ApplicationID]Application
	clients   map[OAuthClientID]OAuthClient
	deleted   map[OAuthClientID]bool
	ops       map[ProviderOperationID]ProviderOperation
	secrets   []ClientSecretRecord
	jobs      []ReconciliationJob
	rotation  map[OAuthClientID]string
	seq       *[]string
	auditSink *fakeEvents

	createAppErr        error
	completeAppErr      error
	updateAppErr        error
	setAppStatusErr     error
	deleteAppErr        error
	listErr             error
	updateClientErr     error
	setClientStatusErr  error
	markDeletingErr     error
	completeDelErr      error
	reconcileMarkErr    error
	beginRotationErr    error
	completeRotationErr error
}

func newFakeStore(seq *[]string) *fakeStore {
	return &fakeStore{
		apps:     make(map[ApplicationID]Application),
		clients:  make(map[OAuthClientID]OAuthClient),
		deleted:  make(map[OAuthClientID]bool),
		ops:      make(map[ProviderOperationID]ProviderOperation),
		rotation: make(map[OAuthClientID]string),
		seq:      seq,
	}
}

func (s *fakeStore) note(step string) {
	if s.seq != nil {
		*s.seq = append(*s.seq, step)
	}
}

// recordAudit mirrors the repository contract: durable success audits
// commit with the terminal state, and an audit write failure aborts the
// whole commit (ADR-0004 §8).
func (s *fakeStore) recordAudit(audit []SecurityEvent) error {
	if s.auditSink == nil {
		return nil
	}
	for _, ev := range audit {
		if err := s.auditSink.Record(context.Background(), ev); err != nil {
			return err
		}
	}
	return nil
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

func (s *fakeStore) CompleteInitialProvisioning(_ context.Context, appID ApplicationID, clientID OAuthClientID, provider, providerProjectID, providerApplicationID, providerClientID string, _ ProviderOperationID, secret *ClientSecretRecord, audit ...SecurityEvent) error {
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
	return s.recordAudit(audit)
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

func (s *fakeStore) UpdateApplication(_ context.Context, appID ApplicationID, upd ApplicationUpdate, expectedVersion int, audit ...SecurityEvent) error {
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
	return s.recordAudit(audit)
}

func (s *fakeStore) SetApplicationStatus(_ context.Context, appID ApplicationID, status Status, expectedVersion int, audit ...SecurityEvent) error {
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
	return s.recordAudit(audit)
}

func (s *fakeStore) DeleteApplication(_ context.Context, appID ApplicationID, expectedVersion int, audit ...SecurityEvent) error {
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
	return s.recordAudit(audit)
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

func (s *fakeStore) CompleteClientProvisioning(_ context.Context, clientID OAuthClientID, provider, providerProjectID, providerApplicationID, providerClientID string, _ ProviderOperationID, secret *ClientSecretRecord, audit ...SecurityEvent) error {
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
	return s.recordAudit(audit)
}

func (s *fakeStore) MarkClientProvisioningFailed(_ context.Context, clientID OAuthClientID, _ ProviderOperationID, _ string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	c := s.clients[clientID]
	c.Provisioning = ProvisioningStatusProvisioningFailed
	s.clients[clientID] = c
	return nil
}

func (s *fakeStore) UpdateClientConfig(_ context.Context, clientID OAuthClientID, upd ClientConfigUpdate, expectedVersion int, audit ...SecurityEvent) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.updateClientErr != nil {
		return s.updateClientErr
	}
	s.note("store:update-client")
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
	return s.recordAudit(audit)
}

func (s *fakeStore) SetClientStatus(_ context.Context, clientID OAuthClientID, status Status, expectedVersion int, audit ...SecurityEvent) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.setClientStatusErr != nil {
		return s.setClientStatusErr
	}
	s.note("store:set-client-status")
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
	return s.recordAudit(audit)
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
	if c.Provisioning != ProvisioningStatusDeleteFailed && c.Provisioning != ProvisioningStatusDeleting {
		return ErrConflict
	}
	c.Provisioning = ProvisioningStatusDeleting
	s.clients[clientID] = c
	s.ops[op.ID] = op
	return nil
}

func (s *fakeStore) CompleteClientDeletion(_ context.Context, clientID OAuthClientID, _ ProviderOperationID, audit ...SecurityEvent) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.completeDelErr != nil {
		return s.completeDelErr
	}
	s.deleted[clientID] = true
	return s.recordAudit(audit)
}

func (s *fakeStore) MarkClientDeleteFailed(_ context.Context, clientID OAuthClientID, _ ProviderOperationID, _ string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	c := s.clients[clientID]
	c.Provisioning = ProvisioningStatusDeleteFailed
	s.clients[clientID] = c
	return nil
}

func (s *fakeStore) rotationStatus(clientID OAuthClientID) string {
	if st, ok := s.rotation[clientID]; ok {
		return st
	}
	return "idle"
}

func (s *fakeStore) BeginSecretRotation(_ context.Context, clientID OAuthClientID, expectedVersion int, op ProviderOperation) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.beginRotationErr != nil {
		return s.beginRotationErr
	}
	c, ok := s.clients[clientID]
	if !ok || s.deleted[clientID] {
		return ErrNotFound
	}
	if c.Version != expectedVersion {
		return ErrConflict
	}
	// Only an idle client may acquire the gate; in_progress and
	// outcome_unknown clients refuse further rotations.
	if s.rotationStatus(clientID) != "idle" {
		return ErrConflict
	}
	s.rotation[clientID] = "in_progress"
	c.Version++
	s.clients[clientID] = c
	s.ops[op.ID] = op
	return nil
}

func (s *fakeStore) CompleteSecretRotation(_ context.Context, clientID OAuthClientID, opID ProviderOperationID, rotatedSecretID ClientSecretID, newRec ClientSecretRecord, rotatedAt time.Time, audit ...SecurityEvent) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.completeRotationErr != nil {
		return s.completeRotationErr
	}
	if s.rotationStatus(clientID) != "in_progress" {
		return ErrConflict
	}
	for i := range s.secrets {
		if s.secrets[i].ID == rotatedSecretID {
			s.secrets[i].LastRotatedAt = &rotatedAt
		}
	}
	s.secrets = append(s.secrets, newRec)
	s.rotation[clientID] = "idle"
	op := s.ops[opID]
	op.Status = ProviderOperationSucceeded
	s.ops[opID] = op
	c := s.clients[clientID]
	c.Version++
	s.clients[clientID] = c
	return s.recordAudit(audit)
}

func (s *fakeStore) AbortSecretRotation(_ context.Context, clientID OAuthClientID, opID ProviderOperationID, errorClass string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.rotation[clientID] = "idle"
	op := s.ops[opID]
	op.Status = ProviderOperationFailed
	op.ErrorClass = errorClass
	s.ops[opID] = op
	return nil
}

func (s *fakeStore) FailSecretRotationUnknown(_ context.Context, clientID OAuthClientID, opID ProviderOperationID, errorClass string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.rotation[clientID] = "outcome_unknown"
	op := s.ops[opID]
	op.Status = ProviderOperationFailed
	op.ErrorClass = errorClass
	s.ops[opID] = op
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

func (p *seqProvisioner) UpdateClient(ctx context.Context, providerApplicationID string, spec ClientUpdateSpec) error {
	*p.seq = append(*p.seq, "provider:update")
	return p.FakeProvisioner.UpdateClient(ctx, providerApplicationID, spec)
}

func newTestService(t *testing.T) (*Service, *fakeStore, *FakeProvisioner, *fakeEvents, *[]string) {
	t.Helper()
	seq := &[]string{}
	store := newFakeStore(seq)
	fakeProv := NewFakeProvisioner()
	prov := &seqProvisioner{FakeProvisioner: fakeProv, seq: seq}
	events := &fakeEvents{}
	// Durable success audits flow through the store's terminal commits into
	// the same sink the best-effort recorder uses.
	store.auditSink = events
	svc := NewService(store, prov, events, &fakeAudits{}, &fakeUsers{ids: map[identity.UserID]bool{"user_owner_1": true}}, "fake", "proj_test", 0)
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

func TestSetStatusLocalFailureAfterProviderSwitchReconciles(t *testing.T) {
	svc, store, prov, events, _ := newTestService(t)
	ctx := context.Background()

	res, err := svc.CreateWithInitialClient(ctx, "user_actor", "req-1", confidentialAppInput(), confidentialClientInput())
	if err != nil {
		t.Fatalf("create: %v", err)
	}
	store.setAppStatusErr = errors.New("db down")

	err = svc.SetStatus(ctx, "user_actor", res.ApplicationID, "req-2", false)
	if err == nil {
		t.Fatal("expected local commit failure")
	}
	// Every client already disabled at the provider: each carries a drift
	// trail, and the local application status stays unchanged.
	if store.apps[res.ApplicationID].Status != StatusActive {
		t.Error("local application status must stay unchanged")
	}
	if len(store.jobs) != 1 {
		t.Errorf("reconciliation jobs = %d, want 1 per switched client", len(store.jobs))
	}
	if len(store.jobs) > 0 && store.jobs[0].DesiredStatus != string(StatusDisabled) {
		t.Errorf("job desired status = %q, want %q", store.jobs[0].DesiredStatus, StatusDisabled)
	}
	fake := prov.Client(store.clients[res.ClientID].ProviderApplicationID)
	if fake == nil || !fake.Disabled {
		t.Error("provider client must already be disabled")
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

// appWithTwoClients creates an application with two confidential clients and
// disables the application, returning the application ID.
func appWithTwoClients(t *testing.T, svc *Service, ctx context.Context) ApplicationID {
	t.Helper()
	res, err := svc.CreateWithInitialClient(ctx, "user_actor", "req-1", confidentialAppInput(), confidentialClientInput())
	if err != nil {
		t.Fatalf("create: %v", err)
	}
	if _, err := svc.CreateClient(ctx, "user_actor", res.ApplicationID, "req-2", confidentialClientInput()); err != nil {
		t.Fatalf("create second client: %v", err)
	}
	if err := svc.SetStatus(ctx, "user_actor", res.ApplicationID, "req-3", false); err != nil {
		t.Fatalf("disable application: %v", err)
	}
	return res.ApplicationID
}

// TestSetStatusEnablePartialFailureRollsBack covers the kill-switch leak:
// enabling an application whose second provider client fails must roll the
// first client back to disabled instead of leaving it active at the provider
// while the application stays disabled locally.
func TestSetStatusEnablePartialFailureRollsBack(t *testing.T) {
	svc, store, prov, _, _ := newTestService(t)
	ctx := context.Background()
	appID := appWithTwoClients(t, svc, ctx)

	// The second provider enable fails: whichever client switches first
	// succeeds, the next one fails and must be rolled back.
	prov.EnableSkip = 1
	prov.EnableErr = ErrProviderUnavailable
	err := svc.SetStatus(ctx, "user_actor", appID, "req-4", true)
	if !errors.Is(err, ErrProviderUnavailable) {
		t.Fatalf("err = %v, want ErrProviderUnavailable", err)
	}
	if store.apps[appID].Status != StatusDisabled {
		t.Error("application must stay disabled after partial enable failure")
	}
	if len(store.jobs) != 0 {
		t.Errorf("successful rollback leaves no jobs, got %d", len(store.jobs))
	}
	for _, c := range store.clients {
		if fake := prov.Client(c.ProviderApplicationID); fake == nil || !fake.Disabled {
			t.Errorf("provider client %s must be rolled back to disabled", c.ID)
		}
	}
}

// TestSetStatusEnablePartialRollbackFailureLeavesJob covers the rollback
// itself failing: the stuck client must carry a reconciliation job with an
// explicit desired status, never a silent active-at-provider state.
func TestSetStatusEnablePartialRollbackFailureLeavesJob(t *testing.T) {
	svc, store, prov, events, _ := newTestService(t)
	ctx := context.Background()
	appID := appWithTwoClients(t, svc, ctx)

	prov.EnableSkip = 1
	prov.EnableErr = ErrProviderUnavailable  // second enable fails
	prov.DisableErr = ErrProviderUnavailable // rollback of the first fails too
	err := svc.SetStatus(ctx, "user_actor", appID, "req-4", true)
	if !errors.Is(err, ErrProviderUnavailable) {
		t.Fatalf("err = %v, want ErrProviderUnavailable", err)
	}
	if store.apps[appID].Status != StatusDisabled {
		t.Error("application must stay disabled")
	}
	if len(store.jobs) != 1 {
		t.Fatalf("reconciliation jobs = %d, want 1 for the failed rollback", len(store.jobs))
	}
	if store.jobs[0].DesiredStatus != string(StatusDisabled) {
		t.Errorf("job desired status = %q, want %q", store.jobs[0].DesiredStatus, StatusDisabled)
	}
	found := false
	for _, ev := range events.events {
		if ev.EventType == EventProviderReconciliationNeed {
			found = true
		}
	}
	if !found {
		t.Error("expected reconciliation audit event for failed rollback")
	}
}

// TestSetStatusDisablePartialFailureRecordsDriftJobs covers the fail-safe
// direction: when a disable fan-out fails mid-way, already-disabled clients
// stay disabled and each carries a reconciliation job with the desired
// status — no silent drift, no re-enable.
func TestSetStatusDisablePartialFailureRecordsDriftJobs(t *testing.T) {
	svc, store, prov, _, _ := newTestService(t)
	ctx := context.Background()

	res, err := svc.CreateWithInitialClient(ctx, "user_actor", "req-1", confidentialAppInput(), confidentialClientInput())
	if err != nil {
		t.Fatalf("create: %v", err)
	}
	if _, err := svc.CreateClient(ctx, "user_actor", res.ApplicationID, "req-2", confidentialClientInput()); err != nil {
		t.Fatalf("create second client: %v", err)
	}

	prov.DisableSkip = 1
	prov.DisableErr = ErrProviderUnavailable // second disable fails
	err = svc.SetStatus(ctx, "user_actor", res.ApplicationID, "req-3", false)
	if !errors.Is(err, ErrProviderUnavailable) {
		t.Fatalf("err = %v, want ErrProviderUnavailable", err)
	}
	if store.apps[res.ApplicationID].Status != StatusActive {
		t.Error("application must stay active after partial disable failure")
	}
	if len(store.jobs) != 1 {
		t.Fatalf("reconciliation jobs = %d, want 1 for the switched client", len(store.jobs))
	}
	if store.jobs[0].DesiredStatus != string(StatusDisabled) {
		t.Errorf("job desired status = %q, want %q (fail-safe)", store.jobs[0].DesiredStatus, StatusDisabled)
	}
	// Exactly one client switched and it must remain disabled (never
	// re-enabled by the recovery path).
	disabled := 0
	for _, c := range store.clients {
		if fake := prov.Client(c.ProviderApplicationID); fake != nil && fake.Disabled {
			disabled++
		}
	}
	if disabled != 1 {
		t.Errorf("disabled provider clients = %d, want exactly the 1 switched client", disabled)
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

func TestDeleteStuckDeletingRetriesIdempotently(t *testing.T) {
	svc, store, _, _, _ := newTestService(t)
	ctx := context.Background()

	res, err := svc.CreateWithInitialClient(ctx, "user_actor", "req-1", confidentialAppInput(), confidentialClientInput())
	if err != nil {
		t.Fatalf("create: %v", err)
	}
	// Simulate a crash after the provider removal succeeded but before the
	// local commit: the client is stuck in deleting. Provider removal is
	// idempotent, so the application deletion re-drives it instead of
	// failing forever.
	for id := range store.clients {
		c := store.clients[id]
		c.Provisioning = ProvisioningStatusDeleting
		store.clients[id] = c
	}
	if err := svc.Delete(ctx, "user_actor", res.ApplicationID, "req-2"); err != nil {
		t.Fatalf("delete application with stuck deleting client: %v", err)
	}
	if _, ok := store.apps[res.ApplicationID]; ok {
		t.Error("application must be deleted after the retry")
	}
}

// --- Create client (standalone) ---

func TestCreateClient_ConfidentialSuccess(t *testing.T) {
	svc, store, prov, events, _ := newTestService(t)
	ctx := context.Background()

	res, err := svc.CreateWithInitialClient(ctx, "user_actor", "req-1", confidentialAppInput(), confidentialClientInput())
	if err != nil {
		t.Fatalf("create app: %v", err)
	}

	clientRes, err := svc.CreateClient(ctx, "user_actor", res.ApplicationID, "req-2", confidentialClientInput())
	if err != nil {
		t.Fatalf("create client: %v", err)
	}
	if clientRes.ClientID == "" {
		t.Fatal("expected generated client ID")
	}
	if clientRes.ClientSecret == "" {
		t.Fatal("confidential client must return the one-time secret")
	}

	stored, err := store.GetClient(ctx, res.ApplicationID, clientRes.ClientID)
	if err != nil {
		t.Fatalf("get client: %v", err)
	}
	if stored.Provisioning != ProvisioningStatusProvisioned || stored.Status != StatusActive {
		t.Errorf("client state = %s/%s, want provisioned/active", stored.Provisioning, stored.Status)
	}
	if prov.Client(stored.ProviderApplicationID) == nil {
		t.Error("provider resource missing")
	}
	secrets, _ := store.GetClientSecretRecords(ctx, clientRes.ClientID)
	if len(secrets) != 1 {
		t.Fatalf("secret records = %d, want 1", len(secrets))
	}
	found := false
	for _, ev := range events.events {
		if ev.EventType == EventOAuthClientCreated && ev.ClientID == clientRes.ClientID && ev.Result == SecurityEventSuccess {
			found = true
		}
	}
	if !found {
		t.Error("expected oauth_client.created success event")
	}
}

func TestCreateClient_PublicNoSecret(t *testing.T) {
	svc, store, _, _, _ := newTestService(t)
	ctx := context.Background()

	res, err := svc.CreateWithInitialClient(ctx, "user_actor", "req-1", confidentialAppInput(), confidentialClientInput())
	if err != nil {
		t.Fatalf("create app: %v", err)
	}
	in := confidentialClientInput()
	in.Profile = ClientProfileSPAMobile
	clientRes, err := svc.CreateClient(ctx, "user_actor", res.ApplicationID, "req-2", in)
	if err != nil {
		t.Fatalf("create client: %v", err)
	}
	if clientRes.ClientSecret != "" {
		t.Fatal("public client must never return a secret")
	}
	secrets, _ := store.GetClientSecretRecords(ctx, clientRes.ClientID)
	if len(secrets) != 0 {
		t.Fatalf("secret records = %d, want 0", len(secrets))
	}
}

func TestCreateClient_AppNotFound(t *testing.T) {
	svc, _, _, _, _ := newTestService(t)
	_, err := svc.CreateClient(context.Background(), "user_actor", ApplicationID("app_missing"), "req-1", confidentialClientInput())
	if !errors.Is(err, ErrNotFound) {
		t.Fatalf("err = %v, want ErrNotFound", err)
	}
}

func TestCreateClient_UnknownProfileRejected(t *testing.T) {
	svc, _, _, _, _ := newTestService(t)
	ctx := context.Background()
	res, err := svc.CreateWithInitialClient(ctx, "user_actor", "req-1", confidentialAppInput(), confidentialClientInput())
	if err != nil {
		t.Fatalf("create app: %v", err)
	}
	in := confidentialClientInput()
	in.Profile = ClientProfile("bogus")
	_, err = svc.CreateClient(ctx, "user_actor", res.ApplicationID, "req-2", in)
	if !errors.Is(err, ErrInvalidStateTransition) {
		t.Fatalf("err = %v, want ErrInvalidStateTransition", err)
	}
}

func TestCreateClient_ProviderFailureMarksFailed(t *testing.T) {
	svc, store, prov, _, _ := newTestService(t)
	ctx := context.Background()
	res, err := svc.CreateWithInitialClient(ctx, "user_actor", "req-1", confidentialAppInput(), confidentialClientInput())
	if err != nil {
		t.Fatalf("create app: %v", err)
	}
	prov.ProvisionErr = ErrProviderUnavailable

	_, err = svc.CreateClient(ctx, "user_actor", res.ApplicationID, "req-2", confidentialClientInput())
	if !errors.Is(err, ErrProviderUnavailable) {
		t.Fatalf("err = %v, want ErrProviderUnavailable", err)
	}
	// The application stays untouched; only the new client row is failed.
	failed := 0
	for _, c := range store.clients {
		if c.Provisioning == ProvisioningStatusProvisioningFailed {
			failed++
		}
	}
	if failed != 1 {
		t.Errorf("failed clients = %d, want 1", failed)
	}
	if store.apps[res.ApplicationID].Provisioning != ProvisioningStatusProvisioned {
		t.Error("application provisioning must stay provisioned")
	}
}

func TestCreateClient_ProviderConflict(t *testing.T) {
	svc, _, prov, _, _ := newTestService(t)
	ctx := context.Background()
	res, err := svc.CreateWithInitialClient(ctx, "user_actor", "req-1", confidentialAppInput(), confidentialClientInput())
	if err != nil {
		t.Fatalf("create app: %v", err)
	}
	prov.ProvisionErr = ErrProviderConflict
	_, err = svc.CreateClient(ctx, "user_actor", res.ApplicationID, "req-2", confidentialClientInput())
	if !errors.Is(err, ErrProviderConflict) {
		t.Fatalf("err = %v, want ErrProviderConflict", err)
	}
}

// --- Client detail ---

func TestGetClientBindingAndLookup(t *testing.T) {
	svc, _, _, _, _ := newTestService(t)
	ctx := context.Background()
	res, err := svc.CreateWithInitialClient(ctx, "user_actor", "req-1", confidentialAppInput(), confidentialClientInput())
	if err != nil {
		t.Fatalf("create: %v", err)
	}
	if _, err := svc.GetClient(ctx, res.ApplicationID, res.ClientID); err != nil {
		t.Fatalf("get client: %v", err)
	}
	// A client looked up under the wrong application is not found
	// (anti-enumeration).
	if _, err := svc.GetClient(ctx, ApplicationID("app_other"), res.ClientID); !errors.Is(err, ErrNotFound) {
		t.Errorf("err = %v, want ErrNotFound", err)
	}
	if _, err := svc.GetClient(ctx, res.ApplicationID, OAuthClientID("clt_missing")); !errors.Is(err, ErrNotFound) {
		t.Errorf("err = %v, want ErrNotFound", err)
	}
}

// --- Update client ---

func TestUpdateClient_MergesAndSyncsProviderFirst(t *testing.T) {
	svc, _, prov, events, seq := newTestService(t)
	ctx := context.Background()
	res, err := svc.CreateWithInitialClient(ctx, "user_actor", "req-1", confidentialAppInput(), confidentialClientInput())
	if err != nil {
		t.Fatalf("create: %v", err)
	}

	newName := "Renamed Client"
	newURIs := []string{"https://new.example.com/callback"}
	newScopes := []string{"openid", "email"}
	updated, err := svc.UpdateClient(ctx, "user_actor", res.ApplicationID, res.ClientID, "req-2", ClientPatch{
		Name:          &newName,
		RedirectURIs:  &newURIs,
		AllowedScopes: &newScopes,
	})
	if err != nil {
		t.Fatalf("update: %v", err)
	}
	if updated.Name != newName {
		t.Errorf("name = %q, want %q", updated.Name, newName)
	}
	if len(updated.RedirectURIs) != 1 || updated.RedirectURIs[0].URI != "https://new.example.com/callback" {
		t.Errorf("redirect uris = %+v", updated.RedirectURIs)
	}
	if len(updated.Scopes) != 2 {
		t.Errorf("scopes = %v", updated.Scopes)
	}
	// Unsubmitted fields are preserved.
	if updated.ConsentMode != ConsentModeAlways || updated.Profile != ClientProfileWebServer {
		t.Errorf("unrelated fields changed: %+v", updated)
	}

	// Provider was synchronized with the new settings.
	stored, err := svc.GetClient(ctx, res.ApplicationID, res.ClientID)
	if err != nil {
		t.Fatalf("get client: %v", err)
	}
	fake := prov.Client(stored.ProviderApplicationID)
	if fake == nil || fake.DisplayName != ProviderDisplayName("Test App", newName, res.ClientID) {
		t.Errorf("provider client not updated: %+v", fake)
	}
	// Provider call must precede the local write.
	var providerIdx, storeIdx = -1, -1
	for i, step := range *seq {
		if step == "provider:update" && providerIdx == -1 {
			providerIdx = i
		}
		if step == "store:update-client" && storeIdx == -1 {
			storeIdx = i
		}
	}
	if providerIdx == -1 || storeIdx == -1 || providerIdx > storeIdx {
		t.Errorf("provider call must precede local update: %v", *seq)
	}
	found := false
	for _, ev := range events.events {
		if ev.EventType == EventOAuthClientUpdated && ev.Result == SecurityEventSuccess {
			found = true
		}
	}
	if !found {
		t.Error("expected oauth_client.updated success event")
	}
}

func TestUpdateClient_ScopeOnlyPatchSkipsProvider(t *testing.T) {
	svc, _, _, _, seq := newTestService(t)
	ctx := context.Background()
	res, err := svc.CreateWithInitialClient(ctx, "user_actor", "req-1", confidentialAppInput(), confidentialClientInput())
	if err != nil {
		t.Fatalf("create: %v", err)
	}
	*seq = (*seq)[:0]
	newScopes := []string{"openid"}
	if _, err := svc.UpdateClient(ctx, "user_actor", res.ApplicationID, res.ClientID, "req-2", ClientPatch{AllowedScopes: &newScopes}); err != nil {
		t.Fatalf("update: %v", err)
	}
	for _, step := range *seq {
		if step == "provider:update" {
			t.Error("local-only fields must not trigger a provider sync")
		}
	}
}

func TestUpdateClient_ValidationErrorNoProviderCall(t *testing.T) {
	svc, store, _, _, seq := newTestService(t)
	ctx := context.Background()
	res, err := svc.CreateWithInitialClient(ctx, "user_actor", "req-1", confidentialAppInput(), confidentialClientInput())
	if err != nil {
		t.Fatalf("create: %v", err)
	}
	before := store.clients[res.ClientID]
	*seq = (*seq)[:0]

	badURIs := []string{"http://insecure.example.com/callback"}
	_, err = svc.UpdateClient(ctx, "user_actor", res.ApplicationID, res.ClientID, "req-2", ClientPatch{RedirectURIs: &badURIs})
	var verr *ValidationErrors
	if !errors.As(err, &verr) {
		t.Fatalf("err = %v, want ValidationErrors", err)
	}
	for _, step := range *seq {
		if step == "provider:update" || step == "store:update-client" {
			t.Errorf("validation failure must not touch provider or store: %v", *seq)
		}
	}
	if store.clients[res.ClientID].Version != before.Version {
		t.Error("local state changed despite validation failure")
	}
}

func TestUpdateClient_ProviderFailureLeavesLocalUnchanged(t *testing.T) {
	svc, store, prov, _, _ := newTestService(t)
	ctx := context.Background()
	res, err := svc.CreateWithInitialClient(ctx, "user_actor", "req-1", confidentialAppInput(), confidentialClientInput())
	if err != nil {
		t.Fatalf("create: %v", err)
	}
	before := store.clients[res.ClientID]
	prov.UpdateErr = ErrProviderUnavailable

	newName := "New Name"
	_, err = svc.UpdateClient(ctx, "user_actor", res.ApplicationID, res.ClientID, "req-2", ClientPatch{Name: &newName})
	if !errors.Is(err, ErrProviderUnavailable) {
		t.Fatalf("err = %v, want ErrProviderUnavailable", err)
	}
	if store.clients[res.ClientID].Name != before.Name || store.clients[res.ClientID].Version != before.Version {
		t.Error("local state must stay unchanged on provider failure")
	}
}

func TestUpdateClient_LocalFailureAfterProviderReconciles(t *testing.T) {
	svc, store, prov, events, _ := newTestService(t)
	ctx := context.Background()
	res, err := svc.CreateWithInitialClient(ctx, "user_actor", "req-1", confidentialAppInput(), confidentialClientInput())
	if err != nil {
		t.Fatalf("create: %v", err)
	}
	store.updateClientErr = errors.New("db down")

	newName := "New Name"
	_, err = svc.UpdateClient(ctx, "user_actor", res.ApplicationID, res.ClientID, "req-2", ClientPatch{Name: &newName})
	if err == nil {
		t.Fatal("expected local write error")
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
	if prov.ClientCount() != 1 {
		t.Error("provider resource must survive; drift is reconciled, not rolled back silently")
	}
}

func TestUpdateClient_VersionConflict(t *testing.T) {
	svc, store, _, _, _ := newTestService(t)
	ctx := context.Background()
	res, err := svc.CreateWithInitialClient(ctx, "user_actor", "req-1", confidentialAppInput(), confidentialClientInput())
	if err != nil {
		t.Fatalf("create: %v", err)
	}
	// Simulate a concurrent writer between the read and the conditional write.
	store.updateClientErr = ErrConflict

	newName := "New Name"
	_, err = svc.UpdateClient(ctx, "user_actor", res.ApplicationID, res.ClientID, "req-2", ClientPatch{Name: &newName})
	if !errors.Is(err, ErrConflict) {
		t.Fatalf("err = %v, want ErrConflict", err)
	}
	if store.clients[res.ClientID].Name == newName {
		t.Error("local state must not change on version conflict")
	}
}

// --- Client enable / disable ---

func TestSetClientStatus_DisableProviderFirst(t *testing.T) {
	svc, store, prov, events, seq := newTestService(t)
	ctx := context.Background()
	res, err := svc.CreateWithInitialClient(ctx, "user_actor", "req-1", confidentialAppInput(), confidentialClientInput())
	if err != nil {
		t.Fatalf("create: %v", err)
	}

	updated, err := svc.SetClientStatus(ctx, "user_actor", res.ApplicationID, res.ClientID, "req-2", false)
	if err != nil {
		t.Fatalf("disable: %v", err)
	}
	if updated.Status != StatusDisabled {
		t.Errorf("status = %s, want disabled", updated.Status)
	}
	fake := prov.Client(store.clients[res.ClientID].ProviderApplicationID)
	if fake == nil || !fake.Disabled {
		t.Error("provider client must be disabled")
	}
	var providerIdx, storeIdx = -1, -1
	for i, step := range *seq {
		if step == "provider:disable" && providerIdx == -1 {
			providerIdx = i
		}
		if step == "store:set-client-status" && storeIdx == -1 {
			storeIdx = i
		}
	}
	if providerIdx == -1 || storeIdx == -1 || providerIdx > storeIdx {
		t.Errorf("provider call must precede local update: %v", *seq)
	}
	found := false
	for _, ev := range events.events {
		if ev.EventType == EventOAuthClientDisabled && ev.Result == SecurityEventSuccess {
			found = true
		}
	}
	if !found {
		t.Error("expected oauth_client.disabled success event")
	}

	// Re-enable returns to active.
	if _, err := svc.SetClientStatus(ctx, "user_actor", res.ApplicationID, res.ClientID, "req-3", true); err != nil {
		t.Fatalf("enable: %v", err)
	}
	if store.clients[res.ClientID].Status != StatusActive {
		t.Error("client not re-enabled")
	}
}

func TestSetClientStatus_ProviderFailureLeavesLocalUnchanged(t *testing.T) {
	svc, store, prov, _, _ := newTestService(t)
	ctx := context.Background()
	res, err := svc.CreateWithInitialClient(ctx, "user_actor", "req-1", confidentialAppInput(), confidentialClientInput())
	if err != nil {
		t.Fatalf("create: %v", err)
	}
	prov.DisableErr = ErrProviderUnavailable

	_, err = svc.SetClientStatus(ctx, "user_actor", res.ApplicationID, res.ClientID, "req-2", false)
	if !errors.Is(err, ErrProviderUnavailable) {
		t.Fatalf("err = %v, want ErrProviderUnavailable", err)
	}
	if store.clients[res.ClientID].Status != StatusActive {
		t.Error("local status must stay unchanged on provider failure")
	}
}

func TestSetClientStatus_InvalidTransition(t *testing.T) {
	svc, _, _, _, _ := newTestService(t)
	ctx := context.Background()
	res, err := svc.CreateWithInitialClient(ctx, "user_actor", "req-1", confidentialAppInput(), confidentialClientInput())
	if err != nil {
		t.Fatalf("create: %v", err)
	}
	// Enabling an already-active client is rejected before any provider call.
	_, err = svc.SetClientStatus(ctx, "user_actor", res.ApplicationID, res.ClientID, "req-2", true)
	if !errors.Is(err, ErrInvalidStateTransition) {
		t.Fatalf("err = %v, want ErrInvalidStateTransition", err)
	}
}

func TestSetClientStatus_LocalFailureAfterProviderSwitchReconciles(t *testing.T) {
	svc, store, prov, events, _ := newTestService(t)
	ctx := context.Background()
	res, err := svc.CreateWithInitialClient(ctx, "user_actor", "req-1", confidentialAppInput(), confidentialClientInput())
	if err != nil {
		t.Fatalf("create: %v", err)
	}
	store.setClientStatusErr = errors.New("db down")

	_, err = svc.SetClientStatus(ctx, "user_actor", res.ApplicationID, res.ClientID, "req-2", false)
	if err == nil {
		t.Fatal("expected local commit failure")
	}
	// The provider already disabled the client; the drift must be recorded,
	// never silently leaked.
	fake := prov.Client(store.clients[res.ClientID].ProviderApplicationID)
	if fake == nil || !fake.Disabled {
		t.Error("provider client must already be disabled")
	}
	if store.clients[res.ClientID].Status != StatusActive {
		t.Error("local status must stay unchanged on local commit failure")
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

// --- Delete client (standalone) ---

func TestDeleteClient_RemovesProviderAndLocal(t *testing.T) {
	svc, store, prov, events, _ := newTestService(t)
	ctx := context.Background()
	res, err := svc.CreateWithInitialClient(ctx, "user_actor", "req-1", confidentialAppInput(), confidentialClientInput())
	if err != nil {
		t.Fatalf("create: %v", err)
	}
	if prov.ClientCount() != 1 {
		t.Fatalf("provider clients = %d, want 1", prov.ClientCount())
	}

	if err := svc.DeleteClient(ctx, "user_actor", res.ApplicationID, res.ClientID, "req-2"); err != nil {
		t.Fatalf("delete: %v", err)
	}
	if !store.deleted[res.ClientID] {
		t.Error("client not marked deleted")
	}
	if prov.ClientCount() != 0 {
		t.Errorf("provider clients = %d, want 0", prov.ClientCount())
	}
	// The parent application survives.
	if _, ok := store.apps[res.ApplicationID]; !ok {
		t.Error("application must survive client deletion")
	}
	found := false
	for _, ev := range events.events {
		if ev.EventType == EventOAuthClientDeleted && ev.Result == SecurityEventSuccess {
			found = true
		}
	}
	if !found {
		t.Error("expected oauth_client.deleted success event")
	}
}

func TestDeleteClient_ProviderFailureAbortsAndReconciles(t *testing.T) {
	svc, store, prov, events, _ := newTestService(t)
	ctx := context.Background()
	res, err := svc.CreateWithInitialClient(ctx, "user_actor", "req-1", confidentialAppInput(), confidentialClientInput())
	if err != nil {
		t.Fatalf("create: %v", err)
	}
	prov.DeleteErr = ErrProviderUnavailable

	err = svc.DeleteClient(ctx, "user_actor", res.ApplicationID, res.ClientID, "req-2")
	if !errors.Is(err, ErrProviderUnavailable) {
		t.Fatalf("err = %v, want ErrProviderUnavailable", err)
	}
	if store.deleted[res.ClientID] {
		t.Error("client must survive a failed provider deletion")
	}
	if store.clients[res.ClientID].Provisioning != ProvisioningStatusDeleteFailed {
		t.Errorf("provisioning = %s, want delete_failed", store.clients[res.ClientID].Provisioning)
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

	// Retry after failure goes through the delete-failed retry path.
	if err := svc.DeleteClient(ctx, "user_actor", res.ApplicationID, res.ClientID, "req-3"); err != nil {
		t.Fatalf("retry delete: %v", err)
	}
	if !store.deleted[res.ClientID] {
		t.Error("client not deleted after retry")
	}
}

func TestDeleteClient_NotFoundAndBinding(t *testing.T) {
	svc, _, _, _, _ := newTestService(t)
	ctx := context.Background()
	res, err := svc.CreateWithInitialClient(ctx, "user_actor", "req-1", confidentialAppInput(), confidentialClientInput())
	if err != nil {
		t.Fatalf("create: %v", err)
	}
	if err := svc.DeleteClient(ctx, "user_actor", res.ApplicationID, OAuthClientID("clt_missing"), "req-2"); !errors.Is(err, ErrNotFound) {
		t.Errorf("err = %v, want ErrNotFound", err)
	}
	// A client deleted under the wrong application is not found.
	if err := svc.DeleteClient(ctx, "user_actor", ApplicationID("app_other"), res.ClientID, "req-2"); !errors.Is(err, ErrNotFound) {
		t.Errorf("err = %v, want ErrNotFound", err)
	}
}

func TestDeleteClient_StuckDeletingIsRetryable(t *testing.T) {
	svc, store, prov, _, _ := newTestService(t)
	ctx := context.Background()
	res, err := svc.CreateWithInitialClient(ctx, "user_actor", "req-1", confidentialAppInput(), confidentialClientInput())
	if err != nil {
		t.Fatalf("create: %v", err)
	}
	// Simulate a crash after provider removal but before the local commit.
	c := store.clients[res.ClientID]
	c.Provisioning = ProvisioningStatusDeleting
	store.clients[res.ClientID] = c

	// The retry re-drives the idempotent provider removal and completes the
	// local soft delete instead of returning a permanent conflict.
	if err := svc.DeleteClient(ctx, "user_actor", res.ApplicationID, res.ClientID, "req-2"); err != nil {
		t.Fatalf("retry stuck deleting client: %v", err)
	}
	if !store.deleted[res.ClientID] {
		t.Error("client not deleted after retry")
	}
	if prov.ClientCount() != 0 {
		t.Errorf("provider clients = %d, want 0", prov.ClientCount())
	}
}

func TestDeleteClient_LocalCommitFailureBecomesRetryable(t *testing.T) {
	svc, store, prov, events, _ := newTestService(t)
	ctx := context.Background()
	res, err := svc.CreateWithInitialClient(ctx, "user_actor", "req-1", confidentialAppInput(), confidentialClientInput())
	if err != nil {
		t.Fatalf("create: %v", err)
	}
	store.completeDelErr = errors.New("db down")

	err = svc.DeleteClient(ctx, "user_actor", res.ApplicationID, res.ClientID, "req-2")
	if err == nil {
		t.Fatal("expected local commit failure")
	}
	// The provider resource is already gone; the client must be parked as
	// delete_failed (retryable) with a reconciliation trail, never stuck in
	// deleting.
	if store.deleted[res.ClientID] {
		t.Error("client must not be marked deleted after a failed commit")
	}
	if store.clients[res.ClientID].Provisioning != ProvisioningStatusDeleteFailed {
		t.Errorf("provisioning = %s, want delete_failed", store.clients[res.ClientID].Provisioning)
	}
	if len(store.jobs) != 1 || store.jobs[0].Reason != "provider_deleted_local_commit_failed" {
		t.Errorf("jobs = %+v, want one provider_deleted_local_commit_failed job", store.jobs)
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
	if prov.ClientCount() != 0 {
		t.Errorf("provider clients = %d, want 0 (already removed)", prov.ClientCount())
	}

	// Retry completes the local soft delete.
	store.completeDelErr = nil
	if err := svc.DeleteClient(ctx, "user_actor", res.ApplicationID, res.ClientID, "req-3"); err != nil {
		t.Fatalf("retry delete: %v", err)
	}
	if !store.deleted[res.ClientID] {
		t.Error("client not deleted after retry")
	}
}

// --- Durable success audit (same-transaction semantics, ADR-0004 §8) ---

func TestDurableAudit_AuditFailureAbortsSuccess(t *testing.T) {
	svc, _, _, events, _ := newTestService(t)
	ctx := context.Background()

	// While the audit store works, the success audits commit with the
	// terminal state and land in the event sink.
	res, err := svc.CreateWithInitialClient(ctx, "user_actor", "req-1", confidentialAppInput(), confidentialClientInput())
	if err != nil {
		t.Fatalf("create: %v", err)
	}
	var created int
	for _, ev := range events.events {
		if ev.EventType == EventApplicationCreated || ev.EventType == EventOAuthClientCreated {
			created++
		}
	}
	if created != 2 {
		t.Fatalf("durable create audits = %d, want 2", created)
	}

	// Once the audit store starts failing, high-risk success commits must
	// abort: an operation whose audit cannot be persisted is never reported
	// as fully successful.
	events.err = errors.New("audit store down")
	if _, err := svc.RotateClientSecret(ctx, "user_actor", res.ApplicationID, res.ClientID, "req-2"); err == nil {
		t.Fatal("rotation must fail when the durable success audit fails")
	}
	newName := "Renamed App"
	if _, err := svc.UpdateApplication(ctx, "user_actor", res.ApplicationID, "req-3", ApplicationPatch{Name: &newName}); err == nil {
		t.Fatal("application update must fail when the durable success audit fails")
	}
	if _, err := svc.SetClientStatus(ctx, "user_actor", res.ApplicationID, res.ClientID, "req-4", false); err == nil {
		t.Fatal("client disable must fail when the durable success audit fails")
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

// --- Secret rotation ---

func TestRotateClientSecret_Success(t *testing.T) {
	svc, store, _, events, _ := newTestService(t)
	ctx := context.Background()
	res, err := svc.CreateWithInitialClient(ctx, "user_actor", "req-1", confidentialAppInput(), confidentialClientInput())
	if err != nil {
		t.Fatalf("create: %v", err)
	}

	out, err := svc.RotateClientSecret(ctx, "user_actor", res.ApplicationID, res.ClientID, "req-2")
	if err != nil {
		t.Fatalf("rotate: %v", err)
	}
	if out.ClientSecret == "" || out.SecretID == "" {
		t.Fatal("rotation must return the one-time secret and its ID")
	}

	secrets, _ := store.GetClientSecretRecords(ctx, res.ClientID)
	if len(secrets) != 2 {
		t.Fatalf("secret records = %d, want 2", len(secrets))
	}
	var rotatedOld, activeNew int
	for _, rec := range secrets {
		if rec.LastRotatedAt != nil {
			rotatedOld++
		} else {
			activeNew++
		}
	}
	if rotatedOld != 1 || activeNew != 1 {
		t.Errorf("secret states wrong: %d rotated, %d active", rotatedOld, activeNew)
	}

	// The gate bump (begin) plus the atomic commit each advance the version.
	if store.clients[res.ClientID].Version != 3 {
		t.Errorf("client version = %d, want 3", store.clients[res.ClientID].Version)
	}
	if store.rotationStatus(res.ClientID) != "idle" {
		t.Errorf("rotation status = %q, want idle after success", store.rotationStatus(res.ClientID))
	}

	found := false
	for _, ev := range events.events {
		if ev.EventType == EventSecretRotated && ev.Result == SecurityEventSuccess {
			found = true
		}
	}
	if !found {
		t.Error("expected oauth_client.secret_rotated success event")
	}
}

func TestRotateClientSecret_PublicClientDenied(t *testing.T) {
	svc, _, prov, events, _ := newTestService(t)
	ctx := context.Background()
	in := confidentialClientInput()
	in.Profile = ClientProfileSPAMobile
	res, err := svc.CreateWithInitialClient(ctx, "user_actor", "req-1", confidentialAppInput(), in)
	if err != nil {
		t.Fatalf("create: %v", err)
	}

	if _, err := svc.RotateClientSecret(ctx, "user_actor", res.ApplicationID, res.ClientID, "req-2"); !errors.Is(err, ErrSecretRotationNotAllowed) {
		t.Fatalf("err = %v, want ErrSecretRotationNotAllowed", err)
	}
	for _, call := range prov.Calls {
		if call == "rotate" {
			t.Fatal("provider must never be called for a public client")
		}
	}
	denied := false
	for _, ev := range events.events {
		if ev.EventType == EventSecretRotationFailed && ev.Result == SecurityEventDenied {
			denied = true
		}
	}
	if !denied {
		t.Error("expected denied secret_rotation_failed event")
	}
}

func TestRotateClientSecret_DisabledClientDenied(t *testing.T) {
	svc, _, _, _, _ := newTestService(t)
	ctx := context.Background()
	res, err := svc.CreateWithInitialClient(ctx, "user_actor", "req-1", confidentialAppInput(), confidentialClientInput())
	if err != nil {
		t.Fatalf("create: %v", err)
	}
	if _, err := svc.SetClientStatus(ctx, "user_actor", res.ApplicationID, res.ClientID, "req-2", false); err != nil {
		t.Fatalf("disable: %v", err)
	}
	if _, err := svc.RotateClientSecret(ctx, "user_actor", res.ApplicationID, res.ClientID, "req-3"); !errors.Is(err, ErrSecretRotationNotAllowed) {
		t.Fatalf("err = %v, want ErrSecretRotationNotAllowed", err)
	}
}

func TestRotateClientSecret_GateConflict(t *testing.T) {
	svc, store, _, _, _ := newTestService(t)
	ctx := context.Background()
	res, err := svc.CreateWithInitialClient(ctx, "user_actor", "req-1", confidentialAppInput(), confidentialClientInput())
	if err != nil {
		t.Fatalf("create: %v", err)
	}
	// Another rotation wins the single-winner gate between the read and the
	// provider call.
	store.beginRotationErr = ErrConflict

	if _, err := svc.RotateClientSecret(ctx, "user_actor", res.ApplicationID, res.ClientID, "req-2"); !errors.Is(err, ErrConflict) {
		t.Fatalf("err = %v, want ErrConflict", err)
	}
}

func TestRotateClientSecret_ProviderFailureKeepsOldSecret(t *testing.T) {
	svc, store, prov, events, _ := newTestService(t)
	ctx := context.Background()
	res, err := svc.CreateWithInitialClient(ctx, "user_actor", "req-1", confidentialAppInput(), confidentialClientInput())
	if err != nil {
		t.Fatalf("create: %v", err)
	}
	prov.RotateErr = ErrProviderUnavailable

	if _, err := svc.RotateClientSecret(ctx, "user_actor", res.ApplicationID, res.ClientID, "req-2"); !errors.Is(err, ErrProviderUnavailable) {
		t.Fatalf("err = %v, want ErrProviderUnavailable", err)
	}
	secrets, _ := store.GetClientSecretRecords(ctx, res.ClientID)
	if len(secrets) != 1 || secrets[0].LastRotatedAt != nil {
		t.Error("a failed rotation must never touch the existing secret")
	}
	// A confirmed provider failure aborts the gate back to idle.
	if store.rotationStatus(res.ClientID) != "idle" {
		t.Errorf("rotation status = %q, want idle after confirmed failure", store.rotationStatus(res.ClientID))
	}
	failed := false
	for _, ev := range events.events {
		if ev.EventType == EventSecretRotationFailed && ev.Result == SecurityEventDenied && ev.FailureClass == "provider_unavailable" {
			failed = true
		}
	}
	if !failed {
		t.Error("expected provider_unavailable rotation failure event")
	}
}

func TestRotateClientSecret_ProviderOutcomeUnknownParksAndBlocksRetry(t *testing.T) {
	svc, store, prov, events, _ := newTestService(t)
	ctx := context.Background()
	res, err := svc.CreateWithInitialClient(ctx, "user_actor", "req-1", confidentialAppInput(), confidentialClientInput())
	if err != nil {
		t.Fatalf("create: %v", err)
	}
	// Simulate an ambiguous provider outcome: the call may already have
	// rotated and revoked the old secret.
	prov.RotateErr = fmt.Errorf("%w: rotate_client_secret", ErrProviderOutcomeUnknown)

	if _, err := svc.RotateClientSecret(ctx, "user_actor", res.ApplicationID, res.ClientID, "req-2"); !errors.Is(err, ErrSecretRotationOutcomeUnknown) {
		t.Fatalf("err = %v, want ErrSecretRotationOutcomeUnknown", err)
	}
	// The client is parked in outcome_unknown with a reconciliation trail.
	if store.rotationStatus(res.ClientID) != "outcome_unknown" {
		t.Fatalf("rotation status = %q, want outcome_unknown", store.rotationStatus(res.ClientID))
	}
	if len(store.jobs) != 1 {
		t.Fatalf("reconciliation jobs = %d, want 1", len(store.jobs))
	}
	secrets, _ := store.GetClientSecretRecords(ctx, res.ClientID)
	if len(secrets) != 1 || secrets[0].LastRotatedAt != nil {
		t.Error("an unknown outcome must never touch the existing secret record")
	}

	// A retry must be refused at the gate and must not reach the provider
	// again (RotateErr is consumed once by the fake provisioner).
	if _, err := svc.RotateClientSecret(ctx, "user_actor", res.ApplicationID, res.ClientID, "req-3"); !errors.Is(err, ErrConflict) {
		t.Fatalf("retry err = %v, want ErrConflict", err)
	}
	rotateCalls := 0
	for _, call := range prov.Calls {
		if call == "rotate" {
			rotateCalls++
		}
	}
	if rotateCalls != 1 {
		t.Fatalf("provider rotate calls = %d, want exactly 1", rotateCalls)
	}

	denied := false
	for _, ev := range events.events {
		if ev.EventType == EventSecretRotationFailed && ev.FailureClass == "provider_outcome_unknown" {
			denied = true
		}
	}
	if !denied {
		t.Error("expected provider_outcome_unknown rotation failure event")
	}
}

func TestRotateClientSecret_ConfirmedFailureAllowsRetry(t *testing.T) {
	svc, store, prov, _, _ := newTestService(t)
	ctx := context.Background()
	res, err := svc.CreateWithInitialClient(ctx, "user_actor", "req-1", confidentialAppInput(), confidentialClientInput())
	if err != nil {
		t.Fatalf("create: %v", err)
	}
	prov.RotateErr = ErrProviderUnavailable

	if _, err := svc.RotateClientSecret(ctx, "user_actor", res.ApplicationID, res.ClientID, "req-2"); !errors.Is(err, ErrProviderUnavailable) {
		t.Fatalf("first err = %v, want ErrProviderUnavailable", err)
	}
	// The gate was aborted to idle, so a retry is allowed and succeeds.
	out, err := svc.RotateClientSecret(ctx, "user_actor", res.ApplicationID, res.ClientID, "req-3")
	if err != nil {
		t.Fatalf("retry: %v", err)
	}
	if out.ClientSecret == "" {
		t.Fatal("retry rotation must return the one-time secret")
	}
	if store.rotationStatus(res.ClientID) != "idle" {
		t.Errorf("rotation status = %q, want idle", store.rotationStatus(res.ClientID))
	}
}

func TestRotateClientSecret_LocalFailureAfterProviderReconciles(t *testing.T) {
	svc, store, _, events, _ := newTestService(t)
	ctx := context.Background()
	res, err := svc.CreateWithInitialClient(ctx, "user_actor", "req-1", confidentialAppInput(), confidentialClientInput())
	if err != nil {
		t.Fatalf("create: %v", err)
	}
	store.completeRotationErr = errors.New("db down")

	if _, err := svc.RotateClientSecret(ctx, "user_actor", res.ApplicationID, res.ClientID, "req-2"); err == nil {
		t.Fatal("rotation must surface the local failure")
	}
	// The provider already rotated; the unconfirmed local commit must park
	// the client in outcome_unknown, never release the gate.
	if store.rotationStatus(res.ClientID) != "outcome_unknown" {
		t.Errorf("rotation status = %q, want outcome_unknown", store.rotationStatus(res.ClientID))
	}
	if len(store.jobs) != 1 {
		t.Fatalf("reconciliation jobs = %d, want 1", len(store.jobs))
	}
	reconciled := false
	for _, ev := range events.events {
		if ev.EventType == EventProviderReconciliationNeed {
			reconciled = true
		}
	}
	if !reconciled {
		t.Error("expected reconciliation event")
	}
}

// --- Provider identity (globally unique display name + recovery) ---

func TestProviderDisplayName_GloballyUnique(t *testing.T) {
	got := ProviderDisplayName("App A", "Web Client", OAuthClientID("clt_0123456789abcdef0123456789abcdef"))
	want := "App A · Web Client · 89abcdef"
	if got != want {
		t.Fatalf("got %q, want %q", got, want)
	}
	// Short IDs fall back to the full value.
	if got := ProviderDisplayName("A", "B", "clt_x"); got != "A · B · clt_x" {
		t.Fatalf("short id: got %q", got)
	}
}

func TestCreate_ProviderDisplayNameIsGloballyUnique(t *testing.T) {
	svc, _, prov, _, _ := newTestService(t)
	ctx := context.Background()

	// Two applications with an identically named client must never collide
	// in the shared provider project: the provider display name embeds the
	// application name and the globally unique client ID suffix.
	res1, err := svc.CreateWithInitialClient(ctx, "user_actor", "req-1", confidentialAppInput(), confidentialClientInput())
	if err != nil {
		t.Fatalf("create first: %v", err)
	}
	app2In := confidentialAppInput()
	app2In.Name = "Second App"
	res2, err := svc.CreateWithInitialClient(ctx, "user_actor", "req-2", app2In, confidentialClientInput())
	if err != nil {
		t.Fatalf("create second: %v", err)
	}

	c1, err := svc.GetClient(ctx, res1.ApplicationID, res1.ClientID)
	if err != nil {
		t.Fatalf("get client 1: %v", err)
	}
	c2, err := svc.GetClient(ctx, res2.ApplicationID, res2.ClientID)
	if err != nil {
		t.Fatalf("get client 2: %v", err)
	}
	fake1 := prov.Client(c1.ProviderApplicationID)
	fake2 := prov.Client(c2.ProviderApplicationID)
	if fake1 == nil || fake2 == nil {
		t.Fatal("expected both provider clients")
	}
	want1 := ProviderDisplayName("Test App", "Test Client", res1.ClientID)
	want2 := ProviderDisplayName("Second App", "Test Client", res2.ClientID)
	if fake1.DisplayName != want1 || fake2.DisplayName != want2 {
		t.Errorf("display names = %q / %q, want %q / %q", fake1.DisplayName, fake2.DisplayName, want1, want2)
	}
	if fake1.DisplayName == fake2.DisplayName {
		t.Error("same client name in different applications must not collide at the provider")
	}
	if fake1.Spec.LocalClientID != res1.ClientID || fake2.Spec.LocalClientID != res2.ClientID {
		t.Error("spec must carry the local client ID for recovery")
	}
}

func TestCreate_AmbiguousProvisionLeavesReconciliation(t *testing.T) {
	svc, store, prov, events, _ := newTestService(t)
	ctx := context.Background()
	// An ambiguous provider outcome: the app may exist even though no
	// response arrived.
	prov.ProvisionErr = fmt.Errorf("%w: provision_client", ErrProviderOutcomeUnknown)

	if _, err := svc.CreateWithInitialClient(ctx, "user_actor", "req-1", confidentialAppInput(), confidentialClientInput()); !errors.Is(err, ErrProviderUnavailable) {
		t.Fatalf("err = %v, want ErrProviderUnavailable", err)
	}
	if len(store.jobs) != 1 {
		t.Fatalf("reconciliation jobs = %d, want 1", len(store.jobs))
	}
	if store.jobs[0].Reason != "provider_outcome_unknown" {
		t.Errorf("job reason = %q", store.jobs[0].Reason)
	}
	found := false
	for _, ev := range events.events {
		if ev.EventType == EventProviderReconciliationNeed && ev.FailureClass == "provider_outcome_unknown" {
			found = true
		}
	}
	if !found {
		t.Error("expected provider_outcome_unknown reconciliation event")
	}
}

// --- Parent application lifecycle (parent/child status matrix) ---

func TestEffectiveClientActive_Matrix(t *testing.T) {
	cases := []struct {
		app, client Status
		want        bool
	}{
		{StatusActive, StatusActive, true},
		{StatusActive, StatusDisabled, false},
		{StatusDisabled, StatusActive, false},
		{StatusDisabled, StatusDisabled, false},
	}
	for _, tc := range cases {
		if got := EffectiveClientActive(tc.app, tc.client); got != tc.want {
			t.Errorf("EffectiveClientActive(%s, %s) = %v, want %v", tc.app, tc.client, got, tc.want)
		}
	}
}

func TestParentLifecycle_DisabledAppBlocksClientMutations(t *testing.T) {
	svc, store, prov, events, seq := newTestService(t)
	ctx := context.Background()
	res, err := svc.CreateWithInitialClient(ctx, "user_actor", "req-1", confidentialAppInput(), confidentialClientInput())
	if err != nil {
		t.Fatalf("create: %v", err)
	}
	if err := svc.SetStatus(ctx, "user_actor", res.ApplicationID, "req-2", false); err != nil {
		t.Fatalf("disable app: %v", err)
	}
	provAppID := store.clients[res.ClientID].ProviderApplicationID
	before := len(*seq)

	// Create client: blocked before any provider call.
	if _, err := svc.CreateClient(ctx, "user_actor", res.ApplicationID, "req-3", confidentialClientInput()); !errors.Is(err, ErrParentApplicationDisabled) {
		t.Fatalf("create client err = %v, want ErrParentApplicationDisabled", err)
	}

	// Enable client: blocked; the provider client must stay disabled.
	if _, err := svc.SetClientStatus(ctx, "user_actor", res.ApplicationID, res.ClientID, "req-4", true); !errors.Is(err, ErrParentApplicationDisabled) {
		t.Fatalf("enable client err = %v, want ErrParentApplicationDisabled", err)
	}
	if fake := prov.Client(provAppID); fake == nil || !fake.Disabled {
		t.Error("provider client must stay disabled while the application is disabled")
	}

	// Protocol-config update: blocked.
	newName := "Renamed Client"
	if _, err := svc.UpdateClient(ctx, "user_actor", res.ApplicationID, res.ClientID, "req-5", ClientPatch{Name: &newName}); !errors.Is(err, ErrParentApplicationDisabled) {
		t.Fatalf("update client err = %v, want ErrParentApplicationDisabled", err)
	}

	// Secret rotation: blocked with a denied audit event.
	if _, err := svc.RotateClientSecret(ctx, "user_actor", res.ApplicationID, res.ClientID, "req-6"); !errors.Is(err, ErrParentApplicationDisabled) {
		t.Fatalf("rotate err = %v, want ErrParentApplicationDisabled", err)
	}
	denied := false
	for _, ev := range events.events {
		if ev.EventType == EventSecretRotationFailed && ev.Result == SecurityEventDenied && ev.FailureClass == "state_conflict" {
			denied = true
		}
	}
	if !denied {
		t.Error("expected denied rotation event for disabled parent application")
	}

	// None of the blocked mutations may have reached the provider.
	for _, step := range (*seq)[before:] {
		if step == "provider:provision" || step == "provider:enable" || step == "provider:update" || step == "provider:rotate" {
			t.Fatalf("blocked mutation reached the provider: %s", step)
		}
	}
}

func TestParentLifecycle_DisableAndDeleteStillAllowedOnDisabledApp(t *testing.T) {
	svc, _, _, _, _ := newTestService(t)
	ctx := context.Background()
	res, err := svc.CreateWithInitialClient(ctx, "user_actor", "req-1", confidentialAppInput(), confidentialClientInput())
	if err != nil {
		t.Fatalf("create: %v", err)
	}
	if err := svc.SetStatus(ctx, "user_actor", res.ApplicationID, "req-2", false); err != nil {
		t.Fatalf("disable app: %v", err)
	}

	// Disabling an individually active client only tightens state.
	if _, err := svc.SetClientStatus(ctx, "user_actor", res.ApplicationID, res.ClientID, "req-3", false); err != nil {
		t.Fatalf("disable client on disabled app: %v", err)
	}
	// Deletion remains possible so resources can be cleaned up.
	if err := svc.DeleteClient(ctx, "user_actor", res.ApplicationID, res.ClientID, "req-4"); err != nil {
		t.Fatalf("delete client on disabled app: %v", err)
	}
}

func TestParentLifecycle_EnableClientAfterAppReenabled(t *testing.T) {
	svc, store, prov, _, _ := newTestService(t)
	ctx := context.Background()
	res, err := svc.CreateWithInitialClient(ctx, "user_actor", "req-1", confidentialAppInput(), confidentialClientInput())
	if err != nil {
		t.Fatalf("create: %v", err)
	}
	if err := svc.SetStatus(ctx, "user_actor", res.ApplicationID, "req-2", false); err != nil {
		t.Fatalf("disable app: %v", err)
	}
	if err := svc.SetStatus(ctx, "user_actor", res.ApplicationID, "req-3", true); err != nil {
		t.Fatalf("enable app: %v", err)
	}
	if _, err := svc.SetClientStatus(ctx, "user_actor", res.ApplicationID, res.ClientID, "req-4", false); err != nil {
		t.Fatalf("disable client: %v", err)
	}

	updated, err := svc.SetClientStatus(ctx, "user_actor", res.ApplicationID, res.ClientID, "req-5", true)
	if err != nil {
		t.Fatalf("enable client after app re-enabled: %v", err)
	}
	if updated.Status != StatusActive {
		t.Errorf("client status = %s, want active", updated.Status)
	}
	fake := prov.Client(store.clients[res.ClientID].ProviderApplicationID)
	if fake == nil || fake.Disabled {
		t.Error("provider client must be re-enabled")
	}
}
