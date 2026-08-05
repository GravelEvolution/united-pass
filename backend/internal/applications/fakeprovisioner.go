package applications

import (
	"context"
	"fmt"
	"sync"
)

// FakeProvisionedClient is one client record held by the FakeProvisioner.
type FakeProvisionedClient struct {
	ProviderApplicationID string
	ProviderClientID      string
	DisplayName           string
	Secret                string
	SecretVersion         int
	Disabled              bool
	Spec                  ClientProvisionSpec
}

// FakeProvisioner is an in-memory OAuthClientProvisioner for unit and HTTP
// tests. It is never wired in production builds: bootstrap only selects it
// when the configured provider is the fake (ADR-0004 §10).
//
// It models the provider behaviors the use cases must survive:
//   - idempotent retries (same idempotency key returns the same result);
//   - duplicate creation attempts (ErrProviderConflict);
//   - arbitrary injected failures per operation;
//   - delete failure leaving provider state behind (reconciliation);
//   - secret rotation invalidating the previous secret immediately.
type FakeProvisioner struct {
	mu      sync.Mutex
	counter int

	// Clients keyed by provider application ID.
	clients map[string]*FakeProvisionedClient
	// Idempotent results keyed by idempotency key.
	byKey map[string]ClientProvisionResult

	// Injected failures. A non-nil value is returned (and consumed) by the
	// matching operation.
	ProvisionErr error
	UpdateErr    error
	EnableErr    error
	DisableErr   error
	DeleteErr    error
	RotateErr    error

	// DuplicateNextProvision makes the next ProvisionClient report a
	// provider-side duplicate.
	DuplicateNextProvision bool

	// Calls records operation names in invocation order for assertions.
	Calls []string
}

// NewFakeProvisioner builds an empty fake.
func NewFakeProvisioner() *FakeProvisioner {
	return &FakeProvisioner{
		clients: make(map[string]*FakeProvisionedClient),
		byKey:   make(map[string]ClientProvisionResult),
	}
}

var _ OAuthClientProvisioner = (*FakeProvisioner)(nil)

// ProvisionClient creates a fake provider client. Retries with the same
// idempotency key return the original result without creating a duplicate.
func (f *FakeProvisioner) ProvisionClient(ctx context.Context, idempotencyKey string, spec ClientProvisionSpec) (ClientProvisionResult, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.Calls = append(f.Calls, "provision")

	if prev, ok := f.byKey[idempotencyKey]; ok && idempotencyKey != "" {
		return prev, nil
	}
	if f.ProvisionErr != nil {
		err := f.ProvisionErr
		f.ProvisionErr = nil
		return ClientProvisionResult{}, err
	}
	if f.DuplicateNextProvision {
		f.DuplicateNextProvision = false
		return ClientProvisionResult{}, fmt.Errorf("%w: fake duplicate", ErrProviderConflict)
	}

	f.counter++
	rules, ok := spec.Profile.Rules()
	if !ok {
		return ClientProvisionResult{}, fmt.Errorf("%w: unknown profile", ErrProviderConflict)
	}
	if rules.RedirectURIRequired && len(spec.RedirectURIs) == 0 {
		return ClientProvisionResult{}, fmt.Errorf("%w: profile requires redirect uris", ErrProviderConflict)
	}

	provAppID := fmt.Sprintf("fake-app-%d", f.counter)
	provClientID := fmt.Sprintf("fake-client-%d", f.counter)
	secret := ""
	if rules.SupportsSecret {
		secret = fmt.Sprintf("fake-secret-%d", f.counter)
	}
	f.clients[provAppID] = &FakeProvisionedClient{
		ProviderApplicationID: provAppID,
		ProviderClientID:      provClientID,
		DisplayName:           spec.DisplayName,
		Secret:                secret,
		SecretVersion:         1,
		Spec:                  spec,
	}
	result := ClientProvisionResult{
		ProviderApplicationID: provAppID,
		ProviderClientID:      provClientID,
		ClientSecret:          secret,
	}
	if idempotencyKey != "" {
		f.byKey[idempotencyKey] = result
	}
	return result, nil
}

// UpdateClient applies the mutable settings to the stored fake client.
func (f *FakeProvisioner) UpdateClient(ctx context.Context, providerApplicationID string, spec ClientUpdateSpec) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.Calls = append(f.Calls, "update")

	if f.UpdateErr != nil {
		err := f.UpdateErr
		f.UpdateErr = nil
		return err
	}
	client, ok := f.clients[providerApplicationID]
	if !ok {
		return fmt.Errorf("%w: fake app not found", ErrProviderConflict)
	}
	if spec.DisplayName != "" {
		client.DisplayName = spec.DisplayName
	}
	client.Spec.RedirectURIs = spec.RedirectURIs
	client.Spec.LogoutURI = spec.LogoutURI
	return nil
}

// EnableClient reactivates the fake client (idempotent).
func (f *FakeProvisioner) EnableClient(ctx context.Context, providerApplicationID string) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.Calls = append(f.Calls, "enable")

	if f.EnableErr != nil {
		err := f.EnableErr
		f.EnableErr = nil
		return err
	}
	client, ok := f.clients[providerApplicationID]
	if !ok {
		return fmt.Errorf("%w: fake app not found", ErrProviderConflict)
	}
	client.Disabled = false
	return nil
}

// DisableClient deactivates the fake client (idempotent).
func (f *FakeProvisioner) DisableClient(ctx context.Context, providerApplicationID string) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.Calls = append(f.Calls, "disable")

	if f.DisableErr != nil {
		err := f.DisableErr
		f.DisableErr = nil
		return err
	}
	client, ok := f.clients[providerApplicationID]
	if !ok {
		return fmt.Errorf("%w: fake app not found", ErrProviderConflict)
	}
	client.Disabled = true
	return nil
}

// DeleteClient removes the fake client. An already-removed client counts as
// success (idempotent delete), mirroring the real adapter contract.
func (f *FakeProvisioner) DeleteClient(ctx context.Context, providerApplicationID string) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.Calls = append(f.Calls, "delete")

	if f.DeleteErr != nil {
		err := f.DeleteErr
		f.DeleteErr = nil
		return err
	}
	delete(f.clients, providerApplicationID)
	return nil
}

// RotateClientSecret regenerates the fake secret, invalidating the previous
// one immediately.
func (f *FakeProvisioner) RotateClientSecret(ctx context.Context, providerApplicationID string) (ClientSecretRotation, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.Calls = append(f.Calls, "rotate")

	if f.RotateErr != nil {
		err := f.RotateErr
		f.RotateErr = nil
		return ClientSecretRotation{}, err
	}
	client, ok := f.clients[providerApplicationID]
	if !ok {
		return ClientSecretRotation{}, fmt.Errorf("%w: fake app not found", ErrProviderConflict)
	}
	client.SecretVersion++
	client.Secret = fmt.Sprintf("fake-secret-%s-v%d", providerApplicationID, client.SecretVersion)
	return ClientSecretRotation{NewSecret: client.Secret}, nil
}

// --- test inspection helpers ---

// Client returns the stored fake client (nil when unknown).
func (f *FakeProvisioner) Client(providerApplicationID string) *FakeProvisionedClient {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.clients[providerApplicationID]
}

// ClientCount returns the number of live fake clients.
func (f *FakeProvisioner) ClientCount() int {
	f.mu.Lock()
	defer f.mu.Unlock()
	return len(f.clients)
}
