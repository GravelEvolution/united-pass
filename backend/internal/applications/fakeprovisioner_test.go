//
// Copyright (c) 2026 Chen Jiajie(Ariakage)
//
// Author: Chen Jiajie(Ariakage) <ariakage233@gmail.com>
// Date: 2026-08-06
// Description: Unit tests for the fake provider provisioner
//

package applications

import (
	"context"
	"errors"
	"testing"
)

func fakeWebSpec() ClientProvisionSpec {
	return ClientProvisionSpec{
		DisplayName:  "Fake Web Client",
		Profile:      ClientProfileWebServer,
		RedirectURIs: []string{"https://app.example.com/callback"},
	}
}

func TestFakeProvisioner_IdempotentRetry(t *testing.T) {
	f := NewFakeProvisioner()
	ctx := context.Background()

	first, err := f.ProvisionClient(ctx, "idem-1", fakeWebSpec())
	if err != nil {
		t.Fatalf("provision: %v", err)
	}
	second, err := f.ProvisionClient(ctx, "idem-1", fakeWebSpec())
	if err != nil {
		t.Fatalf("retry: %v", err)
	}
	if first != second {
		t.Errorf("retry must reuse the original result: %+v vs %+v", first, second)
	}
	if f.ClientCount() != 1 {
		t.Errorf("clients: got %d, want 1", f.ClientCount())
	}
}

func TestFakeProvisioner_DuplicateRejected(t *testing.T) {
	f := NewFakeProvisioner()
	f.DuplicateNextProvision = true

	_, err := f.ProvisionClient(context.Background(), "idem-dup", fakeWebSpec())
	if !errors.Is(err, ErrProviderConflict) {
		t.Fatalf("got %v, want ErrProviderConflict", err)
	}
}

func TestFakeProvisioner_InjectedFailures(t *testing.T) {
	f := NewFakeProvisioner()
	ctx := context.Background()
	f.ProvisionErr = ErrProviderUnavailable

	if _, err := f.ProvisionClient(ctx, "idem-f", fakeWebSpec()); !errors.Is(err, ErrProviderUnavailable) {
		t.Fatalf("got %v, want ErrProviderUnavailable", err)
	}
	// The injected failure is consumed once; the next call succeeds.
	res, err := f.ProvisionClient(ctx, "idem-f2", fakeWebSpec())
	if err != nil {
		t.Fatalf("provision after consumed failure: %v", err)
	}

	f.DeleteErr = ErrProviderUnavailable
	if err := f.DeleteClient(ctx, res.ProviderApplicationID); !errors.Is(err, ErrProviderUnavailable) {
		t.Fatalf("delete failure: got %v", err)
	}
	// Provider state survives a failed delete (reconciliation scenario).
	if f.ClientCount() != 1 {
		t.Errorf("client must survive failed delete, count=%d", f.ClientCount())
	}
	if err := f.DeleteClient(ctx, res.ProviderApplicationID); err != nil {
		t.Fatalf("delete retry: %v", err)
	}
	if f.ClientCount() != 0 {
		t.Errorf("clients after delete: %d", f.ClientCount())
	}
	// Idempotent delete.
	if err := f.DeleteClient(ctx, res.ProviderApplicationID); err != nil {
		t.Fatalf("idempotent delete: %v", err)
	}
}

func TestFakeProvisioner_PublicClientHasNoSecret(t *testing.T) {
	f := NewFakeProvisioner()
	res, err := f.ProvisionClient(context.Background(), "idem-pub", ClientProvisionSpec{
		DisplayName:  "Fake SPA",
		Profile:      ClientProfileSPAMobile,
		RedirectURIs: []string{"http://127.0.0.1:3000/cb"},
	})
	if err != nil {
		t.Fatalf("provision: %v", err)
	}
	if res.ClientSecret != "" {
		t.Errorf("public client must not get a secret, got %q", res.ClientSecret)
	}
}

func TestFakeProvisioner_SecretRotationInvalidatesPrevious(t *testing.T) {
	f := NewFakeProvisioner()
	ctx := context.Background()
	res, err := f.ProvisionClient(ctx, "idem-rot", fakeWebSpec())
	if err != nil {
		t.Fatalf("provision: %v", err)
	}
	before := f.Client(res.ProviderApplicationID).Secret

	rot, err := f.RotateClientSecret(ctx, res.ProviderApplicationID)
	if err != nil {
		t.Fatalf("rotate: %v", err)
	}
	if rot.NewSecret == "" || rot.NewSecret == before {
		t.Errorf("rotation must yield a fresh secret (before=%q after=%q)", before, rot.NewSecret)
	}
	if f.Client(res.ProviderApplicationID).Secret != rot.NewSecret {
		t.Error("stored secret must equal the rotated secret")
	}

	// Rotation of an unknown client is a provider conflict.
	if _, err := f.RotateClientSecret(ctx, "nope"); !errors.Is(err, ErrProviderConflict) {
		t.Fatalf("rotate unknown: got %v, want ErrProviderConflict", err)
	}
}

func TestFakeProvisioner_EnableDisable(t *testing.T) {
	f := NewFakeProvisioner()
	ctx := context.Background()
	res, err := f.ProvisionClient(ctx, "idem-state", fakeWebSpec())
	if err != nil {
		t.Fatalf("provision: %v", err)
	}
	if err := f.DisableClient(ctx, res.ProviderApplicationID); err != nil {
		t.Fatalf("disable: %v", err)
	}
	if !f.Client(res.ProviderApplicationID).Disabled {
		t.Error("client must be disabled")
	}
	if err := f.EnableClient(ctx, res.ProviderApplicationID); err != nil {
		t.Fatalf("enable: %v", err)
	}
	if f.Client(res.ProviderApplicationID).Disabled {
		t.Error("client must be enabled")
	}
}
