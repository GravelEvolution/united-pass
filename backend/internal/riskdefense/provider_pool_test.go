package riskdefense

import (
	"context"
	"errors"
	"testing"
)

type managedProviderStub struct {
	name                string
	mainland, global    bool
	beginErr, verifyErr error
	beginID             string
	verifiedID          string
}

func (s *managedProviderStub) Name() string { return s.name }
func (s *managedProviderStub) Available(_ context.Context, region ProviderRegion) bool {
	return region == ProviderRegionMainlandChina && s.mainland || region == ProviderRegionGlobal && s.global
}
func (s *managedProviderStub) Begin(context.Context, Operation) (ProviderChallenge, error) {
	return ProviderChallenge{ID: s.beginID, PublicPayload: []byte(`{"siteKey":"public"}`)}, s.beginErr
}
func (s *managedProviderStub) Verify(_ context.Context, id, _ string) error {
	s.verifiedID = id
	return s.verifyErr
}

func TestProviderPoolSelectsOnlyHealthyRegionalProvidersAndRotates(t *testing.T) {
	aliyun := &managedProviderStub{name: "aliyun_captcha2", mainland: true, global: true, beginID: "aliyun-id"}
	turnstile := &managedProviderStub{name: "cloudflare_turnstile", mainland: false, global: true, beginID: "turnstile-id"}
	pool, err := NewInteractiveProviderPool(ProviderRegionMainlandChina, turnstile, aliyun)
	if err != nil {
		t.Fatalf("NewInteractiveProviderPool: %v", err)
	}
	for range 2 {
		challenge, err := pool.Begin(t.Context(), OperationRegistration)
		if err != nil || challenge.Provider != "aliyun_captcha2" {
			t.Fatalf("challenge=%#v err=%v", challenge, err)
		}
		if err := pool.Verify(t.Context(), challenge.ID, "opaque-proof"); err != nil || aliyun.verifiedID != "aliyun-id" {
			t.Fatalf("Verify err=%v id=%q", err, aliyun.verifiedID)
		}
	}
}

func TestProviderPoolFallsThroughBeginFailureButNeverLetsClientSwitchVerifier(t *testing.T) {
	first := &managedProviderStub{name: "first", global: true, beginErr: ErrUnavailable}
	second := &managedProviderStub{name: "second", global: true, beginID: "second-id"}
	pool, err := NewInteractiveProviderPool(ProviderRegionGlobal, first, second)
	if err != nil {
		t.Fatalf("NewInteractiveProviderPool: %v", err)
	}
	challenge, err := pool.Begin(t.Context(), OperationLogin)
	if err != nil || challenge.Provider != "second" {
		t.Fatalf("challenge=%#v err=%v", challenge, err)
	}
	if err := pool.Verify(t.Context(), challenge.ID, "proof"); err != nil || second.verifiedID != "second-id" || first.verifiedID != "" {
		t.Fatalf("verify err=%v first=%q second=%q", err, first.verifiedID, second.verifiedID)
	}
	if err := pool.Verify(t.Context(), "client-selected-provider", "proof"); !errors.Is(err, ErrInvalidProof) {
		t.Fatalf("client-selected provider accepted: %v", err)
	}
}

func TestProviderPoolFailsClosedWhenConfiguredSetIsUnavailable(t *testing.T) {
	pool, err := NewInteractiveProviderPool(ProviderRegionMainlandChina,
		&managedProviderStub{name: "cloudflare_turnstile", global: true, beginID: "id"},
		&managedProviderStub{name: "google_recaptcha", global: true, beginID: "id"},
	)
	if err != nil {
		t.Fatalf("NewInteractiveProviderPool: %v", err)
	}
	if _, err := pool.Begin(t.Context(), OperationRegistration); !errors.Is(err, ErrUnavailable) {
		t.Fatalf("Begin error=%v, want ErrUnavailable", err)
	}
}
