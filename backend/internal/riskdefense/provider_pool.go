package riskdefense

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"strings"
	"sync/atomic"
)

type ProviderRegion string

const (
	ProviderRegionMainlandChina ProviderRegion = "mainland_china"
	ProviderRegionGlobal        ProviderRegion = "global"
)

// ManagedInteractiveProvider is a configured server-side verifier. The
// provider name and challenge ID are selected and retained by the server;
// browser input never selects a provider or verification endpoint.
type ManagedInteractiveProvider interface {
	Name() string
	Available(context.Context, ProviderRegion) bool
	Begin(context.Context, Operation) (ProviderChallenge, error)
	Verify(context.Context, string, string) error
}

type InteractiveProviderPool struct {
	region    ProviderRegion
	providers []ManagedInteractiveProvider
	next      atomic.Uint64
}

func NewInteractiveProviderPool(region ProviderRegion, providers ...ManagedInteractiveProvider) (*InteractiveProviderPool, error) {
	if region != ProviderRegionMainlandChina && region != ProviderRegionGlobal {
		return nil, ErrUnavailable
	}
	filtered := make([]ManagedInteractiveProvider, 0, len(providers))
	seen := make(map[string]struct{}, len(providers))
	for _, provider := range providers {
		if provider == nil {
			continue
		}
		name := strings.TrimSpace(provider.Name())
		if name == "" || len(name) > 64 {
			return nil, ErrUnavailable
		}
		if _, exists := seen[name]; exists {
			return nil, ErrUnavailable
		}
		seen[name] = struct{}{}
		filtered = append(filtered, provider)
	}
	return &InteractiveProviderPool{region: region, providers: filtered}, nil
}

func (p *InteractiveProviderPool) Begin(ctx context.Context, operation Operation) (ProviderChallenge, error) {
	if p == nil || len(p.providers) == 0 {
		return ProviderChallenge{}, ErrUnavailable
	}
	start := int(p.next.Add(1)-1) % len(p.providers)
	for offset := range len(p.providers) {
		provider := p.providers[(start+offset)%len(p.providers)]
		if !provider.Available(ctx, p.region) {
			continue
		}
		challenge, err := provider.Begin(ctx, operation)
		if err != nil || challenge.ID == "" || len(challenge.ID) > 2048 {
			continue
		}
		wrapped, err := encodeProviderChallengeID(provider.Name(), challenge.ID)
		if err != nil {
			continue
		}
		challenge.ID = wrapped
		challenge.Provider = provider.Name()
		return challenge, nil
	}
	return ProviderChallenge{}, ErrUnavailable
}

func (p *InteractiveProviderPool) Verify(ctx context.Context, wrappedID, proof string) error {
	if p == nil || proof == "" || len(proof) > 8192 {
		return ErrInvalidProof
	}
	providerName, providerChallengeID, err := decodeProviderChallengeID(wrappedID)
	if err != nil {
		return ErrInvalidProof
	}
	for _, provider := range p.providers {
		if provider.Name() != providerName {
			continue
		}
		if !provider.Available(ctx, p.region) {
			return ErrUnavailable
		}
		if err := provider.Verify(ctx, providerChallengeID, proof); err != nil {
			if errors.Is(err, ErrUnavailable) {
				return ErrUnavailable
			}
			return ErrInvalidProof
		}
		return nil
	}
	return ErrInvalidProof
}

type encodedProviderChallenge struct {
	Provider string `json:"provider"`
	ID       string `json:"id"`
}

func encodeProviderChallengeID(provider, id string) (string, error) {
	if provider == "" || id == "" {
		return "", ErrUnavailable
	}
	payload, err := json.Marshal(encodedProviderChallenge{Provider: provider, ID: id})
	if err != nil {
		return "", ErrUnavailable
	}
	return base64.RawURLEncoding.EncodeToString(payload), nil
}

func decodeProviderChallengeID(value string) (string, string, error) {
	if value == "" || len(value) > 4096 {
		return "", "", ErrInvalidProof
	}
	payload, err := base64.RawURLEncoding.DecodeString(value)
	if err != nil {
		return "", "", ErrInvalidProof
	}
	var encoded encodedProviderChallenge
	if err := json.Unmarshal(payload, &encoded); err != nil || encoded.Provider == "" || len(encoded.Provider) > 64 || encoded.ID == "" || len(encoded.ID) > 2048 {
		return "", "", ErrInvalidProof
	}
	return encoded.Provider, encoded.ID, nil
}

var _ InteractiveVerifier = (*InteractiveProviderPool)(nil)
