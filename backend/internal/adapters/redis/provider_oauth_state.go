//
// Copyright (c) 2026 Chen Jiajie(Ariakage)
//
// Author: Chen Jiajie(Ariakage) <ariakage233@gmail.com>
// Date: 2026-08-11
// Description: Redis single-use Feishu OAuth state store
//

package redis

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"time"

	goredis "github.com/redis/go-redis/v9"

	"github.com/GravelEvolution/united-pass/backend/internal/providers"
)

const providerOAuthStateKeySegment = "provider-oauth-state:"

type ProviderOAuthStateStore struct{ client *Client }

func NewProviderOAuthStateStore(client *Client) *ProviderOAuthStateStore {
	return &ProviderOAuthStateStore{client: client}
}

func (s *ProviderOAuthStateStore) Create(ctx context.Context, stateHash string, state providers.OAuthState, ttl time.Duration) error {
	if stateHash == "" || state.CreatedAt.IsZero() || ttl <= 0 {
		return providers.ErrInvalidInput
	}
	payload, err := json.Marshal(state)
	if err != nil {
		return fmt.Errorf("redis: encode provider OAuth state: %w", err)
	}
	ok, err := s.client.rdb.SetNX(ctx, s.client.buildKey(providerOAuthStateKeySegment, stateHash), payload, ttl).Result()
	if err != nil {
		return fmt.Errorf("redis: create provider OAuth state: %w", err)
	}
	if !ok {
		return providers.ErrConflict
	}
	return nil
}

var consumeProviderOAuthStateScript = goredis.NewScript(`
local value = redis.call('GET', KEYS[1])
if not value then return nil end
redis.call('DEL', KEYS[1])
return value
`)

func (s *ProviderOAuthStateStore) Consume(ctx context.Context, stateHash string) (providers.OAuthState, error) {
	if stateHash == "" {
		return providers.OAuthState{}, providers.ErrInvalidInput
	}
	value, err := consumeProviderOAuthStateScript.Run(ctx, s.client.rdb,
		[]string{s.client.buildKey(providerOAuthStateKeySegment, stateHash)}).Result()
	if errors.Is(err, goredis.Nil) {
		return providers.OAuthState{}, providers.ErrOAuthStateNotFound
	}
	if err != nil {
		return providers.OAuthState{}, fmt.Errorf("redis: consume provider OAuth state: %w", err)
	}
	text, ok := value.(string)
	if !ok {
		return providers.OAuthState{}, errors.New("redis: provider OAuth state has invalid type")
	}
	var state providers.OAuthState
	if err := json.Unmarshal([]byte(text), &state); err != nil {
		return providers.OAuthState{}, fmt.Errorf("redis: decode provider OAuth state: %w", err)
	}
	return state, nil
}

var _ providers.OAuthStateStore = (*ProviderOAuthStateStore)(nil)
