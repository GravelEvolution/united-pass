package redis

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"time"

	goredis "github.com/redis/go-redis/v9"

	"github.com/GravelEvolution/united-pass/backend/internal/registration"
	"github.com/GravelEvolution/united-pass/backend/internal/session"
)

const registrationTokenSegment = "registration-token:"

// RegistrationStore retains only a SHA-256 token key and the minimum user ID
// plus OAuth request recovery data. Raw registration tokens never enter Redis.
type RegistrationStore struct{ client *Client }

func NewRegistrationStore(client *Client) *RegistrationStore {
	return &RegistrationStore{client: client}
}

func (s *RegistrationStore) Create(ctx context.Context, rawToken string, record registration.TokenRecord, ttl time.Duration) error {
	if s == nil || s.client == nil || rawToken == "" || record.UserID == "" || ttl <= 0 {
		return registration.ErrUnavailable
	}
	payload, err := json.Marshal(record)
	if err != nil {
		return fmt.Errorf("redis: encode registration token: %w", err)
	}
	key := s.client.buildKey(registrationTokenSegment, session.HashToken(rawToken))
	ok, err := s.client.rdb.SetNX(ctx, key, payload, ttl).Result()
	if err != nil {
		return fmt.Errorf("redis: create registration token: %w", err)
	}
	if !ok {
		return registration.ErrUnavailable
	}
	return nil
}

func (s *RegistrationStore) Get(ctx context.Context, rawToken string) (registration.TokenRecord, error) {
	if s == nil || s.client == nil || rawToken == "" {
		return registration.TokenRecord{}, registration.ErrTokenNotFound
	}
	key := s.client.buildKey(registrationTokenSegment, session.HashToken(rawToken))
	payload, err := s.client.rdb.Get(ctx, key).Bytes()
	if errors.Is(err, goredis.Nil) {
		return registration.TokenRecord{}, registration.ErrTokenNotFound
	}
	if err != nil {
		return registration.TokenRecord{}, fmt.Errorf("redis: get registration token: %w", err)
	}
	var record registration.TokenRecord
	if err := json.Unmarshal(payload, &record); err != nil || record.UserID == "" {
		return registration.TokenRecord{}, registration.ErrTokenNotFound
	}
	return record, nil
}

func (s *RegistrationStore) Delete(ctx context.Context, rawToken string) error {
	if s == nil || s.client == nil || rawToken == "" {
		return nil
	}
	key := s.client.buildKey(registrationTokenSegment, session.HashToken(rawToken))
	if err := s.client.rdb.Del(ctx, key).Err(); err != nil {
		return fmt.Errorf("redis: delete registration token: %w", err)
	}
	return nil
}

var _ registration.TokenStore = (*RegistrationStore)(nil)
