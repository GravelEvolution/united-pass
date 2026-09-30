package redis

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"time"

	goredis "github.com/redis/go-redis/v9"

	"github.com/GravelEvolution/united-pass/backend/internal/passwordreset"
	"github.com/GravelEvolution/united-pass/backend/internal/session"
)

const passwordResetTokenSegment = "password-reset-token:"

var passwordResetConsumeScript = goredis.NewScript(`
local value = redis.call('GET', KEYS[1])
if not value then
	return nil
end
redis.call('DEL', KEYS[1])
return value
`)

type PasswordResetStore struct{ client *Client }

func NewPasswordResetStore(client *Client) *PasswordResetStore {
	return &PasswordResetStore{client: client}
}

func (s *PasswordResetStore) Create(ctx context.Context, rawToken string, record passwordreset.TokenRecord, ttl time.Duration) error {
	if s == nil || s.client == nil || rawToken == "" || record.UserID == "" || ttl <= 0 {
		return passwordreset.ErrUnavailable
	}
	payload, err := json.Marshal(record)
	if err != nil {
		return fmt.Errorf("redis: encode password reset token: %w", err)
	}
	key := s.client.buildKey(passwordResetTokenSegment, session.HashToken(rawToken))
	ok, err := s.client.rdb.SetNX(ctx, key, payload, ttl).Result()
	if err != nil {
		return fmt.Errorf("redis: create password reset token: %w", err)
	}
	if !ok {
		return passwordreset.ErrUnavailable
	}
	return nil
}

func (s *PasswordResetStore) Consume(ctx context.Context, rawToken string) (passwordreset.TokenRecord, error) {
	if s == nil || s.client == nil || rawToken == "" {
		return passwordreset.TokenRecord{}, passwordreset.ErrInvalidToken
	}
	key := s.client.buildKey(passwordResetTokenSegment, session.HashToken(rawToken))
	value, err := passwordResetConsumeScript.Run(ctx, s.client.rdb, []string{key}).Result()
	if errors.Is(err, goredis.Nil) {
		return passwordreset.TokenRecord{}, passwordreset.ErrInvalidToken
	}
	if err != nil {
		return passwordreset.TokenRecord{}, fmt.Errorf("redis: consume password reset token: %w", err)
	}
	payload, ok := value.(string)
	if !ok || payload == "" {
		return passwordreset.TokenRecord{}, passwordreset.ErrInvalidToken
	}
	var record passwordreset.TokenRecord
	if err := json.Unmarshal([]byte(payload), &record); err != nil || record.UserID == "" {
		return passwordreset.TokenRecord{}, passwordreset.ErrInvalidToken
	}
	return record, nil
}

var _ passwordreset.TokenStore = (*PasswordResetStore)(nil)
