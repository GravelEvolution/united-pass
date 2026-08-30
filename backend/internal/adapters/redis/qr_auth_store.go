package redis

import (
	"context"
	"encoding/json"
	"fmt"
	"time"

	goredis "github.com/redis/go-redis/v9"

	"github.com/GravelEvolution/united-pass/backend/internal/identity"
	"github.com/GravelEvolution/united-pass/backend/internal/qrauth"
)

const qrAuthChallengeSegment = "qr-auth:challenge:"

type QRAuthStore struct{ client *Client }

func NewQRAuthStore(client *Client) *QRAuthStore { return &QRAuthStore{client: client} }

type qrAuthRecord struct {
	ReceiverHash string `json:"receiverHash"`
	UserID       string `json:"userId,omitempty"`
}

func (s *QRAuthStore) Create(ctx context.Context, challengeHash, receiverHash string, ttl time.Duration) error {
	if s == nil || s.client == nil || challengeHash == "" || receiverHash == "" || ttl <= 0 {
		return qrauth.ErrUnavailable
	}
	payload, err := json.Marshal(qrAuthRecord{ReceiverHash: receiverHash})
	if err != nil {
		return qrauth.ErrUnavailable
	}
	ok, err := s.client.rdb.SetNX(ctx, s.key(challengeHash), payload, ttl).Result()
	if err != nil {
		return fmt.Errorf("redis: create QR auth challenge: %w", err)
	}
	if !ok {
		return qrauth.ErrUnavailable
	}
	return nil
}

var approveQRAuthScript = goredis.NewScript(`
local value = redis.call('GET', KEYS[1])
if not value then return 0 end
local record = cjson.decode(value)
if record.userId and record.userId ~= '' then return 2 end
record.userId = ARGV[1]
local ttl = redis.call('PTTL', KEYS[1])
if ttl <= 0 then return 0 end
redis.call('SET', KEYS[1], cjson.encode(record), 'PX', ttl)
return 1
`)

func (s *QRAuthStore) Approve(ctx context.Context, challengeHash string, userID identity.UserID) error {
	if s == nil || s.client == nil || challengeHash == "" || userID == "" {
		return qrauth.ErrUnavailable
	}
	result, err := approveQRAuthScript.Run(ctx, s.client.rdb, []string{s.key(challengeHash)}, string(userID)).Int()
	if err != nil {
		return fmt.Errorf("redis: approve QR auth challenge: %w", err)
	}
	switch result {
	case 1:
		return nil
	case 0:
		return qrauth.ErrNotFound
	default:
		return qrauth.ErrConsumed
	}
}

var consumeQRAuthScript = goredis.NewScript(`
local value = redis.call('GET', KEYS[1])
if not value then return {0} end
local record = cjson.decode(value)
if record.receiverHash ~= ARGV[1] then return {1} end
if not record.userId or record.userId == '' then return {2} end
redis.call('DEL', KEYS[1])
return {3, record.userId}
`)

func (s *QRAuthStore) Consume(ctx context.Context, challengeHash, receiverHash string) (identity.UserID, error) {
	if s == nil || s.client == nil || challengeHash == "" || receiverHash == "" {
		return "", qrauth.ErrDenied
	}
	values, err := consumeQRAuthScript.Run(ctx, s.client.rdb, []string{s.key(challengeHash)}, receiverHash).Slice()
	if err != nil {
		return "", fmt.Errorf("redis: consume QR auth challenge: %w", err)
	}
	if len(values) == 0 {
		return "", qrauth.ErrUnavailable
	}
	status, ok := values[0].(int64)
	if !ok {
		return "", qrauth.ErrUnavailable
	}
	switch status {
	case 0:
		return "", qrauth.ErrNotFound
	case 1:
		return "", qrauth.ErrDenied
	case 2:
		return "", qrauth.ErrPending
	case 3:
		if len(values) != 2 {
			return "", qrauth.ErrUnavailable
		}
		user, ok := values[1].(string)
		if !ok || user == "" {
			return "", qrauth.ErrUnavailable
		}
		return identity.UserID(user), nil
	default:
		return "", qrauth.ErrUnavailable
	}
}

func (s *QRAuthStore) key(challengeHash string) string {
	return s.client.buildKey(qrAuthChallengeSegment, challengeHash)
}

var _ qrauth.Store = (*QRAuthStore)(nil)
