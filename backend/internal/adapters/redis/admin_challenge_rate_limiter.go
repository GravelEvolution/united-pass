package redis

import (
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/base64"
	"errors"
	"fmt"
	"time"

	goredis "github.com/redis/go-redis/v9"

	"github.com/GravelEvolution/united-pass/backend/internal/adminstepup"
	"github.com/GravelEvolution/united-pass/backend/internal/identity"
)

const adminChallengeRateSegment = "rl:admin-challenge:"

// adminChallengeRateScript increments the immutable-user and client buckets
// in one Redis operation. Both counters always advance together, so changing
// an IP/client fingerprint cannot reset the user budget and spraying users
// from one client cannot bypass the client budget.
var adminChallengeRateScript = goredis.NewScript(`
local userKey = KEYS[1]
local clientKey = KEYS[2]
local limit = tonumber(ARGV[1])
local windowMs = tonumber(ARGV[2])

local userCount = redis.call('INCR', userKey)
if userCount == 1 then redis.call('PEXPIRE', userKey, windowMs) end
local clientCount = redis.call('INCR', clientKey)
if clientCount == 1 then redis.call('PEXPIRE', clientKey, windowMs) end

local userTTL = redis.call('PTTL', userKey)
local clientTTL = redis.call('PTTL', clientKey)
if userTTL < 0 then userTTL = windowMs end
if clientTTL < 0 then clientTTL = windowMs end
local retry = userTTL
if clientTTL > retry then retry = clientTTL end

if userCount > limit or clientCount > limit then
  return {0, retry}
end
return {1, 0}
`)

type AdminChallengeRateLimiter struct {
	client  *Client
	keyring *adminstepup.Keyring
	limit   int
	window  time.Duration
}

func NewAdminChallengeRateLimiter(client *Client, keyring *adminstepup.Keyring, limit int, window time.Duration) (*AdminChallengeRateLimiter, error) {
	if client == nil || keyring == nil || limit <= 0 || window <= 0 {
		return nil, errors.New("redis: invalid admin challenge limiter configuration")
	}
	if _, _, err := keyring.Current(); err != nil {
		return nil, err
	}
	return &AdminChallengeRateLimiter{client: client, keyring: keyring, limit: limit, window: window}, nil
}

// Check satisfies adminstepup.RateLimiter. Raw user IDs, IP addresses and user
// agents never reach Redis: only separate purpose-keyed HMACs are used.
func (r *AdminChallengeRateLimiter) Check(ctx context.Context, userID identity.UserID, clientFingerprint string) (time.Duration, error) {
	if userID == "" || clientFingerprint == "" {
		return r.window, errors.New("redis: admin challenge limiter identity unavailable")
	}
	keyID, key, err := r.keyring.Current()
	if err != nil {
		return r.window, err
	}
	userDigest := adminRateDigest(key, "immutable-user", string(userID))
	clientDigest := adminRateDigest(key, "client-fingerprint", clientFingerprint)
	userKey := r.client.buildKey(adminChallengeRateSegment, keyID, ":user:", userDigest)
	clientKey := r.client.buildKey(adminChallengeRateSegment, keyID, ":client:", clientDigest)
	result, err := adminChallengeRateScript.Run(ctx, r.client.rdb, []string{userKey, clientKey}, r.limit, r.window.Milliseconds()).Slice()
	if err != nil {
		return r.window, fmt.Errorf("redis: admin challenge rate limit check: %w", err)
	}
	if len(result) != 2 {
		return r.window, errors.New("redis: invalid admin challenge limiter response")
	}
	allowed, ok := result[0].(int64)
	if !ok {
		return r.window, errors.New("redis: invalid admin challenge limiter decision")
	}
	retryMS, ok := result[1].(int64)
	if !ok {
		return r.window, errors.New("redis: invalid admin challenge limiter retry")
	}
	if allowed != 1 {
		retry := time.Duration(retryMS) * time.Millisecond
		if retry <= 0 {
			retry = r.window
		}
		return retry, adminstepup.ErrRateLimited
	}
	return 0, nil
}

func adminRateDigest(key []byte, purpose, value string) string {
	mac := hmac.New(sha256.New, key)
	_, _ = mac.Write([]byte("united-pass/admin-challenge-rate-limit/v1\x00"))
	_, _ = mac.Write([]byte(purpose))
	_, _ = mac.Write([]byte{0})
	_, _ = mac.Write([]byte(value))
	return base64.RawURLEncoding.EncodeToString(mac.Sum(nil))
}

var _ adminstepup.RateLimiter = (*AdminChallengeRateLimiter)(nil)
