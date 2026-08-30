package redis

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"strings"
	"time"
	"unicode"

	goredis "github.com/redis/go-redis/v9"

	"github.com/GravelEvolution/united-pass/backend/internal/session"
	"github.com/GravelEvolution/united-pass/backend/internal/wechatonboarding"
)

const (
	wechatOnboardingKeySegment         = "wechat-onboarding:v2:"
	wechatOnboardingAttemptsKeySegment = "wechat-onboarding:v2:attempts:"
	wechatOnboardingClaimKeySegment    = "wechat-onboarding:v2:claim:"
	wechatOnboardingClaimTTL           = 60 * time.Second
)

// WeChatOnboardingStore persists only AEAD-encrypted, short-lived challenge
// payloads. The raw bearer is hashed inside this adapter; Redis sees neither
// the raw token nor the WeChat subject, phone, target user or provider session.
type WeChatOnboardingStore struct {
	client    *Client
	encryptor session.Encryptor
}

func NewWeChatOnboardingStore(client *Client, encryptor session.Encryptor) *WeChatOnboardingStore {
	return &WeChatOnboardingStore{client: client, encryptor: encryptor}
}

func (s *WeChatOnboardingStore) Create(ctx context.Context, rawToken string, data wechatonboarding.ChallengeData, ttl time.Duration) error {
	if !s.ready() || !validOnboardingRawToken(rawToken) || ttl <= 0 || ttl/time.Millisecond <= 0 {
		return errors.New("redis: invalid WeChat onboarding challenge input")
	}
	hash := session.HashToken(rawToken)
	ciphertext, err := s.seal(hash, data)
	if err != nil {
		return err
	}
	if data.Kind == wechatonboarding.ChallengeKindMFA {
		cleanupCiphertext, cleanupErr := s.sealCleanup(hash, data)
		if cleanupErr != nil {
			return cleanupErr
		}
		return s.createMFAChallenge(ctx, hash, ciphertext, cleanupCiphertext, ttl)
	}
	created, err := s.client.rdb.SetNX(ctx, s.challengeKey(hash), ciphertext, ttl).Result()
	if err != nil {
		return fmt.Errorf("redis: create WeChat onboarding challenge: %w", err)
	}
	if !created {
		return errors.New("redis: WeChat onboarding challenge token collision")
	}
	return nil
}

func (s *WeChatOnboardingStore) Claim(ctx context.Context, rawToken, claimID string) (wechatonboarding.ChallengeData, error) {
	if !s.ready() || !validOnboardingRawToken(rawToken) || !validOnboardingRawToken(claimID) {
		return wechatonboarding.ChallengeData{}, errors.New("redis: invalid WeChat onboarding claim input")
	}
	hash := session.HashToken(rawToken)
	script := goredis.NewScript(`
local challengeKey = KEYS[1]
local claimKey = KEYS[2]
local claimID = ARGV[1]
local claimTTL = tonumber(ARGV[2])
local locked = redis.call('SET', claimKey, claimID, 'NX', 'PX', claimTTL)
if not locked then return redis.error_reply('CLAIMED') end
local data = redis.call('GET', challengeKey)
if not data then
  redis.call('DEL', claimKey)
  return nil
end
return data
`)
	result, err := script.Run(ctx, s.client.rdb, []string{s.challengeKey(hash), s.claimKey(hash)}, claimID, wechatOnboardingClaimTTL.Milliseconds()).Result()
	if err != nil {
		if isClaimedError(err) {
			return wechatonboarding.ChallengeData{}, wechatonboarding.ErrChallengeClaimed
		}
		if errors.Is(err, goredis.Nil) {
			return wechatonboarding.ChallengeData{}, wechatonboarding.ErrChallengeNotFound
		}
		return wechatonboarding.ChallengeData{}, fmt.Errorf("redis: claim WeChat onboarding challenge: %w", err)
	}
	ciphertext, ok := result.(string)
	if !ok {
		_ = s.consumeHash(context.WithoutCancel(ctx), hash, claimID)
		return wechatonboarding.ChallengeData{}, wechatonboarding.ErrChallengeInvalid
	}
	data, err := s.open(hash, ciphertext)
	if err != nil {
		// Corrupt, swapped or wrong-purpose records can never become usable;
		// remove them while the adapter owns the claim, then fail closed.
		_ = s.consumeHash(context.WithoutCancel(ctx), hash, claimID)
		return wechatonboarding.ChallengeData{}, wechatonboarding.ErrChallengeInvalid
	}
	return data, nil
}

func (s *WeChatOnboardingStore) Release(ctx context.Context, rawToken, claimID string) error {
	if !s.ready() || !validOnboardingRawToken(rawToken) || !validOnboardingRawToken(claimID) {
		return errors.New("redis: invalid WeChat onboarding release input")
	}
	hash := session.HashToken(rawToken)
	script := goredis.NewScript(`
local current = redis.call('GET', KEYS[1])
if not current or current ~= ARGV[1] then return 0 end
redis.call('DEL', KEYS[1])
return 1
`)
	result, err := script.Run(ctx, s.client.rdb, []string{s.claimKey(hash)}, claimID).Int()
	if err != nil {
		return fmt.Errorf("redis: release WeChat onboarding challenge: %w", err)
	}
	if result != 1 {
		return wechatonboarding.ErrChallengeNotHeld
	}
	return nil
}

func (s *WeChatOnboardingStore) Consume(ctx context.Context, rawToken, claimID string) error {
	if !s.ready() || !validOnboardingRawToken(rawToken) || !validOnboardingRawToken(claimID) {
		return errors.New("redis: invalid WeChat onboarding consume input")
	}
	return s.consumeHash(ctx, session.HashToken(rawToken), claimID)
}

func (s *WeChatOnboardingStore) consumeHash(ctx context.Context, hash, claimID string) error {
	script := goredis.NewScript(`
if redis.call('GET', KEYS[3]) ~= ARGV[1] then return 0 end
if redis.call('EXISTS', KEYS[1]) == 0 then
  redis.call('DEL', KEYS[3])
  return -1
end
if redis.call('EXISTS', KEYS[4]) == 0 and redis.call('ZSCORE', KEYS[7], ARGV[2]) then
  -- Atomic MFA creation always writes cleanup + due index together. A due
  -- member without its encrypted cleanup obligation is corruption/eviction;
  -- do not promote a provider session that can no longer be recovered.
  return -2
end
redis.call('DEL', KEYS[1], KEYS[2], KEYS[3], KEYS[5])
if redis.call('EXISTS', KEYS[4]) ~= 0 then
  local redisTime = redis.call('TIME')
  local nowMillis = tonumber(redisTime[1]) * 1000 + math.floor(tonumber(redisTime[2]) / 1000)
  redis.call('SET', KEYS[6], ARGV[1], 'PX', tonumber(ARGV[3]))
  redis.call('ZADD', KEYS[7], nowMillis + tonumber(ARGV[3]), ARGV[2])
else
  -- Non-MFA onboarding challenges have no provider-session cleanup record.
  -- Clear any stale index state rather than manufacturing a promotion lease.
  redis.call('DEL', KEYS[6])
  redis.call('ZREM', KEYS[7], ARGV[2])
end
return 1
`)
	result, err := script.Run(ctx, s.client.rdb, []string{
		s.challengeKey(hash), s.attemptsKey(hash), s.claimKey(hash),
		s.cleanupKey(hash), s.cleanupClaimKey(hash), s.promotionKey(hash), s.cleanupDueKey(),
	}, claimID, hash, wechatOnboardingPromotionLease.Milliseconds()).Int()
	if err != nil {
		return fmt.Errorf("redis: consume WeChat onboarding challenge: %w", err)
	}
	switch result {
	case 1:
		return nil
	case -1:
		return wechatonboarding.ErrChallengeNotFound
	case -2:
		return wechatonboarding.ErrChallengeInvalid
	default:
		return wechatonboarding.ErrChallengeNotHeld
	}
}

func (s *WeChatOnboardingStore) IncrementAttempts(ctx context.Context, rawToken string, maxAttempts int) (int, error) {
	if !s.ready() || !validOnboardingRawToken(rawToken) || maxAttempts <= 0 {
		return 0, errors.New("redis: invalid WeChat onboarding attempts input")
	}
	hash := session.HashToken(rawToken)
	script := goredis.NewScript(`
if redis.call('EXISTS', KEYS[1]) == 0 then return -1 end
local count = redis.call('INCR', KEYS[2])
local ttl = redis.call('PTTL', KEYS[1])
if ttl > 0 then redis.call('PEXPIRE', KEYS[2], ttl) end
return count
`)
	count, err := script.Run(ctx, s.client.rdb, []string{s.challengeKey(hash), s.attemptsKey(hash)}).Int()
	if err != nil {
		return 0, fmt.Errorf("redis: increment WeChat onboarding attempts: %w", err)
	}
	if count < 0 {
		return 0, wechatonboarding.ErrChallengeNotFound
	}
	if count >= maxAttempts {
		return count, wechatonboarding.ErrMaxAttempts
	}
	return count, nil
}

func (s *WeChatOnboardingStore) seal(tokenHash string, data wechatonboarding.ChallengeData) (string, error) {
	if s == nil || s.encryptor == nil || !validLowerSHA256(tokenHash) {
		return "", errors.New("redis: WeChat onboarding encryption unavailable")
	}
	data.TokenHash = tokenHash
	if !validOnboardingChallenge(data) {
		return "", wechatonboarding.ErrChallengeInvalid
	}
	plain, err := json.Marshal(data)
	if err != nil {
		return "", fmt.Errorf("redis: encode WeChat onboarding challenge: %w", err)
	}
	ciphertext, err := s.encryptor.Encrypt(string(plain))
	if err != nil {
		return "", fmt.Errorf("redis: encrypt WeChat onboarding challenge: %w", err)
	}
	if ciphertext == "" {
		return "", errors.New("redis: encrypt WeChat onboarding challenge returned empty ciphertext")
	}
	return ciphertext, nil
}

func (s *WeChatOnboardingStore) open(tokenHash, ciphertext string) (wechatonboarding.ChallengeData, error) {
	if s == nil || s.encryptor == nil || !validLowerSHA256(tokenHash) || ciphertext == "" {
		return wechatonboarding.ChallengeData{}, wechatonboarding.ErrChallengeInvalid
	}
	plain, err := s.encryptor.Decrypt(ciphertext)
	if err != nil || plain == "" {
		return wechatonboarding.ChallengeData{}, wechatonboarding.ErrChallengeInvalid
	}
	var data wechatonboarding.ChallengeData
	decoder := json.NewDecoder(strings.NewReader(plain))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&data); err != nil || data.TokenHash != tokenHash || !validOnboardingChallenge(data) {
		return wechatonboarding.ChallengeData{}, wechatonboarding.ErrChallengeInvalid
	}
	if err := decoder.Decode(&struct{}{}); !errors.Is(err, io.EOF) {
		return wechatonboarding.ChallengeData{}, wechatonboarding.ErrChallengeInvalid
	}
	return data, nil
}

func validOnboardingChallenge(data wechatonboarding.ChallengeData) bool {
	if !validLowerSHA256(data.TokenHash) || data.TenantID == "" || data.Subject == "" || data.CreatedAt.IsZero() {
		return false
	}
	switch data.Kind {
	case wechatonboarding.ChallengeKindOnboarding:
		return data.Purpose == wechatonboarding.ChallengePurpose && data.ProviderSessionID == "" && len(data.AvailableMethods) == 0 && data.NormalizedEmail == "" && data.ExpectedVersion == 0 && data.ExpectedSecurityEpoch == 0
	case wechatonboarding.ChallengeKindMFA:
		return data.Purpose == wechatonboarding.MFAChallengePurpose && data.TargetUserID != "" && data.ProviderSessionID != "" && len(data.AvailableMethods) > 0 && data.NormalizedEmail != "" && data.NormalizedEmail == strings.ToLower(strings.TrimSpace(data.NormalizedEmail)) && data.ExpectedVersion > 0 && data.ExpectedSecurityEpoch > 0
	default:
		return false
	}
}

func validLowerSHA256(value string) bool {
	if len(value) != 64 {
		return false
	}
	for _, r := range value {
		if !((r >= '0' && r <= '9') || (r >= 'a' && r <= 'f')) {
			return false
		}
	}
	return true
}

func validOnboardingRawToken(value string) bool {
	if value == "" || len(value) > 512 || strings.TrimSpace(value) != value {
		return false
	}
	for _, r := range value {
		if unicode.IsControl(r) {
			return false
		}
	}
	return true
}

func (s *WeChatOnboardingStore) challengeKey(hash string) string {
	return s.client.buildKey(wechatOnboardingKeySegment, hash)
}

func (s *WeChatOnboardingStore) attemptsKey(hash string) string {
	return s.client.buildKey(wechatOnboardingAttemptsKeySegment, hash)
}

func (s *WeChatOnboardingStore) claimKey(hash string) string {
	return s.client.buildKey(wechatOnboardingClaimKeySegment, hash)
}

func (s *WeChatOnboardingStore) ready() bool {
	return s != nil && s.client != nil && s.client.rdb != nil && s.encryptor != nil
}

var _ wechatonboarding.ChallengeStore = (*WeChatOnboardingStore)(nil)
