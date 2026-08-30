package redis

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"time"

	goredis "github.com/redis/go-redis/v9"

	"github.com/GravelEvolution/united-pass/backend/internal/riskdefense"
)

const (
	riskDeviceSegment         = "risk:device:"
	riskObservationSegment    = "risk:observe:"
	riskChallengeSegment      = "risk:challenge:"
	riskChallengeClaimSegment = "risk:challenge:claim:"
	riskTrustSegment          = "risk:trust:"
	riskCompletionRateSegment = "rl:risk:complete:"
	riskClaimTTL              = 60 * time.Second
)

type RiskStore struct{ client *Client }

func NewRiskStore(client *Client) *RiskStore { return &RiskStore{client: client} }

func (s *RiskStore) RegisterDevice(ctx context.Context, deviceHash string, ttl time.Duration) error {
	if !validRiskKeyPart(deviceHash) || ttl <= 0 {
		return errors.New("redis: invalid risk device")
	}
	if err := s.client.rdb.Set(ctx, s.client.buildKey(riskDeviceSegment, deviceHash), "1", ttl).Err(); err != nil {
		return fmt.Errorf("redis: register risk device: %w", err)
	}
	return nil
}

func (s *RiskStore) DeviceExists(ctx context.Context, deviceHash string) (bool, error) {
	if !validRiskKeyPart(deviceHash) {
		return false, errors.New("redis: invalid risk device")
	}
	n, err := s.client.rdb.Exists(ctx, s.client.buildKey(riskDeviceSegment, deviceHash)).Result()
	if err != nil {
		return false, fmt.Errorf("redis: read risk device: %w", err)
	}
	return n == 1, nil
}

var riskObserveScript = goredis.NewScript(`
local deviceKey = KEYS[1]
local pairKey = KEYS[2]
local windowMs = tonumber(ARGV[1])
local deviceCount = redis.call('INCR', deviceKey)
if deviceCount == 1 then redis.call('PEXPIRE', deviceKey, windowMs) end
local pairCount = redis.call('INCR', pairKey)
if pairCount == 1 then redis.call('PEXPIRE', pairKey, windowMs) end
if pairCount > deviceCount then return pairCount end
return deviceCount
`)

func (s *RiskStore) Observe(ctx context.Context, operation riskdefense.Operation, deviceHash, identifierHash string, window time.Duration) (riskdefense.Activity, error) {
	if !validRiskKeyPart(deviceHash) || !validRiskKeyPart(identifierHash) || window <= 0 || (operation != riskdefense.OperationLogin && operation != riskdefense.OperationRegistration) {
		return riskdefense.Activity{}, errors.New("redis: invalid risk observation")
	}
	base := riskObservationSegment + string(operation) + ":"
	count, err := riskObserveScript.Run(ctx, s.client.rdb, []string{
		s.client.buildKey(base, "device:", deviceHash),
		s.client.buildKey(base, "pair:", deviceHash, ":", identifierHash),
	}, window.Milliseconds()).Int()
	if err != nil {
		return riskdefense.Activity{}, fmt.Errorf("redis: observe risk activity: %w", err)
	}
	return riskdefense.Activity{Attempts: count}, nil
}

func (s *RiskStore) CreateChallenge(ctx context.Context, tokenHash string, record riskdefense.ChallengeRecord, ttl time.Duration) error {
	if !validRiskKeyPart(tokenHash) || ttl <= 0 {
		return errors.New("redis: invalid risk challenge")
	}
	payload, err := json.Marshal(record)
	if err != nil {
		return fmt.Errorf("redis: encode risk challenge: %w", err)
	}
	key := s.client.buildKey(riskChallengeSegment, tokenHash)
	ok, err := s.client.rdb.SetNX(ctx, key, payload, ttl).Result()
	if err != nil {
		return fmt.Errorf("redis: create risk challenge: %w", err)
	}
	if !ok {
		return errors.New("redis: duplicate risk challenge")
	}
	return nil
}

var riskClaimScript = goredis.NewScript(`
local challengeKey = KEYS[1]
local claimKey = KEYS[2]
local locked = redis.call('SET', claimKey, ARGV[1], 'NX', 'PX', ARGV[2])
if not locked then return redis.error_reply('RISK_CLAIMED') end
local data = redis.call('GET', challengeKey)
if not data then redis.call('DEL', claimKey); return nil end
return data
`)

func (s *RiskStore) ClaimChallenge(ctx context.Context, tokenHash, claimID string) (riskdefense.ChallengeRecord, error) {
	if !validRiskKeyPart(tokenHash) || claimID == "" {
		return riskdefense.ChallengeRecord{}, errors.New("redis: invalid risk challenge claim")
	}
	result, err := riskClaimScript.Run(ctx, s.client.rdb, []string{
		s.client.buildKey(riskChallengeSegment, tokenHash),
		s.client.buildKey(riskChallengeClaimSegment, tokenHash),
	}, claimID, riskClaimTTL.Milliseconds()).Result()
	if err != nil {
		if strings.Contains(err.Error(), "RISK_CLAIMED") {
			return riskdefense.ChallengeRecord{}, riskdefense.ErrChallengeClaimed
		}
		if errors.Is(err, goredis.Nil) {
			return riskdefense.ChallengeRecord{}, riskdefense.ErrChallengeNotFound
		}
		return riskdefense.ChallengeRecord{}, fmt.Errorf("redis: claim risk challenge: %w", err)
	}
	var record riskdefense.ChallengeRecord
	if err := json.Unmarshal([]byte(result.(string)), &record); err != nil {
		return riskdefense.ChallengeRecord{}, fmt.Errorf("redis: decode risk challenge: %w", err)
	}
	return record, nil
}

var riskReleaseScript = goredis.NewScript(`
if redis.call('GET', KEYS[1]) ~= ARGV[1] then return 0 end
redis.call('DEL', KEYS[1])
return 1
`)

func (s *RiskStore) ReleaseChallenge(ctx context.Context, tokenHash, claimID string) error {
	if !validRiskKeyPart(tokenHash) || claimID == "" {
		return errors.New("redis: invalid risk challenge release")
	}
	n, err := riskReleaseScript.Run(ctx, s.client.rdb, []string{s.client.buildKey(riskChallengeClaimSegment, tokenHash)}, claimID).Int()
	if err != nil {
		return fmt.Errorf("redis: release risk challenge: %w", err)
	}
	if n != 1 {
		return riskdefense.ErrChallengeNotHeld
	}
	return nil
}

var riskConsumeScript = goredis.NewScript(`
if redis.call('GET', KEYS[2]) ~= ARGV[1] then return 0 end
if redis.call('EXISTS', KEYS[1]) == 0 then redis.call('DEL', KEYS[2]); return -1 end
redis.call('DEL', KEYS[1], KEYS[2])
return 1
`)

func (s *RiskStore) ConsumeChallenge(ctx context.Context, tokenHash, claimID string) error {
	if !validRiskKeyPart(tokenHash) || claimID == "" {
		return errors.New("redis: invalid risk challenge consume")
	}
	n, err := riskConsumeScript.Run(ctx, s.client.rdb, []string{
		s.client.buildKey(riskChallengeSegment, tokenHash),
		s.client.buildKey(riskChallengeClaimSegment, tokenHash),
	}, claimID).Int()
	if err != nil {
		return fmt.Errorf("redis: consume risk challenge: %w", err)
	}
	if n == -1 {
		return riskdefense.ErrChallengeNotFound
	}
	if n != 1 {
		return riskdefense.ErrChallengeNotHeld
	}
	return nil
}

func (s *RiskStore) PutTrust(ctx context.Context, tokenHash string, record riskdefense.TrustRecord, ttl time.Duration) error {
	if !validRiskKeyPart(tokenHash) || ttl <= 0 {
		return errors.New("redis: invalid risk trust")
	}
	payload, err := json.Marshal(record)
	if err != nil {
		return fmt.Errorf("redis: encode risk trust: %w", err)
	}
	if err := s.client.rdb.Set(ctx, s.client.buildKey(riskTrustSegment, tokenHash), payload, ttl).Err(); err != nil {
		return fmt.Errorf("redis: put risk trust: %w", err)
	}
	return nil
}

func (s *RiskStore) GetTrust(ctx context.Context, tokenHash string) (riskdefense.TrustRecord, error) {
	if !validRiskKeyPart(tokenHash) {
		return riskdefense.TrustRecord{}, errors.New("redis: invalid risk trust")
	}
	raw, err := s.client.rdb.Get(ctx, s.client.buildKey(riskTrustSegment, tokenHash)).Bytes()
	if errors.Is(err, goredis.Nil) {
		return riskdefense.TrustRecord{}, riskdefense.ErrTrustNotFound
	}
	if err != nil {
		return riskdefense.TrustRecord{}, fmt.Errorf("redis: get risk trust: %w", err)
	}
	var record riskdefense.TrustRecord
	if err := json.Unmarshal(raw, &record); err != nil {
		return riskdefense.TrustRecord{}, fmt.Errorf("redis: decode risk trust: %w", err)
	}
	return record, nil
}

func (s *RiskStore) CheckCompletionRate(ctx context.Context, challengeHash string, limit int, window time.Duration) (bool, time.Duration, error) {
	if !validRiskKeyPart(challengeHash) || limit <= 0 || window <= 0 {
		return false, window, errors.New("redis: invalid risk completion rate")
	}
	return NewRateLimiter(s.client).check(ctx, s.client.buildKey(riskCompletionRateSegment, challengeHash), limit, window)
}

func validRiskKeyPart(value string) bool {
	if len(value) != 64 {
		return false
	}
	for _, c := range value {
		if !((c >= '0' && c <= '9') || (c >= 'a' && c <= 'f')) {
			return false
		}
	}
	return true
}

var _ riskdefense.Store = (*RiskStore)(nil)
