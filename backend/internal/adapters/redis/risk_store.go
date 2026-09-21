package redis

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"time"

	goredis "github.com/redis/go-redis/v9"

	"github.com/GravelEvolution/united-pass/backend/internal/registration"
	"github.com/GravelEvolution/united-pass/backend/internal/riskdefense"
)

const (
	riskDeviceSegment                      = "risk:device:"
	riskObservationSegment                 = "risk:observe:"
	riskChallengeSegment                   = "risk:challenge:"
	riskChallengeClaimSegment              = "risk:challenge:claim:"
	riskRegistrationActiveChallengeSegment = "risk:challenge:active:registration:"
	riskTrustSegment                       = "risk:trust:"
	riskCompletionRateSegment              = "rl:risk:complete:"
	riskRegistrationIssueRateSegment       = "rl:risk:registration:issue:"
	riskRegistrationCompletionRateSegment  = "rl:risk:registration:complete:"
	riskClaimTTL                           = 60 * time.Second
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
	if !validRiskKeyPart(deviceHash) || !validRiskKeyPart(identifierHash) || window <= 0 || (operation != riskdefense.OperationLogin && operation != riskdefense.OperationRegistration && operation != riskdefense.OperationPhoneChange) {
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

// riskReserveRegistrationChallengeScript installs a short-lived ownership
// lease for one exact registration scope. The challenge hash doubles as the
// lease owner, so only the request that won SET NX may publish or release it.
// Returning the existing lease TTL gives callers a precise Retry-After while
// keeping the active challenge token and provider payload server-side.
var riskReserveRegistrationChallengeScript = goredis.NewScript(`
local activeKey = KEYS[1]
local owner = ARGV[1]
local leaseMs = tonumber(ARGV[2])

local reserved = redis.call('SET', activeKey, owner, 'NX', 'PX', leaseMs)
if reserved then
    return {1, 0}
end

local ttl = redis.call('PTTL', activeKey)
if ttl < 0 then ttl = leaseMs end
return {0, ttl}
`)

// ReserveRegistrationChallenge atomically elects one issuer for an exact
// registration scope. A losing request must not call the CAPTCHA provider.
func (s *RiskStore) ReserveRegistrationChallenge(ctx context.Context, scopeHash, challengeHash string, leaseTTL time.Duration) (bool, time.Duration, error) {
	if s == nil || s.client == nil || s.client.rdb == nil || !validRiskKeyPart(scopeHash) || !validRiskKeyPart(challengeHash) || leaseTTL < time.Millisecond {
		return false, leaseTTL, errors.New("redis: invalid registration challenge reservation")
	}
	result, err := riskReserveRegistrationChallengeScript.Run(ctx, s.client.rdb, []string{
		s.client.buildKey(riskRegistrationActiveChallengeSegment, scopeHash),
	}, challengeHash, leaseTTL.Milliseconds()).Slice()
	if err != nil {
		return false, leaseTTL, fmt.Errorf("redis: reserve registration challenge: %w", err)
	}
	if len(result) != 2 {
		return false, leaseTTL, fmt.Errorf("redis: registration challenge reservation returned %d values", len(result))
	}
	reserved, reservedOK := result[0].(int64)
	retryMs, retryOK := result[1].(int64)
	if !reservedOK || !retryOK || (reserved != 0 && reserved != 1) {
		return false, leaseTTL, errors.New("redis: invalid registration challenge reservation result")
	}
	if reserved == 1 {
		return true, 0, nil
	}
	if retryMs <= 0 {
		return false, leaseTTL, nil
	}
	return false, time.Duration(retryMs) * time.Millisecond, nil
}

var riskFinalizeRegistrationChallengeScript = goredis.NewScript(`
local activeKey = KEYS[1]
local challengeKey = KEYS[2]
local owner = ARGV[1]
local payload = ARGV[2]
local challengeMs = tonumber(ARGV[3])

if redis.call('GET', activeKey) ~= owner then return -1 end
local created = redis.call('SET', challengeKey, payload, 'NX', 'PX', challengeMs)
if not created then return 0 end
redis.call('PEXPIRE', activeKey, challengeMs)
return 1
`)

// FinalizeRegistrationChallenge atomically publishes the challenge record and
// extends the winning scope lease to the challenge lifetime. A stale or
// foreign issuer can never overwrite the active challenge.
func (s *RiskStore) FinalizeRegistrationChallenge(ctx context.Context, scopeHash, challengeHash string, record riskdefense.ChallengeRecord, ttl time.Duration) error {
	if s == nil || s.client == nil || s.client.rdb == nil || !validRiskKeyPart(scopeHash) || !validRiskKeyPart(challengeHash) || ttl < time.Millisecond {
		return errors.New("redis: invalid registration challenge finalize")
	}
	payload, err := json.Marshal(record)
	if err != nil {
		return fmt.Errorf("redis: encode registration challenge: %w", err)
	}
	n, err := riskFinalizeRegistrationChallengeScript.Run(ctx, s.client.rdb, []string{
		s.client.buildKey(riskRegistrationActiveChallengeSegment, scopeHash),
		s.client.buildKey(riskChallengeSegment, challengeHash),
	}, challengeHash, payload, ttl.Milliseconds()).Int()
	if err != nil {
		return fmt.Errorf("redis: finalize registration challenge: %w", err)
	}
	switch n {
	case 1:
		return nil
	case -1:
		return riskdefense.ErrChallengeNotHeld
	default:
		return errors.New("redis: duplicate risk challenge")
	}
}

// ReleaseRegistrationChallenge releases only the reservation held by the
// supplied challenge hash. It is used when provider setup or finalization
// fails before a challenge becomes visible to the caller.
func (s *RiskStore) ReleaseRegistrationChallenge(ctx context.Context, scopeHash, challengeHash string) error {
	if s == nil || s.client == nil || s.client.rdb == nil || !validRiskKeyPart(scopeHash) || !validRiskKeyPart(challengeHash) {
		return errors.New("redis: invalid registration challenge release")
	}
	n, err := riskReleaseScript.Run(ctx, s.client.rdb, []string{
		s.client.buildKey(riskRegistrationActiveChallengeSegment, scopeHash),
	}, challengeHash).Int()
	if err != nil {
		return fmt.Errorf("redis: release registration challenge: %w", err)
	}
	if n != 1 {
		return riskdefense.ErrChallengeNotHeld
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

var riskConsumeRegistrationChallengeScript = goredis.NewScript(`
local challengeKey = KEYS[1]
local claimKey = KEYS[2]
local activeKey = KEYS[3]
local claimOwner = ARGV[1]
local challengeOwner = ARGV[2]

if redis.call('GET', claimKey) ~= claimOwner then return 0 end
if redis.call('EXISTS', challengeKey) == 0 then
    redis.call('DEL', claimKey)
    if redis.call('GET', activeKey) == challengeOwner then
        redis.call('DEL', activeKey)
    end
    return -1
end

redis.call('DEL', challengeKey, claimKey)
if redis.call('GET', activeKey) == challengeOwner then
    redis.call('DEL', activeKey)
end
return 1
`)

// ConsumeRegistrationChallenge performs the normal claim-authorized consume
// and releases the active scope only when it is still owned by this exact
// challenge. A newer challenge in the same scope cannot be cleared by a stale
// completion.
func (s *RiskStore) ConsumeRegistrationChallenge(ctx context.Context, challengeHash, claimID, scopeHash string) error {
	if s == nil || s.client == nil || s.client.rdb == nil || !validRiskKeyPart(challengeHash) || claimID == "" || !validRiskKeyPart(scopeHash) {
		return errors.New("redis: invalid registration challenge consume")
	}
	n, err := riskConsumeRegistrationChallengeScript.Run(ctx, s.client.rdb, []string{
		s.client.buildKey(riskChallengeSegment, challengeHash),
		s.client.buildKey(riskChallengeClaimSegment, challengeHash),
		s.client.buildKey(riskRegistrationActiveChallengeSegment, scopeHash),
	}, claimID, challengeHash).Int()
	if err != nil {
		return fmt.Errorf("redis: consume registration challenge: %w", err)
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

// CheckRegistrationIssueRate advances device, trusted-network and global
// challenge-issuance budgets atomically. The global burst+sustained pair is
// the distributed ceiling when a caller rotates every scoped identifier.
func (s *RiskStore) CheckRegistrationIssueRate(ctx context.Context, deviceHash, networkHash string, policy riskdefense.RegistrationIssueRatePolicy) (bool, time.Duration, error) {
	if s == nil || s.client == nil || s.client.rdb == nil || !validRiskKeyPart(deviceHash) || !validRiskKeyPart(networkHash) {
		return false, policy.GlobalSustained.Window, errors.New("redis: invalid registration issue rate")
	}
	toRegistrationLimit := func(limit riskdefense.RateLimit) registration.Limit {
		return registration.Limit{Max: limit.Max, Window: limit.Window}
	}
	return NewRateLimiter(s.client).checkBuckets(ctx, []rateBucket{
		{key: s.client.buildKey(riskRegistrationIssueRateSegment, "device:", deviceHash), limit: toRegistrationLimit(policy.Device)},
		{key: s.client.buildKey(riskRegistrationIssueRateSegment, "network:", networkHash), limit: toRegistrationLimit(policy.Network)},
		{key: s.client.buildKey(riskRegistrationIssueRateSegment, "global:v1:burst"), limit: toRegistrationLimit(policy.GlobalBurst)},
		{key: s.client.buildKey(riskRegistrationIssueRateSegment, "global:v1:sustained"), limit: toRegistrationLimit(policy.GlobalSustained)},
	})
}

// CheckRegistrationCompletionRate is the aggregate proof-attempt budget. It
// is intentionally independent from the per-challenge completion counter so
// issuing another challenge cannot restore a fresh guess budget.
func (s *RiskStore) CheckRegistrationCompletionRate(ctx context.Context, deviceHash, networkHash string, deviceLimit, networkLimit int, window time.Duration) (bool, time.Duration, error) {
	return s.checkRegistrationScopeRate(ctx, riskRegistrationCompletionRateSegment, deviceHash, networkHash, deviceLimit, networkLimit, window)
}

// riskRegistrationScopeRateScript differs deliberately from the generic
// multi-key limiter: once either dimension is exhausted, it does not advance
// the other bucket. One already-blocked device therefore cannot burn the
// remaining quota of a shared school, office or carrier network.
var riskRegistrationScopeRateScript = goredis.NewScript(`
local deviceKey = KEYS[1]
local networkKey = KEYS[2]
local deviceLimit = tonumber(ARGV[1])
local networkLimit = tonumber(ARGV[2])
local windowMs = tonumber(ARGV[3])

local deviceCount = tonumber(redis.call('GET', deviceKey) or '0')
local networkCount = tonumber(redis.call('GET', networkKey) or '0')
if deviceCount >= deviceLimit or networkCount >= networkLimit then
    local retryMs = 0
    if deviceCount >= deviceLimit then
        local ttl = redis.call('PTTL', deviceKey)
        if ttl > retryMs then retryMs = ttl end
    end
    if networkCount >= networkLimit then
        local ttl = redis.call('PTTL', networkKey)
        if ttl > retryMs then retryMs = ttl end
    end
    if retryMs <= 0 then retryMs = windowMs end
    return {0, retryMs}
end

deviceCount = redis.call('INCR', deviceKey)
if deviceCount == 1 then redis.call('PEXPIRE', deviceKey, windowMs) end
networkCount = redis.call('INCR', networkKey)
if networkCount == 1 then redis.call('PEXPIRE', networkKey, windowMs) end
return {1, 0}
`)

func (s *RiskStore) checkRegistrationScopeRate(ctx context.Context, segment, deviceHash, networkHash string, deviceLimit, networkLimit int, window time.Duration) (bool, time.Duration, error) {
	if s == nil || s.client == nil || s.client.rdb == nil || (segment != riskRegistrationIssueRateSegment && segment != riskRegistrationCompletionRateSegment) || !validRiskKeyPart(deviceHash) || !validRiskKeyPart(networkHash) || deviceLimit <= 0 || networkLimit <= 0 || window < time.Millisecond {
		return false, window, errors.New("redis: invalid registration risk rate")
	}
	result, err := riskRegistrationScopeRateScript.Run(ctx, s.client.rdb, []string{
		s.client.buildKey(segment, "device:", deviceHash),
		s.client.buildKey(segment, "network:", networkHash),
	}, deviceLimit, networkLimit, window.Milliseconds()).Slice()
	if err != nil {
		return false, window, fmt.Errorf("redis: registration risk rate check: %w", err)
	}
	if len(result) != 2 {
		return false, window, fmt.Errorf("redis: registration risk rate returned %d values", len(result))
	}
	allowed, allowedOK := result[0].(int64)
	retryMs, retryOK := result[1].(int64)
	if !allowedOK || !retryOK || (allowed != 0 && allowed != 1) {
		return false, window, errors.New("redis: invalid registration risk rate result")
	}
	if allowed == 1 {
		return true, 0, nil
	}
	if retryMs <= 0 {
		return false, window, nil
	}
	return false, time.Duration(retryMs) * time.Millisecond, nil
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
