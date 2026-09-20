//
// Copyright (c) 2026 Chen Jiajie(Ariakage)
//
// Author: Chen Jiajie(Ariakage) <ariakage233@gmail.com>
// Date: 2026-08-05
// Description: Redis-backed rate limiter
//

package redis

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"time"

	goredis "github.com/redis/go-redis/v9"

	"github.com/GravelEvolution/united-pass/backend/internal/registration"
)

// rateLimitLoginSegment is the key segment for login rate limits. The full key
// is: {prefix}rl:login:{ip}:{sha256(identifier)}.
const rateLimitLoginSegment = "rl:login:"

// rateLimitMFASegment is the key segment for MFA rate limits. The full key is:
// {prefix}rl:mfa:{ip}:{sha256(mfaToken)}.
const rateLimitMFASegment = "rl:mfa:"

// rateLimitReauthSegment is the key segment for reauthentication rate limits.
// The full key is: {prefix}rl:reauth:{ip}:{sha256(key)}. The key component is
// a hashed session-user or challenge-token identifier; raw identifiers never
// appear in Redis keys.
const rateLimitReauthSegment = "rl:reauth:"

// rateLimitRotationSegment is the key segment for secret rotation rate
// limits. The full key is: {prefix}rl:rotate:{ip}:{sha256(clientId)}.
const rateLimitRotationSegment = "rl:rotate:"

// rateLimitContactSegment is retained for the backwards-compatible account
// contact-change routes. The value component is always a boundary-produced
// digest; raw email addresses, phone numbers and verification codes never
// enter Redis keys.
const rateLimitContactSegment = "rl:contact:"

const (
	rateLimitRegistrationFormIntentSegment = "rl:registration:form-intent:"
	rateLimitRegistrationCreateSegment     = "rl:registration:create:"
	rateLimitRegistrationVerifySegment     = "rl:registration:verify:"
	rateLimitRegistrationResendSegment     = "rl:registration:resend:"
	rateLimitRegistrationUnblockSegment    = "rl:registration:unblock:"
	rateLimitAccountEmailBeginSegment      = "rl:account:email-change:begin:"
	rateLimitAccountEmailVerifySegment     = "rl:account:email-change:verify:"
	rateLimitAccountPhoneChangeSegment     = "rl:account:phone-change:begin:"
	rateLimitWeChatLoginSegment            = "rl:wechat:login:"
	rateLimitWeChatPhoneSegment            = "rl:wechat:phone:"
	rateLimitQRAuthBeginSegment            = "rl:qr-auth:begin:"
	rateLimitDreamUPMobileSegment          = "rl:dreamup-mobile-assertion:"
)

// rateLimitScript atomically increments a rate-limit counter and sets the TTL
// on the first request in a window. It returns a two-element array:
//
//	{allowed (1 or 0), remaining_ttl_ms}
//
// allowed is 1 if the request is within the limit, 0 if it is exceeded. The
// TTL is the remaining time in the current window, which the caller uses as
// Retry-After. See ADR-0002 section 12.
var rateLimitScript = goredis.NewScript(`
local key      = KEYS[1]
local limit    = tonumber(ARGV[1])
local windowMs = tonumber(ARGV[2])

local count = redis.call('INCR', key)
if count == 1 then
	redis.call('PEXPIRE', key, windowMs)
end

local ttl = redis.call('PTTL', key)
if ttl < 0 then
	ttl = windowMs
end

if count > limit then
	return {0, ttl}
else
	return {1, ttl}
end
`)

// multiRateLimitScript advances all registration-creation buckets in one
// Redis operation. Every attempt consumes every applicable budget, so rotating
// email addresses cannot bypass the client-wide buckets and concurrent calls
// cannot observe a partially updated policy.
var multiRateLimitScript = goredis.NewScript(`
local allowed = 1
local retryMs = 0

for index, key in ipairs(KEYS) do
    local offset = (index - 1) * 2
    local limit = tonumber(ARGV[offset + 1])
    local windowMs = tonumber(ARGV[offset + 2])
    local count = redis.call('INCR', key)
    if count == 1 then
        redis.call('PEXPIRE', key, windowMs)
    end
    local ttl = redis.call('PTTL', key)
    if ttl < 0 then
        ttl = windowMs
    end
    if count > limit then
        allowed = 0
        if ttl > retryMs then
            retryMs = ttl
        end
    end
end

return {allowed, retryMs}
`)

// consumeWeChatRegistrationProofsScript atomically claims both one-time
// proof hashes so a failed pair cannot consume only one half.
var consumeWeChatRegistrationProofsScript = goredis.NewScript(`
local loginKey = KEYS[1]
local phoneKey = KEYS[2]
local windowMs = tonumber(ARGV[1])
local loginExists = redis.call('EXISTS', loginKey)
local phoneExists = redis.call('EXISTS', phoneKey)
if loginExists == 1 or phoneExists == 1 then
  local loginTTL = redis.call('PTTL', loginKey)
  local phoneTTL = redis.call('PTTL', phoneKey)
  local ttl = math.max(loginTTL, phoneTTL)
  if ttl < 0 then ttl = windowMs end
  return {0, ttl}
end
redis.call('PSETEX', loginKey, windowMs, '1')
redis.call('PSETEX', phoneKey, windowMs, '1')
return {1, 0}
`)

// RateLimiter implements fixed-window rate limiting using Redis. Each unique
// combination of IP and identifier hash gets a counter that resets when the
// window TTL expires. The limiter fails closed: if Redis is unavailable, all
// requests are denied.
type RateLimiter struct {
	client *Client
}

// NewRateLimiter builds a RateLimiter backed by the given Client.
func NewRateLimiter(client *Client) *RateLimiter {
	return &RateLimiter{client: client}
}

// CheckLogin checks the rate limit for a login attempt. The identifierHash
// must be the SHA-256 hash of the user-provided identifier (email, phone, or
// username); the raw identifier must never appear in the Redis key. The ip is
// included directly per ADR-0002 section 8.
//
// Returns:
//   - allowed: true if the request is within the limit.
//   - retryAfter: the remaining time in the current window (0 when allowed).
//   - err: non-nil only when Redis fails. When err is non-nil, allowed is
//     always false (fail closed) and retryAfter is the full window.
func (r *RateLimiter) CheckLogin(
	ctx context.Context,
	ip string,
	identifierHash string,
	limit int,
	window time.Duration,
) (allowed bool, retryAfter time.Duration, err error) {
	policy := registration.Limit{Max: limit, Window: window}
	return r.checkBuckets(ctx, []rateBucket{
		{key: r.client.buildKey(rateLimitLoginSegment, "ip:", ip), limit: policy},
		{key: r.client.buildKey(rateLimitLoginSegment, "account:", identifierHash), limit: policy},
		{key: r.client.buildKey(rateLimitLoginSegment, "pair:", ip, ":", identifierHash), limit: policy},
	})
}

// CheckMFA checks the rate limit for an MFA verification attempt. The
// mfaTokenHash must be the SHA-256 hash of the MFA token; the raw token must
// never appear in the Redis key. The ip is included directly per ADR-0002
// section 8.
//
// Returns the same semantics as CheckLogin.
func (r *RateLimiter) CheckMFA(
	ctx context.Context,
	ip string,
	mfaTokenHash string,
	limit int,
	window time.Duration,
) (allowed bool, retryAfter time.Duration, err error) {
	key := r.client.buildKey(rateLimitMFASegment, ip, ":", mfaTokenHash)
	return r.check(ctx, key, limit, window)
}

// CheckReauth checks the rate limit for a reauthentication attempt
// (ADR-0004 §7). The keyHash must be the SHA-256 hash of the session-user or
// challenge-token identifier; the raw value must never appear in the Redis
// key. Returns the same semantics as CheckLogin.
func (r *RateLimiter) CheckReauth(
	ctx context.Context,
	ip string,
	keyHash string,
	limit int,
	window time.Duration,
) (allowed bool, retryAfter time.Duration, err error) {
	key := r.client.buildKey(rateLimitReauthSegment, ip, ":", keyHash)
	return r.check(ctx, key, limit, window)
}

// CheckRotation checks the rate limit for an OAuth client secret rotation
// (ADR-0004 §6). The clientIDHash must be the SHA-256 hash of the target
// client ID. Returns the same semantics as CheckLogin.
func (r *RateLimiter) CheckRotation(
	ctx context.Context,
	ip string,
	clientIDHash string,
	limit int,
	window time.Duration,
) (allowed bool, retryAfter time.Duration, err error) {
	key := r.client.buildKey(rateLimitRotationSegment, ip, ":", clientIDHash)
	return r.check(ctx, key, limit, window)
}

// CheckContact enforces the legacy account contact-change budget without
// sharing counters with the newer email-change flow.
func (r *RateLimiter) CheckContact(
	ctx context.Context,
	ip string,
	keyHash string,
	limit int,
	window time.Duration,
) (allowed bool, retryAfter time.Duration, err error) {
	key := r.client.buildKey(rateLimitContactSegment, ip, ":", keyHash)
	return r.check(ctx, key, limit, window)
}

func (r *RateLimiter) CheckRegistrationCreate(ctx context.Context, ip, network, keyHash string, policy registration.CreateRatePolicy) (bool, time.Duration, error) {
	return r.checkBuckets(ctx, r.registrationCreateBuckets(ip, network, keyHash, policy))
}

func (r *RateLimiter) CheckRegistrationFormIntent(ctx context.Context, networkHash string, limit registration.Limit) (bool, time.Duration, error) {
	if r == nil || r.client == nil || networkHash == "" || limit.Max <= 0 || limit.Window <= 0 {
		return false, limit.Window, fmt.Errorf("redis: registration form-intent rate limiter unavailable")
	}
	key := r.registrationFormIntentKey(networkHash)
	return r.check(ctx, key, limit.Max, limit.Window)
}

func (r *RateLimiter) registrationFormIntentKey(networkHash string) string {
	return r.client.buildKey(rateLimitRegistrationFormIntentSegment, "net:", networkHash)
}

func (r *RateLimiter) registrationCreateBuckets(ip, network, keyHash string, policy registration.CreateRatePolicy) []rateBucket {
	return []rateBucket{
		{key: r.client.buildKey(rateLimitRegistrationCreateSegment, "ip:", ip), limit: policy.ClientIP},
		{key: r.client.buildKey(rateLimitRegistrationCreateSegment, "net:", network), limit: policy.ClientNet},
		{key: r.client.buildKey(rateLimitRegistrationCreateSegment, "email:", keyHash), limit: policy.Email},
		{key: r.client.buildKey(rateLimitRegistrationCreateSegment, "pair:", ip, ":", keyHash), limit: policy.ClientEmail},
	}
}

func (r *RateLimiter) ConsumeWeChatRegistrationProofs(ctx context.Context, loginCodeHash, phoneCodeHash string, window time.Duration) (bool, time.Duration, error) {
	if !isLowerSHA256Hex(loginCodeHash) || !isLowerSHA256Hex(phoneCodeHash) || window <= 0 || window/time.Millisecond <= 0 {
		return false, window, fmt.Errorf("redis: invalid WeChat registration proof input")
	}
	if r == nil || r.client == nil || r.client.rdb == nil {
		return false, window, fmt.Errorf("redis: WeChat registration proof store unavailable")
	}
	keys := []string{
		r.client.buildKey(rateLimitWeChatLoginSegment, "proof:", loginCodeHash),
		r.client.buildKey(rateLimitWeChatPhoneSegment, "proof:", phoneCodeHash),
	}
	result, err := consumeWeChatRegistrationProofsScript.Run(ctx, r.client.rdb, keys, int64(window/time.Millisecond)).Slice()
	if err != nil {
		return false, window, fmt.Errorf("redis: consume WeChat registration proofs: %w", err)
	}
	if len(result) != 2 {
		return false, window, fmt.Errorf("redis: WeChat registration proof script returned %d values", len(result))
	}
	allowed, ok := result[0].(int64)
	ttlMs, ttlOK := result[1].(int64)
	if !ok || !ttlOK || (allowed != 0 && allowed != 1) {
		return false, window, fmt.Errorf("redis: invalid WeChat registration proof script result")
	}
	if allowed == 1 {
		return true, 0, nil
	}
	if ttlMs <= 0 {
		return false, window, nil
	}
	return false, time.Duration(ttlMs) * time.Millisecond, nil
}

func isLowerSHA256Hex(value string) bool {
	if len(value) != 64 {
		return false
	}
	for i := 0; i < len(value); i++ {
		if (value[i] < '0' || value[i] > '9') && (value[i] < 'a' || value[i] > 'f') {
			return false
		}
	}
	return true
}

func (r *RateLimiter) CheckRegistrationVerify(ctx context.Context, ip, keyHash string, limit registration.Limit) (bool, time.Duration, error) {
	return r.check(ctx, r.client.buildKey(rateLimitRegistrationVerifySegment, ip, ":", keyHash), limit.Max, limit.Window)
}

func (r *RateLimiter) CheckRegistrationResend(ctx context.Context, ip, keyHash string, limit registration.Limit) (bool, time.Duration, error) {
	return r.check(ctx, r.client.buildKey(rateLimitRegistrationResendSegment, ip, ":", keyHash), limit.Max, limit.Window)
}

// CheckRegistrationBlockRevoke limits the internal recovery operation by the
// authenticated administrator. actorHash must be a lowercase SHA-256 digest;
// a stable user ID never appears in the Redis key. The dedicated segment keeps
// this budget independent from login and reauthentication attempts.
func (r *RateLimiter) CheckRegistrationBlockRevoke(ctx context.Context, actorHash string, limit int, window time.Duration) (bool, time.Duration, error) {
	if r == nil || r.client == nil || !isLowerSHA256(actorHash) || limit <= 0 || window <= 0 {
		return false, window, fmt.Errorf("redis: registration unblock rate limiter unavailable")
	}
	return r.check(ctx, r.registrationBlockRevokeKey(actorHash), limit, window)
}

func (r *RateLimiter) registrationBlockRevokeKey(actorHash string) string {
	return r.client.buildKey(rateLimitRegistrationUnblockSegment, "actor:", actorHash)
}

func isLowerSHA256(value string) bool {
	if len(value) != 64 {
		return false
	}
	for _, char := range value {
		if (char < '0' || char > '9') && (char < 'a' || char > 'f') {
			return false
		}
	}
	return true
}

type rateBucket struct {
	key   string
	limit registration.Limit
}

func (r *RateLimiter) checkBuckets(ctx context.Context, buckets []rateBucket) (bool, time.Duration, error) {
	if r == nil || r.client == nil || len(buckets) == 0 {
		return false, 0, fmt.Errorf("redis: registration rate limiter unavailable")
	}
	keys := make([]string, 0, len(buckets))
	arguments := make([]any, 0, len(buckets)*2)
	var fallback time.Duration
	for _, bucket := range buckets {
		if bucket.key == "" || bucket.limit.Max <= 0 || bucket.limit.Window <= 0 {
			return false, fallback, fmt.Errorf("redis: invalid registration rate bucket")
		}
		keys = append(keys, bucket.key)
		arguments = append(arguments, bucket.limit.Max, int64(bucket.limit.Window/time.Millisecond))
		if bucket.limit.Window > fallback {
			fallback = bucket.limit.Window
		}
	}
	result, err := multiRateLimitScript.Run(ctx, r.client.rdb, keys, arguments...).Slice()
	if err != nil {
		return false, fallback, fmt.Errorf("redis: registration rate limit check: %w", err)
	}
	if len(result) != 2 {
		return false, fallback, fmt.Errorf("redis: registration rate limit script returned %d values, expected 2", len(result))
	}
	allowedValue, ok := result[0].(int64)
	if !ok {
		return false, fallback, fmt.Errorf("redis: registration rate limit script returned unexpected allowed type %T", result[0])
	}
	retryValue, ok := result[1].(int64)
	if !ok {
		return false, fallback, fmt.Errorf("redis: registration rate limit script returned unexpected retry type %T", result[1])
	}
	if allowedValue == 1 {
		return true, 0, nil
	}
	retry := time.Duration(retryValue) * time.Millisecond
	if retry <= 0 {
		retry = fallback
	}
	return false, retry, nil
}

func (r *RateLimiter) CheckAccountEmailChangeBegin(ctx context.Context, ip, keyHash string, limit int, window time.Duration) (bool, time.Duration, error) {
	return r.checkBuckets(ctx, r.accountContactChangeBuckets(rateLimitAccountEmailBeginSegment, ip, keyHash, limit, window))
}

func (r *RateLimiter) CheckAccountEmailChangeVerify(ctx context.Context, ip, keyHash string, limit int, window time.Duration) (bool, time.Duration, error) {
	return r.checkBuckets(ctx, r.accountContactChangeBuckets(rateLimitAccountEmailVerifySegment, ip, keyHash, limit, window))
}

func (r *RateLimiter) CheckAccountPhoneChangeBegin(ctx context.Context, ip, keyHash string, limit int, window time.Duration) (bool, time.Duration, error) {
	return r.checkBuckets(ctx, r.accountContactChangeBuckets(rateLimitAccountPhoneChangeSegment, ip, keyHash, limit, window))
}

func (r *RateLimiter) accountContactChangeBuckets(segment, ip, keyHash string, limit int, window time.Duration) []rateBucket {
	policy := registration.Limit{Max: limit, Window: window}
	return []rateBucket{
		{key: r.client.buildKey(segment, "user:", keyHash), limit: policy},
		{key: r.client.buildKey(segment, "ip:", ip), limit: policy},
		{key: r.client.buildKey(segment, "pair:", ip, ":", keyHash), limit: policy},
	}
}

func (r *RateLimiter) CheckWeChatLogin(ctx context.Context, ip, keyHash string, limit int, window time.Duration) (bool, time.Duration, error) {
	return r.checkWeChatProof(ctx, rateLimitWeChatLoginSegment, ip, keyHash, limit, window)
}

func (r *RateLimiter) CheckWeChatPhone(ctx context.Context, ip, keyHash string, limit int, window time.Duration) (bool, time.Duration, error) {
	return r.checkWeChatProof(ctx, rateLimitWeChatPhoneSegment, ip, keyHash, limit, window)
}

func (r *RateLimiter) checkWeChatProof(ctx context.Context, segment, ip, keyHash string, limit int, window time.Duration) (bool, time.Duration, error) {
	if !isLowerSHA256Hex(keyHash) {
		return false, window, fmt.Errorf("redis: invalid WeChat proof hash")
	}
	return r.checkBuckets(ctx, []rateBucket{
		{key: r.client.buildKey(segment, "ip:", ip), limit: registration.Limit{Max: limit, Window: window}},
		{key: r.client.buildKey(segment, "proof:", keyHash), limit: registration.Limit{Max: 1, Window: window}},
	})
}

func (r *RateLimiter) CheckQRAuthBegin(ctx context.Context, ip string, limit int, window time.Duration) (bool, time.Duration, error) {
	return r.check(ctx, r.client.buildKey(rateLimitQRAuthBeginSegment, ip), limit, window)
}

// CheckDreamUPMobileAssertion atomically advances a session-bound scope and a
// process-wide scope shared by both participant assertion endpoints. The
// subject tuple is hashed before it reaches Redis so user and session IDs are
// never embedded in keys. Any Redis/script failure is returned to the handler,
// which fails closed.
func (r *RateLimiter) CheckDreamUPMobileAssertion(ctx context.Context, userID, sessionID, ip string, scopedLimit, globalLimit int, window time.Duration) (bool, time.Duration, error) {
	if r == nil || r.client == nil || userID == "" || sessionID == "" || ip == "" {
		return false, window, fmt.Errorf("redis: DreamUP Mobile assertion rate limiter unavailable")
	}
	digest := sha256.Sum256([]byte("user\x00" + userID + "\x00session\x00" + sessionID + "\x00ip\x00" + ip))
	scope := hex.EncodeToString(digest[:])
	return r.checkBuckets(ctx, []rateBucket{
		{key: r.client.buildKey(rateLimitDreamUPMobileSegment, "scope:", scope), limit: registration.Limit{Max: scopedLimit, Window: window}},
		{key: r.client.buildKey(rateLimitDreamUPMobileSegment, "global"), limit: registration.Limit{Max: globalLimit, Window: window}},
	})
}

// check executes the rate-limit Lua script against the given key. It is the
// shared implementation for CheckLogin and CheckMFA. On any Redis error, it
// returns allowed=false with the full window as retryAfter (fail closed).
func (r *RateLimiter) check(
	ctx context.Context,
	key string,
	limit int,
	window time.Duration,
) (allowed bool, retryAfter time.Duration, err error) {
	windowMs := int64(window / time.Millisecond)

	result, runErr := rateLimitScript.Run(ctx, r.client.rdb,
		[]string{key},
		limit, windowMs,
	).Slice()
	if runErr != nil {
		// Fail closed: deny the request when Redis is unavailable. Return
		// the full window as retryAfter so the caller can set a conservative
		// Retry-After header.
		return false, window, fmt.Errorf("redis: rate limit check: %w", runErr)
	}

	if len(result) != 2 {
		return false, window, fmt.Errorf("redis: rate limit script returned %d values, expected 2", len(result))
	}

	allowedVal, ok := result[0].(int64)
	if !ok {
		return false, window, fmt.Errorf("redis: rate limit script returned unexpected allowed type %T", result[0])
	}
	ttlMs, ok := result[1].(int64)
	if !ok {
		return false, window, fmt.Errorf("redis: rate limit script returned unexpected ttl type %T", result[1])
	}

	allowed = allowedVal == 1
	retryAfter = time.Duration(ttlMs) * time.Millisecond
	if retryAfter < 0 {
		retryAfter = window
	}
	if allowed {
		retryAfter = 0
	}
	return allowed, retryAfter, nil
}
