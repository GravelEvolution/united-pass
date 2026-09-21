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
	"sort"
	"strings"
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

const (
	rateLimitRegistrationFormIntentSegment       = "rl:registration:form-intent:"
	rateLimitRegistrationFormIntentDeviceSegment = "rl:registration:form-intent:device:v1:"
	rateLimitRegistrationFormIntentGlobalSegment = "rl:registration:form-intent:global:v1:"
	rateLimitRegistrationCreateSegment           = "rl:registration:create:"
	// Keep the email bucket in its own versioned namespace. The v2 cutover
	// retires false-positive 24-hour locks created by conflicts before refunds
	// existed, without resetting the client, network or pair safeguards.
	rateLimitRegistrationCreateEmailSegment   = "rl:registration:create:email:v2:"
	rateLimitRegistrationCreateMailboxSegment = "rl:registration:create:mailbox-family:v1:"
	rateLimitRegistrationCreateChainSegment   = "rl:registration:create-chain:v5:"
	rateLimitRegistrationCreateGlobalSegment  = "rl:registration:create:global:v1:"
	rateLimitRegistrationCreateDomainSegment  = "rl:registration:create:domain:v1:"
	rateLimitRegistrationCreateMXSegment      = "rl:registration:create:mx:v1:"
	rateLimitRegistrationVerifySegment        = "rl:registration:verify:"
	rateLimitRegistrationVerifyGlobalSegment  = "rl:registration:verify:global:v1:"
	rateLimitRegistrationResendSegment        = "rl:registration:resend:"
	rateLimitRegistrationUnblockSegment       = "rl:registration:unblock:"
	rateLimitAccountEmailBeginSegment         = "rl:account:email-change:begin:"
	rateLimitAccountEmailVerifySegment        = "rl:account:email-change:verify:"
	rateLimitAccountPhoneChangeSegment        = "rl:account:phone-change:begin:"
	rateLimitWeChatLoginSegment               = "rl:wechat:login:"
	rateLimitWeChatPhoneSegment               = "rl:wechat:phone:"
	rateLimitWeChatRegistrationProofSegment   = "rl:wechat:registration-proof:"
	rateLimitQRAuthBeginSegment               = "rl:qr-auth:begin:"
	rateLimitDreamUPMobileSegment             = "rl:dreamup-mobile-assertion:"
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
// Redis operation. It validates and checks every bucket before incrementing
// any of them, so a saturated shared bucket cannot poison otherwise unrelated
// long-lived budgets. Allowed attempts still consume every applicable budget,
// so rotating email addresses cannot bypass the client-wide buckets.
var multiRateLimitScript = goredis.NewScript(`
local allowed = 1
local retryMs = 0

for index, key in ipairs(KEYS) do
    local offset = (index - 1) * 2
    local limit = tonumber(ARGV[offset + 1])
    local windowMs = tonumber(ARGV[offset + 2])
    local rawCount = redis.call('GET', key)
    local count = 0
    if rawCount then
        if not string.match(rawCount, '^[1-9][0-9]*$') or
           string.len(rawCount) > 19 or
           (string.len(rawCount) == 19 and rawCount > '9223372036854775807') then
            return redis.error_reply('INVALID_REGISTRATION_CREATE_RATE')
        end
        count = tonumber(rawCount)
        local ttl = redis.call('PTTL', key)
        if ttl < 0 then
            return redis.error_reply('INVALID_REGISTRATION_CREATE_TTL')
        end
        if count >= limit then
            allowed = 0
            if ttl > retryMs then
                retryMs = ttl
            end
        end
    end
end

if allowed == 0 then
    return {0, retryMs}
end

for index, key in ipairs(KEYS) do
    local offset = (index - 1) * 2
    local windowMs = tonumber(ARGV[offset + 2])
    local count = redis.call('INCR', key)
    if count == 1 then
        redis.call('PEXPIRE', key, windowMs)
    end
end

return {1, 0}
`)

// registrationCreateChainScript charges all ordinary registration-create
// buckets exactly once for one browser form intent. It first checks every
// bucket and only charges them when the whole request is allowed. This keeps a
// saturated shared client/network bucket from consuming a caller's long-lived
// email budget. A second request with the same network/email binding is the
// sole free replay used after a completed risk challenge. The marker is keyed
// by a SHA-256 form-intent digest and stores only a SHA-256 binding digest; raw
// form tokens and email addresses never reach Redis. Every branch is atomic,
// including concurrent retries.
var registrationCreateChainScript = goredis.NewScript(`
local markerKey = KEYS[1]
local binding = ARGV[1]
local markerTTL = tonumber(ARGV[2])
local existing = redis.call('HMGET', markerKey, 'binding', 'uses')

if existing[1] then
    local ttl = redis.call('PTTL', markerKey)
    if ttl < 0 then ttl = markerTTL end
    if existing[1] ~= binding then
        return {-1, ttl}
    end
    if existing[2] ~= '1' and existing[2] ~= '2' then
        return {-3, ttl}
    end
    if existing[2] ~= '1' then
        return {-2, ttl}
    end
    redis.call('HSET', markerKey, 'uses', '2')
    return {2, 0}
end

local allowed = 1
local retryMs = 0
for index = 2, #KEYS do
    local offset = 3 + ((index - 2) * 2)
    local limit = tonumber(ARGV[offset])
    local windowMs = tonumber(ARGV[offset + 1])
    local rawCount = redis.call('GET', KEYS[index])
    local count = 0
    if rawCount then
        if not string.match(rawCount, '^[1-9][0-9]*$') or
           string.len(rawCount) > 19 or
           (string.len(rawCount) == 19 and rawCount > '9223372036854775807') then
            return redis.error_reply('INVALID_REGISTRATION_CREATE_RATE')
        end
        count = tonumber(rawCount)
        local ttl = redis.call('PTTL', KEYS[index])
        if ttl < 0 then
            return redis.error_reply('INVALID_REGISTRATION_CREATE_TTL')
        end
        if count >= limit then
            allowed = 0
            if ttl > retryMs then retryMs = ttl end
        end
    end
end

if allowed == 0 then return {0, retryMs} end

for index = 2, #KEYS do
    local offset = 3 + ((index - 2) * 2)
    local windowMs = tonumber(ARGV[offset + 1])
    local count = redis.call('INCR', KEYS[index])
    if count == 1 then
        redis.call('PEXPIRE', KEYS[index], windowMs)
    end
end

redis.call('HSET', markerKey, 'binding', binding, 'uses', '1')
redis.call('PEXPIRE', markerKey, markerTTL)
return {1, 0}
`)

// refundRegistrationCreateEmailScript releases only the long-lived email
// budget after the authoritative registration service reports a conflict. It
// verifies the exact form-intent binding and records the refund on that marker
// so duplicate error handling can never decrement the bucket twice. Shorter
// IP, network and IP/email budgets deliberately remain charged.
var refundRegistrationCreateEmailScript = goredis.NewScript(`
local markerKey = KEYS[1]
local binding = ARGV[1]

if redis.call('HGET', markerKey, 'binding') ~= binding then
    return 0
end
if redis.call('HGET', markerKey, 'email_refunded') == '1' then
    return 0
end

-- Redis scripts are atomic but are not transactional: an error does not roll
-- back earlier writes. Validate every counter and TTL before setting the
-- marker or touching any counter so one corrupt later cohort key cannot cause
-- a partial refund.
local counts = {}
for index = 2, #KEYS do
    counts[index] = 0
    local rawCount = redis.call('GET', KEYS[index])
    if rawCount then
        -- DECR accepts only canonical signed 64-bit integers. Validate that
        -- exact grammar and range up front; tonumber alone would accept forms
        -- such as "1e3" and could let DECR fail after earlier writes.
        if not string.match(rawCount, '^[1-9][0-9]*$') or
           string.len(rawCount) > 19 or
           (string.len(rawCount) == 19 and rawCount > '9223372036854775807') then
            return redis.error_reply('INVALID_REGISTRATION_EMAIL_RATE')
        end
        if redis.call('PTTL', KEYS[index]) < 0 then
            return redis.error_reply('INVALID_REGISTRATION_EMAIL_TTL')
        end
        counts[index] = rawCount
    end
end

redis.call('HSET', markerKey, 'email_refunded', '1')
local changed = 0
for index = 2, #KEYS do
    local count = counts[index]
    if count ~= 0 then
        if count == '1' then
            redis.call('DEL', KEYS[index])
        else
            redis.call('DECR', KEYS[index])
        end
        changed = 1
    end
end
return changed
`)

// claimWeChatRegistrationProofsScript first advances a dedicated source-IP
// budget and only then atomically claims both global one-time proof hashes. A
// source already over budget cannot create attacker-selected per-code keys.
var claimWeChatRegistrationProofsScript = goredis.NewScript(`
local ipKey = KEYS[1]
local loginKey = KEYS[2]
local phoneKey = KEYS[3]
local limit = tonumber(ARGV[1])
local windowMs = tonumber(ARGV[2])

local count = redis.call('INCR', ipKey)
if count == 1 then
  redis.call('PEXPIRE', ipKey, windowMs)
end
local ipTTL = redis.call('PTTL', ipKey)
if ipTTL < 0 then ipTTL = windowMs end
if count > limit then
  return {0, ipTTL}
end

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

func (r *RateLimiter) CheckRegistrationCreate(ctx context.Context, ip, network, keyHash string, policy registration.CreateRatePolicy) (bool, time.Duration, error) {
	return r.checkBuckets(ctx, r.registrationCreateBuckets(ip, network, keyHash, policy))
}

// CheckRegistrationCreateChain preserves the ordinary create-rate semantics
// for the first browser request while making exactly one risk-challenge replay
// idempotent. Direct WeChat registration and onboarding continue to call
// CheckRegistrationCreate and therefore do not receive this replay allowance.
func (r *RateLimiter) CheckRegistrationCreateChain(
	ctx context.Context,
	ip, network, emailHash, formIntentHash string,
	policy registration.CreateRatePolicy,
	markerTTL time.Duration,
) (registration.CreateChainRateOutcome, time.Duration, error) {
	return r.CheckRegistrationCreateChainWithCohorts(ctx, registration.CreateRateSubject{
		ClientIP: ip, ClientNetwork: network, EmailHash: emailHash, FormIntentHash: formIntentHash,
	}, policy, markerTTL)
}

// CheckRegistrationCreateChainWithCohorts extends the exact browser-chain
// transaction with global, unfamiliar-domain and unfamiliar-MX budgets. Empty
// cohort hashes intentionally omit only their corresponding optional buckets.
func (r *RateLimiter) CheckRegistrationCreateChainWithCohorts(
	ctx context.Context,
	subject registration.CreateRateSubject,
	policy registration.CreateRatePolicy,
	markerTTL time.Duration,
) (registration.CreateChainRateOutcome, time.Duration, error) {
	if r == nil || r.client == nil || r.client.rdb == nil || subject.ClientIP == "" || subject.ClientNetwork == "" ||
		!isLowerSHA256Hex(subject.EmailHash) || !isLowerSHA256Hex(subject.FormIntentHash) ||
		(subject.MailboxFamilyHash != "" && !isLowerSHA256Hex(subject.MailboxFamilyHash)) ||
		(subject.DomainHash != "" && !isLowerSHA256Hex(subject.DomainHash)) ||
		markerTTL <= 0 || markerTTL/time.Millisecond <= 0 {
		return registration.CreateChainRateUnknown, markerTTL, fmt.Errorf("redis: registration create-chain limiter unavailable")
	}
	var err error
	subject, err = normalizeRegistrationCreateMXCohorts(subject)
	if err != nil {
		return registration.CreateChainRateUnknown, markerTTL, fmt.Errorf("redis: registration create-chain limiter unavailable: %w", err)
	}
	buckets, err := r.registrationCreateBucketsWithCohorts(subject, policy)
	if err != nil {
		return registration.CreateChainRateUnknown, markerTTL, err
	}
	keys := make([]string, 0, len(buckets)+1)
	keys = append(keys, r.registrationCreateChainKey(subject.FormIntentHash))
	arguments := make([]any, 0, 2+len(buckets)*2)
	arguments = append(arguments, registrationCreateChainCohortBinding(subject), int64(markerTTL/time.Millisecond))
	var fallback time.Duration
	for _, bucket := range buckets {
		if bucket.key == "" || bucket.limit.Max <= 0 || bucket.limit.Window <= 0 || bucket.limit.Window/time.Millisecond <= 0 {
			return registration.CreateChainRateUnknown, fallback, fmt.Errorf("redis: invalid registration create-chain bucket")
		}
		keys = append(keys, bucket.key)
		arguments = append(arguments, bucket.limit.Max, int64(bucket.limit.Window/time.Millisecond))
		if bucket.limit.Window > fallback {
			fallback = bucket.limit.Window
		}
	}
	result, err := registrationCreateChainScript.Run(ctx, r.client.rdb, keys, arguments...).Slice()
	if err != nil {
		return registration.CreateChainRateUnknown, fallback, fmt.Errorf("redis: registration create-chain check: %w", err)
	}
	if len(result) != 2 {
		return registration.CreateChainRateUnknown, fallback, fmt.Errorf("redis: registration create-chain script returned %d values, expected 2", len(result))
	}
	code, ok := result[0].(int64)
	if !ok {
		return registration.CreateChainRateUnknown, fallback, fmt.Errorf("redis: registration create-chain script returned unexpected outcome type %T", result[0])
	}
	retryMilliseconds, ok := result[1].(int64)
	if !ok {
		return registration.CreateChainRateUnknown, fallback, fmt.Errorf("redis: registration create-chain script returned unexpected retry type %T", result[1])
	}
	retryAfter := time.Duration(retryMilliseconds) * time.Millisecond
	switch code {
	case 1:
		return registration.CreateChainRateFirstAllowed, 0, nil
	case 2:
		return registration.CreateChainRateReplayAllowed, 0, nil
	case 0:
		if retryAfter <= 0 {
			retryAfter = fallback
		}
		return registration.CreateChainRateLimited, retryAfter, nil
	case -1:
		return registration.CreateChainRateBindingMismatch, retryAfter, nil
	case -2:
		return registration.CreateChainRateReplayExhausted, retryAfter, nil
	default:
		return registration.CreateChainRateUnknown, fallback, fmt.Errorf("redis: registration create-chain script returned invalid outcome %d", code)
	}
}

// RefundRegistrationCreateEmail releases the long-lived email bucket for one
// exact, already-charged browser registration chain. A missing or mismatched
// marker is ignored rather than turning this method into a generic decrement
// primitive.
func (r *RateLimiter) RefundRegistrationCreateEmail(ctx context.Context, network, emailHash, formIntentHash string) (bool, error) {
	return r.RefundRegistrationCreateCohorts(ctx, registration.CreateRateSubject{
		ClientNetwork: network, EmailHash: emailHash, FormIntentHash: formIntentHash,
	}, registration.CreateRatePolicy{})
}

// RefundRegistrationCreateCohorts releases only shared email/domain/MX
// budgets when the authoritative repository reports an existing account.
// Client, network and global pressure budgets remain charged.
func (r *RateLimiter) RefundRegistrationCreateCohorts(ctx context.Context, subject registration.CreateRateSubject, policy registration.CreateRatePolicy) (bool, error) {
	if r == nil || r.client == nil || r.client.rdb == nil || subject.ClientNetwork == "" ||
		!isLowerSHA256Hex(subject.EmailHash) || !isLowerSHA256Hex(subject.FormIntentHash) ||
		(subject.MailboxFamilyHash != "" && !isLowerSHA256Hex(subject.MailboxFamilyHash)) ||
		(subject.DomainHash != "" && !isLowerSHA256Hex(subject.DomainHash)) {
		return false, fmt.Errorf("redis: invalid registration email-rate refund")
	}
	var err error
	subject, err = normalizeRegistrationCreateMXCohorts(subject)
	if err != nil {
		return false, fmt.Errorf("redis: invalid registration email-rate refund: %w", err)
	}
	keys := []string{r.registrationCreateChainKey(subject.FormIntentHash), r.registrationCreateEmailKey(subject.EmailHash)}
	if subject.MailboxFamilyHash != "" {
		keys = append(keys, r.registrationCreateMailboxFamilyKey(subject.MailboxFamilyHash))
	}
	if subject.DomainHash != "" {
		keys = append(keys, r.registrationDomainKeys(subject.DomainHash, policy.UnfamiliarDomain)...)
	}
	for _, mxHash := range subject.MXHashes {
		keys = append(keys, r.registrationMXKeys(mxHash, policy.UnfamiliarMX)...)
	}
	result, err := refundRegistrationCreateEmailScript.Run(ctx, r.client.rdb, keys, registrationCreateChainCohortBinding(subject)).Int()
	if err != nil {
		return false, fmt.Errorf("redis: refund registration email rate: %w", err)
	}
	if result != 0 && result != 1 {
		return false, fmt.Errorf("redis: invalid registration email-rate refund result %d", result)
	}
	return result == 1, nil
}

func (r *RateLimiter) CheckRegistrationFormIntent(ctx context.Context, networkHash string, limit registration.Limit) (bool, time.Duration, error) {
	if r == nil || r.client == nil || networkHash == "" || limit.Max <= 0 || limit.Window <= 0 {
		return false, limit.Window, fmt.Errorf("redis: registration form-intent rate limiter unavailable")
	}
	key := r.registrationFormIntentKey(networkHash)
	return r.check(ctx, key, limit.Max, limit.Window)
}

// CheckRegistrationFormIntentGlobal applies the trusted-network and global
// admission budgets in one Redis transaction before a device or form-intent
// record is allocated. The global pair is the hard ceiling when a caller
// rotates proxy addresses and cookies on every request.
func (r *RateLimiter) CheckRegistrationFormIntentGlobal(ctx context.Context, networkHash string, network registration.Limit, global registration.AggregateRatePolicy) (bool, time.Duration, error) {
	if r == nil || r.client == nil || !isLowerSHA256Hex(networkHash) {
		return false, network.Window, fmt.Errorf("redis: registration form-intent global limiter unavailable")
	}
	buckets := []rateBucket{{key: r.registrationFormIntentKey(networkHash), limit: network}}
	var err error
	buckets, err = appendAggregateBuckets(buckets, []string{
		r.client.buildKey(rateLimitRegistrationFormIntentGlobalSegment, "burst"),
		r.client.buildKey(rateLimitRegistrationFormIntentGlobalSegment, "sustained"),
	}, global)
	if err != nil {
		return false, network.Window, fmt.Errorf("redis: invalid registration form-intent global policy")
	}
	return r.checkBuckets(ctx, buckets)
}

// CheckRegistrationFormIntentDevice is evaluated after EnsureDevice. Keeping
// it separate lets the global limiter run before any attacker-controlled
// per-device Redis key is created.
func (r *RateLimiter) CheckRegistrationFormIntentDevice(ctx context.Context, deviceHash string, limit registration.Limit) (bool, time.Duration, error) {
	if r == nil || r.client == nil || !isLowerSHA256Hex(deviceHash) {
		return false, limit.Window, fmt.Errorf("redis: registration form-intent device limiter unavailable")
	}
	return r.checkBuckets(ctx, []rateBucket{{
		key:   r.client.buildKey(rateLimitRegistrationFormIntentDeviceSegment, deviceHash),
		limit: limit,
	}})
}

func (r *RateLimiter) registrationFormIntentKey(networkHash string) string {
	return r.client.buildKey(rateLimitRegistrationFormIntentSegment, "net:", networkHash)
}

func (r *RateLimiter) registrationCreateBuckets(ip, network, keyHash string, policy registration.CreateRatePolicy) []rateBucket {
	return []rateBucket{
		{key: r.client.buildKey(rateLimitRegistrationCreateSegment, "ip:", ip), limit: policy.ClientIP},
		{key: r.client.buildKey(rateLimitRegistrationCreateSegment, "net:", network), limit: policy.ClientNet},
		{key: r.registrationCreateEmailKey(keyHash), limit: policy.Email},
		{key: r.client.buildKey(rateLimitRegistrationCreateSegment, "pair:", ip, ":", keyHash), limit: policy.ClientEmail},
	}
}

func (r *RateLimiter) registrationCreateBucketsWithCohorts(subject registration.CreateRateSubject, policy registration.CreateRatePolicy) ([]rateBucket, error) {
	var err error
	subject, err = normalizeRegistrationCreateMXCohorts(subject)
	if err != nil {
		return nil, fmt.Errorf("redis: invalid registration MX cohorts: %w", err)
	}
	buckets := r.registrationCreateBuckets(subject.ClientIP, subject.ClientNetwork, subject.EmailHash, policy)
	if subject.MailboxFamilyHash != "" {
		if policy.MailboxFamily.Max <= 0 || policy.MailboxFamily.Window <= 0 {
			return nil, fmt.Errorf("redis: invalid registration mailbox-family rate policy")
		}
		buckets = append(buckets, rateBucket{key: r.registrationCreateMailboxFamilyKey(subject.MailboxFamilyHash), limit: policy.MailboxFamily})
	}
	buckets, err = appendAggregateBuckets(buckets, r.registrationGlobalKeys(), policy.Global)
	if err != nil {
		return nil, fmt.Errorf("redis: invalid registration global rate policy")
	}
	if subject.DomainHash != "" {
		buckets, err = appendAggregateBuckets(buckets, r.registrationDomainKeys(subject.DomainHash, policy.UnfamiliarDomain), policy.UnfamiliarDomain)
		if err != nil {
			return nil, fmt.Errorf("redis: invalid registration domain rate policy")
		}
	}
	for _, mxHash := range subject.MXHashes {
		buckets, err = appendAggregateBuckets(buckets, r.registrationMXKeys(mxHash, policy.UnfamiliarMX), policy.UnfamiliarMX)
		if err != nil {
			return nil, fmt.Errorf("redis: invalid registration MX rate policy")
		}
	}
	return buckets, nil
}

func appendAggregateBuckets(existing []rateBucket, keys []string, policy registration.AggregateRatePolicy) ([]rateBucket, error) {
	if policy.Burst.Max == 0 && policy.Burst.Window == 0 && policy.Sustained.Max == 0 && policy.Sustained.Window == 0 {
		return existing, nil
	}
	if len(keys) != 2 || policy.Burst.Max <= 0 || policy.Burst.Window <= 0 || policy.Sustained.Max <= 0 || policy.Sustained.Window <= 0 {
		return nil, fmt.Errorf("invalid aggregate policy")
	}
	return append(existing,
		rateBucket{key: keys[0], limit: policy.Burst},
		rateBucket{key: keys[1], limit: policy.Sustained},
	), nil
}

func (r *RateLimiter) registrationGlobalKeys() []string {
	return []string{
		r.client.buildKey(rateLimitRegistrationCreateGlobalSegment, "burst"),
		r.client.buildKey(rateLimitRegistrationCreateGlobalSegment, "sustained"),
	}
}

func (r *RateLimiter) registrationDomainKeys(domainHash string, _ registration.AggregateRatePolicy) []string {
	return []string{
		r.client.buildKey(rateLimitRegistrationCreateDomainSegment, "burst:", domainHash),
		r.client.buildKey(rateLimitRegistrationCreateDomainSegment, "sustained:", domainHash),
	}
}

func (r *RateLimiter) registrationMXKeys(mxHash string, _ registration.AggregateRatePolicy) []string {
	return []string{
		r.client.buildKey(rateLimitRegistrationCreateMXSegment, "burst:", mxHash),
		r.client.buildKey(rateLimitRegistrationCreateMXSegment, "sustained:", mxHash),
	}
}

func (r *RateLimiter) registrationCreateEmailKey(emailHash string) string {
	return r.client.buildKey(rateLimitRegistrationCreateEmailSegment, emailHash)
}

func (r *RateLimiter) registrationCreateMailboxFamilyKey(familyHash string) string {
	return r.client.buildKey(rateLimitRegistrationCreateMailboxSegment, familyHash)
}

func (r *RateLimiter) registrationCreateChainKey(formIntentHash string) string {
	return r.client.buildKey(rateLimitRegistrationCreateChainSegment, "intent:", formIntentHash)
}

func registrationCreateChainBinding(network, emailHash string) string {
	return registrationCreateChainCohortBinding(registration.CreateRateSubject{ClientNetwork: network, EmailHash: emailHash})
}

func registrationCreateChainCohortBinding(subject registration.CreateRateSubject) string {
	mxHashes := append([]string(nil), subject.MXHashes...)
	sort.Strings(mxHashes)
	digest := sha256.Sum256([]byte("network\x00" + subject.ClientNetwork + "\x00email\x00" + subject.EmailHash +
		"\x00mailbox-family\x00" + subject.MailboxFamilyHash + "\x00domain\x00" + subject.DomainHash +
		"\x00mx\x00" + strings.Join(mxHashes, "\x00")))
	return hex.EncodeToString(digest[:])
}

func normalizeRegistrationCreateMXCohorts(subject registration.CreateRateSubject) (registration.CreateRateSubject, error) {
	if len(subject.MXHashes) > registration.MaxCreateRateMXCohorts {
		return registration.CreateRateSubject{}, fmt.Errorf("too many MX cohorts")
	}
	mxHashes := append([]string(nil), subject.MXHashes...)
	for _, mxHash := range mxHashes {
		if !isLowerSHA256Hex(mxHash) {
			return registration.CreateRateSubject{}, fmt.Errorf("invalid MX cohort hash")
		}
	}
	sort.Strings(mxHashes)
	for index := 1; index < len(mxHashes); index++ {
		if mxHashes[index] == mxHashes[index-1] {
			return registration.CreateRateSubject{}, fmt.Errorf("duplicate MX cohort hash")
		}
	}
	subject.MXHashes = mxHashes
	return subject, nil
}

func (r *RateLimiter) ClaimWeChatRegistrationProofs(ctx context.Context, ip, loginCodeHash, phoneCodeHash string, limit int, window time.Duration) (bool, time.Duration, error) {
	if ip == "" || !isLowerSHA256Hex(loginCodeHash) || !isLowerSHA256Hex(phoneCodeHash) || limit <= 0 || window <= 0 || window/time.Millisecond <= 0 {
		return false, window, fmt.Errorf("redis: invalid WeChat registration proof input")
	}
	if r == nil || r.client == nil || r.client.rdb == nil {
		return false, window, fmt.Errorf("redis: WeChat registration proof store unavailable")
	}
	keys := r.wechatRegistrationProofKeys(ip, loginCodeHash, phoneCodeHash)
	result, err := claimWeChatRegistrationProofsScript.Run(ctx, r.client.rdb, keys, limit, int64(window/time.Millisecond)).Slice()
	if err != nil {
		return false, window, fmt.Errorf("redis: claim WeChat registration proofs: %w", err)
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

func (r *RateLimiter) wechatRegistrationProofKeys(ip, loginCodeHash, phoneCodeHash string) []string {
	return []string{
		r.client.buildKey(rateLimitWeChatRegistrationProofSegment, "ip:", ip),
		r.client.buildKey(rateLimitWeChatLoginSegment, "proof:", loginCodeHash),
		r.client.buildKey(rateLimitWeChatPhoneSegment, "proof:", phoneCodeHash),
	}
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
	return r.checkRegistrationLifecycleBuckets(ctx, rateLimitRegistrationVerifySegment, ip, keyHash, limit)
}

// CheckRegistrationVerifyWithGlobal prevents a caller that rotates both a
// guessed user ID and exit address from turning the verification endpoint
// into an unbounded identity-provider RPC fan-out.
func (r *RateLimiter) CheckRegistrationVerifyWithGlobal(ctx context.Context, ip, keyHash string, limit registration.Limit, global registration.AggregateRatePolicy) (bool, time.Duration, error) {
	if r == nil || r.client == nil || ip == "" || !isLowerSHA256Hex(keyHash) {
		return false, limit.Window, fmt.Errorf("redis: invalid registration verification rate scope")
	}
	buckets := r.registrationLifecycleBuckets(rateLimitRegistrationVerifySegment, ip, keyHash, limit)
	var err error
	buckets, err = appendAggregateBuckets(buckets, []string{
		r.client.buildKey(rateLimitRegistrationVerifyGlobalSegment, "burst"),
		r.client.buildKey(rateLimitRegistrationVerifyGlobalSegment, "sustained"),
	}, global)
	if err != nil {
		return false, limit.Window, fmt.Errorf("redis: invalid registration verification global policy")
	}
	return r.checkBuckets(ctx, buckets)
}

func (r *RateLimiter) CheckRegistrationResend(ctx context.Context, ip, keyHash string, limit registration.Limit) (bool, time.Duration, error) {
	return r.checkRegistrationLifecycleBuckets(ctx, rateLimitRegistrationResendSegment, ip, keyHash, limit)
}

// Verification and resend budgets include a stable user/token scope in
// addition to IP and pair scopes. Rotating an exit address therefore cannot
// reset attempts against one verification target or trigger extra email.
func (r *RateLimiter) checkRegistrationLifecycleBuckets(ctx context.Context, segment, ip, keyHash string, limit registration.Limit) (bool, time.Duration, error) {
	if r == nil || r.client == nil || (segment != rateLimitRegistrationVerifySegment && segment != rateLimitRegistrationResendSegment) || ip == "" || !isLowerSHA256Hex(keyHash) {
		return false, limit.Window, fmt.Errorf("redis: invalid registration lifecycle rate scope")
	}
	return r.checkBuckets(ctx, r.registrationLifecycleBuckets(segment, ip, keyHash, limit))
}

func (r *RateLimiter) registrationLifecycleBuckets(segment, ip, keyHash string, limit registration.Limit) []rateBucket {
	return []rateBucket{
		{key: r.client.buildKey(segment, "target:", keyHash), limit: limit},
		{key: r.client.buildKey(segment, "ip:", ip), limit: limit},
		{key: r.client.buildKey(segment, "pair:", ip, ":", keyHash), limit: limit},
	}
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
