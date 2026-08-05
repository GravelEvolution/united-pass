package redis

import (
	"context"
	"fmt"
	"time"

	goredis "github.com/redis/go-redis/v9"
)

// rateLimitLoginSegment is the key segment for login rate limits. The full key
// is: {prefix}rl:login:{ip}:{sha256(identifier)}.
const rateLimitLoginSegment = "rl:login:"

// rateLimitMFASegment is the key segment for MFA rate limits. The full key is:
// {prefix}rl:mfa:{ip}:{sha256(mfaToken)}.
const rateLimitMFASegment = "rl:mfa:"

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
	key := r.client.buildKey(rateLimitLoginSegment, ip, ":", identifierHash)
	return r.check(ctx, key, limit, window)
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
