package redis

import (
	"context"
	cryptorand "crypto/rand"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"strings"
	"sync"
	"time"

	goredis "github.com/redis/go-redis/v9"

	"github.com/GravelEvolution/united-pass/backend/internal/platform/observability"
	"github.com/GravelEvolution/united-pass/backend/internal/session"
	"github.com/GravelEvolution/united-pass/backend/internal/wechatonboarding"
)

const (
	wechatOnboardingCleanupKeySegment       = "wechat-onboarding:v2:cleanup:"
	wechatOnboardingCleanupClaimKeySegment  = "wechat-onboarding:v2:cleanup-claim:"
	wechatOnboardingPromotionKeySegment     = "wechat-onboarding:v2:promotion:"
	wechatOnboardingPromotionDoneKeySegment = "wechat-onboarding:v2:promotion-done:"
	wechatOnboardingCleanupDueKeySegment    = "wechat-onboarding:v2:cleanup-due"
	wechatOnboardingCleanupPurpose          = "wechat_onboarding_mfa_cleanup_v1"

	// Cleanup obligations intentionally have no natural Redis TTL: only an
	// atomically proven provider revocation or successful session promotion may
	// remove one. A fixed retention window could silently lose the obligation
	// during an extended provider/worker outage.
	wechatOnboardingPromotionLease   = 60 * time.Second
	wechatOnboardingPromotionDoneTTL = 15 * time.Minute

	defaultWeChatOnboardingCleanupInterval      = 30 * time.Second
	defaultWeChatOnboardingCleanupLease         = 30 * time.Second
	defaultWeChatOnboardingCleanupRetryDelay    = 30 * time.Second
	defaultWeChatOnboardingCleanupRevokeTimeout = 10 * time.Second
	defaultWeChatOnboardingCleanupBatch         = 100
	maxWeChatOnboardingCleanupBatch             = 1000
	wechatOnboardingCleanupClaimBytes           = 16
)

var (
	errWeChatOnboardingCleanupInvalid = errors.New("redis: invalid WeChat onboarding cleanup payload")

	wechatOnboardingCreateMFAChallengeScript = goredis.NewScript(`
local challengeKey = KEYS[1]
local cleanupKey = KEYS[2]
local dueKey = KEYS[3]
local challengeCiphertext = ARGV[1]
local cleanupCiphertext = ARGV[2]
local challengeTTL = tonumber(ARGV[3])
local tokenHash = ARGV[4]

local dueTypeReply = redis.call('TYPE', dueKey)
local dueType = dueTypeReply['ok'] or dueTypeReply
if dueType ~= 'none' and dueType ~= 'zset' then
  return redis.error_reply('CLEANUP_INDEX_WRONGTYPE')
end
if redis.call('EXISTS', challengeKey) ~= 0
  or redis.call('EXISTS', cleanupKey) ~= 0
  or redis.call('EXISTS', KEYS[4]) ~= 0
  or redis.call('EXISTS', KEYS[5]) ~= 0
  or redis.call('EXISTS', KEYS[6]) ~= 0 then
  return 0
end

local redisTime = redis.call('TIME')
local nowMillis = tonumber(redisTime[1]) * 1000 + math.floor(tonumber(redisTime[2]) / 1000)

-- Write the encrypted revocation obligation and due index before making the
-- MFA challenge visible. Thus every visible MFA challenge is covered even if
-- the process dies immediately after this script returns.
redis.call('SET', cleanupKey, cleanupCiphertext)
redis.call('ZADD', dueKey, nowMillis + challengeTTL, tokenHash)
local created = redis.call('SET', challengeKey, challengeCiphertext, 'NX', 'PX', challengeTTL)
if not created then
  redis.call('DEL', cleanupKey)
  redis.call('ZREM', dueKey, tokenHash)
  return 0
end
return 1
`)

	wechatOnboardingDueCleanupScript = goredis.NewScript(`
local redisTime = redis.call('TIME')
local nowMillis = tonumber(redisTime[1]) * 1000 + math.floor(tonumber(redisTime[2]) / 1000)
return redis.call('ZRANGEBYSCORE', KEYS[1], '-inf', nowMillis, 'LIMIT', 0, tonumber(ARGV[1]))
`)

	wechatOnboardingClaimCleanupScript = goredis.NewScript(`
local challengeKey = KEYS[1]
local challengeClaimKey = KEYS[2]
local promotionKey = KEYS[3]
local promotionDoneKey = KEYS[4]
local cleanupKey = KEYS[5]
local cleanupClaimKey = KEYS[6]
local dueKey = KEYS[7]
local tokenHash = ARGV[1]
local claimID = ARGV[2]
local leaseMillis = tonumber(ARGV[3])

local redisTime = redis.call('TIME')
local nowMillis = tonumber(redisTime[1]) * 1000 + math.floor(tonumber(redisTime[2]) / 1000)
local score = redis.call('ZSCORE', dueKey, tokenHash)
if not score or tonumber(score) > nowMillis then
  return nil
end

-- A completion tombstone is the only proof that missing cleanup is a
-- successful promotion rather than a worker-completed revocation. It also
-- prevents stale/corrupt residual state from revoking a promoted session.
if redis.call('EXISTS', promotionDoneKey) ~= 0 then
  redis.call('DEL', cleanupKey, cleanupClaimKey, promotionKey)
  redis.call('ZREM', dueKey, tokenHash)
  return nil
end

-- Expiry is the authority for abandonment. If Redis has not removed the
-- challenge yet, move the due score past its remaining TTL and never revoke.
if redis.call('EXISTS', challengeKey) ~= 0 then
  local challengeTTL = redis.call('PTTL', challengeKey)
  if challengeTTL < 1000 then challengeTTL = 1000 end
  redis.call('ZADD', dueKey, nowMillis + challengeTTL, tokenHash)
  return nil
end

-- A request may still own the challenge claim while its provider call is in
-- flight at the challenge TTL boundary. Never revoke underneath that call;
-- wait until the request releases/consumes the claim or the claim lease dies.
local challengeClaimTTL = redis.call('PTTL', challengeClaimKey)
if challengeClaimTTL > 0 then
  if challengeClaimTTL < 1000 then challengeClaimTTL = 1000 end
  redis.call('ZADD', dueKey, nowMillis + challengeClaimTTL, tokenHash)
  return nil
end

-- Consume begins a short promotion lease. The provider session is not safe
-- to revoke until the HTTP adapter has durably created the local session and
-- explicitly completed that promotion.
local promotionTTL = redis.call('PTTL', promotionKey)
if promotionTTL > 0 then
  if promotionTTL < 1000 then promotionTTL = 1000 end
  redis.call('ZADD', dueKey, nowMillis + promotionTTL, tokenHash)
  return nil
end

local existingLease = redis.call('PTTL', cleanupClaimKey)
if existingLease > 0 then
  if existingLease < 1000 then existingLease = 1000 end
  redis.call('ZADD', dueKey, nowMillis + existingLease, tokenHash)
  return nil
end

-- GETDEL establishes one HA claimant. The encrypted value is immediately
-- restored under a bounded lease before returning it, so a worker crash does
-- not lose the obligation and another instance can retry after the lease.
local payload = redis.call('GETDEL', cleanupKey)
if not payload then
  redis.call('DEL', cleanupClaimKey)
  redis.call('ZREM', dueKey, tokenHash)
  return nil
end
redis.call('SET', cleanupKey, payload)
redis.call('SET', cleanupClaimKey, claimID, 'PX', leaseMillis)
redis.call('ZADD', dueKey, nowMillis + leaseMillis, tokenHash)
return payload
`)

	wechatOnboardingCompleteCleanupScript = goredis.NewScript(`
if redis.call('GET', KEYS[2]) ~= ARGV[2] then
  if redis.call('EXISTS', KEYS[1]) == 0 and not redis.call('ZSCORE', KEYS[3], ARGV[1]) then return 2 end
  return 0
end
redis.call('DEL', KEYS[1], KEYS[2])
redis.call('ZREM', KEYS[3], ARGV[1])
return 1
`)

	wechatOnboardingRetryCleanupScript = goredis.NewScript(`
if redis.call('GET', KEYS[2]) ~= ARGV[2] then
  if redis.call('EXISTS', KEYS[1]) == 0 then return 2 end
  return 0
end
redis.call('DEL', KEYS[2])
if redis.call('EXISTS', KEYS[1]) == 0 then
  redis.call('ZREM', KEYS[3], ARGV[1])
  return 1
end
local redisTime = redis.call('TIME')
local nowMillis = tonumber(redisTime[1]) * 1000 + math.floor(tonumber(redisTime[2]) / 1000)
redis.call('ZADD', KEYS[3], nowMillis + tonumber(ARGV[3]), ARGV[1])
return 1
`)

	wechatOnboardingCompletePromotionScript = goredis.NewScript(`
if redis.call('EXISTS', KEYS[5]) ~= 0 then return 2 end
if redis.call('EXISTS', KEYS[1]) == 0 then return 0 end
if redis.call('EXISTS', KEYS[2]) == 0 then return 0 end
if redis.call('EXISTS', KEYS[3]) ~= 0 then return -1 end
redis.call('DEL', KEYS[1], KEYS[2])
redis.call('ZREM', KEYS[4], ARGV[1])
redis.call('SET', KEYS[5], '1', 'PX', tonumber(ARGV[2]))
return 1
`)

	wechatOnboardingScheduleCleanupScript = goredis.NewScript(`
redis.call('DEL', KEYS[2])
if redis.call('EXISTS', KEYS[1]) == 0 then
  redis.call('ZREM', KEYS[4], ARGV[1])
  return 1
end
if redis.call('EXISTS', KEYS[3]) ~= 0 then return 1 end
local redisTime = redis.call('TIME')
local nowMillis = tonumber(redisTime[1]) * 1000 + math.floor(tonumber(redisTime[2]) / 1000)
redis.call('ZADD', KEYS[4], nowMillis, ARGV[1])
return 1
`)
)

type weChatOnboardingCleanupPayload struct {
	Purpose           string    `json:"purpose"`
	TokenHash         string    `json:"tokenHash"`
	ProviderSessionID string    `json:"providerSessionId"`
	CreatedAt         time.Time `json:"createdAt"`
}

// createMFAChallenge atomically creates the encrypted MFA challenge, its
// encrypted provider-session cleanup payload and the due ZSET entry.
func (s *WeChatOnboardingStore) createMFAChallenge(ctx context.Context, hash, challengeCiphertext, cleanupCiphertext string, ttl time.Duration) error {
	if !s.ready() || !validLowerSHA256(hash) || challengeCiphertext == "" || cleanupCiphertext == "" || ttl <= 0 || ttl/time.Millisecond <= 0 {
		return errors.New("redis: invalid WeChat onboarding MFA challenge input")
	}
	created, err := wechatOnboardingCreateMFAChallengeScript.Run(
		ctx,
		s.client.rdb,
		[]string{
			s.challengeKey(hash), s.cleanupKey(hash), s.cleanupDueKey(),
			s.promotionKey(hash), s.promotionDoneKey(hash), s.cleanupClaimKey(hash),
		},
		challengeCiphertext,
		cleanupCiphertext,
		ttl.Milliseconds(),
		hash,
	).Int()
	if err != nil {
		return fmt.Errorf("redis: create WeChat onboarding MFA challenge: %w", err)
	}
	if created != 1 {
		return errors.New("redis: WeChat onboarding challenge token collision")
	}
	return nil
}

func (s *WeChatOnboardingStore) sealCleanup(tokenHash string, data wechatonboarding.ChallengeData) (string, error) {
	if s == nil || s.encryptor == nil || !validLowerSHA256(tokenHash) || data.Kind != wechatonboarding.ChallengeKindMFA || data.ProviderSessionID == "" || data.CreatedAt.IsZero() {
		return "", errWeChatOnboardingCleanupInvalid
	}
	payload := weChatOnboardingCleanupPayload{
		Purpose:           wechatOnboardingCleanupPurpose,
		TokenHash:         tokenHash,
		ProviderSessionID: data.ProviderSessionID,
		CreatedAt:         data.CreatedAt,
	}
	plain, err := json.Marshal(payload)
	if err != nil {
		return "", fmt.Errorf("redis: encode WeChat onboarding cleanup payload: %w", err)
	}
	ciphertext, err := s.encryptor.Encrypt(string(plain))
	if err != nil {
		return "", fmt.Errorf("redis: encrypt WeChat onboarding cleanup payload: %w", err)
	}
	if ciphertext == "" {
		return "", errors.New("redis: encrypt WeChat onboarding cleanup payload returned empty ciphertext")
	}
	return ciphertext, nil
}

func (s *WeChatOnboardingStore) openCleanup(tokenHash, ciphertext string) (weChatOnboardingCleanupPayload, error) {
	if s == nil || s.encryptor == nil || !validLowerSHA256(tokenHash) || ciphertext == "" {
		return weChatOnboardingCleanupPayload{}, errWeChatOnboardingCleanupInvalid
	}
	plain, err := s.encryptor.Decrypt(ciphertext)
	if err != nil || plain == "" {
		return weChatOnboardingCleanupPayload{}, errWeChatOnboardingCleanupInvalid
	}
	var payload weChatOnboardingCleanupPayload
	decoder := json.NewDecoder(strings.NewReader(plain))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&payload); err != nil || payload.Purpose != wechatOnboardingCleanupPurpose || payload.TokenHash != tokenHash || payload.ProviderSessionID == "" || payload.CreatedAt.IsZero() {
		return weChatOnboardingCleanupPayload{}, errWeChatOnboardingCleanupInvalid
	}
	if err := decoder.Decode(&struct{}{}); !errors.Is(err, io.EOF) {
		return weChatOnboardingCleanupPayload{}, errWeChatOnboardingCleanupInvalid
	}
	return payload, nil
}

func (s *WeChatOnboardingStore) dueCleanupHashes(ctx context.Context, limit int) ([]string, error) {
	if !s.ready() {
		return nil, errors.New("redis: WeChat onboarding cleanup store unavailable")
	}
	if limit <= 0 {
		limit = defaultWeChatOnboardingCleanupBatch
	}
	if limit > maxWeChatOnboardingCleanupBatch {
		limit = maxWeChatOnboardingCleanupBatch
	}
	hashes, err := wechatOnboardingDueCleanupScript.Run(ctx, s.client.rdb, []string{s.cleanupDueKey()}, limit).StringSlice()
	if err != nil {
		return nil, fmt.Errorf("redis: list due WeChat onboarding cleanup entries: %w", err)
	}
	valid := hashes[:0]
	for _, hash := range hashes {
		if validLowerSHA256(hash) {
			valid = append(valid, hash)
			continue
		}
		// Only hashes are valid members. Remove malformed poison entries
		// without ever returning or logging their contents.
		_ = s.client.rdb.ZRem(context.WithoutCancel(ctx), s.cleanupDueKey(), hash).Err()
	}
	return valid, nil
}

func (s *WeChatOnboardingStore) claimCleanup(ctx context.Context, hash, claimID string, lease time.Duration) (weChatOnboardingCleanupPayload, bool, error) {
	if !s.ready() || !validLowerSHA256(hash) || !validOnboardingRawToken(claimID) || lease <= 0 || lease/time.Millisecond <= 0 {
		return weChatOnboardingCleanupPayload{}, false, errors.New("redis: invalid WeChat onboarding cleanup claim input")
	}
	result, err := wechatOnboardingClaimCleanupScript.Run(
		ctx,
		s.client.rdb,
		[]string{
			s.challengeKey(hash), s.claimKey(hash), s.promotionKey(hash), s.promotionDoneKey(hash),
			s.cleanupKey(hash), s.cleanupClaimKey(hash), s.cleanupDueKey(),
		},
		hash,
		claimID,
		lease.Milliseconds(),
	).Result()
	if err != nil {
		if errors.Is(err, goredis.Nil) {
			return weChatOnboardingCleanupPayload{}, false, nil
		}
		return weChatOnboardingCleanupPayload{}, false, fmt.Errorf("redis: claim WeChat onboarding cleanup entry: %w", err)
	}
	ciphertext, ok := result.(string)
	if !ok || ciphertext == "" {
		return weChatOnboardingCleanupPayload{}, false, nil
	}
	payload, openErr := s.openCleanup(hash, ciphertext)
	if openErr != nil {
		// The claim remains leased and the encrypted obligation remains stored.
		// A restored key/configuration can recover it on a later retry.
		return weChatOnboardingCleanupPayload{}, true, openErr
	}
	return payload, true, nil
}

func (s *WeChatOnboardingStore) completeCleanup(ctx context.Context, hash, claimID string) error {
	if !s.ready() || !validLowerSHA256(hash) || !validOnboardingRawToken(claimID) {
		return errors.New("redis: invalid WeChat onboarding cleanup completion input")
	}
	result, err := wechatOnboardingCompleteCleanupScript.Run(
		ctx,
		s.client.rdb,
		[]string{s.cleanupKey(hash), s.cleanupClaimKey(hash), s.cleanupDueKey()},
		hash,
		claimID,
	).Int()
	if err != nil {
		return fmt.Errorf("redis: complete WeChat onboarding cleanup entry: %w", err)
	}
	if result == 0 {
		return errors.New("redis: WeChat onboarding cleanup claim lost before completion")
	}
	// Result 2 is an idempotent replay after an earlier completion. A stale
	// claimant can never delete a newer claim because that state returns zero.
	return nil
}

func (s *WeChatOnboardingStore) retryCleanup(ctx context.Context, hash, claimID string, delay time.Duration) error {
	if !s.ready() || !validLowerSHA256(hash) || !validOnboardingRawToken(claimID) || delay <= 0 || delay/time.Millisecond <= 0 {
		return errors.New("redis: invalid WeChat onboarding cleanup retry input")
	}
	result, err := wechatOnboardingRetryCleanupScript.Run(
		ctx,
		s.client.rdb,
		[]string{s.cleanupKey(hash), s.cleanupClaimKey(hash), s.cleanupDueKey()},
		hash,
		claimID,
		delay.Milliseconds(),
	).Int()
	if err != nil {
		return fmt.Errorf("redis: retry WeChat onboarding cleanup entry: %w", err)
	}
	if result == 0 {
		return errors.New("redis: WeChat onboarding cleanup claim lost before retry")
	}
	return nil
}

// CompleteProviderSessionPromotion removes the cleanup obligation only after
// the HTTP adapter has durably created the native United Pass session. The
// raw MFA token is possession proof; only its SHA-256 hash reaches Redis.
// A promotion that lost its lease or raced a cleanup claimant fails closed.
func (s *WeChatOnboardingStore) CompleteProviderSessionPromotion(ctx context.Context, rawToken string) error {
	if !s.ready() || !validOnboardingRawToken(rawToken) {
		return errors.New("redis: invalid WeChat onboarding promotion completion input")
	}
	hash := sessionHashToken(rawToken)
	result, err := wechatOnboardingCompletePromotionScript.Run(
		ctx,
		s.client.rdb,
		[]string{s.cleanupKey(hash), s.promotionKey(hash), s.cleanupClaimKey(hash), s.cleanupDueKey(), s.promotionDoneKey(hash)},
		hash,
		wechatOnboardingPromotionDoneTTL.Milliseconds(),
	).Int()
	if err != nil {
		return fmt.Errorf("redis: complete WeChat onboarding provider-session promotion: %w", err)
	}
	if result != 1 && result != 2 {
		return errors.New("redis: WeChat onboarding provider-session promotion lease expired")
	}
	return nil
}

// ScheduleProviderSessionCleanup abandons promotion and makes the encrypted
// revocation obligation immediately due. It is idempotent and never steals a
// cleanup claim already held by another worker instance.
func (s *WeChatOnboardingStore) ScheduleProviderSessionCleanup(ctx context.Context, rawToken string) error {
	if !s.ready() || !validOnboardingRawToken(rawToken) {
		return errors.New("redis: invalid WeChat onboarding cleanup scheduling input")
	}
	hash := sessionHashToken(rawToken)
	_, err := wechatOnboardingScheduleCleanupScript.Run(
		ctx,
		s.client.rdb,
		[]string{s.cleanupKey(hash), s.promotionKey(hash), s.cleanupClaimKey(hash), s.cleanupDueKey()},
		hash,
	).Result()
	if err != nil {
		return fmt.Errorf("redis: schedule WeChat onboarding provider-session cleanup: %w", err)
	}
	return nil
}

func (s *WeChatOnboardingStore) cleanupKey(hash string) string {
	return s.client.buildKey(wechatOnboardingCleanupKeySegment, hash)
}

func (s *WeChatOnboardingStore) cleanupClaimKey(hash string) string {
	return s.client.buildKey(wechatOnboardingCleanupClaimKeySegment, hash)
}

func (s *WeChatOnboardingStore) promotionKey(hash string) string {
	return s.client.buildKey(wechatOnboardingPromotionKeySegment, hash)
}

func (s *WeChatOnboardingStore) promotionDoneKey(hash string) string {
	return s.client.buildKey(wechatOnboardingPromotionDoneKeySegment, hash)
}

func (s *WeChatOnboardingStore) cleanupDueKey() string {
	return s.client.buildKey(wechatOnboardingCleanupDueKeySegment)
}

type weChatOnboardingCleanupQueue interface {
	dueCleanupHashes(context.Context, int) ([]string, error)
	claimCleanup(context.Context, string, string, time.Duration) (weChatOnboardingCleanupPayload, bool, error)
	completeCleanup(context.Context, string, string) error
	retryCleanup(context.Context, string, string, time.Duration) error
}

type weChatOnboardingSessionRevoker interface {
	RevokeProviderSession(context.Context, string) error
}

// WeChatOnboardingCleanupWorker revokes provider sessions belonging to MFA
// challenges that expired or were abandoned. Redis claims make multiple
// worker instances safe: only one instance owns an obligation at a time, and
// a crashed claimant becomes retryable when its lease expires.
type WeChatOnboardingCleanupWorker struct {
	queue         weChatOnboardingCleanupQueue
	revoker       weChatOnboardingSessionRevoker
	logger        *slog.Logger
	interval      time.Duration
	lease         time.Duration
	retryDelay    time.Duration
	revokeTimeout time.Duration
	batch         int

	mu      sync.Mutex
	started bool
	cancel  context.CancelFunc
	done    chan struct{}
}

func NewWeChatOnboardingCleanupWorker(store *WeChatOnboardingStore, revoker weChatOnboardingSessionRevoker, logger *slog.Logger) (*WeChatOnboardingCleanupWorker, error) {
	if store == nil || !store.ready() {
		return nil, errors.New("redis: WeChat onboarding cleanup worker requires a ready store")
	}
	return newWeChatOnboardingCleanupWorker(store, revoker, logger)
}

func newWeChatOnboardingCleanupWorker(queue weChatOnboardingCleanupQueue, revoker weChatOnboardingSessionRevoker, logger *slog.Logger) (*WeChatOnboardingCleanupWorker, error) {
	if queue == nil || revoker == nil || logger == nil {
		return nil, errors.New("redis: WeChat onboarding cleanup worker dependencies are required")
	}
	return &WeChatOnboardingCleanupWorker{
		queue:         queue,
		revoker:       revoker,
		logger:        logger,
		interval:      defaultWeChatOnboardingCleanupInterval,
		lease:         defaultWeChatOnboardingCleanupLease,
		retryDelay:    defaultWeChatOnboardingCleanupRetryDelay,
		revokeTimeout: defaultWeChatOnboardingCleanupRevokeTimeout,
		batch:         defaultWeChatOnboardingCleanupBatch,
	}, nil
}

// Start launches an immediate cleanup pass followed by periodic passes. It is
// idempotent and safe to call more than once.
func (w *WeChatOnboardingCleanupWorker) Start() {
	w.mu.Lock()
	defer w.mu.Unlock()
	if w.started {
		return
	}
	ctx, cancel := context.WithCancel(context.Background())
	w.started = true
	w.cancel = cancel
	w.done = make(chan struct{})
	go w.run(ctx, w.done)
}

// Stop cancels the loop and waits for an in-flight revocation to finish or
// observe cancellation. Concurrent/repeated calls are idempotent.
func (w *WeChatOnboardingCleanupWorker) Stop() {
	w.mu.Lock()
	if !w.started {
		w.mu.Unlock()
		return
	}
	cancel := w.cancel
	done := w.done
	w.mu.Unlock()
	cancel()
	<-done

	// Reset only the generation this Stop observed. Concurrent Stop calls may
	// all wait on the same generation, while a later sequential Start must be
	// able to create a fresh loop.
	w.mu.Lock()
	if w.done == done {
		w.started = false
		w.cancel = nil
		w.done = nil
	}
	w.mu.Unlock()
}

func (w *WeChatOnboardingCleanupWorker) run(ctx context.Context, done chan struct{}) {
	defer close(done)
	w.RunOnce(ctx)
	ticker := time.NewTicker(w.interval)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			w.RunOnce(ctx)
		}
	}
}

// RunOnce processes one bounded batch. Per-entry failures are retried and do
// not block unrelated entries; only the queue-list failure is returned.
func (w *WeChatOnboardingCleanupWorker) RunOnce(ctx context.Context) error {
	hashes, err := w.queue.dueCleanupHashes(ctx, w.batch)
	if err != nil {
		w.logFailure("list", err)
		return err
	}
	revoked := 0
	for _, hash := range hashes {
		if ctx.Err() != nil {
			return ctx.Err()
		}
		claimID, err := newWeChatOnboardingCleanupClaimID()
		if err != nil {
			w.logFailure("claim_id", err)
			continue
		}
		payload, claimed, claimErr := w.queue.claimCleanup(ctx, hash, claimID, w.lease)
		if claimErr != nil {
			if claimed {
				finalizeCtx, finalizeCancel := w.finalizationContext(ctx)
				if retryErr := w.queue.retryCleanup(finalizeCtx, hash, claimID, w.retryDelay); retryErr != nil {
					w.logFailure("retry", retryErr)
				}
				finalizeCancel()
			}
			w.logFailure("claim", claimErr)
			continue
		}
		if !claimed {
			continue
		}

		revokeCtx, cancel := context.WithTimeout(ctx, w.revokeTimeout)
		revokeErr := w.revoker.RevokeProviderSession(revokeCtx, payload.ProviderSessionID)
		cancel()
		if revokeErr != nil {
			finalizeCtx, finalizeCancel := w.finalizationContext(ctx)
			if retryErr := w.queue.retryCleanup(finalizeCtx, hash, claimID, w.retryDelay); retryErr != nil {
				w.logFailure("retry", retryErr)
			}
			finalizeCancel()
			w.logFailure("revoke", revokeErr)
			continue
		}
		finalizeCtx, finalizeCancel := w.finalizationContext(ctx)
		completeErr := w.queue.completeCleanup(finalizeCtx, hash, claimID)
		finalizeCancel()
		if completeErr != nil {
			// The claim and encrypted payload remain. If this process exits or
			// Redis briefly fails, another pass safely repeats the idempotent
			// provider revocation after the lease.
			w.logFailure("complete", completeErr)
			continue
		}
		revoked++
	}
	if revoked > 0 {
		w.logger.Info("WeChat onboarding cleanup revoked abandoned provider sessions", "count", revoked)
	}
	return nil
}

func (w *WeChatOnboardingCleanupWorker) finalizationContext(parent context.Context) (context.Context, context.CancelFunc) {
	return context.WithTimeout(context.WithoutCancel(parent), w.revokeTimeout)
}

func (w *WeChatOnboardingCleanupWorker) logFailure(stage string, err error) {
	// Neither token hashes, ciphertext, provider session identifiers nor raw
	// provider errors are logged. Error classification is deliberately coarse.
	w.logger.Warn("WeChat onboarding cleanup failed", "stage", stage, "errorClass", observability.ClassifyError(err))
}

func newWeChatOnboardingCleanupClaimID() (string, error) {
	random := make([]byte, wechatOnboardingCleanupClaimBytes)
	if _, err := cryptorand.Read(random); err != nil {
		return "", fmt.Errorf("redis: generate WeChat onboarding cleanup claim: %w", err)
	}
	return hex.EncodeToString(random), nil
}

var _ weChatOnboardingCleanupQueue = (*WeChatOnboardingStore)(nil)

// sessionHashToken is kept as a tiny seam so the cleanup file never needs to
// handle or retain raw bearer values beyond a single hash operation.
func sessionHashToken(rawToken string) string {
	return session.HashToken(rawToken)
}
