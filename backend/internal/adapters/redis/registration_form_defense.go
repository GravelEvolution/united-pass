package redis

import (
	"context"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"time"

	goredis "github.com/redis/go-redis/v9"

	"github.com/GravelEvolution/united-pass/backend/internal/registration"
	"github.com/GravelEvolution/united-pass/backend/internal/session"
)

const (
	registrationFormIntentSegment  = "registration:form-intent:"
	registrationBlockDeviceSegment = "registration:block:device:"
	registrationIPStrikeSegment    = "registration:strike:ip:"
	registrationBlockIPSegment     = "registration:block:ip:"
)

type RegistrationFormDefenseStore struct{ client *Client }

func NewRegistrationFormDefenseStore(client *Client) *RegistrationFormDefenseStore {
	return &RegistrationFormDefenseStore{client: client}
}

func (s *RegistrationFormDefenseStore) CreateFormIntent(ctx context.Context, rawToken string, record registration.FormIntentRecord, ttl time.Duration) error {
	if s == nil || s.client == nil || rawToken == "" || record.UserAgentHash == "" || ttl <= 0 {
		return registration.ErrUnavailable
	}
	payload, err := formIntentPayload(record)
	if err != nil {
		return fmt.Errorf("redis: encode registration form intent: %w", err)
	}
	key := s.client.buildKey(registrationFormIntentSegment, session.HashToken(rawToken))
	ok, err := s.client.rdb.SetNX(ctx, key, payload, ttl).Result()
	if err != nil {
		return fmt.Errorf("redis: create registration form intent: %w", err)
	}
	if !ok {
		return registration.ErrUnavailable
	}
	return nil
}

var consumeRegistrationFormIntentScript = goredis.NewScript(`
local payload = redis.call('GET', KEYS[1])
if not payload then return 0 end
local record = cjson.decode(payload)
if record.userAgentHash ~= ARGV[1] then return -1 end
if record.clientNetworkHash ~= ARGV[2] then return -1 end
local storedDevice = record.deviceIdHash or ''
-- A risk challenge can mint the browser's first server-issued device cookie
-- between intent issuance and the browser's one permitted retry. An intent
-- that was issued without a device therefore accepts that first cookie. Once
-- an intent was issued with a device, replacement remains a hard mismatch.
if storedDevice ~= '' and storedDevice ~= ARGV[3] then return -1 end
if tonumber(ARGV[4]) < tonumber(record.notBeforeUnixMilli) then return -2 end
if tonumber(ARGV[4]) >= tonumber(record.expiresAtUnixMilli) then
    redis.call('DEL', KEYS[1])
    return 0
end
redis.call('DEL', KEYS[1])
return 1
`)

type redisFormIntentRecord struct {
	UserAgentHash      string `json:"userAgentHash"`
	ClientNetworkHash  string `json:"clientNetworkHash"`
	DeviceIDHash       string `json:"deviceIdHash,omitempty"`
	NotBeforeUnixMilli int64  `json:"notBeforeUnixMilli"`
	ExpiresAtUnixMilli int64  `json:"expiresAtUnixMilli"`
}

func (s *RegistrationFormDefenseStore) ConsumeFormIntent(ctx context.Context, rawToken string, binding registration.FormIntentBinding, now time.Time) error {
	if s == nil || s.client == nil || rawToken == "" || binding.UserAgentHash == "" || binding.ClientNetworkHash == "" {
		return registration.ErrFormIntentInvalid
	}
	key := s.client.buildKey(registrationFormIntentSegment, session.HashToken(rawToken))
	result, err := consumeRegistrationFormIntentScript.Run(ctx, s.client.rdb, []string{key}, binding.UserAgentHash, binding.ClientNetworkHash, binding.DeviceIDHash, now.UTC().UnixMilli()).Int()
	if err != nil {
		return fmt.Errorf("redis: consume registration form intent: %w", err)
	}
	switch result {
	case 1:
		return nil
	case -2:
		return registration.ErrFormIntentTooYoung
	default:
		return registration.ErrFormIntentInvalid
	}
}

// MarshalJSON is kept at the adapter boundary so Redis never depends on
// time.Time's textual JSON format inside its atomic Lua validation.
func formIntentPayload(record registration.FormIntentRecord) ([]byte, error) {
	return json.Marshal(redisFormIntentRecord{
		UserAgentHash: record.UserAgentHash, ClientNetworkHash: record.ClientNetworkHash, DeviceIDHash: record.DeviceIDHash,
		NotBeforeUnixMilli: record.NotBefore.UTC().UnixMilli(),
		ExpiresAtUnixMilli: record.ExpiresAt.UTC().UnixMilli(),
	})
}

var recordRegistrationHoneypotScript = goredis.NewScript(`
if ARGV[1] == '1' then redis.call('SET', KEYS[1], '1', 'PX', ARGV[2]) end
local strikes = 0
local blocked = 0
local longBlock = 0
if ARGV[3] == '1' then
    strikes = redis.call('INCR', KEYS[2])
    if strikes == 1 then redis.call('PEXPIRE', KEYS[2], ARGV[4]) end
    if strikes >= tonumber(ARGV[7]) then
        redis.call('SET', KEYS[3], '1', 'PX', ARGV[8])
        blocked = 1
        longBlock = 1
    elseif strikes >= tonumber(ARGV[5]) then
        redis.call('SET', KEYS[3], '1', 'PX', ARGV[6])
        blocked = 1
    end
end
return {strikes, blocked, longBlock}
`)

func (s *RegistrationFormDefenseStore) RecordRegistrationHoneypot(ctx context.Context, fingerprint registration.AbuseFingerprint, policy registration.AbusePolicy) (registration.AbuseDisposition, error) {
	if s == nil || s.client == nil {
		return registration.AbuseDisposition{}, registration.ErrUnavailable
	}
	deviceHash := fingerprint.DeviceIDHash
	devicePresent := "1"
	if deviceHash == "" {
		deviceHash = fingerprint.ClientIPHash
		devicePresent = "0"
	}
	ipBlockEligible := "0"
	if fingerprint.ClientIPBlockEligible {
		ipBlockEligible = "1"
	}
	keys := []string{
		s.client.buildKey(registrationBlockDeviceSegment, deviceHash),
		s.client.buildKey(registrationIPStrikeSegment, fingerprint.ClientIPHash),
		s.client.buildKey(registrationBlockIPSegment, fingerprint.ClientIPHash),
	}
	result, err := recordRegistrationHoneypotScript.Run(ctx, s.client.rdb, keys,
		devicePresent, policy.DeviceBlockTTL.Milliseconds(), ipBlockEligible, policy.IPStrikeWindow.Milliseconds(),
		policy.IPBlockAfter, policy.IPBlockTTL.Milliseconds(), policy.IPLongBlockAfter, policy.IPLongBlockTTL.Milliseconds(),
	).Slice()
	if err != nil {
		return registration.AbuseDisposition{}, fmt.Errorf("redis: record registration honeypot: %w", err)
	}
	if len(result) != 3 {
		return registration.AbuseDisposition{}, errors.New("redis: malformed registration honeypot result")
	}
	strikes, strikeOK := result[0].(int64)
	blocked, blockOK := result[1].(int64)
	longBlock, longOK := result[2].(int64)
	if !strikeOK || !blockOK || !longOK {
		return registration.AbuseDisposition{}, errors.New("redis: malformed registration honeypot result types")
	}
	return registration.AbuseDisposition{IPStrikeCount: int(strikes), IPBlocked: blocked == 1, LongIPBlock: longBlock == 1}, nil
}

func (s *RegistrationFormDefenseStore) IsRegistrationBlocked(ctx context.Context, fingerprint registration.AbuseFingerprint) (bool, error) {
	if s == nil || s.client == nil {
		return false, registration.ErrUnavailable
	}
	keys := make([]string, 0, 2)
	if fingerprint.ClientIPBlockEligible {
		keys = append(keys, s.client.buildKey(registrationBlockIPSegment, fingerprint.ClientIPHash))
	}
	if fingerprint.DeviceIDHash != "" {
		keys = append(keys, s.client.buildKey(registrationBlockDeviceSegment, fingerprint.DeviceIDHash))
	}
	if len(keys) == 0 {
		return false, nil
	}
	count, err := s.client.rdb.Exists(ctx, keys...).Result()
	if err != nil {
		return false, fmt.Errorf("redis: read registration abuse blocks: %w", err)
	}
	return count > 0, nil
}

// UnblockRegistrationHash revokes exactly one operator-selected block
// dimension. The caller supplies only a validated SHA-256 digest; Redis key
// prefixes remain private to this adapter, so no management API can be used
// as an arbitrary DEL primitive. IP strike state is removed with an IP block
// so a confirmed false positive does not immediately re-block on the next
// observation.
func (s *RegistrationFormDefenseStore) UnblockRegistrationHash(ctx context.Context, dimension registration.AbuseBlockDimension, digest string) error {
	if s == nil || s.client == nil || !validRegistrationAbuseDigest(digest) || !dimension.Valid() {
		return registration.ErrInvalidInput
	}
	var keys []string
	switch dimension {
	case registration.AbuseBlockDevice:
		keys = []string{s.client.buildKey(registrationBlockDeviceSegment, digest)}
	case registration.AbuseBlockIP:
		keys = []string{
			s.client.buildKey(registrationBlockIPSegment, digest),
			s.client.buildKey(registrationIPStrikeSegment, digest),
		}
	}
	if err := s.client.rdb.Del(ctx, keys...).Err(); err != nil && !errors.Is(err, goredis.Nil) {
		return fmt.Errorf("redis: unblock registration abuse dimension: %w", err)
	}
	return nil
}

func validRegistrationAbuseDigest(value string) bool {
	decoded, err := hex.DecodeString(value)
	return err == nil && len(decoded) == 32 && value == hex.EncodeToString(decoded)
}

var _ registration.FormDefenseStore = (*RegistrationFormDefenseStore)(nil)
