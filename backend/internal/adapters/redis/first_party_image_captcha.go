package redis

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"regexp"
	"time"

	goredis "github.com/redis/go-redis/v9"
)

const firstPartyImageCaptchaSegment = "risk:captcha:first-party:"

var firstPartyImageAnswerPattern = regexp.MustCompile(`^[0-9]{5}$`)

type FirstPartyImageCaptchaStore struct {
	client *Client
}

func NewFirstPartyImageCaptchaStore(client *Client) *FirstPartyImageCaptchaStore {
	return &FirstPartyImageCaptchaStore{client: client}
}

func (s *FirstPartyImageCaptchaStore) Create(ctx context.Context, challengeID, answer string, ttl time.Duration) error {
	if s == nil || s.client == nil || challengeID == "" || len(challengeID) > 128 || !firstPartyImageAnswerPattern.MatchString(answer) || ttl <= 0 || ttl/time.Millisecond <= 0 {
		return errors.New("redis: invalid first-party image CAPTCHA")
	}
	created, err := s.client.rdb.SetNX(ctx, s.key(challengeID), answer, ttl).Result()
	if err != nil {
		return fmt.Errorf("redis: create first-party image CAPTCHA: %w", err)
	}
	if !created {
		return errors.New("redis: duplicate first-party image CAPTCHA")
	}
	return nil
}

var consumeFirstPartyImageCaptchaScript = goredis.NewScript(`
local value = redis.call('GET', KEYS[1])
if not value then
  return -1
end
if value ~= ARGV[1] then
  return 0
end
redis.call('DEL', KEYS[1])
return 1
`)

// ConsumeIfMatches atomically consumes only a correct answer. A wrong answer
// leaves the challenge available for the outer, bounded completion-attempt
// policy; a successful answer cannot be replayed.
func (s *FirstPartyImageCaptchaStore) ConsumeIfMatches(ctx context.Context, challengeID, answer string) (bool, error) {
	if s == nil || s.client == nil || challengeID == "" || len(challengeID) > 128 || !firstPartyImageAnswerPattern.MatchString(answer) {
		return false, errors.New("redis: invalid first-party image CAPTCHA proof")
	}
	result, err := consumeFirstPartyImageCaptchaScript.Run(ctx, s.client.rdb, []string{s.key(challengeID)}, answer).Int()
	if err != nil {
		return false, fmt.Errorf("redis: consume first-party image CAPTCHA: %w", err)
	}
	return result == 1, nil
}

func (s *FirstPartyImageCaptchaStore) key(challengeID string) string {
	digest := sha256.Sum256([]byte(challengeID))
	return s.client.buildKey(firstPartyImageCaptchaSegment, hex.EncodeToString(digest[:]))
}
