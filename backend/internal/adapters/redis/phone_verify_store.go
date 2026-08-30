//
// Copyright (c) 2026 Chen Jiajie(Ariakage)
//
// Author: Chen Jiajie(Ariakage) <ariakage233@gmail.com>
// Date: 2026-08-20
// Description: Redis store for phone verification codes
//

package redis

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"time"

	goredis "github.com/redis/go-redis/v9"

	"github.com/GravelEvolution/united-pass/backend/internal/phoneverify"
)

// phoneVerifyKeySegment is the key segment for phone verification codes. The
// full key is {prefix}phone_verify:{sha256(requestID)}.
const phoneVerifyKeySegment = "phone_verify:"

// PhoneVerifyStore implements phoneverify.Store using Redis. Verification
// codes are short-lived, single-use records keyed by the SHA-256 hash of the
// request ID; the raw request ID never reaches Redis.
type PhoneVerifyStore struct {
	client *Client
}

// NewPhoneVerifyStore builds a PhoneVerifyStore backed by the given Client.
func NewPhoneVerifyStore(client *Client) *PhoneVerifyStore {
	return &PhoneVerifyStore{client: client}
}

// Create stores a phone verification record for the given request ID.
func (s *PhoneVerifyStore) Create(ctx context.Context, requestID, phone, code string, ttl time.Duration) error {
	if requestID == "" || phone == "" || code == "" {
		return errors.New("redis: phone verify request requires request id, phone and code")
	}
	payload, err := json.Marshal(phoneVerifyPayload{Phone: phone, Code: code})
	if err != nil {
		return fmt.Errorf("redis: encode phone verify: %w", err)
	}
	if err := s.client.rdb.Set(ctx, s.key(requestID), payload, ttl).Err(); err != nil {
		return fmt.Errorf("redis: store phone verify: %w", err)
	}
	return nil
}

// Consume atomically reads and deletes a phone verification record, returning
// the phone and code when the request ID exists.
func (s *PhoneVerifyStore) Consume(ctx context.Context, requestID string) (phone, code string, ok bool, err error) {
	if requestID == "" {
		return "", "", false, errors.New("redis: phone verify request id must not be empty")
	}
	key := s.key(requestID)
	raw, err := s.client.rdb.GetDel(ctx, key).Bytes()
	if err != nil {
		if errors.Is(err, goredis.Nil) {
			return "", "", false, nil
		}
		return "", "", false, fmt.Errorf("redis: consume phone verify: %w", err)
	}
	var payload phoneVerifyPayload
	if err := json.Unmarshal(raw, &payload); err != nil {
		return "", "", false, fmt.Errorf("redis: decode phone verify: %w", err)
	}
	return payload.Phone, payload.Code, true, nil
}

func (s *PhoneVerifyStore) key(requestID string) string {
	sum := sha256.Sum256([]byte(requestID))
	return s.client.keyPrefix + phoneVerifyKeySegment + hex.EncodeToString(sum[:])
}

type phoneVerifyPayload struct {
	Phone string `json:"phone"`
	Code  string `json:"code"`
}

var _ phoneverify.Store = (*PhoneVerifyStore)(nil)
