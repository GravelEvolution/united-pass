package adminstepup

import (
	"context"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/base64"
	"errors"
	"fmt"
	"strconv"
	"strings"

	"golang.org/x/crypto/argon2"
)

type Argon2Params struct {
	MemoryKiB   uint32
	Iterations  uint32
	Parallelism uint8
	SaltBytes   uint32
	KeyBytes    uint32
}

var DefaultArgon2Params = Argon2Params{
	MemoryKiB: 64 * 1024, Iterations: 3, Parallelism: 2, SaltBytes: 16, KeyBytes: 32,
}

type PHCComparator interface {
	Equal(expected, actual []byte) bool
}

type ConstantTimePHCComparator struct{}

func (ConstantTimePHCComparator) Equal(expected, actual []byte) bool {
	if len(expected) != len(actual) {
		// Keep a constant-time comparison even for malformed sizes, without
		// ever accepting them.
		var left, right [32]byte
		copy(left[:], expected)
		copy(right[:], actual)
		_ = subtle.ConstantTimeCompare(left[:], right[:])
		return false
	}
	return subtle.ConstantTimeCompare(expected, actual) == 1
}

type AnswerHasher struct {
	peppers    *Keyring
	params     Argon2Params
	semaphore  chan struct{}
	comparator PHCComparator
}

func NewAnswerHasher(peppers *Keyring, params Argon2Params, maxConcurrent int) (*AnswerHasher, error) {
	if _, _, err := peppers.Current(); err != nil || !validArgon2Params(params) || maxConcurrent <= 0 || maxConcurrent > 64 {
		return nil, errors.New("adminstepup: invalid answer hasher configuration")
	}
	return &AnswerHasher{peppers: peppers, params: params, semaphore: make(chan struct{}, maxConcurrent), comparator: ConstantTimePHCComparator{}}, nil
}

func validArgon2Params(params Argon2Params) bool {
	return params.MemoryKiB >= 8*1024 && params.MemoryKiB <= 1024*1024 && params.Iterations >= 1 && params.Iterations <= 10 && params.Parallelism >= 1 && params.Parallelism <= 16 && params.SaltBytes >= 16 && params.SaltBytes <= 64 && params.KeyBytes >= 32 && params.KeyBytes <= 64
}

func (h *AnswerHasher) Hash(ctx context.Context, answer string) (string, string, error) {
	normalized, err := NormalizeAnswer(answer)
	if err != nil {
		return "", "", err
	}
	if err := h.acquire(ctx); err != nil {
		return "", "", err
	}
	defer h.release()
	keyID, pepper, err := h.peppers.Current()
	if err != nil {
		return "", "", err
	}
	salt := make([]byte, h.params.SaltBytes)
	if _, err := rand.Read(salt); err != nil {
		return "", "", fmt.Errorf("adminstepup: generate argon2 salt: %w", err)
	}
	derived := deriveAnswer(normalized, pepper, salt, h.params)
	return encodePHC(h.params, salt, derived), keyID, nil
}

func (h *AnswerHasher) Verify(ctx context.Context, answer, phc, pepperKeyID string) (bool, error) {
	normalized, err := NormalizeAnswer(answer)
	if err != nil {
		return false, err
	}
	params, salt, expected, err := parsePHC(phc)
	if err != nil {
		return false, err
	}
	pepper, err := h.peppers.Key(pepperKeyID)
	if err != nil {
		return false, err
	}
	if err := h.acquire(ctx); err != nil {
		return false, err
	}
	defer h.release()
	actual := deriveAnswer(normalized, pepper, salt, params)
	return h.comparator.Equal(expected, actual), nil
}

func (h *AnswerHasher) acquire(ctx context.Context) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	select {
	case h.semaphore <- struct{}{}:
		if err := ctx.Err(); err != nil {
			h.release()
			return err
		}
		return nil
	case <-ctx.Done():
		return ctx.Err()
	}
}

func (h *AnswerHasher) release() { <-h.semaphore }

func deriveAnswer(answer string, pepper, salt []byte, params Argon2Params) []byte {
	mac := hmac.New(sha256.New, pepper)
	_, _ = mac.Write([]byte("united-pass/admin-challenge-answer/v1\x00"))
	_, _ = mac.Write([]byte(answer))
	peppered := mac.Sum(nil)
	return argon2.IDKey(peppered, salt, params.Iterations, params.MemoryKiB, params.Parallelism, params.KeyBytes)
}

func encodePHC(params Argon2Params, salt, derived []byte) string {
	return fmt.Sprintf("$argon2id$v=%d$m=%d,t=%d,p=%d$%s$%s", argon2.Version, params.MemoryKiB, params.Iterations, params.Parallelism, base64.RawStdEncoding.EncodeToString(salt), base64.RawStdEncoding.EncodeToString(derived))
}

func parsePHC(phc string) (Argon2Params, []byte, []byte, error) {
	parts := strings.Split(phc, "$")
	if len(parts) != 6 || parts[0] != "" || parts[1] != "argon2id" || parts[2] != "v="+strconv.Itoa(argon2.Version) {
		return Argon2Params{}, nil, nil, errors.New("adminstepup: invalid PHC")
	}
	parameterParts := strings.Split(parts[3], ",")
	if len(parameterParts) != 3 {
		return Argon2Params{}, nil, nil, errors.New("adminstepup: invalid PHC")
	}
	memory, memoryErr := parsePHCUint(parameterParts[0], "m=", 32)
	iterations, iterationsErr := parsePHCUint(parameterParts[1], "t=", 32)
	parallelism, parallelismErr := parsePHCUint(parameterParts[2], "p=", 8)
	if memoryErr != nil || iterationsErr != nil || parallelismErr != nil {
		return Argon2Params{}, nil, nil, errors.New("adminstepup: invalid PHC")
	}
	params := Argon2Params{MemoryKiB: uint32(memory), Iterations: uint32(iterations), Parallelism: uint8(parallelism)}
	salt, err := base64.RawStdEncoding.DecodeString(parts[4])
	if err != nil {
		return Argon2Params{}, nil, nil, errors.New("adminstepup: invalid PHC")
	}
	derived, err := base64.RawStdEncoding.DecodeString(parts[5])
	if err != nil {
		return Argon2Params{}, nil, nil, errors.New("adminstepup: invalid PHC")
	}
	params.SaltBytes, params.KeyBytes = uint32(len(salt)), uint32(len(derived))
	if !validArgon2Params(params) {
		return Argon2Params{}, nil, nil, errors.New("adminstepup: unsafe PHC parameters")
	}
	return params, salt, derived, nil
}

func parsePHCUint(value, prefix string, bitSize int) (uint64, error) {
	if !strings.HasPrefix(value, prefix) {
		return 0, errors.New("adminstepup: invalid PHC parameter")
	}
	raw := strings.TrimPrefix(value, prefix)
	parsed, err := strconv.ParseUint(raw, 10, bitSize)
	if err != nil || strconv.FormatUint(parsed, 10) != raw {
		return 0, errors.New("adminstepup: invalid PHC parameter")
	}
	return parsed, nil
}
