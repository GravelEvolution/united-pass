package redis

import (
	"errors"
	"strings"
	"testing"

	"github.com/GravelEvolution/united-pass/backend/internal/registration"
)

func TestUnblockRegistrationHashRejectsArbitraryKeyMaterialBeforeRedis(t *testing.T) {
	store := &RegistrationFormDefenseStore{client: &Client{}}
	validDigest := registration.HashAbuseValue("203.0.113.7")
	tests := []struct {
		dimension registration.AbuseBlockDimension
		digest    string
	}{
		{dimension: registration.AbuseBlockDimension("redis_key"), digest: validDigest},
		{dimension: registration.AbuseBlockIP, digest: "registration:block:ip:attacker-selected"},
		{dimension: registration.AbuseBlockDevice, digest: strings.ToUpper(validDigest)},
		{dimension: registration.AbuseBlockIP, digest: validDigest + "00"},
	}
	for _, test := range tests {
		if err := store.UnblockRegistrationHash(t.Context(), test.dimension, test.digest); !errors.Is(err, registration.ErrInvalidInput) {
			t.Fatalf("dimension=%q digest=%q error=%v", test.dimension, test.digest, err)
		}
	}
}
