package postgres

import (
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"testing"

	"github.com/GravelEvolution/united-pass/backend/internal/wechatregistration"
)

func TestWeChatProviderIntentVerifierBindsEveryProviderField(t *testing.T) {
	intent := wechatregistration.ProviderIntent{
		Username: "moonstone", DisplayName: "Moonstone", Email: "Player@Example.com",
		Password: "Correct-Horse-Battery-Staple9!",
	}
	verifier, err := hashWeChatProviderIntent(intent)
	if err != nil {
		t.Fatalf("hash intent: %v", err)
	}
	matched, err := verifyWeChatProviderIntent(intent, verifier)
	if err != nil || !matched {
		t.Fatalf("verify exact intent: matched=%v err=%v", matched, err)
	}

	tests := []struct {
		name   string
		mutate func(*wechatregistration.ProviderIntent)
	}{
		{name: "username", mutate: func(value *wechatregistration.ProviderIntent) { value.Username = "moonstone-2" }},
		{name: "display name", mutate: func(value *wechatregistration.ProviderIntent) { value.DisplayName = "Different" }},
		{name: "email", mutate: func(value *wechatregistration.ProviderIntent) { value.Email = "other@example.com" }},
		{name: "password", mutate: func(value *wechatregistration.ProviderIntent) { value.Password = "Different-Strong-Password-Number2!" }},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			drifted := intent
			test.mutate(&drifted)
			matched, verifyErr := verifyWeChatProviderIntent(drifted, verifier)
			if verifyErr != nil {
				t.Fatalf("verify drifted intent: %v", verifyErr)
			}
			if matched {
				t.Fatal("drifted provider intent matched durable verifier")
			}
		})
	}

	caseOnlyEmail := intent
	caseOnlyEmail.Email = "player@example.com"
	matched, err = verifyWeChatProviderIntent(caseOnlyEmail, verifier)
	if err != nil || !matched {
		t.Fatalf("normalized email should match: matched=%v err=%v", matched, err)
	}
}

func TestWeChatProviderIntentVerifierRejectsMalformedEncodingBeforeArgon2(t *testing.T) {
	intent := wechatregistration.ProviderIntent{Username: "u", DisplayName: "d", Email: "e@example.com", Password: "password"}
	for _, verifier := range []string{"", "$argon2id$v=19$m=1048576,t=10,p=16$bad$bad", "$argon2id$v=19$m=32768,t=2,p=1$bad$bad"} {
		if matched, err := verifyWeChatProviderIntent(intent, verifier); err == nil || matched {
			t.Fatalf("malformed verifier %q: matched=%v err=%v", verifier, matched, err)
		}
	}
}

func TestWeChatProviderIntentMigrationIsDurableAndIrreversible(t *testing.T) {
	path := filepath.Join(findBackendRoot(t), "migrations", "00014_wechat_registration_provider_intents.sql")
	raw, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read migration: %v", err)
	}
	sql := string(raw)
	for _, term := range []string{"wechat_registration_provider_intents", "request_verifier", "ON DELETE CASCADE", "argon2id", "m=32768,t=2,p=1"} {
		if !strings.Contains(sql, term) {
			t.Errorf("migration missing %q", term)
		}
	}
	down := sql[strings.Index(sql, "-- +goose Down"):]
	if !strings.Contains(down, "intentionally irreversible") || regexp.MustCompile(`(?i)\b(?:DROP|DELETE|TRUNCATE|ALTER)\b`).MatchString(down) {
		t.Fatal("Down must be intentionally inert")
	}
}
