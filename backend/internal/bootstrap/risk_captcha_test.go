package bootstrap

import (
	"strings"
	"testing"

	"github.com/GravelEvolution/united-pass/backend/internal/adapters/captcha"
	"github.com/GravelEvolution/united-pass/backend/internal/config"
	"github.com/GravelEvolution/united-pass/backend/internal/riskdefense"
)

func TestRiskCaptchaProviderIsDisabledWithoutCompleteConfiguration(t *testing.T) {
	provider, err := newRiskCaptchaProvider(config.RiskCaptchaConfig{Region: "mainland_china"})
	if err != nil || provider != nil {
		t.Fatalf("provider=%#v err=%v", provider, err)
	}
}

func TestRiskCaptchaProviderSelectionIsServerOwnedAndRegional(t *testing.T) {
	cfg := config.RiskCaptchaConfig{
		Region: "mainland_china",
		Turnstile: config.RiskCaptchaProviderConfig{
			SiteKey: "turnstile-site", SecretKey: "turnstile-secret", Hostname: "auth.moonstone.org.cn",
		},
		Recaptcha: config.RiskRecaptchaConfig{
			SiteKey: "recaptcha-site", SecretKey: "recaptcha-secret", Hostname: "auth.moonstone.org.cn", MinScore: 0.7,
		},
	}
	provider, err := newRiskCaptchaProvider(cfg)
	if err != nil {
		t.Fatal(err)
	}
	challenge, err := provider.Begin(t.Context(), riskdefense.OperationRegistration)
	if err != nil {
		t.Fatal(err)
	}
	if challenge.Provider != captcha.RecaptchaProviderName {
		t.Fatalf("mainland provider=%q, want recaptcha.net fallback", challenge.Provider)
	}
	if strings.Contains(string(challenge.PublicPayload), "secret") {
		t.Fatalf("provider secret leaked in public payload: %s", challenge.PublicPayload)
	}

	cfg.Region = "global"
	cfg.Recaptcha = config.RiskRecaptchaConfig{}
	provider, err = newRiskCaptchaProvider(cfg)
	if err != nil {
		t.Fatal(err)
	}
	challenge, err = provider.Begin(t.Context(), riskdefense.OperationLogin)
	if err != nil {
		t.Fatal(err)
	}
	if challenge.Provider != captcha.TurnstileProviderName {
		t.Fatalf("global provider=%q, want Turnstile", challenge.Provider)
	}
}

func TestRiskCaptchaGlobalPoolRotatesConfiguredProviders(t *testing.T) {
	provider, err := newRiskCaptchaProvider(config.RiskCaptchaConfig{
		Region: "global",
		Turnstile: config.RiskCaptchaProviderConfig{
			SiteKey: "turnstile-site", SecretKey: "turnstile-secret", Hostname: "auth.moonstone.org.cn",
		},
		Recaptcha: config.RiskRecaptchaConfig{
			SiteKey: "recaptcha-site", SecretKey: "recaptcha-secret", Hostname: "auth.moonstone.org.cn", MinScore: 0.7,
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	selected := make(map[string]bool, 2)
	for range 2 {
		challenge, beginErr := provider.Begin(t.Context(), riskdefense.OperationLogin)
		if beginErr != nil {
			t.Fatal(beginErr)
		}
		selected[challenge.Provider] = true
	}
	if !selected[captcha.TurnstileProviderName] || !selected[captcha.RecaptchaProviderName] {
		t.Fatalf("global provider rotation=%#v", selected)
	}
}
