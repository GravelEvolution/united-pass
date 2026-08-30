package bootstrap

import (
	"fmt"

	"github.com/GravelEvolution/united-pass/backend/internal/adapters/captcha"
	"github.com/GravelEvolution/united-pass/backend/internal/config"
	"github.com/GravelEvolution/united-pass/backend/internal/riskdefense"
)

func newRiskCaptchaProvider(cfg config.RiskCaptchaConfig) (riskdefense.InteractiveVerifier, error) {
	providers := make([]riskdefense.ManagedInteractiveProvider, 0, 2)
	if cfg.Turnstile.Configured() {
		provider, err := captcha.NewTurnstile(captcha.TurnstileConfig{
			SiteKey: cfg.Turnstile.SiteKey, SecretKey: cfg.Turnstile.SecretKey, Hostname: cfg.Turnstile.Hostname,
		})
		if err != nil {
			return nil, fmt.Errorf("configure Turnstile: %w", err)
		}
		providers = append(providers, provider)
	}
	if cfg.Recaptcha.Configured() {
		provider, err := captcha.NewRecaptcha(captcha.RecaptchaConfig{
			SiteKey: cfg.Recaptcha.SiteKey, SecretKey: cfg.Recaptcha.SecretKey,
			Hostname: cfg.Recaptcha.Hostname, MinScore: cfg.Recaptcha.MinScore,
		})
		if err != nil {
			return nil, fmt.Errorf("configure reCAPTCHA: %w", err)
		}
		providers = append(providers, provider)
	}
	if len(providers) == 0 {
		return nil, nil
	}
	region := riskdefense.ProviderRegion(cfg.Region)
	pool, err := riskdefense.NewInteractiveProviderPool(region, providers...)
	if err != nil {
		return nil, fmt.Errorf("configure CAPTCHA provider pool: %w", err)
	}
	return pool, nil
}
