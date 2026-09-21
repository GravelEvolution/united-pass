package bootstrap

import (
	"context"
	"fmt"

	"github.com/GravelEvolution/united-pass/backend/internal/adapters/captcha"
	"github.com/GravelEvolution/united-pass/backend/internal/config"
	"github.com/GravelEvolution/united-pass/backend/internal/riskdefense"
)

func newRiskCaptchaProvider(cfg config.RiskCaptchaConfig, builtIn ...riskdefense.ManagedInteractiveProvider) (riskdefense.InteractiveVerifier, error) {
	providers := make([]riskdefense.ManagedInteractiveProvider, 0, 2+len(builtIn))
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
	providers = append(providers, builtIn...)
	if len(providers) == 0 {
		return nil, nil
	}
	region := riskdefense.ProviderRegion(cfg.Region)
	pool, err := riskdefense.NewInteractiveProviderPool(region, providers...)
	if err != nil {
		return nil, fmt.Errorf("configure CAPTCHA provider pool: %w", err)
	}
	if len(builtIn) == 0 {
		return pool, nil
	}
	registrationPool, err := riskdefense.NewInteractiveProviderPool(region, builtIn...)
	if err != nil {
		return nil, fmt.Errorf("configure registration CAPTCHA provider: %w", err)
	}
	return &registrationPinnedCaptchaProvider{all: pool, registration: registrationPool}, nil
}

// registrationPinnedCaptchaProvider makes the built-in image challenge a
// mandatory, keyless registration gate while retaining the configured
// Turnstile/reCAPTCHA rotation for login. Both pools use the same wrapped
// provider challenge format, so verification remains server-selected.
type registrationPinnedCaptchaProvider struct {
	all          riskdefense.InteractiveVerifier
	registration riskdefense.InteractiveVerifier
}

func (p *registrationPinnedCaptchaProvider) Begin(ctx context.Context, operation riskdefense.Operation) (riskdefense.ProviderChallenge, error) {
	if operation == riskdefense.OperationRegistration || operation == riskdefense.OperationPhoneChange {
		return p.registration.Begin(ctx, operation)
	}
	return p.all.Begin(ctx, operation)
}

func (p *registrationPinnedCaptchaProvider) Verify(ctx context.Context, challengeID, proof string) error {
	return p.all.Verify(ctx, challengeID, proof)
}
