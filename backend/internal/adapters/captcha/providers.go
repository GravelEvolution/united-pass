// Package captcha contains reviewed server-side adapters for interactive
// CAPTCHA providers. Provider secrets and verification endpoints never cross
// the HTTP API boundary.
package captcha

import (
	"context"
	"crypto/rand"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"math"
	"net/http"
	"net/url"
	"strings"
	"sync/atomic"
	"time"

	"github.com/GravelEvolution/united-pass/backend/internal/riskdefense"
)

const (
	TurnstileProviderName = "cloudflare_turnstile"
	RecaptchaProviderName = "google_recaptcha"

	turnstileSiteverifyURL = "https://challenges.cloudflare.com/turnstile/v0/siteverify"
	recaptchaSiteverifyURL = "https://www.recaptcha.net/recaptcha/api/siteverify"

	maxProviderResponseBytes = 16 << 10
	defaultRequestTimeout    = 4 * time.Second
	defaultUnhealthyCooldown = 30 * time.Second
)

type TurnstileConfig struct {
	SiteKey   string
	SecretKey string
	Hostname  string
	Client    *http.Client
	Now       func() time.Time
	Random    io.Reader
}

type RecaptchaConfig struct {
	SiteKey   string
	SecretKey string
	Hostname  string
	MinScore  float64
	Client    *http.Client
	Now       func() time.Time
	Random    io.Reader
}

type providerRuntime struct {
	client         *http.Client
	now            func() time.Time
	random         io.Reader
	unhealthyUntil atomic.Int64
}

type Turnstile struct {
	runtime   providerRuntime
	siteKey   string
	secretKey string
	hostname  string
}

type Recaptcha struct {
	runtime   providerRuntime
	siteKey   string
	secretKey string
	hostname  string
	minScore  float64
}

func NewTurnstile(cfg TurnstileConfig) (*Turnstile, error) {
	siteKey, secretKey, hostname, err := normalizeConfig(cfg.SiteKey, cfg.SecretKey, cfg.Hostname)
	if err != nil {
		return nil, fmt.Errorf("turnstile: %w", err)
	}
	return &Turnstile{
		runtime:   newProviderRuntime(cfg.Client, cfg.Now, cfg.Random),
		siteKey:   siteKey,
		secretKey: secretKey,
		hostname:  hostname,
	}, nil
}

func NewRecaptcha(cfg RecaptchaConfig) (*Recaptcha, error) {
	siteKey, secretKey, hostname, err := normalizeConfig(cfg.SiteKey, cfg.SecretKey, cfg.Hostname)
	if err != nil {
		return nil, fmt.Errorf("recaptcha: %w", err)
	}
	if math.IsNaN(cfg.MinScore) || math.IsInf(cfg.MinScore, 0) || cfg.MinScore <= 0 || cfg.MinScore > 1 {
		return nil, errors.New("recaptcha: minimum score must be greater than zero and at most one")
	}
	return &Recaptcha{
		runtime:   newProviderRuntime(cfg.Client, cfg.Now, cfg.Random),
		siteKey:   siteKey,
		secretKey: secretKey,
		hostname:  hostname,
		minScore:  cfg.MinScore,
	}, nil
}

func (p *Turnstile) Name() string { return TurnstileProviderName }

func (p *Turnstile) Available(ctx context.Context, region riskdefense.ProviderRegion) bool {
	// Cloudflare documents that Turnstile is not supported in Mainland China.
	return p != nil && region == riskdefense.ProviderRegionGlobal && p.runtime.available(ctx)
}

func (p *Turnstile) Begin(ctx context.Context, operation riskdefense.Operation) (riskdefense.ProviderChallenge, error) {
	if p == nil || !p.runtime.available(ctx) {
		return riskdefense.ProviderChallenge{}, riskdefense.ErrUnavailable
	}
	action, err := providerAction(operation)
	if err != nil {
		return riskdefense.ProviderChallenge{}, err
	}
	cdata, err := p.runtime.randomToken(24)
	if err != nil {
		return riskdefense.ProviderChallenge{}, riskdefense.ErrUnavailable
	}
	idempotencyKey, err := p.runtime.randomUUID()
	if err != nil {
		return riskdefense.ProviderChallenge{}, riskdefense.ErrUnavailable
	}
	state := turnstileState{Action: action, CData: cdata, IdempotencyKey: idempotencyKey}
	id, err := encodeState(state)
	if err != nil {
		return riskdefense.ProviderChallenge{}, riskdefense.ErrUnavailable
	}
	payload, err := json.Marshal(turnstilePublicPayload{SiteKey: p.siteKey, Action: action, CData: cdata})
	if err != nil {
		return riskdefense.ProviderChallenge{}, riskdefense.ErrUnavailable
	}
	return riskdefense.ProviderChallenge{ID: id, Provider: p.Name(), PublicPayload: payload}, nil
}

func (p *Turnstile) Verify(ctx context.Context, challengeID, proof string) error {
	if p == nil || proof == "" || len(proof) > 2048 {
		return riskdefense.ErrInvalidProof
	}
	var state turnstileState
	if err := decodeState(challengeID, &state); err != nil || !validAction(state.Action) || !validCData(state.CData) || !validUUID(state.IdempotencyKey) {
		return riskdefense.ErrInvalidProof
	}
	form := url.Values{
		"secret":          {p.secretKey},
		"response":        {proof},
		"idempotency_key": {state.IdempotencyKey},
	}
	var result turnstileVerifyResponse
	if err := p.runtime.verifyJSON(ctx, turnstileSiteverifyURL, form, &result); err != nil {
		return err
	}
	if !result.Success {
		if providerConfigurationError(result.ErrorCodes) {
			p.runtime.markUnavailable()
			return riskdefense.ErrUnavailable
		}
		if providerServiceError(result.ErrorCodes) {
			return riskdefense.ErrUnavailable
		}
		return riskdefense.ErrInvalidProof
	}
	if len(result.ErrorCodes) != 0 || normalizeHostname(result.Hostname) != p.hostname || result.Action != state.Action || result.CData != state.CData || !freshTimestamp(result.ChallengeTS, p.runtime.now(), 6*time.Minute) {
		return riskdefense.ErrInvalidProof
	}
	return nil
}

func (p *Recaptcha) Name() string { return RecaptchaProviderName }

func (p *Recaptcha) Available(ctx context.Context, region riskdefense.ProviderRegion) bool {
	// recaptcha.net is the documented alternate domain when google.com is not
	// reachable. It is retained as a fallback in both regional pools.
	return p != nil && (region == riskdefense.ProviderRegionMainlandChina || region == riskdefense.ProviderRegionGlobal) && p.runtime.available(ctx)
}

func (p *Recaptcha) Begin(ctx context.Context, operation riskdefense.Operation) (riskdefense.ProviderChallenge, error) {
	if p == nil || !p.runtime.available(ctx) {
		return riskdefense.ProviderChallenge{}, riskdefense.ErrUnavailable
	}
	actionPrefix, err := providerAction(operation)
	if err != nil {
		return riskdefense.ProviderChallenge{}, err
	}
	// reCAPTCHA has no cdata equivalent. Make the server-issued action unique
	// per challenge so a valid token cannot be replayed across two UP
	// challenges for the same operation.
	nonce, err := p.runtime.randomLowerHex(5)
	if err != nil {
		return riskdefense.ProviderChallenge{}, riskdefense.ErrUnavailable
	}
	action := actionPrefix + "_" + nonce
	if !validAction(action) {
		return riskdefense.ProviderChallenge{}, riskdefense.ErrUnavailable
	}
	id, err := encodeState(recaptchaState{Action: action})
	if err != nil {
		return riskdefense.ProviderChallenge{}, riskdefense.ErrUnavailable
	}
	payload, err := json.Marshal(recaptchaPublicPayload{SiteKey: p.siteKey, Action: action})
	if err != nil {
		return riskdefense.ProviderChallenge{}, riskdefense.ErrUnavailable
	}
	return riskdefense.ProviderChallenge{ID: id, Provider: p.Name(), PublicPayload: payload}, nil
}

func (p *Recaptcha) Verify(ctx context.Context, challengeID, proof string) error {
	if p == nil || proof == "" || len(proof) > 4096 {
		return riskdefense.ErrInvalidProof
	}
	var state recaptchaState
	if err := decodeState(challengeID, &state); err != nil || !validAction(state.Action) {
		return riskdefense.ErrInvalidProof
	}
	form := url.Values{"secret": {p.secretKey}, "response": {proof}}
	var result recaptchaVerifyResponse
	if err := p.runtime.verifyJSON(ctx, recaptchaSiteverifyURL, form, &result); err != nil {
		return err
	}
	if !result.Success {
		if providerConfigurationError(result.ErrorCodes) {
			p.runtime.markUnavailable()
			return riskdefense.ErrUnavailable
		}
		if providerServiceError(result.ErrorCodes) {
			return riskdefense.ErrUnavailable
		}
		return riskdefense.ErrInvalidProof
	}
	// Fail closed when the legacy v3 endpoint reports a quota/configuration
	// warning alongside success; its documented over-quota behavior can return
	// a static score and must not be accepted as human verification.
	if len(result.ErrorCodes) != 0 || result.Score == nil || *result.Score < p.minScore || normalizeHostname(result.Hostname) != p.hostname || result.Action != state.Action || !freshTimestamp(result.ChallengeTS, p.runtime.now(), 3*time.Minute) {
		return riskdefense.ErrInvalidProof
	}
	return nil
}

type turnstileState struct {
	Action         string `json:"action"`
	CData          string `json:"cdata"`
	IdempotencyKey string `json:"idempotencyKey"`
}

type recaptchaState struct {
	Action string `json:"action"`
}

type turnstilePublicPayload struct {
	SiteKey string `json:"siteKey"`
	Action  string `json:"action"`
	CData   string `json:"cdata"`
}

type recaptchaPublicPayload struct {
	SiteKey string `json:"siteKey"`
	Action  string `json:"action"`
}

type turnstileVerifyResponse struct {
	Success     bool     `json:"success"`
	ChallengeTS string   `json:"challenge_ts"`
	Hostname    string   `json:"hostname"`
	ErrorCodes  []string `json:"error-codes"`
	Action      string   `json:"action"`
	CData       string   `json:"cdata"`
}

type recaptchaVerifyResponse struct {
	Success     bool     `json:"success"`
	Score       *float64 `json:"score"`
	Action      string   `json:"action"`
	ChallengeTS string   `json:"challenge_ts"`
	Hostname    string   `json:"hostname"`
	ErrorCodes  []string `json:"error-codes"`
}

func newProviderRuntime(client *http.Client, now func() time.Time, random io.Reader) providerRuntime {
	if now == nil {
		now = time.Now
	}
	if random == nil {
		random = rand.Reader
	}
	if client == nil {
		client = &http.Client{Timeout: defaultRequestTimeout}
	}
	clone := *client
	clone.Timeout = defaultRequestTimeout
	clone.CheckRedirect = func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }
	return providerRuntime{client: &clone, now: now, random: random}
}

func (r *providerRuntime) available(ctx context.Context) bool {
	if r == nil || ctx.Err() != nil {
		return false
	}
	return r.unhealthyUntil.Load() <= r.now().UnixMilli()
}

func (r *providerRuntime) markUnavailable() {
	r.unhealthyUntil.Store(r.now().Add(defaultUnhealthyCooldown).UnixMilli())
}

func (r *providerRuntime) verifyJSON(ctx context.Context, endpoint string, form url.Values, target any) error {
	requestContext, cancel := context.WithTimeout(ctx, defaultRequestTimeout)
	defer cancel()
	req, err := http.NewRequestWithContext(requestContext, http.MethodPost, endpoint, strings.NewReader(form.Encode()))
	if err != nil {
		return riskdefense.ErrUnavailable
	}
	req.Header.Set("Accept", "application/json")
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	resp, err := r.client.Do(req)
	if err != nil {
		r.markUnavailable()
		return riskdefense.ErrUnavailable
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		r.markUnavailable()
		return riskdefense.ErrUnavailable
	}
	body, err := io.ReadAll(io.LimitReader(resp.Body, maxProviderResponseBytes+1))
	if err != nil || len(body) > maxProviderResponseBytes || json.Unmarshal(body, target) != nil {
		r.markUnavailable()
		return riskdefense.ErrUnavailable
	}
	return nil
}

func (r *providerRuntime) randomToken(size int) (string, error) {
	value := make([]byte, size)
	if _, err := io.ReadFull(r.random, value); err != nil {
		return "", err
	}
	return base64.RawURLEncoding.EncodeToString(value), nil
}

func (r *providerRuntime) randomLowerHex(size int) (string, error) {
	value := make([]byte, size)
	if _, err := io.ReadFull(r.random, value); err != nil {
		return "", err
	}
	return hex.EncodeToString(value), nil
}

func (r *providerRuntime) randomUUID() (string, error) {
	var value [16]byte
	if _, err := io.ReadFull(r.random, value[:]); err != nil {
		return "", err
	}
	value[6] = value[6]&0x0f | 0x40
	value[8] = value[8]&0x3f | 0x80
	hexValue := hex.EncodeToString(value[:])
	return hexValue[0:8] + "-" + hexValue[8:12] + "-" + hexValue[12:16] + "-" + hexValue[16:20] + "-" + hexValue[20:32], nil
}

func normalizeConfig(siteKey, secretKey, hostname string) (string, string, string, error) {
	siteKey = strings.TrimSpace(siteKey)
	secretKey = strings.TrimSpace(secretKey)
	hostname = normalizeHostname(hostname)
	if siteKey == "" || len(siteKey) > 512 || secretKey == "" || len(secretKey) > 512 || !validHostname(hostname) {
		return "", "", "", errors.New("site key, secret key, and exact hostname are required")
	}
	return siteKey, secretKey, hostname, nil
}

func providerAction(operation riskdefense.Operation) (string, error) {
	switch operation {
	case riskdefense.OperationLogin:
		return "united_pass_login", nil
	case riskdefense.OperationRegistration:
		return "united_pass_register", nil
	default:
		return "", riskdefense.ErrUnavailable
	}
}

func encodeState(value any) (string, error) {
	payload, err := json.Marshal(value)
	if err != nil {
		return "", err
	}
	return base64.RawURLEncoding.EncodeToString(payload), nil
}

func decodeState(value string, target any) error {
	if value == "" || len(value) > 2048 {
		return riskdefense.ErrInvalidProof
	}
	payload, err := base64.RawURLEncoding.DecodeString(value)
	if err != nil || len(payload) > 1024 || json.Unmarshal(payload, target) != nil {
		return riskdefense.ErrInvalidProof
	}
	return nil
}

func providerConfigurationError(codes []string) bool {
	for _, code := range codes {
		switch code {
		case "missing-input-secret", "invalid-input-secret":
			return true
		}
	}
	return false
}

func providerServiceError(codes []string) bool {
	for _, code := range codes {
		if code == "internal-error" {
			return true
		}
	}
	return false
}

func freshTimestamp(raw string, now time.Time, maxAge time.Duration) bool {
	parsed, err := time.Parse(time.RFC3339, raw)
	if err != nil {
		return false
	}
	parsed = parsed.UTC()
	now = now.UTC()
	return !parsed.After(now.Add(time.Minute)) && !parsed.Before(now.Add(-maxAge))
}

func normalizeHostname(value string) string {
	return strings.TrimSuffix(strings.ToLower(strings.TrimSpace(value)), ".")
}

func validHostname(value string) bool {
	if value == "" || len(value) > 253 || strings.ContainsAny(value, "/:@") {
		return false
	}
	for _, label := range strings.Split(value, ".") {
		if label == "" || len(label) > 63 || label[0] == '-' || label[len(label)-1] == '-' {
			return false
		}
		for _, char := range label {
			if (char < 'a' || char > 'z') && (char < '0' || char > '9') && char != '-' {
				return false
			}
		}
	}
	return true
}

func validAction(value string) bool {
	if value == "" || len(value) > 32 {
		return false
	}
	for _, char := range value {
		if (char < 'a' || char > 'z') && (char < '0' || char > '9') && char != '_' && char != '-' {
			return false
		}
	}
	return true
}

func validCData(value string) bool {
	if value == "" || len(value) > 255 {
		return false
	}
	for _, char := range value {
		if (char < 'A' || char > 'Z') && (char < 'a' || char > 'z') && (char < '0' || char > '9') && char != '_' && char != '-' {
			return false
		}
	}
	return true
}

func validUUID(value string) bool {
	if len(value) != 36 || value[8] != '-' || value[13] != '-' || value[18] != '-' || value[23] != '-' {
		return false
	}
	_, err := hex.DecodeString(strings.ReplaceAll(value, "-", ""))
	return err == nil
}

var (
	_ riskdefense.ManagedInteractiveProvider = (*Turnstile)(nil)
	_ riskdefense.ManagedInteractiveProvider = (*Recaptcha)(nil)
)
