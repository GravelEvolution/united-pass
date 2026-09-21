// Package riskdefense applies objective, server-observed abuse signals to
// public registration and login. It deliberately does not inspect names,
// prose, display names, or any other subjective user content.
package riskdefense

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"time"
)

type Operation string

const (
	OperationLogin        Operation = "login"
	OperationRegistration Operation = "registration"
	OperationPhoneChange  Operation = "phone_change"
)

type Level string

const (
	LevelLow    Level = "low"
	LevelMedium Level = "medium"
	LevelHigh   Level = "high"
)

type Method string

const (
	// MethodAutomationCost is a proof-of-work speed bump. It is not human
	// verification and must never be presented as CAPTCHA or identity proof.
	MethodAutomationCost     Method = "automation_cost"
	MethodInteractiveCAPTCHA Method = "interactive_captcha"
	MethodMFA                Method = "mfa"
	MethodReauthentication   Method = "reauth"
)

var (
	ErrUnavailable       = errors.New("risk defense unavailable")
	ErrChallengeNotFound = errors.New("risk challenge not found")
	ErrChallengeClaimed  = errors.New("risk challenge claimed")
	ErrChallengeNotHeld  = errors.New("risk challenge claim not held")
	ErrTrustNotFound     = errors.New("risk device trust not found")
	ErrInvalidProof      = errors.New("invalid risk challenge proof")
	ErrRateLimited       = errors.New("risk challenge rate limited")
)

type RateLimitError struct{ RetryAfter time.Duration }

func (e *RateLimitError) Error() string { return ErrRateLimited.Error() }
func (e *RateLimitError) Unwrap() error { return ErrRateLimited }

// RateLimit is kept local to the risk boundary so CAPTCHA issuance cannot
// depend on the account-registration package.
type RateLimit struct {
	Max    int
	Window time.Duration
}

type RegistrationIssueRatePolicy struct {
	Device          RateLimit
	Network         RateLimit
	GlobalBurst     RateLimit
	GlobalSustained RateLimit
}

type Activity struct {
	Attempts int
}

// ChallengeRecord is stored only under a SHA-256 hash of the raw challenge
// token. Device and user-agent values are hashes as well.
type ChallengeRecord struct {
	Operation           Operation `json:"operation"`
	Level               Level     `json:"level"`
	Method              Method    `json:"method"`
	DeviceIDHash        string    `json:"deviceIdHash"`
	UserAgentHash       string    `json:"userAgentHash"`
	IdentifierHash      string    `json:"identifierHash"`
	ClientNetworkHash   string    `json:"clientNetworkHash,omitempty"`
	RegistrationScope   string    `json:"registrationScope,omitempty"`
	Difficulty          uint8     `json:"difficulty,omitempty"`
	ProviderChallengeID string    `json:"providerChallengeId,omitempty"`
	CreatedAt           time.Time `json:"createdAt"`
}

type TrustRecord struct {
	DeviceIDHash   string    `json:"deviceIdHash"`
	UserAgentHash  string    `json:"userAgentHash"`
	Operation      Operation `json:"operation,omitempty"`
	IdentifierHash string    `json:"identifierHash,omitempty"`
	ExpiresAt      time.Time `json:"expiresAt"`
}

type Store interface {
	RegisterDevice(context.Context, string, time.Duration) error
	DeviceExists(context.Context, string) (bool, error)
	Observe(context.Context, Operation, string, string, time.Duration) (Activity, error)
	CreateChallenge(context.Context, string, ChallengeRecord, time.Duration) error
	ReserveRegistrationChallenge(context.Context, string, string, time.Duration) (bool, time.Duration, error)
	FinalizeRegistrationChallenge(context.Context, string, string, ChallengeRecord, time.Duration) error
	ReleaseRegistrationChallenge(context.Context, string, string) error
	ClaimChallenge(context.Context, string, string) (ChallengeRecord, error)
	ReleaseChallenge(context.Context, string, string) error
	ConsumeChallenge(context.Context, string, string) error
	ConsumeRegistrationChallenge(context.Context, string, string, string) error
	PutTrust(context.Context, string, TrustRecord, time.Duration) error
	GetTrust(context.Context, string) (TrustRecord, error)
	CheckCompletionRate(context.Context, string, int, time.Duration) (bool, time.Duration, error)
	CheckRegistrationIssueRate(context.Context, string, string, RegistrationIssueRatePolicy) (bool, time.Duration, error)
	CheckRegistrationCompletionRate(context.Context, string, string, int, int, time.Duration) (bool, time.Duration, error)
}

type ProviderChallenge struct {
	ID            string
	Provider      string
	PublicPayload json.RawMessage
}

// InteractiveVerifier is the narrow seam for a human-verification provider.
// An Aliyun CAPTCHA 2.0 adapter can implement it without changing HTTP types.
type InteractiveVerifier interface {
	Begin(context.Context, Operation) (ProviderChallenge, error)
	Verify(context.Context, string, string) error
}

type Config struct {
	Enabled                            bool
	ObservationWindow                  time.Duration
	LoginMediumAfter                   int
	LoginHighAfter                     int
	RegistrationMediumAfter            int
	RegistrationHighAfter              int
	ChallengeTTL                       time.Duration
	DeviceIDTTL                        time.Duration
	TrustTTL                           time.Duration
	AutomationCostDifficulty           uint8
	CompletionLimit                    int
	CompletionWindow                   time.Duration
	RegistrationIssueDeviceLimit       int
	RegistrationIssueNetworkLimit      int
	RegistrationIssueWindow            time.Duration
	RegistrationIssueGlobalBurstLimit  int
	RegistrationIssueGlobalBurstWindow time.Duration
	RegistrationIssueGlobalLimit       int
	RegistrationIssueGlobalWindow      time.Duration
	RegistrationIssueMaxInFlight       int
	RegistrationIssueMaxQueued         int
	RegistrationIssueWaitTimeout       time.Duration
	RegistrationCompletionDeviceLimit  int
	RegistrationCompletionNetworkLimit int
	RegistrationCompletionWindow       time.Duration
	AllowlistedHashes                  []string
	Now                                func() time.Time
	GenerateToken                      func() (string, error)
}

type Signal struct {
	Operation        Operation
	IdentifierHash   string
	DeviceIDToken    string
	DeviceTrustToken string
	UserAgentHash    string
	// ClientNetworkHash is supplied only by the trusted HTTP boundary after
	// canonical proxy parsing. Registration requires it; login deliberately
	// keeps its existing provider flow and leaves it empty.
	ClientNetworkHash string
	SessionTrusted    bool
	// ProtocolAnomaly is set only for a server-verifiable protocol problem,
	// never for ordinary first use or elapsed time.
	ProtocolAnomaly bool
	SessionAnomaly  bool
	EmailRisk       bool
	ReplayAnomaly   bool
}

type Challenge struct {
	Token         string
	Level         Level
	Method        Method
	Difficulty    uint8
	Provider      string
	PublicPayload json.RawMessage
	ExpiresAt     time.Time
	ProviderReady bool
}

type Decision struct {
	Allow         bool
	DeviceIDToken string
	Challenge     *Challenge
}

type Completion struct {
	ChallengeToken string
	Nonce          string
	ProviderProof  string
	DeviceIDToken  string
	UserAgentHash  string
}

type CompleteResult struct {
	TrustToken string
	ExpiresAt  time.Time
}

type Service struct {
	store                      Store
	provider                   InteractiveVerifier
	cfg                        Config
	allowlist                  map[string]struct{}
	registrationIssueAdmission *issueAdmission
}

const highRiskAutomationCostExtraBits uint8 = 4

const registrationChallengeReservationTTL = 15 * time.Second

func NewService(store Store, provider InteractiveVerifier, cfg Config) (*Service, error) {
	if cfg.Now == nil {
		cfg.Now = time.Now
	}
	if cfg.GenerateToken == nil {
		cfg.GenerateToken = generateToken
	}
	if cfg.RegistrationIssueDeviceLimit <= 0 {
		cfg.RegistrationIssueDeviceLimit = 4
	}
	if cfg.RegistrationIssueNetworkLimit <= 0 {
		cfg.RegistrationIssueNetworkLimit = 128
	}
	if cfg.RegistrationIssueWindow <= 0 {
		cfg.RegistrationIssueWindow = cfg.ObservationWindow
	}
	if cfg.RegistrationIssueGlobalBurstLimit <= 0 {
		cfg.RegistrationIssueGlobalBurstLimit = 20
	}
	if cfg.RegistrationIssueGlobalBurstWindow <= 0 {
		cfg.RegistrationIssueGlobalBurstWindow = 10 * time.Second
	}
	if cfg.RegistrationIssueGlobalLimit <= 0 {
		cfg.RegistrationIssueGlobalLimit = 100
	}
	if cfg.RegistrationIssueGlobalWindow <= 0 {
		cfg.RegistrationIssueGlobalWindow = 5 * time.Minute
	}
	if cfg.RegistrationIssueMaxInFlight <= 0 {
		cfg.RegistrationIssueMaxInFlight = 4
	}
	if cfg.RegistrationIssueMaxQueued < 0 {
		return nil, ErrUnavailable
	}
	if cfg.RegistrationIssueWaitTimeout <= 0 {
		cfg.RegistrationIssueWaitTimeout = 500 * time.Millisecond
	}
	if cfg.RegistrationCompletionDeviceLimit <= 0 {
		cfg.RegistrationCompletionDeviceLimit = cfg.CompletionLimit
	}
	if cfg.RegistrationCompletionNetworkLimit <= 0 {
		cfg.RegistrationCompletionNetworkLimit = cfg.CompletionLimit * 32
	}
	if cfg.RegistrationCompletionWindow <= 0 {
		cfg.RegistrationCompletionWindow = cfg.CompletionWindow
	}
	if cfg.Enabled && (store == nil || cfg.ObservationWindow <= 0 || cfg.ChallengeTTL <= 0 || cfg.DeviceIDTTL <= 0 || cfg.TrustTTL <= 0 || cfg.CompletionLimit <= 0 || cfg.CompletionWindow <= 0 || cfg.AutomationCostDifficulty == 0 || cfg.AutomationCostDifficulty > 30) {
		return nil, ErrUnavailable
	}
	if cfg.LoginMediumAfter <= 0 || cfg.LoginHighAfter <= cfg.LoginMediumAfter || cfg.RegistrationMediumAfter <= 0 || cfg.RegistrationHighAfter <= cfg.RegistrationMediumAfter {
		return nil, ErrUnavailable
	}
	allowlist := make(map[string]struct{}, len(cfg.AllowlistedHashes))
	for _, raw := range cfg.AllowlistedHashes {
		digest := strings.ToLower(strings.TrimSpace(raw))
		decoded, err := hex.DecodeString(digest)
		if err != nil || len(decoded) != sha256.Size {
			return nil, fmt.Errorf("%w: malformed allowlist digest", ErrUnavailable)
		}
		allowlist[digest] = struct{}{}
	}
	issueGate, err := newIssueAdmission(cfg.RegistrationIssueMaxInFlight, cfg.RegistrationIssueMaxQueued, cfg.RegistrationIssueWaitTimeout)
	if err != nil {
		return nil, ErrUnavailable
	}
	return &Service{store: store, provider: provider, cfg: cfg, allowlist: allowlist, registrationIssueAdmission: issueGate}, nil
}

func (s *Service) Assess(ctx context.Context, signal Signal) (Decision, error) {
	if s == nil || !s.cfg.Enabled {
		return Decision{Allow: true}, nil
	}
	if !validSignal(signal) {
		return Decision{}, ErrUnavailable
	}

	deviceToken, deviceHash, invalidDevice, err := s.ensureDevice(ctx, signal.DeviceIDToken)
	if err != nil {
		return Decision{}, err
	}
	decision := Decision{DeviceIDToken: deviceToken}
	// Registration must always prove one freshly bound interactive challenge.
	// Login allowlists and an existing authenticated session therefore never
	// bypass the registration gate; only the one-use trust produced for the
	// exact registration intent may admit its automatic retry.
	if signal.Operation != OperationRegistration && signal.Operation != OperationPhoneChange {
		_, allowlisted := s.allowlist[strings.ToLower(signal.IdentifierHash)]
		if allowlisted || signal.SessionTrusted {
			decision.Allow = true
			return decision, nil
		}
	}
	if signal.DeviceTrustToken != "" {
		trusted, trustErr := s.validTrust(ctx, signal.DeviceTrustToken, deviceHash, signal)
		if trustErr != nil {
			return Decision{}, trustErr
		}
		if trusted {
			decision.Allow = true
			return decision, nil
		}
	}

	activity, err := s.store.Observe(ctx, signal.Operation, deviceHash, strings.ToLower(signal.IdentifierHash), s.cfg.ObservationWindow)
	if err != nil {
		return Decision{}, ErrUnavailable
	}
	anomalies := 0
	if signal.ProtocolAnomaly || invalidDevice {
		anomalies++
	}
	if signal.SessionAnomaly {
		anomalies++
	}
	if signal.EmailRisk {
		anomalies++
	}
	if signal.ReplayAnomaly {
		// A confirmed replay is independently strong enough to satisfy the
		// two-signal high-risk requirement. Ordinary elapsed time is not.
		anomalies += 2
	}
	level := s.level(signal.Operation, activity.Attempts, anomalies)
	if level == LevelLow {
		decision.Allow = true
		return decision, nil
	}

	challenge, err := s.issue(ctx, signal, deviceHash, level)
	if err != nil {
		return Decision{}, err
	}
	decision.Challenge = &challenge
	return decision, nil
}

// EnsureDevice returns a server-registered device token without granting any
// request or trust. Registration form intents use it before issuance so their
// binding never has an empty-device wildcard.
func (s *Service) EnsureDevice(ctx context.Context, raw string) (string, error) {
	if s == nil || !s.cfg.Enabled {
		return "", ErrUnavailable
	}
	token, _, _, err := s.ensureDevice(ctx, raw)
	if err != nil || token == "" {
		return "", ErrUnavailable
	}
	return token, nil
}

func (s *Service) Complete(ctx context.Context, input Completion) (CompleteResult, error) {
	if s == nil || !s.cfg.Enabled || input.ChallengeToken == "" || input.DeviceIDToken == "" || input.UserAgentHash == "" {
		return CompleteResult{}, ErrInvalidProof
	}
	challengeHash := hash(input.ChallengeToken)
	claimID, err := s.cfg.GenerateToken()
	if err != nil || claimID == "" {
		return CompleteResult{}, ErrUnavailable
	}
	record, err := s.store.ClaimChallenge(ctx, challengeHash, claimID)
	if err != nil {
		return CompleteResult{}, err
	}
	release := func() { _ = s.store.ReleaseChallenge(context.WithoutCancel(ctx), challengeHash, claimID) }
	if !constantEqual(record.DeviceIDHash, hash(input.DeviceIDToken)) || !constantEqual(record.UserAgentHash, input.UserAgentHash) {
		release()
		return CompleteResult{}, ErrInvalidProof
	}
	allowed, retryAfter, err := s.store.CheckCompletionRate(ctx, challengeHash, s.cfg.CompletionLimit, s.cfg.CompletionWindow)
	if err != nil {
		release()
		return CompleteResult{}, ErrUnavailable
	}
	if !allowed {
		release()
		return CompleteResult{}, &RateLimitError{RetryAfter: retryAfter}
	}
	if record.Operation == OperationRegistration {
		if !validDigest(record.ClientNetworkHash) || !validDigest(record.RegistrationScope) {
			release()
			return CompleteResult{}, ErrUnavailable
		}
		allowed, retryAfter, err = s.store.CheckRegistrationCompletionRate(
			ctx, record.DeviceIDHash, record.ClientNetworkHash,
			s.cfg.RegistrationCompletionDeviceLimit, s.cfg.RegistrationCompletionNetworkLimit,
			s.cfg.RegistrationCompletionWindow,
		)
		if err != nil {
			release()
			return CompleteResult{}, ErrUnavailable
		}
		if !allowed {
			release()
			return CompleteResult{}, &RateLimitError{RetryAfter: retryAfter}
		}
	}

	switch record.Method {
	case MethodAutomationCost:
		if !validAutomationCost(input.ChallengeToken, input.Nonce, record.Difficulty) {
			release()
			return CompleteResult{}, ErrInvalidProof
		}
	case MethodInteractiveCAPTCHA:
		if s.provider == nil || record.ProviderChallengeID == "" {
			release()
			return CompleteResult{}, ErrUnavailable
		}
		if err := s.provider.Verify(ctx, record.ProviderChallengeID, input.ProviderProof); err != nil {
			release()
			return CompleteResult{}, ErrInvalidProof
		}
	default:
		release()
		return CompleteResult{}, ErrInvalidProof
	}

	if record.Operation == OperationRegistration {
		err = s.store.ConsumeRegistrationChallenge(ctx, challengeHash, claimID, record.RegistrationScope)
	} else {
		err = s.store.ConsumeChallenge(ctx, challengeHash, claimID)
	}
	if err != nil {
		return CompleteResult{}, err
	}
	trustToken, err := s.cfg.GenerateToken()
	if err != nil || trustToken == "" {
		return CompleteResult{}, ErrUnavailable
	}
	expiresAt := s.cfg.Now().UTC().Add(s.cfg.TrustTTL)
	trust := TrustRecord{
		DeviceIDHash: record.DeviceIDHash, UserAgentHash: record.UserAgentHash,
		Operation: record.Operation, IdentifierHash: record.IdentifierHash, ExpiresAt: expiresAt,
	}
	if err := s.store.PutTrust(ctx, hash(trustToken), trust, s.cfg.TrustTTL); err != nil {
		return CompleteResult{}, ErrUnavailable
	}
	return CompleteResult{TrustToken: trustToken, ExpiresAt: expiresAt}, nil
}

func (s *Service) ensureDevice(ctx context.Context, raw string) (string, string, bool, error) {
	if raw != "" {
		digest := hash(raw)
		exists, err := s.store.DeviceExists(ctx, digest)
		if err != nil {
			return "", "", false, ErrUnavailable
		}
		if exists {
			return raw, digest, false, nil
		}
	}
	token, err := s.cfg.GenerateToken()
	if err != nil || token == "" {
		return "", "", false, ErrUnavailable
	}
	digest := hash(token)
	if err := s.store.RegisterDevice(ctx, digest, s.cfg.DeviceIDTTL); err != nil {
		return "", "", false, ErrUnavailable
	}
	// Absence is the normal first-use case. Only a supplied token that the
	// server never issued (or that expired) is an objective protocol anomaly.
	return token, digest, raw != "", nil
}

func (s *Service) validTrust(ctx context.Context, raw, deviceHash string, signal Signal) (bool, error) {
	record, err := s.store.GetTrust(ctx, hash(raw))
	if errors.Is(err, ErrTrustNotFound) {
		return false, nil
	}
	if err != nil {
		return false, ErrUnavailable
	}
	valid := s.cfg.Now().UTC().Before(record.ExpiresAt) && constantEqual(record.DeviceIDHash, deviceHash) && constantEqual(record.UserAgentHash, signal.UserAgentHash)
	if !valid {
		return false, nil
	}
	// Trust is always operation- and identifier-bound. In particular, a solved
	// registration CAPTCHA must not suppress login defenses, and a login trust
	// for one identifier must not carry to another account.
	return record.Operation == signal.Operation && constantEqual(record.IdentifierHash, strings.ToLower(signal.IdentifierHash)), nil
}

func (s *Service) level(operation Operation, attempts, anomalies int) Level {
	medium, high := s.cfg.LoginMediumAfter, s.cfg.LoginHighAfter
	if operation == OperationRegistration {
		// A bot can rotate email, IP and cookies so every public registration
		// appears to be a first low-risk attempt. Registration therefore starts
		// at the interactive tier; its one-use trust is bound to the exact form
		// intent tuple by IdentifierHash at the HTTP boundary.
		return LevelHigh
	}
	if operation == OperationPhoneChange {
		return LevelHigh
	}
	// Login stays deliberately conservative: frequency alone cannot distinguish
	// a person mistyping a password from automation. It only strengthens an
	// independent server-verifiable anomaly.
	if attempts >= high && anomalies >= 2 {
		return LevelHigh
	}
	if attempts >= medium && anomalies >= 1 {
		return LevelMedium
	}
	return LevelLow
}

func (s *Service) issue(ctx context.Context, signal Signal, deviceHash string, level Level) (Challenge, error) {
	token, err := s.cfg.GenerateToken()
	if err != nil || token == "" {
		return Challenge{}, ErrUnavailable
	}
	now := s.cfg.Now().UTC()
	record := ChallengeRecord{
		Operation: signal.Operation, Level: level, DeviceIDHash: deviceHash,
		UserAgentHash: signal.UserAgentHash, IdentifierHash: strings.ToLower(signal.IdentifierHash), CreatedAt: now,
	}
	challenge := Challenge{Token: token, Level: level, ExpiresAt: now.Add(s.cfg.ChallengeTTL)}
	registrationReserved := false
	if signal.Operation == OperationRegistration {
		record.ClientNetworkHash = strings.ToLower(signal.ClientNetworkHash)
		record.RegistrationScope = registrationScope(signal, deviceHash)
		reserved, retryAfter, reserveErr := s.store.ReserveRegistrationChallenge(
			ctx, record.RegistrationScope, hash(token), registrationChallengeReservationTTL,
		)
		if reserveErr != nil {
			return Challenge{}, ErrUnavailable
		}
		if !reserved {
			return Challenge{}, &RateLimitError{RetryAfter: retryAfter}
		}
		registrationReserved = true
		allowed, retryAfter, rateErr := s.store.CheckRegistrationIssueRate(ctx, deviceHash, record.ClientNetworkHash, RegistrationIssueRatePolicy{
			Device:          RateLimit{Max: s.cfg.RegistrationIssueDeviceLimit, Window: s.cfg.RegistrationIssueWindow},
			Network:         RateLimit{Max: s.cfg.RegistrationIssueNetworkLimit, Window: s.cfg.RegistrationIssueWindow},
			GlobalBurst:     RateLimit{Max: s.cfg.RegistrationIssueGlobalBurstLimit, Window: s.cfg.RegistrationIssueGlobalBurstWindow},
			GlobalSustained: RateLimit{Max: s.cfg.RegistrationIssueGlobalLimit, Window: s.cfg.RegistrationIssueGlobalWindow},
		})
		if rateErr != nil {
			_ = s.store.ReleaseRegistrationChallenge(context.WithoutCancel(ctx), record.RegistrationScope, hash(token))
			return Challenge{}, ErrUnavailable
		}
		if !allowed {
			_ = s.store.ReleaseRegistrationChallenge(context.WithoutCancel(ctx), record.RegistrationScope, hash(token))
			return Challenge{}, &RateLimitError{RetryAfter: retryAfter}
		}
	}
	releaseRegistrationReservation := func() {
		if registrationReserved {
			_ = s.store.ReleaseRegistrationChallenge(context.WithoutCancel(ctx), record.RegistrationScope, hash(token))
		}
	}
	if level == LevelMedium {
		record.Method = MethodAutomationCost
		record.Difficulty = s.cfg.AutomationCostDifficulty
		challenge.Method = record.Method
		challenge.Difficulty = record.Difficulty
		challenge.ProviderReady = true
	} else {
		// High risk prefers an interactive provider. Until a reviewed provider
		// and its production credentials are configured (or while Begin is
		// temporarily unavailable), never issue an impossible providerReady=false
		// challenge. Fall back to a stronger computational cost that the existing
		// completion endpoint can actually satisfy. This is not human verification.
		if s.provider != nil {
			releaseIssue := func() {}
			if signal.Operation == OperationRegistration {
				var acquired bool
				releaseIssue, acquired = s.registrationIssueAdmission.acquire(ctx)
				if !acquired {
					releaseRegistrationReservation()
					return Challenge{}, &RateLimitError{RetryAfter: s.cfg.RegistrationIssueWaitTimeout}
				}
			}
			providerChallenge, beginErr := s.provider.Begin(ctx, signal.Operation)
			releaseIssue()
			if beginErr == nil && providerChallenge.ID != "" && strings.TrimSpace(providerChallenge.Provider) != "" {
				record.Method = MethodInteractiveCAPTCHA
				record.ProviderChallengeID = providerChallenge.ID
				challenge.Method = record.Method
				challenge.Provider = providerChallenge.Provider
				challenge.PublicPayload = providerChallenge.PublicPayload
				challenge.ProviderReady = true
			}
		}
		if record.Method == "" && (signal.Operation == OperationRegistration || signal.Operation == OperationPhoneChange) {
			// Registration has no computational fallback: proof-of-work is not
			// human verification and would reopen the first-attempt bypass when an
			// interactive provider is absent or unhealthy.
			releaseRegistrationReservation()
			return Challenge{}, ErrUnavailable
		}
		if record.Method == "" {
			record.Method = MethodAutomationCost
			record.Difficulty = strongerAutomationCostDifficulty(s.cfg.AutomationCostDifficulty)
			challenge.Method = record.Method
			challenge.Difficulty = record.Difficulty
			challenge.ProviderReady = true
		}
	}
	if signal.Operation == OperationRegistration {
		err = s.store.FinalizeRegistrationChallenge(ctx, record.RegistrationScope, hash(token), record, s.cfg.ChallengeTTL)
		if err == nil {
			registrationReserved = false
		}
	} else {
		err = s.store.CreateChallenge(ctx, hash(token), record, s.cfg.ChallengeTTL)
	}
	if err != nil {
		releaseRegistrationReservation()
		return Challenge{}, ErrUnavailable
	}
	return challenge, nil
}

func strongerAutomationCostDifficulty(base uint8) uint8 {
	if base >= 30-highRiskAutomationCostExtraBits {
		return 30
	}
	return base + highRiskAutomationCostExtraBits
}

func validSignal(signal Signal) bool {
	valid := (signal.Operation == OperationLogin || signal.Operation == OperationRegistration || signal.Operation == OperationPhoneChange) && validDigest(signal.IdentifierHash) && validDigest(signal.UserAgentHash)
	return valid && (signal.Operation != OperationRegistration || validDigest(signal.ClientNetworkHash))
}

func registrationScope(signal Signal, deviceHash string) string {
	return hash(string(OperationRegistration) + "\x00" + strings.ToLower(signal.IdentifierHash) + "\x00" + deviceHash + "\x00" + strings.ToLower(signal.ClientNetworkHash))
}

func validDigest(value string) bool {
	if len(value) != sha256.Size*2 {
		return false
	}
	_, err := hex.DecodeString(value)
	return err == nil
}

func validAutomationCost(token, nonce string, difficulty uint8) bool {
	if token == "" || nonce == "" || len(nonce) > 256 || difficulty == 0 || difficulty > 30 {
		return false
	}
	sum := sha256.Sum256([]byte(token + ":" + nonce))
	whole := int(difficulty / 8)
	for i := 0; i < whole; i++ {
		if sum[i] != 0 {
			return false
		}
	}
	remaining := difficulty % 8
	return remaining == 0 || sum[whole]>>(8-remaining) == 0
}

func hash(value string) string {
	sum := sha256.Sum256([]byte(value))
	return hex.EncodeToString(sum[:])
}

func constantEqual(a, b string) bool {
	return len(a) == len(b) && subtle.ConstantTimeCompare([]byte(a), []byte(b)) == 1
}

func generateToken() (string, error) {
	var raw [32]byte
	if _, err := rand.Read(raw[:]); err != nil {
		return "", err
	}
	return base64.RawURLEncoding.EncodeToString(raw[:]), nil
}
