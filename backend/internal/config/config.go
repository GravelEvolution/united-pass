//
// Copyright (c) 2026 Chen Jiajie(Ariakage)
//
// Author: Chen Jiajie(Ariakage) <ariakage233@gmail.com>
// Date: 2026-08-05
// Description: Application configuration model and environment loading
//

// Package config loads and validates typed runtime configuration for the
// United Pass API service. Configuration is concentrated here so the rest of
// the codebase never reads environment variables directly.
package config

import (
	"bytes"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"math"
	"net"
	"net/mail"
	"net/netip"
	"net/url"
	"os"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"time"
)

// Environment classifies the deployment context. Production triggers stricter
// startup validation and security defaults.
type Environment string

const (
	EnvironmentDevelopment Environment = "development"
	EnvironmentProduction  Environment = "production"
)

const (
	defaultHTTPAddr            = ":8080"
	defaultReadHeaderTimeout   = 5 * time.Second
	defaultReadTimeout         = 15 * time.Second
	defaultWriteTimeout        = 30 * time.Second
	defaultIdleTimeout         = 60 * time.Second
	defaultShutdownTimeout     = 30 * time.Second
	defaultMaxRequestBodyBytes = 1 << 20 // 1 MiB
	defaultLogLevel            = "info"
	defaultAvatarDir           = "/var/lib/moonstone-united-pass/avatars"

	defaultDatabaseSchema               = "united_pass"
	defaultDatabaseMaxConns       int32 = 10
	defaultDatabaseMinConns       int32 = 1
	defaultDatabaseConnectTimeout       = 10 * time.Second

	defaultRedisKeyPrefix          = "up:development:"
	defaultRedisPoolSize       int = 10
	defaultRedisConnectTimeout     = 10 * time.Second
	defaultRedisReadTimeout        = 3 * time.Second
	defaultRedisWriteTimeout       = 3 * time.Second

	defaultSessionTTL           = 12 * time.Hour
	defaultSessionRememberTTL   = 720 * time.Hour
	defaultSessionIdleTTL       = 2 * time.Hour
	defaultSessionTouchInterval = 5 * time.Minute
	defaultSessionSameSite      = "lax"

	defaultMFAChallengeTTL              = 5 * time.Minute
	defaultMFAMaxAttempts               = 5
	defaultLoginRateLimit               = 10
	defaultLoginRateWindow              = 15 * time.Minute
	defaultMFARateLimit                 = 10
	defaultMFARateWindow                = 15 * time.Minute
	defaultAliyunSMSEndpoint            = "https://dysmsapi.aliyuncs.com/"
	defaultWeChatRequestTimeout         = 8 * time.Second
	defaultQRAuthChallengeTTL           = 2 * time.Minute
	defaultQRAuthRateLimit              = 12
	defaultQRAuthRateWindow             = 2 * time.Minute
	defaultDreamUPMobileScopedRateLimit = 60
	defaultDreamUPMobileGlobalRateLimit = 2000
	defaultDreamUPMobileRateWindow      = time.Minute
	defaultRiskObservationWindow        = 15 * time.Minute
	defaultRiskLoginMediumAfter         = 3
	defaultRiskLoginHighAfter           = 7
	defaultRiskRegistrationMediumAfter  = 2
	defaultRiskRegistrationHighAfter    = 3
	defaultRiskChallengeTTL             = 5 * time.Minute
	defaultRiskDeviceIDTTL              = 30 * 24 * time.Hour
	defaultRiskTrustTTL                 = 15 * time.Minute
	defaultRiskAutomationCostDifficulty = 18
	defaultRiskCompletionLimit          = 8
	defaultRiskCompletionWindow         = 15 * time.Minute
	defaultRiskCaptchaRegion            = "mainland_china"
	defaultRiskRecaptchaMinScore        = 0.7

	defaultRegistrationCreateIPLimit     = 3
	defaultRegistrationCreateIPWindow    = time.Hour
	defaultRegistrationCreateNetLimit    = 10
	defaultRegistrationCreateNetWindow   = time.Hour
	defaultRegistrationCreateEmailLimit  = 3
	defaultRegistrationCreateEmailWindow = 24 * time.Hour
	defaultRegistrationCreatePairLimit   = 2
	defaultRegistrationCreatePairWindow  = time.Hour
	defaultRegistrationVerifyLimit       = 8
	defaultRegistrationVerifyWindow      = 15 * time.Minute
	defaultRegistrationResendLimit       = 3
	defaultRegistrationResendWindow      = 30 * time.Minute
	defaultRegistrationIPv4NetBits       = 24
	defaultRegistrationIPv6NetBits       = 56
	defaultTrustedProxyCIDRs             = "127.0.0.1/32,::1/128"

	defaultReauthChallengeTTL    = 5 * time.Minute
	defaultReauthGrantTTL        = 5 * time.Minute
	defaultReauthMaxAttempts     = 5
	defaultReauthRateLimit       = 10
	defaultReauthRateWindow      = 15 * time.Minute
	defaultReauthCleanupInterval = 60 * time.Second

	defaultRotationGracePeriod = time.Duration(0)
	defaultRotationRateLimit   = 3
	defaultRotationRateWindow  = 15 * time.Minute

	defaultSecurityProviderDeadline      = 10 * time.Second
	defaultSecurityLeaseTTL              = 60 * time.Second
	defaultSecuritySettlementTimeout     = 15 * time.Second
	defaultSecurityRecoveryTimeout       = 15 * time.Second
	defaultSecurityMaxSettlementAttempts = 3

	defaultFeishuBaseURL           = "https://open.feishu.cn"
	defaultFeishuAuthorizeURL      = "https://accounts.feishu.cn/open-apis/authen/v1/authorize"
	defaultFeishuContactScope      = "应用通讯录授权范围"
	defaultFeishuOAuthStateTTL     = 5 * time.Minute
	defaultFeishuRequestTimeout    = 15 * time.Second
	defaultFeishuReconcileInterval = 15 * time.Second
	defaultFeishuSyncTimeout       = 2 * time.Minute

	defaultCerbosRequestTimeout    = 3 * time.Second
	defaultCerbosReconcileInterval = 30 * time.Second

	defaultAdminFreshLoginMaxAge  = 5 * time.Minute
	defaultAdminGeneralFreshness  = 30 * time.Minute
	defaultAdminHighRiskFreshness = 5 * time.Minute
	defaultAdminRateLimit         = 5
	defaultAdminRateWindow        = 15 * time.Minute
	defaultAdminLockDuration      = 30 * time.Minute
	defaultAdminArgon2Concurrency = 2
)

// Config holds all process-level configuration. Values are loaded once at
// startup and treated as immutable for the lifetime of the process.
type Config struct {
	// Phase 0 — HTTP server
	Environment         Environment
	HTTPAddr            string
	ReadHeaderTimeout   time.Duration
	ReadTimeout         time.Duration
	WriteTimeout        time.Duration
	IdleTimeout         time.Duration
	ShutdownTimeout     time.Duration
	MaxRequestBodyBytes int64
	LogLevel            string

	// AvatarDir is the directory where re-encoded user avatars are stored.
	// It must be writable by the API process at runtime.
	AvatarDir string

	// Phase 1 — Storage
	Database         DatabaseConfig
	IsolatedDatabase DatabaseConfig
	Redis            RedisConfig

	// Phase 1 — Session
	Session SessionConfig

	// Phase 1 — Authentication
	MFA         MFAConfig
	RateLimit   RateLimitConfig
	RiskDefense RiskDefenseConfig
	Auth        AuthProviderConfig
	ClientIP    TrustedClientIPConfig
	// Registration is a master-gated public surface. It is closed unless an
	// operator explicitly enables it and all durable/provider dependencies are
	// configured.
	Registration RegistrationConfig
	// WeChatMiniProgram gates server-side Mini Program proof exchange and an
	// independently enabled registration surface.
	WeChatMiniProgram WeChatMiniProgramConfig
	// QRAuth gates short-lived browser login challenges.
	QRAuth QRAuthConfig
	// DreamUPMobile signs request-bound participant assertions with dedicated
	// key material and remains default-off.
	DreamUPMobile DreamUPMobileConfig

	// Phone binding verification (SMS) — Aliyun SMS delivery and code TTL.
	AliyunSMS   AliyunSMSConfig
	PhoneVerify PhoneVerifyConfig

	// Phase 1 — Permissions
	Permission PermissionConfig

	// Phase 2 — Reauthentication and secret rotation
	Reauth   ReauthConfig
	Rotation RotationConfig

	// Phase 4 — Security generation and password mutation intents (ADR-0007)
	SecurityState SecurityStateConfig

	// Phase 3 — OAuth endpoint topology
	OAuth OAuthConfig

	// Operator-only DreamUP OAuth client bootstrap.
	DreamUPBootstrap DreamUPBootstrapConfig

	// Phase 6 — Feishu login and directory Provider
	Feishu FeishuConfig

	// Phase 7 — Cerbos policy decision and management APIs
	Cerbos CerbosConfig

	// DreamUP administration is a master-gated surface. It defaults off and
	// no keyring is opened unless explicitly enabled.
	DreamUPAdmin DreamUPAdminConfig

	// Email configures the SMTP sender used by the internal email endpoint.
	// Emails are only sent when the SMTP host is configured.
	Email EmailConfig

	// Integration tests
	Test TestConfig
}

// DatabaseConfig holds PostgreSQL connection parameters.
type DatabaseConfig struct {
	URL            string
	Schema         string
	MaxConns       int32
	MinConns       int32
	ConnectTimeout time.Duration
}

// RedisConfig holds Redis connection parameters.
type RedisConfig struct {
	URL            string
	KeyPrefix      string
	PoolSize       int
	ConnectTimeout time.Duration
	ReadTimeout    time.Duration
	WriteTimeout   time.Duration
}

// SessionConfig holds browser session parameters.
type SessionConfig struct {
	TTL             time.Duration
	RememberTTL     time.Duration
	IdleTTL         time.Duration
	TouchInterval   time.Duration
	CookieSecure    bool
	CookieSameSite  string
	EncryptionKey   string // base64-encoded 32-byte AES-GCM key
	EncryptionKeyID string
}

// MFAConfig holds MFA challenge parameters.
type MFAConfig struct {
	ChallengeTTL time.Duration
	MaxAttempts  int
}

// RateLimitConfig holds rate limiting parameters.
type RateLimitConfig struct {
	LoginLimit  int
	LoginWindow time.Duration
	MFALimit    int
	MFAWindow   time.Duration
}

type WeChatMiniProgramConfig struct {
	Enabled             bool
	RegistrationEnabled bool
	// OnboardingEnabled independently gates the authority-writing account
	// creation/linking routes. It remains false when only legacy WeChat login or
	// registration is enabled.
	OnboardingEnabled         bool
	OnboardingEncryptionKey   string // base64-encoded 32-byte AES-GCM key, never shared with sessions
	OnboardingEncryptionKeyID string
	// OnboardingRetainedDecryptionKeys is a JSON object of historical
	// key-ID/base64-key pairs. These keys decrypt durable cleanup obligations
	// after rotation but are never used for new ciphertext.
	OnboardingRetainedDecryptionKeys string
	AppID                            string
	AppSecret                        string
	APIBaseURL                       string
	RequestTimeout                   time.Duration
}

type QRAuthConfig struct {
	Enabled      bool
	ChallengeTTL time.Duration
	RateLimit    int
	RateWindow   time.Duration
}

type DreamUPMobileConfig struct {
	Enabled                bool
	DelegationKeyringPath  string
	DelegationCurrentKeyID string
	DelegationIssuer       string
	DelegationAudience     string
	AssertionTTL           time.Duration
	ScopedRateLimit        int
	GlobalRateLimit        int
	RateWindow             time.Duration
}

// RiskDefenseConfig controls objective registration/login abuse defense.
// Allowlist entries are SHA-256 hex digests of normalized identifiers; raw
// emails, names, and usernames are intentionally not accepted here.
type RiskDefenseConfig struct {
	Enabled                  bool
	ObservationWindow        time.Duration
	LoginMediumAfter         int
	LoginHighAfter           int
	RegistrationMediumAfter  int
	RegistrationHighAfter    int
	ChallengeTTL             time.Duration
	DeviceIDTTL              time.Duration
	TrustTTL                 time.Duration
	AutomationCostDifficulty int
	CompletionLimit          int
	CompletionWindow         time.Duration
	AllowlistedHashes        []string
	Captcha                  RiskCaptchaConfig
}

// RiskCaptchaConfig enables only providers whose complete credential and
// hostname tuple is present. Browser code never selects the region or provider.
type RiskCaptchaConfig struct {
	Region    string
	Turnstile RiskCaptchaProviderConfig
	Recaptcha RiskRecaptchaConfig
}

type RiskCaptchaProviderConfig struct {
	SiteKey   string
	SecretKey string
	Hostname  string
}

type RiskRecaptchaConfig struct {
	SiteKey   string
	SecretKey string
	Hostname  string
	MinScore  float64
}

func (c RiskCaptchaProviderConfig) Configured() bool {
	return c.SiteKey != "" && c.SecretKey != "" && c.Hostname != ""
}

func (c RiskRecaptchaConfig) Configured() bool {
	return c.SiteKey != "" && c.SecretKey != "" && c.Hostname != ""
}

// TrustedClientIPConfig defines the transport peers allowed to supply the
// internal X-Moonstone-Client-IP header. The public gateway must overwrite
// that header on every request.
type TrustedClientIPConfig struct {
	TrustedProxyCIDRs []string
}

// ReauthConfig holds reauthentication challenge and grant parameters
// (ADR-0004 §7). Challenges and grants are short-lived, single-use and
// bound to user + session + action + target resource.
type ReauthConfig struct {
	ChallengeTTL time.Duration
	GrantTTL     time.Duration
	MaxAttempts  int
	RateLimit    int
	RateWindow   time.Duration
	// CleanupInterval is how often the abandoned-challenge cleanup worker
	// sweeps the Redis cleanup index and revokes leaked provider sessions.
	CleanupInterval time.Duration
}

// RotationConfig holds OAuth client secret rotation parameters (ADR-0004 §6).
// GracePeriod is the overlap window reported as previousSecretExpiresAt;
// against ZITADEL v2.71 the effective grace period is zero because the
// provider invalidates the previous secret immediately.
type RotationConfig struct {
	GracePeriod time.Duration
	RateLimit   int
	RateWindow  time.Duration
}

// SecurityStateConfig holds the ADR-0007 security generation (epoch) and
// durable password mutation intent parameters. PostgreSQL is the single
// authority for the epoch and the intent ledger; Redis may mirror hot-path
// state at most and never decides.
type SecurityStateConfig struct {
	// ProviderDeadline bounds the provider SetPassword call.
	ProviderDeadline time.Duration
	// LeaseTTL bounds the active intent lease before a takeover may
	// proceed. It must strictly outlive the provider deadline plus the
	// settlement timeout (the frozen safety margin) so a live, legitimate
	// mutation always owns its fence.
	LeaseTTL time.Duration
	// SettlementTimeout bounds the detached settlement run after the
	// provider outcome is known.
	SettlementTimeout time.Duration
	// RecoveryTimeout bounds each detached opportunistic recovery run.
	RecoveryTimeout time.Duration
	// MaxSettlementAttempts bounds takeover settlement retries before the
	// intent is force-settled degraded (bounded terminalization, F6).
	MaxSettlementAttempts int
}

// AuthProviderConfig holds authentication provider parameters.
type AuthProviderConfig struct {
	Provider       string
	BaseURL        string
	ProjectID      string
	OrganizationID string
	ClientID       string
	ClientSecret   string
	// ServiceAccountKeyFile is the path to the ZITADEL service account
	// key.json used for JWT profile authentication to the ZITADEL API. The
	// key file is read at adapter construction; it must contain the keyId
	// and the RSA private key.
	ServiceAccountKeyFile string
	// Domain is the WebAuthn relying-party domain used for passkey MFA
	// challenges (e.g. "login.example.com"). It must be the exact domain or
	// a top-level domain of the request origin. Empty disables passkey
	// challenges (TOTP remains available).
	Domain string
}

// AliyunSMSConfig controls SMS verification delivery through Aliyun SendSms.
type AliyunSMSConfig struct {
	AccessKeyID     string
	AccessKeySecret string
	SignName        string
	TemplateCode    string
	Endpoint        string
	Enabled         bool
}

// PhoneVerifyConfig tunes the phone binding verification flow.
type PhoneVerifyConfig struct {
	TTL time.Duration
}

// RegistrationConfig controls the public account-registration surface.
type RegistrationConfig struct {
	Enabled           bool
	CreateIPLimit     int
	CreateIPWindow    time.Duration
	CreateNetLimit    int
	CreateNetWindow   time.Duration
	CreateEmailLimit  int
	CreateEmailWindow time.Duration
	CreatePairLimit   int
	CreatePairWindow  time.Duration
	VerifyLimit       int
	VerifyWindow      time.Duration
	ResendLimit       int
	ResendWindow      time.Duration
	IPv4NetBits       int
	IPv6NetBits       int
}

// PermissionConfig holds permission resolver parameters.
type PermissionConfig struct {
	DevOverrideEnabled bool
	DevOverrideUserID  string
}

// OAuthConfig describes the public OAuth endpoint topology (ADR-0005 §1).
// The protocol endpoints themselves (authorize, token, revoke, introspect,
// keys, userinfo, end_session, device_authorization, discovery) live in the
// reverse proxy in front of the provider; Go and Next.js never implement
// them. PublicOrigin is the single browser-visible origin, and every other
// topology value is derived from it so the pieces can never drift apart.
type OAuthConfig struct {
	// PublicOrigin is the origin the reverse proxy serves the public OAuth
	// endpoints on (e.g. "https://id.example.com"). It is an origin, not an
	// arbitrary base URL: scheme + host (+ optional port) only — no path
	// other than "/", no userinfo, query or fragment. It must never be
	// conflated with UP_AUTH_PROVIDER_BASE_URL, which is the internal
	// provider management/API address; this value is the browser-visible
	// issuer origin.
	PublicOrigin string
}

// DreamUPBootstrapConfig contains the stable local owner required to create
// the DreamUP application. It is intentionally separate from request-serving
// OAuth configuration because only the one-shot operator command consumes it.
type DreamUPBootstrapConfig struct {
	OwnerUserID string
}

// FeishuConfig contains the server-only Phase 6 Provider configuration.
// AppSecret never leaves this typed configuration object and is never copied
// into API responses, database rows or logs.
type FeishuConfig struct {
	BaseURL           string
	AuthorizeURL      string
	AppID             string
	AppSecret         string
	TenantID          string
	RedirectURL       string
	ContactScope      string
	OAuthStateTTL     time.Duration
	RequestTimeout    time.Duration
	ReconcileInterval time.Duration
	SyncTimeout       time.Duration
}

// CerbosConfig contains server-only PDP and Admin API configuration. Admin
// credentials are used only on policy publication and are never logged or
// returned by an API.
type CerbosConfig struct {
	PDPURL            string
	AdminURL          string
	AdminUsername     string
	AdminPassword     string
	RequestTimeout    time.Duration
	ReconcileInterval time.Duration
}

type DreamUPAdminConfig struct {
	Enabled bool
	// MiniProgramEnabled permits the native transport to reach the same BFF;
	// authorization and true session-bound step-up remain mandatory.
	MiniProgramEnabled bool

	ChallengeEncryptionKeyringPath   string
	ChallengeEncryptionCurrentKeyID  string
	ChallengePepperKeyringPath       string
	ChallengePepperCurrentKeyID      string
	ProtectedReasonKeyringPath       string
	ProtectedReasonCurrentKeyID      string
	RateLimitKeyringPath             string
	RateLimitCurrentKeyID            string
	OperationFingerprintKeyringPath  string
	OperationFingerprintCurrentKeyID string
	DelegationKeyringPath            string
	DelegationCurrentKeyID           string

	BaseURL                  string
	DelegationIssuer         string
	DelegationAudience       string
	AdminOrigin              string
	ResponseLimitBytes       int64
	ReconcileInterval        time.Duration
	ReconcileBatchSize       int
	ReconcileLease           time.Duration
	DelegationServiceSubject string
	DelegationServiceVersion int64

	FreshLoginMaxAge    time.Duration
	GeneralFreshness    time.Duration
	HighRiskFreshness   time.Duration
	RateLimit           int
	RateWindow          time.Duration
	LockDuration        time.Duration
	Argon2MaxConcurrent int
}

func (c CerbosConfig) Configured() bool {
	return c.PDPURL != "" && c.AdminURL != "" && c.AdminUsername != "" && c.AdminPassword != ""
}

// Configured reports whether the complete Feishu credential and tenant set
// is present. Partial sets are rejected by Config.Validate.
func (c FeishuConfig) Configured() bool {
	return c.AppID != "" && c.AppSecret != "" && c.TenantID != "" && c.RedirectURL != ""
}

// InteractionBaseURI derives the ZITADEL LoginV2 Interaction Base URI from
// the public origin: <origin>/_interaction. This is the only derivation in
// the system — there is deliberately no independent interaction base
// configuration. Returns "" when no public origin is configured.
func (c OAuthConfig) InteractionBaseURI() string {
	if c.PublicOrigin == "" {
		return ""
	}
	return strings.TrimRight(c.PublicOrigin, "/") + "/_interaction"
}

// EmailConfig contains the SMTP sender settings used by the internal email
// endpoint. The endpoint only sends when SMTPHost is non-empty; the shared
// token authenticates loopback callers such as the DreamUP worker.
type EmailConfig struct {
	SMTPHost      string
	SMTPPort      int
	SMTPUser      string
	SMTPPassword  string
	FromAddress   string
	FromName      string
	InternalToken string
}

// Configured reports whether an SMTP host has been set so the internal email
// endpoint can fail closed when no sender is available.
func (c EmailConfig) Configured() bool { return c.SMTPHost != "" }

// SecurityNotificationsConfigured reports whether onboarding can start with
// a usable notification transport. Credentials may be empty for SMTP relays
// that intentionally support unauthenticated delivery.
func (c EmailConfig) SecurityNotificationsConfigured() bool {
	host := strings.TrimSpace(c.SMTPHost)
	from := strings.TrimSpace(c.FromAddress)
	if host == "" || host != c.SMTPHost || strings.ContainsAny(host, "\r\n\t ") || c.SMTPPort < 1 || c.SMTPPort > 65535 || from == "" || from != c.FromAddress {
		return false
	}
	address, err := mail.ParseAddress(from)
	return err == nil && address.Address == from
}

// ParseWeChatOnboardingRetainedDecryptionKeys parses the optional rotation
// keyring without ever including key IDs or key material in returned errors.
// The small hard limit bounds secret exposure and configuration complexity.
func ParseWeChatOnboardingRetainedDecryptionKeys(raw string) (map[string]string, error) {
	keys := make(map[string]string)
	if strings.TrimSpace(raw) == "" {
		return keys, nil
	}
	decoder := json.NewDecoder(strings.NewReader(raw))
	start, err := decoder.Token()
	if err != nil || start != json.Delim('{') {
		return nil, errors.New("retained onboarding decryption keys must be a JSON object")
	}
	for decoder.More() {
		keyToken, tokenErr := decoder.Token()
		keyID, ok := keyToken.(string)
		if tokenErr != nil || !ok {
			return nil, errors.New("retained onboarding decryption keys contain an invalid key ID")
		}
		if len(keys) >= 8 {
			return nil, errors.New("retained onboarding decryption keys exceed the maximum of 8")
		}
		if _, exists := keys[keyID]; exists {
			return nil, errors.New("retained onboarding decryption keys contain a duplicate key ID")
		}
		if keyID == "" || keyID != strings.TrimSpace(keyID) || strings.Contains(keyID, ":") {
			return nil, errors.New("retained onboarding decryption key IDs must be non-empty, trimmed and must not contain ':'")
		}
		var keyB64 string
		if err := decoder.Decode(&keyB64); err != nil {
			return nil, errors.New("retained onboarding decryption key values must be base64 strings")
		}
		key, decodeErr := base64.StdEncoding.DecodeString(keyB64)
		if decodeErr != nil || len(key) != 32 {
			return nil, errors.New("retained onboarding decryption keys must decode to 32 bytes")
		}
		keys[keyID] = keyB64
	}
	end, err := decoder.Token()
	if err != nil || end != json.Delim('}') {
		return nil, errors.New("retained onboarding decryption keys must be a JSON object")
	}
	var trailing any
	if err := decoder.Decode(&trailing); !errors.Is(err, io.EOF) {
		return nil, errors.New("retained onboarding decryption keys contain trailing data")
	}
	return keys, nil
}

// TestConfig holds integration test environment parameters.
type TestConfig struct {
	DatabaseURL    string
	DatabaseSchema string
	RedisURL       string
	RedisKeyPrefix string
}

// Load reads configuration from environment variables, applying development
// defaults for any value that is not explicitly set. Call LoadDotEnv first in
// local development to populate variables from an ignored .env file.
func Load() (Config, error) {
	cfg := Config{
		Environment:         Environment(envOr("UP_ENVIRONMENT", string(EnvironmentDevelopment))),
		HTTPAddr:            envOr("UP_HTTP_ADDR", defaultHTTPAddr),
		ReadHeaderTimeout:   durationOr("UP_READ_HEADER_TIMEOUT", defaultReadHeaderTimeout),
		ReadTimeout:         durationOr("UP_READ_TIMEOUT", defaultReadTimeout),
		WriteTimeout:        durationOr("UP_WRITE_TIMEOUT", defaultWriteTimeout),
		IdleTimeout:         durationOr("UP_IDLE_TIMEOUT", defaultIdleTimeout),
		ShutdownTimeout:     durationOr("UP_SHUTDOWN_TIMEOUT", defaultShutdownTimeout),
		MaxRequestBodyBytes: int64Or("UP_MAX_REQUEST_BODY_BYTES", defaultMaxRequestBodyBytes),
		LogLevel:            envOr("UP_LOG_LEVEL", defaultLogLevel),
		AvatarDir:           envOr("UP_AVATAR_DIR", defaultAvatarDir),

		Database: DatabaseConfig{
			URL:            envOr("UP_DATABASE_URL", ""),
			Schema:         envOr("UP_DATABASE_SCHEMA", defaultDatabaseSchema),
			MaxConns:       int32Or("UP_DATABASE_MAX_CONNS", defaultDatabaseMaxConns),
			MinConns:       int32Or("UP_DATABASE_MIN_CONNS", defaultDatabaseMinConns),
			ConnectTimeout: durationOr("UP_DATABASE_CONNECT_TIMEOUT", defaultDatabaseConnectTimeout),
		},

		// The isolated operational store is optional for legacy deployments. When
		// configured, WeChat registration retry verifiers and DreamUP cross-system
		// mutation receipts are kept out of the United Pass authority database.
		// This permits a side-by-side rollout without altering the production
		// identity/permission schema.
		IsolatedDatabase: DatabaseConfig{
			URL:            envOr("UP_ISOLATED_DATABASE_URL", ""),
			Schema:         envOr("UP_ISOLATED_DATABASE_SCHEMA", "dreamup_isolated"),
			MaxConns:       int32Or("UP_ISOLATED_DATABASE_MAX_CONNS", defaultDatabaseMaxConns),
			MinConns:       int32Or("UP_ISOLATED_DATABASE_MIN_CONNS", defaultDatabaseMinConns),
			ConnectTimeout: durationOr("UP_ISOLATED_DATABASE_CONNECT_TIMEOUT", defaultDatabaseConnectTimeout),
		},

		Redis: RedisConfig{
			URL:            envOr("UP_REDIS_URL", ""),
			KeyPrefix:      envOr("UP_REDIS_KEY_PREFIX", defaultRedisKeyPrefix),
			PoolSize:       intOr("UP_REDIS_POOL_SIZE", defaultRedisPoolSize),
			ConnectTimeout: durationOr("UP_REDIS_CONNECT_TIMEOUT", defaultRedisConnectTimeout),
			ReadTimeout:    durationOr("UP_REDIS_READ_TIMEOUT", defaultRedisReadTimeout),
			WriteTimeout:   durationOr("UP_REDIS_WRITE_TIMEOUT", defaultRedisWriteTimeout),
		},

		Session: SessionConfig{
			TTL:             durationOr("UP_SESSION_TTL", defaultSessionTTL),
			RememberTTL:     durationOr("UP_SESSION_REMEMBER_TTL", defaultSessionRememberTTL),
			IdleTTL:         durationOr("UP_SESSION_IDLE_TTL", defaultSessionIdleTTL),
			TouchInterval:   durationOr("UP_SESSION_TOUCH_INTERVAL", defaultSessionTouchInterval),
			CookieSecure:    boolOr("UP_SESSION_COOKIE_SECURE", true),
			CookieSameSite:  envOr("UP_SESSION_COOKIE_SAME_SITE", defaultSessionSameSite),
			EncryptionKey:   envOr("UP_SESSION_ENCRYPTION_KEY", ""),
			EncryptionKeyID: envOr("UP_SESSION_ENCRYPTION_KEY_ID", ""),
		},

		MFA: MFAConfig{
			ChallengeTTL: durationOr("UP_MFA_CHALLENGE_TTL", defaultMFAChallengeTTL),
			MaxAttempts:  intOr("UP_MFA_MAX_ATTEMPTS", defaultMFAMaxAttempts),
		},

		RateLimit: RateLimitConfig{
			LoginLimit:  intOr("UP_LOGIN_RATE_LIMIT", defaultLoginRateLimit),
			LoginWindow: durationOr("UP_LOGIN_RATE_WINDOW", defaultLoginRateWindow),
			MFALimit:    intOr("UP_MFA_RATE_LIMIT", defaultMFARateLimit),
			MFAWindow:   durationOr("UP_MFA_RATE_WINDOW", defaultMFARateWindow),
		},
		RiskDefense: RiskDefenseConfig{
			Enabled:                  boolOr("UP_RISK_DEFENSE_ENABLED", false),
			ObservationWindow:        durationOr("UP_RISK_OBSERVATION_WINDOW", defaultRiskObservationWindow),
			LoginMediumAfter:         intOr("UP_RISK_LOGIN_MEDIUM_AFTER", defaultRiskLoginMediumAfter),
			LoginHighAfter:           intOr("UP_RISK_LOGIN_HIGH_AFTER", defaultRiskLoginHighAfter),
			RegistrationMediumAfter:  intOr("UP_RISK_REGISTRATION_MEDIUM_AFTER", defaultRiskRegistrationMediumAfter),
			RegistrationHighAfter:    intOr("UP_RISK_REGISTRATION_HIGH_AFTER", defaultRiskRegistrationHighAfter),
			ChallengeTTL:             durationOr("UP_RISK_CHALLENGE_TTL", defaultRiskChallengeTTL),
			DeviceIDTTL:              durationOr("UP_RISK_DEVICE_ID_TTL", defaultRiskDeviceIDTTL),
			TrustTTL:                 durationOr("UP_RISK_TRUST_TTL", defaultRiskTrustTTL),
			AutomationCostDifficulty: intOr("UP_RISK_AUTOMATION_COST_DIFFICULTY", defaultRiskAutomationCostDifficulty),
			CompletionLimit:          intOr("UP_RISK_COMPLETION_LIMIT", defaultRiskCompletionLimit),
			CompletionWindow:         durationOr("UP_RISK_COMPLETION_WINDOW", defaultRiskCompletionWindow),
			AllowlistedHashes:        csvOr("UP_RISK_ALLOWLIST_SHA256", ""),
			Captcha: RiskCaptchaConfig{
				Region: envOr("UP_RISK_CAPTCHA_REGION", defaultRiskCaptchaRegion),
				Turnstile: RiskCaptchaProviderConfig{
					SiteKey:   envOr("UP_RISK_TURNSTILE_SITE_KEY", ""),
					SecretKey: envOr("UP_RISK_TURNSTILE_SECRET_KEY", ""),
					Hostname:  envOr("UP_RISK_TURNSTILE_HOSTNAME", ""),
				},
				Recaptcha: RiskRecaptchaConfig{
					SiteKey:   envOr("UP_RISK_RECAPTCHA_SITE_KEY", ""),
					SecretKey: envOr("UP_RISK_RECAPTCHA_SECRET_KEY", ""),
					Hostname:  envOr("UP_RISK_RECAPTCHA_HOSTNAME", ""),
					MinScore:  float64Or("UP_RISK_RECAPTCHA_MIN_SCORE", defaultRiskRecaptchaMinScore),
				},
			},
		},

		Auth: AuthProviderConfig{
			Provider:              envOr("UP_AUTH_PROVIDER", ""),
			BaseURL:               envOr("UP_AUTH_PROVIDER_BASE_URL", ""),
			ProjectID:             envOr("UP_AUTH_PROVIDER_PROJECT_ID", ""),
			OrganizationID:        envOr("UP_AUTH_PROVIDER_ORGANIZATION_ID", ""),
			ClientID:              envOr("UP_AUTH_PROVIDER_CLIENT_ID", ""),
			ClientSecret:          envOr("UP_AUTH_PROVIDER_CLIENT_SECRET", ""),
			ServiceAccountKeyFile: envOr("UP_AUTH_PROVIDER_SERVICE_ACCOUNT_KEY_FILE", ""),
			Domain:                envOr("UP_AUTH_PROVIDER_DOMAIN", ""),
		},
		ClientIP: TrustedClientIPConfig{
			TrustedProxyCIDRs: csvOr("UP_TRUSTED_PROXY_CIDRS", defaultTrustedProxyCIDRs),
		},

		Registration: RegistrationConfig{
			Enabled:           boolOr("UP_PUBLIC_REGISTRATION_ENABLED", false),
			CreateIPLimit:     intOr("UP_REGISTRATION_CREATE_IP_LIMIT", defaultRegistrationCreateIPLimit),
			CreateIPWindow:    durationOr("UP_REGISTRATION_CREATE_IP_WINDOW", defaultRegistrationCreateIPWindow),
			CreateNetLimit:    intOr("UP_REGISTRATION_CREATE_NET_LIMIT", defaultRegistrationCreateNetLimit),
			CreateNetWindow:   durationOr("UP_REGISTRATION_CREATE_NET_WINDOW", defaultRegistrationCreateNetWindow),
			CreateEmailLimit:  intOr("UP_REGISTRATION_CREATE_EMAIL_LIMIT", defaultRegistrationCreateEmailLimit),
			CreateEmailWindow: durationOr("UP_REGISTRATION_CREATE_EMAIL_WINDOW", defaultRegistrationCreateEmailWindow),
			CreatePairLimit:   intOr("UP_REGISTRATION_CREATE_PAIR_LIMIT", defaultRegistrationCreatePairLimit),
			CreatePairWindow:  durationOr("UP_REGISTRATION_CREATE_PAIR_WINDOW", defaultRegistrationCreatePairWindow),
			VerifyLimit:       intOr("UP_REGISTRATION_VERIFY_LIMIT", defaultRegistrationVerifyLimit),
			VerifyWindow:      durationOr("UP_REGISTRATION_VERIFY_WINDOW", defaultRegistrationVerifyWindow),
			ResendLimit:       intOr("UP_REGISTRATION_RESEND_LIMIT", defaultRegistrationResendLimit),
			ResendWindow:      durationOr("UP_REGISTRATION_RESEND_WINDOW", defaultRegistrationResendWindow),
			IPv4NetBits:       intOr("UP_REGISTRATION_IPV4_NET_BITS", defaultRegistrationIPv4NetBits),
			IPv6NetBits:       intOr("UP_REGISTRATION_IPV6_NET_BITS", defaultRegistrationIPv6NetBits),
		},
		WeChatMiniProgram: WeChatMiniProgramConfig{
			Enabled:                          boolOr("UP_WECHAT_MINIPROGRAM_ENABLED", false),
			RegistrationEnabled:              boolOr("UP_WECHAT_MINIPROGRAM_REGISTRATION_ENABLED", false),
			OnboardingEnabled:                boolOr("UP_WECHAT_MINIPROGRAM_ONBOARDING_ENABLED", false),
			OnboardingEncryptionKey:          envOr("UP_WECHAT_MINIPROGRAM_ONBOARDING_ENCRYPTION_KEY", ""),
			OnboardingEncryptionKeyID:        envOr("UP_WECHAT_MINIPROGRAM_ONBOARDING_ENCRYPTION_KEY_ID", ""),
			OnboardingRetainedDecryptionKeys: envOr("UP_WECHAT_MINIPROGRAM_ONBOARDING_RETAINED_DECRYPTION_KEYS", ""),
			AppID:                            envOr("UP_WECHAT_MINIPROGRAM_APP_ID", ""),
			AppSecret:                        envOr("UP_WECHAT_MINIPROGRAM_APP_SECRET", ""),
			APIBaseURL:                       envOr("UP_WECHAT_MINIPROGRAM_API_BASE_URL", "https://api.weixin.qq.com"),
			RequestTimeout:                   durationOr("UP_WECHAT_MINIPROGRAM_REQUEST_TIMEOUT", defaultWeChatRequestTimeout),
		},
		QRAuth: QRAuthConfig{
			Enabled:      boolOr("UP_QR_AUTH_ENABLED", false),
			ChallengeTTL: durationOr("UP_QR_AUTH_CHALLENGE_TTL", defaultQRAuthChallengeTTL),
			RateLimit:    intOr("UP_QR_AUTH_RATE_LIMIT", defaultQRAuthRateLimit),
			RateWindow:   durationOr("UP_QR_AUTH_RATE_WINDOW", defaultQRAuthRateWindow),
		},
		DreamUPMobile: DreamUPMobileConfig{
			Enabled:                boolOr("UP_DREAMUP_MOBILE_ENABLED", false),
			DelegationKeyringPath:  envOr("UP_DREAMUP_MOBILE_DELEGATION_KEYRING_PATH", ""),
			DelegationCurrentKeyID: envOr("UP_DREAMUP_MOBILE_DELEGATION_CURRENT_KEY_ID", ""),
			DelegationIssuer:       envOr("UP_DREAMUP_MOBILE_DELEGATION_ISSUER", "https://auth.moonstone.org.cn"),
			DelegationAudience:     envOr("UP_DREAMUP_MOBILE_DELEGATION_AUDIENCE", "dreamup-mobile-api"),
			AssertionTTL:           durationOr("UP_DREAMUP_MOBILE_ASSERTION_TTL", 15*time.Second),
			ScopedRateLimit:        intOr("UP_DREAMUP_MOBILE_SCOPED_RATE_LIMIT", defaultDreamUPMobileScopedRateLimit),
			GlobalRateLimit:        intOr("UP_DREAMUP_MOBILE_GLOBAL_RATE_LIMIT", defaultDreamUPMobileGlobalRateLimit),
			RateWindow:             durationOr("UP_DREAMUP_MOBILE_RATE_WINDOW", defaultDreamUPMobileRateWindow),
		},

		AliyunSMS: AliyunSMSConfig{
			AccessKeyID:     envOr("UP_ALIYUN_SMS_ACCESS_KEY_ID", ""),
			AccessKeySecret: envOr("UP_ALIYUN_SMS_ACCESS_KEY_SECRET", ""),
			SignName:        envOr("UP_ALIYUN_SMS_SIGN_NAME", ""),
			TemplateCode:    envOr("UP_ALIYUN_SMS_TEMPLATE_CODE", ""),
			Endpoint:        envOr("UP_ALIYUN_SMS_ENDPOINT", defaultAliyunSMSEndpoint),
			Enabled:         boolOr("UP_ALIYUN_SMS_ENABLED", false),
		},
		PhoneVerify: PhoneVerifyConfig{
			TTL: durationOr("UP_PHONE_VERIFY_TTL", 5*time.Minute),
		},

		Permission: PermissionConfig{
			DevOverrideEnabled: boolOr("UP_PERMISSION_DEV_OVERRIDE", false),
			DevOverrideUserID:  envOr("UP_PERMISSION_DEV_OVERRIDE_USER_ID", ""),
		},

		Reauth: ReauthConfig{
			ChallengeTTL:    durationOr("UP_REAUTH_CHALLENGE_TTL", defaultReauthChallengeTTL),
			GrantTTL:        durationOr("UP_REAUTH_GRANT_TTL", defaultReauthGrantTTL),
			MaxAttempts:     intOr("UP_REAUTH_MAX_ATTEMPTS", defaultReauthMaxAttempts),
			RateLimit:       intOr("UP_REAUTH_RATE_LIMIT", defaultReauthRateLimit),
			RateWindow:      durationOr("UP_REAUTH_RATE_WINDOW", defaultReauthRateWindow),
			CleanupInterval: durationOr("UP_REAUTH_CLEANUP_INTERVAL", defaultReauthCleanupInterval),
		},

		Rotation: RotationConfig{
			GracePeriod: durationOr("UP_SECRET_ROTATION_GRACE_PERIOD", defaultRotationGracePeriod),
			RateLimit:   intOr("UP_SECRET_ROTATION_RATE_LIMIT", defaultRotationRateLimit),
			RateWindow:  durationOr("UP_SECRET_ROTATION_RATE_WINDOW", defaultRotationRateWindow),
		},

		SecurityState: SecurityStateConfig{
			ProviderDeadline:      durationOr("UP_SECURITY_PROVIDER_DEADLINE", defaultSecurityProviderDeadline),
			LeaseTTL:              durationOr("UP_SECURITY_LEASE_TTL", defaultSecurityLeaseTTL),
			SettlementTimeout:     durationOr("UP_SECURITY_SETTLEMENT_TIMEOUT", defaultSecuritySettlementTimeout),
			RecoveryTimeout:       durationOr("UP_SECURITY_RECOVERY_TIMEOUT", defaultSecurityRecoveryTimeout),
			MaxSettlementAttempts: intOr("UP_SECURITY_MAX_SETTLEMENT_ATTEMPTS", defaultSecurityMaxSettlementAttempts),
		},

		OAuth: OAuthConfig{
			PublicOrigin: envOr("UP_OAUTH_PUBLIC_ORIGIN", ""),
		},

		DreamUPBootstrap: DreamUPBootstrapConfig{
			OwnerUserID: envOr("UP_DREAMUP_OWNER_USER_ID", ""),
		},

		Feishu: FeishuConfig{
			BaseURL:           envOr("UP_FEISHU_BASE_URL", defaultFeishuBaseURL),
			AuthorizeURL:      envOr("UP_FEISHU_AUTHORIZE_URL", defaultFeishuAuthorizeURL),
			AppID:             envOr("UP_FEISHU_APP_ID", ""),
			AppSecret:         envOr("UP_FEISHU_APP_SECRET", ""),
			TenantID:          envOr("UP_FEISHU_TENANT_ID", ""),
			RedirectURL:       envOr("UP_FEISHU_REDIRECT_URL", ""),
			ContactScope:      envOr("UP_FEISHU_CONTACT_SCOPE", defaultFeishuContactScope),
			OAuthStateTTL:     durationOr("UP_FEISHU_OAUTH_STATE_TTL", defaultFeishuOAuthStateTTL),
			RequestTimeout:    durationOr("UP_FEISHU_REQUEST_TIMEOUT", defaultFeishuRequestTimeout),
			ReconcileInterval: durationOr("UP_FEISHU_RECONCILE_INTERVAL", defaultFeishuReconcileInterval),
			SyncTimeout:       durationOr("UP_FEISHU_SYNC_TIMEOUT", defaultFeishuSyncTimeout),
		},

		Cerbos: CerbosConfig{
			PDPURL:            envOr("UP_CERBOS_PDP_URL", ""),
			AdminURL:          envOr("UP_CERBOS_ADMIN_URL", ""),
			AdminUsername:     envOr("UP_CERBOS_ADMIN_USERNAME", ""),
			AdminPassword:     envOr("UP_CERBOS_ADMIN_PASSWORD", ""),
			RequestTimeout:    durationOr("UP_CERBOS_REQUEST_TIMEOUT", defaultCerbosRequestTimeout),
			ReconcileInterval: durationOr("UP_CERBOS_RECONCILE_INTERVAL", defaultCerbosReconcileInterval),
		},

		DreamUPAdmin: DreamUPAdminConfig{
			Enabled:                          boolOr("UP_DREAMUP_ADMIN_ENABLED", false),
			MiniProgramEnabled:               boolOr("UP_DREAMUP_ADMIN_MINIPROGRAM_ENABLED", false),
			ChallengeEncryptionKeyringPath:   envOr("UP_ADMIN_CHALLENGE_ENCRYPTION_KEYRING_PATH", ""),
			ChallengeEncryptionCurrentKeyID:  envOr("UP_ADMIN_CHALLENGE_ENCRYPTION_CURRENT_KEY_ID", ""),
			ChallengePepperKeyringPath:       envOr("UP_ADMIN_CHALLENGE_PEPPER_KEYRING_PATH", ""),
			ChallengePepperCurrentKeyID:      envOr("UP_ADMIN_CHALLENGE_PEPPER_CURRENT_KEY_ID", ""),
			ProtectedReasonKeyringPath:       envOr("UP_PROTECTED_REASON_KEYRING_PATH", ""),
			ProtectedReasonCurrentKeyID:      envOr("UP_PROTECTED_REASON_CURRENT_KEY_ID", ""),
			RateLimitKeyringPath:             envOr("UP_ADMIN_CHALLENGE_RATE_LIMIT_KEYRING_PATH", ""),
			RateLimitCurrentKeyID:            envOr("UP_ADMIN_CHALLENGE_RATE_LIMIT_CURRENT_KEY_ID", ""),
			OperationFingerprintKeyringPath:  envOr("UP_ADMIN_OPERATION_FINGERPRINT_KEYRING_PATH", ""),
			OperationFingerprintCurrentKeyID: envOr("UP_ADMIN_OPERATION_FINGERPRINT_CURRENT_KEY_ID", ""),
			DelegationKeyringPath:            envOr("UP_DREAMUP_DELEGATION_KEYRING_PATH", ""),
			DelegationCurrentKeyID:           envOr("UP_DREAMUP_DELEGATION_CURRENT_KEY_ID", ""),
			BaseURL:                          envOr("UP_DREAMUP_ADMIN_BASE_URL", "http://127.0.0.1:18084"),
			DelegationIssuer:                 envOr("UP_DREAMUP_DELEGATION_ISSUER", "https://auth.moonstone.org.cn"),
			DelegationAudience:               envOr("UP_DREAMUP_DELEGATION_AUDIENCE", "dreamup-admin-api"),
			AdminOrigin:                      envOr("UP_DREAMUP_ADMIN_ORIGIN", "https://auth.moonstone.org.cn"),
			ResponseLimitBytes:               int64Or("UP_DREAMUP_ADMIN_RESPONSE_LIMIT_BYTES", 8<<20),
			ReconcileInterval:                durationOr("UP_DREAMUP_RECONCILE_INTERVAL", 15*time.Second),
			ReconcileBatchSize:               intOr("UP_DREAMUP_RECONCILE_BATCH_SIZE", 50),
			ReconcileLease:                   durationOr("UP_DREAMUP_RECONCILE_LEASE", 30*time.Second),
			DelegationServiceSubject:         envOr("UP_DREAMUP_DELEGATION_SERVICE_SUBJECT", "united-pass:dreamup-reconciler"),
			DelegationServiceVersion:         int64Or("UP_DREAMUP_DELEGATION_SERVICE_VERSION", 1),
			FreshLoginMaxAge:                 durationOr("UP_ADMIN_CHALLENGE_FRESH_LOGIN_MAX_AGE", defaultAdminFreshLoginMaxAge),
			GeneralFreshness:                 durationOr("UP_ADMIN_CHALLENGE_GENERAL_FRESHNESS", defaultAdminGeneralFreshness),
			HighRiskFreshness:                durationOr("UP_ADMIN_CHALLENGE_HIGH_RISK_FRESHNESS", defaultAdminHighRiskFreshness),
			RateLimit:                        intOr("UP_ADMIN_CHALLENGE_RATE_LIMIT", defaultAdminRateLimit),
			RateWindow:                       durationOr("UP_ADMIN_CHALLENGE_RATE_WINDOW", defaultAdminRateWindow),
			LockDuration:                     durationOr("UP_ADMIN_CHALLENGE_LOCK_DURATION", defaultAdminLockDuration),
			Argon2MaxConcurrent:              intOr("UP_ADMIN_CHALLENGE_ARGON2_MAX_CONCURRENT", defaultAdminArgon2Concurrency),
		},

		Email: EmailConfig{
			SMTPHost:      envOr("UP_SMTP_HOST", ""),
			SMTPPort:      intOr("UP_SMTP_PORT", 465),
			SMTPUser:      envOr("UP_SMTP_USER", ""),
			SMTPPassword:  envOr("UP_SMTP_PASS", ""),
			FromAddress:   envOr("UP_SMTP_FROM", ""),
			FromName:      envOr("UP_SMTP_FROM_NAME", ""),
			InternalToken: envOr("UP_INTERNAL_EMAIL_TOKEN", ""),
		},

		Test: TestConfig{
			DatabaseURL:    envOr("UP_TEST_DATABASE_URL", ""),
			DatabaseSchema: envOr("UP_TEST_DATABASE_SCHEMA", "united_pass_test"),
			RedisURL:       envOr("UP_TEST_REDIS_URL", ""),
			RedisKeyPrefix: envOr("UP_TEST_REDIS_KEY_PREFIX", "up:test:"),
		},
	}

	if err := cfg.Validate(); err != nil {
		return Config{}, err
	}
	return cfg, nil
}

// Validate enforces invariants. Production requires explicit, safe settings and
// rejects any configuration that would weaken security or availability.
func (c Config) Validate() error {
	var errs []error

	if c.Registration.Enabled {
		if c.Database.URL == "" || c.Redis.URL == "" {
			errs = append(errs, errors.New("public registration requires UP_DATABASE_URL and UP_REDIS_URL"))
		}
		if c.Auth.Provider != "zitadel" || c.Auth.BaseURL == "" || c.Auth.ServiceAccountKeyFile == "" {
			errs = append(errs, errors.New("public registration requires complete ZITADEL provider configuration"))
		}
		if c.Auth.ProjectID == "" {
			errs = append(errs, errors.New("public registration requires UP_AUTH_PROVIDER_PROJECT_ID"))
		}
		if c.Auth.OrganizationID == "" {
			errs = append(errs, errors.New("public registration requires UP_AUTH_PROVIDER_ORGANIZATION_ID"))
		}
		if c.OAuth.PublicOrigin == "" {
			errs = append(errs, errors.New("public registration requires UP_OAUTH_PUBLIC_ORIGIN"))
		}
		if len(c.ClientIP.TrustedProxyCIDRs) == 0 {
			errs = append(errs, errors.New("public registration requires a trusted gateway client-IP boundary"))
		}
	}
	registrationLimits := []struct {
		limit  int
		window time.Duration
		name   string
	}{
		{c.Registration.CreateIPLimit, c.Registration.CreateIPWindow, "registration create IP"},
		{c.Registration.CreateNetLimit, c.Registration.CreateNetWindow, "registration create network"},
		{c.Registration.CreateEmailLimit, c.Registration.CreateEmailWindow, "registration create email"},
		{c.Registration.CreatePairLimit, c.Registration.CreatePairWindow, "registration create client/email pair"},
		{c.Registration.VerifyLimit, c.Registration.VerifyWindow, "registration verification"},
		{c.Registration.ResendLimit, c.Registration.ResendWindow, "registration resend"},
	}
	for _, rate := range registrationLimits {
		if rate.limit <= 0 || rate.window <= 0 {
			errs = append(errs, fmt.Errorf("%s rate limit and window must be positive", rate.name))
		}
	}
	if c.Registration.IPv4NetBits < 8 || c.Registration.IPv4NetBits > 32 {
		errs = append(errs, errors.New("registration IPv4 network prefix must be between 8 and 32 bits"))
	}
	if c.Registration.IPv6NetBits < 16 || c.Registration.IPv6NetBits > 128 {
		errs = append(errs, errors.New("registration IPv6 network prefix must be between 16 and 128 bits"))
	}
	for _, raw := range c.ClientIP.TrustedProxyCIDRs {
		prefix, err := netip.ParsePrefix(strings.TrimSpace(raw))
		if err != nil || prefix.Bits() == 0 {
			errs = append(errs, fmt.Errorf("trusted proxy CIDR %q is invalid or over-broad", raw))
		}
	}
	if c.WeChatMiniProgram.RegistrationEnabled {
		if !c.WeChatMiniProgram.Enabled {
			errs = append(errs, errors.New("WeChat Mini Program registration requires UP_WECHAT_MINIPROGRAM_ENABLED"))
		}
		if c.Database.URL == "" || c.Redis.URL == "" || c.Auth.Provider != "zitadel" || c.Auth.BaseURL == "" || c.Auth.ServiceAccountKeyFile == "" || c.Auth.ProjectID == "" || c.Auth.OrganizationID == "" || c.OAuth.PublicOrigin == "" {
			errs = append(errs, errors.New("WeChat Mini Program registration requires complete database, Redis, ZITADEL and public-origin configuration"))
		}
		if len(c.ClientIP.TrustedProxyCIDRs) == 0 {
			errs = append(errs, errors.New("WeChat Mini Program registration requires a trusted gateway client-IP boundary"))
		}
		if !c.HasIsolatedDatabase() {
			errs = append(errs, errors.New("WeChat Mini Program registration requires UP_ISOLATED_DATABASE_URL so retry verifiers never alter the authority schema"))
		}
	}
	if c.WeChatMiniProgram.OnboardingEnabled {
		if !c.WeChatMiniProgram.Enabled || !c.WeChatMiniProgram.RegistrationEnabled {
			errs = append(errs, errors.New("WeChat Mini Program onboarding requires UP_WECHAT_MINIPROGRAM_ENABLED and UP_WECHAT_MINIPROGRAM_REGISTRATION_ENABLED"))
		}
		if c.WeChatMiniProgram.OnboardingEncryptionKey == "" || strings.TrimSpace(c.WeChatMiniProgram.OnboardingEncryptionKeyID) == "" {
			errs = append(errs, errors.New("WeChat Mini Program onboarding requires UP_WECHAT_MINIPROGRAM_ONBOARDING_ENCRYPTION_KEY and UP_WECHAT_MINIPROGRAM_ONBOARDING_ENCRYPTION_KEY_ID"))
		} else {
			onboardingKey, err := base64.StdEncoding.DecodeString(c.WeChatMiniProgram.OnboardingEncryptionKey)
			if err != nil {
				errs = append(errs, errors.New("WeChat Mini Program onboarding encryption key must be base64-encoded"))
			} else if len(onboardingKey) != 32 {
				errs = append(errs, fmt.Errorf("WeChat Mini Program onboarding encryption key must decode to 32 bytes, got %d", len(onboardingKey)))
			}
			if c.WeChatMiniProgram.OnboardingEncryptionKeyID != strings.TrimSpace(c.WeChatMiniProgram.OnboardingEncryptionKeyID) || strings.Contains(c.WeChatMiniProgram.OnboardingEncryptionKeyID, ":") {
				errs = append(errs, errors.New("WeChat Mini Program onboarding encryption key id must be non-empty, trimmed and must not contain ':'"))
			}
			if c.Session.EncryptionKey != "" {
				sessionKey, sessionErr := base64.StdEncoding.DecodeString(c.Session.EncryptionKey)
				if err == nil && sessionErr == nil && bytes.Equal(onboardingKey, sessionKey) {
					errs = append(errs, errors.New("UP_WECHAT_MINIPROGRAM_ONBOARDING_ENCRYPTION_KEY must be distinct from UP_SESSION_ENCRYPTION_KEY"))
				}
			}
			retained, retainedErr := ParseWeChatOnboardingRetainedDecryptionKeys(c.WeChatMiniProgram.OnboardingRetainedDecryptionKeys)
			if retainedErr != nil {
				errs = append(errs, fmt.Errorf("UP_WECHAT_MINIPROGRAM_ONBOARDING_RETAINED_DECRYPTION_KEYS is invalid: %w", retainedErr))
			} else {
				if _, duplicateID := retained[c.WeChatMiniProgram.OnboardingEncryptionKeyID]; duplicateID {
					errs = append(errs, errors.New("retained onboarding decryption keys must not repeat the current key ID"))
				}
				materials := make([][]byte, 0, len(retained)+1)
				if err == nil && len(onboardingKey) == 32 {
					materials = append(materials, onboardingKey)
				}
				var sessionKey []byte
				if c.Session.EncryptionKey != "" {
					sessionKey, _ = base64.StdEncoding.DecodeString(c.Session.EncryptionKey)
				}
				for _, keyB64 := range retained {
					key, _ := base64.StdEncoding.DecodeString(keyB64)
					duplicateMaterial := false
					for _, existing := range materials {
						if bytes.Equal(existing, key) {
							duplicateMaterial = true
							break
						}
					}
					if duplicateMaterial {
						errs = append(errs, errors.New("retained onboarding decryption key material must be unique"))
					} else {
						materials = append(materials, key)
					}
					if len(sessionKey) == 32 && bytes.Equal(sessionKey, key) {
						errs = append(errs, errors.New("retained onboarding decryption keys must be distinct from UP_SESSION_ENCRYPTION_KEY"))
					}
				}
			}
		}
		if !c.Email.SecurityNotificationsConfigured() {
			errs = append(errs, errors.New("WeChat Mini Program onboarding requires UP_SMTP_HOST, a valid UP_SMTP_PORT and UP_SMTP_FROM for security notifications"))
		}
	}
	if c.WeChatMiniProgram.Enabled {
		if c.Database.URL == "" || c.Redis.URL == "" {
			errs = append(errs, errors.New("WeChat Mini Program login requires UP_DATABASE_URL and UP_REDIS_URL"))
		}
		if strings.TrimSpace(c.WeChatMiniProgram.AppID) == "" || strings.TrimSpace(c.WeChatMiniProgram.AppSecret) == "" {
			errs = append(errs, errors.New("WeChat Mini Program login requires UP_WECHAT_MINIPROGRAM_APP_ID and UP_WECHAT_MINIPROGRAM_APP_SECRET"))
		}
		if c.WeChatMiniProgram.RequestTimeout <= 0 || c.WeChatMiniProgram.RequestTimeout > 30*time.Second {
			errs = append(errs, errors.New("WeChat Mini Program request timeout must be positive and at most 30 seconds"))
		}
	}
	if c.AliyunSMS.Enabled {
		required := []struct {
			name  string
			value string
		}{
			{"UP_ALIYUN_SMS_ACCESS_KEY_ID", c.AliyunSMS.AccessKeyID},
			{"UP_ALIYUN_SMS_ACCESS_KEY_SECRET", c.AliyunSMS.AccessKeySecret},
			{"UP_ALIYUN_SMS_SIGN_NAME", c.AliyunSMS.SignName},
			{"UP_ALIYUN_SMS_TEMPLATE_CODE", c.AliyunSMS.TemplateCode},
		}
		for _, field := range required {
			if field.value == "" || field.value != strings.TrimSpace(field.value) {
				errs = append(errs, fmt.Errorf("Aliyun SMS requires a non-empty, trimmed %s", field.name))
			}
		}
		if err := validateAliyunSMSEndpoint(c.AliyunSMS.Endpoint); err != nil {
			errs = append(errs, err)
		}
	}
	if c.QRAuth.Enabled {
		if c.Redis.URL == "" {
			errs = append(errs, errors.New("QR authentication requires UP_REDIS_URL"))
		}
		if c.QRAuth.ChallengeTTL <= 0 || c.QRAuth.ChallengeTTL > 10*time.Minute {
			errs = append(errs, errors.New("QR authentication challenge TTL must be positive and at most 10 minutes"))
		}
		if c.QRAuth.RateLimit < 1 || c.QRAuth.RateLimit > 100 || c.QRAuth.RateWindow <= 0 || c.QRAuth.RateWindow > time.Hour {
			errs = append(errs, errors.New("QR authentication rate limit must be 1-100 with a positive window no longer than one hour"))
		}
	}
	if c.DreamUPMobile.Enabled {
		if c.Database.URL == "" || c.Redis.URL == "" || c.Auth.Provider != "zitadel" || c.Auth.ProjectID == "" {
			errs = append(errs, errors.New("DreamUP Mobile bridge requires PostgreSQL, Redis, ZITADEL provider and project ID"))
		}
		if strings.TrimSpace(c.DreamUPMobile.DelegationKeyringPath) == "" || strings.TrimSpace(c.DreamUPMobile.DelegationCurrentKeyID) == "" || !filepath.IsAbs(c.DreamUPMobile.DelegationKeyringPath) {
			errs = append(errs, errors.New("DreamUP Mobile bridge requires an absolute dedicated delegation keyring path and current key ID"))
		}
		if err := validateHTTPSOrigin(c.DreamUPMobile.DelegationIssuer, "DreamUP Mobile bridge issuer"); err != nil {
			errs = append(errs, err)
		}
		if strings.TrimSpace(c.DreamUPMobile.DelegationAudience) == "" || c.DreamUPMobile.AssertionTTL < time.Second || c.DreamUPMobile.AssertionTTL > 20*time.Second {
			errs = append(errs, errors.New("DreamUP Mobile bridge audience and assertion TTL are invalid"))
		}
		if c.DreamUPMobile.ScopedRateLimit < 1 || c.DreamUPMobile.ScopedRateLimit > 1000 || c.DreamUPMobile.GlobalRateLimit < c.DreamUPMobile.ScopedRateLimit || c.DreamUPMobile.GlobalRateLimit > 100000 || c.DreamUPMobile.RateWindow <= 0 || c.DreamUPMobile.RateWindow > time.Hour {
			errs = append(errs, errors.New("DreamUP Mobile assertion rate limits must have a scoped limit of 1-1000, a global limit from the scoped limit through 100000, and a positive window no longer than one hour"))
		}
	}
	if c.DreamUPMobile.Enabled && c.DreamUPAdmin.Enabled {
		mobilePath := filepath.Clean(strings.TrimSpace(c.DreamUPMobile.DelegationKeyringPath))
		administratorPath := filepath.Clean(strings.TrimSpace(c.DreamUPAdmin.DelegationKeyringPath))
		if mobilePath != "." && administratorPath != "." && strings.EqualFold(mobilePath, administratorPath) {
			errs = append(errs, errors.New("UP_DREAMUP_MOBILE_DELEGATION_KEYRING_PATH and UP_DREAMUP_DELEGATION_KEYRING_PATH must use distinct keyrings"))
		}
		mobileKeyID := strings.TrimSpace(c.DreamUPMobile.DelegationCurrentKeyID)
		administratorKeyID := strings.TrimSpace(c.DreamUPAdmin.DelegationCurrentKeyID)
		if mobileKeyID != "" && administratorKeyID != "" && mobileKeyID == administratorKeyID {
			errs = append(errs, errors.New("UP_DREAMUP_MOBILE_DELEGATION_CURRENT_KEY_ID and UP_DREAMUP_DELEGATION_CURRENT_KEY_ID current key IDs must be distinct"))
		}
	}

	if c.DreamUPAdmin.Enabled {
		if !c.HasIsolatedDatabase() {
			errs = append(errs, errors.New("DreamUP administration requires UP_ISOLATED_DATABASE_URL for cross-system mutation receipts"))
		}
		keyrings := []struct{ path, current, purpose string }{
			{c.DreamUPAdmin.ChallengeEncryptionKeyringPath, c.DreamUPAdmin.ChallengeEncryptionCurrentKeyID, "challenge encryption"},
			{c.DreamUPAdmin.ChallengePepperKeyringPath, c.DreamUPAdmin.ChallengePepperCurrentKeyID, "challenge pepper"},
			{c.DreamUPAdmin.ProtectedReasonKeyringPath, c.DreamUPAdmin.ProtectedReasonCurrentKeyID, "protected reason"},
			{c.DreamUPAdmin.RateLimitKeyringPath, c.DreamUPAdmin.RateLimitCurrentKeyID, "challenge rate limit"},
			{c.DreamUPAdmin.OperationFingerprintKeyringPath, c.DreamUPAdmin.OperationFingerprintCurrentKeyID, "operation fingerprint"},
		}
		seen := map[string]string{}
		for _, keyring := range keyrings {
			if strings.TrimSpace(keyring.path) == "" || strings.TrimSpace(keyring.current) == "" {
				errs = append(errs, fmt.Errorf("DreamUP admin %s keyring path and current key ID are required", keyring.purpose))
				continue
			}
			identity := keyring.path + "\x00" + keyring.current
			if prior, ok := seen[identity]; ok {
				errs = append(errs, fmt.Errorf("DreamUP admin keyring purpose reuse: %s and %s", prior, keyring.purpose))
			}
			seen[identity] = keyring.purpose
		}
		if c.DreamUPAdmin.FreshLoginMaxAge <= 0 || c.DreamUPAdmin.FreshLoginMaxAge > 15*time.Minute {
			errs = append(errs, errors.New("DreamUP admin fresh login max age must be positive and at most 15 minutes"))
		}
		if c.DreamUPAdmin.GeneralFreshness <= 0 || c.DreamUPAdmin.HighRiskFreshness <= 0 || c.DreamUPAdmin.HighRiskFreshness > c.DreamUPAdmin.GeneralFreshness {
			errs = append(errs, errors.New("DreamUP admin freshness durations are invalid"))
		}
		if c.DreamUPAdmin.RateLimit != 5 || c.DreamUPAdmin.RateWindow != 15*time.Minute || c.DreamUPAdmin.LockDuration != 30*time.Minute {
			errs = append(errs, errors.New("DreamUP admin challenge policy must be five attempts per 15 minutes with a 30 minute lock"))
		}
		if c.DreamUPAdmin.Argon2MaxConcurrent <= 0 || c.DreamUPAdmin.Argon2MaxConcurrent > 64 {
			errs = append(errs, errors.New("DreamUP admin Argon2 concurrency must be between 1 and 64"))
		}
		if strings.TrimSpace(c.DreamUPAdmin.DelegationKeyringPath) == "" || strings.TrimSpace(c.DreamUPAdmin.DelegationCurrentKeyID) == "" || !filepath.IsAbs(c.DreamUPAdmin.DelegationKeyringPath) {
			errs = append(errs, errors.New("DreamUP admin BFF delegation keyring requires an absolute path and current key ID"))
		}
		if err := validateDreamUPInternalBaseURL(c.DreamUPAdmin.BaseURL); err != nil {
			errs = append(errs, err)
		}
		if err := validateHTTPSOrigin(c.DreamUPAdmin.DelegationIssuer, "DreamUP admin BFF issuer"); err != nil {
			errs = append(errs, err)
		}
		if err := validateHTTPSOrigin(c.DreamUPAdmin.AdminOrigin, "DreamUP admin BFF browser origin"); err != nil {
			errs = append(errs, err)
		}
		if strings.TrimSpace(c.DreamUPAdmin.DelegationAudience) == "" {
			errs = append(errs, errors.New("DreamUP admin BFF delegation audience is required"))
		}
		if c.DreamUPAdmin.ResponseLimitBytes < 1<<20 || c.DreamUPAdmin.ResponseLimitBytes > 16<<20 {
			errs = append(errs, errors.New("DreamUP admin BFF response limit must be between 1 MiB and 16 MiB"))
		}
		if c.DreamUPAdmin.ReconcileInterval < time.Second || c.DreamUPAdmin.ReconcileInterval > 5*time.Minute || c.DreamUPAdmin.ReconcileBatchSize < 1 || c.DreamUPAdmin.ReconcileBatchSize > 100 || c.DreamUPAdmin.ReconcileLease < c.DreamUPAdmin.ReconcileInterval || c.DreamUPAdmin.ReconcileLease > 10*time.Minute {
			errs = append(errs, errors.New("DreamUP admin BFF reconciliation settings are invalid"))
		}
		if c.DreamUPAdmin.DelegationServiceSubject != "united-pass:dreamup-reconciler" || c.DreamUPAdmin.DelegationServiceVersion <= 0 {
			errs = append(errs, errors.New("DreamUP admin BFF service subject and positive version are required"))
		}
	}

	switch c.Environment {
	case EnvironmentDevelopment, EnvironmentProduction:
	default:
		errs = append(errs, fmt.Errorf("invalid environment %q: must be %q or %q",
			c.Environment, EnvironmentDevelopment, EnvironmentProduction))
	}

	if c.HTTPAddr == "" {
		errs = append(errs, errors.New("http address must not be empty"))
	}
	if c.ReadHeaderTimeout <= 0 {
		errs = append(errs, errors.New("read header timeout must be positive"))
	}
	if c.ReadTimeout <= 0 {
		errs = append(errs, errors.New("read timeout must be positive"))
	}
	if c.WriteTimeout <= 0 {
		errs = append(errs, errors.New("write timeout must be positive"))
	}
	if c.IdleTimeout <= 0 {
		errs = append(errs, errors.New("idle timeout must be positive"))
	}
	if c.ShutdownTimeout <= 0 {
		errs = append(errs, errors.New("shutdown timeout must be positive"))
	}
	if c.MaxRequestBodyBytes <= 0 {
		errs = append(errs, errors.New("max request body bytes must be positive"))
	}

	if _, err := parseLogLevel(c.LogLevel); err != nil {
		errs = append(errs, err)
	}

	// Session validation.
	if c.Session.TTL <= 0 {
		errs = append(errs, errors.New("session TTL must be positive"))
	}
	if c.Session.EncryptionKey != "" {
		key, err := base64.StdEncoding.DecodeString(c.Session.EncryptionKey)
		if err != nil {
			errs = append(errs, errors.New("session encryption key must be base64-encoded"))
		} else if len(key) != 32 {
			errs = append(errs, fmt.Errorf("session encryption key must decode to 32 bytes, got %d", len(key)))
		}
		// The ciphertext format is "{keyID}:{payload}"; a ':' in the key ID
		// would break parsing and could collide with other key IDs.
		if strings.Contains(c.Session.EncryptionKeyID, ":") {
			errs = append(errs, errors.New("session encryption key id must not contain ':'"))
		}
	}
	if c.Session.RememberTTL <= 0 {
		errs = append(errs, errors.New("session remember TTL must be positive"))
	}
	if c.Session.IdleTTL <= 0 {
		errs = append(errs, errors.New("session idle TTL must be positive"))
	}
	if c.Session.TouchInterval <= 0 {
		errs = append(errs, errors.New("session touch interval must be positive"))
	}
	switch strings.ToLower(c.Session.CookieSameSite) {
	case "lax", "strict", "none":
	default:
		errs = append(errs, fmt.Errorf("invalid session cookie SameSite %q: must be lax, strict or none", c.Session.CookieSameSite))
	}

	// MFA validation.
	if c.MFA.ChallengeTTL <= 0 {
		errs = append(errs, errors.New("MFA challenge TTL must be positive"))
	}
	if c.MFA.MaxAttempts <= 0 {
		errs = append(errs, errors.New("MFA max attempts must be positive"))
	}

	// Reauthentication validation.
	if c.Reauth.ChallengeTTL <= 0 {
		errs = append(errs, errors.New("reauthentication challenge TTL must be positive"))
	}
	if c.Reauth.GrantTTL <= 0 {
		errs = append(errs, errors.New("reauthentication grant TTL must be positive"))
	}
	if c.Reauth.MaxAttempts <= 0 {
		errs = append(errs, errors.New("reauthentication max attempts must be positive"))
	}
	if c.Reauth.RateLimit <= 0 {
		errs = append(errs, errors.New("reauthentication rate limit must be positive"))
	}
	if c.Reauth.RateWindow <= 0 {
		errs = append(errs, errors.New("reauthentication rate window must be positive"))
	}
	if c.Reauth.CleanupInterval <= 0 {
		errs = append(errs, errors.New("reauthentication cleanup interval must be positive"))
	}

	// Secret rotation validation.
	if c.Rotation.GracePeriod < 0 {
		errs = append(errs, errors.New("secret rotation grace period must not be negative"))
	}
	if c.Rotation.RateLimit <= 0 {
		errs = append(errs, errors.New("secret rotation rate limit must be positive"))
	}
	if c.Rotation.RateWindow <= 0 {
		errs = append(errs, errors.New("secret rotation rate window must be positive"))
	}

	// Security state validation (ADR-0007).
	if c.SecurityState.ProviderDeadline <= 0 {
		errs = append(errs, errors.New("security state provider deadline must be positive"))
	}
	if c.SecurityState.SettlementTimeout <= 0 {
		errs = append(errs, errors.New("security state settlement timeout must be positive"))
	}
	if c.SecurityState.RecoveryTimeout <= 0 {
		errs = append(errs, errors.New("security state recovery timeout must be positive"))
	}
	if c.SecurityState.MaxSettlementAttempts <= 0 {
		errs = append(errs, errors.New("security state max settlement attempts must be positive"))
	}
	// Lease expiry must strictly outlive the provider deadline plus the
	// settlement timeout (the frozen safety margin): a live, legitimate
	// mutation must always own its fence until its authoritative work is
	// done.
	if c.SecurityState.LeaseTTL <= c.SecurityState.ProviderDeadline+c.SecurityState.SettlementTimeout {
		errs = append(errs, errors.New("security state lease TTL must strictly exceed the provider deadline plus the settlement timeout"))
	}

	// Rate limit validation.
	if c.RateLimit.LoginLimit <= 0 {
		errs = append(errs, errors.New("login rate limit must be positive"))
	}
	if c.RateLimit.LoginWindow <= 0 {
		errs = append(errs, errors.New("login rate window must be positive"))
	}
	if c.RateLimit.MFALimit <= 0 {
		errs = append(errs, errors.New("MFA rate limit must be positive"))
	}
	if c.RateLimit.MFAWindow <= 0 {
		errs = append(errs, errors.New("MFA rate window must be positive"))
	}
	if c.RiskDefense.Enabled {
		risk := c.RiskDefense
		if risk.ObservationWindow <= 0 || risk.ChallengeTTL <= 0 || risk.DeviceIDTTL <= 0 || risk.TrustTTL <= 0 || risk.CompletionWindow <= 0 || risk.CompletionLimit <= 0 {
			errs = append(errs, errors.New("risk defense TTLs, windows, and completion limit must be positive"))
		}
		if risk.LoginMediumAfter <= 0 || risk.LoginHighAfter <= risk.LoginMediumAfter || risk.RegistrationMediumAfter <= 0 || risk.RegistrationHighAfter <= risk.RegistrationMediumAfter {
			errs = append(errs, errors.New("risk defense thresholds must be positive and high must exceed medium"))
		}
		if risk.AutomationCostDifficulty <= 0 || risk.AutomationCostDifficulty > 30 {
			errs = append(errs, errors.New("risk automation-cost difficulty must be between 1 and 30 bits"))
		}
		for _, digest := range risk.AllowlistedHashes {
			if !riskAllowlistDigestPattern.MatchString(strings.ToLower(strings.TrimSpace(digest))) {
				errs = append(errs, errors.New("risk allowlist entries must be SHA-256 hex digests"))
			}
		}
		if risk.Captcha.Region != "mainland_china" && risk.Captcha.Region != "global" {
			errs = append(errs, errors.New("risk captcha region must be mainland_china or global"))
		}
		if err := validateRiskCaptchaProvider("Turnstile", risk.Captcha.Turnstile.SiteKey, risk.Captcha.Turnstile.SecretKey, risk.Captcha.Turnstile.Hostname); err != nil {
			errs = append(errs, err)
		}
		if err := validateRiskCaptchaProvider("reCAPTCHA", risk.Captcha.Recaptcha.SiteKey, risk.Captcha.Recaptcha.SecretKey, risk.Captcha.Recaptcha.Hostname); err != nil {
			errs = append(errs, err)
		}
		if risk.Captcha.Recaptcha.Configured() && (math.IsNaN(risk.Captcha.Recaptcha.MinScore) || math.IsInf(risk.Captcha.Recaptcha.MinScore, 0) || risk.Captcha.Recaptcha.MinScore <= 0 || risk.Captcha.Recaptcha.MinScore > 1) {
			errs = append(errs, errors.New("risk reCAPTCHA minimum score must be greater than zero and at most one"))
		}
	}

	// Database validation (when configured).
	if c.Database.URL != "" {
		if c.Database.Schema == "" {
			errs = append(errs, errors.New("database schema must not be empty when database URL is set"))
		} else if !ValidSchemaIdentifier(c.Database.Schema) {
			errs = append(errs, fmt.Errorf("database schema %q is not a valid PostgreSQL identifier", c.Database.Schema))
		}
		if c.Database.MaxConns <= 0 {
			errs = append(errs, errors.New("database max connections must be positive"))
		}
		if c.Database.MinConns < 0 {
			errs = append(errs, errors.New("database min connections must not be negative"))
		}
		if c.Database.ConnectTimeout <= 0 {
			errs = append(errs, errors.New("database connect timeout must be positive"))
		}
	}
	if c.IsolatedDatabase.URL != "" {
		if c.IsolatedDatabase.Schema == "" {
			errs = append(errs, errors.New("isolated database schema must not be empty when UP_ISOLATED_DATABASE_URL is set"))
		} else if !ValidSchemaIdentifier(c.IsolatedDatabase.Schema) {
			errs = append(errs, fmt.Errorf("isolated database schema %q is not a valid PostgreSQL identifier", c.IsolatedDatabase.Schema))
		}
		if c.IsolatedDatabase.MaxConns <= 0 {
			errs = append(errs, errors.New("isolated database max connections must be positive"))
		}
		if c.IsolatedDatabase.MinConns < 0 {
			errs = append(errs, errors.New("isolated database min connections must not be negative"))
		}
		if c.IsolatedDatabase.ConnectTimeout <= 0 {
			errs = append(errs, errors.New("isolated database connect timeout must be positive"))
		}
		if samePostgresDatabase(c.Database, c.IsolatedDatabase) {
			errs = append(errs, errors.New("UP_ISOLATED_DATABASE_URL must identify a database distinct from UP_DATABASE_URL"))
		}
	}

	// Redis validation (when configured).
	if c.Redis.URL != "" {
		if c.Redis.KeyPrefix == "" {
			errs = append(errs, errors.New("redis key prefix must not be empty when redis URL is set"))
		}
		if c.Redis.PoolSize <= 0 {
			errs = append(errs, errors.New("redis pool size must be positive"))
		}
		if c.Redis.ConnectTimeout <= 0 {
			errs = append(errs, errors.New("redis connect timeout must be positive"))
		}
	}

	// OAuth topology validation (when configured). The public origin is an
	// origin, not a base URL; derived URIs (InteractionBaseURI) must never be
	// poisonable by extra URL components smuggled into the configuration.
	if c.OAuth.PublicOrigin != "" {
		if err := validateOAuthPublicOrigin(c.OAuth.PublicOrigin, c.IsProduction()); err != nil {
			errs = append(errs, err)
		}
	}

	// Feishu Provider validation. The integration is optional, but partial
	// credentials are never accepted because they produce a misleading
	// secretConfigured state and fail only after an administrator enables it.
	feishuValues := []string{c.Feishu.AppID, c.Feishu.AppSecret, c.Feishu.TenantID, c.Feishu.RedirectURL}
	configuredFeishuValues := 0
	for _, value := range feishuValues {
		if value != "" {
			configuredFeishuValues++
		}
	}
	if configuredFeishuValues != 0 && configuredFeishuValues != len(feishuValues) {
		errs = append(errs, errors.New("Feishu requires UP_FEISHU_APP_ID, UP_FEISHU_APP_SECRET, UP_FEISHU_TENANT_ID and UP_FEISHU_REDIRECT_URL together"))
	}
	if configuredFeishuValues > 0 {
		if c.Feishu.OAuthStateTTL <= 0 || c.Feishu.OAuthStateTTL > 15*time.Minute {
			errs = append(errs, errors.New("Feishu OAuth state TTL must be positive and at most 15 minutes"))
		}
		if c.Feishu.RequestTimeout <= 0 || c.Feishu.ReconcileInterval <= 0 || c.Feishu.SyncTimeout <= 0 {
			errs = append(errs, errors.New("Feishu request, reconciliation and sync durations must be positive"))
		}
	}
	if c.Feishu.Configured() {
		if len(c.Feishu.AppID) > 256 || len(c.Feishu.AppSecret) > 512 || len(c.Feishu.TenantID) > 256 {
			errs = append(errs, errors.New("Feishu credential or tenant identifier exceeds the allowed length"))
		}
		if strings.TrimSpace(c.Feishu.ContactScope) == "" || len(c.Feishu.ContactScope) > 256 {
			errs = append(errs, errors.New("Feishu contact scope label must be 1 to 256 bytes"))
		}
		if err := validateProviderURL(c.Feishu.BaseURL, c.IsProduction(), false); err != nil {
			errs = append(errs, fmt.Errorf("Feishu base URL: %w", err))
		}
		if err := validateProviderURL(c.Feishu.AuthorizeURL, c.IsProduction(), true); err != nil {
			errs = append(errs, fmt.Errorf("Feishu authorization URL: %w", err))
		}
		if err := validateFeishuRedirectURL(c.Feishu.RedirectURL, c.IsProduction()); err != nil {
			errs = append(errs, err)
		}
	}

	cerbosValues := []string{c.Cerbos.PDPURL, c.Cerbos.AdminURL, c.Cerbos.AdminUsername, c.Cerbos.AdminPassword}
	configuredCerbosValues := 0
	for _, value := range cerbosValues {
		if value != "" {
			configuredCerbosValues++
		}
	}
	if configuredCerbosValues != 0 && configuredCerbosValues != len(cerbosValues) {
		errs = append(errs, errors.New("Cerbos requires UP_CERBOS_PDP_URL, UP_CERBOS_ADMIN_URL, UP_CERBOS_ADMIN_USERNAME and UP_CERBOS_ADMIN_PASSWORD together"))
	}
	if c.Cerbos.Configured() {
		if c.Cerbos.RequestTimeout <= 0 || c.Cerbos.RequestTimeout > 30*time.Second || c.Cerbos.ReconcileInterval <= 0 {
			errs = append(errs, errors.New("Cerbos request timeout must be positive and at most 30 seconds; reconciliation interval must be positive"))
		}
		if err := validateProviderURL(c.Cerbos.PDPURL, c.IsProduction(), false); err != nil {
			errs = append(errs, fmt.Errorf("Cerbos PDP URL: %w", err))
		}
		if err := validateProviderURL(c.Cerbos.AdminURL, c.IsProduction(), false); err != nil {
			errs = append(errs, fmt.Errorf("Cerbos Admin URL: %w", err))
		}
		if c.Cerbos.AdminUsername == "cerbos" && c.Cerbos.AdminPassword == "cerbosAdmin" {
			errs = append(errs, errors.New("Cerbos default Admin API credentials are forbidden"))
		}
	}

	// Integration test validation (when configured).
	if c.Test.DatabaseURL != "" {
		if c.Test.DatabaseSchema == "" {
			errs = append(errs, errors.New("test database schema must not be empty when test database URL is set"))
		} else if !ValidSchemaIdentifier(c.Test.DatabaseSchema) {
			errs = append(errs, fmt.Errorf("test database schema %q is not a valid PostgreSQL identifier", c.Test.DatabaseSchema))
		}
	}

	if c.IsProduction() {
		if len(c.ClientIP.TrustedProxyCIDRs) == 0 {
			errs = append(errs, errors.New("production requires UP_TRUSTED_PROXY_CIDRS"))
		}
		if c.ShutdownTimeout > 60*time.Second {
			errs = append(errs, errors.New("production shutdown timeout must not exceed 60s"))
		}
		if c.MaxRequestBodyBytes > 16*(1<<20) {
			errs = append(errs, errors.New("production max request body bytes must not exceed 16 MiB"))
		}
		// Production requires TLS-capable database and Redis.
		if c.Database.URL == "" {
			errs = append(errs, errors.New("production requires UP_DATABASE_URL"))
		}
		if c.Redis.URL == "" {
			errs = append(errs, errors.New("production requires UP_REDIS_URL"))
		}
		if !c.Session.CookieSecure {
			errs = append(errs, errors.New("production requires UP_SESSION_COOKIE_SECURE=true"))
		}
		if c.Auth.Provider == "" || c.Auth.BaseURL == "" {
			errs = append(errs, errors.New("production requires authentication provider configuration"))
		}
		if c.Auth.Provider == "zitadel" && c.Auth.ServiceAccountKeyFile == "" {
			errs = append(errs, errors.New("zitadel provider requires UP_AUTH_PROVIDER_SERVICE_ACCOUNT_KEY_FILE"))
		}
		// Production ZITADEL must be reached over HTTPS. Rejecting plaintext
		// and URL injection prevents a misconfigured deployment from
		// downgrading the provider connection or leaking credentials.
		if c.Auth.BaseURL != "" {
			u, err := url.Parse(c.Auth.BaseURL)
			if err != nil {
				errs = append(errs, fmt.Errorf("authentication provider base URL is invalid: %w", err))
			} else {
				if u.Scheme != "https" {
					errs = append(errs, errors.New("production authentication provider base URL must use https"))
				}
				if u.Host == "" {
					errs = append(errs, errors.New("authentication provider base URL must include a host"))
				}
				if u.User != nil {
					errs = append(errs, errors.New("authentication provider base URL must not contain userinfo"))
				}
				if u.RawQuery != "" || u.Fragment != "" {
					errs = append(errs, errors.New("authentication provider base URL must not contain query or fragment"))
				}
			}
		}
		// The public OAuth topology is mandatory in production: the issuer,
		// the LoginV2 Interaction Base URI and the provisioned app
		// configuration are all derived from it.
		if c.OAuth.PublicOrigin == "" {
			errs = append(errs, errors.New("production requires UP_OAUTH_PUBLIC_ORIGIN"))
		}
		// Production stores provider session references encrypted at rest
		// (ADR-0002 section 13), so the encryption key is mandatory.
		if c.Session.EncryptionKey == "" {
			errs = append(errs, errors.New("production requires UP_SESSION_ENCRYPTION_KEY"))
		}
		if c.Permission.DevOverrideEnabled {
			errs = append(errs, errors.New("production must not enable permission dev override"))
		}
		if !c.Cerbos.Configured() {
			errs = append(errs, errors.New("production requires complete Cerbos configuration"))
		}
	}

	return errors.Join(errs...)
}

// IsProduction reports whether the process runs in the production environment.
func (c Config) IsProduction() bool {
	return c.Environment == EnvironmentProduction
}

// LogLevel returns the parsed slog.Level for the configured log level.
func (c Config) LogLevelValue() (slog.Level, error) {
	return parseLogLevel(c.LogLevel)
}

// HasDatabase reports whether a database URL is configured.
func (c Config) HasDatabase() bool {
	return c.Database.URL != ""
}

// HasIsolatedDatabase reports whether the optional DreamUP/Mini Program
// operational store has been configured. It never substitutes for the main
// United Pass authority database.
func (c Config) HasIsolatedDatabase() bool {
	return c.IsolatedDatabase.URL != ""
}

// HasRedis reports whether a Redis URL is configured.
func (c Config) HasRedis() bool {
	return c.Redis.URL != ""
}

// HasAuthProvider reports whether an authentication provider is configured.
func (c Config) HasAuthProvider() bool {
	return c.Auth.Provider != "" && c.Auth.BaseURL != ""
}

// schemaIdentifierPattern restricts schema names to safe PostgreSQL
// identifiers: lowercase ASCII letters, digits and underscores, at most 63
// characters (PostgreSQL's NAMEDATALEN limit). Schema names from environment
// variables must never be interpolated into SQL without this check.
var schemaIdentifierPattern = regexp.MustCompile(`^[a-z_][a-z0-9_]{0,62}$`)
var riskAllowlistDigestPattern = regexp.MustCompile(`^[0-9a-f]{64}$`)

// ValidSchemaIdentifier reports whether s is a safe PostgreSQL schema
// identifier. Schema names are interpolated into SQL (CREATE SCHEMA, goose
// version table name, cleanup statements), so they must be validated before
// use and quoted with pgx.Identifier when concatenated into statements.
func ValidSchemaIdentifier(s string) bool {
	return schemaIdentifierPattern.MatchString(s)
}

func samePostgresDatabase(primary, isolated DatabaseConfig) bool {
	if primary.URL == "" || isolated.URL == "" {
		return false
	}
	primaryHost, primaryDatabase, primaryOK := normalizedPostgresTarget(primary.URL)
	isolatedHost, isolatedDatabase, isolatedOK := normalizedPostgresTarget(isolated.URL)
	if !primaryOK || !isolatedOK {
		return false
	}
	return primaryHost == isolatedHost && primaryDatabase == isolatedDatabase
}

// normalizedPostgresTarget deliberately ignores credentials, TLS query
// parameters and the postgres/postgresql spelling difference. Those values
// can differ while still selecting the same authority database. Treat an
// omitted TCP port as PostgreSQL's 5432 default so cosmetic URL changes cannot
// bypass the isolated-store boundary check.
func normalizedPostgresTarget(raw string) (host, database string, ok bool) {
	parsed, err := url.Parse(raw)
	if err != nil {
		return "", "", false
	}
	switch strings.ToLower(parsed.Scheme) {
	case "postgres", "postgresql":
	default:
		return "", "", false
	}
	hostname := strings.ToLower(strings.TrimSpace(parsed.Hostname()))
	if hostname == "" {
		return "", "", false
	}
	port := parsed.Port()
	if port == "" {
		port = "5432"
	}
	database = strings.TrimPrefix(parsed.Path, "/")
	if queryDatabase := parsed.Query().Get("dbname"); queryDatabase != "" {
		if database != "" && database != queryDatabase {
			return "", "", false
		}
		database = queryDatabase
	}
	if database == "" {
		return "", "", false
	}
	return net.JoinHostPort(hostname, port), database, true
}

// validateOAuthPublicOrigin enforces strict origin syntax: scheme://host[:port]
// with nothing else. A trailing "/" is tolerated and normalized away by
// InteractionBaseURI. Production additionally requires HTTPS.
func validateOAuthPublicOrigin(origin string, requireHTTPS bool) error {
	u, err := url.Parse(origin)
	if err != nil {
		return fmt.Errorf("oauth public origin is invalid: %w", err)
	}
	switch u.Scheme {
	case "https":
	case "http":
		if requireHTTPS {
			return errors.New("oauth public origin must use https in production")
		}
	default:
		return fmt.Errorf("oauth public origin scheme %q must be http or https", u.Scheme)
	}
	if u.Host == "" {
		return errors.New("oauth public origin must include a host")
	}
	if u.User != nil {
		return errors.New("oauth public origin must not contain userinfo")
	}
	if u.Path != "" && u.Path != "/" {
		return fmt.Errorf("oauth public origin must not contain a path, got %q", u.Path)
	}
	if u.RawQuery != "" {
		return errors.New("oauth public origin must not contain a query")
	}
	if u.Fragment != "" {
		return errors.New("oauth public origin must not contain a fragment")
	}
	return nil
}

func validateDreamUPInternalBaseURL(raw string) error {
	u, err := url.Parse(strings.TrimSpace(raw))
	if err != nil || u.Host == "" || u.User != nil || u.RawQuery != "" || u.Fragment != "" || (u.Path != "" && u.Path != "/") {
		return errors.New("DreamUP admin BFF base URL must be an origin without credentials, path, query, or fragment")
	}
	if u.Scheme == "https" {
		return nil
	}
	address := net.ParseIP(u.Hostname())
	if u.Scheme != "http" || address == nil || !address.IsLoopback() {
		return errors.New("DreamUP admin BFF cleartext base URL is permitted only on loopback")
	}
	return nil
}

// validateAliyunSMSEndpoint pins every runtime SMS request to Aliyun's public
// SendSms origin. Tests that need a loopback provider use the adapter's
// injected HTTP-client seam and never pass through deployment configuration.
func validateAliyunSMSEndpoint(raw string) error {
	if raw == "" || raw != strings.TrimSpace(raw) {
		return errors.New("Aliyun SMS endpoint must be non-empty and trimmed")
	}
	endpoint, err := url.Parse(raw)
	if err != nil || strings.Contains(raw, "#") || endpoint.Scheme == "" || endpoint.Host == "" || endpoint.Opaque != "" || endpoint.User != nil || endpoint.RawQuery != "" || endpoint.ForceQuery || endpoint.Fragment != "" || endpoint.RawPath != "" || (endpoint.Path != "" && endpoint.Path != "/") {
		return errors.New("Aliyun SMS endpoint must be an origin without userinfo, path, query, or fragment")
	}
	officialHost := strings.EqualFold(endpoint.Host, "dysmsapi.aliyuncs.com") || strings.EqualFold(endpoint.Host, "dysmsapi.aliyuncs.com:443")
	if endpoint.Scheme != "https" || !officialHost {
		return errors.New("Aliyun SMS endpoint must use the official https://dysmsapi.aliyuncs.com origin on port 443")
	}
	return nil
}

func validateHTTPSOrigin(raw, label string) error {
	u, err := url.Parse(strings.TrimSpace(raw))
	if err != nil || u.Scheme != "https" || u.Host == "" || u.User != nil || u.RawQuery != "" || u.Fragment != "" || (u.Path != "" && u.Path != "/") {
		return fmt.Errorf("%s must be an HTTPS origin", label)
	}
	return nil
}

func validateProviderURL(raw string, requireHTTPS, allowPath bool) error {
	u, err := url.Parse(raw)
	if err != nil {
		return fmt.Errorf("invalid URL: %w", err)
	}
	if u.Scheme != "https" && (requireHTTPS || u.Scheme != "http") {
		return errors.New("URL must use https")
	}
	if u.Host == "" || u.User != nil || u.RawQuery != "" || u.Fragment != "" {
		return errors.New("URL must include a host and must not contain userinfo, query or fragment")
	}
	if !allowPath && u.Path != "" && u.Path != "/" {
		return errors.New("base URL must not contain a path")
	}
	return nil
}

func validateFeishuRedirectURL(raw string, requireHTTPS bool) error {
	u, err := url.Parse(raw)
	if err != nil {
		return fmt.Errorf("Feishu redirect URL is invalid: %w", err)
	}
	if u.Scheme != "https" && (requireHTTPS || u.Scheme != "http") {
		return errors.New("Feishu redirect URL must use https")
	}
	if u.Host == "" || u.User != nil || u.Fragment != "" || u.RawQuery != "" {
		return errors.New("Feishu redirect URL must include a host and must not contain userinfo, query or fragment")
	}
	if u.Path == "" || u.Path == "/" {
		return errors.New("Feishu redirect URL must contain the exact callback path")
	}
	if u.Path != "/api/v1/auth/providers/feishu/callback" {
		return errors.New("Feishu redirect URL path must be /api/v1/auth/providers/feishu/callback")
	}
	return nil
}

func validateRiskCaptchaProvider(label, siteKey, secretKey, hostname string) error {
	values := []string{strings.TrimSpace(siteKey), strings.TrimSpace(secretKey), strings.TrimSpace(hostname)}
	configured := 0
	for _, value := range values {
		if value != "" {
			configured++
		}
	}
	if configured == 0 {
		return nil
	}
	if configured != len(values) {
		return fmt.Errorf("risk %s requires site key, secret key, and exact hostname together", label)
	}
	if len(values[0]) > 512 || len(values[1]) > 512 || !validRiskCaptchaHostname(values[2]) {
		return fmt.Errorf("risk %s site key, secret key, or hostname is invalid", label)
	}
	return nil
}

func validRiskCaptchaHostname(value string) bool {
	value = strings.TrimSuffix(strings.ToLower(strings.TrimSpace(value)), ".")
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

func parseLogLevel(raw string) (slog.Level, error) {
	switch strings.ToLower(strings.TrimSpace(raw)) {
	case "debug":
		return slog.LevelDebug, nil
	case "info":
		return slog.LevelInfo, nil
	case "warn":
		return slog.LevelWarn, nil
	case "error":
		return slog.LevelError, nil
	default:
		return 0, fmt.Errorf("invalid log level %q: must be debug, info, warn or error", raw)
	}
}

func envOr(key, fallback string) string {
	if value, ok := os.LookupEnv(key); ok && value != "" {
		return value
	}
	return fallback
}

func csvOr(key, fallback string) []string {
	raw := envOr(key, fallback)
	parts := strings.Split(raw, ",")
	values := make([]string, 0, len(parts))
	for _, part := range parts {
		if value := strings.TrimSpace(part); value != "" {
			values = append(values, value)
		}
	}
	return values
}

func durationOr(key string, fallback time.Duration) time.Duration {
	if value, ok := os.LookupEnv(key); ok && value != "" {
		parsed, err := time.ParseDuration(value)
		if err == nil {
			return parsed
		}
	}
	return fallback
}

func int64Or(key string, fallback int64) int64 {
	if value, ok := os.LookupEnv(key); ok && value != "" {
		parsed, err := strconv.ParseInt(value, 10, 64)
		if err == nil {
			return parsed
		}
	}
	return fallback
}

func int32Or(key string, fallback int32) int32 {
	if value, ok := os.LookupEnv(key); ok && value != "" {
		parsed, err := strconv.ParseInt(value, 10, 32)
		if err == nil {
			return int32(parsed)
		}
	}
	return fallback
}

func intOr(key string, fallback int) int {
	if value, ok := os.LookupEnv(key); ok && value != "" {
		parsed, err := strconv.Atoi(value)
		if err == nil {
			return parsed
		}
	}
	return fallback
}

func float64Or(key string, fallback float64) float64 {
	if value, ok := os.LookupEnv(key); ok && value != "" {
		parsed, err := strconv.ParseFloat(value, 64)
		if err == nil {
			return parsed
		}
	}
	return fallback
}

func boolOr(key string, fallback bool) bool {
	if value, ok := os.LookupEnv(key); ok && value != "" {
		parsed, err := strconv.ParseBool(value)
		if err == nil {
			return parsed
		}
	}
	return fallback
}
