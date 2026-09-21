//
// Copyright (c) 2026 Chen Jiajie(Ariakage)
//
// Author: Chen Jiajie(Ariakage) <ariakage233@gmail.com>
// Date: 2026-08-05
// Description: Unit tests for the configuration loading
//

package config

import (
	"bytes"
	"encoding/base64"
	"math"
	"strings"
	"testing"
	"time"
)

func TestLoadDefaults(t *testing.T) {
	t.Setenv("UP_ENVIRONMENT", "development")
	// Clear optional overrides so defaults apply.
	clearEnv(t,
		"UP_HTTP_ADDR", "UP_READ_HEADER_TIMEOUT", "UP_READ_TIMEOUT",
		"UP_WRITE_TIMEOUT", "UP_IDLE_TIMEOUT", "UP_SHUTDOWN_TIMEOUT",
		"UP_MAX_REQUEST_BODY_BYTES", "UP_LOG_LEVEL", "UP_DREAMUP_ADMIN_ORIGIN",
		"UP_PUBLIC_REGISTRATION_ENABLED", "UP_AUTH_PROVIDER_ORGANIZATION_ID",
		"UP_TRUSTED_PROXY_CIDRS", "UP_REGISTRATION_CREATE_IP_LIMIT",
		"UP_REGISTRATION_CREATE_IP_WINDOW", "UP_REGISTRATION_CREATE_NET_LIMIT",
		"UP_REGISTRATION_CREATE_NET_WINDOW", "UP_REGISTRATION_CREATE_EMAIL_LIMIT",
		"UP_REGISTRATION_CREATE_EMAIL_WINDOW", "UP_REGISTRATION_CREATE_MAILBOX_FAMILY_LIMIT", "UP_REGISTRATION_CREATE_MAILBOX_FAMILY_WINDOW", "UP_REGISTRATION_CREATE_PAIR_LIMIT",
		"UP_REGISTRATION_CREATE_PAIR_WINDOW", "UP_REGISTRATION_GLOBAL_BURST_LIMIT",
		"UP_REGISTRATION_FORM_INTENT_DEVICE_LIMIT", "UP_REGISTRATION_FORM_INTENT_DEVICE_WINDOW",
		"UP_REGISTRATION_FORM_INTENT_NET_LIMIT", "UP_REGISTRATION_FORM_INTENT_NET_WINDOW",
		"UP_REGISTRATION_FORM_INTENT_GLOBAL_BURST_LIMIT", "UP_REGISTRATION_FORM_INTENT_GLOBAL_BURST_WINDOW",
		"UP_REGISTRATION_FORM_INTENT_GLOBAL_LIMIT", "UP_REGISTRATION_FORM_INTENT_GLOBAL_WINDOW",
		"UP_REGISTRATION_GLOBAL_BURST_WINDOW", "UP_REGISTRATION_GLOBAL_LIMIT", "UP_REGISTRATION_GLOBAL_WINDOW",
		"UP_REGISTRATION_UNFAMILIAR_DOMAIN_BURST_LIMIT", "UP_REGISTRATION_UNFAMILIAR_DOMAIN_BURST_WINDOW",
		"UP_REGISTRATION_UNFAMILIAR_DOMAIN_LIMIT", "UP_REGISTRATION_UNFAMILIAR_DOMAIN_WINDOW",
		"UP_REGISTRATION_UNFAMILIAR_MX_BURST_LIMIT", "UP_REGISTRATION_UNFAMILIAR_MX_BURST_WINDOW",
		"UP_REGISTRATION_UNFAMILIAR_MX_LIMIT", "UP_REGISTRATION_UNFAMILIAR_MX_WINDOW",
		"UP_REGISTRATION_ADMISSION_MAX_IN_FLIGHT", "UP_REGISTRATION_ADMISSION_MAX_QUEUED", "UP_REGISTRATION_ADMISSION_WAIT_TIMEOUT",
		"UP_REGISTRATION_UNFAMILIAR_MAX_IN_FLIGHT", "UP_REGISTRATION_UNFAMILIAR_MAX_QUEUED", "UP_REGISTRATION_UNFAMILIAR_PER_DOMAIN",
		"UP_REGISTRATION_BLOCKED_EMAIL_DOMAINS_EXTRA", "UP_REGISTRATION_BLOCKED_MX_DOMAINS_EXTRA",
		"UP_REGISTRATION_ESTABLISHED_EMAIL_DOMAINS_EXTRA", "UP_REGISTRATION_ESTABLISHED_MX_DOMAINS_EXTRA",
		"UP_REGISTRATION_HONEYPOT_IP_BLOCKS_ENABLED", "UP_REGISTRATION_VERIFY_LIMIT",
		"UP_REGISTRATION_VERIFY_WINDOW", "UP_REGISTRATION_VERIFY_GLOBAL_BURST_LIMIT", "UP_REGISTRATION_VERIFY_GLOBAL_BURST_WINDOW",
		"UP_REGISTRATION_VERIFY_GLOBAL_LIMIT", "UP_REGISTRATION_VERIFY_GLOBAL_WINDOW", "UP_REGISTRATION_RESEND_LIMIT",
		"UP_REGISTRATION_RESEND_WINDOW", "UP_REGISTRATION_IPV4_NET_BITS",
		"UP_REGISTRATION_IPV6_NET_BITS", "UP_RISK_DEFENSE_ENABLED",
		"UP_RISK_OBSERVATION_WINDOW", "UP_RISK_LOGIN_MEDIUM_AFTER", "UP_RISK_LOGIN_HIGH_AFTER",
		"UP_RISK_REGISTRATION_MEDIUM_AFTER", "UP_RISK_REGISTRATION_HIGH_AFTER",
		"UP_RISK_CHALLENGE_TTL", "UP_RISK_DEVICE_ID_TTL", "UP_RISK_TRUST_TTL",
		"UP_RISK_AUTOMATION_COST_DIFFICULTY", "UP_RISK_COMPLETION_LIMIT",
		"UP_RISK_COMPLETION_WINDOW", "UP_RISK_ALLOWLIST_SHA256",
		"UP_RISK_REGISTRATION_ISSUE_DEVICE_LIMIT", "UP_RISK_REGISTRATION_ISSUE_NETWORK_LIMIT", "UP_RISK_REGISTRATION_ISSUE_WINDOW",
		"UP_RISK_REGISTRATION_ISSUE_GLOBAL_BURST_LIMIT", "UP_RISK_REGISTRATION_ISSUE_GLOBAL_BURST_WINDOW",
		"UP_RISK_REGISTRATION_ISSUE_GLOBAL_LIMIT", "UP_RISK_REGISTRATION_ISSUE_GLOBAL_WINDOW",
		"UP_RISK_REGISTRATION_ISSUE_MAX_IN_FLIGHT", "UP_RISK_REGISTRATION_ISSUE_MAX_QUEUED", "UP_RISK_REGISTRATION_ISSUE_WAIT_TIMEOUT",
		"UP_DREAMUP_MOBILE_SCOPED_RATE_LIMIT", "UP_DREAMUP_MOBILE_GLOBAL_RATE_LIMIT",
		"UP_DREAMUP_MOBILE_RATE_WINDOW",
		"UP_ISOLATED_DATABASE_URL", "UP_ISOLATED_DATABASE_SCHEMA",
		"UP_WECHAT_MINIPROGRAM_ONBOARDING_ENCRYPTION_KEY",
		"UP_WECHAT_MINIPROGRAM_ONBOARDING_ENCRYPTION_KEY_ID",
		"UP_WECHAT_MINIPROGRAM_ONBOARDING_RETAINED_DECRYPTION_KEYS",
		"UP_RISK_CAPTCHA_REGION", "UP_RISK_TURNSTILE_SITE_KEY",
		"UP_RISK_TURNSTILE_SECRET_KEY", "UP_RISK_TURNSTILE_HOSTNAME",
		"UP_RISK_RECAPTCHA_SITE_KEY", "UP_RISK_RECAPTCHA_SECRET_KEY",
		"UP_RISK_RECAPTCHA_HOSTNAME", "UP_RISK_RECAPTCHA_MIN_SCORE",
	)

	cfg, err := Load()
	if err != nil {
		t.Fatalf("Load returned error: %v", err)
	}
	if cfg.HTTPAddr != ":8080" {
		t.Errorf("HTTPAddr = %q, want %q", cfg.HTTPAddr, ":8080")
	}
	if cfg.ReadHeaderTimeout != 5*time.Second {
		t.Errorf("ReadHeaderTimeout = %v, want 5s", cfg.ReadHeaderTimeout)
	}
	if cfg.MaxRequestBodyBytes != 1<<20 {
		t.Errorf("MaxRequestBodyBytes = %d, want %d", cfg.MaxRequestBodyBytes, 1<<20)
	}
	if cfg.LogLevel != "info" {
		t.Errorf("LogLevel = %q, want %q", cfg.LogLevel, "info")
	}
	if cfg.DreamUPAdmin.Enabled {
		t.Fatal("DreamUP administration must default off")
	}
	if cfg.Registration.Enabled {
		t.Fatal("public registration must default off")
	}
	if cfg.Registration.CreateIPLimit != 3 || cfg.Registration.CreateIPWindow != time.Hour || cfg.Registration.CreateMailboxFamilyLimit != 3 || cfg.Registration.CreateMailboxFamilyWindow != 24*time.Hour || cfg.RateLimit.LoginLimit != 10 {
		t.Fatalf("registration/login limits drifted: registration=%#v login=%#v", cfg.Registration, cfg.RateLimit)
	}
	if cfg.Registration.FormIntentDeviceLimit != 6 || cfg.Registration.FormIntentNetLimit != 20 || cfg.Registration.FormIntentBurstLimit != 30 || cfg.Registration.FormIntentGlobalLimit != 300 ||
		cfg.Registration.GlobalBurstLimit != 20 || cfg.Registration.GlobalLimit != 200 || cfg.Registration.GlobalWindow != time.Hour || cfg.Registration.DomainBurstLimit != 3 || cfg.Registration.DomainLimit != 10 ||
		cfg.Registration.AdmissionInFlight != 8 || cfg.Registration.AdmissionWait != 3*time.Second || cfg.Registration.UnfamiliarInFlight != 2 || cfg.Registration.UnfamiliarPerDomain != 2 || cfg.Registration.HoneypotIPBlocksEnabled {
		t.Fatalf("registration cohort/admission defaults drifted: %#v", cfg.Registration)
	}
	if len(cfg.ClientIP.TrustedProxyCIDRs) != 2 {
		t.Fatalf("trusted proxy defaults = %#v", cfg.ClientIP.TrustedProxyCIDRs)
	}
	if cfg.DreamUPAdmin.AdminOrigin != "https://moonstone.org.cn" {
		t.Fatalf("DreamUP administration browser origin = %q", cfg.DreamUPAdmin.AdminOrigin)
	}
	if cfg.DreamUPMobile.ScopedRateLimit != 60 || cfg.DreamUPMobile.GlobalRateLimit != 2000 || cfg.DreamUPMobile.RateWindow != time.Minute {
		t.Fatalf("DreamUP Mobile rate defaults drifted: %#v", cfg.DreamUPMobile)
	}
	if cfg.HasIsolatedDatabase() {
		t.Fatal("isolated operational database must default off")
	}
	if cfg.RiskDefense.Captcha.Region != "mainland_china" || cfg.RiskDefense.Captcha.Turnstile.Configured() || cfg.RiskDefense.Captcha.Recaptcha.Configured() {
		t.Fatalf("risk captcha defaults = %#v", cfg.RiskDefense.Captcha)
	}
}

func TestIsolatedOperationalDatabaseMustUseADistinctTarget(t *testing.T) {
	cfg := validDevelopmentConfig()
	cfg.Database = DatabaseConfig{
		URL: "postgres://user:pass@localhost:5432/united_pass?sslmode=disable", Schema: "united_pass",
		MaxConns: 10, MinConns: 1, ConnectTimeout: 10 * time.Second,
	}
	cfg.IsolatedDatabase = cfg.Database
	if err := cfg.Validate(); err == nil || !strings.Contains(err.Error(), "distinct") {
		t.Fatalf("authority database accepted as isolated target: %v", err)
	}
	cfg.IsolatedDatabase.Schema = "dreamup_isolated"
	if err := cfg.Validate(); err == nil || !strings.Contains(err.Error(), "distinct") {
		t.Fatalf("authority database with a separate schema accepted as isolated target: %v", err)
	}
	cfg.IsolatedDatabase.URL = "postgres://isolated:pass@localhost:5432/dreamup_ops?sslmode=disable"
	if err := cfg.Validate(); err != nil {
		t.Fatalf("separate operational database rejected: %v", err)
	}
}

func TestIsolatedOperationalDatabaseRejectsEquivalentURLSpellings(t *testing.T) {
	cfg := validDevelopmentConfig()
	cfg.Database = DatabaseConfig{
		URL: "postgres://authority:one@localhost:5432/united_pass?sslmode=disable", Schema: "united_pass",
		MaxConns: 10, MinConns: 1, ConnectTimeout: 10 * time.Second,
	}
	cfg.IsolatedDatabase = DatabaseConfig{
		URL: "postgresql://isolated:two@LOCALHOST/united_pass?sslmode=require", Schema: "united_pass",
		MaxConns: 4, MinConns: 0, ConnectTimeout: 5 * time.Second,
	}
	if err := cfg.Validate(); err == nil || !strings.Contains(err.Error(), "distinct") {
		t.Fatalf("equivalent authority target spelling accepted: %v", err)
	}
}

func TestLoadIsolatedOperationalDatabaseConfiguration(t *testing.T) {
	t.Setenv("UP_ISOLATED_DATABASE_URL", "postgres://isolated:pass@localhost:5544/dreamup_ops?sslmode=disable")
	t.Setenv("UP_ISOLATED_DATABASE_SCHEMA", "dreamup_ops")
	cfg, err := Load()
	if err != nil {
		t.Fatal(err)
	}
	if !cfg.HasIsolatedDatabase() || cfg.IsolatedDatabase.Schema != "dreamup_ops" {
		t.Fatalf("isolated database config=%#v", cfg.IsolatedDatabase)
	}
}

func TestDreamUPMobileEnabledRejectsUnsafeRateLimits(t *testing.T) {
	cfg := validDevelopmentConfig()
	cfg.DreamUPMobile = DreamUPMobileConfig{
		Enabled: true, DelegationKeyringPath: `C:\secrets\dreamup-mobile.json`, DelegationCurrentKeyID: "mobile-1",
		DelegationIssuer: "https://auth.moonstone.org.cn", DelegationAudience: "dreamup-mobile-api", AssertionTTL: 15 * time.Second,
		ScopedRateLimit: 60, GlobalRateLimit: 59, RateWindow: time.Minute,
	}
	cfg.Database.URL = "postgres://user:pass@localhost:5432/united_pass?sslmode=disable"
	cfg.Redis.URL = "redis://localhost:6379/0"
	cfg.Auth.Provider = "zitadel"
	cfg.Auth.ProjectID = "project-id"
	if err := cfg.Validate(); err == nil || !strings.Contains(err.Error(), "assertion rate limits") {
		t.Fatalf("unsafe DreamUP Mobile rate limits accepted: %v", err)
	}
}

func TestDreamUPMobileAndAdministratorDelegationKeysMustBeDistinct(t *testing.T) {
	cfg := validDevelopmentConfig()
	cfg.Database = DatabaseConfig{
		URL: "postgres://user:pass@localhost:5432/united_pass?sslmode=disable", Schema: "united_pass",
		MaxConns: 10, MinConns: 1, ConnectTimeout: 10 * time.Second,
	}
	cfg.Redis = RedisConfig{
		URL: "redis://localhost:6379/0", KeyPrefix: "up:test:", PoolSize: 10,
		ConnectTimeout: 10 * time.Second, ReadTimeout: 3 * time.Second, WriteTimeout: 3 * time.Second,
	}
	cfg.Auth.Provider = "zitadel"
	cfg.Auth.ProjectID = "project-id"
	cfg.DreamUPMobile = DreamUPMobileConfig{
		Enabled: true, DelegationKeyringPath: `C:\secrets\dreamup-mobile.json`, DelegationCurrentKeyID: "mobile-1",
		DelegationIssuer: "https://auth.moonstone.org.cn", DelegationAudience: "dreamup-mobile-api", AssertionTTL: 15 * time.Second,
		ScopedRateLimit: 60, GlobalRateLimit: 2000, RateWindow: time.Minute,
	}
	cfg.DreamUPAdmin = validDreamUPAdminConfigForTest()

	cfg.DreamUPMobile.DelegationKeyringPath = cfg.DreamUPAdmin.DelegationKeyringPath
	if err := cfg.Validate(); err == nil || !strings.Contains(err.Error(), "must use distinct keyrings") {
		t.Fatalf("shared delegation keyring path accepted: %v", err)
	}

	cfg.DreamUPMobile.DelegationKeyringPath = `C:\secrets\dreamup-mobile.json`
	cfg.DreamUPMobile.DelegationCurrentKeyID = cfg.DreamUPAdmin.DelegationCurrentKeyID
	if err := cfg.Validate(); err == nil || !strings.Contains(err.Error(), "current key IDs must be distinct") {
		t.Fatalf("shared delegation current key ID accepted: %v", err)
	}

	cfg.DreamUPMobile.DelegationCurrentKeyID = "mobile-1"
	if err := cfg.Validate(); err != nil {
		t.Fatalf("distinct mobile/admin delegation key material rejected: %v", err)
	}
}

func TestLoadPublicRegistrationConfiguration(t *testing.T) {
	t.Setenv("UP_ENVIRONMENT", "development")
	t.Setenv("UP_PUBLIC_REGISTRATION_ENABLED", "true")
	t.Setenv("UP_DATABASE_URL", "postgres://user:pass@localhost:5432/united_pass?sslmode=disable")
	t.Setenv("UP_REDIS_URL", "redis://localhost:6379/0")
	t.Setenv("UP_AUTH_PROVIDER", "zitadel")
	t.Setenv("UP_AUTH_PROVIDER_BASE_URL", "http://localhost:8080")
	t.Setenv("UP_AUTH_PROVIDER_PROJECT_ID", "project-id")
	t.Setenv("UP_AUTH_PROVIDER_ORGANIZATION_ID", "organization-id")
	t.Setenv("UP_AUTH_PROVIDER_SERVICE_ACCOUNT_KEY_FILE", "key.json")
	t.Setenv("UP_OAUTH_PUBLIC_ORIGIN", "http://localhost:3000")

	cfg, err := Load()
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	if !cfg.Registration.Enabled || cfg.Auth.OrganizationID != "organization-id" {
		t.Fatalf("registration/auth config = %#v %#v", cfg.Registration, cfg.Auth)
	}
}

func TestRegistrationLimitsAreIndependentFromLogin(t *testing.T) {
	t.Setenv("UP_ENVIRONMENT", "development")
	t.Setenv("UP_LOGIN_RATE_LIMIT", "19")
	t.Setenv("UP_REGISTRATION_CREATE_IP_LIMIT", "2")
	t.Setenv("UP_REGISTRATION_CREATE_IP_WINDOW", "45m")

	cfg, err := Load()
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	if cfg.RateLimit.LoginLimit != 19 || cfg.Registration.CreateIPLimit != 2 || cfg.Registration.CreateIPWindow != 45*time.Minute {
		t.Fatalf("login/registration limits not independent: login=%#v registration=%#v", cfg.RateLimit, cfg.Registration)
	}
}

func TestRegistrationCohortPolicyLoadsOperationalDomainLists(t *testing.T) {
	t.Setenv("UP_REGISTRATION_GLOBAL_LIMIT", "77")
	t.Setenv("UP_REGISTRATION_BLOCKED_EMAIL_DOMAINS_EXTRA", "one.example,two.example")
	t.Setenv("UP_REGISTRATION_BLOCKED_MX_DOMAINS_EXTRA", "mx.bad.example")
	t.Setenv("UP_REGISTRATION_ESTABLISHED_EMAIL_DOMAINS_EXTRA", "school.example")
	t.Setenv("UP_REGISTRATION_HONEYPOT_IP_BLOCKS_ENABLED", "true")
	cfg, err := Load()
	if err != nil {
		t.Fatal(err)
	}
	if cfg.Registration.GlobalLimit != 77 || len(cfg.Registration.BlockedEmailDomains) != 2 || len(cfg.Registration.BlockedMXDomains) != 1 || len(cfg.Registration.EstablishedEmailDomains) != 1 || !cfg.Registration.HoneypotIPBlocksEnabled {
		t.Fatalf("registration cohort config = %#v", cfg.Registration)
	}
}

func TestRiskDefenseConfigurationUsesOnlyHashedAllowlistEntries(t *testing.T) {
	t.Setenv("UP_RISK_DEFENSE_ENABLED", "true")
	t.Setenv("UP_RISK_ALLOWLIST_SHA256", "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa")
	cfg, err := Load()
	if err != nil {
		t.Fatal(err)
	}
	if !cfg.RiskDefense.Enabled || len(cfg.RiskDefense.AllowlistedHashes) != 1 || cfg.RiskDefense.LoginMediumAfter >= cfg.RiskDefense.LoginHighAfter {
		t.Fatalf("risk config=%#v", cfg.RiskDefense)
	}

	cfg.RiskDefense.AllowlistedHashes = []string{"alice@example.com"}
	if err := cfg.Validate(); err == nil || !strings.Contains(err.Error(), "SHA-256") {
		t.Fatalf("plain-text allowlist validation err=%v", err)
	}
}

func TestRiskCaptchaProvidersRequireCompleteServerOnlyConfiguration(t *testing.T) {
	t.Setenv("UP_RISK_DEFENSE_ENABLED", "true")
	t.Setenv("UP_RISK_CAPTCHA_REGION", "global")
	t.Setenv("UP_RISK_TURNSTILE_SITE_KEY", "turnstile-site")
	t.Setenv("UP_RISK_TURNSTILE_SECRET_KEY", "turnstile-secret")
	t.Setenv("UP_RISK_TURNSTILE_HOSTNAME", "auth.moonstone.org.cn")
	t.Setenv("UP_RISK_RECAPTCHA_SITE_KEY", "recaptcha-site")
	t.Setenv("UP_RISK_RECAPTCHA_SECRET_KEY", "recaptcha-secret")
	t.Setenv("UP_RISK_RECAPTCHA_HOSTNAME", "auth.moonstone.org.cn")
	t.Setenv("UP_RISK_RECAPTCHA_MIN_SCORE", "0.75")

	cfg, err := Load()
	if err != nil {
		t.Fatal(err)
	}
	if !cfg.RiskDefense.Captcha.Turnstile.Configured() || !cfg.RiskDefense.Captcha.Recaptcha.Configured() || cfg.RiskDefense.Captcha.Recaptcha.MinScore != 0.75 {
		t.Fatalf("risk captcha config=%#v", cfg.RiskDefense.Captcha)
	}

	cfg.RiskDefense.Captcha.Turnstile.SecretKey = ""
	if err := cfg.Validate(); err == nil || !strings.Contains(err.Error(), "Turnstile requires") {
		t.Fatalf("partial Turnstile config accepted: %v", err)
	}
	cfg.RiskDefense.Captcha.Turnstile.SecretKey = "turnstile-secret"
	cfg.RiskDefense.Captcha.Recaptcha.Hostname = "https://auth.moonstone.org.cn/path"
	if err := cfg.Validate(); err == nil || !strings.Contains(err.Error(), "reCAPTCHA") {
		t.Fatalf("invalid reCAPTCHA hostname accepted: %v", err)
	}
}

func TestRiskCaptchaRejectsUnknownRegionAndInvalidScore(t *testing.T) {
	cfg := validDevelopmentConfig()
	cfg.RiskDefense.Enabled = true
	cfg.RiskDefense.ObservationWindow = 15 * time.Minute
	cfg.RiskDefense.LoginMediumAfter = 3
	cfg.RiskDefense.LoginHighAfter = 7
	cfg.RiskDefense.RegistrationMediumAfter = 2
	cfg.RiskDefense.RegistrationHighAfter = 3
	cfg.RiskDefense.ChallengeTTL = 5 * time.Minute
	cfg.RiskDefense.DeviceIDTTL = 24 * time.Hour
	cfg.RiskDefense.TrustTTL = 15 * time.Minute
	cfg.RiskDefense.AutomationCostDifficulty = 18
	cfg.RiskDefense.CompletionLimit = 8
	cfg.RiskDefense.CompletionWindow = 15 * time.Minute
	cfg.RiskDefense.Captcha.Region = "client_selected"
	cfg.RiskDefense.Captcha.Recaptcha = RiskRecaptchaConfig{
		SiteKey: "site", SecretKey: "secret", Hostname: "auth.moonstone.org.cn", MinScore: 1.1,
	}
	if err := cfg.Validate(); err == nil || !strings.Contains(err.Error(), "captcha region") || !strings.Contains(err.Error(), "minimum score") {
		t.Fatalf("invalid captcha policy accepted: %v", err)
	}
	cfg.RiskDefense.Captcha.Region = "mainland_china"
	cfg.RiskDefense.Captcha.Recaptcha.MinScore = math.NaN()
	if err := cfg.Validate(); err == nil || !strings.Contains(err.Error(), "minimum score") {
		t.Fatalf("NaN captcha score accepted: %v", err)
	}
}

func TestRegistrationRejectsUnsafeGatewayAndRateConfiguration(t *testing.T) {
	cfg := validDevelopmentConfig()
	cfg.Registration.Enabled = true
	cfg.ClientIP.TrustedProxyCIDRs = nil
	if err := cfg.Validate(); err == nil || !strings.Contains(err.Error(), "trusted gateway") {
		t.Fatalf("registration accepted no trusted gateway: %v", err)
	}

	cfg = validDevelopmentConfig()
	cfg.ClientIP.TrustedProxyCIDRs = []string{"0.0.0.0/0"}
	if err := cfg.Validate(); err == nil || !strings.Contains(err.Error(), "over-broad") {
		t.Fatalf("over-broad trusted proxy accepted: %v", err)
	}

	cfg = validDevelopmentConfig()
	cfg.Registration.CreateIPLimit = 0
	if err := cfg.Validate(); err == nil || !strings.Contains(err.Error(), "registration create IP") {
		t.Fatalf("invalid registration rate accepted: %v", err)
	}

	cfg = validDevelopmentConfig()
	cfg.Registration.AdmissionInFlight = 1
	cfg.Registration.UnfamiliarInFlight = 2
	if err := cfg.Validate(); err == nil || !strings.Contains(err.Error(), "admission") {
		t.Fatalf("invalid registration admission accepted: %v", err)
	}
}

func TestRegistrationRejectsAdmissionCapacityOverflow(t *testing.T) {
	maxInt := int(^uint(0) >> 1)
	for _, test := range []struct {
		name   string
		mutate func(*RegistrationConfig)
	}{
		{name: "in flight", mutate: func(cfg *RegistrationConfig) { cfg.AdmissionInFlight = maxInt }},
		{name: "queued", mutate: func(cfg *RegistrationConfig) { cfg.AdmissionQueued = maxInt }},
		{name: "combined slots", mutate: func(cfg *RegistrationConfig) {
			cfg.AdmissionInFlight = maxRegistrationAdmissionInFlight
			cfg.AdmissionQueued = maxRegistrationAdmissionTotalSlots
		}},
		{name: "unfamiliar combined slots", mutate: func(cfg *RegistrationConfig) {
			cfg.UnfamiliarQueued = maxRegistrationAdmissionTotalSlots
		}},
	} {
		t.Run(test.name, func(t *testing.T) {
			cfg := validDevelopmentConfig()
			test.mutate(&cfg.Registration)
			if err := cfg.Validate(); err == nil || !strings.Contains(err.Error(), "admission") {
				t.Fatalf("oversized registration admission accepted: %v", err)
			}
		})
	}
}

func TestPublicRegistrationFailsClosedWithoutOrganizationID(t *testing.T) {
	cfg := validDevelopmentConfig()
	cfg.Registration.Enabled = true
	cfg.Database = DatabaseConfig{
		URL: "postgres://user:pass@localhost:5432/united_pass?sslmode=disable", Schema: "united_pass",
		MaxConns: 10, MinConns: 1, ConnectTimeout: 10 * time.Second,
	}
	cfg.Redis = RedisConfig{
		URL: "redis://localhost:6379/0", KeyPrefix: "up:test:", PoolSize: 10,
		ConnectTimeout: 10 * time.Second, ReadTimeout: 3 * time.Second, WriteTimeout: 3 * time.Second,
	}
	cfg.Auth.Provider = "zitadel"
	cfg.Auth.BaseURL = "http://localhost:8080"
	cfg.Auth.ProjectID = "project-id"
	cfg.Auth.ServiceAccountKeyFile = "key.json"
	cfg.OAuth.PublicOrigin = "http://localhost:3000"

	if err := cfg.Validate(); err == nil || !strings.Contains(err.Error(), "UP_AUTH_PROVIDER_ORGANIZATION_ID") {
		t.Fatalf("missing organization ID error = %v", err)
	}
	cfg.Auth.OrganizationID = "organization-id"
	if err := cfg.Validate(); err != nil {
		t.Fatalf("complete registration config rejected: %v", err)
	}
}

func TestWeChatRegistrationRequiresIsolatedOperationalDatabase(t *testing.T) {
	cfg := validDevelopmentConfig()
	cfg.IsolatedDatabase = DatabaseConfig{}
	cfg.WeChatMiniProgram = WeChatMiniProgramConfig{
		Enabled: true, RegistrationEnabled: true, AppID: "mini-app", AppSecret: "server-secret", RequestTimeout: 8 * time.Second,
	}
	cfg.Database = DatabaseConfig{
		URL: "postgres://user:pass@localhost:5432/united_pass?sslmode=disable", Schema: "united_pass",
		MaxConns: 10, MinConns: 1, ConnectTimeout: 10 * time.Second,
	}
	cfg.Redis = RedisConfig{
		URL: "redis://localhost:6379/0", KeyPrefix: "up:test:", PoolSize: 10,
		ConnectTimeout: 10 * time.Second, ReadTimeout: 3 * time.Second, WriteTimeout: 3 * time.Second,
	}
	cfg.Auth = AuthProviderConfig{
		Provider: "zitadel", BaseURL: "http://localhost:8080", ProjectID: "project-id", OrganizationID: "organization-id", ServiceAccountKeyFile: "key.json",
	}
	cfg.OAuth.PublicOrigin = "http://localhost:3000"
	if err := cfg.Validate(); err == nil || !strings.Contains(err.Error(), "UP_ISOLATED_DATABASE_URL") {
		t.Fatalf("WeChat registration accepted authority-database retry verifier: %v", err)
	}
}

func TestWeChatOnboardingHasIndependentDefaultOffGate(t *testing.T) {
	cfg := validDevelopmentConfig()
	cfg.WeChatMiniProgram.OnboardingEnabled = true
	if err := cfg.Validate(); err == nil || !strings.Contains(err.Error(), "UP_WECHAT_MINIPROGRAM_ENABLED and UP_WECHAT_MINIPROGRAM_REGISTRATION_ENABLED") {
		t.Fatalf("onboarding accepted without parent gates: %v", err)
	}

	cfg.WeChatMiniProgram.Enabled = true
	cfg.WeChatMiniProgram.AppID = "mini-app"
	cfg.WeChatMiniProgram.AppSecret = "server-secret"
	cfg.WeChatMiniProgram.RequestTimeout = 8 * time.Second
	if err := cfg.Validate(); err == nil || !strings.Contains(err.Error(), "UP_WECHAT_MINIPROGRAM_REGISTRATION_ENABLED") {
		t.Fatalf("onboarding accepted without registration gate: %v", err)
	}
}

func TestLoadReadsDedicatedWeChatOnboardingEncryptionMaterial(t *testing.T) {
	key := configTestAESKey(0x42)
	retained := `{"wechat-onboarding-v0":"` + configTestAESKey(0x41) + `"}`
	t.Setenv("UP_ENVIRONMENT", "development")
	t.Setenv("UP_WECHAT_MINIPROGRAM_ENABLED", "false")
	t.Setenv("UP_WECHAT_MINIPROGRAM_REGISTRATION_ENABLED", "false")
	t.Setenv("UP_WECHAT_MINIPROGRAM_ONBOARDING_ENABLED", "false")
	t.Setenv("UP_WECHAT_MINIPROGRAM_ONBOARDING_ENCRYPTION_KEY", key)
	t.Setenv("UP_WECHAT_MINIPROGRAM_ONBOARDING_ENCRYPTION_KEY_ID", "wechat-onboarding-v1")
	t.Setenv("UP_WECHAT_MINIPROGRAM_ONBOARDING_RETAINED_DECRYPTION_KEYS", retained)

	cfg, err := Load()
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	if cfg.WeChatMiniProgram.OnboardingEncryptionKey != key || cfg.WeChatMiniProgram.OnboardingEncryptionKeyID != "wechat-onboarding-v1" {
		t.Fatalf("dedicated onboarding material was not loaded: %#v", cfg.WeChatMiniProgram)
	}
	if cfg.WeChatMiniProgram.OnboardingRetainedDecryptionKeys != retained {
		t.Fatal("retained onboarding decryption keyring was not loaded")
	}
}

func TestWeChatOnboardingRequiresDedicatedEncryptionMaterial(t *testing.T) {
	base := validWeChatOnboardingConfigForEncryptionTest()
	tests := []struct {
		name    string
		mutate  func(*Config)
		wantErr string
	}{
		{name: "missing key", mutate: func(cfg *Config) {
			cfg.WeChatMiniProgram.OnboardingEncryptionKey = ""
		}, wantErr: "UP_WECHAT_MINIPROGRAM_ONBOARDING_ENCRYPTION_KEY"},
		{name: "missing key id", mutate: func(cfg *Config) {
			cfg.WeChatMiniProgram.OnboardingEncryptionKeyID = ""
		}, wantErr: "UP_WECHAT_MINIPROGRAM_ONBOARDING_ENCRYPTION_KEY_ID"},
		{name: "malformed base64", mutate: func(cfg *Config) {
			cfg.WeChatMiniProgram.OnboardingEncryptionKey = "not-base64"
		}, wantErr: "must be base64-encoded"},
		{name: "wrong key length", mutate: func(cfg *Config) {
			cfg.WeChatMiniProgram.OnboardingEncryptionKey = base64.StdEncoding.EncodeToString(bytes.Repeat([]byte{1}, 16))
		}, wantErr: "must decode to 32 bytes"},
		{name: "unsafe key id", mutate: func(cfg *Config) {
			cfg.WeChatMiniProgram.OnboardingEncryptionKeyID = "wechat:v1"
		}, wantErr: "must not contain ':'"},
		{name: "session key reuse", mutate: func(cfg *Config) {
			cfg.Session.EncryptionKey = cfg.WeChatMiniProgram.OnboardingEncryptionKey
			cfg.Session.EncryptionKeyID = "session-v1"
		}, wantErr: "must be distinct from UP_SESSION_ENCRYPTION_KEY"},
		{name: "session key reuse with alternate base64 whitespace", mutate: func(cfg *Config) {
			key := cfg.WeChatMiniProgram.OnboardingEncryptionKey
			cfg.Session.EncryptionKey = key[:8] + "\n" + key[8:]
			cfg.Session.EncryptionKeyID = "session-v1"
		}, wantErr: "must be distinct from UP_SESSION_ENCRYPTION_KEY"},
		{name: "retained malformed JSON", mutate: func(cfg *Config) {
			cfg.WeChatMiniProgram.OnboardingRetainedDecryptionKeys = `{`
		}, wantErr: "RETAINED_DECRYPTION_KEYS"},
		{name: "retained repeats current id", mutate: func(cfg *Config) {
			cfg.WeChatMiniProgram.OnboardingRetainedDecryptionKeys = `{"wechat-onboarding-v1":"` + configTestAESKey(0x43) + `"}`
		}, wantErr: "must not repeat the current key ID"},
		{name: "retained repeats current material", mutate: func(cfg *Config) {
			cfg.WeChatMiniProgram.OnboardingRetainedDecryptionKeys = `{"wechat-onboarding-v0":"` + cfg.WeChatMiniProgram.OnboardingEncryptionKey + `"}`
		}, wantErr: "material must be unique"},
		{name: "retained reuses session material", mutate: func(cfg *Config) {
			cfg.Session.EncryptionKey = configTestAESKey(0x44)
			cfg.Session.EncryptionKeyID = "session-v1"
			cfg.WeChatMiniProgram.OnboardingRetainedDecryptionKeys = `{"wechat-onboarding-v0":"` + cfg.Session.EncryptionKey + `"}`
		}, wantErr: "distinct from UP_SESSION_ENCRYPTION_KEY"},
		{name: "missing security notification SMTP", mutate: func(cfg *Config) {
			cfg.Email = EmailConfig{}
		}, wantErr: "requires UP_SMTP_HOST"},
		{name: "invalid security notification SMTP port", mutate: func(cfg *Config) {
			cfg.Email.SMTPPort = 70000
		}, wantErr: "requires UP_SMTP_HOST"},
		{name: "invalid security notification sender", mutate: func(cfg *Config) {
			cfg.Email.FromAddress = "not-an-email"
		}, wantErr: "requires UP_SMTP_HOST"},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			cfg := base
			test.mutate(&cfg)
			err := cfg.Validate()
			if err == nil || !strings.Contains(err.Error(), test.wantErr) {
				t.Fatalf("Validate error = %v, want %q", err, test.wantErr)
			}
		})
	}
	if err := base.Validate(); err != nil {
		t.Fatalf("distinct dedicated onboarding key rejected: %v", err)
	}
}

func validWeChatOnboardingConfigForEncryptionTest() Config {
	cfg := validDevelopmentConfig()
	cfg.Database = DatabaseConfig{
		URL: "postgres://user:pass@localhost:5432/united_pass?sslmode=disable", Schema: "united_pass",
		MaxConns: 10, MinConns: 1, ConnectTimeout: 10 * time.Second,
	}
	cfg.Redis = RedisConfig{
		URL: "redis://localhost:6379/0", KeyPrefix: "up:test:", PoolSize: 10,
		ConnectTimeout: 10 * time.Second, ReadTimeout: 3 * time.Second, WriteTimeout: 3 * time.Second,
	}
	cfg.Auth = AuthProviderConfig{
		Provider: "zitadel", BaseURL: "http://localhost:8080", ProjectID: "project-id",
		OrganizationID: "organization-id", ServiceAccountKeyFile: "key.json",
	}
	cfg.OAuth.PublicOrigin = "http://localhost:3000"
	cfg.WeChatMiniProgram = WeChatMiniProgramConfig{
		Enabled: true, RegistrationEnabled: true, OnboardingEnabled: true,
		OnboardingEncryptionKey: configTestAESKey(0x42), OnboardingEncryptionKeyID: "wechat-onboarding-v1",
		AppID: "mini-app", AppSecret: "server-secret", RequestTimeout: 8 * time.Second,
	}
	cfg.Email = EmailConfig{SMTPHost: "smtp.example.test", SMTPPort: 465, FromAddress: "security@example.test"}
	return cfg
}

func TestParseWeChatOnboardingRetainedDecryptionKeys(t *testing.T) {
	valid := `{"onboarding-v1":"` + configTestAESKey(0x31) + `","onboarding-v0":"` + configTestAESKey(0x30) + `"}`
	keys, err := ParseWeChatOnboardingRetainedDecryptionKeys(valid)
	if err != nil || len(keys) != 2 || keys["onboarding-v1"] == "" {
		t.Fatalf("valid retained keyring = %#v, %v", keys, err)
	}
	for _, raw := range []string{
		`null`, `[]`, `{"unsafe:id":"` + configTestAESKey(0x31) + `"}`,
		`{"duplicate":"` + configTestAESKey(0x31) + `","duplicate":"` + configTestAESKey(0x30) + `"}`,
		`{"short":"c2hvcnQ="}`, `{} trailing`,
	} {
		if _, err := ParseWeChatOnboardingRetainedDecryptionKeys(raw); err == nil {
			t.Fatalf("accepted invalid retained keyring %q", raw)
		}
	}
	keys, err = ParseWeChatOnboardingRetainedDecryptionKeys("")
	if err != nil || len(keys) != 0 {
		t.Fatalf("empty retained keyring = %#v, %v", keys, err)
	}
}

func configTestAESKey(fill byte) string {
	return base64.StdEncoding.EncodeToString(bytes.Repeat([]byte{fill}, 32))
}

func TestDreamUPAdminDisabledDoesNotRequireOrReadKeyrings(t *testing.T) {
	t.Setenv("UP_ENVIRONMENT", "development")
	t.Setenv("UP_DREAMUP_ADMIN_ENABLED", "false")
	for _, key := range []string{
		"UP_ADMIN_CHALLENGE_ENCRYPTION_KEYRING_PATH", "UP_ADMIN_CHALLENGE_PEPPER_KEYRING_PATH",
		"UP_PROTECTED_REASON_KEYRING_PATH", "UP_ADMIN_CHALLENGE_RATE_LIMIT_KEYRING_PATH",
		"UP_ADMIN_OPERATION_FINGERPRINT_KEYRING_PATH",
	} {
		t.Setenv(key, `Z:\definitely-unreadable\secret.json`)
	}
	cfg, err := Load()
	if err != nil {
		t.Fatalf("disabled Load touched or required keyrings: %v", err)
	}
	if cfg.DreamUPAdmin.Enabled {
		t.Fatal("disabled flag ignored")
	}
}

func TestDreamUPAdminEnabledRequiresEveryPurposeSpecificKeyring(t *testing.T) {
	cfg := validDevelopmentConfig()
	cfg.DreamUPAdmin = DreamUPAdminConfig{Enabled: true}
	if err := cfg.Validate(); err == nil {
		t.Fatal("enabled config accepted missing keyrings")
	}
	cfg.DreamUPAdmin = DreamUPAdminConfig{
		Enabled:                        true,
		ChallengeEncryptionKeyringPath: "challenge-encryption.json", ChallengeEncryptionCurrentKeyID: "ce-1",
		ChallengePepperKeyringPath: "challenge-pepper.json", ChallengePepperCurrentKeyID: "cp-1",
		ProtectedReasonKeyringPath: "protected-reason.json", ProtectedReasonCurrentKeyID: "pr-1",
		RateLimitKeyringPath: "rate-limit.json", RateLimitCurrentKeyID: "rl-1",
		OperationFingerprintKeyringPath: "operation-fingerprint.json", OperationFingerprintCurrentKeyID: "of-1",
		FreshLoginMaxAge: 5 * time.Minute, GeneralFreshness: 30 * time.Minute,
		HighRiskFreshness: 5 * time.Minute, RateLimit: 5, RateWindow: 15 * time.Minute,
		LockDuration: 30 * time.Minute, Argon2MaxConcurrent: 2,
		BaseURL: "http://127.0.0.1:18084", DelegationIssuer: "https://auth.moonstone.org.cn",
		DelegationAudience: "dreamup-admin-api", DelegationKeyringPath: `C:\secrets\dreamup-delegation.json`,
		DelegationCurrentKeyID: "delegation-1", AdminOrigin: "https://auth.moonstone.org.cn",
		ResponseLimitBytes: 8 << 20, ReconcileInterval: 15 * time.Second,
		ReconcileBatchSize: 50, ReconcileLease: 30 * time.Second,
		DelegationServiceSubject: "united-pass:dreamup-reconciler", DelegationServiceVersion: 1,
	}
	if err := cfg.Validate(); err != nil {
		t.Fatalf("complete enabled config: %v", err)
	}
	cfg.DreamUPAdmin.OperationFingerprintKeyringPath = cfg.DreamUPAdmin.ChallengePepperKeyringPath
	cfg.DreamUPAdmin.OperationFingerprintCurrentKeyID = cfg.DreamUPAdmin.ChallengePepperCurrentKeyID
	if err := cfg.Validate(); err == nil {
		t.Fatal("purpose-reused keyring accepted")
	}
}

func TestDreamUPAdminRequiresIsolatedOperationalDatabase(t *testing.T) {
	cfg := validDevelopmentConfig()
	cfg.DreamUPAdmin = validDreamUPAdminConfigForTest()
	cfg.IsolatedDatabase = DatabaseConfig{}
	if err := cfg.Validate(); err == nil || !strings.Contains(err.Error(), "UP_ISOLATED_DATABASE_URL") {
		t.Fatalf("DreamUP admin accepted authority-database outbox: %v", err)
	}
}

func TestDreamUPAdminBFFConfigurationFailsClosed(t *testing.T) {
	cfg := validDevelopmentConfig()
	cfg.DreamUPAdmin = DreamUPAdminConfig{
		Enabled:                        true,
		ChallengeEncryptionKeyringPath: "challenge-encryption.json", ChallengeEncryptionCurrentKeyID: "ce-1",
		ChallengePepperKeyringPath: "challenge-pepper.json", ChallengePepperCurrentKeyID: "cp-1",
		ProtectedReasonKeyringPath: "protected-reason.json", ProtectedReasonCurrentKeyID: "pr-1",
		RateLimitKeyringPath: "rate-limit.json", RateLimitCurrentKeyID: "rl-1",
		OperationFingerprintKeyringPath: "operation-fingerprint.json", OperationFingerprintCurrentKeyID: "of-1",
		FreshLoginMaxAge: 5 * time.Minute, GeneralFreshness: 30 * time.Minute,
		HighRiskFreshness: 5 * time.Minute, RateLimit: 5, RateWindow: 15 * time.Minute,
		LockDuration: 30 * time.Minute, Argon2MaxConcurrent: 2,
	}
	if err := cfg.Validate(); err == nil || !strings.Contains(err.Error(), "BFF") {
		t.Fatalf("missing BFF config error=%v", err)
	}

	cfg.DreamUPAdmin.BaseURL = "http://127.0.0.1:18084"
	cfg.DreamUPAdmin.DelegationIssuer = "https://auth.moonstone.org.cn"
	cfg.DreamUPAdmin.DelegationAudience = "dreamup-admin-api"
	cfg.DreamUPAdmin.DelegationKeyringPath = `C:\secrets\dreamup-delegation.json`
	cfg.DreamUPAdmin.DelegationCurrentKeyID = "delegation-1"
	cfg.DreamUPAdmin.AdminOrigin = "https://auth.moonstone.org.cn"
	cfg.DreamUPAdmin.ResponseLimitBytes = 8 << 20
	cfg.DreamUPAdmin.ReconcileInterval = 15 * time.Second
	cfg.DreamUPAdmin.ReconcileBatchSize = 50
	cfg.DreamUPAdmin.ReconcileLease = 30 * time.Second
	cfg.DreamUPAdmin.DelegationServiceSubject = "united-pass:dreamup-reconciler"
	cfg.DreamUPAdmin.DelegationServiceVersion = 1
	if err := cfg.Validate(); err != nil {
		t.Fatalf("complete BFF config: %v", err)
	}

	cfg.Environment = EnvironmentProduction
	cfg.DreamUPAdmin.BaseURL = "http://dreamup.example.invalid"
	if err := cfg.Validate(); err == nil || !strings.Contains(err.Error(), "loopback") {
		t.Fatalf("production cleartext non-loopback base accepted: %v", err)
	}
}

func TestLoadParsesOverrides(t *testing.T) {
	t.Setenv("UP_ENVIRONMENT", "development")
	t.Setenv("UP_HTTP_ADDR", ":9090")
	t.Setenv("UP_READ_TIMEOUT", "45s")
	t.Setenv("UP_MAX_REQUEST_BODY_BYTES", "2097152")
	t.Setenv("UP_LOG_LEVEL", "debug")
	t.Setenv("UP_OAUTH_PUBLIC_ORIGIN", "http://localhost:3000")

	cfg, err := Load()
	if err != nil {
		t.Fatalf("Load returned error: %v", err)
	}
	if cfg.HTTPAddr != ":9090" {
		t.Errorf("HTTPAddr = %q, want %q", cfg.HTTPAddr, ":9090")
	}
	if cfg.ReadTimeout != 45*time.Second {
		t.Errorf("ReadTimeout = %v, want 45s", cfg.ReadTimeout)
	}
	if cfg.MaxRequestBodyBytes != 2097152 {
		t.Errorf("MaxRequestBodyBytes = %d, want 2097152", cfg.MaxRequestBodyBytes)
	}
	if cfg.LogLevel != "debug" {
		t.Errorf("LogLevel = %q, want %q", cfg.LogLevel, "debug")
	}
	if cfg.OAuth.PublicOrigin != "http://localhost:3000" {
		t.Errorf("OAuth.PublicOrigin = %q", cfg.OAuth.PublicOrigin)
	}
	if cfg.OAuth.InteractionBaseURI() != "http://localhost:3000/_interaction" {
		t.Errorf("InteractionBaseURI = %q", cfg.OAuth.InteractionBaseURI())
	}
}

func TestValidateRejectsInvalidEnvironment(t *testing.T) {
	cfg := Config{
		Environment:         "staging",
		HTTPAddr:            ":8080",
		ReadHeaderTimeout:   5 * time.Second,
		ReadTimeout:         15 * time.Second,
		WriteTimeout:        30 * time.Second,
		IdleTimeout:         60 * time.Second,
		ShutdownTimeout:     30 * time.Second,
		MaxRequestBodyBytes: 1 << 20,
		LogLevel:            "info",
	}
	if err := cfg.Validate(); err == nil {
		t.Fatal("Validate should reject invalid environment")
	}
}

func TestValidateRejectsNonPositiveTimeouts(t *testing.T) {
	cfg := validDevelopmentConfig()
	cfg.ReadTimeout = 0
	if err := cfg.Validate(); err == nil {
		t.Fatal("Validate should reject zero read timeout")
	}
}

func TestValidateRejectsInvalidLogLevel(t *testing.T) {
	cfg := validDevelopmentConfig()
	cfg.LogLevel = "verbose"
	if err := cfg.Validate(); err == nil {
		t.Fatal("Validate should reject invalid log level")
	}
}

func TestValidateProductionConstraints(t *testing.T) {
	cfg := validDevelopmentConfig()
	cfg.Environment = EnvironmentProduction

	cfg.ShutdownTimeout = 120 * time.Second
	if err := cfg.Validate(); err == nil {
		t.Fatal("Validate should reject production shutdown timeout > 60s")
	}

	cfg.ShutdownTimeout = 30 * time.Second
	cfg.MaxRequestBodyBytes = 32 * (1 << 20)
	if err := cfg.Validate(); err == nil {
		t.Fatal("Validate should reject production max body > 16 MiB")
	}

	cfg.MaxRequestBodyBytes = 1 << 20
	// Production requires database, Redis, auth provider, and secure cookies.
	cfg.Database = DatabaseConfig{
		URL:            "postgres://user:pass@host:5432/db?sslmode=require",
		Schema:         "united_pass",
		MaxConns:       10,
		MinConns:       1,
		ConnectTimeout: 10 * time.Second,
	}
	cfg.Redis = RedisConfig{
		URL:            "rediss://:pass@host:6379/0",
		KeyPrefix:      "up:production:",
		PoolSize:       10,
		ConnectTimeout: 10 * time.Second,
		ReadTimeout:    3 * time.Second,
		WriteTimeout:   3 * time.Second,
	}
	cfg.Session.CookieSecure = true
	cfg.Session.EncryptionKey = "MDEyMzQ1Njc4OWFiY2RlZjAxMjM0NTY3ODlhYmNkZWY=" // 32 bytes
	cfg.Session.EncryptionKeyID = "production-v1"
	cfg.Auth.Provider = "zitadel"
	cfg.Auth.BaseURL = "https://auth.example.com"
	cfg.Auth.ServiceAccountKeyFile = "/secrets/zitadel/key.json"
	cfg.OAuth.PublicOrigin = "https://id.example.com"
	cfg.Cerbos = CerbosConfig{
		PDPURL: "https://cerbos-pdp.example.com", AdminURL: "https://cerbos-admin.example.com",
		AdminUsername: "united-pass", AdminPassword: "test-password",
		RequestTimeout: 3 * time.Second, ReconcileInterval: 30 * time.Second,
	}
	if err := cfg.Validate(); err != nil {
		t.Fatalf("Validate should accept valid production config: %v", err)
	}

	// Production requires the public OAuth origin: issuer and interaction
	// base URI are derived from it.
	cfg.OAuth.PublicOrigin = ""
	if err := cfg.Validate(); err == nil {
		t.Fatal("Validate should reject production without UP_OAUTH_PUBLIC_ORIGIN")
	}
	cfg.OAuth.PublicOrigin = "https://id.example.com"

	// Production must reject permission dev override.
	cfg.Permission.DevOverrideEnabled = true
	if err := cfg.Validate(); err == nil {
		t.Fatal("Validate should reject production permission dev override")
	}
}

func TestLogLevelValue(t *testing.T) {
	cfg := validDevelopmentConfig()
	cfg.LogLevel = "warn"
	level, err := cfg.LogLevelValue()
	if err != nil {
		t.Fatalf("LogLevelValue returned error: %v", err)
	}
	// slog.LevelWarn is a negative value; compare via string to avoid coupling.
	if level.String() != "WARN" {
		t.Errorf("LogLevelValue = %q, want WARN", level.String())
	}
}

func TestValidSchemaIdentifier(t *testing.T) {
	valid := []string{
		"united_pass",
		"united_pass_test",
		"a",
		"_private",
		"schema_with_123_digits",
	}
	for _, s := range valid {
		if !ValidSchemaIdentifier(s) {
			t.Errorf("ValidSchemaIdentifier(%q) = false, want true", s)
		}
	}

	invalid := []string{
		"",
		"UPPER",
		"with-dash",
		"with space",
		"1starts_with_digit",
		"a; DROP TABLE users",
		"x." + strings.Repeat("a", 63), // over 63 chars
		"schema\"quote",
	}
	for _, s := range invalid {
		if ValidSchemaIdentifier(s) {
			t.Errorf("ValidSchemaIdentifier(%q) = true, want false", s)
		}
	}
}

func TestValidateRejectsInvalidDatabaseSchema(t *testing.T) {
	cfg := validDevelopmentConfig()
	cfg.Database = DatabaseConfig{
		URL:            "postgres://user:pass@host:5432/db?sslmode=disable",
		Schema:         "bad-schema; DROP TABLE users",
		MaxConns:       5,
		MinConns:       1,
		ConnectTimeout: 10 * time.Second,
	}
	if err := cfg.Validate(); err == nil {
		t.Fatal("Validate should reject invalid database schema identifier")
	}
}

func TestValidateRejectsInvalidEncryptionKey(t *testing.T) {
	cases := []struct {
		name  string
		key   string
		keyID string
	}{
		{name: "not base64", key: "!!!not-base64!!!", keyID: "v1"},
		{name: "wrong length", key: "c2hvcnQ=", keyID: "v1"}, // 4 bytes
		{name: "key id with colon", key: "MDEyMzQ1Njc4OWFiY2RlZjAxMjM0NTY3ODlhYmNkZWY=", keyID: "bad:id"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			cfg := validDevelopmentConfig()
			cfg.Session.EncryptionKey = tc.key
			cfg.Session.EncryptionKeyID = tc.keyID
			if err := cfg.Validate(); err == nil {
				t.Fatal("Validate should reject invalid session encryption key")
			}
		})
	}
}

func TestValidateAcceptsValidEncryptionKey(t *testing.T) {
	cfg := validDevelopmentConfig()
	cfg.Session.EncryptionKey = "MDEyMzQ1Njc4OWFiY2RlZjAxMjM0NTY3ODlhYmNkZWY=" // 32 bytes
	cfg.Session.EncryptionKeyID = "development-v1"
	if err := cfg.Validate(); err != nil {
		t.Fatalf("Validate should accept a valid session encryption key: %v", err)
	}
}

func TestValidateRejectsPartialFeishuCredentials(t *testing.T) {
	cfg := validDevelopmentConfig()
	cfg.Feishu.AppID = "cli_test"
	if err := cfg.Validate(); err == nil {
		t.Fatal("Validate should reject a partial Feishu credential set")
	}
}

func TestValidateCerbosConfiguration(t *testing.T) {
	t.Run("partial set", func(t *testing.T) {
		cfg := validDevelopmentConfig()
		cfg.Cerbos.PDPURL = "http://127.0.0.1:3592"
		if err := cfg.Validate(); err == nil {
			t.Fatal("partial Cerbos configuration must be rejected")
		}
	})
	t.Run("default admin credentials", func(t *testing.T) {
		cfg := validDevelopmentConfig()
		cfg.Cerbos = CerbosConfig{PDPURL: "http://127.0.0.1:3592", AdminURL: "http://127.0.0.1:3592", AdminUsername: "cerbos", AdminPassword: "cerbosAdmin", RequestTimeout: 3 * time.Second, ReconcileInterval: 30 * time.Second}
		if err := cfg.Validate(); err == nil {
			t.Fatal("default Cerbos Admin API credentials must be rejected")
		}
	})
	t.Run("complete development set", func(t *testing.T) {
		cfg := validDevelopmentConfig()
		cfg.Cerbos = CerbosConfig{PDPURL: "http://127.0.0.1:3592", AdminURL: "http://127.0.0.1:3592", AdminUsername: "united-pass", AdminPassword: "private", RequestTimeout: 3 * time.Second, ReconcileInterval: 30 * time.Second}
		if err := cfg.Validate(); err != nil {
			t.Fatalf("complete Cerbos configuration rejected: %v", err)
		}
	})
}

func TestValidateAcceptsCompleteFeishuConfiguration(t *testing.T) {
	cfg := validDevelopmentConfig()
	cfg.Feishu = FeishuConfig{
		BaseURL:           "https://open.feishu.cn",
		AuthorizeURL:      "https://accounts.feishu.cn/open-apis/authen/v1/authorize",
		AppID:             "cli_test",
		AppSecret:         "secret_test",
		TenantID:          "tenant_test",
		RedirectURL:       "http://localhost:3000/api/v1/auth/providers/feishu/callback",
		ContactScope:      "contact:user.base:readonly",
		OAuthStateTTL:     5 * time.Minute,
		RequestTimeout:    10 * time.Second,
		ReconcileInterval: 15 * time.Second,
		SyncTimeout:       2 * time.Minute,
	}
	if err := cfg.Validate(); err != nil {
		t.Fatalf("Validate should accept complete Feishu configuration: %v", err)
	}
	if !cfg.Feishu.Configured() {
		t.Fatal("complete Feishu configuration should report Configured")
	}
}

func TestValidateRejectsWrongFeishuCallbackPath(t *testing.T) {
	cfg := validDevelopmentConfig()
	cfg.Feishu = FeishuConfig{
		BaseURL:           "https://open.feishu.cn",
		AuthorizeURL:      "https://accounts.feishu.cn/open-apis/authen/v1/authorize",
		AppID:             "cli_test",
		AppSecret:         "secret_test",
		TenantID:          "tenant_test",
		RedirectURL:       "http://localhost:3000/auth/callback",
		ContactScope:      "contact:user.base:readonly",
		OAuthStateTTL:     5 * time.Minute,
		RequestTimeout:    10 * time.Second,
		ReconcileInterval: 15 * time.Second,
		SyncTimeout:       2 * time.Minute,
	}
	if err := cfg.Validate(); err == nil {
		t.Fatal("Validate should reject a drifting Feishu callback path")
	}
}

// TestValidateRejectsInsecureProductionAuthURL verifies that production
// rejects any ZITADEL base URL that is not a bare HTTPS URL.
func TestValidateRejectsInsecureProductionAuthURL(t *testing.T) {
	base := validDevelopmentConfig()
	base.Environment = EnvironmentProduction
	base.Database = DatabaseConfig{
		URL:            "postgres://user:pass@host:5432/db?sslmode=require",
		Schema:         "united_pass",
		MaxConns:       10,
		MinConns:       1,
		ConnectTimeout: 10 * time.Second,
	}
	base.Redis = RedisConfig{
		URL:            "rediss://:pass@host:6379/0",
		KeyPrefix:      "up:production:",
		PoolSize:       10,
		ConnectTimeout: 10 * time.Second,
		ReadTimeout:    3 * time.Second,
		WriteTimeout:   3 * time.Second,
	}
	base.Session.CookieSecure = true
	base.Session.EncryptionKey = "MDEyMzQ1Njc4OWFiY2RlZjAxMjM0NTY3ODlhYmNkZWY="
	base.Session.EncryptionKeyID = "production-v1"
	base.Auth.Provider = "zitadel"
	base.Auth.ServiceAccountKeyFile = "/secrets/zitadel/key.json"
	base.OAuth.PublicOrigin = "https://id.example.com"

	cases := []struct {
		name string
		url  string
	}{
		{name: "http scheme", url: "http://auth.example.com"},
		{name: "userinfo", url: "https://user:pass@auth.example.com"},
		{name: "query", url: "https://auth.example.com?debug=1"},
		{name: "fragment", url: "https://auth.example.com#frag"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			cfg := base
			cfg.Auth.BaseURL = tc.url
			if err := cfg.Validate(); err == nil {
				t.Fatalf("Validate should reject %q in production", tc.url)
			}
		})
	}
}

// TestValidateOAuthPublicOriginSyntax verifies the strict origin grammar:
// scheme + host (+ port) only — never a base URL with path, userinfo, query
// or fragment (ADR-0005 §1).
func TestValidateOAuthPublicOriginSyntax(t *testing.T) {
	valid := []string{
		"https://id.example.com",
		"https://id.example.com:8443",
		"http://localhost:3000",
		"http://127.0.0.1:3000",
		"https://id.example.com/", // trailing slash tolerated, normalized away
	}
	for _, origin := range valid {
		cfg := validDevelopmentConfig()
		cfg.OAuth.PublicOrigin = origin
		if err := cfg.Validate(); err != nil {
			t.Errorf("Validate should accept %q: %v", origin, err)
		}
	}

	invalid := []struct {
		name   string
		origin string
	}{
		{name: "path", origin: "https://id.example.com/foo"},
		{name: "nested path", origin: "https://id.example.com/foo/bar"},
		{name: "userinfo", origin: "https://user:pass@id.example.com"},
		{name: "query", origin: "https://id.example.com?q=x"},
		{name: "fragment", origin: "https://id.example.com/#x"},
		{name: "missing host", origin: "https://"},
		{name: "wrong scheme", origin: "ftp://id.example.com"},
		{name: "no scheme", origin: "id.example.com"},
		{name: "whitespace", origin: " https://id.example.com"},
	}
	for _, tc := range invalid {
		t.Run(tc.name, func(t *testing.T) {
			cfg := validDevelopmentConfig()
			cfg.OAuth.PublicOrigin = tc.origin
			if err := cfg.Validate(); err == nil {
				t.Fatalf("Validate should reject %q", tc.origin)
			}
		})
	}
}

// TestValidateOAuthPublicOriginProductionHTTPS verifies production rejects a
// plaintext public origin.
func TestValidateOAuthPublicOriginProductionHTTPS(t *testing.T) {
	base := validDevelopmentConfig()
	base.Environment = EnvironmentProduction
	base.Database = DatabaseConfig{
		URL:            "postgres://user:pass@host:5432/db?sslmode=require",
		Schema:         "united_pass",
		MaxConns:       10,
		MinConns:       1,
		ConnectTimeout: 10 * time.Second,
	}
	base.Redis = RedisConfig{
		URL:            "rediss://:pass@host:6379/0",
		KeyPrefix:      "up:production:",
		PoolSize:       10,
		ConnectTimeout: 10 * time.Second,
		ReadTimeout:    3 * time.Second,
		WriteTimeout:   3 * time.Second,
	}
	base.Session.CookieSecure = true
	base.Session.EncryptionKey = "MDEyMzQ1Njc4OWFiY2RlZjAxMjM0NTY3ODlhYmNkZWY="
	base.Session.EncryptionKeyID = "production-v1"
	base.Auth.Provider = "zitadel"
	base.Auth.BaseURL = "https://auth.example.com"
	base.Auth.ServiceAccountKeyFile = "/secrets/zitadel/key.json"
	base.Cerbos = CerbosConfig{
		PDPURL: "https://cerbos-pdp.example.com", AdminURL: "https://cerbos-admin.example.com",
		AdminUsername: "united-pass", AdminPassword: "test-password",
		RequestTimeout: 3 * time.Second, ReconcileInterval: 30 * time.Second,
	}

	cfg := base
	cfg.OAuth.PublicOrigin = "http://id.example.com"
	if err := cfg.Validate(); err == nil {
		t.Fatal("Validate should reject http public origin in production")
	}
	cfg.OAuth.PublicOrigin = "https://id.example.com"
	if err := cfg.Validate(); err != nil {
		t.Fatalf("Validate should accept https public origin in production: %v", err)
	}
}

// TestInteractionBaseURIDerivation verifies the single derivation rule:
// InteractionBaseURI = PublicOrigin + "/_interaction", never independently
// configured (ADR-0005 §1).
func TestInteractionBaseURIDerivation(t *testing.T) {
	cases := []struct {
		origin string
		want   string
	}{
		{"", ""},
		{"https://id.example.com", "https://id.example.com/_interaction"},
		{"https://id.example.com/", "https://id.example.com/_interaction"},
		{"http://localhost:3000", "http://localhost:3000/_interaction"},
	}
	for _, tc := range cases {
		got := OAuthConfig{PublicOrigin: tc.origin}.InteractionBaseURI()
		if got != tc.want {
			t.Errorf("InteractionBaseURI(%q) = %q, want %q", tc.origin, got, tc.want)
		}
	}
}

func validDevelopmentConfig() Config {
	return Config{
		Environment:         EnvironmentDevelopment,
		HTTPAddr:            ":8080",
		ReadHeaderTimeout:   5 * time.Second,
		ReadTimeout:         15 * time.Second,
		WriteTimeout:        30 * time.Second,
		IdleTimeout:         60 * time.Second,
		ShutdownTimeout:     30 * time.Second,
		MaxRequestBodyBytes: 1 << 20,
		LogLevel:            "info",
		IsolatedDatabase: DatabaseConfig{
			URL: "postgres://isolated:pass@localhost:5544/dreamup_ops?sslmode=disable", Schema: "dreamup_isolated",
			MaxConns: 10, MinConns: 1, ConnectTimeout: 10 * time.Second,
		},

		Session: SessionConfig{
			TTL:            12 * time.Hour,
			RememberTTL:    720 * time.Hour,
			IdleTTL:        2 * time.Hour,
			TouchInterval:  5 * time.Minute,
			CookieSecure:   false,
			CookieSameSite: "lax",
		},

		MFA: MFAConfig{
			ChallengeTTL: 5 * time.Minute,
			MaxAttempts:  5,
		},

		RateLimit: RateLimitConfig{
			LoginLimit:  10,
			LoginWindow: 15 * time.Minute,
			MFALimit:    10,
			MFAWindow:   15 * time.Minute,
		},
		ClientIP: TrustedClientIPConfig{
			TrustedProxyCIDRs: []string{"127.0.0.1/32", "::1/128"},
		},
		Registration: RegistrationConfig{
			FormIntentDeviceLimit: 6, FormIntentDeviceWindow: 5 * time.Minute,
			FormIntentNetLimit: 20, FormIntentNetWindow: 5 * time.Minute,
			FormIntentBurstLimit: 30, FormIntentBurstWindow: 10 * time.Second,
			FormIntentGlobalLimit: 300, FormIntentGlobalWindow: 5 * time.Minute,
			CreateIPLimit: 3, CreateIPWindow: time.Hour,
			CreateNetLimit: 10, CreateNetWindow: time.Hour,
			CreateEmailLimit: 3, CreateEmailWindow: 24 * time.Hour,
			CreateMailboxFamilyLimit: 3, CreateMailboxFamilyWindow: 24 * time.Hour,
			CreatePairLimit: 2, CreatePairWindow: time.Hour,
			GlobalBurstLimit: 20, GlobalBurstWindow: 10 * time.Second,
			GlobalLimit: 200, GlobalWindow: time.Hour,
			DomainBurstLimit: 3, DomainBurstWindow: 10 * time.Minute,
			DomainLimit: 10, DomainWindow: 24 * time.Hour,
			MXBurstLimit: 20, MXBurstWindow: 10 * time.Minute,
			MXLimit: 100, MXWindow: 24 * time.Hour,
			AdmissionInFlight: 8, AdmissionQueued: 32, AdmissionWait: time.Second,
			UnfamiliarInFlight: 2, UnfamiliarQueued: 8, UnfamiliarPerDomain: 1,
			VerifyLimit: 8, VerifyWindow: 15 * time.Minute,
			VerifyGlobalBurstLimit: 20, VerifyGlobalBurstWindow: 10 * time.Second,
			VerifyGlobalLimit: 100, VerifyGlobalWindow: 5 * time.Minute,
			ResendLimit: 3, ResendWindow: 30 * time.Minute,
			IPv4NetBits: 24, IPv6NetBits: 56,
		},

		Reauth: ReauthConfig{
			ChallengeTTL:    5 * time.Minute,
			GrantTTL:        5 * time.Minute,
			MaxAttempts:     5,
			RateLimit:       10,
			RateWindow:      15 * time.Minute,
			CleanupInterval: 60 * time.Second,
		},

		Rotation: RotationConfig{
			RateLimit:  3,
			RateWindow: 15 * time.Minute,
		},

		SecurityState: SecurityStateConfig{
			ProviderDeadline:      10 * time.Second,
			LeaseTTL:              60 * time.Second,
			SettlementTimeout:     15 * time.Second,
			RecoveryTimeout:       15 * time.Second,
			MaxSettlementAttempts: 3,
		},
	}
}

func validDreamUPAdminConfigForTest() DreamUPAdminConfig {
	return DreamUPAdminConfig{
		Enabled:                        true,
		ChallengeEncryptionKeyringPath: "challenge-encryption.json", ChallengeEncryptionCurrentKeyID: "ce-1",
		ChallengePepperKeyringPath: "challenge-pepper.json", ChallengePepperCurrentKeyID: "cp-1",
		ProtectedReasonKeyringPath: "protected-reason.json", ProtectedReasonCurrentKeyID: "pr-1",
		RateLimitKeyringPath: "rate-limit.json", RateLimitCurrentKeyID: "rl-1",
		OperationFingerprintKeyringPath: "operation-fingerprint.json", OperationFingerprintCurrentKeyID: "of-1",
		FreshLoginMaxAge: 5 * time.Minute, GeneralFreshness: 30 * time.Minute,
		HighRiskFreshness: 5 * time.Minute, RateLimit: 5, RateWindow: 15 * time.Minute,
		LockDuration: 30 * time.Minute, Argon2MaxConcurrent: 2,
		BaseURL: "http://127.0.0.1:18084", DelegationIssuer: "https://auth.moonstone.org.cn",
		DelegationAudience: "dreamup-admin-api", DelegationKeyringPath: `C:\secrets\dreamup-admin.json`,
		DelegationCurrentKeyID: "administrator-1", AdminOrigin: "https://auth.moonstone.org.cn",
		ResponseLimitBytes: 8 << 20, ReconcileInterval: 15 * time.Second,
		ReconcileBatchSize: 50, ReconcileLease: 30 * time.Second,
		DelegationServiceSubject: "united-pass:dreamup-reconciler", DelegationServiceVersion: 1,
	}
}

func clearEnv(t *testing.T, keys ...string) {
	t.Helper()
	for _, key := range keys {
		t.Setenv(key, "")
	}
}
