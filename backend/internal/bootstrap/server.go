//
// Copyright (c) 2026 Chen Jiajie(Ariakage)
//
// Author: Chen Jiajie(Ariakage) <ariakage233@gmail.com>
// Date: 2026-08-05
// Description: Server assembly: configuration wiring, dependency construction and route registration
//

// Package bootstrap assembles the HTTP server, router and middleware for the
// United Pass API service. It is the only place that imports chi; handlers and
// middleware stay compatible with standard net/http types.
package bootstrap

import (
	"bytes"
	"context"
	"encoding/base64"
	"errors"
	"fmt"
	"log/slog"
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/go-chi/chi/v5"
	zitadelsdk "github.com/zitadel/zitadel-go/v3/pkg/client"

	"github.com/GravelEvolution/united-pass/backend/internal/accountcontact"
	"github.com/GravelEvolution/united-pass/backend/internal/adapters/aliyunsms"
	"github.com/GravelEvolution/united-pass/backend/internal/adapters/cerbos"
	dreamupclient "github.com/GravelEvolution/united-pass/backend/internal/adapters/dreamupadmin"
	"github.com/GravelEvolution/united-pass/backend/internal/adapters/feishu"
	"github.com/GravelEvolution/united-pass/backend/internal/adapters/httpapi"
	"github.com/GravelEvolution/united-pass/backend/internal/adapters/httpapi/request"
	"github.com/GravelEvolution/united-pass/backend/internal/adapters/internalsms"
	"github.com/GravelEvolution/united-pass/backend/internal/adapters/postgres"
	"github.com/GravelEvolution/united-pass/backend/internal/adapters/redis"
	wechatadapter "github.com/GravelEvolution/united-pass/backend/internal/adapters/wechat"
	"github.com/GravelEvolution/united-pass/backend/internal/adapters/zitadel"
	"github.com/GravelEvolution/united-pass/backend/internal/adminpagination"
	"github.com/GravelEvolution/united-pass/backend/internal/adminroles"
	"github.com/GravelEvolution/united-pass/backend/internal/adminstepup"
	"github.com/GravelEvolution/united-pass/backend/internal/adminstore"
	"github.com/GravelEvolution/united-pass/backend/internal/applications"
	"github.com/GravelEvolution/united-pass/backend/internal/audit"
	"github.com/GravelEvolution/united-pass/backend/internal/auth"
	"github.com/GravelEvolution/united-pass/backend/internal/config"
	"github.com/GravelEvolution/united-pass/backend/internal/consent"
	app "github.com/GravelEvolution/united-pass/backend/internal/dreamupadmin"
	"github.com/GravelEvolution/united-pass/backend/internal/dreamupdelegation"
	"github.com/GravelEvolution/united-pass/backend/internal/email"
	"github.com/GravelEvolution/united-pass/backend/internal/identity"
	"github.com/GravelEvolution/united-pass/backend/internal/permissions"
	"github.com/GravelEvolution/united-pass/backend/internal/phoneverify"
	"github.com/GravelEvolution/united-pass/backend/internal/policies"
	"github.com/GravelEvolution/united-pass/backend/internal/privacy"
	"github.com/GravelEvolution/united-pass/backend/internal/providers"
	"github.com/GravelEvolution/united-pass/backend/internal/qrauth"
	"github.com/GravelEvolution/united-pass/backend/internal/registration"
	"github.com/GravelEvolution/united-pass/backend/internal/riskdefense"
	"github.com/GravelEvolution/united-pass/backend/internal/securitystate"
	"github.com/GravelEvolution/united-pass/backend/internal/session"
	wechatdomain "github.com/GravelEvolution/united-pass/backend/internal/wechat"
	"github.com/GravelEvolution/united-pass/backend/internal/wechatonboarding"
	"github.com/GravelEvolution/united-pass/backend/internal/wechatregistration"
	"github.com/GravelEvolution/united-pass/backend/internal/workforce"
)

// Server bundles the configured *http.Server with its router so the entry point
// can start it and shut it down.
type Server struct {
	HTTP           *http.Server
	Router         http.Handler
	logger         *slog.Logger
	config         config.Config
	pool           *postgres.Pool
	isolatedPool   *postgres.Pool
	redisClient    *redis.Client
	providerCloser interface{ Close() error }
	// dreamUPAuthorizer is wired for later BFF composition but intentionally
	// has no browser route in Task 2. The DreamUP administration switch and
	// handlers remain default-off until their dedicated task.
	dreamUPAuthorizer permissions.Authorizer
	// workerStops stops background workers (e.g. the abandoned reauth
	// challenge cleanup worker) before infrastructure is closed.
	workerStops []func()
}

type roleFingerprinterAdapter struct {
	base *adminstore.OperationFingerprinter
}

type stepUpFingerprinterAdapter struct {
	base *adminstore.OperationFingerprinter
}

func (a *stepUpFingerprinterAdapter) Fingerprint(purpose string, canonical []byte) (adminstepup.RequestFingerprint, error) {
	if a == nil || a.base == nil {
		return adminstepup.RequestFingerprint{}, errors.New("bootstrap: step-up fingerprinter unavailable")
	}
	fingerprint, err := a.base.Fingerprint(purpose, canonical)
	if err != nil {
		return adminstepup.RequestFingerprint{}, err
	}
	return adminstepup.RequestFingerprint{Version: fingerprint.Version, KeyID: fingerprint.KeyID, Digest: fingerprint.Digest}, nil
}

var _ adminstepup.Fingerprinter = (*stepUpFingerprinterAdapter)(nil)

type dreamUPAdminSecurityMaterial struct {
	challengeCipher *adminstepup.AESGCMCipher
	protectedCipher *adminstepup.AESGCMCipher
	pepperKeyring   *adminstepup.Keyring
	rateKeyring     *adminstepup.Keyring
	fingerprinter   *adminstore.OperationFingerprinter
}

// loadDreamUPAdminSecurityMaterial loads every purpose-specific keyring in a
// single, fail-closed boundary. Key bytes may never be reused between
// purposes, including retained rotation keys: purpose separation must remain
// true for reads as well as writes.
func loadDreamUPAdminSecurityMaterial(cfg config.Config) (*dreamUPAdminSecurityMaterial, error) {
	adminCfg := cfg.DreamUPAdmin
	type purposeKeyring struct {
		name      string
		path      string
		currentID string
	}
	specs := []purposeKeyring{
		{name: "challenge encryption", path: adminCfg.ChallengeEncryptionKeyringPath, currentID: adminCfg.ChallengeEncryptionCurrentKeyID},
		{name: "challenge pepper", path: adminCfg.ChallengePepperKeyringPath, currentID: adminCfg.ChallengePepperCurrentKeyID},
		{name: "protected reason", path: adminCfg.ProtectedReasonKeyringPath, currentID: adminCfg.ProtectedReasonCurrentKeyID},
		{name: "challenge rate limit", path: adminCfg.RateLimitKeyringPath, currentID: adminCfg.RateLimitCurrentKeyID},
		{name: "operation fingerprint", path: adminCfg.OperationFingerprintKeyringPath, currentID: adminCfg.OperationFingerprintCurrentKeyID},
	}

	rings := make(map[string]*adminstepup.Keyring, len(specs))
	type ownedKey struct {
		purpose string
		value   []byte
	}
	var allKeys []ownedKey
	if cfg.Session.EncryptionKey != "" {
		sessionKey, err := base64.StdEncoding.DecodeString(cfg.Session.EncryptionKey)
		if err != nil {
			return nil, errors.New("DreamUP admin cannot validate session key purpose separation")
		}
		allKeys = append(allKeys, ownedKey{purpose: "session encryption", value: sessionKey})
	}
	for _, spec := range specs {
		ring, err := adminstepup.LoadKeyring(spec.path, spec.currentID)
		if err != nil {
			return nil, fmt.Errorf("load %s keyring: %w", spec.name, err)
		}
		_, snapshot, err := ring.Snapshot()
		if err != nil {
			return nil, fmt.Errorf("snapshot %s keyring: %w", spec.name, err)
		}
		for _, key := range snapshot {
			for _, previous := range allKeys {
				if bytes.Equal(previous.value, key) && previous.purpose != spec.name {
					return nil, errors.New("DreamUP admin key material must be distinct for every cryptographic purpose")
				}
			}
			allKeys = append(allKeys, ownedKey{purpose: spec.name, value: append([]byte(nil), key...)})
		}
		rings[spec.name] = ring
	}

	challengeCipher, err := adminstepup.NewAESGCMCipher(rings["challenge encryption"])
	if err != nil {
		return nil, fmt.Errorf("challenge encryption keyring: %w", err)
	}
	protectedCipher, err := adminstepup.NewAESGCMCipher(rings["protected reason"])
	if err != nil {
		return nil, fmt.Errorf("protected reason keyring: %w", err)
	}
	activeID, operationKeys, err := rings["operation fingerprint"].Snapshot()
	if err != nil {
		return nil, fmt.Errorf("operation fingerprint keyring: %w", err)
	}
	fingerprinter, err := adminstore.NewOperationFingerprinter(adminstore.Keyring{ActiveKeyID: activeID, Keys: operationKeys})
	if err != nil {
		return nil, fmt.Errorf("operation fingerprint keyring: %w", err)
	}

	return &dreamUPAdminSecurityMaterial{
		challengeCipher: challengeCipher,
		protectedCipher: protectedCipher,
		pepperKeyring:   rings["challenge pepper"],
		rateKeyring:     rings["challenge rate limit"],
		fingerprinter:   fingerprinter,
	}, nil
}

var _ adminroles.Fingerprinter = (*roleFingerprinterAdapter)(nil)

func (a *roleFingerprinterAdapter) Fingerprint(purpose string, canonical []byte) (adminroles.RequestFingerprint, error) {
	if a == nil || a.base == nil {
		return adminroles.RequestFingerprint{}, errors.New("bootstrap: role fingerprinter unavailable")
	}
	fingerprint, err := a.base.Fingerprint(purpose, canonical)
	if err != nil {
		return adminroles.RequestFingerprint{}, err
	}
	return adminroles.RequestFingerprint{Version: fingerprint.Version, KeyID: fingerprint.KeyID, Digest: fingerprint.Digest}, nil
}

type cerbosReadinessChecker struct {
	client  interface{ Ready(context.Context) error }
	timeout time.Duration
}

func (c *cerbosReadinessChecker) Name() string { return "cerbos" }
func (c *cerbosReadinessChecker) Check(ctx context.Context) error {
	checkCtx, cancel := context.WithTimeout(ctx, c.timeout)
	defer cancel()
	return c.client.Ready(checkCtx)
}

// NewServer constructs the router, applies middleware, mounts routes and
// returns a Server wrapping a configured *http.Server. It creates
// infrastructure (PostgreSQL pool, Redis client) based on configuration and
// wires all Phase 1 handlers.
//
// NewServer returns an error when the configuration demands an authentication
// provider adapter that is not implemented (always the case in production),
// or when the configured session encryption key is unusable.
type registrationSurfacePlan struct {
	legacy            bool
	emailLifecycle    bool
	wechatMiniProgram bool
}

func configuredRegistrationSurfaces(cfg config.Config) registrationSurfacePlan {
	return registrationSurfacePlan{
		legacy:            cfg.Registration.Enabled,
		emailLifecycle:    cfg.Registration.Enabled || (cfg.WeChatMiniProgram.Enabled && cfg.WeChatMiniProgram.RegistrationEnabled),
		wechatMiniProgram: cfg.WeChatMiniProgram.Enabled && cfg.WeChatMiniProgram.RegistrationEnabled,
	}
}

func mountRegistrationSurfaces(router chi.Router, plan registrationSurfacePlan, legacy *httpapi.RegistrationHandlers, wechatMiniProgram *httpapi.WeChatRegistrationHandlers) {
	if plan.legacy && legacy != nil {
		legacy.MountCreate(router)
	}
	if plan.emailLifecycle && legacy != nil {
		legacy.MountEmailLifecycle(router)
	}
	if plan.wechatMiniProgram && wechatMiniProgram != nil {
		wechatMiniProgram.Mount(router)
	}
}

func newAliyunSMSClient(cfg config.AliyunSMSConfig) (*aliyunsms.Client, error) {
	return aliyunsms.NewClient(aliyunsms.Config{
		AccessKeyID:     cfg.AccessKeyID,
		AccessKeySecret: cfg.AccessKeySecret,
		SignName:        cfg.SignName,
		TemplateCode:    cfg.TemplateCode,
		Endpoint:        cfg.Endpoint,
	}, nil)
}

func NewServer(cfg config.Config, logger *slog.Logger) (*Server, error) {
	if cfg.WeChatMiniProgram.RegistrationEnabled && !cfg.WeChatMiniProgram.Enabled {
		return nil, errors.New("WeChat Mini Program registration requires the WeChat Mini Program surface")
	}
	if cfg.WeChatMiniProgram.OnboardingEnabled && (!cfg.WeChatMiniProgram.Enabled || !cfg.WeChatMiniProgram.RegistrationEnabled) {
		return nil, errors.New("WeChat Mini Program onboarding requires the login and registration surfaces")
	}
	var wechatOnboardingEncryptor session.Encryptor
	if cfg.WeChatMiniProgram.OnboardingEnabled {
		var err error
		wechatOnboardingEncryptor, err = newWeChatOnboardingEncryptor(cfg)
		if err != nil {
			return nil, fmt.Errorf("WeChat Mini Program onboarding encryption key: %w", err)
		}
		if !cfg.Email.SecurityNotificationsConfigured() {
			return nil, errors.New("WeChat Mini Program onboarding security notification transport is unavailable")
		}
	}
	router := chi.NewRouter()
	trustedClientIP, err := httpapi.TrustedClientIP(cfg.ClientIP.TrustedProxyCIDRs)
	if err != nil {
		return nil, fmt.Errorf("trusted client IP configuration: %w", err)
	}

	// The master gate is checked before any keyring open or service
	// construction. Disabled deployments keep the old graph byte-for-byte and
	// do not require the new secrets.
	var dreamUPAdminMaterial *dreamUPAdminSecurityMaterial
	var dreamUPDelegationKeyring *dreamupdelegation.Keyring
	var dreamUPMobileDelegationKeyring *dreamupdelegation.Keyring
	if cfg.DreamUPAdmin.Enabled {
		var err error
		dreamUPAdminMaterial, err = loadDreamUPAdminSecurityMaterial(cfg)
		if err != nil {
			return nil, fmt.Errorf("DreamUP admin security material: %w", err)
		}
		dreamUPDelegationKeyring, err = dreamupdelegation.LoadKeyring(cfg.DreamUPAdmin.DelegationKeyringPath)
		if err != nil {
			return nil, fmt.Errorf("DreamUP delegation keyring: %w", err)
		}
		if dreamUPDelegationKeyring.CurrentKeyID() != cfg.DreamUPAdmin.DelegationCurrentKeyID {
			return nil, errors.New("DreamUP delegation current key ID does not match keyring")
		}
	}
	if cfg.DreamUPMobile.Enabled {
		var err error
		dreamUPMobileDelegationKeyring, err = dreamupdelegation.LoadKeyring(cfg.DreamUPMobile.DelegationKeyringPath)
		if err != nil {
			return nil, fmt.Errorf("DreamUP Mobile delegation keyring: %w", err)
		}
		if dreamUPMobileDelegationKeyring.CurrentKeyID() != cfg.DreamUPMobile.DelegationCurrentKeyID {
			return nil, errors.New("DreamUP Mobile delegation current key ID does not match keyring")
		}
	}

	router.Use(httpapi.MaxBodyBytesByPath(cfg.MaxRequestBodyBytes, map[string]int64{
		"/api/v1/me/avatar": httpapi.AvatarRequestBodyLimit,
	}))
	router.Use(trustedClientIP)
	router.Use(httpapi.RequestID)
	router.Use(httpapi.SecurityHeaders)
	router.Use(httpapi.AccessLog(logger))
	router.Use(httpapi.Recovery(logger, cfg))

	// Infrastructure — created based on configuration. When database or Redis
	// URLs are absent (e.g. local dev without remote services), the server
	// starts but readiness checks will fail for those dependencies.
	var pool *postgres.Pool
	var isolatedPool *postgres.Pool
	isolatedPoolTransferred := false
	defer func() {
		if isolatedPool != nil && !isolatedPoolTransferred {
			isolatedPool.Close()
		}
	}()
	var redisClient *redis.Client
	var readinessCheckers []httpapi.ReadinessChecker

	if cfg.HasDatabase() {
		var err error
		pool, err = postgres.NewPool(context.Background(), cfg)
		if err != nil {
			logger.Error("failed to create postgres pool", "error", err)
		} else {
			readinessCheckers = append(readinessCheckers,
				NewPostgresReadinessChecker(pool, 3*time.Second))
		}
	}
	if cfg.HasIsolatedDatabase() {
		var err error
		isolatedPool, err = postgres.NewPoolFromConfig(context.Background(), cfg.IsolatedDatabase)
		if err != nil {
			return nil, fmt.Errorf("create isolated operational database pool: %w", err)
		}
		contractCtx, cancel := context.WithTimeout(context.Background(), cfg.IsolatedDatabase.ConnectTimeout)
		contractErr := postgres.ValidateIsolatedOperationalStore(contractCtx, isolatedPool.PgxPool())
		cancel()
		if contractErr != nil {
			return nil, fmt.Errorf("validate isolated operational database: %w", contractErr)
		}
		readinessCheckers = append(readinessCheckers,
			NewPostgresReadinessChecker(isolatedPool, 3*time.Second))
	}

	if cfg.HasRedis() {
		var err error
		redisClient, err = redis.NewClient(cfg.Redis)
		if err != nil {
			logger.Error("failed to create redis client", "error", err)
		} else {
			readinessCheckers = append(readinessCheckers,
				httpapi.NewRedisChecker(redisClient, 3*time.Second))
		}
	}

	// Session service. The encryption key is validated up front: an invalid
	// key must prevent startup (fail closed), not degrade to plaintext.
	encryptor, err := newSessionEncryptor(cfg)
	if err != nil {
		return nil, fmt.Errorf("session encryption key: %w", err)
	}

	var sessionSvc *session.Service
	var userChecker httpapi.UserStatusChecker
	var userReader httpapi.UserReader
	var userWriter httpapi.UserWriter
	var userLinker identity.UserLinker
	var permResolver permissions.Resolver
	var authenticator auth.Authenticator
	var sdkClient *zitadelsdk.Client
	var providerCloser interface{ Close() error }
	var mfaStore httpapi.MFAChallengeStore
	var rateChecker httpapi.RateChecker
	var sessionAuditor session.SecurityAuditor
	var workerStops []func()
	var cerbosClient *cerbos.Client
	var accountDeleter privacy.ProviderAccountDeleter
	var userRepo *postgres.UserRepository
	var registrationRateChecker httpapi.RegistrationRateChecker
	var wechatRegistrationRateChecker httpapi.WeChatRegistrationRateChecker
	var registrationBlockRateChecker httpapi.RegistrationBlockRateChecker
	var registrationBlockHandlers *httpapi.RegistrationBlockHandlers
	var accountContactRateChecker httpapi.AccountContactRateChecker
	var legacyContactRateChecker httpapi.ContactRateChecker
	var phoneChangeRateChecker httpapi.PhoneVerifyRateChecker
	var accountContactService httpapi.AccountContactService
	var wechatRateChecker httpapi.WeChatRateChecker
	var qrAuthRateChecker httpapi.QRAuthRateChecker
	var dreamUPMobileRateChecker httpapi.DreamUPMobileRateChecker
	var accountContactHandlers *httpapi.AccountContactHandlers
	var phoneVerifyHandlers *httpapi.PhoneVerifyHandlers
	var wechatHandlers *httpapi.WeChatHandlers
	var wechatOnboardingHandlers *httpapi.WeChatOnboardingHandlers
	var wechatOnboardingCleanup *redis.WeChatOnboardingCleanupWorker
	var wechatRegistrationHandlers *httpapi.WeChatRegistrationHandlers
	var qrAuthHandlers *httpapi.QRAuthHandlers
	var riskGuard *httpapi.RiskGuard
	var registrationProvider registration.Provider
	var registrationRepository *postgres.RegistrationRepository
	var wechatIntentCleanup *postgres.WeChatRegistrationIntentCleanupWorker
	var wechatNotificationWorker *postgres.WeChatNotificationWorker
	cookieAttrs := httpapi.CookieAttributesFromConfig(cfg.Session)
	registrationSurfaces := configuredRegistrationSurfaces(cfg)

	if pool != nil {
		userRepo = postgres.NewUserRepository(pool.PgxPool())
		userReader = userRepo
		userWriter = userRepo
		userChecker = &userStatusChecker{repo: userRepo}
		userLinker = userRepo
	}

	// Authenticator selection: the production safety boundary from Phase 1
	// hardening is preserved, and the ZITADEL adapter (Phase 1.2) is now
	// wired for the "zitadel" provider in all environments. It is built
	// before the session service so the session inventory can wire its
	// best-effort provider revocation seam (ADR-0006 §1).
	authenticator, sdkClient, providerCloser, err = buildAuthenticator(cfg, userLinker, logger)
	if err != nil {
		return nil, err
	}
	if sdkClient != nil {
		accountDeleter = zitadel.NewAccountDeleter(sdkClient.UserServiceV2())
	}

	// Security-state authority (ADR-0007): the PostgreSQL epoch + durable
	// mutation intent ledger behind the shared promotion validator, the
	// sensitive-consumption gate and the takeover/recovery trigger.
	// PostgreSQL is the single authority — Redis never decides. The dev
	// fake authenticator operates users that never exist in PostgreSQL, so
	// the gate stays unwired there and the promotion paths keep the
	// gate-less test semantics.
	var securitySvc *securitystate.Service
	var securityGate httpapi.SecurityStateGate
	var sensitiveGate httpapi.SensitiveConsumptionGate
	if _, isFake := authenticator.(*auth.FakeAuthenticator); !isFake && pool != nil {
		securitySvc = securitystate.NewService(
			postgres.NewSecurityStateStore(pool.PgxPool()), nil,
			cfg.SecurityState.LeaseTTL,
			securitystate.WithLogger(logger),
			securitystate.WithMaxSettlementAttempts(cfg.SecurityState.MaxSettlementAttempts),
			securitystate.WithRecoveryTimeout(cfg.SecurityState.RecoveryTimeout),
		)
		securityGate = securitySvc
		sensitiveGate = securitySvc
	}

	if redisClient != nil {
		sessionStore := redis.NewSessionStore(redisClient)
		sessionOpts := []session.ServiceOption{
			session.WithProviderRevoker(authenticator),
			session.WithLogger(logger),
		}
		if pool != nil {
			// Durable session security audit (ADR-0004 §8): session revocations
			// are persisted through the canonical security event store —
			// log-based audit alone is not a substitute.
			sessionAuditor = newSessionSecurityAuditor(postgres.NewSecurityEventStore(pool.PgxPool()))
			sessionOpts = append(sessionOpts, session.WithSecurityAuditor(sessionAuditor))
		}
		if securitySvc != nil {
			// Epoch stamping (ADR-0007 Decision 1/F2): every new session is
			// stamped with the user's authoritative epoch, fail closed.
			sessionOpts = append(sessionOpts, session.WithEpochStamper(securitySvc))
		}
		sessionSvc = session.NewService(sessionStore, session.SystemClock{},
			cfg.Session.TTL, cfg.Session.RememberTTL,
			cfg.Session.IdleTTL, cfg.Session.TouchInterval,
			encryptor,
			sessionOpts...)
		if securitySvc != nil {
			// Resolve the session <-> security-state construction cycle:
			// generation-scoped settlement cleanup runs through the session
			// service (ADR-0007 F4).
			securitySvc.SetCleaner(sessionSvc)
		}

		mfaStore = redis.NewMFAStore(redisClient)
		limiter := redis.NewRateLimiter(redisClient)
		rateChecker = limiter
		registrationRateChecker = limiter
		wechatRegistrationRateChecker = limiter
		registrationBlockRateChecker = limiter
		accountContactRateChecker = limiter
		legacyContactRateChecker = limiter
		phoneChangeRateChecker = limiter
		wechatRateChecker = limiter
		qrAuthRateChecker = limiter
		dreamUPMobileRateChecker = limiter
	}
	if cfg.RiskDefense.Enabled {
		if redisClient == nil {
			return nil, errors.New("risk defense requires Redis")
		}
		interactiveProvider, providerErr := newRiskCaptchaProvider(cfg.RiskDefense.Captcha)
		if providerErr != nil {
			return nil, fmt.Errorf("risk defense CAPTCHA: %w", providerErr)
		}
		riskService, riskErr := riskdefense.NewService(redis.NewRiskStore(redisClient), interactiveProvider, riskdefense.Config{
			Enabled:                  cfg.RiskDefense.Enabled,
			ObservationWindow:        cfg.RiskDefense.ObservationWindow,
			LoginMediumAfter:         cfg.RiskDefense.LoginMediumAfter,
			LoginHighAfter:           cfg.RiskDefense.LoginHighAfter,
			RegistrationMediumAfter:  cfg.RiskDefense.RegistrationMediumAfter,
			RegistrationHighAfter:    cfg.RiskDefense.RegistrationHighAfter,
			ChallengeTTL:             cfg.RiskDefense.ChallengeTTL,
			DeviceIDTTL:              cfg.RiskDefense.DeviceIDTTL,
			TrustTTL:                 cfg.RiskDefense.TrustTTL,
			AutomationCostDifficulty: uint8(cfg.RiskDefense.AutomationCostDifficulty),
			CompletionLimit:          cfg.RiskDefense.CompletionLimit,
			CompletionWindow:         cfg.RiskDefense.CompletionWindow,
			AllowlistedHashes:        cfg.RiskDefense.AllowlistedHashes,
		})
		if riskErr != nil {
			return nil, fmt.Errorf("risk defense: %w", riskErr)
		}
		riskGuard = httpapi.NewRiskGuard(
			riskService, sessionSvc, httpapi.CookieAttributesFromConfig(cfg.Session),
			cfg.RiskDefense.DeviceIDTTL, cfg.RiskDefense.TrustTTL,
		)
	}

	registrationRatePolicy := registration.RatePolicy{
		FormIntent: registration.Limit{Max: 20, Window: 5 * time.Minute},
		Create: registration.CreateRatePolicy{
			ClientIP:    registration.Limit{Max: cfg.Registration.CreateIPLimit, Window: cfg.Registration.CreateIPWindow},
			ClientNet:   registration.Limit{Max: cfg.Registration.CreateNetLimit, Window: cfg.Registration.CreateNetWindow},
			Email:       registration.Limit{Max: cfg.Registration.CreateEmailLimit, Window: cfg.Registration.CreateEmailWindow},
			ClientEmail: registration.Limit{Max: cfg.Registration.CreatePairLimit, Window: cfg.Registration.CreatePairWindow},
			IPv4NetBits: cfg.Registration.IPv4NetBits,
			IPv6NetBits: cfg.Registration.IPv6NetBits,
		},
		Verify: registration.Limit{Max: cfg.Registration.VerifyLimit, Window: cfg.Registration.VerifyWindow},
		Resend: registration.Limit{Max: cfg.Registration.ResendLimit, Window: cfg.Registration.ResendWindow},
	}
	emailDeliveryValidator := registration.NewDefaultEmailDeliveryValidator()
	var registrationHandlers *httpapi.RegistrationHandlers
	if registrationSurfaces.emailLifecycle {
		if pool == nil || redisClient == nil || sdkClient == nil || userRepo == nil || registrationRateChecker == nil {
			return nil, errors.New("registration dependencies are unavailable")
		}
		registrationProvider = zitadel.NewRegistrationProvider(sdkClient.UserServiceV2(), cfg.Auth.OrganizationID)
		if registrationSurfaces.wechatMiniProgram {
			if isolatedPool == nil {
				return nil, errors.New("WeChat Mini Program registration intent store is unavailable")
			}
			intentStore := postgres.NewWeChatRegistrationIntentStore(isolatedPool.PgxPool())
			registrationRepository = postgres.NewRegistrationRepositoryWithIntentStore(
				pool.PgxPool(), zitadel.ProviderName, cfg.Auth.ProjectID,
				intentStore,
			)
			wechatIntentCleanup = postgres.NewWeChatRegistrationIntentCleanupWorker(intentStore, pool.PgxPool(), 15*time.Minute, time.Hour, logger)
		} else {
			registrationRepository = postgres.NewRegistrationRepository(pool.PgxPool(), zitadel.ProviderName, cfg.Auth.ProjectID)
		}
		registrationService := registration.NewService(
			registrationProvider,
			registrationRepository,
			redis.NewRegistrationStore(redisClient),
			registration.Config{
				PublicOrigin:   cfg.OAuth.PublicOrigin,
				TokenTTL:       30 * time.Minute,
				EmailValidator: emailDeliveryValidator,
			},
		)
		formDefense, err := registration.NewFormDefense(
			redis.NewRegistrationFormDefenseStore(redisClient),
			newRegistrationAbuseAuditor(postgres.NewSecurityEventStore(pool.PgxPool())),
			registration.FormDefenseConfig{
				IntentTTL: 20 * time.Minute, MinimumFormAge: 2 * time.Second, MaxHoneypotSize: 12 << 10,
				Policy: registration.AbusePolicy{
					DeviceBlockTTL: 24 * time.Hour,
					IPStrikeWindow: time.Hour, IPBlockAfter: 3, IPBlockTTL: time.Hour,
					IPLongBlockAfter: 6, IPLongBlockTTL: 24 * time.Hour,
				},
			},
		)
		if err != nil {
			return nil, fmt.Errorf("registration form defense: %w", err)
		}
		registrationHandlers = httpapi.NewRegistrationHandlers(
			registrationService, registrationRateChecker, true, cfg.OAuth.PublicOrigin,
			registrationRatePolicy, logger, httpapi.WithRegistrationRiskGuard(riskGuard),
			httpapi.WithRegistrationFormDefense(formDefense),
		)
	}
	if pool != nil && redisClient != nil && sdkClient != nil && accountContactRateChecker != nil {
		accountContactService = accountcontact.NewService(
			zitadel.NewAccountContactProvider(sdkClient.UserServiceV2()),
			postgres.NewAccountContactRepository(pool.PgxPool(), zitadel.ProviderName, cfg.Auth.ProjectID),
			accountcontact.Config{
				PublicOrigin:   cfg.OAuth.PublicOrigin,
				EmailValidator: &accountContactEmailValidator{inner: emailDeliveryValidator},
			},
		)
	}
	if redisClient != nil && userRepo != nil && cfg.AliyunSMS.Enabled {
		phoneStore := redis.NewPhoneVerifyStore(redisClient)
		smsClient, err := newAliyunSMSClient(cfg.AliyunSMS)
		if err != nil {
			return nil, fmt.Errorf("build Aliyun SMS client: %w", err)
		}
		var internationalSMS phoneverify.Sender
		if cfg.InternalSMS.Enabled {
			internationalSMS = internalsms.NewClient(internalsms.Config{
				Endpoint: cfg.InternalSMS.Endpoint,
				APIKey:   cfg.InternalSMS.APIKey,
				From:     cfg.InternalSMS.From,
				Timeout:  cfg.InternalSMS.Timeout,
			}, nil)
		}
		phoneService, err := phoneverify.NewService(
			phoneStore, phoneverify.NewRoutingSender(smsClient, internationalSMS), userRepo,
			phoneverify.Config{TTL: cfg.PhoneVerify.TTL},
		)
		if err != nil {
			return nil, fmt.Errorf("build phone verify service: %w", err)
		}
		phoneVerifyHandlers = httpapi.NewPhoneVerifyHandlers(
			phoneService, cfg.OAuth.PublicOrigin, logger,
			httpapi.WithPhoneVerifyRiskGuard(riskGuard),
			httpapi.WithPhoneVerifyRateChecker(phoneChangeRateChecker, cfg.RateLimit.LoginLimit, cfg.RateLimit.LoginWindow),
		)
	}
	if cfg.WeChatMiniProgram.Enabled {
		if userRepo == nil || sessionSvc == nil || wechatRateChecker == nil {
			return nil, errors.New("WeChat Mini Program dependencies are unavailable")
		}
		client, clientErr := wechatadapter.NewClient(wechatadapter.Config{
			AppID: cfg.WeChatMiniProgram.AppID, AppSecret: cfg.WeChatMiniProgram.AppSecret,
			APIBaseURL: cfg.WeChatMiniProgram.APIBaseURL, RequestTimeout: cfg.WeChatMiniProgram.RequestTimeout,
		}, nil)
		if clientErr != nil {
			return nil, fmt.Errorf("WeChat Mini Program client: %w", clientErr)
		}
		wechatService := wechatdomain.NewService(client, userRepo, userRepo)
		wechatHandlers = httpapi.NewWeChatHandlers(wechatService, sessionSvc, wechatRateChecker, cfg.RateLimit.LoginLimit, cfg.RateLimit.LoginWindow, logger)
		if registrationSurfaces.wechatMiniProgram {
			if registrationProvider == nil || registrationRepository == nil || isolatedPool == nil || redisClient == nil || wechatRegistrationRateChecker == nil {
				return nil, errors.New("WeChat Mini Program registration dependencies are unavailable")
			}
			// The shared repository is deliberate: the email verification route
			// mounted above must clear the same isolated intent created by this
			// WeChat registration flow. A second repository wired only here would
			// make activation fall back to the authority-schema migration.
			wechatRegistrationService := wechatregistration.NewService(client, registrationProvider, registrationRepository, redis.NewRegistrationStore(redisClient), wechatregistration.Config{PublicOrigin: cfg.OAuth.PublicOrigin, TokenTTL: 30 * time.Minute})
			wechatRegistrationHandlers = httpapi.NewWeChatRegistrationHandlers(wechatRegistrationService, wechatRegistrationRateChecker, registrationRatePolicy.Create, logger)
			if cfg.WeChatMiniProgram.OnboardingEnabled {
				if wechatOnboardingEncryptor == nil || rateChecker == nil {
					return nil, errors.New("WeChat Mini Program onboarding secure challenge dependencies are unavailable")
				}
				passwordAuthenticator, ok := authenticator.(wechatonboarding.PasswordAuthenticator)
				if !ok {
					return nil, errors.New("WeChat Mini Program onboarding password authentication is unavailable")
				}
				wechatOnboardingStore := redis.NewWeChatOnboardingStore(redisClient, wechatOnboardingEncryptor)
				wechatOnboardingCleanup, err = redis.NewWeChatOnboardingCleanupWorker(wechatOnboardingStore, passwordAuthenticator, logger)
				if err != nil {
					return nil, fmt.Errorf("WeChat Mini Program onboarding cleanup worker: %w", err)
				}
				wechatOnboardingService := wechatonboarding.NewService(
					client, userRepo, postgres.NewWeChatOnboardingAccountRepository(pool.PgxPool()),
					passwordAuthenticator, wechatRegistrationService,
					wechatOnboardingStore, rateChecker, wechatRegistrationRateChecker,
					wechatonboarding.Config{
						OnboardingTTL: 15 * time.Minute, MFATTL: 5 * time.Minute,
						MaxAttempts: 5, RateLimit: cfg.RateLimit.LoginLimit, RateWindow: cfg.RateLimit.LoginWindow,
						CompletionRatePolicy: registrationRatePolicy.Create,
					},
				)
				wechatOnboardingHandlers = httpapi.NewWeChatOnboardingHandlers(
					wechatOnboardingService, sessionSvc, wechatRateChecker, passwordAuthenticator,
					wechatOnboardingStore,
					registrationRatePolicy.Create,
					cfg.RateLimit.LoginLimit, cfg.RateLimit.LoginWindow, logger,
				)
			}
		}
	}
	if cfg.QRAuth.Enabled {
		if redisClient == nil || pool == nil || sessionSvc == nil || qrAuthRateChecker == nil {
			return nil, errors.New("QR authentication dependencies are unavailable")
		}
		qrAuthHandlers = httpapi.NewQRAuthHandlers(
			qrauth.NewService(redis.NewQRAuthStore(redisClient), cfg.QRAuth.ChallengeTTL, nil),
			sessionSvc, userChecker, qrAuthRateChecker, newQRAuthSecurityAuditor(postgres.NewSecurityEventStore(pool.PgxPool())),
			cookieAttrs, cfg.QRAuth.ChallengeTTL, cfg.QRAuth.RateLimit, cfg.QRAuth.RateWindow, logger,
		)
	}

	// Phase 7 Cerbos boundary (ADR-0013). The REST adapter uses bounded HTTP
	// calls and the Admin credentials never leave server configuration.
	if cfg.Cerbos.Configured() {
		cerbosClient, err = cerbos.NewClient(
			cfg.Cerbos.PDPURL, cfg.Cerbos.AdminURL,
			cfg.Cerbos.AdminUsername, cfg.Cerbos.AdminPassword,
			&http.Client{Timeout: cfg.Cerbos.RequestTimeout},
		)
		if err != nil {
			return nil, fmt.Errorf("Cerbos client: %w", err)
		}
		readinessCheckers = append(readinessCheckers, &cerbosReadinessChecker{client: cerbosClient, timeout: cfg.Cerbos.RequestTimeout})
	}

	// Permission resolver: Cerbos is authoritative when configured. The
	// development-only explicit override remains outermost, while the
	// workforce offboarding guard is added below and therefore always wins.
	var permissionBase permissions.Resolver = permissions.NewDefaultResolver()
	var dreamUPAuthorizer permissions.Authorizer
	var policyRepo *postgres.PolicyRepository
	if pool != nil {
		policyRepo = postgres.NewPolicyRepository(pool.PgxPool())
	}
	if pool != nil && cerbosClient != nil && policyRepo != nil {
		principalContext := postgres.NewPermissionContextRepository(pool.PgxPool())
		permissionBase = permissions.NewCerbosResolver(
			principalContext, policyRepo, cerbosClient, request.ID)
		dreamUPAuthorizer = permissions.NewCerbosAuthorizer(
			postgres.NewAdminRoleRepository(pool.PgxPool(), nil), principalContext, policyRepo, cerbosClient, request.ID)
	}
	permResolver = permissionBase
	if cfg.Permission.DevOverrideEnabled {
		permResolver = permissions.NewDevOverrideResolver(permissionBase, cfg.Permission)
	}

	// Phase 5 identity/workforce authority (ADR-0011). PostgreSQL owns the
	// employee/department state and wraps every permission decision with the
	// mandatory offboarding deny. The service uses only the target user's
	// Redis session index for cleanup; unresolved cleanups remain durable jobs.
	var workforceRepo *postgres.WorkforceRepository
	var workforceSvc *workforce.Service
	var workforceHandlers *httpapi.WorkforceHandlers
	if pool != nil && cfg.Session.EncryptionKey != "" {
		workforceRepo, err = postgres.NewWorkforceRepository(pool.PgxPool(), cfg.Session.EncryptionKey)
		if err != nil {
			return nil, fmt.Errorf("workforce repository: %w", err)
		}
		permResolver = permissions.NewWorkforceGuardResolver(permResolver, workforceRepo)
		if sessionSvc != nil {
			workforceSvc = workforce.NewService(workforceRepo, sessionSvc, logger)
			reconciler := workforce.NewReconciler(workforceSvc, 30*time.Second, 25)
			reconciler.Start()
			workerStops = append(workerStops, reconciler.Stop)
		}
	}
	// Phase 6 Provider plane (ADR-0012). PostgreSQL stores only safe metadata,
	// durable sync jobs, normalized directory staging and explicit identity
	// links. Feishu credentials remain in typed process configuration and the
	// adapter keeps access tokens in memory only.
	var providerSvc *providers.Service
	var providerHandlers *httpapi.ProviderHandlers
	var providerLoginHandlers *httpapi.ProviderLoginHandlers
	if pool != nil {
		providerRepo := postgres.NewProviderRepository(pool.PgxPool())
		var directorySource providers.DirectorySource
		var oauthSource providers.OAuthSource
		if cfg.Feishu.Configured() {
			client, err := feishu.NewClient(cfg.Feishu)
			if err != nil {
				return nil, fmt.Errorf("Feishu provider: %w", err)
			}
			directorySource, oauthSource = client, client
		}
		providerSvc = providers.NewService(providerRepo, directorySource, oauthSource, providers.RuntimeMetadata{
			AppID: cfg.Feishu.AppID, RedirectURL: cfg.Feishu.RedirectURL,
			ContactScope: cfg.Feishu.ContactScope, TenantID: cfg.Feishu.TenantID,
			SecretConfigured: cfg.Feishu.Configured(),
		}, logger)
		if directorySource != nil {
			reconciler := providers.NewReconciler(providerSvc, cfg.Feishu.ReconcileInterval, cfg.Feishu.SyncTimeout)
			reconciler.Start()
			workerStops = append(workerStops, reconciler.Stop)
		}
	}

	// Phase 7 policy and audit services. Drafts and audit search remain
	// available with PostgreSQL alone; publication additionally requires the
	// explicitly configured mutable Cerbos Admin API and fails closed without it.
	var policySvc *policies.Service
	var auditSvc *audit.Service
	if pool != nil && policyRepo != nil {
		policySvc = policies.NewService(policyRepo, cerbosClient, logger)
		if cerbosClient != nil {
			reconciler := policies.NewReconciler(policySvc, cfg.Cerbos.ReconcileInterval, 20)
			reconciler.Start()
			workerStops = append(workerStops, reconciler.Stop)
		}
		auditSvc = audit.NewService(postgres.NewAuditRepository(pool.PgxPool()), 15*time.Minute, logger)
		exportWorker := audit.NewWorker(auditSvc, time.Second, 5)
		exportWorker.Start()
		workerStops = append(workerStops, exportWorker.Stop)
	}

	// When using the fake development authenticator, skip database-backed
	// user existence checks: fake users have hardcoded IDs that do not exist
	// in PostgreSQL. Replace the userReader with an in-memory fake that
	// returns the dev users so /me works.
	//
	// The FakeAuthenticator type is only ever constructed in non-production
	// environments (buildAuthenticator rejects it in production), and the
	// explicit IsProduction guard below makes that boundary defensive
	// against future changes.
	if _, isFake := authenticator.(*auth.FakeAuthenticator); isFake && !cfg.IsProduction() {
		userChecker = nil
		userReader = &fakeUserReader{}
	}

	// Provider readiness: the ZITADEL adapter reports API connectivity.
	if checker, ok := authenticator.(httpapi.ReadinessChecker); ok {
		readinessCheckers = append(readinessCheckers, checker)
	}

	// Application management plane (ADR-0004). The provisioner follows the
	// authenticator selection: the ZITADEL Management API in real setups and
	// the in-memory fake for development. Every dependency must be present or
	// the routes stay unregistered (fail closed).
	var provisioner applications.OAuthClientProvisioner
	providerName := ""
	if sdkClient != nil {
		prov, err := zitadel.NewProvisioner(sdkClient.ManagementService(), cfg.Auth.ProjectID, cfg.OAuth.InteractionBaseURI(), logger)
		if err != nil {
			return nil, err
		}
		provisioner = prov
		providerName = zitadel.ProviderName
		// Project readability joins readiness so a wrong project ID or missing
		// service-account permission fails /readyz instead of surfacing on the
		// first admin operation (ADR-0004 §1). The stronger PROJECT_OWNER
		// permission required for deletions cannot be probed without side
		// effects and remains covered by deployment acceptance checks.
		readinessCheckers = append(readinessCheckers,
			newProjectReadinessChecker(prov, 3*time.Second))
	} else if _, isFake := authenticator.(*auth.FakeAuthenticator); isFake && !cfg.IsProduction() {
		provisioner = applications.NewFakeProvisioner()
		providerName = "fake"
	}

	// Authorization-request provider for consent resolution and decision
	// orchestration (ADR-0005 §2, §5, §12): the ZITADEL oidc.v2 adapter in
	// real setups, the fake provider for development. Resolution only ever
	// reads through the narrow AuthRequestReader view of this seam; the
	// completion methods are reachable exclusively from the decision
	// service and the future interaction gateway.
	var authRequestProvider consent.AuthRequestProvider
	if sdkClient != nil {
		authRequestProvider = zitadel.NewAuthRequestAdapter(sdkClient.OIDCServiceV2())
	} else if _, isFake := authenticator.(*auth.FakeAuthenticator); isFake && !cfg.IsProduction() {
		authRequestProvider = consent.NewFakeAuthRequestProvider()
	}

	var appRepo *postgres.ApplicationRepository
	var appHandlers *httpapi.ApplicationHandlers
	var reauthHandlers *httpapi.ReauthHandlers
	var securityHandlers *httpapi.SecurityHandlers
	var passwordHandlers *httpapi.PasswordHandlers
	var reauthVerifier httpapi.ReauthVerifier
	var reauthGrantVerifier app.ReauthGrantVerifier
	var rotationRates httpapi.RotationRateChecker
	var policyHandlers *httpapi.PolicyHandlers
	var auditHandlers *httpapi.AuditHandlers
	var dashboardHandlers *httpapi.DashboardHandlers
	var privacyHandlers *httpapi.PrivacyHandlers
	var legalHandlers *httpapi.LegalHandlers
	var accountMutationHandlers *httpapi.AccountMutationHandlers
	var publicAccountHandlers *httpapi.PublicAccountHandlers
	var adminStepUpHandlers *httpapi.AdminStepUpHandlers
	var dreamUPAdminHandlers *httpapi.DreamUPAdminHandlers
	var dreamUPJWKSHandler *httpapi.DreamUPJWKSHandler
	var dreamUPMobileHandlers *httpapi.DreamUPMobileHandlers
	var dreamUPMobileJWKSHandler *httpapi.DreamUPJWKSHandler
	// Reauthentication is shared infrastructure for account, application and
	// workforce high-risk operations. It must not disappear merely because an
	// unrelated OAuth provisioner is unavailable (ADR-0011 §3).
	if pool != nil && redisClient != nil && sessionSvc != nil {
		limiter := redis.NewRateLimiter(redisClient)
		rotationRates = limiter
		reauthStore := redis.NewReauthStore(redisClient)
		reauthGrants := httpapi.NewReauthGrants(reauthStore, sensitiveGate)
		reauthVerifier = reauthGrants
		reauthGrantVerifier = reauthGrants
		if reauthAuth, ok := authenticator.(httpapi.ReauthAuthenticator); ok {
			reauthAuditor := newReauthSecurityAuditor(postgres.NewSecurityEventStore(pool.PgxPool()))
			reauthHandlers = httpapi.NewReauthHandlers(
				reauthAuth, reauthStore, reauthStore, limiter, reauthAuditor,
				cfg.Reauth.ChallengeTTL, cfg.Reauth.GrantTTL,
				cfg.Reauth.MaxAttempts, cfg.Reauth.RateLimit, cfg.Reauth.RateWindow,
				logger)
			cleanupWorker := httpapi.NewReauthCleanupWorker(
				reauthAuth, reauthStore, reauthAuditor, cfg.Reauth.CleanupInterval, logger)
			cleanupWorker.Start()
			workerStops = append(workerStops, cleanupWorker.Stop)
		}

		if factorManager, ok := authenticator.(auth.FactorManager); ok {
			enrollmentStore := redis.NewEnrollmentStore(redisClient)
			securityHandlers = httpapi.NewSecurityHandlers(
				factorManager, reauthVerifier, enrollmentStore,
				sensitiveGate, cfg.Reauth.GrantTTL, logger)
			cleanupWorker := httpapi.NewPasskeyEnrollmentCleanupWorker(
				factorManager, enrollmentStore, cfg.Reauth.CleanupInterval, logger)
			cleanupWorker.Start()
			workerStops = append(workerStops, cleanupWorker.Stop)
		}

		if passwordManager, ok := authenticator.(auth.PasswordManager); ok && securitySvc != nil {
			passwordHandlers = httpapi.NewPasswordHandlers(
				passwordManager, reauthVerifier, sessionSvc, securitySvc, sessionAuditor,
				cfg.SecurityState.ProviderDeadline, cfg.SecurityState.SettlementTimeout,
				cfg, logger)
		}
	}
	if accountContactService != nil && accountContactRateChecker != nil && reauthVerifier != nil {
		accountContactHandlers = httpapi.NewAccountContactHandlers(
			accountContactService, accountContactRateChecker, reauthVerifier, cfg.OAuth.PublicOrigin,
			cfg.RateLimit.LoginLimit, cfg.RateLimit.LoginWindow, logger,
		)
	}
	if pool != nil && redisClient != nil && sessionSvc != nil && reauthVerifier != nil &&
		registrationBlockRateChecker != nil && cfg.Session.EncryptionKey != "" {
		auditRootKey, decodeErr := base64.StdEncoding.DecodeString(cfg.Session.EncryptionKey)
		if decodeErr != nil {
			return nil, fmt.Errorf("registration block audit key: %w", decodeErr)
		}
		auditTargets, targetErr := httpapi.NewRegistrationBlockAuditTargets(auditRootKey, cfg.Session.EncryptionKeyID)
		if targetErr != nil {
			return nil, fmt.Errorf("registration block audit targets: %w", targetErr)
		}
		registrationBlockHandlers = httpapi.NewRegistrationBlockHandlers(
			redis.NewRegistrationFormDefenseStore(redisClient),
			postgres.NewAdminRoleRepository(pool.PgxPool(), nil),
			postgres.NewPermissionContextRepository(pool.PgxPool()),
			permResolver,
			postgres.NewSecurityEventStore(pool.PgxPool()),
			httpapi.RegistrationBlockControls{
				Reauth: reauthVerifier, Rates: registrationBlockRateChecker,
				AuditTargets: auditTargets, RateLimit: 12, RateWindow: 15 * time.Minute,
			},
			logger,
		)
	}
	if cfg.DreamUPAdmin.Enabled {
		if pool == nil || isolatedPool == nil || redisClient == nil || sessionSvc == nil || dreamUPAdminMaterial == nil || dreamUPDelegationKeyring == nil || dreamUPAuthorizer == nil {
			return nil, errors.New("DreamUP admin requires authority and isolated PostgreSQL, Redis, and browser sessions")
		}
		hasher, err := adminstepup.NewAnswerHasher(dreamUPAdminMaterial.pepperKeyring, adminstepup.DefaultArgon2Params, cfg.DreamUPAdmin.Argon2MaxConcurrent)
		if err != nil {
			return nil, fmt.Errorf("DreamUP admin answer hasher: %w", err)
		}
		limiter, err := redis.NewAdminChallengeRateLimiter(redisClient, dreamUPAdminMaterial.rateKeyring, cfg.DreamUPAdmin.RateLimit, cfg.DreamUPAdmin.RateWindow)
		if err != nil {
			return nil, fmt.Errorf("DreamUP admin rate limiter: %w", err)
		}
		cursorCodec, err := adminpagination.NewCursorCodec(cfg.Session.EncryptionKey, nil)
		if err != nil {
			return nil, fmt.Errorf("DreamUP admin cursor codec: %w", err)
		}
		uow := postgres.NewAdminUnitOfWork(pool.PgxPool(), cursorCodec)
		dreamUPBFFUOW := postgres.NewAdminOutboxUnitOfWork(isolatedPool.PgxPool())
		stepUpRepository := postgres.NewAdminStepUpRepository(pool.PgxPool())
		service, err := adminstepup.NewService(adminstepup.ServiceDependencies{
			Repository: stepUpRepository,
			Bindings:   postgres.NewAdminRoleRepository(pool.PgxPool(), nil),
			UnitOfWork: uow, Limiter: limiter, Hasher: hasher,
			QuestionCipher: dreamUPAdminMaterial.challengeCipher,
			Fingerprinter:  &stepUpFingerprinterAdapter{base: dreamUPAdminMaterial.fingerprinter},
			GrantStore:     redis.NewReauthStore(redisClient),
		}, adminstepup.ServiceConfig{GeneralFreshness: cfg.DreamUPAdmin.GeneralFreshness, HighRiskFreshness: cfg.DreamUPAdmin.HighRiskFreshness, GrantTTL: cfg.Reauth.GrantTTL})
		if err != nil {
			return nil, fmt.Errorf("DreamUP admin step-up service: %w", err)
		}
		adminStepUpHandlers = httpapi.NewAdminStepUpHandlers(service, cfg.DreamUPAdmin.FreshLoginMaxAge, nil)

		administratorSigner, err := dreamupdelegation.NewAdministratorSigner(dreamUPDelegationKeyring, dreamupdelegation.SignerConfig{
			Issuer: cfg.DreamUPAdmin.DelegationIssuer, Audience: cfg.DreamUPAdmin.DelegationAudience,
			TTL: dreamupdelegation.MaxOrdinaryTTL, ClockSkew: dreamupdelegation.MaxClockSkew,
			Now: func() time.Time { return time.Now().UTC() },
		})
		if err != nil {
			return nil, fmt.Errorf("DreamUP administrator signer: %w", err)
		}
		upstreamClient, err := dreamupclient.NewClient(cfg.DreamUPAdmin.BaseURL, nil, dreamupclient.WithMaxResponseBytes(cfg.DreamUPAdmin.ResponseLimitBytes))
		if err != nil {
			return nil, fmt.Errorf("DreamUP administration client: %w", err)
		}
		bffService, err := app.NewService(app.ServiceDependencies{
			Authorizer:      dreamUPAuthorizer,
			Registry:        postgres.NewDreamUPEventRegistryRepository(pool.PgxPool(), cursorCodec),
			StepUps:         stepUpRepository,
			AccountSecurity: postgres.NewSecurityStateStore(pool.PgxPool()),
			ReauthGrants:    reauthGrantVerifier,
			Signer:          administratorSigner,
			Client:          upstreamClient,
			UnitOfWork:      dreamUPBFFUOW,
			Fingerprinter:   dreamUPAdminMaterial.fingerprinter,
		}, app.ServiceConfig{RequireDurableMutations: true, MutationLease: cfg.DreamUPAdmin.ReconcileLease})
		if err != nil {
			return nil, fmt.Errorf("DreamUP administration BFF: %w", err)
		}
		dreamUPAdminHandlers, err = httpapi.NewDreamUPAdminHandlers(bffService, cfg.DreamUPAdmin.AdminOrigin, cfg.DreamUPAdmin.MiniProgramEnabled)
		if err != nil {
			return nil, fmt.Errorf("DreamUP administration handlers: %w", err)
		}
		dreamUPJWKSHandler, err = httpapi.NewDreamUPJWKSHandler(dreamUPDelegationKeyring)
		if err != nil {
			return nil, fmt.Errorf("DreamUP delegation JWKS: %w", err)
		}
		serviceSigner, err := dreamupdelegation.NewServiceSigner(dreamUPDelegationKeyring, dreamupdelegation.SignerConfig{
			Issuer: cfg.DreamUPAdmin.DelegationIssuer, Audience: cfg.DreamUPAdmin.DelegationAudience,
			TTL: dreamupdelegation.MaxOrdinaryTTL, ClockSkew: dreamupdelegation.MaxClockSkew,
			Now: func() time.Time { return time.Now().UTC() },
		})
		if err != nil {
			return nil, fmt.Errorf("DreamUP reconciler signer: %w", err)
		}
		reconciler, err := app.NewReconciler(app.ReconcilerDependencies{UnitOfWork: dreamUPBFFUOW, Signer: serviceSigner, Client: upstreamClient}, app.ReconcilerConfig{
			Interval: cfg.DreamUPAdmin.ReconcileInterval, BatchSize: cfg.DreamUPAdmin.ReconcileBatchSize,
			Lease: cfg.DreamUPAdmin.ReconcileLease, ServiceSubject: cfg.DreamUPAdmin.DelegationServiceSubject,
			ServiceVersion: cfg.DreamUPAdmin.DelegationServiceVersion,
		})
		if err != nil {
			return nil, fmt.Errorf("DreamUP administration reconciler: %w", err)
		}
		reconciler.Start(context.Background())
		workerStops = append(workerStops, reconciler.Stop)
	}
	if cfg.DreamUPMobile.Enabled {
		if userRepo == nil || sessionSvc == nil || dreamUPMobileDelegationKeyring == nil || dreamUPMobileRateChecker == nil {
			return nil, errors.New("DreamUP Mobile bridge requires PostgreSQL, Redis, and sessions")
		}
		signer, signerErr := dreamupdelegation.NewParticipantSigner(dreamUPMobileDelegationKeyring, dreamupdelegation.SignerConfig{Issuer: cfg.DreamUPMobile.DelegationIssuer, Audience: cfg.DreamUPMobile.DelegationAudience, TTL: cfg.DreamUPMobile.AssertionTTL, Now: func() time.Time { return time.Now().UTC() }})
		if signerErr != nil {
			return nil, fmt.Errorf("DreamUP Mobile participant signer: %w", signerErr)
		}
		dreamUPMobileHandlers = httpapi.NewDreamUPMobileHandlers(signer, userRepo, dreamUPMobileRateChecker, cfg.Auth.Provider, cfg.Auth.ProjectID, cfg.DreamUPMobile.ScopedRateLimit, cfg.DreamUPMobile.GlobalRateLimit, cfg.DreamUPMobile.RateWindow, logger)
		var jwksErr error
		dreamUPMobileJWKSHandler, jwksErr = httpapi.NewDreamUPJWKSHandler(dreamUPMobileDelegationKeyring)
		if jwksErr != nil {
			return nil, fmt.Errorf("DreamUP Mobile JWKS: %w", jwksErr)
		}
	}
	if pool != nil && provisioner != nil && userReader != nil && sessionSvc != nil && cfg.Session.EncryptionKey != "" {
		var err error
		appRepo, err = postgres.NewApplicationRepository(pool.PgxPool(), cfg.Session.EncryptionKey)
		if err != nil {
			return nil, fmt.Errorf("application repository: %w", err)
		}
		eventStore := postgres.NewSecurityEventStore(pool.PgxPool())
		appSvc := applications.NewService(appRepo, provisioner, eventStore, eventStore, userReader,
			providerName, cfg.Auth.ProjectID, cfg.Rotation.GracePeriod)

		appHandlers = httpapi.NewApplicationHandlers(appSvc, permResolver, reauthVerifier,
			rotationRates, cfg.Rotation.RateLimit, cfg.Rotation.RateWindow, logger)
	}
	if workforceSvc != nil {
		workforceHandlers = httpapi.NewWorkforceHandlers(
			workforceSvc, permResolver, reauthVerifier, sessionSvc, logger)
	}
	if providerSvc != nil {
		providerHandlers = httpapi.NewProviderHandlers(providerSvc, permResolver, reauthVerifier, logger)
		if cfg.Feishu.Configured() && redisClient != nil && sessionSvc != nil {
			providerLoginHandlers = httpapi.NewProviderLoginHandlers(
				providerSvc, redis.NewProviderOAuthStateStore(redisClient), sessionSvc,
				userChecker, rateChecker, cfg, logger)
		}
	}
	if policySvc != nil {
		policyHandlers = httpapi.NewPolicyHandlers(policySvc, permResolver, reauthVerifier)
	}
	if auditSvc != nil {
		auditHandlers = httpapi.NewAuditHandlers(auditSvc, permResolver, reauthVerifier)
		dashboardHandlers = httpapi.NewDashboardHandlers(
			postgres.NewDashboardRepository(pool.PgxPool()), permResolver, auditSvc,
		)
	}
	if pool != nil {
		privacySvc := privacy.NewService(
			postgres.NewPrivacyRepository(pool.PgxPool(), cfg.Auth.Provider),
			accountDeleter, sessionSvc, logger,
		)
		privacyHandlers = httpapi.NewPrivacyHandlers(privacySvc, reauthVerifier)
		legalHandlers = httpapi.NewLegalHandlers(privacySvc)
		privacyWorker := privacy.NewWorker(privacySvc, time.Second, 5)
		privacyWorker.Start()
		workerStops = append(workerStops, privacyWorker.Stop)
	}
	if userRepo != nil && legacyContactRateChecker != nil {
		contactProvider, _ := authenticator.(identity.AccountContactProvider)
		accountMutationHandlers = httpapi.NewAccountMutationHandlers(
			userRepo, contactProvider, legacyContactRateChecker, logger,
		)
		if sdkClient != nil && securitySvc != nil && sessionAuditor != nil &&
			encryptor != nil && cfg.OAuth.PublicOrigin != "" {
			lifecycleProvider := zitadel.NewLifecycleProvider(
				sdkClient.UserServiceV2(), sdkClient.ManagementService(), cfg.Auth.ProjectID,
			)
			publicAccountHandlers = httpapi.NewPublicAccountHandlers(
				userRepo, lifecycleProvider, legacyContactRateChecker, securitySvc,
				sessionAuditor, encryptor, zitadel.ProviderName, cfg.Auth.ProjectID,
				cfg.OAuth.PublicOrigin, logger,
			)
		}
	}

	// Consent resolution (P3.3, ADR-0005 §2): the side-effect free
	// derivation of the ConsentResolution union. Every dependency must be
	// present or the route stays unregistered (fail closed).
	var authorizationHandlers *httpapi.AuthorizationHandlers
	var decisionHandlers *httpapi.AuthorizationDecisionHandlers
	var authorizedAppHandlers *httpapi.AuthorizedApplicationHandlers
	var interactionHandlers *httpapi.InteractionGatewayHandlers
	var grantRepo *postgres.GrantRepository
	if pool != nil && sessionSvc != nil && appRepo != nil && authRequestProvider != nil && providerName != "" {
		grantRepo = postgres.NewGrantRepository(pool.PgxPool())
		resolutionSvc, err := consent.NewResolutionService(
			authRequestProvider, appRepo, grantRepo, providerName,
			func() time.Time { return time.Now().UTC() })
		if err != nil {
			return nil, fmt.Errorf("consent resolution service: %w", err)
		}
		authorizationHandlers = httpapi.NewAuthorizationHandlers(resolutionSvc, logger)

		// Decision orchestration (P3.4, ADR-0005 §5): the interactive
		// allow/deny execution entry. The provider tenant follows the
		// identity-link tenant convention (the configured project).
		decisionSvc, err := consent.NewDecisionService(
			authRequestProvider, appRepo, grantRepo,
			providerName, cfg.Auth.ProjectID,
			func() time.Time { return time.Now().UTC() })
		if err != nil {
			return nil, fmt.Errorf("consent decision service: %w", err)
		}
		decisionHandlers = httpapi.NewAuthorizationDecisionHandlers(decisionSvc, sessionSvc, logger)

		// Authorized application management (P3.5, ADR-0005 §6): the
		// current user's grant listing and owner-bound revocation. Purely
		// local consent state — no provider token revocation is claimed.
		grantMgmtSvc, err := consent.NewGrantManagementService(grantRepo, appRepo)
		if err != nil {
			return nil, fmt.Errorf("consent grant management service: %w", err)
		}
		authorizedAppHandlers = httpapi.NewAuthorizedApplicationHandlers(grantMgmtSvc, logger)

		// Authorization Interaction Gateway (P3.6, ADR-0005 §12): the
		// server-side execution entry for prompt=none and the router into
		// the Next.js login/consent pages. It reuses the resolution and
		// decision services — no second authorization judgment exists.
		gatewaySvc, err := consent.NewInteractionGatewayService(
			authRequestProvider, appRepo, grantRepo,
			resolutionSvc, decisionSvc,
			providerName, func() time.Time { return time.Now().UTC() })
		if err != nil {
			return nil, fmt.Errorf("consent interaction gateway: %w", err)
		}
		interactionHandlers = httpapi.NewInteractionGatewayHandlers(gatewaySvc, sessionSvc, logger)

		// Background reconciliation (ADR-0005 §4): forward-repair rows
		// carrying the provider success proof and fail stale pending rows.
		reconciler, err := consent.NewReconciler(grantRepo, grantRepo,
			consent.DefaultReconciliationInterval, consent.DefaultPendingStaleAfter,
			consent.DefaultReconciliationBatch, logger)
		if err != nil {
			return nil, fmt.Errorf("consent reconciler: %w", err)
		}
		reconciler.Start()
		workerStops = append(workerStops, reconciler.Stop)
	}

	health := httpapi.NewHealthHandlers(readinessCheckers...)
	router.Get("/healthz", health.Healthz)
	router.Get("/readyz", health.Readyz)
	if dreamUPJWKSHandler != nil {
		router.Get("/.well-known/dreamup-admin-jwks.json", dreamUPJWKSHandler.JWKS)
		router.Head("/.well-known/dreamup-admin-jwks.json", dreamUPJWKSHandler.JWKS)
	}
	if dreamUPMobileJWKSHandler != nil {
		router.Get("/.well-known/dreamup-mobile-jwks.json", dreamUPMobileJWKSHandler.JWKS)
		router.Head("/.well-known/dreamup-mobile-jwks.json", dreamUPMobileJWKSHandler.JWKS)
	}

	// Loopback-only email sender used by the DreamUP worker. The endpoint
	// fails closed with a 503 when SMTP is not configured. It is not proxied
	// by nginx, so only colocated services can reach it.
	var emailHandlers *httpapi.EmailHandlers
	var smtpSender email.Sender
	if cfg.Email.Configured() {
		sender, senderErr := email.NewSMTP(email.Config{
			Host:        cfg.Email.SMTPHost,
			Port:        cfg.Email.SMTPPort,
			User:        cfg.Email.SMTPUser,
			Password:    cfg.Email.SMTPPassword,
			FromAddress: cfg.Email.FromAddress,
			FromName:    cfg.Email.FromName,
		})
		if senderErr != nil {
			return nil, fmt.Errorf("email sender: %w", senderErr)
		}
		smtpSender = sender
		emailHandlers = httpapi.NewEmailHandlers(sender, cfg.Email.InternalToken)
	} else {
		emailHandlers = httpapi.NewEmailHandlers(nil, "")
	}
	router.Post("/internal/v1/emails", emailHandlers.Send)
	if cfg.WeChatMiniProgram.OnboardingEnabled && pool != nil && smtpSender != nil {
		wechatNotificationWorker = postgres.NewWeChatNotificationWorker(
			postgres.NewWeChatNotificationStore(pool.PgxPool()),
			postgres.NewWeChatNotificationEmailSender(smtpSender),
			logger,
		)
	}

	// Session promotion middleware parameters (ADR-0007 F1): every
	// promotion path shares the same authoritative security-state
	// validator and the same cookie attributes; the gate is nil only in
	// gate-less wiring (fake development mode).
	// cookieAttrs was constructed before feature wiring so native and browser
	// transports share the exact same cookie policy.

	// Authorization Interaction Gateway (ADR-0005 §1, §12): the sole entry
	// point ZITADEL generates for LoginV2 clients, served on the public
	// origin under the /_interaction prefix the reverse proxy routes to
	// this backend. Optional session (prompt=none must run without one);
	// GET-only, every outcome is a 302 or the fixed local failure page.
	router.Group(func(r chi.Router) {
		if sessionSvc != nil {
			r.Use(httpapi.OptionalSession(sessionSvc, userChecker, securityGate, cookieAttrs, logger))
		}
		if interactionHandlers != nil {
			r.Get("/_interaction/login", interactionHandlers.InteractionLogin)
		}
	})

	// API v1 routes.
	router.Route("/api/v1", func(r chi.Router) {
		// Preserve immutable PostgreSQL-backed avatar URLs issued by the public
		// repository before the deployed filesystem-backed avatar contract.
		if accountMutationHandlers != nil {
			r.Get("/media/avatars/{avatarFile:avt_[0-9a-f]+\\.png}", accountMutationHandlers.GetAvatar)
		}

		// Auth endpoints (no session required for login/MFA; logout requires
		// session + CSRF).
		authHandlers := httpapi.NewAuthHandlers(
			authenticator, sessionSvc, mfaStore, rateChecker,
			userChecker, cfg, logger, httpapi.WithAuthRiskGuard(riskGuard))
		trustedAuthMutation := httpapi.RequireTrustedBrowserMutation(cfg.OAuth.PublicOrigin)
		miniProgramClient := httpapi.RequireMiniProgramClient()
		jsonMutation := httpapi.RequireJSONMutation()
		if publicAccountHandlers != nil {
			r.With(trustedAuthMutation).Post("/password-reset-requests", publicAccountHandlers.RequestPasswordReset)
			r.With(trustedAuthMutation).Post("/password-resets", publicAccountHandlers.ResetPassword)
			r.With(trustedAuthMutation).Post("/email-verifications", publicAccountHandlers.VerifyEmail)
		}

		r.With(trustedAuthMutation).Post("/auth/sessions", authHandlers.Login)
		r.With(miniProgramClient, jsonMutation).Post("/auth/miniprogram/sessions", authHandlers.LoginMiniProgram)
		r.With(miniProgramClient, jsonMutation).Post("/auth/miniprogram/sessions/mfa", authHandlers.CompleteMFAMiniProgram)
		if wechatHandlers != nil {
			r.With(miniProgramClient, jsonMutation).Post("/auth/wechat/sessions", wechatHandlers.Login)
		}
		if wechatOnboardingHandlers != nil {
			wechatOnboardingHandlers.Mount(r)
		}
		if qrAuthHandlers != nil {
			r.With(trustedAuthMutation).Post("/auth/qr/challenges", qrAuthHandlers.Begin)
			r.With(trustedAuthMutation).Post("/auth/qr/challenges/{challengeId}/consume", qrAuthHandlers.Consume)
		}
		r.With(trustedAuthMutation).Post("/auth/passkey/begin", authHandlers.BeginPasskeyLogin)
		r.With(trustedAuthMutation).Post("/auth/sessions/mfa", authHandlers.CompleteMFA)
		if riskGuard != nil {
			r.With(trustedAuthMutation).Post("/auth/step-up", riskGuard.Complete)
		}
		mountRegistrationSurfaces(r, registrationSurfaces, registrationHandlers, wechatRegistrationHandlers)
		if registrationBlockHandlers != nil {
			r.Group(func(r chi.Router) {
				r.Use(httpapi.RequireSession(sessionSvc, userChecker, securityGate, cookieAttrs, logger))
				r.Use(httpapi.RequireCSRF())
				r.Post("/admin/registration-defense/blocks/revoke", registrationBlockHandlers.Revoke)
			})
		}
		if legalHandlers != nil {
			r.Get("/legal-documents", legalHandlers.List)
		}
		if providerLoginHandlers != nil {
			r.Get("/auth/providers", providerLoginHandlers.ListPublicProviders)
			r.Get("/auth/providers/feishu/authorize", providerLoginHandlers.BeginFeishu)
			r.Get("/auth/providers/feishu/callback", providerLoginHandlers.FeishuCallback)
		}

		// DreamUP administrator challenge routes exist only behind the master
		// gate. With the default false value the whole namespace remains 404.
		if adminStepUpHandlers != nil {
			r.Group(func(r chi.Router) {
				r.Use(httpapi.RequireSession(sessionSvc, userChecker, securityGate, cookieAttrs, logger))
				r.Use(httpapi.RequireCSRF())
				r.Get("/admin/step-up/challenge", adminStepUpHandlers.Challenge)
				r.Post("/admin/step-up/enroll", adminStepUpHandlers.Enroll)
				r.Post("/admin/step-up/verify", adminStepUpHandlers.Verify)
				r.Post("/admin/step-up/rotate", adminStepUpHandlers.Rotate)
			})
		}
		if dreamUPAdminHandlers != nil {
			r.Group(func(r chi.Router) {
				r.Use(dreamUPAdminHandlers.CORS)
				r.Use(httpapi.RequireSession(sessionSvc, userChecker, securityGate, cookieAttrs, logger))
				r.Use(httpapi.RequireCSRF())
				r.Route("/admin/dreamup", func(r chi.Router) {
					dreamUPAdminHandlers.Mount(r)
					if adminStepUpHandlers != nil {
						r.Get("/step-up/challenge", adminStepUpHandlers.Challenge)
						r.Post("/step-up/enroll", adminStepUpHandlers.Enroll)
						r.Post("/step-up/verify", adminStepUpHandlers.Verify)
						r.Post("/step-up/rotate", adminStepUpHandlers.Rotate)
					}
				})
			})
		}

		// Logout requires session and CSRF.
		r.Group(func(r chi.Router) {
			if sessionSvc != nil {
				r.Use(httpapi.RequireSession(sessionSvc, userChecker, securityGate, cookieAttrs, logger))
				r.Use(httpapi.RequireCSRF())
			}
			r.Delete("/auth/session", authHandlers.Logout)
		})

		// Reauthentication for high-risk operations (session + CSRF required;
		// challenges and grants are bound to the session, ADR-0004 §7).
		r.Group(func(r chi.Router) {
			if sessionSvc != nil {
				r.Use(httpapi.RequireSession(sessionSvc, userChecker, securityGate, cookieAttrs, logger))
				r.Use(httpapi.RequireCSRF())
			}
			if reauthHandlers != nil {
				r.Post("/auth/reauthentication", reauthHandlers.Request)
				r.Post("/auth/reauthentication/mfa", reauthHandlers.CompleteMFA)
			}
		})

		// Consent resolution: side-effect free GET behind an optional
		// session — an absent session resolves to the unauthenticated
		// outcome instead of a 401 (frozen ConsentResolution union,
		// ADR-0005 §12).
		r.Group(func(r chi.Router) {
			if sessionSvc != nil {
				r.Use(httpapi.OptionalSession(sessionSvc, userChecker, securityGate, cookieAttrs, logger))
			}
			if authorizationHandlers != nil {
				r.Get("/authorization/requests/{requestId}", authorizationHandlers.ResolveRequest)
			}
		})

		// Consent decision (ADR-0005 §5, §11): the interactive allow/deny
		// execution entry. Session + CSRF required; the response carries
		// the provider callback URL exclusively as redirectUrl under the
		// global no-store / no-referrer header policy.
		r.Group(func(r chi.Router) {
			if sessionSvc != nil {
				r.Use(httpapi.RequireSession(sessionSvc, userChecker, securityGate, cookieAttrs, logger))
				r.Use(httpapi.RequireCSRF())
			}
			if decisionHandlers != nil {
				r.Post("/authorization/requests/{requestId}/decision", decisionHandlers.DecideRequest)
			}
		})

		// Authorized applications (ADR-0005 §6): the current user's grant
		// listing and owner-bound, idempotent revocation. Session required;
		// the DELETE additionally passes the CSRF check (safe methods skip
		// the token requirement).
		r.Group(func(r chi.Router) {
			if sessionSvc != nil {
				r.Use(httpapi.RequireSession(sessionSvc, userChecker, securityGate, cookieAttrs, logger))
				r.Use(httpapi.RequireCSRF())
			}
			if authorizedAppHandlers != nil {
				r.Get("/me/authorized-applications", authorizedAppHandlers.ListAuthorizedApplications)
				r.Delete("/me/authorized-applications/{grantId}", authorizedAppHandlers.RevokeGrant)
			}
		})

		// Account endpoints (require session).
		r.Group(func(r chi.Router) {
			if sessionSvc != nil {
				r.Use(httpapi.RequireSession(sessionSvc, userChecker, securityGate, cookieAttrs, logger))
			}
			if userReader != nil && permResolver != nil {
				accountHandlers := httpapi.NewAccountHandlers(userReader, permResolver, userWriter, cfg.AvatarDir)
				if workforceRepo != nil {
					accountHandlers = httpapi.NewAccountHandlers(userReader, permResolver, userWriter, cfg.AvatarDir, workforceRepo)
				}
				r.Get("/me", accountHandlers.GetCurrentUser)
				r.Get("/me/permissions", accountHandlers.GetPermissions)
				r.Get("/media/avatars/{userId}", accountHandlers.ServeAvatar)

				r.Group(func(r chi.Router) {
					if sessionSvc != nil {
						r.Use(httpapi.RequireCSRF())
					}
					if userWriter != nil {
						r.Patch("/me/profile", accountHandlers.UpdateProfile)
						r.With(miniProgramClient, httpapi.RequireNativeMiniProgramBearer()).Post("/me/miniprogram/profile", accountHandlers.UpdateProfileFromMiniProgram)
						avatarUpload := http.HandlerFunc(accountHandlers.UploadAvatar)
						if accountMutationHandlers != nil {
							avatarUpload = httpapi.CompatibleAvatarUpload(avatarUpload, accountMutationHandlers.UploadAvatar)
						}
						r.Post("/me/avatar", avatarUpload)
					}
					if accountMutationHandlers != nil {
						r.Patch("/me", accountMutationHandlers.UpdateProfile)
						r.Post("/me/email-change-requests", accountMutationHandlers.RequestEmailChange)
						r.Post("/me/email-change-requests/{requestId}/verify", accountMutationHandlers.VerifyEmailChange)
						r.Post("/me/phone-change-requests", accountMutationHandlers.RequestPhoneChange)
						r.Post("/me/phone-change-requests/{requestId}/verify", accountMutationHandlers.VerifyPhoneChange)
					}
				})
			}
		})

		// Verified primary email changes are provider-owned and mirror back to
		// the local identity only after the provider confirms the one-time code.
		r.Group(func(r chi.Router) {
			if sessionSvc != nil {
				r.Use(httpapi.RequireSession(sessionSvc, userChecker, securityGate, cookieAttrs, logger))
				r.Use(httpapi.RequireCSRF())
			}
			if accountContactHandlers != nil {
				r.Post("/me/email-change", accountContactHandlers.BeginEmailChange)
				r.Post("/me/email-change/verify", accountContactHandlers.VerifyEmailChange)
			}
			if phoneVerifyHandlers != nil {
				r.Post("/me/phone-change", phoneVerifyHandlers.RequestPhoneChange)
				r.Post("/me/phone-change/verify", phoneVerifyHandlers.VerifyPhoneChange)
			}
			if wechatHandlers != nil {
				r.With(miniProgramClient, httpapi.RequireNativeMiniProgramBearer()).Post("/me/wechat/phone", wechatHandlers.BindPhone)
			}
			if dreamUPMobileHandlers != nil {
				r.With(miniProgramClient, httpapi.RequireNativeMiniProgramBearer()).Post("/dreamup/mobile/assertions", dreamUPMobileHandlers.CreateAssertion)
				r.With(miniProgramClient, httpapi.RequireNativeMiniProgramBearer()).Post("/dreamup/mobile/resume-upload-assertions", dreamUPMobileHandlers.CreateResumeUploadAssertion)
			}
			if qrAuthHandlers != nil {
				r.With(miniProgramClient, httpapi.RequireNativeMiniProgramBearer()).Post("/auth/qr/challenges/{challengeId}/approve", qrAuthHandlers.Approve)
			}
		})

		// Phase 8 privacy rights (ADR-0014): requester-owned short-lived
		// exports and a cancellable 30-day deletion lifecycle. All mutations
		// pass CSRF; export/deletion creation additionally consume a grant
		// bound to the caller's stable user ID.
		r.Group(func(r chi.Router) {
			if sessionSvc != nil {
				r.Use(httpapi.RequireSession(sessionSvc, userChecker, securityGate, cookieAttrs, logger))
				r.Use(httpapi.RequireCSRF())
			}
			if privacyHandlers != nil {
				r.Post("/me/data-exports", privacyHandlers.BeginExport)
				r.Get("/me/data-exports/{exportId}", privacyHandlers.GetExport)
				r.Get("/me/data-exports/{exportId}/download", privacyHandlers.Download)
				r.Get("/me/account-deletion", privacyHandlers.GetDeletion)
				r.Post("/me/account-deletion", privacyHandlers.RequestDeletion)
				r.Delete("/me/account-deletion", privacyHandlers.CancelDeletion)
			}
		})

		// Session inventory (ADR-0006 §2): list and revoke the caller's own
		// sessions. GET is a safe method and passes the CSRF middleware; the
		// DELETE mutations additionally require the CSRF token.
		r.Group(func(r chi.Router) {
			if sessionSvc != nil {
				r.Use(httpapi.RequireSession(sessionSvc, userChecker, securityGate, cookieAttrs, logger))
				r.Use(httpapi.RequireCSRF())
				sessionHandlers := httpapi.NewSessionHandlers(sessionSvc, logger)
				r.Get("/me/sessions", sessionHandlers.ListSessions)
				r.Delete("/me/sessions", sessionHandlers.RevokeAllOthers)
				r.Delete("/me/sessions/{sessionId}", sessionHandlers.RevokeSession)
			}
		})

		// Account security factors (ADR-0006 §7/§8): factor summary plus the
		// TOTP and passkey lifecycle. Mutations consume a step-up reauth
		// grant; enrollment confirmations consume the single-use
		// enrollmentToken minted at the begin step.
		r.Group(func(r chi.Router) {
			if sessionSvc != nil {
				r.Use(httpapi.RequireSession(sessionSvc, userChecker, securityGate, cookieAttrs, logger))
				r.Use(httpapi.RequireCSRF())
			}
			if securityHandlers != nil {
				r.Get("/me/security", securityHandlers.GetSecurityFactors)
				r.Post("/me/security/totp/enrollment", securityHandlers.BeginTOTPEnrollment)
				r.Post("/me/security/totp/enrollment/confirm", securityHandlers.ConfirmTOTPEnrollment)
				r.Post("/me/security/totp/enrollment/cancel", securityHandlers.CancelTOTPEnrollment)
				r.Delete("/me/security/totp", securityHandlers.RemoveTOTP)
				r.Post("/me/security/passkeys/enrollment", securityHandlers.BeginPasskeyEnrollment)
				r.Post("/me/security/passkeys/enrollment/confirm", securityHandlers.ConfirmPasskeyEnrollment)
				r.Post("/me/security/passkeys/enrollment/cancel", securityHandlers.CancelPasskeyEnrollment)
				r.Delete("/me/security/passkeys/{passkeyId}", securityHandlers.RemovePasskey)
			}
			if passwordHandlers != nil {
				r.Post("/me/security/password", passwordHandlers.ChangePassword)
			}
		})

		// Admin application management plane (session + CSRF required;
		// capability checks happen inside the handlers).
		r.Group(func(r chi.Router) {
			if sessionSvc != nil {
				r.Use(httpapi.RequireSession(sessionSvc, userChecker, securityGate, cookieAttrs, logger))
				r.Use(httpapi.RequireCSRF())
			}
			if appHandlers != nil {
				r.Get("/admin/scopes", appHandlers.ListScopes)
				r.Post("/admin/applications/with-initial-client", appHandlers.CreateWithInitialClient)
				r.Get("/admin/applications", appHandlers.ListApplications)
				r.Get("/admin/applications/{applicationId}", appHandlers.GetApplication)
				r.Patch("/admin/applications/{applicationId}", appHandlers.UpdateApplication)
				r.Post("/admin/applications/{applicationId}/enable", appHandlers.EnableApplication)
				r.Post("/admin/applications/{applicationId}/disable", appHandlers.DisableApplication)
				r.Delete("/admin/applications/{applicationId}", appHandlers.DeleteApplication)
				r.Post("/admin/applications/{applicationId}/clients", appHandlers.CreateClient)
				r.Get("/admin/applications/{applicationId}/clients/{clientId}", appHandlers.GetClient)
				r.Patch("/admin/applications/{applicationId}/clients/{clientId}", appHandlers.UpdateClient)
				r.Post("/admin/applications/{applicationId}/clients/{clientId}/enable", appHandlers.EnableClient)
				r.Post("/admin/applications/{applicationId}/clients/{clientId}/disable", appHandlers.DisableClient)
				r.Delete("/admin/applications/{applicationId}/clients/{clientId}", appHandlers.DeleteClient)
				r.Post("/admin/applications/{applicationId}/clients/{clientId}/secret-rotations", appHandlers.RotateClientSecret)
			}
			if dashboardHandlers != nil {
				r.Get("/admin/dashboard", dashboardHandlers.Get)
			}
		})

		// Phase 5 identity and workforce management plane (ADR-0011). All
		// routes require session + CSRF; reads and mutations independently
		// resolve their capability inside WorkforceHandlers. High-risk target
		// operations additionally consume target-bound reauth grants.
		r.Group(func(r chi.Router) {
			if sessionSvc != nil {
				r.Use(httpapi.RequireSession(sessionSvc, userChecker, securityGate, cookieAttrs, logger))
				r.Use(httpapi.RequireCSRF())
			}
			if workforceHandlers != nil {
				r.Get("/admin/users", workforceHandlers.ListUsers)
				r.Get("/admin/users/{userId}", workforceHandlers.GetUser)
				r.Post("/admin/users/{userId}/enable", workforceHandlers.EnableUser)
				r.Post("/admin/users/{userId}/disable", workforceHandlers.DisableUser)
				r.Delete("/admin/users/{userId}/sessions", workforceHandlers.RevokeUserSessions)
				r.Delete("/admin/users/{userId}/sessions/{sessionId}", workforceHandlers.RevokeUserSession)

				r.Get("/admin/employees", workforceHandlers.ListEmployees)
				r.Post("/admin/employees/link", workforceHandlers.LinkEmployee)
				r.Get("/admin/users/{userId}/employee-profile", workforceHandlers.GetEmployee)
				r.Put("/admin/users/{userId}/employee-profile", workforceHandlers.UpdateEmployee)
				r.Post("/admin/users/{userId}/offboarding", workforceHandlers.OffboardEmployee)

				r.Get("/admin/departments", workforceHandlers.ListDepartments)
				r.Post("/admin/departments", workforceHandlers.CreateDepartment)
				r.Get("/admin/departments/{departmentId}", workforceHandlers.GetDepartment)
				r.Patch("/admin/departments/{departmentId}", workforceHandlers.UpdateDepartment)
				r.Delete("/admin/departments/{departmentId}", workforceHandlers.DeleteDepartment)
			}
		})

		// Phase 6 Feishu Provider administration (ADR-0012). Reads and writes
		// independently resolve provider capabilities. Enabling/disabling and
		// explicit identity linking consume target-bound single-use reauth
		// grants; directory synchronization returns a durable 202 job.
		r.Group(func(r chi.Router) {
			if sessionSvc != nil {
				r.Use(httpapi.RequireSession(sessionSvc, userChecker, securityGate, cookieAttrs, logger))
				r.Use(httpapi.RequireCSRF())
			}
			if providerHandlers != nil {
				r.Get("/admin/identity-providers", providerHandlers.ListProviders)
				r.Get("/admin/identity-providers/{providerId}", providerHandlers.GetProvider)
				r.Post("/admin/identity-providers/{providerId}/enable", providerHandlers.EnableProvider)
				r.Post("/admin/identity-providers/{providerId}/disable", providerHandlers.DisableProvider)
				r.Post("/admin/identity-providers/{providerId}/directory-syncs", providerHandlers.StartDirectorySync)
				r.Get("/admin/identity-providers/{providerId}/directory-syncs", providerHandlers.ListSyncHistory)
				r.Get("/admin/identity-providers/{providerId}/sync-conflicts", providerHandlers.ListConflicts)
				r.Post("/admin/identity-providers/sync-conflicts/{conflictId}/resolve", providerHandlers.ResolveConflict)
				r.Post("/admin/identity-providers/sync-conflicts/{conflictId}/ignore", providerHandlers.IgnoreConflict)
			}
		})

		// Phase 7 policy authority and audit plane (ADR-0013). All handlers
		// independently enforce Cerbos-derived capabilities. Publishing and
		// export creation consume target-bound single-use reauthentication.
		r.Group(func(r chi.Router) {
			if sessionSvc != nil {
				r.Use(httpapi.RequireSession(sessionSvc, userChecker, securityGate, cookieAttrs, logger))
				r.Use(httpapi.RequireCSRF())
			}
			if policyHandlers != nil {
				r.Get("/admin/policies", policyHandlers.List)
				r.Post("/admin/policies", policyHandlers.Create)
				r.Get("/admin/policies/{policyId}", policyHandlers.Get)
				r.Patch("/admin/policies/{policyId}", policyHandlers.Update)
				r.Post("/admin/policies/{policyId}/publish", policyHandlers.Publish)
				r.Post("/admin/policies/{policyId}/simulate", policyHandlers.Simulate)
				r.Get("/admin/policies/{policyId}/versions", policyHandlers.Versions)
			}
			if auditHandlers != nil {
				r.Get("/admin/audit-events", auditHandlers.List)
				r.Post("/admin/audit-exports", auditHandlers.CreateExport)
				r.Get("/admin/audit-exports/{exportId}", auditHandlers.GetExport)
				r.Get("/admin/audit-exports/{exportId}/download", auditHandlers.Download)
			}
		})
	})

	srv := &http.Server{
		Addr:              cfg.HTTPAddr,
		Handler:           router,
		ReadHeaderTimeout: cfg.ReadHeaderTimeout,
		ReadTimeout:       cfg.ReadTimeout,
		WriteTimeout:      cfg.WriteTimeout,
		IdleTimeout:       cfg.IdleTimeout,
	}
	if wechatIntentCleanup != nil {
		wechatIntentCleanup.Start()
		workerStops = append(workerStops, wechatIntentCleanup.Stop)
	}
	if wechatOnboardingCleanup != nil {
		wechatOnboardingCleanup.Start()
		workerStops = append(workerStops, wechatOnboardingCleanup.Stop)
	}
	if wechatNotificationWorker != nil {
		wechatNotificationWorker.Start()
		workerStops = append(workerStops, wechatNotificationWorker.Stop)
	}

	server := &Server{
		HTTP:              srv,
		Router:            router,
		logger:            logger,
		config:            cfg,
		pool:              pool,
		isolatedPool:      isolatedPool,
		redisClient:       redisClient,
		providerCloser:    providerCloser,
		dreamUPAuthorizer: dreamUPAuthorizer,
		workerStops:       workerStops,
	}
	isolatedPoolTransferred = true
	return server, nil
}

// buildAuthenticator selects the authentication provider implementation.
//
//   - "":          fake, non-production only
//   - "fake":      fake, non-production only
//   - "zitadel":   ZITADEL LoginV2 adapter (Phase 1.2), all environments
//   - other:       startup error in all environments (ADR-0003)
//
// The fake must never serve production traffic, and a misspelled or unknown
// provider must not silently fall back to it. The ZITADEL adapter requires a
// database-backed user linker for first-login identity mapping. The returned
// closer (nil for the fake) closes the provider's underlying connection; the
// returned SDK client (nil for the fake) is reused by the application
// management provisioner.
func buildAuthenticator(
	cfg config.Config,
	userLinker identity.UserLinker,
	logger *slog.Logger,
) (auth.Authenticator, *zitadelsdk.Client, interface{ Close() error }, error) {
	switch cfg.Auth.Provider {
	case "":
		if cfg.IsProduction() {
			return nil, nil, nil, errors.New("production requires a configured authentication provider")
		}
		logger.Info("using fake authenticator for development")
		return createDevAuthenticator(), nil, nil, nil

	case "fake":
		if cfg.IsProduction() {
			return nil, nil, nil, errors.New("production must not use the fake authenticator")
		}
		logger.Info("using fake authenticator for development")
		return createDevAuthenticator(), nil, nil, nil

	case zitadel.ProviderName:
		if !cfg.HasAuthProvider() {
			return nil, nil, nil, errors.New("zitadel provider requires UP_AUTH_PROVIDER_BASE_URL")
		}
		if userLinker == nil {
			return nil, nil, nil, errors.New("zitadel provider requires database configuration for identity mapping")
		}
		zc, err := zitadel.NewSDKClient(context.Background(), cfg.Auth)
		if err != nil {
			return nil, nil, nil, err
		}
		authz := zitadel.NewAuthenticator(
			zc.SessionServiceV2(),
			zc.UserServiceV2(),
			userLinker,
			cfg.Auth.ProjectID,
			cfg.Auth.Domain,
			logger,
		)
		logger.Info("authentication provider initialized", "provider", zitadel.ProviderName)
		return authz, zc, zc, nil

	default:
		return nil, nil, nil, fmt.Errorf("authentication provider %q has no implemented adapter", cfg.Auth.Provider)
	}
}

// newSessionEncryptor builds the AES-GCM encryptor for provider session
// references from configuration. It returns a nil encryptor (no error) only
// when no key is configured — the caller guarantees no provider references
// will be stored, or refuses them at session creation. An invalid key
// (malformed base64, wrong length) is a bootstrap error: the service must not
// start with a key that silently cannot encrypt.
func newSessionEncryptor(cfg config.Config) (session.Encryptor, error) {
	if cfg.Session.EncryptionKey == "" {
		return nil, nil
	}
	enc, err := session.NewAESGCMEncryptor(cfg.Session.EncryptionKey, cfg.Session.EncryptionKeyID)
	if err != nil {
		return nil, err
	}
	return enc, nil
}

// newWeChatOnboardingEncryptor constructs the dedicated AEAD boundary for
// short-lived onboarding and MFA challenges. It is intentionally unavailable
// while the feature is disabled, and it refuses session-key reuse even when
// the same key bytes are supplied through a different base64 representation.
func newWeChatOnboardingEncryptor(cfg config.Config) (session.Encryptor, error) {
	if !cfg.WeChatMiniProgram.OnboardingEnabled {
		return nil, nil
	}
	keyB64 := cfg.WeChatMiniProgram.OnboardingEncryptionKey
	keyID := cfg.WeChatMiniProgram.OnboardingEncryptionKeyID
	if keyB64 == "" || strings.TrimSpace(keyID) == "" {
		return nil, errors.New("dedicated key and key ID are required")
	}
	if keyID != strings.TrimSpace(keyID) || strings.Contains(keyID, ":") {
		return nil, errors.New("key ID must be non-empty, trimmed and must not contain ':'")
	}
	onboardingKey, err := base64.StdEncoding.DecodeString(keyB64)
	if err != nil {
		return nil, errors.New("key must be base64-encoded")
	}
	if len(onboardingKey) != 32 {
		return nil, fmt.Errorf("key must decode to 32 bytes, got %d", len(onboardingKey))
	}
	if cfg.Session.EncryptionKey != "" {
		sessionKey, sessionErr := base64.StdEncoding.DecodeString(cfg.Session.EncryptionKey)
		if sessionErr == nil && bytes.Equal(onboardingKey, sessionKey) {
			return nil, errors.New("key material must be distinct from the session encryption key")
		}
	}
	retained, err := config.ParseWeChatOnboardingRetainedDecryptionKeys(cfg.WeChatMiniProgram.OnboardingRetainedDecryptionKeys)
	if err != nil {
		return nil, errors.New("retained decryption keyring is invalid")
	}
	if cfg.Session.EncryptionKey != "" {
		sessionKey, sessionErr := base64.StdEncoding.DecodeString(cfg.Session.EncryptionKey)
		if sessionErr == nil {
			for _, retainedKeyB64 := range retained {
				retainedKey, decodeErr := base64.StdEncoding.DecodeString(retainedKeyB64)
				if decodeErr == nil && bytes.Equal(retainedKey, sessionKey) {
					return nil, errors.New("retained key material must be distinct from the session encryption key")
				}
			}
		}
	}
	return session.NewAESGCMKeyring(keyB64, keyID, retained)
}

// Run starts the HTTP server. It blocks until the server stops accepting
// connections and returns the resulting error.
func (s *Server) Run() error {
	s.logger.Info("http server starting",
		"addr", s.config.HTTPAddr,
		"environment", string(s.config.Environment),
	)
	err := s.HTTP.ListenAndServe()
	if err != nil && err != http.ErrServerClosed {
		return err
	}
	return nil
}

// Shutdown gracefully stops the server, waiting up to the configured
// ShutdownTimeout for in-flight requests to complete. It also closes the
// PostgreSQL pool and Redis client.
func (s *Server) Shutdown(ctx context.Context) error {
	shutdownCtx, cancel := context.WithTimeout(ctx, s.config.ShutdownTimeout)
	defer cancel()

	s.logger.Info("http server shutting down", "timeout", s.config.ShutdownTimeout.String())
	if err := s.HTTP.Shutdown(shutdownCtx); err != nil {
		s.logger.Error("graceful shutdown failed", "error", err)
	}

	// Stop background workers before their infrastructure (Redis) closes.
	for _, stop := range s.workerStops {
		stop()
	}

	if s.redisClient != nil {
		if err := s.redisClient.Close(); err != nil {
			s.logger.Error("redis close failed", "error", err)
		}
	}

	if s.providerCloser != nil {
		if err := s.providerCloser.Close(); err != nil {
			s.logger.Error("authentication provider close failed", "error", err)
		}
	}

	if s.pool != nil {
		s.pool.Close()
	}
	if s.isolatedPool != nil {
		s.isolatedPool.Close()
	}

	s.logger.Info("http server stopped")
	return nil
}

// Config returns the loaded configuration.
func (s *Server) Config() config.Config { return s.config }

// sessionSecurityAuditor adapts the canonical durable security event store
// to the session package's narrow SecurityAuditor seam (ADR-0004 §8 /
// ADR-0006 §2). It keeps the session package free of application-plane
// dependencies; the composition root owns the mapping. Session events carry
// no application/client references, so those columns stay empty.
type sessionSecurityAuditor struct {
	store *postgres.SecurityEventStore
}

type registrationAbuseAuditor struct {
	store *postgres.SecurityEventStore
}

// accountContactEmailValidator translates the registration delivery policy's
// narrow error contract into accountcontact's domain errors. Both flows share
// the same cached domain/MX validator instance without coupling the two domain
// packages to one another.
type accountContactEmailValidator struct {
	inner registration.EmailValidator
}

func (v *accountContactEmailValidator) Validate(ctx context.Context, email string) error {
	if v == nil || v.inner == nil {
		return accountcontact.ErrUnavailable
	}
	if err := v.inner.Validate(ctx, email); err != nil {
		if errors.Is(err, registration.ErrInvalidInput) {
			return accountcontact.ErrInvalidInput
		}
		return accountcontact.ErrUnavailable
	}
	return nil
}

func newRegistrationAbuseAuditor(store *postgres.SecurityEventStore) *registrationAbuseAuditor {
	return &registrationAbuseAuditor{store: store}
}

func (a *registrationAbuseAuditor) RecordRegistrationAbuse(ctx context.Context, event registration.AbuseAuditEvent) error {
	if a == nil || a.store == nil {
		return registration.ErrUnavailable
	}
	extra := map[string]string{
		"reason":                   event.Reason.String(),
		"client_ip_hash":           event.Fingerprint.ClientIPHash,
		"client_ip_block_eligible": strconv.FormatBool(event.Fingerprint.ClientIPBlockEligible),
		"user_agent_hash":          event.Fingerprint.UserAgentHash,
		"ip_strike_count":          strconv.Itoa(event.Disposition.IPStrikeCount),
		"ip_blocked":               strconv.FormatBool(event.Disposition.IPBlocked),
		"long_ip_block":            strconv.FormatBool(event.Disposition.LongIPBlock),
	}
	if event.Fingerprint.DeviceIDHash != "" {
		extra["device_id_hash"] = event.Fingerprint.DeviceIDHash
	}
	return a.store.Record(ctx, applications.SecurityEvent{
		EventID: applications.NewSecurityEventID(), EventType: "registration.honeypot_triggered",
		RequestID: event.RequestID, Operation: "registration.create", Result: applications.SecurityEventDenied,
		TargetKey: "client_ip_hash", TargetID: event.Fingerprint.ClientIPHash, Extra: extra, OccurredAt: event.OccurredAt,
	})
}

func newSessionSecurityAuditor(store *postgres.SecurityEventStore) *sessionSecurityAuditor {
	return &sessionSecurityAuditor{store: store}
}

func (a *sessionSecurityAuditor) RecordSessionEvent(ctx context.Context, ev session.SecurityAuditEvent) error {
	requestID := ev.RequestID
	if requestID == "" {
		requestID = request.ID(ctx)
	}
	return a.store.Record(ctx, toCanonicalSecurityEvent(ev, requestID))
}

// reauthSecurityAuditor keeps the shared reauthentication plane independent
// from OAuth application provisioning while writing to the same canonical
// audit table. Recording remains best-effort at this narrow seam, matching
// ReauthEventRecorder semantics.
type reauthSecurityAuditor struct {
	store *postgres.SecurityEventStore
}

type qrAuthSecurityAuditor struct {
	store *postgres.SecurityEventStore
}

func newQRAuthSecurityAuditor(store *postgres.SecurityEventStore) *qrAuthSecurityAuditor {
	return &qrAuthSecurityAuditor{store: store}
}

func (a *qrAuthSecurityAuditor) RecordQRAuthEvent(ctx context.Context, event httpapi.QRAuthAuditEvent) error {
	if a == nil || a.store == nil || event.ChallengeReference == "" {
		return errors.New("QR authentication audit unavailable")
	}
	var eventType string
	switch event.EventType {
	case "qr_login.approval_requested":
		eventType = applications.EventQRLoginApprovalRequested
	case "qr_login.receiver_verified":
		eventType = applications.EventQRLoginReceiverVerified
	case "qr_login.receiver_rejected":
		eventType = applications.EventQRLoginReceiverRejected
	default:
		return errors.New("unknown QR authentication audit event")
	}
	var result applications.SecurityEventResult
	switch event.Result {
	case "success":
		result = applications.SecurityEventSuccess
	case "denied":
		result = applications.SecurityEventDenied
	default:
		return errors.New("invalid QR authentication audit result")
	}
	requestID := event.RequestID
	if requestID == "" {
		requestID = request.ID(ctx)
	}
	return a.store.Record(ctx, applications.SecurityEvent{EventID: applications.NewSecurityEventID(), EventType: eventType, ActorUserID: event.ActorUserID, RequestID: requestID, Operation: event.Operation, Result: result, FailureClass: event.FailureClass, TargetKey: "qr_challenge_hash", TargetID: event.ChallengeReference, OccurredAt: time.Now().UTC()})
}

func newReauthSecurityAuditor(store *postgres.SecurityEventStore) *reauthSecurityAuditor {
	return &reauthSecurityAuditor{store: store}
}

func (a *reauthSecurityAuditor) RecordEvent(ctx context.Context, eventType string,
	actor identity.UserID, appID applications.ApplicationID, clientID applications.OAuthClientID,
	requestID, operation string, result applications.SecurityEventResult, failureClass string,
) error {
	if a == nil || a.store == nil {
		return errors.New("reauth security audit unavailable")
	}
	return a.store.Record(ctx, applications.SecurityEvent{
		EventID: applications.NewSecurityEventID(), EventType: eventType,
		ActorUserID: actor, ApplicationID: appID, ClientID: clientID,
		RequestID: requestID, Operation: operation, Result: result,
		FailureClass: failureClass, OccurredAt: time.Now().UTC(),
	})
}

// toCanonicalSecurityEvent maps the session package's audit event onto the
// canonical durable security event. Session events carry no
// application/client references, so those columns stay empty; the target
// session ID and the provider-cleanup failure class travel through the
// generic payload seam so they reach the durable JSONB payload (ADR-0006
// §2).
func toCanonicalSecurityEvent(ev session.SecurityAuditEvent, requestID string) applications.SecurityEvent {
	return applications.SecurityEvent{
		EventID:      applications.NewSecurityEventID(),
		EventType:    ev.EventType,
		ActorUserID:  ev.ActorUserID,
		RequestID:    requestID,
		Operation:    ev.Operation,
		Result:       applications.SecurityEventResult(ev.Result),
		FailureClass: ev.FailureClass,
		TargetKey:    "session_id",
		TargetID:     string(ev.SessionID),
		Extra:        settlementAuditExtra(ev),
		OccurredAt:   ev.OccurredAt,
	}
}

// settlementAuditExtra carries the ADR-0007 Decision 5 additive settlement
// facts (providerOutcome, settlementOutcome and their forensic context)
// into the durable JSONB payload without touching the frozen result model.
// Zero values are omitted.
func settlementAuditExtra(ev session.SecurityAuditEvent) map[string]string {
	extra := map[string]string{}
	if ev.ProviderOutcome != "" {
		extra["provider_outcome"] = ev.ProviderOutcome
	}
	if ev.SettlementOutcome != "" {
		extra["settlement_outcome"] = ev.SettlementOutcome
	}
	if ev.IntentID != 0 {
		extra["intent_id"] = strconv.FormatInt(ev.IntentID, 10)
	}
	if ev.FromEpoch != 0 {
		extra["from_epoch"] = strconv.FormatInt(ev.FromEpoch, 10)
	}
	if ev.ToEpoch != 0 {
		extra["to_epoch"] = strconv.FormatInt(ev.ToEpoch, 10)
	}
	if ev.AffectedCount > 0 {
		extra["revoked_count"] = strconv.Itoa(ev.AffectedCount)
	}
	if ev.ProviderFailureClass != "" {
		extra["provider_failure_class"] = ev.ProviderFailureClass
	}
	if len(extra) == 0 {
		return nil
	}
	return extra
}

// userStatusChecker adapts postgres.UserRepository to the UserStatusChecker
// interface. It checks whether the user exists and is still active.
type userStatusChecker struct {
	repo userGetter
}

type userGetter interface {
	GetByID(ctx context.Context, userID identity.UserID) (identity.User, error)
}

func (c *userStatusChecker) CanUseSession(ctx context.Context, userID identity.UserID) error {
	user, err := c.repo.GetByID(ctx, userID)
	if err != nil {
		return err
	}
	if !user.Status.CanAuthenticate() {
		return identity.ErrUserNotFound
	}
	return nil
}

// postgresReadinessChecker adapts postgres.Pool to the ReadinessChecker
// interface. postgres.Pool.Ping takes a timeout parameter, so we wrap it.
type postgresReadinessChecker struct {
	pool    *postgres.Pool
	timeout time.Duration
}

func NewPostgresReadinessChecker(pool *postgres.Pool, timeout time.Duration) *postgresReadinessChecker {
	return &postgresReadinessChecker{pool: pool, timeout: timeout}
}

func (c *postgresReadinessChecker) Name() string { return "postgresql" }

func (c *postgresReadinessChecker) Check(ctx context.Context) error {
	return c.pool.Ping(ctx, c.timeout)
}

// projectReadinessChecker verifies that the OAuth provisioning project is
// readable through the provider Management API. It is registered only for the
// real (ZITADEL) provisioner; the fake development provisioner has no project
// to verify.
type projectReadinessChecker struct {
	verifier interface {
		VerifyProject(ctx context.Context) error
	}
	timeout time.Duration
}

func newProjectReadinessChecker(verifier interface {
	VerifyProject(ctx context.Context) error
}, timeout time.Duration) *projectReadinessChecker {
	if timeout <= 0 {
		timeout = 3 * time.Second
	}
	return &projectReadinessChecker{verifier: verifier, timeout: timeout}
}

func (c *projectReadinessChecker) Name() string { return "auth_project" }

func (c *projectReadinessChecker) Check(ctx context.Context) error {
	checkCtx, cancel := context.WithTimeout(ctx, c.timeout)
	defer cancel()
	if err := c.verifier.VerifyProject(checkCtx); err != nil {
		return fmt.Errorf("auth project: %w", err)
	}
	return nil
}

// createDevAuthenticator creates a FakeAuthenticator with a test user for local
// development. This is NOT for production use.
func createDevAuthenticator() *auth.FakeAuthenticator {
	f := auth.NewFakeAuthenticator()
	f.AddUser(auth.FakeUser{
		UserID:      identity.UserID("user_01JZDEVTEST001"),
		Identifier:  "zhixing.lin",
		Password:    "TestPassword123!",
		UserStatus:  identity.UserStatusActive,
		Provider:    "united-pass-fake",
		SessionRef:  "fake-session-ref-001",
		RequiresMFA: false,
	})
	f.AddUser(auth.FakeUser{
		UserID:      identity.UserID("user_01JZDEVTEST002"),
		Identifier:  "mfa.user",
		Password:    "TestPassword123!",
		UserStatus:  identity.UserStatusActive,
		Provider:    "united-pass-fake",
		SessionRef:  "fake-session-ref-002",
		RequiresMFA: true,
		MFAMethods:  []auth.MFAMethod{auth.MFAMethodTOTP, auth.MFAMethodRecovery},
		MFACode:     "123456",
	})
	return f
}

// fakeUserReader is an in-memory UserReader used only with the fake
// authenticator for local development. It returns hardcoded user records for
// the two dev users so that GET /api/v1/me works without populating
// PostgreSQL.
type fakeUserReader struct{}

func (fakeUserReader) GetByID(_ context.Context, userID identity.UserID) (identity.User, error) {
	now := time.Now().UTC()
	switch userID {
	case "user_01JZDEVTEST001":
		return identity.User{
			ID:            "user_01JZDEVTEST001",
			Status:        identity.UserStatusActive,
			DisplayName:   "Zhixing Lin",
			Nickname:      "Zhixing",
			Email:         "zhixing.lin@example.com",
			EmailVerified: true,
			Personas:      []identity.Persona{identity.PersonaConsumer},
			Version:       1,
			CreatedAt:     now,
			UpdatedAt:     now,
		}, nil
	case "user_01JZDEVTEST002":
		return identity.User{
			ID:            "user_01JZDEVTEST002",
			Status:        identity.UserStatusActive,
			DisplayName:   "MFA User",
			Nickname:      "MFA",
			Email:         "mfa.user@example.com",
			EmailVerified: true,
			Personas:      []identity.Persona{identity.PersonaConsumer},
			Version:       1,
			CreatedAt:     now,
			UpdatedAt:     now,
		}, nil
	default:
		return identity.User{}, identity.ErrUserNotFound
	}
}
