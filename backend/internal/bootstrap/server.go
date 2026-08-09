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
	"context"
	"errors"
	"fmt"
	"log/slog"
	"net/http"
	"time"

	"github.com/go-chi/chi/v5"
	zitadelsdk "github.com/zitadel/zitadel-go/v3/pkg/client"

	"github.com/GravelEvolution/united-pass/backend/internal/adapters/httpapi"
	"github.com/GravelEvolution/united-pass/backend/internal/adapters/httpapi/request"
	"github.com/GravelEvolution/united-pass/backend/internal/adapters/postgres"
	"github.com/GravelEvolution/united-pass/backend/internal/adapters/redis"
	"github.com/GravelEvolution/united-pass/backend/internal/adapters/zitadel"
	"github.com/GravelEvolution/united-pass/backend/internal/applications"
	"github.com/GravelEvolution/united-pass/backend/internal/auth"
	"github.com/GravelEvolution/united-pass/backend/internal/config"
	"github.com/GravelEvolution/united-pass/backend/internal/consent"
	"github.com/GravelEvolution/united-pass/backend/internal/identity"
	"github.com/GravelEvolution/united-pass/backend/internal/permissions"
	"github.com/GravelEvolution/united-pass/backend/internal/session"
)

// Server bundles the configured *http.Server with its router so the entry point
// can start it and shut it down.
type Server struct {
	HTTP           *http.Server
	Router         http.Handler
	logger         *slog.Logger
	config         config.Config
	pool           *postgres.Pool
	redisClient    *redis.Client
	providerCloser interface{ Close() error }
	// workerStops stops background workers (e.g. the abandoned reauth
	// challenge cleanup worker) before infrastructure is closed.
	workerStops []func()
}

// NewServer constructs the router, applies middleware, mounts routes and
// returns a Server wrapping a configured *http.Server. It creates
// infrastructure (PostgreSQL pool, Redis client) based on configuration and
// wires all Phase 1 handlers.
//
// NewServer returns an error when the configuration demands an authentication
// provider adapter that is not implemented (always the case in production),
// or when the configured session encryption key is unusable.
func NewServer(cfg config.Config, logger *slog.Logger) (*Server, error) {
	router := chi.NewRouter()

	router.Use(httpapi.MaxBodyBytes(cfg.MaxRequestBodyBytes))
	router.Use(httpapi.RequestID)
	router.Use(httpapi.SecurityHeaders)
	router.Use(httpapi.AccessLog(logger))
	router.Use(httpapi.Recovery(logger, cfg))

	// Infrastructure — created based on configuration. When database or Redis
	// URLs are absent (e.g. local dev without remote services), the server
	// starts but readiness checks will fail for those dependencies.
	var pool *postgres.Pool
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
	var userLinker identity.UserLinker
	var permResolver permissions.Resolver
	var authenticator auth.Authenticator
	var sdkClient *zitadelsdk.Client
	var providerCloser interface{ Close() error }
	var mfaStore httpapi.MFAChallengeStore
	var rateChecker httpapi.RateChecker
	var sessionAuditor session.SecurityAuditor

	if pool != nil {
		userRepo := postgres.NewUserRepository(pool.PgxPool())
		userReader = userRepo
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
		sessionSvc = session.NewService(sessionStore, session.SystemClock{},
			cfg.Session.TTL, cfg.Session.RememberTTL,
			cfg.Session.IdleTTL, cfg.Session.TouchInterval,
			encryptor,
			sessionOpts...)

		mfaStore = redis.NewMFAStore(redisClient)
		rateChecker = redis.NewRateLimiter(redisClient)
	}

	// Permission resolver: fail-closed by default, with optional dev override.
	permResolver = permissions.NewResolver(cfg)

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
	var workerStops []func()
	if pool != nil && provisioner != nil && userReader != nil && sessionSvc != nil && cfg.Session.EncryptionKey != "" {
		var err error
		appRepo, err = postgres.NewApplicationRepository(pool.PgxPool(), cfg.Session.EncryptionKey)
		if err != nil {
			return nil, fmt.Errorf("application repository: %w", err)
		}
		eventStore := postgres.NewSecurityEventStore(pool.PgxPool())
		appSvc := applications.NewService(appRepo, provisioner, eventStore, eventStore, userReader,
			providerName, cfg.Auth.ProjectID, cfg.Rotation.GracePeriod)

		// Reauthentication and rotation infrastructure follow Redis
		// availability; both fail closed while it is absent (ADR-0004 §6/§7).
		var reauthVerifier httpapi.ReauthVerifier
		var rotationRates httpapi.RotationRateChecker
		if redisClient != nil {
			limiter := redis.NewRateLimiter(redisClient)
			rotationRates = limiter
			reauthStore := redis.NewReauthStore(redisClient)
			reauthVerifier = httpapi.NewReauthGrants(reauthStore)
			if reauthAuth, ok := authenticator.(httpapi.ReauthAuthenticator); ok {
				reauthHandlers = httpapi.NewReauthHandlers(
					reauthAuth, reauthStore, reauthStore, limiter, appSvc,
					cfg.Reauth.ChallengeTTL, cfg.Reauth.GrantTTL,
					cfg.Reauth.MaxAttempts, cfg.Reauth.RateLimit, cfg.Reauth.RateWindow,
					logger)
				// Abandoned/expired challenges leak their temporary provider
				// session unless the cleanup worker revokes them (ADR-0004 §7).
				cleanupWorker := httpapi.NewReauthCleanupWorker(
					reauthAuth, reauthStore, appSvc, cfg.Reauth.CleanupInterval, logger)
				cleanupWorker.Start()
				workerStops = append(workerStops, cleanupWorker.Stop)
			}

			// Account security factor endpoints (ADR-0006 §7/§8): the
			// authenticator doubles as the factor manager (ZITADEL adapter or
			// dev fake). Enrollments follow the grant TTL; both stores share
			// the fail-closed Redis semantics of the reauth infrastructure.
			if factorManager, ok := authenticator.(auth.FactorManager); ok && reauthVerifier != nil {
				securityHandlers = httpapi.NewSecurityHandlers(
					factorManager, reauthVerifier, redis.NewEnrollmentStore(redisClient),
					cfg.Reauth.GrantTTL, logger)
			}

			// Password management (ADR-0006 §6): the authenticator doubles as
			// the password authority (ZITADEL adapter or dev fake). The
			// mutation consumes an account.password.change reauth grant,
			// rotates the current session and revokes all others; the durable
			// audit shares the canonical session security auditor.
			if passwordManager, ok := authenticator.(auth.PasswordManager); ok && reauthVerifier != nil && sessionSvc != nil {
				passwordHandlers = httpapi.NewPasswordHandlers(
					passwordManager, reauthVerifier, sessionSvc, sessionAuditor, cfg, logger)
			}
		}

		appHandlers = httpapi.NewApplicationHandlers(appSvc, permResolver, reauthVerifier,
			rotationRates, cfg.Rotation.RateLimit, cfg.Rotation.RateWindow, logger)
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

	// Authorization Interaction Gateway (ADR-0005 §1, §12): the sole entry
	// point ZITADEL generates for LoginV2 clients, served on the public
	// origin under the /_interaction prefix the reverse proxy routes to
	// this backend. Optional session (prompt=none must run without one);
	// GET-only, every outcome is a 302 or the fixed local failure page.
	router.Group(func(r chi.Router) {
		if sessionSvc != nil {
			r.Use(httpapi.OptionalSession(sessionSvc, userChecker, logger))
		}
		if interactionHandlers != nil {
			r.Get("/_interaction/login", interactionHandlers.InteractionLogin)
		}
	})

	// API v1 routes.
	router.Route("/api/v1", func(r chi.Router) {
		// Auth endpoints (no session required for login/MFA; logout requires
		// session + CSRF).
		authHandlers := httpapi.NewAuthHandlers(
			authenticator, sessionSvc, mfaStore, rateChecker,
			userChecker, cfg, logger)

		r.Post("/auth/sessions", authHandlers.Login)
		r.Post("/auth/sessions/mfa", authHandlers.CompleteMFA)

		// Logout requires session and CSRF.
		r.Group(func(r chi.Router) {
			if sessionSvc != nil {
				r.Use(httpapi.RequireSession(sessionSvc, userChecker, logger))
				r.Use(httpapi.RequireCSRF())
			}
			r.Delete("/auth/session", authHandlers.Logout)
		})

		// Reauthentication for high-risk operations (session + CSRF required;
		// challenges and grants are bound to the session, ADR-0004 §7).
		r.Group(func(r chi.Router) {
			if sessionSvc != nil {
				r.Use(httpapi.RequireSession(sessionSvc, userChecker, logger))
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
				r.Use(httpapi.OptionalSession(sessionSvc, userChecker, logger))
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
				r.Use(httpapi.RequireSession(sessionSvc, userChecker, logger))
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
				r.Use(httpapi.RequireSession(sessionSvc, userChecker, logger))
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
				r.Use(httpapi.RequireSession(sessionSvc, userChecker, logger))
			}
			if userReader != nil && permResolver != nil {
				accountHandlers := httpapi.NewAccountHandlers(userReader, permResolver)
				r.Get("/me", accountHandlers.GetCurrentUser)
				r.Get("/me/permissions", accountHandlers.GetPermissions)
			}
		})

		// Session inventory (ADR-0006 §2): list and revoke the caller's own
		// sessions. GET is a safe method and passes the CSRF middleware; the
		// DELETE mutations additionally require the CSRF token.
		r.Group(func(r chi.Router) {
			if sessionSvc != nil {
				r.Use(httpapi.RequireSession(sessionSvc, userChecker, logger))
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
				r.Use(httpapi.RequireSession(sessionSvc, userChecker, logger))
				r.Use(httpapi.RequireCSRF())
			}
			if securityHandlers != nil {
				r.Get("/me/security", securityHandlers.GetSecurityFactors)
				r.Post("/me/security/totp/enrollment", securityHandlers.BeginTOTPEnrollment)
				r.Post("/me/security/totp/enrollment/confirm", securityHandlers.ConfirmTOTPEnrollment)
				r.Delete("/me/security/totp", securityHandlers.RemoveTOTP)
				r.Post("/me/security/passkeys/enrollment", securityHandlers.BeginPasskeyEnrollment)
				r.Post("/me/security/passkeys/enrollment/confirm", securityHandlers.ConfirmPasskeyEnrollment)
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
				r.Use(httpapi.RequireSession(sessionSvc, userChecker, logger))
				r.Use(httpapi.RequireCSRF())
			}
			if appHandlers != nil {
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

	return &Server{
		HTTP:           srv,
		Router:         router,
		logger:         logger,
		config:         cfg,
		pool:           pool,
		redisClient:    redisClient,
		providerCloser: providerCloser,
		workerStops:    workerStops,
	}, nil
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
		OccurredAt:   ev.OccurredAt,
	}
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
