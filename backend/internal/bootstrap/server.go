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

	"github.com/GravelEvolution/united-pass/backend/internal/adapters/httpapi"
	"github.com/GravelEvolution/united-pass/backend/internal/adapters/postgres"
	"github.com/GravelEvolution/united-pass/backend/internal/adapters/redis"
	"github.com/GravelEvolution/united-pass/backend/internal/adapters/zitadel"
	"github.com/GravelEvolution/united-pass/backend/internal/auth"
	"github.com/GravelEvolution/united-pass/backend/internal/config"
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
	var providerCloser interface{ Close() error }
	var mfaStore httpapi.MFAChallengeStore
	var rateChecker httpapi.RateChecker

	if redisClient != nil {
		sessionStore := redis.NewSessionStore(redisClient)
		sessionSvc = session.NewService(sessionStore, session.SystemClock{},
			cfg.Session.TTL, cfg.Session.RememberTTL,
			cfg.Session.IdleTTL, cfg.Session.TouchInterval,
			encryptor)

		mfaStore = redis.NewMFAStore(redisClient)
		rateChecker = redis.NewRateLimiter(redisClient)
	}

	if pool != nil {
		userRepo := postgres.NewUserRepository(pool.PgxPool())
		userReader = userRepo
		userChecker = &userStatusChecker{repo: userRepo}
		userLinker = userRepo
	}

	// Permission resolver: fail-closed by default, with optional dev override.
	permResolver = permissions.NewResolver(cfg)

	// Authenticator selection: the production safety boundary from Phase 1
	// hardening is preserved, and the ZITADEL adapter (Phase 1.2) is now
	// wired for the "zitadel" provider in all environments.
	authenticator, providerCloser, err = buildAuthenticator(cfg, userLinker, logger)
	if err != nil {
		return nil, err
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

	health := httpapi.NewHealthHandlers(readinessCheckers...)
	router.Get("/healthz", health.Healthz)
	router.Get("/readyz", health.Readyz)

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
// closer (nil for the fake) closes the provider's underlying connection.
func buildAuthenticator(
	cfg config.Config,
	userLinker identity.UserLinker,
	logger *slog.Logger,
) (auth.Authenticator, interface{ Close() error }, error) {
	switch cfg.Auth.Provider {
	case "":
		if cfg.IsProduction() {
			return nil, nil, errors.New("production requires a configured authentication provider")
		}
		logger.Info("using fake authenticator for development")
		return createDevAuthenticator(), nil, nil

	case "fake":
		if cfg.IsProduction() {
			return nil, nil, errors.New("production must not use the fake authenticator")
		}
		logger.Info("using fake authenticator for development")
		return createDevAuthenticator(), nil, nil

	case zitadel.ProviderName:
		if !cfg.HasAuthProvider() {
			return nil, nil, errors.New("zitadel provider requires UP_AUTH_PROVIDER_BASE_URL")
		}
		if userLinker == nil {
			return nil, nil, errors.New("zitadel provider requires database configuration for identity mapping")
		}
		zc, err := zitadel.NewSDKClient(context.Background(), cfg.Auth)
		if err != nil {
			return nil, nil, err
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
		return authz, zc, nil

	default:
		return nil, nil, fmt.Errorf("authentication provider %q has no implemented adapter", cfg.Auth.Provider)
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

// userStatusChecker adapts postgres.UserRepository to the UserStatusChecker
// interface. It checks whether a user exists and is still active.
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
