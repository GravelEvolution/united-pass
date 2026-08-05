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
	"github.com/GravelEvolution/united-pass/backend/internal/auth"
	"github.com/GravelEvolution/united-pass/backend/internal/config"
	"github.com/GravelEvolution/united-pass/backend/internal/identity"
	"github.com/GravelEvolution/united-pass/backend/internal/permissions"
	"github.com/GravelEvolution/united-pass/backend/internal/session"
)

// Server bundles the configured *http.Server with its router so the entry point
// can start it and shut it down.
type Server struct {
	HTTP        *http.Server
	Router      http.Handler
	logger      *slog.Logger
	config      config.Config
	pool        *postgres.Pool
	redisClient *redis.Client
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

	// Session service.
	var sessionSvc *session.Service
	var userChecker httpapi.UserStatusChecker
	var userReader httpapi.UserReader
	var permResolver permissions.Resolver
	var authenticator auth.Authenticator
	var mfaStore httpapi.MFAChallengeStore
	var rateChecker httpapi.RateChecker

	if redisClient != nil {
		sessionStore := redis.NewSessionStore(redisClient)
		sessionSvc = session.NewService(sessionStore, session.SystemClock{},
			cfg.Session.TTL, cfg.Session.RememberTTL,
			cfg.Session.IdleTTL, cfg.Session.TouchInterval,
			newSessionEncryptor(cfg, logger))

		mfaStore = redis.NewMFAStore(redisClient)
		rateChecker = redis.NewRateLimiter(redisClient)
	}

	if pool != nil {
		userRepo := postgres.NewUserRepository(pool.PgxPool())
		userReader = userRepo
		userChecker = &userStatusChecker{repo: userRepo}
	}

	// Permission resolver: fail-closed by default, with optional dev override.
	permResolver = permissions.NewResolver(cfg)

	// Authenticator selection enforces the production safety boundary: the
	// development fake must never serve production traffic, and a production
	// deployment must not start with an unimplemented provider adapter.
	authenticator, err := buildAuthenticator(cfg, logger)
	if err != nil {
		return nil, err
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
		HTTP:        srv,
		Router:      router,
		logger:      logger,
		config:      cfg,
		pool:        pool,
		redisClient: redisClient,
	}, nil
}

// buildAuthenticator selects the authentication provider implementation. The
// development fake is permitted only in non-production environments. In
// production, a configured provider without an implemented adapter is a
// startup error: the service must never present the fake as a real identity
// provider.
func buildAuthenticator(cfg config.Config, logger *slog.Logger) (auth.Authenticator, error) {
	if cfg.IsProduction() {
		if !cfg.HasAuthProvider() {
			return nil, errors.New("production requires a configured authentication provider")
		}
		// No real provider adapter is implemented yet (Phase 6). Refuse to
		// start rather than silently authenticate with the development fake.
		return nil, fmt.Errorf("authentication provider %q has no implemented adapter", cfg.Auth.Provider)
	}

	if cfg.Auth.Provider != "" && cfg.Auth.Provider != "fake" {
		logger.Warn("authentication provider adapter not implemented; using fake for development",
			"provider", cfg.Auth.Provider)
	} else {
		logger.Info("using fake authenticator for development")
	}
	return createDevAuthenticator(), nil
}

// newSessionEncryptor builds the AES-GCM encryptor for provider session
// references from configuration. It returns nil when no key is configured
// (tests, or development without provider references); production validation
// requires UP_SESSION_ENCRYPTION_KEY, and a session with a provider reference
// is refused at creation time when the encryptor is nil.
func newSessionEncryptor(cfg config.Config, logger *slog.Logger) session.Encryptor {
	if cfg.Session.EncryptionKey == "" {
		if cfg.IsProduction() {
			logger.Error("production requires UP_SESSION_ENCRYPTION_KEY; provider session references will be refused")
		}
		return nil
	}
	enc, err := session.NewAESGCMEncryptor(cfg.Session.EncryptionKey, cfg.Session.EncryptionKeyID)
	if err != nil {
		logger.Error("session encryption key invalid; provider session references will be refused",
			"error", err)
		return nil
	}
	return enc
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
