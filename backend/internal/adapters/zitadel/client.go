//
// Copyright (c) 2026 Chen Jiajie(Ariakage)
//
// Author: Chen Jiajie(Ariakage) <ariakage233@gmail.com>
// Date: 2026-08-05
// Description: ZITADEL API client construction (service account credentials)
//

package zitadel

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/url"
	"os"
	"sync"
	"time"

	"github.com/GravelEvolution/united-pass/backend/internal/config"

	"github.com/zitadel/oidc/v3/pkg/client/profile"
	"github.com/zitadel/zitadel-go/v3/pkg/client"
	"github.com/zitadel/zitadel-go/v3/pkg/zitadel"
	"golang.org/x/oauth2"
)

const (
	serviceAccountTokenRequestTimeout = 5 * time.Second
	serviceAccountTokenEarlyExpiry    = 30 * time.Second
	serviceAccountTokenFailureBackoff = 250 * time.Millisecond
)

// contextTokenSource is the context-aware subset exposed by the ZITADEL OIDC
// JWT-profile source. Keeping it small makes the timeout and cache behavior
// independently testable without handling real service-account key material.
type contextTokenSource interface {
	TokenCtx(context.Context) (*oauth2.Token, error)
}

type tokenRefresh struct {
	done  chan struct{}
	token *oauth2.Token
	err   error
}

// cachedTokenSource caches a valid service-account token and coalesces each
// refresh into one provider request. All concurrent callers waiting for the
// same refresh receive that refresh's result, including errors. A short error
// backoff prevents a failed token endpoint from turning a burst of gRPC calls
// into serialized requestTimeout waits, while allowing recovery quickly.
type cachedTokenSource struct {
	source         contextTokenSource
	requestTimeout time.Duration
	earlyExpiry    time.Duration
	failureBackoff time.Duration
	now            func() time.Time

	mu         sync.Mutex
	token      *oauth2.Token
	inflight   *tokenRefresh
	lastErr    error
	retryAfter time.Time
}

func newCachedTokenSource(source contextTokenSource, requestTimeout, earlyExpiry time.Duration) *cachedTokenSource {
	return &cachedTokenSource{
		source:         source,
		requestTimeout: requestTimeout,
		earlyExpiry:    earlyExpiry,
		failureBackoff: serviceAccountTokenFailureBackoff,
		now:            time.Now,
	}
}

func (s *cachedTokenSource) Token() (*oauth2.Token, error) {
	s.mu.Lock()
	now := s.now()
	if serviceAccountTokenValid(s.token, now, s.earlyExpiry) {
		token := s.token
		s.mu.Unlock()
		return token, nil
	}
	if refresh := s.inflight; refresh != nil {
		s.mu.Unlock()
		<-refresh.done
		return refresh.token, refresh.err
	}
	if s.lastErr != nil && now.Before(s.retryAfter) {
		err := s.lastErr
		s.mu.Unlock()
		return nil, err
	}

	refresh := &tokenRefresh{done: make(chan struct{})}
	s.inflight = refresh
	s.mu.Unlock()

	ctx, cancel := context.WithTimeout(context.Background(), s.requestTimeout)
	token, err := s.source.TokenCtx(ctx)
	cancel()
	if err == nil && (token == nil || token.AccessToken == "") {
		err = errors.New("zitadel: token endpoint returned an empty access token")
	}

	s.mu.Lock()
	refresh.token = token
	refresh.err = err
	if err == nil {
		s.token = token
		s.lastErr = nil
		s.retryAfter = time.Time{}
	} else {
		refresh.token = nil
		s.lastErr = err
		s.retryAfter = s.now().Add(s.failureBackoff)
	}
	s.inflight = nil
	close(refresh.done)
	s.mu.Unlock()

	return refresh.token, refresh.err
}

func serviceAccountTokenValid(token *oauth2.Token, now time.Time, earlyExpiry time.Duration) bool {
	if token == nil || token.AccessToken == "" {
		return false
	}
	if token.Expiry.IsZero() {
		return true
	}
	return token.Expiry.After(now.Add(earlyExpiry))
}

func newServiceAccountHTTPClient(timeout time.Duration) *http.Client {
	// Reuse the process-wide transport and its connection pool, but keep timeout
	// policy on a dedicated client. Never mutate http.DefaultClient.
	return &http.Client{
		Transport: http.DefaultTransport,
		Timeout:   timeout,
	}
}

func serviceAccountAuthentication(
	key *client.KeyFile,
	httpClient *http.Client,
	requestTimeout time.Duration,
	earlyExpiry time.Duration,
) client.TokenSourceInitializer {
	return func(ctx context.Context, issuer string) (oauth2.TokenSource, error) {
		source, err := profile.NewJWTProfileTokenSource(
			ctx,
			issuer,
			key.UserID,
			key.KeyID,
			key.Key,
			[]string{client.ScopeZitadelAPI()},
			profile.WithHTTPClient(httpClient),
		)
		if err != nil {
			return nil, fmt.Errorf("zitadel: initialize service account token source: %w", err)
		}
		return newCachedTokenSource(source, requestTimeout, earlyExpiry), nil
	}
}

// NewSDKClient builds the ZITADEL gRPC client authenticated as the configured
// service account (OAuth2 JWT profile grant). The base URL must be HTTPS in
// production; an explicit http:// base URL (local test instances) enables the
// SDK's insecure mode.
func NewSDKClient(ctx context.Context, cfg config.AuthProviderConfig) (*client.Client, error) {
	key, err := loadServiceAccountKey(cfg.ServiceAccountKeyFile)
	if err != nil {
		return nil, err
	}

	u, err := url.Parse(cfg.BaseURL)
	if err != nil {
		return nil, fmt.Errorf("zitadel: parse base url: %w", err)
	}

	host := u.Hostname()
	var conf *zitadel.Zitadel
	if u.Scheme == "http" {
		port := u.Port()
		if port == "" {
			port = "80"
		}
		conf = zitadel.New(host, zitadel.WithInsecure(port))
	} else {
		conf = zitadel.New(host)
	}

	// The JWT profile token is minted for the ZITADEL API audience; the same
	// token authorizes the session and user service calls. Cache it in-process
	// until shortly before expiry so one login does not mint a fresh token for
	// every ZITADEL RPC. Token acquisition remains bounded independently from
	// the caller because the upstream SDK invokes oauth2.TokenSource.Token.
	tokenHTTPClient := newServiceAccountHTTPClient(serviceAccountTokenRequestTimeout)
	authentication := serviceAccountAuthentication(
		key,
		tokenHTTPClient,
		serviceAccountTokenRequestTimeout,
		serviceAccountTokenEarlyExpiry,
	)
	c, err := client.New(ctx, conf,
		client.WithAuth(authentication))
	if err != nil {
		return nil, fmt.Errorf("zitadel: create client: %w", err)
	}
	return c, nil
}

// loadServiceAccountKey reads and validates the ZITADEL service account
// key.json file.
func loadServiceAccountKey(path string) (*client.KeyFile, error) {
	raw, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("zitadel: read service account key file: %w", err)
	}
	var key client.KeyFile
	if err := json.Unmarshal(raw, &key); err != nil {
		return nil, fmt.Errorf("zitadel: parse service account key file: %w", err)
	}
	if key.KeyID == "" || len(key.Key) == 0 || key.UserID == "" {
		return nil, errors.New("zitadel: service account key file must contain keyId, key and userId")
	}
	return &key, nil
}
