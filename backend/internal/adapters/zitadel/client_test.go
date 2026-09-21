//
// Copyright (c) 2026 Chen Jiajie(Ariakage)
//
// Author: Chen Jiajie(Ariakage) <ariakage233@gmail.com>
// Date: 2026-09-04
// Description: Service-account token cache and timeout tests
//

package zitadel

import (
	"context"
	"errors"
	"net/http"
	"sync"
	"testing"
	"time"

	"golang.org/x/oauth2"
)

type recordingContextTokenSource struct {
	mu      sync.Mutex
	calls   int
	tokenFn func(context.Context, int) (*oauth2.Token, error)
}

type tokenTestClock struct {
	mu  sync.Mutex
	now time.Time
}

func (c *tokenTestClock) Now() time.Time {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.now
}

func (c *tokenTestClock) Advance(delta time.Duration) {
	c.mu.Lock()
	c.now = c.now.Add(delta)
	c.mu.Unlock()
}

func (s *recordingContextTokenSource) TokenCtx(ctx context.Context) (*oauth2.Token, error) {
	s.mu.Lock()
	s.calls++
	call := s.calls
	s.mu.Unlock()
	return s.tokenFn(ctx, call)
}

func (s *recordingContextTokenSource) callCount() int {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.calls
}

func validToken(value string) *oauth2.Token {
	return &oauth2.Token{
		AccessToken: value,
		TokenType:   "Bearer",
		Expiry:      time.Now().Add(time.Hour),
	}
}

func TestCachedTokenSourceReusesValidTokenSequentially(t *testing.T) {
	raw := &recordingContextTokenSource{
		tokenFn: func(context.Context, int) (*oauth2.Token, error) {
			return validToken("shared-token"), nil
		},
	}
	source := newCachedTokenSource(raw, time.Second, 30*time.Second)

	for i := 0; i < 10; i++ {
		token, err := source.Token()
		if err != nil {
			t.Fatalf("Token() call %d: %v", i+1, err)
		}
		if token.AccessToken != "shared-token" {
			t.Fatalf("Token() call %d access token = %q, want shared-token", i+1, token.AccessToken)
		}
	}
	if got := raw.callCount(); got != 1 {
		t.Fatalf("underlying TokenCtx calls = %d, want 1", got)
	}
}

func TestCachedTokenSourceReusesValidTokenConcurrently(t *testing.T) {
	const callers = 32
	raw := &recordingContextTokenSource{
		tokenFn: func(context.Context, int) (*oauth2.Token, error) {
			time.Sleep(10 * time.Millisecond)
			return validToken("concurrent-token"), nil
		},
	}
	source := newCachedTokenSource(raw, time.Second, 30*time.Second)

	start := make(chan struct{})
	errs := make(chan error, callers)
	var wg sync.WaitGroup
	for i := 0; i < callers; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			<-start
			token, err := source.Token()
			if err != nil {
				errs <- err
				return
			}
			if token.AccessToken != "concurrent-token" {
				errs <- errors.New("unexpected access token")
			}
		}()
	}
	close(start)
	wg.Wait()
	close(errs)
	for err := range errs {
		t.Errorf("concurrent Token(): %v", err)
	}
	if got := raw.callCount(); got != 1 {
		t.Fatalf("underlying TokenCtx calls = %d, want 1", got)
	}
}

func TestCachedTokenSourceRefreshesBeforeExpiry(t *testing.T) {
	raw := &recordingContextTokenSource{
		tokenFn: func(_ context.Context, call int) (*oauth2.Token, error) {
			if call == 1 {
				return &oauth2.Token{
					AccessToken: "near-expiry",
					TokenType:   "Bearer",
					Expiry:      time.Now().Add(10 * time.Second),
				}, nil
			}
			return validToken("refreshed"), nil
		},
	}
	source := newCachedTokenSource(raw, time.Second, 30*time.Second)

	first, err := source.Token()
	if err != nil {
		t.Fatalf("first Token(): %v", err)
	}
	if first.AccessToken != "near-expiry" {
		t.Fatalf("first access token = %q, want near-expiry", first.AccessToken)
	}
	second, err := source.Token()
	if err != nil {
		t.Fatalf("second Token(): %v", err)
	}
	if second.AccessToken != "refreshed" {
		t.Fatalf("second access token = %q, want refreshed", second.AccessToken)
	}
	third, err := source.Token()
	if err != nil {
		t.Fatalf("third Token(): %v", err)
	}
	if third.AccessToken != "refreshed" {
		t.Fatalf("third access token = %q, want refreshed", third.AccessToken)
	}
	if got := raw.callCount(); got != 2 {
		t.Fatalf("underlying TokenCtx calls = %d, want 2", got)
	}
}

func TestCachedTokenSourceSharesConcurrentFailure(t *testing.T) {
	const callers = 32
	wantErr := errors.New("temporary token endpoint failure")
	refreshStarted := make(chan struct{})
	releaseRefresh := make(chan struct{})
	raw := &recordingContextTokenSource{
		tokenFn: func(_ context.Context, call int) (*oauth2.Token, error) {
			if call != 1 {
				return nil, errors.New("concurrent failure triggered more than one refresh")
			}
			close(refreshStarted)
			<-releaseRefresh
			return nil, wantErr
		},
	}
	source := newCachedTokenSource(raw, time.Second, 30*time.Second)

	start := make(chan struct{})
	errs := make(chan error, callers)
	var wg sync.WaitGroup
	for i := 0; i < callers; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			<-start
			_, err := source.Token()
			errs <- err
		}()
	}
	close(start)
	select {
	case <-refreshStarted:
	case <-time.After(time.Second):
		t.Fatal("token refresh did not start")
	}
	close(releaseRefresh)

	done := make(chan struct{})
	go func() {
		wg.Wait()
		close(done)
	}()
	select {
	case <-done:
	case <-time.After(time.Second):
		t.Fatal("concurrent callers deadlocked after refresh failure")
	}
	close(errs)
	for err := range errs {
		if !errors.Is(err, wantErr) {
			t.Errorf("concurrent Token() error = %v, want %v", err, wantErr)
		}
	}
	if got := raw.callCount(); got != 1 {
		t.Fatalf("underlying TokenCtx calls = %d, want one shared failure", got)
	}
}

func TestCachedTokenSourceBacksOffThenRecovers(t *testing.T) {
	wantErr := errors.New("temporary token endpoint failure")
	raw := &recordingContextTokenSource{
		tokenFn: func(_ context.Context, call int) (*oauth2.Token, error) {
			if call == 1 {
				return nil, wantErr
			}
			return validToken("recovered-token"), nil
		},
	}
	clock := &tokenTestClock{now: time.Now()}
	source := newCachedTokenSource(raw, time.Second, 30*time.Second)
	source.now = clock.Now
	source.failureBackoff = 100 * time.Millisecond

	if _, err := source.Token(); !errors.Is(err, wantErr) {
		t.Fatalf("first Token() error = %v, want %v", err, wantErr)
	}
	for i := 0; i < 5; i++ {
		if _, err := source.Token(); !errors.Is(err, wantErr) {
			t.Fatalf("backoff Token() call %d error = %v, want %v", i+1, err, wantErr)
		}
	}
	if got := raw.callCount(); got != 1 {
		t.Fatalf("underlying calls during failure backoff = %d, want 1", got)
	}

	clock.Advance(101 * time.Millisecond)
	token, err := source.Token()
	if err != nil {
		t.Fatalf("recovery Token(): %v", err)
	}
	if token.AccessToken != "recovered-token" {
		t.Fatalf("recovery access token = %q, want recovered-token", token.AccessToken)
	}
	if got := raw.callCount(); got != 2 {
		t.Fatalf("underlying calls after recovery = %d, want 2", got)
	}
	if _, err := source.Token(); err != nil {
		t.Fatalf("cached recovered Token(): %v", err)
	}
	if got := raw.callCount(); got != 2 {
		t.Fatalf("recovered token was not cached; calls = %d", got)
	}
}

func TestCachedTokenSourceBoundsTokenRequest(t *testing.T) {
	const timeout = 20 * time.Millisecond
	raw := &recordingContextTokenSource{
		tokenFn: func(ctx context.Context, _ int) (*oauth2.Token, error) {
			<-ctx.Done()
			return nil, ctx.Err()
		},
	}
	source := newCachedTokenSource(raw, timeout, 30*time.Second)

	started := time.Now()
	_, err := source.Token()
	elapsed := time.Since(started)
	if !errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("Token() error = %v, want context deadline exceeded", err)
	}
	if elapsed < timeout/2 {
		t.Fatalf("Token() returned too early after %s", elapsed)
	}
	if elapsed > 500*time.Millisecond {
		t.Fatalf("Token() exceeded bounded test window: %s", elapsed)
	}
	if got := raw.callCount(); got != 1 {
		t.Fatalf("underlying TokenCtx calls = %d, want 1", got)
	}
}

func TestCachedTokenSourceSharesConcurrentTimeoutWithoutDeadlock(t *testing.T) {
	const (
		callers = 24
		timeout = 25 * time.Millisecond
	)
	raw := &recordingContextTokenSource{
		tokenFn: func(ctx context.Context, _ int) (*oauth2.Token, error) {
			<-ctx.Done()
			return nil, ctx.Err()
		},
	}
	source := newCachedTokenSource(raw, timeout, 30*time.Second)

	start := make(chan struct{})
	errs := make(chan error, callers)
	var wg sync.WaitGroup
	for i := 0; i < callers; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			<-start
			_, err := source.Token()
			errs <- err
		}()
	}
	started := time.Now()
	close(start)
	done := make(chan struct{})
	go func() {
		wg.Wait()
		close(done)
	}()
	select {
	case <-done:
	case <-time.After(time.Second):
		t.Fatal("concurrent callers deadlocked after token refresh timeout")
	}
	elapsed := time.Since(started)
	close(errs)
	for err := range errs {
		if !errors.Is(err, context.DeadlineExceeded) {
			t.Errorf("concurrent timeout error = %v, want deadline exceeded", err)
		}
	}
	if got := raw.callCount(); got != 1 {
		t.Fatalf("underlying TokenCtx calls = %d, want one shared timeout", got)
	}
	if elapsed > 500*time.Millisecond {
		t.Fatalf("concurrent timeout took %s; want one bounded refresh, not serialized waits", elapsed)
	}
}

func TestServiceAccountHTTPClientIsDedicatedAndBounded(t *testing.T) {
	const timeout = 75 * time.Millisecond
	client := newServiceAccountHTTPClient(timeout)
	if client == http.DefaultClient {
		t.Fatal("service-account HTTP client must not be http.DefaultClient")
	}
	if client.Timeout != timeout {
		t.Fatalf("HTTP client timeout = %s, want %s", client.Timeout, timeout)
	}
	if client.Transport != http.DefaultTransport {
		t.Fatal("HTTP client should reuse the default transport connection pool")
	}
}
