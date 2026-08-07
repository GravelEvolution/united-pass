//
// Copyright (c) 2026 Chen Jiajie(Ariakage)
//
// Author: Chen Jiajie(Ariakage) <ariakage233@gmail.com>
// Date: 2026-08-07
// Description: In-memory fake provider authorization request provider for tests
//

package consent

import (
	"context"
	"fmt"
	"net/url"
	"sync"
)

// FakeAuthRequestProvider is the in-memory AuthRequestProvider used by unit
// tests. It mirrors every documented provider behavior (ADR-0005 §4, §5,
// §8): one-shot completion, the consumed/expired indistinguishability after
// completion, provider-success-with-lost-response (outcome_unknown), and
// all stable error classes through injection.
type FakeAuthRequestProvider struct {
	mu        sync.Mutex
	requests  map[string]*AuthRequestView
	completed map[string]int
	getErr    error
	compErr   error
	lostErr   error
	// CallbackBase is the RP callback origin used to build deterministic
	// callback URLs. Defaults to https://rp.example/callback.
	CallbackBase string
}

// NewFakeAuthRequestProvider returns an empty fake provider.
func NewFakeAuthRequestProvider() *FakeAuthRequestProvider {
	return &FakeAuthRequestProvider{
		requests:     make(map[string]*AuthRequestView),
		completed:    make(map[string]int),
		CallbackBase: "https://rp.example/callback",
	}
}

// AddRequest registers an auth request the fake will serve. The view is
// deep-copied so later mutation of the caller's value cannot reach the
// store.
func (f *FakeAuthRequestProvider) AddRequest(view *AuthRequestView) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.requests[view.ID] = cloneAuthRequestView(view)
}

// InjectGetError makes every subsequent GetAuthRequest fail with err until
// cleared with InjectGetError(nil). The failure does not consume anything.
func (f *FakeAuthRequestProvider) InjectGetError(err error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.getErr = err
}

// InjectCompleteError makes every subsequent completion call fail with err
// until cleared. The failure does not consume the one-shot: a later clean
// call can still complete the request, matching a real provider whose call
// never arrived.
func (f *FakeAuthRequestProvider) InjectCompleteError(err error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.compErr = err
}

// InjectLostCompletionResponse simulates the outcome_unknown crash window
// (ADR-0005 §5): the completion call reaches the provider, the request is
// consumed there, but the response is lost on the way back, so the caller
// observes err (typically provider_unavailable) with no provider_succeeded
// proof. Unlike InjectCompleteError this DOES consume the one-shot: a later
// GetAuthRequest reads not_found and any further completion fails with
// already_completed.
func (f *FakeAuthRequestProvider) InjectLostCompletionResponse(err error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.lostErr = err
}

// Completions returns how many completion calls succeeded for an ID.
func (f *FakeAuthRequestProvider) Completions(id string) int {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.completed[id]
}

// GetAuthRequest implements AuthRequestProvider. Unknown and already
// completed requests both surface as ClassNotFound — the fake deliberately
// reproduces the provider ambiguity that keeps reconciliation fail-closed
// (ADR-0005 §4).
func (f *FakeAuthRequestProvider) GetAuthRequest(_ context.Context, authRequestID string) (*AuthRequestView, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.getErr != nil {
		return nil, f.getErr
	}
	if err := ValidateAuthRequestID(authRequestID); err != nil {
		return nil, NewProviderError(ClassNotFound, err)
	}
	if _, done := f.completed[authRequestID]; done {
		return nil, NewProviderError(ClassNotFound, nil)
	}
	view, ok := f.requests[authRequestID]
	if !ok {
		return nil, NewProviderError(ClassNotFound, nil)
	}
	return cloneAuthRequestView(view), nil
}

// CompleteWithSession implements AuthRequestProvider (Allow path).
func (f *FakeAuthRequestProvider) CompleteWithSession(_ context.Context, authRequestID string, session SessionHandle) (CallbackResult, error) {
	if err := session.Validate(); err != nil {
		return CallbackResult{}, NewProviderError(ClassInternal, err)
	}
	if err := f.complete(authRequestID); err != nil {
		return CallbackResult{}, err
	}
	return f.callback(authRequestID, url.Values{
		"code":  {"fake-code-" + authRequestID},
		"state": {"fake-state"},
	})
}

// CompleteWithError implements AuthRequestProvider (Deny / *_required paths).
func (f *FakeAuthRequestProvider) CompleteWithError(_ context.Context, authRequestID string, reason CallbackErrorReason) (CallbackResult, error) {
	if reason.String() == "unknown" {
		return CallbackResult{}, NewProviderError(ClassInternal, fmt.Errorf("consent: unknown callback error reason %d", int(reason)))
	}
	if err := f.complete(authRequestID); err != nil {
		return CallbackResult{}, err
	}
	return f.callback(authRequestID, url.Values{
		"error": {reason.String()},
		"state": {"fake-state"},
	})
}

// complete runs the shared completion preconditions: ID limits, existence,
// one-shot enforcement, then the two distinct fault injections. The
// injected transport failure (compErr) happens before the provider is
// reached and does not consume; the lost-response failure (lostErr)
// happens after the provider consumed the request, and does.
func (f *FakeAuthRequestProvider) complete(authRequestID string) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	if err := ValidateAuthRequestID(authRequestID); err != nil {
		return NewProviderError(ClassNotFound, err)
	}
	if _, ok := f.requests[authRequestID]; !ok {
		return NewProviderError(ClassNotFound, nil)
	}
	if f.completed[authRequestID] > 0 {
		return NewProviderError(ClassAlreadyCompleted, nil)
	}
	if f.compErr != nil {
		return f.compErr
	}
	f.completed[authRequestID]++
	if f.lostErr != nil {
		return f.lostErr
	}
	return nil
}

// cloneAuthRequestView deep-copies a view including its slices and the
// MaxAge pointer, so neither the store nor returned values share backing
// storage.
func cloneAuthRequestView(view *AuthRequestView) *AuthRequestView {
	if view == nil {
		return nil
	}
	cloned := *view
	cloned.Scopes = append([]string(nil), view.Scopes...)
	cloned.Prompts = append([]Prompt(nil), view.Prompts...)
	if view.MaxAge != nil {
		maxAge := *view.MaxAge
		cloned.MaxAge = &maxAge
	}
	return &cloned
}

func (f *FakeAuthRequestProvider) callback(authRequestID string, q url.Values) (CallbackResult, error) {
	f.mu.Lock()
	base := f.CallbackBase
	f.mu.Unlock()
	sep := "?"
	if base != "" && base[len(base)-1] == '?' {
		sep = ""
	}
	return NewCallbackResult(base + sep + q.Encode())
}

var _ AuthRequestProvider = (*FakeAuthRequestProvider)(nil)
