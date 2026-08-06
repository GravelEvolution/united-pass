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
// completion, and all stable error classes through injection.
type FakeAuthRequestProvider struct {
	mu        sync.Mutex
	requests  map[string]*AuthRequestView
	completed map[string]int
	getErr    error
	compErr   error
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

// AddRequest registers an auth request the fake will serve.
func (f *FakeAuthRequestProvider) AddRequest(view *AuthRequestView) {
	f.mu.Lock()
	defer f.mu.Unlock()
	copied := *view
	f.requests[view.ID] = &copied
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
	copied := *view
	return &copied, nil
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
// injected failure, one-shot enforcement.
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
	return nil
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
