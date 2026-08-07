//
// Copyright (c) 2026 Chen Jiajie(Ariakage)
//
// Author: Chen Jiajie(Ariakage) <ariakage233@gmail.com>
// Date: 2026-08-07
// Description: Unit tests for the consent domain helpers
//

package consent

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"strings"
	"testing"
	"time"
)

func TestProviderErrorHidesCause(t *testing.T) {
	cause := errors.New("grpc: PermissionDenied OIDC-foSyH49RvL raw provider detail")
	err := NewProviderError(ClassUserNotEligible, cause)

	if got := err.Error(); strings.Contains(got, "OIDC-") || strings.Contains(got, "raw provider") {
		t.Fatalf("Error() leaks provider detail: %q", got)
	}
	if class, ok := ErrorClassOf(err); !ok || class != ClassUserNotEligible {
		t.Fatalf("ErrorClassOf = %v, %v", class, ok)
	}
	if !IsClass(err, ClassUserNotEligible) {
		t.Fatal("IsClass(user_not_eligible) = false")
	}
	if !errors.Is(err, cause) {
		t.Fatal("Unwrap chain must reach the cause for internal handling")
	}
	if _, ok := ErrorClassOf(errors.New("plain")); ok {
		t.Fatal("plain errors must not classify as provider errors")
	}
}

func TestCallbackResultRedaction(t *testing.T) {
	result, err := NewCallbackResult("https://rp.example/callback?code=secret&state=s")
	if err != nil {
		t.Fatalf("NewCallbackResult: %v", err)
	}
	if result.Raw() != "https://rp.example/callback?code=secret&state=s" {
		t.Fatalf("Raw lost the url: %q", result.Raw())
	}

	// Every rendering path a log line, panic dump or debugger could take
	// must stay redacted — including reflection-based %#v.
	renderings := []string{
		result.String(),
		result.GoString(),
		fmt.Sprintf("%v", result),
		fmt.Sprintf("%+v", result),
		fmt.Sprintf("%#v", result),
		fmt.Sprintf("%q", result),
		fmt.Sprintf("%s", result),
	}
	var buf bytes.Buffer
	logger := slog.New(slog.NewTextHandler(&buf, nil))
	logger.Info("decision", "callback", result)
	renderings = append(renderings, buf.String())

	for _, rendered := range renderings {
		if strings.Contains(rendered, "secret") {
			t.Fatalf("callback leaked: %q", rendered)
		}
	}

	if _, err := NewCallbackResult("   "); err == nil {
		t.Fatal("empty callback url must be rejected")
	}
	var zero CallbackResult
	if zero.String() != "[no callback]" {
		t.Fatalf("zero value String = %q", zero.String())
	}
}

func TestSessionHandleValidation(t *testing.T) {
	if _, err := NewSessionHandle("s", "t"); err != nil {
		t.Fatalf("valid handle rejected: %v", err)
	}
	long := strings.Repeat("x", MaxProviderSessionFieldLen)
	if _, err := NewSessionHandle(long, long); err != nil {
		t.Fatalf("200-char fields must pass (proto max_len=200): %v", err)
	}

	cases := []struct {
		name        string
		id, token   string
		wantMessage string
	}{
		{"missing id", "", "t", "invalid provider session id"},
		{"oversized id", strings.Repeat("x", MaxProviderSessionFieldLen+1), "t", "invalid provider session id"},
		{"missing token", "s", "", "invalid provider session token"},
		{"oversized token", "s", strings.Repeat("x", MaxProviderSessionFieldLen+1), "invalid provider session token"},
	}
	for _, tc := range cases {
		if _, err := NewSessionHandle(tc.id, tc.token); err == nil || !strings.Contains(err.Error(), tc.wantMessage) {
			t.Fatalf("%s: want error containing %q, got %v", tc.name, tc.wantMessage, err)
		}
	}
}

func TestSessionHandleRedaction(t *testing.T) {
	handle, err := NewSessionHandle("sess-1", "super-secret-token")
	if err != nil {
		t.Fatalf("NewSessionHandle: %v", err)
	}
	if handle.SessionID() != "sess-1" || handle.SessionToken() != "super-secret-token" {
		t.Fatal("getters must return the wrapped values")
	}

	renderings := []string{
		handle.String(),
		handle.GoString(),
		fmt.Sprintf("%v", handle),
		fmt.Sprintf("%+v", handle),
		fmt.Sprintf("%#v", handle),
		fmt.Sprintf("%q", handle),
	}

	// Unexported fields must make json.Marshal structurally blind.
	raw, err := json.Marshal(handle)
	if err != nil {
		t.Fatalf("json.Marshal: %v", err)
	}
	renderings = append(renderings, string(raw))

	// Pointer rendering must redact too.
	renderings = append(renderings, fmt.Sprintf("%v", &handle), fmt.Sprintf("%+v", &handle))

	var buf bytes.Buffer
	logger := slog.New(slog.NewTextHandler(&buf, nil))
	logger.Info("completion", "session", handle)
	renderings = append(renderings, buf.String())

	for _, rendered := range renderings {
		if strings.Contains(rendered, "super-secret-token") || strings.Contains(rendered, "sess-1") {
			t.Fatalf("session handle leaked: %q", rendered)
		}
	}
}

func TestValidateAuthRequestID(t *testing.T) {
	if err := ValidateAuthRequestID(""); err == nil {
		t.Fatal("empty id must be rejected")
	}
	if err := ValidateAuthRequestID(strings.Repeat("x", MaxAuthRequestIDLen)); err != nil {
		t.Fatalf("200-byte id must pass: %v", err)
	}
	if err := ValidateAuthRequestID(strings.Repeat("x", MaxAuthRequestIDLen+1)); err == nil {
		t.Fatal("oversized id must be rejected")
	}
}

func TestPromptAndReasonStrings(t *testing.T) {
	cases := map[string]string{
		PromptNone.String():          "none",
		PromptLogin.String():         "login",
		PromptConsent.String():       "consent",
		PromptSelectAccount.String(): "select_account",
		PromptCreate.String():        "create",
		PromptUnspecified.String():   "unspecified",
		Prompt(99).String():          "unspecified",
	}
	for got, want := range cases {
		if got != want {
			t.Fatalf("string = %q, want %q", got, want)
		}
	}
	reasons := map[CallbackErrorReason]string{
		ReasonAccessDenied:             "access_denied",
		ReasonLoginRequired:            "login_required",
		ReasonConsentRequired:          "consent_required",
		ReasonAccountSelectionRequired: "account_selection_required",
		ReasonServerError:              "server_error",
		ReasonTemporarilyUnavailable:   "temporarily_unavailable",
		ReasonRequestNotSupported:      "request_not_supported",
		CallbackErrorReason(0):         "unknown",
		CallbackErrorReason(99):        "unknown",
	}
	for reason, want := range reasons {
		if got := reason.String(); got != want {
			t.Fatalf("reason %d = %q, want %q", int(reason), got, want)
		}
	}
}

func fakeWithRequest(id string) *FakeAuthRequestProvider {
	fake := NewFakeAuthRequestProvider()
	maxAge := 30 * time.Second
	fake.AddRequest(&AuthRequestView{
		ID:          id,
		ClientID:    "client-1",
		Scopes:      []string{"openid", "profile"},
		RedirectURI: "https://rp.example/callback",
		Prompts:     []Prompt{PromptConsent},
		MaxAge:      &maxAge,
		CreatedAt:   time.Now(),
	})
	return fake
}

func mustHandle(t *testing.T, id, token string) SessionHandle {
	t.Helper()
	handle, err := NewSessionHandle(id, token)
	if err != nil {
		t.Fatalf("NewSessionHandle: %v", err)
	}
	return handle
}

func TestFakeGetAuthRequest(t *testing.T) {
	ctx := context.Background()
	fake := fakeWithRequest("v2-req-1")

	view, err := fake.GetAuthRequest(ctx, "v2-req-1")
	if err != nil {
		t.Fatalf("GetAuthRequest: %v", err)
	}
	if view.ClientID != "client-1" || !view.HasPrompt(PromptConsent) || view.MaxAge == nil {
		t.Fatalf("view mismatch: %+v", view)
	}

	if _, err := fake.GetAuthRequest(ctx, "missing"); !IsClass(err, ClassNotFound) {
		t.Fatalf("unknown request: want not_found, got %v", err)
	}
	if _, err := fake.GetAuthRequest(ctx, strings.Repeat("x", MaxAuthRequestIDLen+1)); !IsClass(err, ClassNotFound) {
		t.Fatalf("oversized id: want not_found, got %v", err)
	}

	injected := NewProviderError(ClassProviderUnavailable, nil)
	fake.InjectGetError(injected)
	if _, err := fake.GetAuthRequest(ctx, "v2-req-1"); !errors.Is(err, injected) {
		t.Fatalf("injected get error must pass through, got %v", err)
	}
}

func TestFakeDeepCopyIsolation(t *testing.T) {
	ctx := context.Background()
	fake := NewFakeAuthRequestProvider()
	maxAge := 30 * time.Second
	fake.AddRequest(&AuthRequestView{
		ID:       "v2-req-1",
		ClientID: "client-1",
		Scopes:   []string{"openid", "profile"},
		Prompts:  []Prompt{PromptConsent},
		MaxAge:   &maxAge,
	})

	// Mutating the caller's original after AddRequest must not reach the
	// store (slices and the MaxAge pointer included).
	maxAge = 5 * time.Second

	view, err := fake.GetAuthRequest(ctx, "v2-req-1")
	if err != nil {
		t.Fatalf("GetAuthRequest: %v", err)
	}
	view.ClientID = "mutated"
	view.Scopes[0] = "mutated-scope"
	view.Prompts[0] = PromptNone
	*view.MaxAge = time.Hour

	stored, err := fake.GetAuthRequest(ctx, "v2-req-1")
	if err != nil {
		t.Fatalf("second GetAuthRequest: %v", err)
	}
	if stored.ClientID != "client-1" || stored.Scopes[0] != "openid" ||
		stored.Prompts[0] != PromptConsent || *stored.MaxAge != 30*time.Second {
		t.Fatalf("store must be isolated from returned views: %+v", stored)
	}
}

func TestFakeAllowOneShot(t *testing.T) {
	ctx := context.Background()
	fake := fakeWithRequest("v2-req-1")
	handle := mustHandle(t, "s1", "t1")

	result, err := fake.CompleteWithSession(ctx, "v2-req-1", handle)
	if err != nil {
		t.Fatalf("CompleteWithSession: %v", err)
	}
	if !strings.Contains(result.Raw(), "code=fake-code-v2-req-1") {
		t.Fatalf("callback must carry the code: %q", result.Raw())
	}
	if fake.Completions("v2-req-1") != 1 {
		t.Fatalf("Completions = %d, want 1", fake.Completions("v2-req-1"))
	}

	// Provider one-shot: the second completion is rejected.
	if _, err := fake.CompleteWithSession(ctx, "v2-req-1", handle); !IsClass(err, ClassAlreadyCompleted) {
		t.Fatalf("second completion: want already_completed, got %v", err)
	}
	if _, err := fake.CompleteWithError(ctx, "v2-req-1", ReasonAccessDenied); !IsClass(err, ClassAlreadyCompleted) {
		t.Fatalf("mixed second completion: want already_completed, got %v", err)
	}

	// Consumed requests read back as not_found — the documented ambiguity
	// reconciliation must treat fail-closed.
	if _, err := fake.GetAuthRequest(ctx, "v2-req-1"); !IsClass(err, ClassNotFound) {
		t.Fatalf("completed request read: want not_found, got %v", err)
	}
	if fake.Completions("v2-req-1") != 1 {
		t.Fatal("rejected completions must not count")
	}
}

func TestFakeDenyAndErrorCallbacks(t *testing.T) {
	ctx := context.Background()

	for _, reason := range []CallbackErrorReason{
		ReasonAccessDenied,
		ReasonLoginRequired,
		ReasonConsentRequired,
		ReasonAccountSelectionRequired,
		ReasonServerError,
		ReasonTemporarilyUnavailable,
		ReasonRequestNotSupported,
	} {
		fake := fakeWithRequest("req-" + reason.String())
		result, err := fake.CompleteWithError(ctx, "req-"+reason.String(), reason)
		if err != nil {
			t.Fatalf("CompleteWithError(%s): %v", reason, err)
		}
		if !strings.Contains(result.Raw(), "error="+reason.String()) {
			t.Fatalf("callback must carry error=%s: %q", reason, result.Raw())
		}
	}

	fake := fakeWithRequest("v2-req-1")
	if _, err := fake.CompleteWithError(ctx, "v2-req-1", CallbackErrorReason(0)); !IsClass(err, ClassInternal) {
		t.Fatalf("unknown reason: want internal, got %v", err)
	}
	if _, err := fake.CompleteWithSession(ctx, "v2-req-1", SessionHandle{}); !IsClass(err, ClassInternal) {
		t.Fatalf("invalid session handle: want internal, got %v", err)
	}
	if _, err := fake.CompleteWithSession(ctx, "missing", mustHandle(t, "s", "t")); !IsClass(err, ClassNotFound) {
		t.Fatalf("unknown request completion: want not_found, got %v", err)
	}
}

func TestFakeInjectedFailureDoesNotConsumeOneShot(t *testing.T) {
	ctx := context.Background()
	fake := fakeWithRequest("v2-req-1")
	handle := mustHandle(t, "s1", "t1")

	fake.InjectCompleteError(NewProviderError(ClassProviderUnavailable, nil))
	if _, err := fake.CompleteWithSession(ctx, "v2-req-1", handle); !IsClass(err, ClassProviderUnavailable) {
		t.Fatalf("injected failure: want provider_unavailable, got %v", err)
	}
	if fake.Completions("v2-req-1") != 0 {
		t.Fatal("failed call must not consume the one-shot")
	}

	fake.InjectCompleteError(nil)
	if _, err := fake.CompleteWithSession(ctx, "v2-req-1", handle); err != nil {
		t.Fatalf("recovery after injected failure: %v", err)
	}
}

// TestFakeLostCompletionResponse covers the outcome_unknown crash window:
// the provider succeeded and consumed the request, but the response was
// lost, so United Pass sees provider_unavailable without any
// provider_succeeded proof (ADR-0005 §5).
func TestFakeLostCompletionResponse(t *testing.T) {
	ctx := context.Background()
	fake := fakeWithRequest("v2-req-1")
	handle := mustHandle(t, "s1", "t1")

	fake.InjectLostCompletionResponse(NewProviderError(ClassProviderUnavailable, nil))

	// The caller observes a transport failure...
	if _, err := fake.CompleteWithSession(ctx, "v2-req-1", handle); !IsClass(err, ClassProviderUnavailable) {
		t.Fatalf("lost response: want provider_unavailable, got %v", err)
	}
	// ...but the provider already consumed the request.
	if fake.Completions("v2-req-1") != 1 {
		t.Fatalf("lost response must consume the provider one-shot, Completions = %d", fake.Completions("v2-req-1"))
	}
	// A re-read is indistinguishable from expiry (fail-closed evidence).
	if _, err := fake.GetAuthRequest(ctx, "v2-req-1"); !IsClass(err, ClassNotFound) {
		t.Fatalf("read after lost completion: want not_found, got %v", err)
	}
	// A retried completion surfaces the provider one-shot, never a second
	// success.
	if _, err := fake.CompleteWithSession(ctx, "v2-req-1", handle); !IsClass(err, ClassAlreadyCompleted) {
		t.Fatalf("retry after lost completion: want already_completed, got %v", err)
	}
	if fake.Completions("v2-req-1") != 1 {
		t.Fatal("rejected retry must not count as a second completion")
	}
}

func TestFakeSupportsEveryDocumentedErrorClass(t *testing.T) {
	// Orchestration tests must be able to simulate all contract §8 classes.
	classes := []ErrorClass{
		ClassNotFound, ClassExpired, ClassAlreadyCompleted, ClassInvalidRedirect,
		ClassInvalidScope, ClassProviderConflict, ClassProviderUnavailable,
		ClassRateLimited, ClassInternal, ClassUserNotEligible,
	}
	for _, class := range classes {
		fake := fakeWithRequest("v2-req-1")
		want := NewProviderError(class, nil)
		fake.InjectCompleteError(want)
		_, err := fake.CompleteWithSession(context.Background(), "v2-req-1", mustHandle(t, "s", "t"))
		if !IsClass(err, class) {
			t.Fatalf("class %s: got %v", class, err)
		}
	}
}
