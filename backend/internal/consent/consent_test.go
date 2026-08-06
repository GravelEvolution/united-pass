package consent

import (
	"context"
	"errors"
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
	for _, rendered := range []string{result.String(), result.Raw()[:0] + result.String()} {
		if strings.Contains(rendered, "secret") {
			t.Fatalf("String() leaks the callback url: %q", rendered)
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

func TestSessionHandleValidate(t *testing.T) {
	if err := (SessionHandle{SessionID: "s", SessionToken: "t"}).Validate(); err != nil {
		t.Fatalf("valid handle rejected: %v", err)
	}
	if err := (SessionHandle{SessionID: "s"}).Validate(); err == nil {
		t.Fatal("missing token must be rejected")
	}
	if err := (SessionHandle{SessionToken: "t"}).Validate(); err == nil {
		t.Fatal("missing session id must be rejected")
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

	// Returned copies must be isolated from the store.
	view.ClientID = "mutated"
	view2, err := fake.GetAuthRequest(ctx, "v2-req-1")
	if err != nil || view2.ClientID != "client-1" {
		t.Fatalf("store must not be mutated through returned views: %v %+v", err, view2)
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

func TestFakeAllowOneShot(t *testing.T) {
	ctx := context.Background()
	fake := fakeWithRequest("v2-req-1")
	handle := SessionHandle{SessionID: "s1", SessionToken: "t1"}

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
	if _, err := fake.CompleteWithSession(ctx, "missing", SessionHandle{SessionID: "s", SessionToken: "t"}); !IsClass(err, ClassNotFound) {
		t.Fatalf("unknown request completion: want not_found, got %v", err)
	}
}

func TestFakeInjectedFailureDoesNotConsumeOneShot(t *testing.T) {
	ctx := context.Background()
	fake := fakeWithRequest("v2-req-1")
	handle := SessionHandle{SessionID: "s1", SessionToken: "t1"}

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
		_, err := fake.CompleteWithSession(context.Background(), "v2-req-1", SessionHandle{SessionID: "s", SessionToken: "t"})
		if !IsClass(err, class) {
			t.Fatalf("class %s: got %v", class, err)
		}
	}
}
