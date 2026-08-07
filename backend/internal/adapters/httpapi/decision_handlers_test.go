package httpapi

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/go-chi/chi/v5"

	"github.com/GravelEvolution/united-pass/backend/internal/adapters/httpapi/request"
	"github.com/GravelEvolution/united-pass/backend/internal/consent"
	"github.com/GravelEvolution/united-pass/backend/internal/identity"
	"github.com/GravelEvolution/united-pass/backend/internal/session"
)

// stubDecider records the decision input it receives and optionally probes
// the per-request credential reader the handler hands over.
type stubDecider struct {
	outcome consent.DecisionOutcome
	err     error

	lastInput   consent.DecisionInput
	lastCred    session.ProviderSessionCredential
	lastCredErr error
	probeCred   bool
	calls       int
}

func (s *stubDecider) Decide(ctx context.Context, input consent.DecisionInput, credentials consent.ProviderSessionCredentialReader) (consent.DecisionOutcome, error) {
	s.lastInput = input
	s.calls++
	if s.probeCred && input.Session != nil {
		s.lastCred, s.lastCredErr = credentials.ReadProviderSessionCredential(ctx, input.Session.SessionID)
	}
	return s.outcome, s.err
}

// stubDecrypter satisfies ProviderSessionCredentialDecrypter and records
// the ciphertext it was asked to open.
type stubDecrypter struct {
	cred  session.ProviderSessionCredential
	err   error
	blob  session.EncryptedProviderSessionCredential
	calls int
}

func (s *stubDecrypter) DecryptProviderSessionCredential(_ context.Context, encrypted session.EncryptedProviderSessionCredential) (session.ProviderSessionCredential, error) {
	s.blob = encrypted
	s.calls++
	return s.cred, s.err
}

const (
	testDecisionSessionID = session.SessionID("up-session-1")
	testDecisionBlob      = session.EncryptedProviderSessionCredential("sealed-blob-1")
)

// buildDecisionRouter mounts the decision route and injects the
// authentication context RequireSession + RequireCSRF would have
// established in production.
func buildDecisionRouter(decider *stubDecider, decrypter *stubDecrypter, injectPrincipal, injectRecord bool) http.Handler {
	r := chi.NewRouter()
	r.Use(func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) {
			ctx := request.WithID(req.Context(), "req-test-1")
			if injectPrincipal {
				ctx = WithPrincipal(ctx, session.Principal{
					UserID:             identity.UserID("user_actor"),
					SessionID:          testDecisionSessionID,
					AuthenticationTime: time.Date(2026, 8, 6, 11, 55, 0, 0, time.UTC),
				})
			}
			if injectRecord {
				ctx = WithSessionRecord(ctx, session.SessionRecord{
					SessionID:                 testDecisionSessionID,
					UserID:                    identity.UserID("user_actor"),
					ProviderSessionCredential: testDecisionBlob,
				})
			}
			next.ServeHTTP(w, req.WithContext(ctx))
		})
	})
	handlers := NewAuthorizationDecisionHandlers(decider, decrypter, discardLogger())
	r.Post("/authorization/requests/{requestId}/decision", handlers.DecideRequest)
	return r
}

func doPost(t *testing.T, router http.Handler, path, body string) *httptest.ResponseRecorder {
	t.Helper()
	rec := httptest.NewRecorder()
	router.ServeHTTP(rec, httptest.NewRequest(http.MethodPost, path, strings.NewReader(body)))
	return rec
}

func TestDecideRequestHappyPath(t *testing.T) {
	decider := &stubDecider{outcome: consent.DecisionOutcome{RedirectURL: "https://rp.example/callback?code=abc"}}
	router := buildDecisionRouter(decider, &stubDecrypter{}, true, true)

	rec := doPost(t, router, "/authorization/requests/V2-request-1/decision", `{"decision":"allow"}`)
	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, body %s", rec.Code, rec.Body.String())
	}
	if got := rec.Header().Get("Cache-Control"); got != "no-store" {
		t.Fatalf("cache-control = %q", got)
	}
	body := decodeBody(t, rec)
	if len(body) != 1 || body["redirectUrl"] != "https://rp.example/callback?code=abc" {
		t.Fatalf("body = %v, want exactly the frozen redirectUrl shape", body)
	}
	if decider.lastInput.AuthRequestID != "V2-request-1" || decider.lastInput.Decision != consent.DecisionAllow {
		t.Fatalf("input = %+v", decider.lastInput)
	}
	sess := decider.lastInput.Session
	if sess == nil || sess.UserID != "user_actor" || sess.SessionID != testDecisionSessionID {
		t.Fatalf("session = %+v", sess)
	}
	if !sess.AuthenticationTime.Equal(time.Date(2026, 8, 6, 11, 55, 0, 0, time.UTC)) {
		t.Fatalf("authentication time = %v", sess.AuthenticationTime)
	}
}

func TestDecideRequestForwardsDeny(t *testing.T) {
	decider := &stubDecider{outcome: consent.DecisionOutcome{RedirectURL: "https://rp.example/callback?error=access_denied"}}
	router := buildDecisionRouter(decider, &stubDecrypter{}, true, true)

	rec := doPost(t, router, "/authorization/requests/V2-request-1/decision", `{"decision":"deny"}`)
	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, body %s", rec.Code, rec.Body.String())
	}
	if decider.lastInput.Decision != consent.DecisionDeny {
		t.Fatalf("decision = %v", decider.lastInput.Decision)
	}
}

func TestDecideRequestRejectsMalformedID(t *testing.T) {
	decider := &stubDecider{}
	router := buildDecisionRouter(decider, &stubDecrypter{}, true, true)

	longID := make([]rune, consent.MaxAuthRequestIDLen+1)
	for i := range longID {
		longID[i] = 'a'
	}
	rec := doPost(t, router, "/authorization/requests/"+string(longID)+"/decision", `{"decision":"allow"}`)
	if rec.Code != http.StatusBadRequest {
		t.Fatalf("status = %d", rec.Code)
	}
	if decider.calls != 0 {
		t.Fatal("decider called for malformed id")
	}
}

func TestDecideRequestBodyValidation(t *testing.T) {
	cases := []struct {
		name string
		body string
	}{
		{"unknown field", `{"decision":"allow","evil":true}`},
		{"invalid decision value", `{"decision":"maybe"}`},
		{"missing decision", `{}`},
		{"empty body", ``},
		{"not json", `allow`},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			decider := &stubDecider{}
			router := buildDecisionRouter(decider, &stubDecrypter{}, true, true)
			rec := doPost(t, router, "/authorization/requests/V2-request-1/decision", tc.body)
			if rec.Code != http.StatusBadRequest {
				t.Fatalf("status = %d, body %s", rec.Code, rec.Body.String())
			}
			if decider.calls != 0 {
				t.Fatal("decider called for invalid body")
			}
		})
	}
}

func TestDecideRequestRequiresAuthenticatedSession(t *testing.T) {
	t.Run("no principal", func(t *testing.T) {
		decider := &stubDecider{}
		router := buildDecisionRouter(decider, &stubDecrypter{}, false, true)
		rec := doPost(t, router, "/authorization/requests/V2-request-1/decision", `{"decision":"allow"}`)
		if rec.Code != http.StatusUnauthorized {
			t.Fatalf("status = %d", rec.Code)
		}
		if decider.calls != 0 {
			t.Fatal("decider called without principal")
		}
	})
	t.Run("no session record", func(t *testing.T) {
		decider := &stubDecider{}
		router := buildDecisionRouter(decider, &stubDecrypter{}, true, false)
		rec := doPost(t, router, "/authorization/requests/V2-request-1/decision", `{"decision":"allow"}`)
		if rec.Code != http.StatusUnauthorized {
			t.Fatalf("status = %d", rec.Code)
		}
		if decider.calls != 0 {
			t.Fatal("decider called without session record")
		}
	})
}

func TestDecideRequestErrorMapping(t *testing.T) {
	cases := []struct {
		name       string
		err        error
		wantStatus int
		wantCode   string
	}{
		{"not interactive", consent.ErrResolutionNotInteractive, http.StatusBadRequest, CodeInteractionNotSupported},
		{"credential required", consent.ErrDecisionCredentialRequired, http.StatusUnauthorized, CodeCredentialRequired},
		{"request expired", consent.ErrDecisionRequestExpired, http.StatusGone, CodeRequestExpired},
		{"already decided", consent.ErrDecisionAlreadyDecided, http.StatusConflict, CodeRequestAlreadyDecided},
		{"user not eligible", consent.NewProviderError(consent.ClassUserNotEligible, nil), http.StatusForbidden, CodeUserNotEligible},
		{"provider unavailable", consent.NewProviderError(consent.ClassProviderUnavailable, nil), http.StatusBadGateway, CodeProviderUnavailable},
		{"rate limited", consent.NewProviderError(consent.ClassRateLimited, nil), http.StatusBadGateway, CodeProviderUnavailable},
		{"unexpected provider class", consent.NewProviderError(consent.ClassInternal, nil), http.StatusInternalServerError, CodeInternal},
		{"store failure", context.DeadlineExceeded, http.StatusInternalServerError, CodeInternal},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			decider := &stubDecider{err: tc.err}
			router := buildDecisionRouter(decider, &stubDecrypter{}, true, true)
			rec := doPost(t, router, "/authorization/requests/V2-request-1/decision", `{"decision":"allow"}`)
			if rec.Code != tc.wantStatus {
				t.Fatalf("status = %d, want %d, body %s", rec.Code, tc.wantStatus, rec.Body.String())
			}
			body := decodeBody(t, rec)
			errBody := body["error"].(map[string]any)
			if errBody["code"] != tc.wantCode {
				t.Fatalf("code = %v, want %s", errBody["code"], tc.wantCode)
			}
		})
	}
}

// TestDecideRequestCredentialReaderBindsAuthenticatedRecord proves the
// reader handed to the service decrypts ONLY the sealed credential of the
// session authenticated on this request.
func TestDecideRequestCredentialReaderBindsAuthenticatedRecord(t *testing.T) {
	decider := &stubDecider{
		outcome:   consent.DecisionOutcome{RedirectURL: "https://rp.example/callback?code=abc"},
		probeCred: true,
	}
	decrypter := &stubDecrypter{cred: session.ProviderSessionCredential{
		Version:      session.ProviderSessionCredentialVersion2,
		Provider:     "zitadel",
		SessionID:    "provider-session-1",
		SessionToken: "provider-token-1",
	}}
	router := buildDecisionRouter(decider, decrypter, true, true)

	rec := doPost(t, router, "/authorization/requests/V2-request-1/decision", `{"decision":"allow"}`)
	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, body %s", rec.Code, rec.Body.String())
	}
	if decider.lastCredErr != nil || decider.lastCred.Provider != "zitadel" {
		t.Fatalf("probed credential: cred=%+v err=%v", decider.lastCred, decider.lastCredErr)
	}
	if decrypter.calls != 1 || decrypter.blob != testDecisionBlob {
		t.Fatalf("decrypter usage: calls=%d blob=%q", decrypter.calls, decrypter.blob)
	}
}

func TestSessionCredentialReaderFailsClosed(t *testing.T) {
	record := session.SessionRecord{
		SessionID:                 testDecisionSessionID,
		ProviderSessionCredential: testDecisionBlob,
	}
	decrypter := &stubDecrypter{}

	t.Run("mismatched session id", func(t *testing.T) {
		reader := NewSessionCredentialReader(record, decrypter)
		_, err := reader.ReadProviderSessionCredential(context.Background(), session.SessionID("other-session"))
		if !errors.Is(err, session.ErrProviderSessionCredentialMissing) {
			t.Fatalf("err = %v, want missing sentinel", err)
		}
		if decrypter.calls != 0 {
			t.Fatal("decrypter called for a foreign session id")
		}
	})

	t.Run("empty session id", func(t *testing.T) {
		reader := NewSessionCredentialReader(record, decrypter)
		_, err := reader.ReadProviderSessionCredential(context.Background(), "")
		if !errors.Is(err, session.ErrProviderSessionCredentialMissing) {
			t.Fatalf("err = %v, want missing sentinel", err)
		}
	})

	t.Run("legacy session without credential", func(t *testing.T) {
		legacy := session.SessionRecord{SessionID: testDecisionSessionID}
		reader := NewSessionCredentialReader(legacy, decrypter)
		_, err := reader.ReadProviderSessionCredential(context.Background(), testDecisionSessionID)
		if !errors.Is(err, session.ErrProviderSessionCredentialMissing) {
			t.Fatalf("err = %v, want missing sentinel", err)
		}
		if decrypter.calls != 0 {
			t.Fatal("decrypter called for a credential-less record")
		}
	})

	t.Run("decrypter failure propagates", func(t *testing.T) {
		failing := &stubDecrypter{err: errors.New("key exploded")}
		reader := NewSessionCredentialReader(record, failing)
		_, err := reader.ReadProviderSessionCredential(context.Background(), testDecisionSessionID)
		if err == nil || errors.Is(err, session.ErrProviderSessionCredentialMissing) {
			t.Fatalf("err = %v, want the raw decrypter failure", err)
		}
	})
}
