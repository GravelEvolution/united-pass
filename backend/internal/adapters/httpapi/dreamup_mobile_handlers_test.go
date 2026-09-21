package httpapi

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"net/http"
	"net/http/httptest"
	"strconv"
	"strings"
	"testing"
	"time"

	requestctx "github.com/GravelEvolution/united-pass/backend/internal/adapters/httpapi/request"
	"github.com/GravelEvolution/united-pass/backend/internal/dreamupdelegation"
	"github.com/GravelEvolution/united-pass/backend/internal/identity"
	"github.com/GravelEvolution/united-pass/backend/internal/session"
)

type dreamUPParticipantSignerStub struct {
	input dreamupdelegation.ParticipantAssertion
	err   error
}

func (s *dreamUPParticipantSignerStub) SignParticipant(input dreamupdelegation.ParticipantAssertion) (dreamupdelegation.SignedAssertion, error) {
	s.input = input
	if s.err != nil {
		return dreamupdelegation.SignedAssertion{}, s.err
	}
	return dreamupdelegation.SignedAssertion{Token: "short-lived-request-bound-assertion", ExpiresAt: time.Now().Add(time.Second)}, nil
}

type dreamUPSubjectResolverStub struct {
	link  identity.IdentityLink
	err   error
	calls int
}

func (s *dreamUPSubjectResolverStub) GetIdentityLinkByUserID(context.Context, string, string, identity.UserID) (identity.IdentityLink, error) {
	s.calls++
	return s.link, s.err
}

type dreamUPMobileRateStub struct {
	deny      bool
	retry     time.Duration
	err       error
	calls     int
	userID    string
	sessionID string
	ip        string
	scoped    int
	global    int
	window    time.Duration
}

func (s *dreamUPMobileRateStub) CheckDreamUPMobileAssertion(_ context.Context, userID, sessionID, ip string, scoped, global int, window time.Duration) (bool, time.Duration, error) {
	s.calls++
	s.userID, s.sessionID, s.ip = userID, sessionID, ip
	s.scoped, s.global, s.window = scoped, global, window
	return !s.deny && s.err == nil, s.retry, s.err
}

func newDreamUPMobileTestHandlers(signer DreamUPParticipantSigner, resolver DreamUPSubjectResolver) *DreamUPMobileHandlers {
	return NewDreamUPMobileHandlers(signer, resolver, &dreamUPMobileRateStub{}, "zitadel", "project", 60, 2000, time.Minute, testLogger())
}

func dreamUPMobilePrincipal(userID identity.UserID) session.Principal {
	return session.Principal{UserID: userID, SessionID: "session_mobile_01"}
}

func TestDreamUPMobileAssertionUsesBoundOIDCSubjectAndExactBody(t *testing.T) {
	userID := identity.UserID("up-user-01")
	signer := &dreamUPParticipantSignerStub{}
	h := newDreamUPMobileTestHandlers(signer, &dreamUPSubjectResolverStub{link: identity.IdentityLink{UserID: userID, Provider: "zitadel", ProviderTenantID: "project", ProviderSubject: "oidc-subject-01"}})
	requestBody := `{"schemaVersion":"dreamup-application-v2"}`
	body := `{"method":"PUT","path":"/api/v1/events/dreamup-shanghai/me/application","body":` + strconv.Quote(requestBody) + `}`
	req := httptest.NewRequest(http.MethodPost, "/api/v1/dreamup/mobile/assertions", strings.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("X-UnitedPass-Client", "dreamup-miniprogram")
	ctx := requestctx.WithID(WithPrincipal(req.Context(), dreamUPMobilePrincipal(userID)), "req_mobile_assertion_01")
	rr := httptest.NewRecorder()
	h.CreateAssertion(rr, req.WithContext(ctx))
	if rr.Code != http.StatusCreated {
		t.Fatalf("status=%d body=%s", rr.Code, rr.Body.String())
	}
	if signer.input.Subject != "oidc-subject-01" || signer.input.JWTID != "req_mobile_assertion_01" {
		t.Fatalf("input=%+v", signer.input)
	}
	sum := sha256.Sum256([]byte(requestBody))
	if signer.input.BodySHA256 != hex.EncodeToString(sum[:]) {
		t.Fatalf("body hash=%q", signer.input.BodySHA256)
	}
	if strings.Contains(rr.Body.String(), "oidc-subject-01") {
		t.Fatal("response exposed provider subject")
	}
}

func TestDreamUPMobileAssertionRejectsMissingNativeMarker(t *testing.T) {
	signer := &dreamUPParticipantSignerStub{}
	h := newDreamUPMobileTestHandlers(signer, &dreamUPSubjectResolverStub{link: identity.IdentityLink{UserID: "up-user-01", Provider: "zitadel", ProviderTenantID: "project", ProviderSubject: "oidc"}})
	req := httptest.NewRequest(http.MethodPost, "/api/v1/dreamup/mobile/assertions", strings.NewReader(`{"method":"GET","path":"/api/v1/events/dreamup/me/application","body":""}`))
	req.Header.Set("Content-Type", "application/json")
	rr := httptest.NewRecorder()
	h.CreateAssertion(rr, req.WithContext(WithPrincipal(req.Context(), dreamUPMobilePrincipal("up-user-01"))))
	if rr.Code != http.StatusNotFound || signer.input.Subject != "" {
		t.Fatalf("status=%d input=%+v", rr.Code, signer.input)
	}
}

func TestDreamUPMobileAssertionEnforcesWorkerRouteSpecificUTF8ByteLimits(t *testing.T) {
	userID := identity.UserID("up-user-limits")
	for _, test := range []struct {
		name  string
		path  string
		limit int
	}{
		{name: "feedback", path: "/api/v1/events/dreamup-shanghai/me/feedback", limit: maxDreamUPMobileContactBody},
		{name: "seat confirm", path: "/api/v1/events/dreamup-shanghai/me/seat-confirm", limit: maxDreamUPMobileContactBody},
		{name: "admission entry code", path: "/api/v1/events/dreamup-shanghai/me/admission/entry-code", limit: maxDreamUPMobileContactBody},
		{name: "team", path: "/api/v1/events/dreamup-shanghai/me/team", limit: maxDreamUPMobileTeamBody},
		{name: "application", path: "/api/v1/events/dreamup-shanghai/me/application", limit: maxDreamUPMobileAssertionBody},
	} {
		t.Run(test.name, func(t *testing.T) {
			for _, size := range []int{test.limit, test.limit + 1} {
				signer := &dreamUPParticipantSignerStub{}
				h := newDreamUPMobileTestHandlers(signer, &dreamUPSubjectResolverStub{link: identity.IdentityLink{UserID: userID, Provider: "zitadel", ProviderTenantID: "project", ProviderSubject: "oidc-limit-subject"}})
				requestBody := strings.Repeat("a", size)
				body := `{"method":"POST","path":` + strconv.Quote(test.path) + `,"body":` + strconv.Quote(requestBody) + `,"idempotencyKey":"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"}`
				req := httptest.NewRequest(http.MethodPost, "/api/v1/dreamup/mobile/assertions", strings.NewReader(body))
				req.Header.Set("Content-Type", "application/json")
				req.Header.Set("X-UnitedPass-Client", "dreamup-miniprogram")
				ctx := requestctx.WithID(WithPrincipal(req.Context(), dreamUPMobilePrincipal(userID)), "req_mobile_limit_01")
				rr := httptest.NewRecorder()
				h.CreateAssertion(rr, req.WithContext(ctx))
				if size == test.limit && rr.Code != http.StatusCreated {
					t.Fatalf("size=%d status=%d body=%s", size, rr.Code, rr.Body.String())
				}
				if size > test.limit && (rr.Code != http.StatusUnprocessableEntity || signer.input.Subject != "") {
					t.Fatalf("oversize=%d status=%d signer=%+v", size, rr.Code, signer.input)
				}
			}
		})
	}
}

func TestDreamUPMobileResumeUploadRejectsUppercaseDigestBeforeSigning(t *testing.T) {
	userID := identity.UserID("up-user-resume-uppercase")
	signer := &dreamUPParticipantSignerStub{}
	h := newDreamUPMobileTestHandlers(signer, &dreamUPSubjectResolverStub{link: identity.IdentityLink{UserID: userID, Provider: "zitadel", ProviderTenantID: "project", ProviderSubject: "oidc-resume-subject"}})
	digest := strings.ToUpper(strings.Repeat("ab", sha256.Size))
	body := `{"method":"PUT","path":"/api/v1/events/dreamup-shanghai/me/application/resume","fileName":"resume.pdf","contentType":"application/pdf","byteSize":33,"bodySha256":"` + digest + `"}`
	req := httptest.NewRequest(http.MethodPost, "/api/v1/dreamup/mobile/resume-upload-assertions", strings.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("X-UnitedPass-Client", "dreamup-miniprogram")
	rr := httptest.NewRecorder()
	h.CreateResumeUploadAssertion(rr, req.WithContext(WithPrincipal(req.Context(), dreamUPMobilePrincipal(userID))))
	if rr.Code != http.StatusUnprocessableEntity || signer.input.Subject != "" {
		t.Fatalf("status=%d signer=%+v body=%s", rr.Code, signer.input, rr.Body.String())
	}
}

func TestDreamUPMobileResumeUploadAssertionBindsMetadataAndDigestWithoutFileBody(t *testing.T) {
	userID := identity.UserID("up-user-resume")
	signer := &dreamUPParticipantSignerStub{}
	h := newDreamUPMobileTestHandlers(signer, &dreamUPSubjectResolverStub{link: identity.IdentityLink{UserID: userID, Provider: "zitadel", ProviderTenantID: "project", ProviderSubject: "oidc-resume-subject"}})
	digest := sha256.Sum256([]byte("PDF bytes are sent only to DreamUP"))
	body := `{"method":"PUT","path":"/api/v1/events/dreamup-shanghai/me/application/resume","fileName":"resume.pdf","contentType":"application/pdf","byteSize":33,"bodySha256":"` + hex.EncodeToString(digest[:]) + `"}`
	req := httptest.NewRequest(http.MethodPost, "/api/v1/dreamup/mobile/resume-upload-assertions", strings.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("X-UnitedPass-Client", "dreamup-miniprogram")
	ctx := requestctx.WithID(WithPrincipal(req.Context(), dreamUPMobilePrincipal(userID)), "req_mobile_resume_01")
	rr := httptest.NewRecorder()
	h.CreateResumeUploadAssertion(rr, req.WithContext(ctx))
	if rr.Code != http.StatusCreated {
		t.Fatalf("status=%d body=%s", rr.Code, rr.Body.String())
	}
	if signer.input.Subject != "oidc-resume-subject" || signer.input.BodySHA256 != hex.EncodeToString(digest[:]) || signer.input.ResumeUpload == nil {
		t.Fatalf("input=%+v", signer.input)
	}
	if got := signer.input.ResumeUpload; got.FileName != "resume.pdf" || got.ContentType != "application/pdf" || got.ByteSize != 33 {
		t.Fatalf("metadata=%+v", got)
	}
	if strings.Contains(rr.Body.String(), "resume.pdf") || strings.Contains(rr.Body.String(), "oidc-resume-subject") {
		t.Fatal("response exposed bound identity or file metadata")
	}
}

func TestDreamUPMobileAssertionIdentityFailuresDoNotMasqueradeAsExpiredSessions(t *testing.T) {
	userID := identity.UserID("up-user-identity-failure")
	digest := sha256.Sum256([]byte("resume"))
	endpoints := []struct {
		name   string
		path   string
		body   string
		invoke func(*DreamUPMobileHandlers, http.ResponseWriter, *http.Request)
	}{
		{
			name: "ordinary", path: "/api/v1/dreamup/mobile/assertions",
			body:   `{"method":"GET","path":"/api/v1/events/dreamup-shanghai/me/application","body":""}`,
			invoke: (*DreamUPMobileHandlers).CreateAssertion,
		},
		{
			name: "resume", path: "/api/v1/dreamup/mobile/resume-upload-assertions",
			body:   `{"method":"PUT","path":"/api/v1/events/dreamup-shanghai/me/application/resume","fileName":"resume.pdf","contentType":"application/pdf","byteSize":6,"bodySha256":"` + hex.EncodeToString(digest[:]) + `"}`,
			invoke: (*DreamUPMobileHandlers).CreateResumeUploadAssertion,
		},
	}
	failures := []struct {
		name       string
		resolver   *dreamUPSubjectResolverStub
		wantStatus int
		wantCode   string
	}{
		{name: "missing", resolver: &dreamUPSubjectResolverStub{err: identity.ErrUserNotFound}, wantStatus: http.StatusForbidden, wantCode: CodeForbidden},
		{name: "conflict", resolver: &dreamUPSubjectResolverStub{err: identity.ErrIdentityLinkConflict}, wantStatus: http.StatusConflict, wantCode: CodeConflict},
		{name: "storage", resolver: &dreamUPSubjectResolverStub{err: errors.New("database unavailable")}, wantStatus: http.StatusInternalServerError, wantCode: CodeInternal},
		{name: "wrong user projection", resolver: &dreamUPSubjectResolverStub{link: identity.IdentityLink{UserID: "different-user", Provider: "zitadel", ProviderTenantID: "project", ProviderSubject: "oidc"}}, wantStatus: http.StatusInternalServerError, wantCode: CodeInternal},
		{name: "wrong provider projection", resolver: &dreamUPSubjectResolverStub{link: identity.IdentityLink{UserID: userID, Provider: "other", ProviderTenantID: "project", ProviderSubject: "oidc"}}, wantStatus: http.StatusInternalServerError, wantCode: CodeInternal},
		{name: "wrong tenant projection", resolver: &dreamUPSubjectResolverStub{link: identity.IdentityLink{UserID: userID, Provider: "zitadel", ProviderTenantID: "other", ProviderSubject: "oidc"}}, wantStatus: http.StatusInternalServerError, wantCode: CodeInternal},
		{name: "empty subject projection", resolver: &dreamUPSubjectResolverStub{link: identity.IdentityLink{UserID: userID, Provider: "zitadel", ProviderTenantID: "project"}}, wantStatus: http.StatusInternalServerError, wantCode: CodeInternal},
	}

	for _, endpoint := range endpoints {
		for _, failure := range failures {
			t.Run(endpoint.name+"/"+failure.name, func(t *testing.T) {
				signer := &dreamUPParticipantSignerStub{}
				h := newDreamUPMobileTestHandlers(signer, failure.resolver)
				req := httptest.NewRequest(http.MethodPost, endpoint.path, strings.NewReader(endpoint.body))
				req.Header.Set("Content-Type", "application/json")
				req.Header.Set("X-UnitedPass-Client", "dreamup-miniprogram")
				rr := httptest.NewRecorder()
				endpoint.invoke(h, rr, req.WithContext(WithPrincipal(req.Context(), dreamUPMobilePrincipal(userID))))
				if rr.Code != failure.wantStatus {
					t.Fatalf("status=%d want=%d body=%s", rr.Code, failure.wantStatus, rr.Body.String())
				}
				if body := decodeErrorBody(t, rr); body.Code != failure.wantCode || body.Code == CodeUnauthorized {
					t.Fatalf("error=%+v want code=%q and never %q", body, failure.wantCode, CodeUnauthorized)
				}
				if signer.input.Subject != "" {
					t.Fatalf("identity failure reached signer: %+v", signer.input)
				}
			})
		}
	}
}

func TestDreamUPMobileAssertionEndpointsReserveUnauthenticatedForMissingPrincipal(t *testing.T) {
	for _, endpoint := range []struct {
		name   string
		path   string
		invoke func(*DreamUPMobileHandlers, http.ResponseWriter, *http.Request)
	}{
		{name: "ordinary", path: "/api/v1/dreamup/mobile/assertions", invoke: (*DreamUPMobileHandlers).CreateAssertion},
		{name: "resume", path: "/api/v1/dreamup/mobile/resume-upload-assertions", invoke: (*DreamUPMobileHandlers).CreateResumeUploadAssertion},
	} {
		t.Run(endpoint.name, func(t *testing.T) {
			h := newDreamUPMobileTestHandlers(&dreamUPParticipantSignerStub{}, &dreamUPSubjectResolverStub{})
			rr := httptest.NewRecorder()
			endpoint.invoke(h, rr, httptest.NewRequest(http.MethodPost, endpoint.path, nil))
			if rr.Code != http.StatusUnauthorized {
				t.Fatalf("status=%d body=%s", rr.Code, rr.Body.String())
			}
			if body := decodeErrorBody(t, rr); body.Code != CodeUnauthorized {
				t.Fatalf("error=%+v want code=%q", body, CodeUnauthorized)
			}
		})
	}
}

func TestDreamUPMobileAssertionEndpointsRateLimitBeforeDecodeResolveAndSign(t *testing.T) {
	for _, endpoint := range []struct {
		name   string
		path   string
		invoke func(*DreamUPMobileHandlers, http.ResponseWriter, *http.Request)
	}{
		{name: "ordinary", path: "/api/v1/dreamup/mobile/assertions", invoke: (*DreamUPMobileHandlers).CreateAssertion},
		{name: "resume", path: "/api/v1/dreamup/mobile/resume-upload-assertions", invoke: (*DreamUPMobileHandlers).CreateResumeUploadAssertion},
	} {
		for _, failure := range []struct {
			name string
			deny bool
			err  error
		}{
			{name: "budget exhausted", deny: true},
			{name: "redis unavailable", err: errors.New("redis unavailable")},
		} {
			t.Run(endpoint.name+"/"+failure.name, func(t *testing.T) {
				userID := identity.UserID("up-user-rate")
				signer := &dreamUPParticipantSignerStub{}
				resolver := &dreamUPSubjectResolverStub{link: identity.IdentityLink{UserID: userID, Provider: "zitadel", ProviderTenantID: "project", ProviderSubject: "oidc-rate"}}
				rate := &dreamUPMobileRateStub{deny: failure.deny, retry: 7 * time.Second, err: failure.err}
				h := NewDreamUPMobileHandlers(signer, resolver, rate, "zitadel", "project", 60, 2000, time.Minute, testLogger())
				req := httptest.NewRequest(http.MethodPost, endpoint.path, strings.NewReader("not-json"))
				req.RemoteAddr = "203.0.113.77:443"
				req.Header.Set("Content-Type", "application/json")
				req.Header.Set("X-UnitedPass-Client", "dreamup-miniprogram")
				ctx := WithPrincipal(req.Context(), session.Principal{UserID: userID, SessionID: "session-rate-01"})
				rr := httptest.NewRecorder()
				endpoint.invoke(h, rr, req.WithContext(ctx))
				if rr.Code != http.StatusTooManyRequests || rr.Header().Get("Retry-After") != "7" {
					t.Fatalf("status=%d retry=%q body=%s", rr.Code, rr.Header().Get("Retry-After"), rr.Body.String())
				}
				if rate.calls != 1 || rate.userID != string(userID) || rate.sessionID != "session-rate-01" || rate.ip != "203.0.113.77" || rate.scoped != 60 || rate.global != 2000 || rate.window != time.Minute {
					t.Fatalf("rate binding=%+v", rate)
				}
				if resolver.calls != 0 || signer.input.Subject != "" {
					t.Fatalf("expensive work ran: resolverCalls=%d signer=%+v", resolver.calls, signer.input)
				}
			})
		}
	}
}
