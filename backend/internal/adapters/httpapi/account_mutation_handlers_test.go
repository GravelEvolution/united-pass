//
// Copyright (c) 2026 Chen Jiajie(Ariakage)
//
// Author: Chen Jiajie(Ariakage) <ariakage233@gmail.com>
// Date: 2026-08-16
// Description: Account profile, avatar and verified-contact handler tests
//

package httpapi

import (
	"bytes"
	"context"
	"encoding/json"
	"image"
	"image/color"
	"image/png"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/go-chi/chi/v5"

	"github.com/GravelEvolution/united-pass/backend/internal/identity"
	"github.com/GravelEvolution/united-pass/backend/internal/session"
)

type accountMutationStoreStub struct {
	displayName *string
	nickname    *string
	avatar      []byte
	etag        string
	contact     identity.ContactChangeRequest
	cancelled   bool
	completed   bool
}

func (s *accountMutationStoreStub) UpdateOwnProfile(
	_ context.Context,
	_ identity.UserID,
	displayName, nickname *string,
) error {
	s.displayName, s.nickname = displayName, nickname
	return nil
}
func (s *accountMutationStoreStub) SaveAvatar(context.Context, identity.UserID, string, []byte, string) (string, error) {
	return "/api/v1/media/avatars/avt_00000000000000000000000000000000.png", nil
}
func (s *accountMutationStoreStub) GetAvatar(context.Context, string) ([]byte, string, error) {
	return s.avatar, s.etag, nil
}
func (s *accountMutationStoreStub) CreateContactChange(_ context.Context, req identity.ContactChangeRequest) error {
	s.contact = req
	return nil
}
func (s *accountMutationStoreStub) CancelContactChange(context.Context, string) error {
	s.cancelled = true
	return nil
}
func (s *accountMutationStoreStub) ClaimContactChange(
	_ context.Context,
	hash string,
	userID identity.UserID,
	sessionID, _ string,
	_ time.Duration,
) (identity.ContactChangeRequest, error) {
	if hash != s.contact.RequestIDHash || userID != s.contact.UserID || sessionID != s.contact.SessionID {
		return identity.ContactChangeRequest{}, identity.ErrContactRequestNotFound
	}
	return s.contact, nil
}
func (s *accountMutationStoreStub) ReleaseContactChange(context.Context, string, string, bool) error {
	return nil
}
func (s *accountMutationStoreStub) CompleteContactChange(context.Context, string, string) error {
	s.completed = true
	return nil
}

type accountContactProviderStub struct {
	beginEmail string
	beginPhone string
	verified   identity.ContactKind
	value      string
}

func (s *accountContactProviderStub) BeginEmailChange(_ context.Context, _ identity.UserID, email string) error {
	s.beginEmail = email
	return nil
}
func (s *accountContactProviderStub) VerifyEmailChange(_ context.Context, _ identity.UserID, email, _ string) error {
	s.verified, s.value = identity.ContactKindEmail, email
	return nil
}
func (s *accountContactProviderStub) BeginPhoneChange(_ context.Context, _ identity.UserID, phone string) error {
	s.beginPhone = phone
	return nil
}
func (s *accountContactProviderStub) VerifyPhoneChange(_ context.Context, _ identity.UserID, phone, _ string) error {
	s.verified, s.value = identity.ContactKindPhone, phone
	return nil
}

type accountContactRateStub struct{}

func (accountContactRateStub) CheckContact(context.Context, string, string, int, time.Duration) (bool, time.Duration, error) {
	return true, 0, nil
}

func accountMutationRequest(method, path, body string) *http.Request {
	req := httptest.NewRequest(method, path, strings.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	return req.WithContext(WithPrincipal(req.Context(), session.Principal{
		UserID: "user_1", SessionID: "session_1",
	}))
}

func withAvatarFile(req *http.Request, value string) *http.Request {
	routeContext := chi.NewRouteContext()
	routeContext.URLParams.Add("avatarFile", value)
	return req.WithContext(context.WithValue(req.Context(), chi.RouteCtxKey, routeContext))
}

func withContactRequestID(req *http.Request, value string) *http.Request {
	routeContext := chi.NewRouteContext()
	routeContext.URLParams.Add("requestId", value)
	return req.WithContext(context.WithValue(req.Context(), chi.RouteCtxKey, routeContext))
}

func TestUpdateOwnProfileTrimsOnlyAllowedFields(t *testing.T) {
	store := &accountMutationStoreStub{}
	handler := NewAccountMutationHandlers(store, nil, accountContactRateStub{}, nil)
	recorder := httptest.NewRecorder()
	handler.UpdateProfile(recorder, accountMutationRequest(
		http.MethodPatch, "/api/v1/me", `{"displayName":"  New Name  ","nickname":" nick "}`,
	))
	if recorder.Code != http.StatusNoContent || store.displayName == nil || *store.displayName != "New Name" ||
		store.nickname == nil || *store.nickname != "nick" {
		t.Fatalf("status = %d, displayName = %v, nickname = %v", recorder.Code, store.displayName, store.nickname)
	}
}

func TestAvatarRouteRequiresCanonicalPNGSuffixAndReturnsCacheValidator(t *testing.T) {
	store := &accountMutationStoreStub{avatar: []byte("controlled-png"), etag: strings.Repeat("a", 64)}
	handler := NewAccountMutationHandlers(store, nil, accountContactRateStub{}, nil)
	avatarID := "avt_00000000000000000000000000000000"

	nonCanonical := httptest.NewRecorder()
	handler.GetAvatar(nonCanonical, withAvatarFile(
		httptest.NewRequest(http.MethodGet, "/api/v1/media/avatars/"+avatarID, nil), avatarID,
	))
	if nonCanonical.Code != http.StatusNotFound {
		t.Fatalf("suffix-less status = %d, want 404", nonCanonical.Code)
	}

	req := withAvatarFile(
		httptest.NewRequest(http.MethodGet, "/api/v1/media/avatars/"+avatarID+".png", nil), avatarID+".png",
	)
	req.Header.Set("If-None-Match", `"`+store.etag+`"`)
	cached := httptest.NewRecorder()
	handler.GetAvatar(cached, req)
	if cached.Code != http.StatusNotModified || cached.Header().Get("ETag") == "" ||
		cached.Header().Get("Cache-Control") == "" {
		t.Fatalf("status = %d, headers = %v", cached.Code, cached.Header())
	}
}

func TestVerifiedEmailChangeIsBoundToUserAndSession(t *testing.T) {
	store := &accountMutationStoreStub{}
	provider := &accountContactProviderStub{}
	handler := NewAccountMutationHandlers(store, provider, accountContactRateStub{}, nil)

	begin := httptest.NewRecorder()
	handler.RequestEmailChange(begin, accountMutationRequest(
		http.MethodPost, "/api/v1/me/email-change-requests", `{"value":"new@example.test"}`,
	))
	if begin.Code != http.StatusCreated || provider.beginEmail != "new@example.test" || store.contact.SessionID != "session_1" {
		t.Fatalf("status = %d, provider = %q, contact = %+v", begin.Code, provider.beginEmail, store.contact)
	}
	var response contactChangeResponse
	if err := decodeJSONRecorder(begin, &response); err != nil {
		t.Fatal(err)
	}

	verifyReq := withContactRequestID(accountMutationRequest(
		http.MethodPost,
		"/api/v1/me/email-change-requests/"+response.RequestID+"/verify",
		`{"code":"ABC123"}`,
	), response.RequestID)
	verify := httptest.NewRecorder()
	handler.VerifyEmailChange(verify, verifyReq)
	if verify.Code != http.StatusNoContent || provider.verified != identity.ContactKindEmail ||
		provider.value != "new@example.test" || !store.completed {
		t.Fatalf("status = %d, provider = %q/%q, completed = %v", verify.Code, provider.verified, provider.value, store.completed)
	}
}

func decodeJSONRecorder(recorder *httptest.ResponseRecorder, target any) error {
	return json.NewDecoder(recorder.Body).Decode(target)
}

func TestSanitizeAvatarReencodesAndRejectsMIMEConfusion(t *testing.T) {
	imageValue := image.NewNRGBA(image.Rect(0, 0, 80, 80))
	for y := 0; y < 80; y++ {
		for x := 0; x < 80; x++ {
			imageValue.Set(x, y, color.NRGBA{R: 50, G: 100, B: 150, A: 255})
		}
	}
	var input bytes.Buffer
	if err := png.Encode(&input, imageValue); err != nil {
		t.Fatal(err)
	}
	output, err := sanitizeAvatar(input.Bytes(), "image/png")
	if err != nil || len(output) == 0 {
		t.Fatalf("sanitize error = %v, output bytes = %d", err, len(output))
	}
	if _, format, err := image.Decode(bytes.NewReader(output)); err != nil || format != "png" {
		t.Fatalf("decoded format = %q, err = %v", format, err)
	}
	if _, err := sanitizeAvatar(input.Bytes(), "image/jpeg"); err == nil {
		t.Fatal("MIME-confused image was accepted")
	}
}
