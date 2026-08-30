package httpapi

import (
	"bytes"
	"context"
	"encoding/json"
	"image"
	"image/color"
	"image/png"
	"mime/multipart"
	"net/http"
	"net/http/httptest"
	"sync"
	"testing"
	"time"

	"github.com/GravelEvolution/united-pass/backend/internal/identity"
	"github.com/GravelEvolution/united-pass/backend/internal/permissions"
	"github.com/GravelEvolution/united-pass/backend/internal/session"
	"github.com/go-chi/chi/v5"
)

// profileMemoryStore is deliberately stateful: mutation handlers and GET /me
// share the same store so these tests prove that successful writes are visible
// to a subsequent authoritative read instead of merely changing handler-local
// state.
type profileMemoryStore struct {
	mu    sync.Mutex
	users map[identity.UserID]identity.User
}

func (s *profileMemoryStore) GetByID(_ context.Context, userID identity.UserID) (identity.User, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	user, ok := s.users[userID]
	if !ok {
		return identity.User{}, identity.ErrUserNotFound
	}
	return user, nil
}

func (s *profileMemoryStore) UpdateProfile(_ context.Context, userID identity.UserID, displayName, nickname string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	user, ok := s.users[userID]
	if !ok {
		return identity.ErrUserNotFound
	}
	user.DisplayName = displayName
	user.Nickname = nickname
	user.UpdatedAt = time.Now().UTC()
	user.Version++
	s.users[userID] = user
	return nil
}

func (s *profileMemoryStore) UpdateAvatar(_ context.Context, userID identity.UserID, avatarURL string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	user, ok := s.users[userID]
	if !ok {
		return identity.ErrUserNotFound
	}
	user.AvatarURL = avatarURL
	user.UpdatedAt = time.Now().UTC()
	user.Version++
	s.users[userID] = user
	return nil
}

func newProfileHandlerTestStore() (*profileMemoryStore, identity.User) {
	now := time.Now().UTC()
	user := identity.User{
		ID:          identity.UserID("user_0123456789abcdef0123456789abcdef"),
		Status:      identity.UserStatusActive,
		DisplayName: "旧显示名称",
		Nickname:    "旧昵称",
		Email:       "profile@example.com",
		Personas:    []identity.Persona{identity.PersonaConsumer},
		CreatedAt:   now,
		UpdatedAt:   now,
		Version:     1,
	}
	return &profileMemoryStore{users: map[identity.UserID]identity.User{user.ID: user}}, user
}

func profileRequestWithPrincipal(method, target string, body *bytes.Reader, userID identity.UserID) *http.Request {
	req := httptest.NewRequest(method, target, body)
	ctx := WithPrincipal(req.Context(), session.Principal{UserID: userID})
	return req.WithContext(ctx)
}

func readCurrentUserForProfileTest(t *testing.T, handler *AccountHandlers, userID identity.UserID) currentUserResponse {
	t.Helper()
	req := httptest.NewRequest(http.MethodGet, "/api/v1/me", nil)
	req = req.WithContext(WithPrincipal(req.Context(), session.Principal{UserID: userID}))
	recorder := httptest.NewRecorder()
	handler.GetCurrentUser(recorder, req)
	if recorder.Code != http.StatusOK {
		t.Fatalf("GET /me status = %d, want %d; body=%s", recorder.Code, http.StatusOK, recorder.Body.String())
	}
	var response currentUserResponse
	if err := json.Unmarshal(recorder.Body.Bytes(), &response); err != nil {
		t.Fatalf("decode GET /me: %v", err)
	}
	return response
}

func TestUpdateProfilePersistsAndCurrentUserReadsItBack(t *testing.T) {
	store, user := newProfileHandlerTestStore()
	handler := NewAccountHandlers(store, permissions.NewDefaultResolver(), store, t.TempDir())
	body := bytes.NewBufferString(`{"displayName":"  新显示名称  ","nickname":"  新昵称  "}`)
	req := profileRequestWithPrincipal(http.MethodPatch, "/api/v1/me/profile", bytes.NewReader(body.Bytes()), user.ID)
	recorder := httptest.NewRecorder()

	handler.UpdateProfile(recorder, req)

	if recorder.Code != http.StatusNoContent {
		t.Fatalf("PATCH /me/profile status = %d, want %d; body=%s", recorder.Code, http.StatusNoContent, recorder.Body.String())
	}
	current := readCurrentUserForProfileTest(t, handler, user.ID)
	if current.DisplayName != "新显示名称" || current.Nickname != "新昵称" {
		t.Fatalf("GET /me profile = %q/%q, want persisted normalized values", current.DisplayName, current.Nickname)
	}
	stored, err := store.GetByID(context.Background(), user.ID)
	if err != nil {
		t.Fatalf("read profile store: %v", err)
	}
	if stored.Version != user.Version+1 {
		t.Fatalf("stored version = %d, want %d", stored.Version, user.Version+1)
	}
}

func TestUpdateProfilePartialMutationPreservesOmittedValue(t *testing.T) {
	store, user := newProfileHandlerTestStore()
	handler := NewAccountHandlers(store, permissions.NewDefaultResolver(), store, t.TempDir())
	req := profileRequestWithPrincipal(http.MethodPatch, "/api/v1/me/profile", bytes.NewReader([]byte(`{"nickname":"只改昵称"}`)), user.ID)
	recorder := httptest.NewRecorder()

	handler.UpdateProfile(recorder, req)

	if recorder.Code != http.StatusNoContent {
		t.Fatalf("PATCH /me/profile status = %d, want %d; body=%s", recorder.Code, http.StatusNoContent, recorder.Body.String())
	}
	current := readCurrentUserForProfileTest(t, handler, user.ID)
	if current.DisplayName != user.DisplayName || current.Nickname != "只改昵称" {
		t.Fatalf("GET /me profile = %q/%q, want %q/%q", current.DisplayName, current.Nickname, user.DisplayName, "只改昵称")
	}
}

func TestUploadAvatarPersistsURLAndCurrentUserReadsItBack(t *testing.T) {
	store, user := newProfileHandlerTestStore()
	avatarDir := t.TempDir()
	handler := NewAccountHandlers(store, permissions.NewDefaultResolver(), store, avatarDir)

	var imageBytes bytes.Buffer
	img := image.NewRGBA(image.Rect(0, 0, 96, 80))
	for y := 0; y < 80; y++ {
		for x := 0; x < 96; x++ {
			img.SetRGBA(x, y, color.RGBA{R: uint8(x), G: uint8(y), B: 160, A: 255})
		}
	}
	if err := png.Encode(&imageBytes, img); err != nil {
		t.Fatalf("encode test avatar: %v", err)
	}
	var multipartBody bytes.Buffer
	writer := multipart.NewWriter(&multipartBody)
	part, err := writer.CreateFormFile("file", "avatar.png")
	if err != nil {
		t.Fatalf("create avatar multipart field: %v", err)
	}
	if _, err := part.Write(imageBytes.Bytes()); err != nil {
		t.Fatalf("write avatar multipart field: %v", err)
	}
	if err := writer.Close(); err != nil {
		t.Fatalf("close multipart body: %v", err)
	}

	req := httptest.NewRequest(http.MethodPost, "/api/v1/me/avatar", &multipartBody)
	req.Header.Set("Content-Type", writer.FormDataContentType())
	req = req.WithContext(WithPrincipal(req.Context(), session.Principal{UserID: user.ID}))
	recorder := httptest.NewRecorder()
	handler.UploadAvatar(recorder, req)

	if recorder.Code != http.StatusOK {
		t.Fatalf("POST /me/avatar status = %d, want %d; body=%s", recorder.Code, http.StatusOK, recorder.Body.String())
	}
	wantStoredURL := "/api/v1/media/avatars/" + string(user.ID)
	wantURL := wantStoredURL + "?v=2"
	var uploadResponse map[string]string
	if err := json.Unmarshal(recorder.Body.Bytes(), &uploadResponse); err != nil {
		t.Fatalf("decode avatar upload: %v", err)
	}
	if uploadResponse["avatarUrl"] != wantURL {
		t.Fatalf("upload avatarUrl = %q, want %q", uploadResponse["avatarUrl"], wantURL)
	}
	current := readCurrentUserForProfileTest(t, handler, user.ID)
	if current.AvatarURL == nil || *current.AvatarURL != wantURL {
		t.Fatalf("GET /me avatarUrl = %v, want %q", current.AvatarURL, wantURL)
	}
	stored, err := store.GetByID(context.Background(), user.ID)
	if err != nil {
		t.Fatalf("read avatar store: %v", err)
	}
	if stored.AvatarURL != wantStoredURL {
		t.Fatalf("stored avatarUrl = %q, want stable %q", stored.AvatarURL, wantStoredURL)
	}

	// Exercise the production media handler through chi so its route parameter
	// and stored file path are both verified.
	router := chi.NewRouter()
	router.Get("/api/v1/media/avatars/{userId}", func(w http.ResponseWriter, r *http.Request) {
		r = r.WithContext(WithPrincipal(r.Context(), session.Principal{UserID: user.ID}))
		handler.ServeAvatar(w, r)
	})
	serveReq := httptest.NewRequest(http.MethodGet, wantURL, nil)
	serveRecorder := httptest.NewRecorder()
	router.ServeHTTP(serveRecorder, serveReq)
	if serveRecorder.Code != http.StatusOK || serveRecorder.Body.Len() == 0 {
		t.Fatalf("served avatar status/bytes = %d/%d, want 200/non-empty", serveRecorder.Code, serveRecorder.Body.Len())
	}
}
