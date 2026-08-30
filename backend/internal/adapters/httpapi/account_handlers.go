//
// Copyright (c) 2026 Chen Jiajie(Ariakage)
//
// Author: Chen Jiajie(Ariakage) <ariakage233@gmail.com>
// Date: 2026-08-05
// Description: HTTP handlers for the account self-service endpoints
//

package httpapi

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"image"
	"image/color"
	"image/jpeg"
	_ "image/png"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"unicode/utf8"

	"github.com/GravelEvolution/united-pass/backend/internal/identity"
	"github.com/GravelEvolution/united-pass/backend/internal/permissions"
	"github.com/GravelEvolution/united-pass/backend/internal/workforce"
	"github.com/go-chi/chi/v5"
)

// UserReader loads user data for the current-user endpoints. The PostgreSQL
// UserRepository satisfies this interface. It is defined here (close to the
// consumer) per AGENTS.md §8.
type UserReader interface {
	// GetByID loads a user by stable United Pass user ID, including personas.
	// Returns identity.ErrUserNotFound when no row matches.
	GetByID(ctx context.Context, userID identity.UserID) (identity.User, error)
}

// UserWriter persists self-service user profile mutations. The PostgreSQL
// UserRepository satisfies this interface.
type UserWriter interface {
	// UpdateProfile stores the display name and nickname of a user. Returns
	// identity.ErrUserNotFound when no row matches.
	UpdateProfile(ctx context.Context, userID identity.UserID, displayName, nickname string) error
	// UpdateAvatar stores the avatar URL of a user. Returns
	// identity.ErrUserNotFound when no row matches.
	UpdateAvatar(ctx context.Context, userID identity.UserID, avatarURL string) error
}

// AccountHandlers serves the current-user endpoints: GET /me, profile and
// avatar self-service, and the avatar media endpoint.
type AccountHandlers struct {
	userReader   UserReader
	userWriter   UserWriter
	avatarDir    string
	permResolver permissions.Resolver
	employees    interface {
		GetEmployeeProfile(ctx context.Context, userID identity.UserID) (workforce.EmployeeProfile, error)
	}
}

// NewAccountHandlers builds AccountHandlers from the given dependencies.
func NewAccountHandlers(userReader UserReader, permResolver permissions.Resolver, userWriter UserWriter, avatarDir string, employeeReaders ...interface {
	GetEmployeeProfile(ctx context.Context, userID identity.UserID) (workforce.EmployeeProfile, error)
}) *AccountHandlers {
	handler := &AccountHandlers{
		userReader:   userReader,
		userWriter:   userWriter,
		avatarDir:    avatarDir,
		permResolver: permResolver,
	}
	if len(employeeReaders) > 0 {
		handler.employees = employeeReaders[0]
	}
	return handler
}

// currentUserResponse is the JSON response for GET /api/v1/me. Field names
// match the frontend CurrentUser type exactly.
// See ../frontend/src/types/identity.ts.
type currentUserResponse struct {
	UserID          string                          `json:"userId"`
	DisplayName     string                          `json:"displayName"`
	Nickname        string                          `json:"nickname"`
	AvatarURL       *string                         `json:"avatarUrl"`
	Email           string                          `json:"email"`
	PhoneMasked     string                          `json:"phoneMasked"`
	Personas        []string                        `json:"personas"`
	EmployeeProfile *currentEmployeeProfileResponse `json:"employeeProfile"`
}

type currentEmployeeProfileResponse struct {
	EmployeeID     string `json:"employeeId"`
	DepartmentName string `json:"departmentName"`
	Title          string `json:"title"`
}

// GetCurrentUser handles GET /api/v1/me.
//
// Returns the current session user's profile. The response uses the stable
// United Pass user ID and never includes provider subjects, tokens, or the raw
// phone number. EmployeeProfile is null in Phase 1 (employee profiles are a
// Phase 5 feature).
func (h *AccountHandlers) GetCurrentUser(w http.ResponseWriter, r *http.Request) {
	principal, ok := PrincipalFromContext(r.Context())
	if !ok {
		WriteUnauthorized(w, r)
		return
	}

	user, err := h.userReader.GetByID(r.Context(), principal.UserID)
	if err != nil {
		writeUserLookupError(w, r, err)
		return
	}

	// Verify the user is still active. A disabled user should not receive
	// profile data even if the session has not been cleaned up yet.
	if !user.Status.CanAuthenticate() {
		WriteUnauthorized(w, r)
		return
	}

	personas := make([]string, len(user.Personas))
	for i, p := range user.Personas {
		personas[i] = string(p)
	}
	if len(personas) == 0 {
		personas = []string{}
	}

	var employeeProfile *currentEmployeeProfileResponse
	if h.employees != nil {
		profile, err := h.employees.GetEmployeeProfile(r.Context(), principal.UserID)
		if err == nil {
			employeeProfile = &currentEmployeeProfileResponse{
				EmployeeID: profile.EmployeeNumber, DepartmentName: profile.DepartmentName,
				Title: profile.Title,
			}
		} else if !errors.Is(err, workforce.ErrNotFound) {
			WriteInternalError(w, r)
			return
		}
	}

	resp := currentUserResponse{
		UserID:          string(user.ID),
		DisplayName:     user.DisplayName,
		Nickname:        user.Nickname,
		AvatarURL:       nullableString(versionedAvatarURL(user.AvatarURL, user.Version)),
		Email:           user.Email,
		PhoneMasked:     identity.MaskPhone(user.Phone),
		Personas:        personas,
		EmployeeProfile: employeeProfile,
	}

	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	w.Header().Set("Cache-Control", "no-store")
	w.WriteHeader(http.StatusOK)
	_ = json.NewEncoder(w).Encode(resp)
}

// GetPermissions handles GET /api/v1/me/permissions.
//
// Returns the permission capabilities for the current session user. In Phase 1,
// the resolver is a temporary fail-closed implementation. Phase 7 replaces it
// with Cerbos without changing the API contract.
func (h *AccountHandlers) GetPermissions(w http.ResponseWriter, r *http.Request) {
	principal, ok := PrincipalFromContext(r.Context())
	if !ok {
		WriteUnauthorized(w, r)
		return
	}

	caps, err := h.permResolver.Resolve(r.Context(), principal.UserID)
	if err != nil {
		WriteInternalError(w, r)
		return
	}

	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	w.Header().Set("Cache-Control", "no-store")
	w.WriteHeader(http.StatusOK)
	_ = json.NewEncoder(w).Encode(caps)
}

const (
	maxAvatarBodyBytes = 2 << 20 // 2 MiB upload payload
	minAvatarEdge      = 64
	maxAvatarEdge      = 4096
	maxAvatarPixels    = 8_388_608
	targetAvatarEdge   = 512
)

type updateProfileRequest struct {
	DisplayName *string `json:"displayName"`
	Nickname    *string `json:"nickname"`
}

// UpdateProfile handles PATCH /api/v1/me/profile. It updates the user's
// self-service display name and nickname. Absent fields keep their current
// values. The display name is required and limited to 64 runes; the nickname
// is optional and limited to 64 runes.
func (h *AccountHandlers) UpdateProfile(w http.ResponseWriter, r *http.Request) {
	principal, ok := PrincipalFromContext(r.Context())
	if !ok || h.userWriter == nil {
		WriteUnauthorized(w, r)
		return
	}

	body, err := io.ReadAll(io.LimitReader(r.Body, 4<<10))
	if err != nil {
		WriteBadRequest(w, r, "请求体无法读取。")
		return
	}
	var req updateProfileRequest
	if err := json.Unmarshal(body, &req); err != nil {
		WriteBadRequest(w, r, "请求格式无效。")
		return
	}

	user, err := h.userReader.GetByID(r.Context(), principal.UserID)
	if err != nil {
		writeUserLookupError(w, r, err)
		return
	}
	displayName := strings.TrimSpace(user.DisplayName)
	if req.DisplayName != nil {
		displayName = strings.TrimSpace(*req.DisplayName)
	}
	nickname := strings.TrimSpace(user.Nickname)
	if req.Nickname != nil {
		nickname = strings.TrimSpace(*req.Nickname)
	}
	if displayName == "" || utf8.RuneCountInString(displayName) > 64 || utf8.RuneCountInString(nickname) > 64 {
		WriteValidation(w, r, "显示名称不能为空且不超过 64 个字符，昵称不超过 64 个字符。", nil)
		return
	}

	if err := h.userWriter.UpdateProfile(r.Context(), principal.UserID, displayName, nickname); err != nil {
		if errors.Is(err, identity.ErrUserNotFound) {
			WriteUnauthorized(w, r)
			return
		}
		WriteInternalError(w, r)
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

// UpdateProfileFromMiniProgram is the narrow POST adaptation required by
// wx.request. Authentication remains a transport-bound native bearer.
func (h *AccountHandlers) UpdateProfileFromMiniProgram(w http.ResponseWriter, r *http.Request) {
	if !isMiniProgramClientRequest(r) || !IsNativeBearerSession(r.Context()) {
		WriteNotFound(w, r)
		return
	}
	h.UpdateProfile(w, r)
}

// UploadAvatar handles POST /api/v1/me/avatar. It accepts a JPEG or PNG
// upload (field "file"), validates the image header and dimensions, re-encodes
// it to a JPEG stored under the configured avatar directory, then records the
// served URL on the user. The stored file is named after the stable user ID so
// replacing an avatar is atomic.
func (h *AccountHandlers) UploadAvatar(w http.ResponseWriter, r *http.Request) {
	principal, ok := PrincipalFromContext(r.Context())
	if !ok || h.userWriter == nil || h.avatarDir == "" {
		WriteUnauthorized(w, r)
		return
	}

	r.Body = http.MaxBytesReader(w, r.Body, maxAvatarBodyBytes+(1<<20))
	if err := r.ParseMultipartForm(maxAvatarBodyBytes); err != nil {
		WriteBadRequest(w, r, "头像文件过大或无法解析。")
		return
	}
	file, header, err := r.FormFile("file")
	if err != nil {
		WriteBadRequest(w, r, "缺少头像文件字段。")
		return
	}
	defer file.Close()
	if header.Size <= 0 || header.Size > maxAvatarBodyBytes {
		WriteValidation(w, r, "头像文件必须大于 0 且不超过 2 MiB。", nil)
		return
	}

	data, err := io.ReadAll(io.LimitReader(file, maxAvatarBodyBytes+1))
	if err != nil || len(data) > maxAvatarBodyBytes {
		WriteValidation(w, r, "头像文件必须大于 0 且不超过 2 MiB。", nil)
		return
	}
	img, err := decodeAvatar(data)
	if err != nil {
		WriteValidation(w, r, err.Error(), nil)
		return
	}
	bounds := img.Bounds()
	width, height := bounds.Dx(), bounds.Dy()
	if width < minAvatarEdge || height < minAvatarEdge || width > maxAvatarEdge || height > maxAvatarEdge || width*height > maxAvatarPixels {
		WriteValidation(w, r, "图片宽高必须在 64 到 4096 像素之间，且总像素不得超过 838 万。", nil)
		return
	}

	scaled := scaleAvatar(img, targetAvatarEdge)
	var out bytes.Buffer
	if err := jpeg.Encode(&out, scaled, &jpeg.Options{Quality: 88}); err != nil {
		WriteInternalError(w, r)
		return
	}
	if err := os.MkdirAll(h.avatarDir, 0o750); err != nil {
		WriteInternalError(w, r)
		return
	}
	path := filepath.Join(h.avatarDir, string(principal.UserID)+".jpg")
	tmp := path + ".tmp"
	if err := os.WriteFile(tmp, out.Bytes(), 0o640); err != nil {
		WriteInternalError(w, r)
		return
	}
	if err := os.Rename(tmp, path); err != nil {
		_ = os.Remove(tmp)
		WriteInternalError(w, r)
		return
	}

	avatarURL := "/api/v1/media/avatars/" + string(principal.UserID)
	if err := h.userWriter.UpdateAvatar(r.Context(), principal.UserID, avatarURL); err != nil {
		if errors.Is(err, identity.ErrUserNotFound) {
			WriteUnauthorized(w, r)
			return
		}
		WriteInternalError(w, r)
		return
	}
	updatedUser, err := h.userReader.GetByID(r.Context(), principal.UserID)
	if err != nil {
		writeUserLookupError(w, r, err)
		return
	}
	responseAvatarURL := versionedAvatarURL(avatarURL, updatedUser.Version)

	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	w.Header().Set("Cache-Control", "no-store")
	w.WriteHeader(http.StatusOK)
	_ = json.NewEncoder(w).Encode(map[string]string{"avatarUrl": responseAvatarURL})
}

// ServeAvatar handles GET /api/v1/media/avatars/{userId}. Only an
// authenticated session may read an avatar; the file is served directly from
// the configured avatar directory.
func (h *AccountHandlers) ServeAvatar(w http.ResponseWriter, r *http.Request) {
	if _, ok := PrincipalFromContext(r.Context()); !ok || h.avatarDir == "" {
		WriteUnauthorized(w, r)
		return
	}
	userID := chi.URLParam(r, "userId")
	if !safeAvatarUserID(userID) {
		WriteNotFound(w, r)
		return
	}
	data, err := os.ReadFile(filepath.Join(h.avatarDir, userID+".jpg"))
	if err != nil {
		WriteNotFound(w, r)
		return
	}
	w.Header().Set("Content-Type", "image/jpeg")
	w.Header().Set("Cache-Control", "private, max-age=300")
	w.Header().Set("Content-Length", strconv.Itoa(len(data)))
	w.WriteHeader(http.StatusOK)
	_, _ = w.Write(data)
}

func safeAvatarUserID(userID string) bool {
	if userID == "" || len(userID) > 80 || strings.ContainsAny(userID, `/\`) {
		return false
	}
	return true
}

func decodeAvatar(data []byte) (image.Image, error) {
	img, _, err := image.Decode(bytes.NewReader(data))
	if err != nil {
		return nil, errors.New("图片无法解码，仅支持 JPEG 或 PNG。")
	}
	return img, nil
}

// scaleAvatar resizes src with nearest-neighbour sampling and composites any
// transparency onto a white background, producing an opaque RGBA image that
// JPEG encoding can represent without black spill-through.
func scaleAvatar(src image.Image, maxEdge int) *image.RGBA {
	b := src.Bounds()
	srcW, srcH := b.Dx(), b.Dy()
	scale := 1.0
	if srcW > maxEdge || srcH > maxEdge {
		if srcW >= srcH {
			scale = float64(maxEdge) / float64(srcW)
		} else {
			scale = float64(maxEdge) / float64(srcH)
		}
	}
	dstW := max(1, int(float64(srcW)*scale+0.5))
	dstH := max(1, int(float64(srcH)*scale+0.5))
	dst := image.NewRGBA(image.Rect(0, 0, dstW, dstH))
	for y := 0; y < dstH; y++ {
		for x := 0; x < dstW; x++ {
			sx := b.Min.X + min(srcW-1, int(float64(x)*float64(srcW)/float64(dstW)))
			sy := b.Min.Y + min(srcH-1, int(float64(y)*float64(srcH)/float64(dstH)))
			pr, pg, pb, pa := src.At(sx, sy).RGBA()
			alpha := float64(pa>>8) / 255.0
			dr := float64(pr>>8)*alpha + 255.0*(1-alpha)
			dg := float64(pg>>8)*alpha + 255.0*(1-alpha)
			db := float64(pb>>8)*alpha + 255.0*(1-alpha)
			dst.SetRGBA(x, y, color.RGBA{R: uint8(dr + 0.5), G: uint8(dg + 0.5), B: uint8(db + 0.5), A: 255})
		}
	}
	return dst
}

// writeUserLookupError maps user lookup errors to appropriate HTTP responses.
func writeUserLookupError(w http.ResponseWriter, r *http.Request, err error) {
	if err == identity.ErrUserNotFound {
		WriteUnauthorized(w, r)
		return
	}
	WriteInternalError(w, r)
}

// nullableString returns a pointer to the string when non-empty, or nil when
// empty. This ensures the JSON response uses null for absent optional string
// fields (matching the frontend type which uses `string | null`).
func nullableString(s string) *string {
	if s == "" {
		return nil
	}
	return &s
}

// versionedAvatarURL gives every persisted avatar revision a distinct browser
// cache key while keeping the stable storage path in PostgreSQL. Profile-only
// changes may advance the version and cause one harmless extra image fetch;
// replacing an avatar can never remain hidden behind a cached prior response.
func versionedAvatarURL(raw string, version int) string {
	if raw == "" || !strings.HasPrefix(raw, "/api/v1/media/avatars/") {
		return raw
	}
	return raw + "?v=" + strconv.Itoa(max(0, version))
}
