//
// Copyright (c) 2026 Chen Jiajie(Ariakage)
//
// Author: Chen Jiajie(Ariakage) <ariakage233@gmail.com>
// Date: 2026-08-16
// Description: Current-user profile, avatar and verified-contact mutations
//

package httpapi

import (
	"bytes"
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"image"
	_ "image/jpeg"
	"image/png"
	"io"
	"log/slog"
	"mime"
	"net/http"
	"net/mail"
	"regexp"
	"strconv"
	"strings"
	"time"
	"unicode/utf8"

	"github.com/GravelEvolution/united-pass/backend/internal/identity"
	"github.com/GravelEvolution/united-pass/backend/internal/platform/observability"
	"github.com/GravelEvolution/united-pass/backend/internal/session"
	"github.com/go-chi/chi/v5"
	xdraw "golang.org/x/image/draw"
	_ "golang.org/x/image/webp"
)

const (
	maxAvatarInputBytes   = int64(2 * 1024 * 1024)
	maxAvatarRequestBytes = maxAvatarInputBytes + 128*1024
	maxAvatarEdge         = 4096
	minAvatarEdge         = 64
	maxAvatarPixels       = 8_388_608
	maxAvatarOutputEdge   = 1024
	maxAvatarOutputBytes  = 5 * 1024 * 1024
	contactRequestTTL     = 10 * time.Minute
	contactClaimTTL       = 60 * time.Second
	contactProviderTTL    = 10 * time.Second
	contactRateLimit      = 5
	contactRateWindow     = 15 * time.Minute
)

// AvatarRequestBodyLimit is the multipart-aware route override used by the
// global request-body middleware. All other routes retain the configured
// JSON limit.
const AvatarRequestBodyLimit = maxAvatarRequestBytes

var (
	avatarIDPattern = regexp.MustCompile(`^avt_[0-9a-f]{32}$`)
	phonePattern    = regexp.MustCompile(`^\+[1-9][0-9]{7,14}$`)
)

type AccountMutationStore interface {
	UpdateOwnProfile(ctx context.Context, userID identity.UserID, displayName, nickname *string) error
	SaveAvatar(ctx context.Context, userID identity.UserID, avatarID string, content []byte, etag string) (string, error)
	GetAvatar(ctx context.Context, avatarID string) ([]byte, string, error)
	CreateContactChange(ctx context.Context, req identity.ContactChangeRequest) error
	CancelContactChange(ctx context.Context, requestIDHash string) error
	ClaimContactChange(ctx context.Context, requestIDHash string, userID identity.UserID, sessionID, claimID string, claimTTL time.Duration) (identity.ContactChangeRequest, error)
	ReleaseContactChange(ctx context.Context, requestIDHash, claimID string, invalidCode bool) error
	CompleteContactChange(ctx context.Context, requestIDHash, claimID string) error
}

type ContactRateChecker interface {
	CheckContact(ctx context.Context, ip, keyHash string, limit int, window time.Duration) (allowed bool, retryAfter time.Duration, err error)
}

// AccountMutationHandlers owns self-service writes separately from the read
// handler so fake development readers can never accidentally acquire write
// authority over PostgreSQL or the identity provider.
type AccountMutationHandlers struct {
	store       AccountMutationStore
	provider    identity.AccountContactProvider
	rateChecker ContactRateChecker
	logger      *slog.Logger
	requestTTL  time.Duration
	claimTTL    time.Duration
	rateLimit   int
	rateWindow  time.Duration
}

func NewAccountMutationHandlers(
	store AccountMutationStore,
	provider identity.AccountContactProvider,
	rateChecker ContactRateChecker,
	logger *slog.Logger,
) *AccountMutationHandlers {
	return &AccountMutationHandlers{
		store: store, provider: provider, rateChecker: rateChecker, logger: logger,
		requestTTL: contactRequestTTL, claimTTL: contactClaimTTL,
		rateLimit: contactRateLimit, rateWindow: contactRateWindow,
	}
}

type profilePatchRequest struct {
	DisplayName *string `json:"displayName"`
	Nickname    *string `json:"nickname"`
}

// UpdateProfile handles PATCH /api/v1/me. Email, phone and avatar fields are
// deliberately absent and rejected by the strict JSON decoder.
func (h *AccountMutationHandlers) UpdateProfile(w http.ResponseWriter, r *http.Request) {
	principal, ok := PrincipalFromContext(r.Context())
	if !ok {
		WriteUnauthorized(w, r)
		return
	}
	var req profilePatchRequest
	if err := decodeJSONBody(w, r, &req, "update own profile"); err != nil {
		return
	}
	if req.DisplayName == nil && req.Nickname == nil {
		WriteBadRequest(w, r, "至少需要提交一个更新字段。")
		return
	}

	var fieldErrors []FieldError
	if req.DisplayName != nil {
		trimmed := strings.TrimSpace(*req.DisplayName)
		if count := utf8.RuneCountInString(trimmed); count < 1 || count > 80 {
			fieldErrors = append(fieldErrors, FieldError{Field: "displayName", Message: "显示名称长度必须为 1 至 80 个字符。"})
		} else {
			*req.DisplayName = trimmed
		}
	}
	if req.Nickname != nil {
		trimmed := strings.TrimSpace(*req.Nickname)
		if utf8.RuneCountInString(trimmed) > 40 {
			fieldErrors = append(fieldErrors, FieldError{Field: "nickname", Message: "昵称不能超过 40 个字符。"})
		} else {
			*req.Nickname = trimmed
		}
	}
	if len(fieldErrors) > 0 {
		WriteValidation(w, r, "请求参数校验失败。", fieldErrors)
		return
	}
	if err := h.store.UpdateOwnProfile(r.Context(), principal.UserID, req.DisplayName, req.Nickname); err != nil {
		writeUserLookupError(w, r, err)
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

type avatarUploadResponse struct {
	AvatarURL string `json:"avatarUrl"`
}

// UploadAvatar accepts exactly one multipart file named "avatar", verifies
// declared and decoded formats, bounds decompression, strips metadata by
// re-encoding a static PNG and persists only the controlled output.
func (h *AccountMutationHandlers) UploadAvatar(w http.ResponseWriter, r *http.Request) {
	principal, ok := PrincipalFromContext(r.Context())
	if !ok {
		WriteUnauthorized(w, r)
		return
	}
	r.Body = http.MaxBytesReader(w, r.Body, maxAvatarRequestBytes)
	if err := r.ParseMultipartForm(maxAvatarRequestBytes); err != nil {
		var maxBytesError *http.MaxBytesError
		if errors.As(err, &maxBytesError) {
			WriteRequestBodyTooLarge(w, r)
		} else {
			WriteBadRequest(w, r, "头像上传请求格式不正确。")
		}
		return
	}
	if r.MultipartForm != nil {
		defer r.MultipartForm.RemoveAll()
	}
	file, header, err := r.FormFile("avatar")
	if err != nil {
		WriteValidation(w, r, "请求参数校验失败。", []FieldError{{Field: "avatar", Message: "请选择头像文件。"}})
		return
	}
	defer file.Close()

	declaredType, _, err := mime.ParseMediaType(header.Header.Get("Content-Type"))
	if err != nil {
		declaredType = ""
	}
	input, err := io.ReadAll(io.LimitReader(file, maxAvatarInputBytes+1))
	if err != nil {
		WriteBadRequest(w, r, "头像文件无法读取。")
		return
	}
	output, err := sanitizeAvatar(input, declaredType)
	if err != nil {
		WriteValidation(w, r, "头像文件不符合安全要求。", []FieldError{{Field: "avatar", Message: err.Error()}})
		return
	}
	avatarID, err := generateAvatarID()
	if err != nil {
		WriteInternalError(w, r)
		return
	}
	digest := sha256.Sum256(output)
	avatarURL, err := h.store.SaveAvatar(
		r.Context(), principal.UserID, avatarID, output, hex.EncodeToString(digest[:]),
	)
	if err != nil {
		writeUserLookupError(w, r, err)
		return
	}
	writeJSONNoStore(w, r, http.StatusCreated, avatarUploadResponse{AvatarURL: avatarURL})
}

// GetAvatar serves only bytes produced by sanitizeAvatar. Avatar IDs are
// opaque, immutable per URL and safe for long-lived public caching.
func (h *AccountMutationHandlers) GetAvatar(w http.ResponseWriter, r *http.Request) {
	avatarFile := chi.URLParam(r, "avatarFile")
	if !strings.HasSuffix(avatarFile, ".png") {
		WriteNotFound(w, r)
		return
	}
	pathValue := strings.TrimSuffix(avatarFile, ".png")
	if !avatarIDPattern.MatchString(pathValue) {
		WriteNotFound(w, r)
		return
	}
	content, etag, err := h.store.GetAvatar(r.Context(), pathValue)
	if err != nil {
		if errors.Is(err, identity.ErrUserNotFound) {
			WriteNotFound(w, r)
		} else {
			WriteInternalError(w, r)
		}
		return
	}
	quotedETag := `"` + etag + `"`
	w.Header().Set("Cache-Control", "public, max-age=31536000, immutable")
	w.Header().Set("ETag", quotedETag)
	if r.Header.Get("If-None-Match") == quotedETag {
		w.WriteHeader(http.StatusNotModified)
		return
	}
	w.Header().Set("Content-Type", "image/png")
	w.Header().Set("Content-Length", strconv.Itoa(len(content)))
	w.Header().Set("Content-Disposition", "inline")
	w.Header().Set("X-Content-Type-Options", "nosniff")
	w.WriteHeader(http.StatusOK)
	_, _ = w.Write(content)
}

type contactChangeRequest struct {
	Value string `json:"value"`
}

type contactChangeResponse struct {
	RequestID string `json:"requestId"`
}

type contactVerificationRequest struct {
	Code string `json:"code"`
}

func (h *AccountMutationHandlers) RequestEmailChange(w http.ResponseWriter, r *http.Request) {
	h.requestContactChange(w, r, identity.ContactKindEmail)
}

func (h *AccountMutationHandlers) RequestPhoneChange(w http.ResponseWriter, r *http.Request) {
	h.requestContactChange(w, r, identity.ContactKindPhone)
}

func (h *AccountMutationHandlers) requestContactChange(w http.ResponseWriter, r *http.Request, kind identity.ContactKind) {
	principal, ok := PrincipalFromContext(r.Context())
	if !ok {
		WriteUnauthorized(w, r)
		return
	}
	var req contactChangeRequest
	if err := decodeJSONBody(w, r, &req, "request contact change"); err != nil {
		return
	}
	req.Value = strings.TrimSpace(req.Value)
	if message := validateContact(kind, req.Value); message != "" {
		WriteValidation(w, r, "请求参数校验失败。", []FieldError{{Field: "value", Message: message}})
		return
	}
	if !h.checkContactRate(w, r, hashIdentifier(string(principal.UserID)+":"+string(kind))) {
		return
	}
	if h.provider == nil {
		WriteProviderUnavailable(w, r)
		return
	}

	requestID, err := session.GenerateMFAToken()
	if err != nil {
		WriteInternalError(w, r)
		return
	}
	requestIDHash := session.HashToken(requestID)
	change := identity.ContactChangeRequest{
		RequestIDHash: requestIDHash,
		UserID:        principal.UserID,
		SessionID:     string(principal.SessionID),
		Kind:          kind,
		Value:         req.Value,
		ExpiresAt:     time.Now().UTC().Add(h.requestTTL),
	}
	if err := h.store.CreateContactChange(r.Context(), change); err != nil {
		h.logAccountError(r, "contact request persistence failed", err)
		WriteInternalError(w, r)
		return
	}

	providerCtx, cancel := context.WithTimeout(r.Context(), contactProviderTTL)
	if kind == identity.ContactKindEmail {
		err = h.provider.BeginEmailChange(providerCtx, principal.UserID, req.Value)
	} else {
		err = h.provider.BeginPhoneChange(providerCtx, principal.UserID, req.Value)
	}
	cancel()
	if err != nil {
		if cancelErr := h.store.CancelContactChange(r.Context(), requestIDHash); cancelErr != nil {
			h.logAccountError(r, "contact request cancellation failed", cancelErr)
		}
		h.writeContactProviderError(w, r, err)
		return
	}
	writeJSONNoStore(w, r, http.StatusCreated, contactChangeResponse{RequestID: requestID})
}

func (h *AccountMutationHandlers) VerifyEmailChange(w http.ResponseWriter, r *http.Request) {
	h.verifyContactChange(w, r, identity.ContactKindEmail)
}

func (h *AccountMutationHandlers) VerifyPhoneChange(w http.ResponseWriter, r *http.Request) {
	h.verifyContactChange(w, r, identity.ContactKindPhone)
}

func (h *AccountMutationHandlers) verifyContactChange(w http.ResponseWriter, r *http.Request, expectedKind identity.ContactKind) {
	principal, ok := PrincipalFromContext(r.Context())
	if !ok {
		WriteUnauthorized(w, r)
		return
	}
	requestID := chi.URLParam(r, "requestId")
	if requestID == "" {
		WriteNotFound(w, r)
		return
	}
	var req contactVerificationRequest
	if err := decodeJSONBody(w, r, &req, "verify contact change"); err != nil {
		return
	}
	req.Code = strings.TrimSpace(req.Code)
	if !validVerificationCode(req.Code) {
		WriteValidation(w, r, "验证码格式不正确。", []FieldError{{Field: "code", Message: "请输入有效的验证码。"}})
		return
	}
	requestIDHash := session.HashToken(requestID)
	if !h.checkContactRate(w, r, requestIDHash) {
		return
	}
	claimID, err := generateClaimID()
	if err != nil {
		WriteInternalError(w, r)
		return
	}
	change, err := h.store.ClaimContactChange(
		r.Context(), requestIDHash, principal.UserID, string(principal.SessionID), claimID, h.claimTTL,
	)
	if err != nil {
		if errors.Is(err, identity.ErrContactRequestClaimed) {
			writeError(w, r, http.StatusConflict, CodeConflict, "验证请求正在处理中。", nil)
		} else if errors.Is(err, identity.ErrContactRequestNotFound) {
			WriteNotFound(w, r)
		} else {
			h.logAccountError(r, "contact request claim failed", err)
			WriteInternalError(w, r)
		}
		return
	}
	if change.Kind != expectedKind {
		_ = h.store.ReleaseContactChange(r.Context(), requestIDHash, claimID, false)
		WriteNotFound(w, r)
		return
	}
	if h.provider == nil {
		_ = h.store.ReleaseContactChange(r.Context(), requestIDHash, claimID, false)
		WriteProviderUnavailable(w, r)
		return
	}

	providerCtx, cancel := context.WithTimeout(r.Context(), contactProviderTTL)
	if change.Kind == identity.ContactKindEmail {
		err = h.provider.VerifyEmailChange(providerCtx, principal.UserID, change.Value, req.Code)
	} else {
		err = h.provider.VerifyPhoneChange(providerCtx, principal.UserID, change.Value, req.Code)
	}
	cancel()
	if err != nil {
		invalid := errors.Is(err, identity.ErrContactCodeInvalid)
		if releaseErr := h.store.ReleaseContactChange(r.Context(), requestIDHash, claimID, invalid); releaseErr != nil {
			h.logAccountError(r, "contact request release failed", releaseErr)
		}
		h.writeContactProviderError(w, r, err)
		return
	}
	if err := h.store.CompleteContactChange(r.Context(), requestIDHash, claimID); err != nil {
		_ = h.store.ReleaseContactChange(r.Context(), requestIDHash, claimID, false)
		h.logAccountError(r, "verified contact settlement failed", err)
		WriteInternalError(w, r)
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

func (h *AccountMutationHandlers) checkContactRate(w http.ResponseWriter, r *http.Request, keyHash string) bool {
	if h.rateChecker == nil {
		WriteRateLimited(w, r, int(h.rateWindow.Seconds()))
		return false
	}
	allowed, retryAfter, err := h.rateChecker.CheckContact(
		r.Context(), clientIP(r), keyHash, h.rateLimit, h.rateWindow,
	)
	if err != nil {
		h.logAccountError(r, "contact rate limit failed", err)
		WriteRateLimited(w, r, int(h.rateWindow.Seconds()))
		return false
	}
	if !allowed {
		WriteRateLimited(w, r, int(retryAfter.Seconds()))
		return false
	}
	return true
}

func (h *AccountMutationHandlers) writeContactProviderError(w http.ResponseWriter, r *http.Request, err error) {
	switch {
	case errors.Is(err, identity.ErrContactCodeInvalid):
		WriteValidation(w, r, "验证码无效或已过期。", []FieldError{{Field: "code", Message: "验证码无效或已过期。"}})
	case errors.Is(err, identity.ErrContactConflict):
		WriteValidation(w, r, "该联系方式无法使用。", []FieldError{{Field: "value", Message: "该联系方式无法使用。"}})
	default:
		h.logAccountError(r, "account provider operation failed", err)
		WriteProviderUnavailable(w, r)
	}
}

func (h *AccountMutationHandlers) logAccountError(r *http.Request, message string, err error) {
	if h.logger == nil {
		return
	}
	h.logger.Error(message,
		"requestId", requestID(r),
		"errorClass", observability.ClassifyError(err),
		"errorDetail", observability.RedactedError(err, 256),
	)
}

func validateContact(kind identity.ContactKind, value string) string {
	switch kind {
	case identity.ContactKindEmail:
		if len(value) > 254 {
			return "邮箱地址格式不正确。"
		}
		parsed, err := mail.ParseAddress(value)
		if err != nil || parsed.Address != value || !strings.Contains(value, "@") {
			return "邮箱地址格式不正确。"
		}
	case identity.ContactKindPhone:
		if !phonePattern.MatchString(value) {
			return "手机号码必须使用 E.164 格式，例如 +8613800138000。"
		}
	default:
		return "联系方式类型无效。"
	}
	return ""
}

func validVerificationCode(code string) bool {
	if len(code) < 4 || len(code) > 20 {
		return false
	}
	for _, char := range code {
		if !((char >= '0' && char <= '9') || (char >= 'a' && char <= 'z') || (char >= 'A' && char <= 'Z')) {
			return false
		}
	}
	return true
}

func generateAvatarID() (string, error) {
	var data [16]byte
	if _, err := rand.Read(data[:]); err != nil {
		return "", err
	}
	return "avt_" + hex.EncodeToString(data[:]), nil
}

func sanitizeAvatar(input []byte, declaredType string) ([]byte, error) {
	if len(input) == 0 || int64(len(input)) > maxAvatarInputBytes {
		return nil, errors.New("头像文件必须大于 0 且不超过 2 MiB。")
	}
	config, format, err := image.DecodeConfig(bytes.NewReader(input))
	if err != nil {
		return nil, errors.New("文件内容不是可安全解码的 PNG、JPEG 或 WebP 图片。")
	}
	formatMIME := map[string]string{"png": "image/png", "jpeg": "image/jpeg", "webp": "image/webp"}[format]
	if formatMIME == "" || declaredType != formatMIME {
		return nil, errors.New("文件声明格式与真实内容不一致，或格式不受支持。")
	}
	if format == "webp" && len(input) > 20 && string(input[12:16]) == "VP8X" && input[20]&0x02 != 0 {
		return nil, errors.New("不支持动画 WebP 头像。")
	}
	if format == "png" && bytes.Contains(input, []byte("acTL")) {
		return nil, errors.New("不支持动画 PNG 头像。")
	}
	if config.Width < minAvatarEdge || config.Height < minAvatarEdge {
		return nil, errors.New("头像宽高均不能小于 64 像素。")
	}
	if config.Width > maxAvatarEdge || config.Height > maxAvatarEdge ||
		int64(config.Width)*int64(config.Height) > maxAvatarPixels {
		return nil, errors.New("头像尺寸过大，宽高不得超过 4096 像素且总像素不得超过 838 万。")
	}
	decoded, decodedFormat, err := image.Decode(bytes.NewReader(input))
	if err != nil || decodedFormat != format {
		return nil, errors.New("头像图片无法完整解码。")
	}
	if decoded.Bounds().Dx() != config.Width || decoded.Bounds().Dy() != config.Height {
		return nil, errors.New("图片解码尺寸与文件头不一致。")
	}

	outputImage := decoded
	if config.Width > maxAvatarOutputEdge || config.Height > maxAvatarOutputEdge {
		scale := min(float64(maxAvatarOutputEdge)/float64(config.Width), float64(maxAvatarOutputEdge)/float64(config.Height))
		width := max(1, int(float64(config.Width)*scale+0.5))
		height := max(1, int(float64(config.Height)*scale+0.5))
		resized := image.NewNRGBA(image.Rect(0, 0, width, height))
		xdraw.CatmullRom.Scale(resized, resized.Bounds(), decoded, decoded.Bounds(), xdraw.Over, nil)
		outputImage = resized
	}

	var output bytes.Buffer
	encoder := png.Encoder{CompressionLevel: png.DefaultCompression}
	if err := encoder.Encode(&output, outputImage); err != nil {
		return nil, errors.New("头像重新编码失败。")
	}
	if output.Len() == 0 || output.Len() > maxAvatarOutputBytes {
		return nil, errors.New("头像重新编码后的文件过大。")
	}
	return output.Bytes(), nil
}
