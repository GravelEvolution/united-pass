package httpapi

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"log/slog"
	"mime"
	"net/http"
	"strings"
	"time"
	"unicode/utf8"

	requestctx "github.com/GravelEvolution/united-pass/backend/internal/adapters/httpapi/request"
	"github.com/GravelEvolution/united-pass/backend/internal/dreamupdelegation"
	"github.com/GravelEvolution/united-pass/backend/internal/identity"
	"github.com/GravelEvolution/united-pass/backend/internal/platform/observability"
	"github.com/GravelEvolution/united-pass/backend/internal/session"
)

const (
	// Inner DreamUP payload limits mirror the Worker verifier. The escaped
	// representation in this assertion request can be larger.
	maxDreamUPMobileContactBody      = 8 << 10
	maxDreamUPMobileTeamBody         = 16 << 10
	maxDreamUPMobileAssertionBody    = 64 << 10
	maxDreamUPMobileAssertionRequest = 128 << 10
)

type DreamUPParticipantSigner interface {
	SignParticipant(dreamupdelegation.ParticipantAssertion) (dreamupdelegation.SignedAssertion, error)
}

type DreamUPSubjectResolver interface {
	GetIdentityLinkByUserID(context.Context, string, string, identity.UserID) (identity.IdentityLink, error)
}

type DreamUPMobileRateChecker interface {
	CheckDreamUPMobileAssertion(context.Context, string, string, string, int, int, time.Duration) (bool, time.Duration, error)
}

type DreamUPMobileHandlers struct {
	signer          DreamUPParticipantSigner
	resolver        DreamUPSubjectResolver
	rate            DreamUPMobileRateChecker
	provider        string
	tenantID        string
	scopedRateLimit int
	globalRateLimit int
	rateWindow      time.Duration
	logger          *slog.Logger
}

func NewDreamUPMobileHandlers(signer DreamUPParticipantSigner, resolver DreamUPSubjectResolver, rate DreamUPMobileRateChecker, provider, tenantID string, scopedRateLimit, globalRateLimit int, rateWindow time.Duration, logger *slog.Logger) *DreamUPMobileHandlers {
	if logger == nil {
		logger = slog.New(slog.DiscardHandler)
	}
	return &DreamUPMobileHandlers{signer: signer, resolver: resolver, rate: rate, provider: provider, tenantID: tenantID, scopedRateLimit: scopedRateLimit, globalRateLimit: globalRateLimit, rateWindow: rateWindow, logger: logger}
}

// CreateAssertion proves an existing explicit native United Pass bearer,
// resolves its durable OIDC binding, then issues one short-lived assertion for
// exactly one DreamUP participant request. It never exposes a United Pass
// session token or accepts an unverified subject from the Mini Program.
func (h *DreamUPMobileHandlers) CreateAssertion(w http.ResponseWriter, r *http.Request) {
	principal, ok := PrincipalFromContext(r.Context())
	if !ok {
		WriteUnauthorized(w, r)
		return
	}
	if !h.prepareIssuance(w, r, principal) {
		return
	}
	var body struct {
		Method         string `json:"method"`
		Path           string `json:"path"`
		Body           string `json:"body"`
		IfMatch        string `json:"ifMatch"`
		IdempotencyKey string `json:"idempotencyKey"`
	}
	if !decodeDreamUPMobileBody(w, r, &body) {
		return
	}
	if !utf8.ValidString(body.Body) || len([]byte(body.Body)) > dreamUPMobileBodyLimit(body.Path) {
		WriteValidation(w, r, "DreamUP 请求内容过大。", nil)
		return
	}
	subject, ok := h.resolveParticipantSubject(w, r, principal.UserID)
	if !ok {
		return
	}
	digest := sha256.Sum256([]byte(body.Body))
	assertion, err := h.signer.SignParticipant(dreamupdelegation.ParticipantAssertion{
		Subject: subject, JWTID: requestctx.ID(r.Context()), Method: body.Method, PathAndQuery: body.Path, BodySHA256: hex.EncodeToString(digest[:]),
		HeaderSHA256: dreamupdelegation.ParticipantHeadersSHA256(body.IfMatch, body.IdempotencyKey),
	})
	if err != nil {
		WriteValidation(w, r, "DreamUP 请求不在允许范围内。", nil)
		return
	}
	writeJSONNoStore(w, r, http.StatusCreated, map[string]any{"assertion": assertion.Token, "expiresAt": assertion.ExpiresAt.Format("2006-01-02T15:04:05Z")})
}

func dreamUPMobileBodyLimit(path string) int {
	switch {
	case strings.HasSuffix(path, "/me/feedback"),
		strings.HasSuffix(path, "/me/sponsorship-enquiries"),
		strings.HasSuffix(path, "/me/seat-confirm"),
		strings.HasSuffix(path, "/me/admission/entry-code"):
		return maxDreamUPMobileContactBody
	case strings.Contains(path, "/me/team"):
		return maxDreamUPMobileTeamBody
	default:
		return maxDreamUPMobileAssertionBody
	}
}

// CreateResumeUploadAssertion issues a grant for one binary resume upload.
// Unlike ordinary participant assertions, the file body is never sent to
// United Pass. The client submits only bounded metadata and the file digest;
// DreamUP verifies the bytes, content type, size, and signed metadata before
// writing the restricted object.
func (h *DreamUPMobileHandlers) CreateResumeUploadAssertion(w http.ResponseWriter, r *http.Request) {
	principal, ok := PrincipalFromContext(r.Context())
	if !ok {
		WriteUnauthorized(w, r)
		return
	}
	if !h.prepareIssuance(w, r, principal) {
		return
	}
	var body struct {
		Method      string `json:"method"`
		Path        string `json:"path"`
		FileName    string `json:"fileName"`
		ContentType string `json:"contentType"`
		ByteSize    int64  `json:"byteSize"`
		BodySHA256  string `json:"bodySha256"`
	}
	if !decodeDreamUPMobileBody(w, r, &body) {
		return
	}
	if len(body.BodySHA256) != sha256.Size*2 {
		WriteValidation(w, r, "文件摘要无效。", nil)
		return
	}
	if body.BodySHA256 != strings.ToLower(body.BodySHA256) {
		WriteValidation(w, r, "文件摘要无效。", nil)
		return
	}
	if _, err := hex.DecodeString(body.BodySHA256); err != nil {
		WriteValidation(w, r, "文件摘要无效。", nil)
		return
	}
	subject, ok := h.resolveParticipantSubject(w, r, principal.UserID)
	if !ok {
		return
	}
	assertion, err := h.signer.SignParticipant(dreamupdelegation.ParticipantAssertion{
		Subject: subject, JWTID: requestctx.ID(r.Context()), Method: body.Method, PathAndQuery: body.Path,
		BodySHA256: body.BodySHA256, HeaderSHA256: dreamupdelegation.ParticipantHeadersSHA256("", ""),
		ResumeUpload: &dreamupdelegation.ResumeUploadMetadata{FileName: body.FileName, ContentType: body.ContentType, ByteSize: body.ByteSize},
	})
	if err != nil {
		WriteValidation(w, r, "简历上传请求不在允许范围内。", nil)
		return
	}
	writeJSONNoStore(w, r, http.StatusCreated, map[string]any{"assertion": assertion.Token, "expiresAt": assertion.ExpiresAt.Format("2006-01-02T15:04:05Z")})
}

// resolveParticipantSubject keeps session authentication failures separate
// from identity-link state and dependency failures. The native client may
// evict its bearer on session.unauthenticated, so this handler must never use
// that code for a valid principal whose durable identity projection cannot be
// read or is inconsistent.
func (h *DreamUPMobileHandlers) resolveParticipantSubject(w http.ResponseWriter, r *http.Request, userID identity.UserID) (string, bool) {
	link, err := h.resolver.GetIdentityLinkByUserID(r.Context(), h.provider, h.tenantID, userID)
	switch {
	case errors.Is(err, identity.ErrUserNotFound):
		WriteForbidden(w, r)
		return "", false
	case errors.Is(err, identity.ErrIdentityLinkConflict):
		writeError(w, r, http.StatusConflict, CodeConflict, "统一账户身份绑定存在冲突，请联系管理员。", nil)
		return "", false
	case err != nil:
		h.logger.Error("DreamUP Mobile identity link lookup failed", "requestId", requestID(r), "errorClass", observability.ClassifyError(err))
		WriteInternalError(w, r)
		return "", false
	case link.UserID != userID || link.Provider != h.provider || link.ProviderTenantID != h.tenantID || link.ProviderSubject == "":
		h.logger.Error("DreamUP Mobile identity link projection invalid", "requestId", requestID(r))
		WriteInternalError(w, r)
		return "", false
	default:
		return link.ProviderSubject, true
	}
}

func (h *DreamUPMobileHandlers) prepareIssuance(w http.ResponseWriter, r *http.Request, principal session.Principal) bool {
	// Reject other transports before consuming the shared global budget. This
	// marker is only a routing boundary; the native bearer principal remains
	// the authentication authority.
	if r.Header.Get("X-UnitedPass-Client") != "dreamup-miniprogram" {
		WriteNotFound(w, r)
		return false
	}
	if h == nil || h.signer == nil || h.resolver == nil || h.rate == nil || principal.UserID == "" || principal.SessionID == "" || h.scopedRateLimit <= 0 || h.globalRateLimit < h.scopedRateLimit || h.rateWindow <= 0 {
		WriteRateLimited(w, r, retryAfterSeconds(h.rateWindow))
		return false
	}
	allowed, retryAfter, err := h.rate.CheckDreamUPMobileAssertion(r.Context(), string(principal.UserID), string(principal.SessionID), clientIP(r), h.scopedRateLimit, h.globalRateLimit, h.rateWindow)
	if err != nil || !allowed {
		if retryAfter <= 0 {
			retryAfter = h.rateWindow
		}
		if err != nil {
			h.logger.Error("DreamUP Mobile assertion rate limit failed", "requestId", requestID(r), "errorClass", observability.ClassifyError(err))
		}
		WriteRateLimited(w, r, retryAfterSeconds(retryAfter))
		return false
	}
	return true
}

func retryAfterSeconds(value time.Duration) int {
	if value <= 0 {
		return 1
	}
	return int((value + time.Second - 1) / time.Second)
}

func decodeDreamUPMobileBody(w http.ResponseWriter, r *http.Request, target any) bool {
	if r.Header.Get("X-UnitedPass-Client") != "dreamup-miniprogram" {
		WriteNotFound(w, r)
		return false
	}
	mediaType, _, err := mime.ParseMediaType(r.Header.Get("Content-Type"))
	if err != nil || mediaType != "application/json" {
		writeError(w, r, http.StatusUnsupportedMediaType, codeUnsupportedMediaType, "请求必须使用 JSON 格式。", nil)
		return false
	}
	r.Body = http.MaxBytesReader(w, r.Body, maxDreamUPMobileAssertionRequest)
	if decodeJSONBody(w, r, target, "dreamup mobile assertion") != nil {
		return false
	}
	encoded, err := json.Marshal(target)
	if err != nil || len(encoded) > maxDreamUPMobileAssertionRequest {
		WriteValidation(w, r, "请求内容无效。", nil)
		return false
	}
	return true
}
