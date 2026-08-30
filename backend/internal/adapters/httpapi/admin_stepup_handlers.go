package httpapi

import (
	"context"
	"errors"
	"net"
	"net/http"
	"regexp"
	"strconv"
	"strings"
	"time"

	"github.com/GravelEvolution/united-pass/backend/internal/adapters/httpapi/request"
	"github.com/GravelEvolution/united-pass/backend/internal/adminstepup"
	"github.com/GravelEvolution/united-pass/backend/internal/auth"
	"github.com/GravelEvolution/united-pass/backend/internal/dreamupdelegation"
	"github.com/GravelEvolution/united-pass/backend/internal/identity"
	"github.com/GravelEvolution/united-pass/backend/internal/session"
)

const (
	CodeAdminStepUpEnrollmentRequired = "admin_stepup.enrollment_required"
	CodeAdminStepUpRotationRequired   = "admin_stepup.rotation_required"
	CodeAdminStepUpLocked             = "admin_stepup.locked"
	CodeAdminStepUpInvalidAnswer      = "admin_stepup.invalid_answer"
)

type AdminStepUpService interface {
	Challenge(context.Context, identity.UserID, string) (adminstepup.ChallengeView, error)
	InitialEnrollmentAllowed(context.Context, identity.UserID, string) (bool, error)
	Enroll(context.Context, adminstepup.EnrollInput) (adminstepup.Challenge, error)
	Verify(context.Context, adminstepup.VerifyRequest) (adminstepup.VerifyResult, error)
	Rotate(context.Context, adminstepup.RotateInput) (adminstepup.Challenge, error)
}

type AdminStepUpHandlers struct {
	service       AdminStepUpService
	freshLoginMax time.Duration
	now           func() time.Time
}

func NewAdminStepUpHandlers(service AdminStepUpService, freshLoginMax time.Duration, now func() time.Time) *AdminStepUpHandlers {
	if freshLoginMax <= 0 {
		freshLoginMax = 5 * time.Minute
	}
	if now == nil {
		now = func() time.Time { return time.Now().UTC() }
	}
	return &AdminStepUpHandlers{service: service, freshLoginMax: freshLoginMax, now: now}
}

type adminStepUpEnrollRequest struct {
	EventID  string `json:"eventId"`
	Question string `json:"question"`
	Answer   string `json:"answer"`
}

type adminStepUpVerifyRequest struct {
	EventID string `json:"eventId"`
	Answer  string `json:"answer"`
	Action  string `json:"action"`
	Target  string `json:"target,omitempty"`
}

type adminStepUpRotateRequest struct {
	EventID   string `json:"eventId"`
	OldAnswer string `json:"oldAnswer"`
	Question  string `json:"question"`
	Answer    string `json:"answer"`
}

type adminStepUpChallengeResponse struct {
	State             adminstepup.State `json:"state"`
	Question          string            `json:"question,omitempty"`
	Version           int64             `json:"version,omitempty"`
	CredentialVersion int64             `json:"credentialVersion,omitempty"`
	LockedUntil       *time.Time        `json:"lockedUntil,omitempty"`
}

type adminStepUpMutationResponse struct {
	State            adminstepup.State `json:"state"`
	Version          int64             `json:"version,omitempty"`
	ChallengeVersion int64             `json:"challengeVersion,omitempty"`
	VerifiedAt       *time.Time        `json:"verifiedAt,omitempty"`
	ExpiresAt        *time.Time        `json:"expiresAt,omitempty"`
	Reauthentication string            `json:"reauthenticationToken,omitempty"`
	GrantID          string            `json:"grantId,omitempty"`
	Replayed         bool              `json:"replayed,omitempty"`
}

func (h *AdminStepUpHandlers) Challenge(w http.ResponseWriter, r *http.Request) {
	principal, _, ok := h.requireOwnerSession(w, r)
	if !ok {
		return
	}
	eventID := strings.TrimSpace(r.URL.Query().Get("eventId"))
	if eventID == "" {
		WriteValidation(w, r, "活动标识不能为空。", []FieldError{{Field: "eventId", Message: "请选择活动。"}})
		return
	}
	view, err := h.service.Challenge(r.Context(), principal.UserID, eventID)
	if err != nil {
		h.writeServiceError(w, r, err)
		return
	}
	if view.Version > 0 {
		w.Header().Set("ETag", `"`+strconv.FormatInt(view.Version, 10)+`"`)
	}
	writeJSONNoStore(w, r, http.StatusOK, adminStepUpChallengeResponse{State: view.State, Question: view.Question, Version: view.Version, CredentialVersion: view.CredentialVersion, LockedUntil: view.LockedUntil})
}

func (h *AdminStepUpHandlers) Enroll(w http.ResponseWriter, r *http.Request) {
	principal, record, ok := h.requireOwnerSession(w, r)
	if !ok {
		return
	}
	var body adminStepUpEnrollRequest
	if err := decodeJSONBody(w, r, &body, "administrator challenge enrollment"); err != nil {
		return
	}
	if !h.allowEnrollment(r.Context(), principal, record, strings.TrimSpace(body.EventID)) {
		writeError(w, r, http.StatusForbidden, CodeReauthenticationReq, "设置安全问题前，请重新登录并完成多因素认证。", nil)
		return
	}
	result, err := h.service.Enroll(r.Context(), adminstepup.EnrollInput{
		UserID: principal.UserID, EventID: body.EventID, Question: body.Question, Answer: body.Answer,
		IdempotencyKey: r.Header.Get("Idempotency-Key"), RequestID: request.ID(r.Context()),
	})
	if err != nil {
		h.writeServiceError(w, r, err)
		return
	}
	w.Header().Set("ETag", `"`+strconv.FormatInt(result.Version, 10)+`"`)
	writeJSONNoStore(w, r, http.StatusCreated, adminStepUpMutationResponse{State: adminstepup.StateActive, Version: result.Version, ChallengeVersion: result.CredentialVersion})
}

func (h *AdminStepUpHandlers) allowEnrollment(ctx context.Context, principal session.Principal, record session.SessionRecord, eventID string) bool {
	now := h.now()
	if eventID == "" || record.AuthenticationTime.IsZero() || record.AuthenticationTime.After(now.Add(time.Minute)) || now.Sub(record.AuthenticationTime) > h.freshLoginMax {
		return false
	}
	if hasSessionMFA(record.AuthenticationMethods) {
		return true
	}
	allowed, err := h.service.InitialEnrollmentAllowed(ctx, principal.UserID, eventID)
	return err == nil && allowed
}

func (h *AdminStepUpHandlers) Verify(w http.ResponseWriter, r *http.Request) {
	principal, record, ok := h.requireOwnerSession(w, r)
	if !ok {
		return
	}
	now := h.now().UTC()
	authTime := record.AuthenticationTime.UTC()
	if authTime.IsZero() || authTime.After(now.Add(dreamupdelegation.MaxClockSkew)) || now.Sub(authTime) > dreamupdelegation.MaxAdministratorLoginAge {
		writeError(w, r, http.StatusForbidden, CodeReauthenticationReq, "管理员安全验证前，请重新登录。", nil)
		return
	}
	var body adminStepUpVerifyRequest
	if err := decodeJSONBody(w, r, &body, "administrator challenge verification"); err != nil {
		return
	}
	result, err := h.service.Verify(r.Context(), adminstepup.VerifyRequest{
		UserID: principal.UserID, SessionID: string(principal.SessionID), EventID: body.EventID,
		Answer: body.Answer, Action: body.Action, Target: body.Target,
		ClientFingerprint: adminChallengeClientFingerprint(r),
		IdempotencyKey:    r.Header.Get("Idempotency-Key"), RequestID: request.ID(r.Context()),
	})
	if err != nil {
		h.writeServiceError(w, r, err)
		return
	}
	response := adminStepUpMutationResponse{State: result.State, ChallengeVersion: result.ChallengeVersion, Reauthentication: result.ReauthGrant, GrantID: result.GrantID, Replayed: result.Replayed}
	if !result.VerifiedAt.IsZero() {
		response.VerifiedAt = &result.VerifiedAt
	}
	if !result.ExpiresAt.IsZero() {
		response.ExpiresAt = &result.ExpiresAt
	}
	writeJSONNoStore(w, r, http.StatusOK, response)
}

func (h *AdminStepUpHandlers) Rotate(w http.ResponseWriter, r *http.Request) {
	principal, _, ok := h.requireOwnerSession(w, r)
	if !ok {
		return
	}
	expected, err := parseChallengeIfMatch(r.Header.Get("If-Match"))
	if err != nil {
		writeError(w, r, http.StatusPreconditionRequired, CodeConflict, "请刷新安全问题后重试。", nil)
		return
	}
	var body adminStepUpRotateRequest
	if err := decodeJSONBody(w, r, &body, "administrator challenge rotation"); err != nil {
		return
	}
	result, err := h.service.Rotate(r.Context(), adminstepup.RotateInput{
		UserID: principal.UserID, EventID: body.EventID, OldAnswer: body.OldAnswer,
		NewQuestion: body.Question, NewAnswer: body.Answer, ExpectedVersion: expected,
		ClientFingerprint: adminChallengeClientFingerprint(r),
		IdempotencyKey:    r.Header.Get("Idempotency-Key"), RequestID: request.ID(r.Context()),
	})
	if err != nil {
		h.writeServiceError(w, r, err)
		return
	}
	w.Header().Set("ETag", `"`+strconv.FormatInt(result.Version, 10)+`"`)
	writeJSONNoStore(w, r, http.StatusOK, adminStepUpMutationResponse{State: adminstepup.StateActive, Version: result.Version, ChallengeVersion: result.CredentialVersion})
}

func (h *AdminStepUpHandlers) requireOwnerSession(w http.ResponseWriter, r *http.Request) (session.Principal, session.SessionRecord, bool) {
	principal, principalOK := PrincipalFromContext(r.Context())
	record, recordOK := SessionRecordFromContext(r.Context())
	if !principalOK || !recordOK || principal.UserID == "" || principal.UserID != record.UserID || principal.SessionID == "" || principal.SessionID != record.SessionID {
		writeError(w, r, http.StatusUnauthorized, CodeUnauthorized, "请先登录。", nil)
		return session.Principal{}, session.SessionRecord{}, false
	}
	if h.service == nil || record.Provider == "" || record.Provider == "fake" {
		writeError(w, r, http.StatusForbidden, CodeForbidden, "需要由身份提供方建立的登录会话。", nil)
		return session.Principal{}, session.SessionRecord{}, false
	}
	if record.ProviderSessionReference == "" || record.ProviderSessionCredential == "" {
		writeError(w, r, http.StatusForbidden, CodeReauthenticationReq, "管理员安全验证前，请使用密码重新登录。", nil)
		return session.Principal{}, session.SessionRecord{}, false
	}
	return principal, record, true
}

func hasSessionMFA(methods []auth.AuthenticationMethod) bool {
	for _, method := range methods {
		if method == auth.MethodTOTP || method == auth.MethodPasskey || method == auth.MethodRecovery {
			return true
		}
	}
	return false
}

var quotedVersionPattern = regexp.MustCompile(`^"([1-9][0-9]*)"$`)

func parseChallengeIfMatch(value string) (int64, error) {
	match := quotedVersionPattern.FindStringSubmatch(strings.TrimSpace(value))
	if len(match) != 2 {
		return 0, adminstepup.ErrIfMatchRequired
	}
	version, err := strconv.ParseInt(match[1], 10, 64)
	if err != nil || version <= 0 {
		return 0, adminstepup.ErrIfMatchRequired
	}
	return version, nil
}

func adminChallengeClientFingerprint(r *http.Request) string {
	host := strings.TrimSpace(r.RemoteAddr)
	if parsed, _, err := net.SplitHostPort(host); err == nil {
		host = parsed
	}
	if ip := net.ParseIP(host); ip != nil {
		host = ip.String()
	}
	userAgent := strings.ToLower(strings.Join(strings.Fields(r.UserAgent()), " "))
	if len(userAgent) > 512 {
		userAgent = userAgent[:512]
	}
	if len(host) > 128 {
		host = host[:128]
	}
	return host + "\x00" + userAgent
}

func (h *AdminStepUpHandlers) writeServiceError(w http.ResponseWriter, r *http.Request, err error) {
	switch {
	case errors.Is(err, adminstepup.ErrDisabled):
		WriteNotFound(w, r)
	case errors.Is(err, adminstepup.ErrEnrollmentRequired):
		writeError(w, r, http.StatusConflict, CodeAdminStepUpEnrollmentRequired, "请先设置管理员安全问题。", nil)
	case errors.Is(err, adminstepup.ErrRotationRequired):
		writeError(w, r, http.StatusConflict, CodeAdminStepUpRotationRequired, "必须先更新管理员安全问题。", nil)
	case errors.Is(err, adminstepup.ErrLocked):
		writeError(w, r, http.StatusLocked, CodeAdminStepUpLocked, "验证尝试过多，请稍后再试。", nil)
	case errors.Is(err, adminstepup.ErrInvalidChallengeAnswer):
		writeError(w, r, http.StatusUnauthorized, CodeAdminStepUpInvalidAnswer, "答案不正确。", nil)
	case errors.Is(err, adminstepup.ErrRateLimited):
		writeError(w, r, http.StatusTooManyRequests, CodeRateLimited, "尝试过于频繁，请稍后再试。", nil)
	case errors.Is(err, adminstepup.ErrInvalidQuestion), errors.Is(err, adminstepup.ErrInvalidAnswer),
		errors.Is(err, adminstepup.ErrForbiddenChallengeText), errors.Is(err, adminstepup.ErrQuestionEqualsAnswer),
		errors.Is(err, adminstepup.ErrInvalidIdempotencyKey), errors.Is(err, adminstepup.ErrIfMatchRequired),
		errors.Is(err, adminstepup.ErrInvalidActionTarget), errors.Is(err, adminstepup.ErrUnsupportedAction),
		errors.Is(err, adminstepup.ErrInvalidVerifyRequest):
		WriteValidation(w, r, "请检查提交内容。", nil)
	case errors.Is(err, adminstepup.ErrConflict), errors.Is(err, adminstepup.ErrIdempotencyConflict), errors.Is(err, adminstepup.ErrEnrollmentNotAllowed):
		writeError(w, r, http.StatusConflict, CodeConflict, "状态已发生变化，请刷新后重试。", nil)
	default:
		WriteInternalError(w, r)
	}
}
