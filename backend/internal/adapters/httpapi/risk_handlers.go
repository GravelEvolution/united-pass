package httpapi

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"net/http"
	"time"

	"github.com/GravelEvolution/united-pass/backend/internal/riskdefense"
	"github.com/GravelEvolution/united-pass/backend/internal/session"
)

const (
	RiskDeviceCookieName  = "up_risk_device"
	DeviceTrustCookieName = "up_device_trust"
)

type StepUpDetails struct {
	ChallengeToken  string          `json:"challengeToken"`
	Level           string          `json:"level"`
	Method          string          `json:"method"`
	ExpiresAt       time.Time       `json:"expiresAt"`
	Algorithm       string          `json:"algorithm,omitempty"`
	Difficulty      uint8           `json:"difficulty,omitempty"`
	Provider        string          `json:"provider,omitempty"`
	ProviderReady   bool            `json:"providerReady"`
	ProviderPayload json.RawMessage `json:"providerPayload,omitempty"`
	CompletionPath  string          `json:"completionPath"`
}

type RiskDefenseService interface {
	Assess(context.Context, riskdefense.Signal) (riskdefense.Decision, error)
	Complete(context.Context, riskdefense.Completion) (riskdefense.CompleteResult, error)
}

type SessionTrustValidator interface {
	ValidateSession(context.Context, string) (session.Principal, session.SessionRecord, error)
}

// RiskGuard owns the HTTP boundary for objective registration/login abuse
// defense. It never receives display names, prose, or other subjective data.
type RiskGuard struct {
	service     RiskDefenseService
	sessions    SessionTrustValidator
	cookieAttrs SessionCookieAttributes
	deviceIDTTL time.Duration
	trustTTL    time.Duration
}

func NewRiskGuard(service RiskDefenseService, sessions SessionTrustValidator, attrs SessionCookieAttributes, deviceIDTTL, trustTTL time.Duration) *RiskGuard {
	if service == nil {
		return nil
	}
	return &RiskGuard{service: service, sessions: sessions, cookieAttrs: attrs, deviceIDTTL: deviceIDTTL, trustTTL: trustTTL}
}

func (g *RiskGuard) Require(w http.ResponseWriter, r *http.Request, operation riskdefense.Operation, identifierHash string) bool {
	if g == nil || g.service == nil {
		return true
	}
	deviceID := readCookie(r, RiskDeviceCookieName)
	deviceTrust := readCookie(r, DeviceTrustCookieName)
	sessionTrusted, sessionAnomaly := g.sessionTrust(r)
	decision, err := g.service.Assess(r.Context(), riskdefense.Signal{
		Operation: operation, IdentifierHash: identifierHash,
		DeviceIDToken: deviceID, DeviceTrustToken: deviceTrust,
		UserAgentHash: hashRiskValue(r.UserAgent()), SessionTrusted: sessionTrusted,
		SessionAnomaly: sessionAnomaly,
	})
	if err != nil {
		WriteInternalError(w, r)
		return false
	}
	if decision.DeviceIDToken != "" && decision.DeviceIDToken != deviceID {
		setRiskCookie(w, RiskDeviceCookieName, decision.DeviceIDToken, g.deviceIDTTL, g.cookieAttrs)
	}
	if decision.Allow {
		return true
	}
	if decision.Challenge == nil {
		WriteInternalError(w, r)
		return false
	}
	writeStepUpRequired(w, r, *decision.Challenge)
	return false
}

type stepUpCompletionRequest struct {
	ChallengeToken string `json:"challengeToken"`
	Nonce          string `json:"nonce,omitempty"`
	ProviderProof  string `json:"providerProof,omitempty"`
}

func (g *RiskGuard) Complete(w http.ResponseWriter, r *http.Request) {
	if g == nil || g.service == nil {
		writeError(w, r, http.StatusServiceUnavailable, CodeStepUpUnavailable, "额外验证服务暂不可用。", nil)
		return
	}
	var body stepUpCompletionRequest
	if err := decodeJSONBody(w, r, &body, "risk step-up"); err != nil {
		return
	}
	if body.ChallengeToken == "" || len(body.ChallengeToken) > 512 || len(body.Nonce) > 256 || len(body.ProviderProof) > 8192 {
		writeError(w, r, http.StatusBadRequest, CodeBadRequest, "额外验证请求格式不正确。", nil)
		return
	}
	result, err := g.service.Complete(r.Context(), riskdefense.Completion{
		ChallengeToken: body.ChallengeToken, Nonce: body.Nonce, ProviderProof: body.ProviderProof,
		DeviceIDToken: readCookie(r, RiskDeviceCookieName), UserAgentHash: hashRiskValue(r.UserAgent()),
	})
	if err != nil {
		var rateErr *riskdefense.RateLimitError
		switch {
		case errors.Is(err, riskdefense.ErrUnavailable):
			writeError(w, r, http.StatusServiceUnavailable, CodeStepUpUnavailable, "额外验证服务暂不可用。", nil)
		case errors.As(err, &rateErr):
			seconds := int((rateErr.RetryAfter + time.Second - 1) / time.Second)
			WriteRateLimited(w, r, seconds)
		case errors.Is(err, riskdefense.ErrChallengeClaimed):
			WriteRateLimited(w, r, 1)
		default:
			writeError(w, r, http.StatusUnauthorized, CodeUnauthorized, "额外验证无效、已过期或已使用。", nil)
		}
		return
	}
	setRiskCookie(w, DeviceTrustCookieName, result.TrustToken, g.trustTTL, g.cookieAttrs)
	w.WriteHeader(http.StatusNoContent)
}

func (g *RiskGuard) sessionTrust(r *http.Request) (trusted, anomaly bool) {
	token := ReadSessionCookie(r)
	if token == "" {
		return false, false
	}
	if g.sessions == nil {
		return false, true
	}
	_, record, err := g.sessions.ValidateSession(r.Context(), token)
	if err != nil {
		return false, true
	}
	if record.AuthenticationTime.IsZero() || g.trustTTL <= 0 {
		return false, false
	}
	age := time.Since(record.AuthenticationTime)
	return age >= 0 && age <= g.trustTTL, false
}

func writeStepUpRequired(w http.ResponseWriter, r *http.Request, challenge riskdefense.Challenge) {
	details := &StepUpDetails{
		ChallengeToken: challenge.Token, Level: string(challenge.Level), Method: string(challenge.Method),
		ExpiresAt: challenge.ExpiresAt, Difficulty: challenge.Difficulty,
		Provider: challenge.Provider, ProviderReady: challenge.ProviderReady, ProviderPayload: challenge.PublicPayload,
		CompletionPath: stepUpCompletionPath(challenge.Method),
	}
	if challenge.Method == riskdefense.MethodAutomationCost {
		details.Algorithm = "sha256_leading_zero_bits"
	}
	body := ErrorResponse{Error: ErrorBody{
		Code: CodeStepUpRequired, Message: "需要完成额外验证后继续。", RequestID: requestID(r), StepUp: details,
	}}
	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	w.Header().Set("Cache-Control", "no-store")
	w.Header().Set("X-Request-ID", requestID(r))
	w.WriteHeader(http.StatusForbidden)
	_ = json.NewEncoder(w).Encode(body)
}

func stepUpCompletionPath(method riskdefense.Method) string {
	switch method {
	case riskdefense.MethodMFA:
		return "/api/v1/auth/sessions/mfa"
	case riskdefense.MethodReauthentication:
		return "/api/v1/auth/reauthentication"
	default:
		return "/api/v1/auth/step-up"
	}
}

func readCookie(r *http.Request, name string) string {
	cookie, err := r.Cookie(name)
	if err != nil || len(cookie.Value) > 512 {
		return ""
	}
	return cookie.Value
}

func setRiskCookie(w http.ResponseWriter, name, value string, ttl time.Duration, attrs SessionCookieAttributes) {
	http.SetCookie(w, &http.Cookie{
		Name: name, Value: value, Path: "/", HttpOnly: true, Secure: attrs.Secure,
		SameSite: attrs.SameSite, MaxAge: sessionCookieMaxAge(ttl),
	})
}

func hashRiskValue(value string) string {
	sum := sha256.Sum256([]byte(value))
	return hex.EncodeToString(sum[:])
}
