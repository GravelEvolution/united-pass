//
// Copyright (c) 2026 Chen Jiajie(Ariakage)
//
// Author: Chen Jiajie(Ariakage) <ariakage233@gmail.com>
// Date: 2026-08-11
// Description: Feishu OAuth login begin/callback handlers
//

package httpapi

import (
	"errors"
	"log/slog"
	"net/http"
	"net/url"
	"time"

	"github.com/GravelEvolution/united-pass/backend/internal/auth"
	"github.com/GravelEvolution/united-pass/backend/internal/config"
	"github.com/GravelEvolution/united-pass/backend/internal/providers"
	"github.com/GravelEvolution/united-pass/backend/internal/session"
)

type ProviderLoginHandlers struct {
	service     *providers.Service
	stateStore  providers.OAuthStateStore
	sessions    *session.Service
	users       UserStatusChecker
	rateChecker RateChecker
	cookieAttrs SessionCookieAttributes
	stateTTL    time.Duration
	sessionTTL  time.Duration
	rememberTTL time.Duration
	loginLimit  int
	loginWindow time.Duration
	logger      *slog.Logger
}

func NewProviderLoginHandlers(service *providers.Service, stateStore providers.OAuthStateStore, sessions *session.Service, users UserStatusChecker, rateChecker RateChecker, cfg config.Config, logger *slog.Logger) *ProviderLoginHandlers {
	return &ProviderLoginHandlers{service: service, stateStore: stateStore, sessions: sessions, users: users, rateChecker: rateChecker, cookieAttrs: CookieAttributesFromConfig(cfg.Session), stateTTL: cfg.Feishu.OAuthStateTTL, sessionTTL: cfg.Session.TTL, rememberTTL: cfg.Session.RememberTTL, loginLimit: cfg.RateLimit.LoginLimit, loginWindow: cfg.RateLimit.LoginWindow, logger: logger}
}

func (h *ProviderLoginHandlers) ListPublicProviders(w http.ResponseWriter, r *http.Request) {
	detail, err := h.service.GetProvider(r.Context(), providers.FeishuProviderID)
	if err != nil {
		WriteInternalError(w, r)
		return
	}
	writeJSONNoStore(w, r, http.StatusOK, map[string]any{"items": []map[string]any{{"providerId": string(detail.ProviderID), "displayName": detail.DisplayName, "loginEnabled": detail.LoginEnabled && detail.SecretConfigured && detail.Status == providers.ProviderStatusActive}}})
}

func (h *ProviderLoginHandlers) BeginFeishu(w http.ResponseWriter, r *http.Request) {
	if !h.checkRate(w, r, "feishu_begin") {
		return
	}
	detail, err := h.service.GetProvider(r.Context(), providers.FeishuProviderID)
	if err != nil || !detail.SecretConfigured || !detail.LoginEnabled || detail.Status != providers.ProviderStatusActive {
		WriteNotFound(w, r)
		return
	}
	resume := r.URL.Query().Get("resumeRequestId")
	if resume != "" && !validOpaqueValue(resume) {
		WriteBadRequest(w, r, "resumeRequestId 格式不正确。")
		return
	}
	state, err := session.GenerateToken()
	if err != nil {
		WriteInternalError(w, r)
		return
	}
	remember := r.URL.Query().Get("remember") != "false"
	if err := h.stateStore.Create(r.Context(), session.HashToken(state), providers.OAuthState{ResumeRequestID: resume, Remember: remember, CreatedAt: time.Now().UTC()}, h.stateTTL); err != nil {
		WriteInternalError(w, r)
		return
	}
	authorizationURL, err := h.service.OAuthSource().AuthorizationURL(state)
	if err != nil {
		WriteInternalError(w, r)
		return
	}
	http.Redirect(w, r, authorizationURL, http.StatusFound)
}

func (h *ProviderLoginHandlers) FeishuCallback(w http.ResponseWriter, r *http.Request) {
	state, code := r.URL.Query().Get("state"), r.URL.Query().Get("code")
	if state == "" || code == "" || len(state) > 512 || len(code) > 2048 {
		h.redirectLoginError(w, r, "provider_login_failed")
		return
	}
	if !h.checkRate(w, r, session.HashToken(state)) {
		return
	}
	stored, err := h.stateStore.Consume(r.Context(), session.HashToken(state))
	if err != nil || time.Since(stored.CreatedAt) > h.stateTTL {
		h.redirectLoginError(w, r, "provider_login_failed")
		return
	}
	info, err := h.service.OAuthSource().ExchangeCode(r.Context(), code)
	if err != nil {
		h.redirectLoginError(w, r, "provider_login_failed")
		return
	}
	user, err := h.service.ResolveOAuthUser(r.Context(), providers.FeishuProviderID, info)
	if errors.Is(err, providers.ErrIdentityUnlinked) {
		h.redirectLoginError(w, r, "identity_unlinked")
		return
	}
	if err != nil || !user.Status.CanAuthenticate() {
		h.redirectLoginError(w, r, "provider_login_failed")
		return
	}
	if h.users != nil && h.users.CanUseSession(r.Context(), user.ID) != nil {
		h.redirectLoginError(w, r, "provider_login_failed")
		return
	}
	created, err := h.sessions.CreateSession(r.Context(), session.CreateSessionInput{UserID: user.ID, Provider: string(providers.FeishuProviderID), AuthenticationMethods: []auth.AuthenticationMethod{auth.MethodFederated}, Remember: stored.Remember, UserAgent: r.UserAgent(), ClientIP: peerIP(r)})
	if err != nil {
		WriteInternalError(w, r)
		return
	}
	ttl := h.sessionTTL
	if stored.Remember {
		ttl = h.rememberTTL
	}
	maxAge := sessionCookieMaxAge(ttl)
	SetSessionCookie(w, created.SessionToken, maxAge, h.cookieAttrs)
	SetCSRFCookie(w, created.CSRFToken, maxAge, h.cookieAttrs)
	destination := "/account"
	if stored.ResumeRequestID != "" {
		destination = "/authorize?requestId=" + url.QueryEscape(stored.ResumeRequestID)
	}
	http.Redirect(w, r, destination, http.StatusSeeOther)
}

func (h *ProviderLoginHandlers) checkRate(w http.ResponseWriter, r *http.Request, key string) bool {
	if h.rateChecker == nil {
		WriteRateLimited(w, r, int(h.loginWindow.Seconds()))
		return false
	}
	allowed, retryAfter, err := h.rateChecker.CheckLogin(r.Context(), clientIP(r), hashIdentifier(key), h.loginLimit, h.loginWindow)
	if err != nil || !allowed {
		seconds := int(retryAfter.Seconds())
		if seconds <= 0 {
			seconds = int(h.loginWindow.Seconds())
		}
		WriteRateLimited(w, r, seconds)
		return false
	}
	return true
}

func (h *ProviderLoginHandlers) redirectLoginError(w http.ResponseWriter, r *http.Request, code string) {
	http.Redirect(w, r, "/login?providerError="+url.QueryEscape(code), http.StatusSeeOther)
}

func validOpaqueValue(value string) bool {
	if value == "" || len(value) > 256 {
		return false
	}
	for _, character := range value {
		if (character >= 'a' && character <= 'z') || (character >= 'A' && character <= 'Z') || (character >= '0' && character <= '9') || character == '_' || character == '-' || character == ':' {
			continue
		}
		return false
	}
	return true
}
