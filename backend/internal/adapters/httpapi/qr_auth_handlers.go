package httpapi

import (
	"context"
	"errors"
	"log/slog"
	"net/http"
	"regexp"
	"time"

	"github.com/go-chi/chi/v5"

	"github.com/GravelEvolution/united-pass/backend/internal/auth"
	"github.com/GravelEvolution/united-pass/backend/internal/identity"
	"github.com/GravelEvolution/united-pass/backend/internal/qrauth"
	"github.com/GravelEvolution/united-pass/backend/internal/session"
)

const qrReceiverCookieName = "up_qr_receiver"

var qrChallengeIDPattern = regexp.MustCompile(`^[A-Za-z0-9_-]{20,255}$`)

// QRAuthService is the cross-device handoff boundary. Challenge IDs are safe
// to render as QR codes; receiver secrets are browser-only HttpOnly cookies.
type QRAuthService interface {
	Begin(context.Context) (string, string, error)
	Approve(context.Context, string, identity.UserID) error
	Consume(context.Context, string, string) (identity.UserID, error)
}

type QRAuthRateChecker interface {
	CheckQRAuthBegin(context.Context, string, int, time.Duration) (bool, time.Duration, error)
}

// QRAuthAuditEvent contains only durable, non-secret handoff facts. In
// particular ChallengeReference is a SHA-256 correlation value, never the QR
// challenge, receiver secret, session token, client IP, or device metadata.
type QRAuthAuditEvent struct {
	EventType          string
	ActorUserID        identity.UserID
	RequestID          string
	Operation          string
	Result             string
	FailureClass       string
	ChallengeReference string
}

// QRAuthAuditor is the mandatory durable-audit boundary for a QR handoff.
// A successful receiver verification must not issue a browser session if its
// audit event cannot be stored.
type QRAuthAuditor interface {
	RecordQRAuthEvent(context.Context, QRAuthAuditEvent) error
}

const (
	qrAuthEventApprovalRequested = "qr_login.approval_requested"
	qrAuthEventReceiverVerified  = "qr_login.receiver_verified"
	qrAuthEventReceiverRejected  = "qr_login.receiver_rejected"
)

type QRAuthHandlers struct {
	service     QRAuthService
	sessions    WeChatSessionService
	users       UserStatusChecker
	rate        QRAuthRateChecker
	auditor     QRAuthAuditor
	cookieAttrs SessionCookieAttributes
	ttl         time.Duration
	rateLimit   int
	rateWindow  time.Duration
	logger      *slog.Logger
}

func NewQRAuthHandlers(service QRAuthService, sessions WeChatSessionService, users UserStatusChecker, rate QRAuthRateChecker, auditor QRAuthAuditor, attrs SessionCookieAttributes, ttl time.Duration, rateLimit int, rateWindow time.Duration, logger *slog.Logger) *QRAuthHandlers {
	if logger == nil {
		logger = slog.New(slog.DiscardHandler)
	}
	return &QRAuthHandlers{service: service, sessions: sessions, users: users, rate: rate, auditor: auditor, cookieAttrs: attrs, ttl: ttl, rateLimit: rateLimit, rateWindow: rateWindow, logger: logger}
}

// Begin creates a one-time browser challenge. Route composition must require a
// trusted browser mutation, so a hostile site cannot create login handoffs.
func (h *QRAuthHandlers) Begin(w http.ResponseWriter, r *http.Request) {
	if h == nil || h.service == nil || h.rate == nil || h.rateLimit < 1 || h.rateWindow <= 0 {
		WriteNotFound(w, r)
		return
	}
	allowed, retryAfter, err := h.rate.CheckQRAuthBegin(r.Context(), clientIP(r), h.rateLimit, h.rateWindow)
	if err != nil {
		WriteRateLimited(w, r, int(h.rateWindow.Seconds()))
		return
	}
	if !allowed {
		WriteRateLimited(w, r, int((retryAfter+time.Second-1)/time.Second))
		return
	}
	id, receiver, err := h.service.Begin(r.Context())
	if err != nil {
		h.logger.Error("QR challenge creation failed", "requestId", requestID(r))
		WriteProviderUnavailable(w, r)
		return
	}
	h.setReceiver(w, receiver, sessionCookieMaxAge(h.ttl))
	writeJSONNoStore(w, r, http.StatusCreated, map[string]any{"challengeId": id, "expiresInSeconds": int(h.ttl.Seconds())})
}

// Approve is invoked from an already-authenticated Mini Program session after
// the user has deliberately scanned a QR code. Route composition requires the
// explicit native bearer and transport marker; no browser cookie or CSRF token
// participates.
func (h *QRAuthHandlers) Approve(w http.ResponseWriter, r *http.Request) {
	principal, ok := PrincipalFromContext(r.Context())
	if !ok || h == nil || h.service == nil || h.auditor == nil {
		WriteUnauthorized(w, r)
		return
	}
	challengeID := chi.URLParam(r, "challengeId")
	if !qrChallengeIDPattern.MatchString(challengeID) {
		WriteNotFound(w, r)
		return
	}
	// The audit is deliberately committed before the Redis transition. Its
	// event name records an authenticated approval *request*, not an asserted
	// approval outcome, so a later expired/raced challenge cannot create a
	// false success record. If the durable sink is unavailable, no approval is
	// accepted and no browser can subsequently obtain a QR-created session.
	if err := h.record(r.Context(), QRAuthAuditEvent{
		EventType: qrAuthEventApprovalRequested, ActorUserID: principal.UserID,
		RequestID: requestID(r), Operation: "qr_login.approve", Result: "success",
		ChallengeReference: qrauth.AuditChallengeReference(challengeID),
	}); err != nil {
		h.logger.Error("QR approval audit failed", "requestId", requestID(r))
		WriteProviderUnavailable(w, r)
		return
	}
	if err := h.service.Approve(r.Context(), challengeID, principal.UserID); err != nil {
		if errors.Is(err, qrauth.ErrNotFound) || errors.Is(err, qrauth.ErrConsumed) {
			WriteNotFound(w, r)
			return
		}
		h.logger.Error("QR approval failed", "requestId", requestID(r))
		WriteProviderUnavailable(w, r)
		return
	}
	writeJSONNoStore(w, r, http.StatusOK, map[string]string{"status": "approved"})
}

// Consume requires the independent receiver secret held only by the waiting
// browser. On success it creates a normal cookie session and immediately
// removes the one-time receiver cookie.
func (h *QRAuthHandlers) Consume(w http.ResponseWriter, r *http.Request) {
	if h == nil || h.service == nil || h.sessions == nil || h.auditor == nil {
		WriteNotFound(w, r)
		return
	}
	challengeID := chi.URLParam(r, "challengeId")
	receiver := readQRReceiver(r)
	if !qrChallengeIDPattern.MatchString(challengeID) || receiver == "" {
		WriteNotFound(w, r)
		return
	}
	userID, err := h.service.Consume(r.Context(), challengeID, receiver)
	if err != nil {
		switch {
		case errors.Is(err, qrauth.ErrPending):
			writeJSONNoStore(w, r, http.StatusAccepted, map[string]string{"status": "pending"})
		case errors.Is(err, qrauth.ErrDenied), errors.Is(err, qrauth.ErrNotFound), errors.Is(err, qrauth.ErrConsumed):
			h.recordRejected(r, challengeID, err)
			WriteNotFound(w, r)
		default:
			h.logger.Error("QR consume failed", "requestId", requestID(r))
			WriteProviderUnavailable(w, r)
		}
		return
	}
	if h.users != nil && h.users.CanUseSession(r.Context(), userID) != nil {
		h.recordAccountRejected(r, challengeID, userID)
		WriteUnauthorized(w, r)
		return
	}
	// Redis has atomically consumed the receiver proof. Record that exact
	// terminal fact before issuing any browser session; audit failure therefore
	// fails closed and can never yield an unaudited QR-created session.
	if err := h.record(r.Context(), QRAuthAuditEvent{
		EventType: qrAuthEventReceiverVerified, ActorUserID: userID,
		RequestID: requestID(r), Operation: "qr_login.consume", Result: "success",
		ChallengeReference: qrauth.AuditChallengeReference(challengeID),
	}); err != nil {
		h.logger.Error("QR receiver verification audit failed", "requestId", requestID(r))
		h.setReceiver(w, "", -1)
		WriteProviderUnavailable(w, r)
		return
	}
	created, err := h.sessions.CreateSession(r.Context(), session.CreateSessionInput{UserID: userID, Provider: "wechat_miniprogram_qr", AuthenticationMethods: []auth.AuthenticationMethod{auth.MethodFederated}, UserAgent: r.UserAgent(), ClientIP: clientIP(r)})
	if err != nil {
		h.logger.Error("QR session creation failed", "requestId", requestID(r))
		h.setReceiver(w, "", -1)
		WriteInternalError(w, r)
		return
	}
	maxAge := sessionCookieMaxAge(time.Until(created.Record.ExpiresAt))
	SetSessionCookie(w, created.SessionToken, maxAge, h.cookieAttrs)
	SetCSRFCookie(w, created.CSRFToken, maxAge, h.cookieAttrs)
	h.setReceiver(w, "", -1)
	writeJSONNoStore(w, r, http.StatusOK, map[string]any{"status": "authenticated", "csrfToken": created.CSRFToken})
}

func (h *QRAuthHandlers) record(ctx context.Context, event QRAuthAuditEvent) error {
	if h == nil || h.auditor == nil || event.ChallengeReference == "" {
		return errors.New("QR auth audit unavailable")
	}
	return h.auditor.RecordQRAuthEvent(ctx, event)
}

// recordRejected is best-effort because a failure path must not be converted
// into a different externally observable outcome. Its fixed vocabulary keeps
// raw receiver-proof values and backend errors out of the audit payload.
func (h *QRAuthHandlers) recordRejected(r *http.Request, challengeID string, cause error) {
	if h == nil || h.auditor == nil {
		return
	}
	failureClass := "not_found"
	if errors.Is(cause, qrauth.ErrDenied) {
		failureClass = "receiver_proof"
	} else if errors.Is(cause, qrauth.ErrConsumed) {
		failureClass = "replayed"
	}
	_ = h.record(r.Context(), QRAuthAuditEvent{
		EventType: qrAuthEventReceiverRejected, RequestID: requestID(r),
		Operation: "qr_login.consume", Result: "denied", FailureClass: failureClass,
		ChallengeReference: qrauth.AuditChallengeReference(challengeID),
	})
}

func (h *QRAuthHandlers) recordAccountRejected(r *http.Request, challengeID string, userID identity.UserID) {
	if h == nil || h.auditor == nil {
		return
	}
	_ = h.record(r.Context(), QRAuthAuditEvent{
		EventType: qrAuthEventReceiverRejected, ActorUserID: userID, RequestID: requestID(r),
		Operation: "qr_login.consume", Result: "denied", FailureClass: "account_unavailable",
		ChallengeReference: qrauth.AuditChallengeReference(challengeID),
	})
}

func (h *QRAuthHandlers) setReceiver(w http.ResponseWriter, value string, maxAge int) {
	http.SetCookie(w, &http.Cookie{Name: qrReceiverCookieName, Value: value, Path: "/api/v1/auth/qr", HttpOnly: true, Secure: h.cookieAttrs.Secure, SameSite: h.cookieAttrs.SameSite, MaxAge: maxAge})
}
func readQRReceiver(r *http.Request) string {
	c, err := r.Cookie(qrReceiverCookieName)
	if err != nil {
		return ""
	}
	return c.Value
}
