package httpapi

import (
	"encoding/json"
	"net/http"

	"github.com/GravelEvolution/united-pass/backend/internal/adapters/httpapi/request"
)

// FieldError is a single field-level validation error. fieldErrors uses an
// array format so a single field can carry multiple messages and the frontend
// can map them onto form controls.
type FieldError struct {
	Field   string `json:"field"`
	Message string `json:"message"`
}

// ErrorBody is the machine-readable error payload. code is stable and
// machine-readable; message is safe for user display; requestId supports
// troubleshooting correlation.
type ErrorBody struct {
	Code        string       `json:"code"`
	Message     string       `json:"message"`
	RequestID   string       `json:"requestId,omitempty"`
	FieldErrors []FieldError `json:"fieldErrors,omitempty"`
}

// ErrorResponse is the standard API error envelope shared by every failing
// operation. It matches the frontend contract in ../frontend/docs/api-contracts.md.
type ErrorResponse struct {
	Error ErrorBody `json:"error"`
}

// Stable error codes used across the service.
const (
	CodeInternal            = "internal.unexpected"
	CodeBadRequest          = "request.malformed"
	CodeUnauthorized        = "session.unauthenticated"
	CodeForbidden           = "authorization.forbidden"
	CodeNotFound            = "resource.not_found"
	CodeConflict            = "state.conflict"
	CodeValidation          = "validation.failed"
	CodeRateLimited         = "rate_limited"
	CodeReauthenticationReq = "session.reauthentication_required"
	CodeRequestBodyTooLarge = "request.body_too_large"
	CodeProviderUnavailable = "provider.unavailable"
)

// writeError writes a standard error envelope with the given status and code.
// The request ID is pulled from the request context so every error response
// stays correlated with logs and audit records.
func writeError(w http.ResponseWriter, r *http.Request, status int, code, message string, fieldErrors []FieldError) {
	requestID := request.ID(r.Context())

	body := ErrorResponse{
		Error: ErrorBody{
			Code:        code,
			Message:     message,
			RequestID:   requestID,
			FieldErrors: fieldErrors,
		},
	}

	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	w.Header().Set("X-Request-ID", requestID)
	w.WriteHeader(status)

	_ = json.NewEncoder(w).Encode(body)
}

// WriteInternalError is the safe fallback for unexpected failures. It never
// leaks internal details.
func WriteInternalError(w http.ResponseWriter, r *http.Request) {
	writeError(w, r, http.StatusInternalServerError, CodeInternal, "服务暂时无法处理该请求。", nil)
}

// WriteBadRequest writes a 400 for malformed requests.
func WriteBadRequest(w http.ResponseWriter, r *http.Request, message string) {
	writeError(w, r, http.StatusBadRequest, CodeBadRequest, message, nil)
}

// WriteNotFound writes a 404 that does not reveal whether the resource exists.
func WriteNotFound(w http.ResponseWriter, r *http.Request) {
	writeError(w, r, http.StatusNotFound, CodeNotFound, "请求的资源不存在或无权访问。", nil)
}

// WriteValidation writes a 422 with field-level errors.
func WriteValidation(w http.ResponseWriter, r *http.Request, message string, fieldErrors []FieldError) {
	writeError(w, r, http.StatusUnprocessableEntity, CodeValidation, message, fieldErrors)
}

// WriteRequestBodyTooLarge writes a 413 for requests whose body exceeds the
// configured maximum size.
func WriteRequestBodyTooLarge(w http.ResponseWriter, r *http.Request) {
	writeError(w, r, http.StatusRequestEntityTooLarge, CodeRequestBodyTooLarge, "请求体超过允许的大小。", nil)
}

// WriteProviderUnavailable writes a 502 when the identity provider rejects
// or fails a provisioning call. Only the stable error class is conveyed —
// never raw provider detail.
func WriteProviderUnavailable(w http.ResponseWriter, r *http.Request) {
	writeError(w, r, http.StatusBadGateway, CodeProviderUnavailable, "身份提供方暂不可用，请稍后重试。", nil)
}
