package httpapi

import (
	"crypto/rand"
	"encoding/hex"
	"log/slog"
	"net/http"
	"runtime/debug"
	"time"

	"github.com/GravelEvolution/united-pass/backend/internal/adapters/httpapi/request"
)

// RequestIDHeader is the header name used to accept upstream request IDs and to
// return the effective request ID on every response.
const RequestIDHeader = "X-Request-ID"

const requestIDPrefix = "req_"

// RequestID accepts a valid upstream request ID or generates a new one. The
// effective ID is stored in the request context and echoed on the response so
// logs, error envelopes and audit records stay correlated.
func RequestID(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		id := r.Header.Get(RequestIDHeader)
		if !isValidRequestID(id) {
			id = generateRequestID()
		}
		w.Header().Set(RequestIDHeader, id)
		r = r.WithContext(request.WithID(r.Context(), id))
		next.ServeHTTP(w, r)
	})
}

// isValidRequestID accepts only alphanumeric, dash and underscore identifiers
// within a bounded length to prevent header injection or log poisoning.
func isValidRequestID(id string) bool {
	if len(id) < 8 || len(id) > 128 {
		return false
	}
	for _, c := range id {
		switch {
		case c >= 'a' && c <= 'z':
		case c >= 'A' && c <= 'Z':
		case c >= '0' && c <= '9':
		case c == '-' || c == '_' || c == ':':
		default:
			return false
		}
	}
	return true
}

// generateRequestID produces a non-guessable request ID using crypto/rand.
func generateRequestID() string {
	var buf [16]byte
	if _, err := rand.Read(buf[:]); err != nil {
		// crypto/rand should not fail in practice; fall back to a time-based
		// value so the process never crashes on ID generation.
		return requestIDPrefix + hex.EncodeToString([]byte(time.Now().UTC().Format("20060102150405.000000000")))
	}
	return requestIDPrefix + hex.EncodeToString(buf[:])
}

// Recovery catches panics in downstream handlers, logs the stack trace at error
// level, and returns a safe 500 envelope. It prevents a single faulty handler
// from crashing the whole process.
func Recovery(logger *slog.Logger) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			defer func() {
				if rec := recover(); rec != nil {
					logger.Error("panic recovered",
						"requestId", request.ID(r.Context()),
						"method", r.Method,
						"path", r.URL.Path,
						"panic", rec,
						"stack", string(debug.Stack()),
					)
					WriteInternalError(w, r)
				}
			}()
			next.ServeHTTP(w, r)
		})
	}
}

// statusRecorder captures the response status code for access logging without
// buffering the entire body.
type statusRecorder struct {
	http.ResponseWriter
	status int
}

func (s *statusRecorder) WriteHeader(code int) {
	s.status = code
	s.ResponseWriter.WriteHeader(code)
}

// AccessLog records one structured access log entry per request, including the
// request ID, method, path, status and duration.
func AccessLog(logger *slog.Logger) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			start := time.Now()
			rec := &statusRecorder{ResponseWriter: w, status: http.StatusOK}
			next.ServeHTTP(rec, r)
			duration := time.Since(start)

			logger.Info("http request",
				"requestId", request.ID(r.Context()),
				"method", r.Method,
				"path", r.URL.Path,
				"status", rec.status,
				"durationMs", duration.Milliseconds(),
			)
		})
	}
}

// SecurityHeaders adds baseline response headers that harden the API against
// common content-sniffing and framing attacks. Cookie security is enforced
// separately when sessions are introduced.
func SecurityHeaders(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		h := w.Header()
		h.Set("X-Content-Type-Options", "nosniff")
		h.Set("X-Frame-Options", "DENY")
		h.Set("Referrer-Policy", "no-referrer")
		h.Set("Cache-Control", "no-store")
		next.ServeHTTP(w, r)
	})
}

// MaxBodyBytes limits the size of request bodies. Bodies exceeding the limit
// are rejected with a 413 before any handler reads them.
func MaxBodyBytes(max int64) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			r.Body = http.MaxBytesReader(w, r.Body, max)
			next.ServeHTTP(w, r)
		})
	}
}
