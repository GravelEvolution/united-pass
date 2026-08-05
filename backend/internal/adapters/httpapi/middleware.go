package httpapi

import (
	"crypto/rand"
	"encoding/hex"
	"log/slog"
	"net/http"
	"runtime/debug"
	"time"

	"github.com/GravelEvolution/united-pass/backend/internal/adapters/httpapi/request"
	"github.com/GravelEvolution/united-pass/backend/internal/config"
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

// Recovery catches panics in downstream handlers. If the response has not yet
// been committed (no WriteHeader or Write call), it returns a safe 500
// envelope. If the response was already partially written, it logs the panic
// but cannot change the status — pretending to would corrupt the response.
//
// Recovery installs its own statusRecorder so it can track whether the handler
// committed the response, regardless of whether AccessLog is also present.
//
// In production the raw panic value is not logged because it may contain
// sensitive data (request payloads, credentials in stack frames). The stack
// trace is always logged at debug level for developer diagnosis.
func Recovery(logger *slog.Logger, cfg config.Config) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			rec := newStatusRecorder(w)
			defer func() {
				if recovered := recover(); recovered != nil {
					logPanic(logger, cfg, r, recovered)
					// Only write the 500 envelope if the response has not been
					// committed. If bytes were already sent to the client we
					// cannot change the status code or body.
					if !rec.wroteHeader {
						WriteInternalError(rec, r)
					}
				}
			}()
			next.ServeHTTP(rec, r)
		})
	}
}

// logPanic records the panic. In production it omits the raw panic value to
// avoid logging sensitive data; in development the value is included for
// faster diagnosis. The stack trace is logged at debug level in all
// environments.
func logPanic(logger *slog.Logger, cfg config.Config, r *http.Request, rec any) {
	attrs := []any{
		"requestId", request.ID(r.Context()),
		"method", r.Method,
		"path", r.URL.Path,
	}
	if cfg.IsProduction() {
		// Production: do not log the raw panic value, which may contain
		// sensitive data from request payloads or credential variables.
		attrs = append(attrs, "panic", "redacted")
	} else {
		attrs = append(attrs, "panic", rec)
	}
	logger.Error("panic recovered", attrs...)
	logger.Debug("panic stack trace", "stack", string(debug.Stack()))
}

// statusRecorder captures the response status code for access logging without
// buffering the entire body. It implements Unwrap so middleware that needs
// access to the underlying http.ResponseWriter (e.g. http.Flusher) can reach
// it via http.ResponseController.
type statusRecorder struct {
	http.ResponseWriter
	status      int
	wroteHeader bool
}

func newStatusRecorder(w http.ResponseWriter) *statusRecorder {
	return &statusRecorder{ResponseWriter: w, status: http.StatusOK}
}

// WriteHeader records the first status code and forwards it. Subsequent calls
// are ignored to match net/http semantics where only the first WriteHeader
// matters.
func (s *statusRecorder) WriteHeader(code int) {
	if s.wroteHeader {
		return
	}
	s.status = code
	s.wroteHeader = true
	s.ResponseWriter.WriteHeader(code)
}

// Write ensures the default 200 status is recorded before the first body
// write, matching net/http behavior.
func (s *statusRecorder) Write(body []byte) (int, error) {
	if !s.wroteHeader {
		s.WriteHeader(http.StatusOK)
	}
	return s.ResponseWriter.Write(body)
}

// Unwrap exposes the underlying http.ResponseWriter so http.ResponseController
// can access interfaces like http.Flusher and http.Hijacker.
func (s *statusRecorder) Unwrap() http.ResponseWriter {
	return s.ResponseWriter
}

// AccessLog records one structured access log entry per request, including the
// request ID, method, path, status and duration. The status recorder is
// installed so the log captures the actual response status, including the
// default 200 when a handler writes a body without calling WriteHeader.
func AccessLog(logger *slog.Logger) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			start := time.Now()
			rec := newStatusRecorder(w)
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

// MaxBodyBytes wraps the request body in an http.MaxBytesReader so handlers
// that read the body will encounter an *http.MaxBytesError when the limit is
// exceeded. The middleware itself does not return 413 automatically — the
// error surfaces when a handler or JSON decoder reads past the limit. Phase 1
// handlers should map *http.MaxBytesError to WriteRequestBodyTooLarge in their
// decode path:
//
//	var maxBytesError *http.MaxBytesError
//	if errors.As(err, &maxBytesError) {
//	    httpapi.WriteRequestBodyTooLarge(w, r)
//	    return
//	}
func MaxBodyBytes(max int64) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			r.Body = http.MaxBytesReader(w, r.Body, max)
			next.ServeHTTP(w, r)
		})
	}
}
