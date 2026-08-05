package httpapi

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/GravelEvolution/united-pass/backend/internal/adapters/httpapi/request"
)

func TestRequestIDGeneratedWhenAbsent(t *testing.T) {
	h := RequestID(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if id := request.ID(r.Context()); id == "" || !strings.HasPrefix(id, requestIDPrefix) {
			t.Errorf("expected generated id with prefix %q, got %q", requestIDPrefix, id)
		}
		w.WriteHeader(http.StatusOK)
	}))

	rec := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "/", nil)
	h.ServeHTTP(rec, req)

	if id := rec.Header().Get(RequestIDHeader); !strings.HasPrefix(id, requestIDPrefix) {
		t.Errorf("response header id = %q, want prefix %q", id, requestIDPrefix)
	}
}

func TestRequestIDPassthroughWhenValid(t *testing.T) {
	upstream := "req_abcdef1234567890"
	h := RequestID(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if got := request.ID(r.Context()); got != upstream {
			t.Errorf("context id = %q, want %q", got, upstream)
		}
		w.WriteHeader(http.StatusOK)
	}))

	rec := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "/", nil)
	req.Header.Set(RequestIDHeader, upstream)
	h.ServeHTTP(rec, req)

	if got := rec.Header().Get(RequestIDHeader); got != upstream {
		t.Errorf("response header id = %q, want %q", got, upstream)
	}
}

func TestRequestIDRegeneratesWhenInvalid(t *testing.T) {
	cases := []string{"", "short", "contains spaces and is long enough but invalid!!", strings.Repeat("x", 200)}
	for _, invalid := range cases {
		t.Run(invalid, func(t *testing.T) {
			h := RequestID(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				id := request.ID(r.Context())
				if id == invalid {
					t.Errorf("invalid id was accepted: %q", id)
				}
			}))

			rec := httptest.NewRecorder()
			req := httptest.NewRequest(http.MethodGet, "/", nil)
			if invalid != "" {
				req.Header.Set(RequestIDHeader, invalid)
			}
			h.ServeHTTP(rec, req)

			if id := rec.Header().Get(RequestIDHeader); !strings.HasPrefix(id, requestIDPrefix) {
				t.Errorf("response id = %q, want regenerated prefix %q", id, requestIDPrefix)
			}
		})
	}
}

func TestRecoveryReturnsSafeEnvelope(t *testing.T) {
	logger := newTestLogger()
	h := Recovery(logger)(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		panic("boom")
	}))

	rec := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "/", nil)
	req = req.WithContext(request.WithID(req.Context(), "req_test1234567890"))
	h.ServeHTTP(rec, req)

	if rec.Code != http.StatusInternalServerError {
		t.Fatalf("status = %d, want %d", rec.Code, http.StatusInternalServerError)
	}
	var resp ErrorResponse
	if err := json.Unmarshal(rec.Body.Bytes(), &resp); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	if resp.Error.Code != CodeInternal {
		t.Errorf("code = %q, want %q", resp.Error.Code, CodeInternal)
	}
	if resp.Error.RequestID != "req_test1234567890" {
		t.Errorf("requestId = %q, want %q", resp.Error.RequestID, "req_test1234567890")
	}
	if strings.Contains(rec.Body.String(), "boom") {
		t.Errorf("response leaked panic detail: %s", rec.Body.String())
	}
}

func TestSecurityHeaders(t *testing.T) {
	h := SecurityHeaders(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))

	rec := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "/", nil)
	h.ServeHTTP(rec, req)

	checks := map[string]string{
		"X-Content-Type-Options": "nosniff",
		"X-Frame-Options":        "DENY",
		"Referrer-Policy":        "no-referrer",
		"Cache-Control":          "no-store",
	}
	for header, want := range checks {
		if got := rec.Header().Get(header); got != want {
			t.Errorf("header %q = %q, want %q", header, got, want)
		}
	}
}

func TestMaxBodyBytesRejectsOversized(t *testing.T) {
	h := MaxBodyBytes(16)(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body, err := io.ReadAll(r.Body)
		if err != nil {
			WriteRequestBodyTooLarge(w, r)
			return
		}
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write(body)
	}))

	rec := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodPost, "/", bytes.NewReader(bytes.Repeat([]byte("a"), 64)))
	h.ServeHTTP(rec, req)

	if rec.Code != http.StatusRequestEntityTooLarge {
		t.Fatalf("status = %d, want %d", rec.Code, http.StatusRequestEntityTooLarge)
	}
	var resp ErrorResponse
	if err := json.Unmarshal(rec.Body.Bytes(), &resp); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	if resp.Error.Code != CodeRequestBodyTooLarge {
		t.Errorf("code = %q, want %q", resp.Error.Code, CodeRequestBodyTooLarge)
	}
}

func TestMaxBodyBytesAllowsWithinLimit(t *testing.T) {
	h := MaxBodyBytes(64)(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body, err := io.ReadAll(r.Body)
		if err != nil {
			WriteRequestBodyTooLarge(w, r)
			return
		}
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write(body)
	}))

	rec := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodPost, "/", bytes.NewReader([]byte("hello")))
	h.ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want %d", rec.Code, http.StatusOK)
	}
}

func TestErrorEnvelopeShape(t *testing.T) {
	rec := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "/", nil)
	req = req.WithContext(request.WithID(req.Context(), "req_shape_abcdef"))
	WriteValidation(rec, req, "字段校验失败", []FieldError{
		{Field: "email", Message: "邮箱格式无效"},
	})

	if rec.Code != http.StatusUnprocessableEntity {
		t.Fatalf("status = %d, want %d", rec.Code, http.StatusUnprocessableEntity)
	}
	if ct := rec.Header().Get("Content-Type"); !strings.HasPrefix(ct, "application/json") {
		t.Errorf("content-type = %q, want application/json", ct)
	}
	if id := rec.Header().Get(RequestIDHeader); id != "req_shape_abcdef" {
		t.Errorf("response request id header = %q, want %q", id, "req_shape_abcdef")
	}

	var resp ErrorResponse
	if err := json.Unmarshal(rec.Body.Bytes(), &resp); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	if resp.Error.Code != CodeValidation {
		t.Errorf("code = %q, want %q", resp.Error.Code, CodeValidation)
	}
	if resp.Error.Message != "字段校验失败" {
		t.Errorf("message = %q, want %q", resp.Error.Message, "字段校验失败")
	}
	if resp.Error.RequestID != "req_shape_abcdef" {
		t.Errorf("requestId = %q, want %q", resp.Error.RequestID, "req_shape_abcdef")
	}
	if len(resp.Error.FieldErrors) != 1 || resp.Error.FieldErrors[0].Field != "email" {
		t.Errorf("fieldErrors = %+v, want one email error", resp.Error.FieldErrors)
	}
}

// failingChecker is a ReadinessChecker that always errors.
type failingChecker struct{}

func (failingChecker) Name() string { return "failing" }
func (failingChecker) Check(context.Context) error {
	return errors.New("dependency down")
}

// okChecker is a ReadinessChecker that always succeeds.
type okChecker struct{}

func (okChecker) Name() string                { return "ok" }
func (okChecker) Check(context.Context) error { return nil }

func TestHealthz(t *testing.T) {
	h := NewHealthHandlers()
	rec := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "/healthz", nil)
	h.Healthz(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want %d", rec.Code, http.StatusOK)
	}
	var body map[string]string
	if err := json.Unmarshal(rec.Body.Bytes(), &body); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	if body["status"] != "ok" {
		t.Errorf("status = %q, want %q", body["status"], "ok")
	}
}

func TestReadyzNoCheckers(t *testing.T) {
	h := NewHealthHandlers()
	rec := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "/readyz", nil)
	h.Readyz(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want %d", rec.Code, http.StatusOK)
	}
	var body map[string]string
	if err := json.Unmarshal(rec.Body.Bytes(), &body); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	if body["status"] != "ready" {
		t.Errorf("status = %q, want %q", body["status"], "ready")
	}
}

func TestReadyzFailingChecker(t *testing.T) {
	h := NewHealthHandlers(failingChecker{})
	rec := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "/readyz", nil)
	h.Readyz(rec, req)

	if rec.Code != http.StatusServiceUnavailable {
		t.Fatalf("status = %d, want %d", rec.Code, http.StatusServiceUnavailable)
	}
}

func TestReadyzAllCheckersPass(t *testing.T) {
	h := NewHealthHandlers(okChecker{}, okChecker{})
	rec := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "/readyz", nil)
	h.Readyz(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want %d", rec.Code, http.StatusOK)
	}
}

func TestReadyzDoesNotLeakDependencyDetails(t *testing.T) {
	h := NewHealthHandlers(failingChecker{})
	rec := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "/readyz", nil)
	h.Readyz(rec, req)

	if strings.Contains(rec.Body.String(), "dependency down") {
		t.Errorf("response leaked internal error detail: %s", rec.Body.String())
	}
}

func newTestLogger() *slog.Logger {
	return slog.New(slog.NewTextHandler(io.Discard, nil))
}
