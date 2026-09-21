package dreamupadmin

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/http/cookiejar"
	"net/http/httptest"
	"net/url"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/GravelEvolution/united-pass/backend/internal/adapters/httpapi/request"
	admincontract "github.com/GravelEvolution/united-pass/backend/internal/dreamupadmin"
	"github.com/GravelEvolution/united-pass/backend/internal/dreamupdelegation"
	"github.com/GravelEvolution/united-pass/backend/internal/identityaccess"
)

func TestDoPropagatesBoundHeadersAndJSONExactlyOnce(t *testing.T) {
	t.Parallel()
	var calls atomic.Int32
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		calls.Add(1)
		if r.Method != http.MethodPut || r.URL.Path != "/internal/v1/events/evt_shanghai/applications/app_1/reviews/me" || r.URL.RawQuery != "mode=final" {
			t.Fatalf("request = %s %s?%s", r.Method, r.URL.Path, r.URL.RawQuery)
		}
		wantHeaders := map[string]string{
			"Authorization":   "Bearer delegation-secret",
			"X-Request-ID":    "req.client.123456",
			"Idempotency-Key": "idem_0123456789abcdefghijklmnopqrstuv",
			"If-Match":        `"7"`,
			"Accept":          "application/json",
			"Content-Type":    "application/json",
		}
		for name, want := range wantHeaders {
			if got := r.Header.Get(name); got != want {
				t.Errorf("%s = %q, want %q", name, got, want)
			}
		}
		body, err := io.ReadAll(r.Body)
		if err != nil {
			t.Fatal(err)
		}
		if string(body) != `{"recommendation":"accept","note":"ship it"}` {
			t.Fatalf("body = %s", body)
		}
		w.Header().Set("Content-Type", "application/json")
		w.Header().Set("X-Request-ID", "req.client.123456")
		w.Header().Set("ETag", `"8"`)
		_, _ = io.WriteString(w, `{"review":{"version":8}}`)
	}))
	defer server.Close()

	client := newTestClient(t, server.URL, server.Client())
	raw, meta, err := client.Do(context.Background(), Request{
		Method: http.MethodPut,
		Path:   "/internal/v1/events/evt_shanghai/applications/app_1/reviews/me",
		Query:  url.Values{"mode": {"final"}},
		Body: struct {
			Recommendation string `json:"recommendation"`
			Note           string `json:"note"`
		}{Recommendation: "accept", Note: "ship it"},
		Assertion:      validAssertion(10 * time.Second),
		RequestID:      "req.client.123456",
		IdempotencyKey: "idem_0123456789abcdefghijklmnopqrstuv",
		IfMatch:        `"7"`,
	})
	if err != nil {
		t.Fatalf("Do: %v", err)
	}
	if calls.Load() != 1 {
		t.Fatalf("calls = %d, want 1", calls.Load())
	}
	if string(raw) != `{"review":{"version":8}}` {
		t.Fatalf("raw = %s", raw)
	}
	if meta.StatusCode != http.StatusOK || meta.RequestID != "req.client.123456" || meta.ETag != `"8"` {
		t.Fatalf("meta = %+v", meta)
	}
}

func TestDoUsesTheSameWHATWGQueryCanonicalizationAsDelegationSignatures(t *testing.T) {
	t.Parallel()
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.RawQuery != "punctuation=*%7E&space=a+b" {
			t.Fatalf("raw query = %q", r.URL.RawQuery)
		}
		w.Header().Set("Content-Type", "application/json")
		_, _ = io.WriteString(w, `{"applications":[]}`)
	}))
	defer server.Close()

	client := newTestClient(t, server.URL, server.Client())
	input := testRequest(http.MethodGet, "/internal/v1/events/evt_shanghai/applications")
	input.Query = url.Values{"punctuation": {"*~"}, "space": {"a b"}}
	if _, _, err := client.Do(context.Background(), input); err != nil {
		t.Fatalf("Do: %v", err)
	}
}

func TestNewClientDoesNotForwardCookiesFromTheSuppliedHTTPClient(t *testing.T) {
	t.Parallel()
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if cookie := r.Header.Get("Cookie"); cookie != "" {
			t.Errorf("internal request carried ambient cookie %q", cookie)
		}
		w.Header().Set("Content-Type", "application/json")
		_, _ = io.WriteString(w, `{"applications":[]}`)
	}))
	defer server.Close()

	jar, err := cookiejar.New(nil)
	if err != nil {
		t.Fatal(err)
	}
	endpoint, err := url.Parse(server.URL)
	if err != nil {
		t.Fatal(err)
	}
	jar.SetCookies(endpoint, []*http.Cookie{{Name: "session", Value: "ambient-secret"}})
	client := newTestClient(t, server.URL, &http.Client{Transport: server.Client().Transport, Jar: jar})
	if _, _, err := client.Do(context.Background(), testRequest(http.MethodGet, "/internal/v1/events/evt_shanghai/applications")); err != nil {
		t.Fatalf("Do: %v", err)
	}
}

func TestExecuteAdaptsApplicationUpstreamContract(t *testing.T) {
	t.Parallel()
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodGet || r.URL.Path != "/internal/v1/events/evt_shanghai/applications" || r.URL.RawQuery != "limit=10&sort=created_at" {
			t.Fatalf("request = %s %s?%s", r.Method, r.URL.Path, r.URL.RawQuery)
		}
		if r.Header.Get("Idempotency-Key") != "" {
			t.Fatalf("safe GET carried idempotency key %q", r.Header.Get("Idempotency-Key"))
		}
		if r.Header.Get("Content-Type") != "" || r.ContentLength != 0 {
			t.Fatalf("safe GET body metadata = content-type %q length %d", r.Header.Get("Content-Type"), r.ContentLength)
		}
		w.Header().Set("Content-Type", "application/json")
		w.Header().Set("X-Request-ID", "req_execute_123456")
		w.Header().Set("ETag", `"4"`)
		_, _ = io.WriteString(w, `{"applications":[]}`)
	}))
	defer server.Close()
	client := newTestClient(t, server.URL, server.Client())
	response, err := client.Execute(context.Background(), admincontract.UpstreamRequest{
		Method: http.MethodGet, Path: "/internal/v1/events/evt_shanghai/applications",
		Query: url.Values{"sort": {"created_at"}, "limit": {"10"}}, Assertion: validAssertion(10 * time.Second), RequestID: "req_execute_123456",
	})
	if err != nil {
		t.Fatalf("Execute: %v", err)
	}
	if response.StatusCode != http.StatusOK || response.RequestID != "req_execute_123456" || response.ETag != `"4"` || string(response.Body) != `{"applications":[]}` {
		t.Fatalf("response = %+v body=%s", response, response.Body)
	}
}

func TestExecuteMapsTransportClassificationsToApplicationErrors(t *testing.T) {
	t.Parallel()
	cases := []struct {
		status int
		want   error
	}{
		{http.StatusBadRequest, admincontract.ErrInvalidRequest},
		{http.StatusUnauthorized, admincontract.ErrForbidden},
		{http.StatusForbidden, admincontract.ErrForbidden},
		{http.StatusNotFound, admincontract.ErrNotFound},
		{http.StatusConflict, admincontract.ErrConflict},
		{http.StatusPreconditionFailed, admincontract.ErrConflict},
		{http.StatusTooManyRequests, admincontract.ErrUpstream},
		{http.StatusRequestTimeout, admincontract.ErrUpstream},
		{http.StatusInternalServerError, admincontract.ErrUpstream},
	}
	for _, tc := range cases {
		t.Run(http.StatusText(tc.status), func(t *testing.T) {
			transport := roundTripperFunc(func(*http.Request) (*http.Response, error) {
				return jsonResponse(tc.status, `{"error":"redacted"}`), nil
			})
			client := newTestClient(t, "http://127.0.0.1:18084", &http.Client{Transport: transport})
			_, err := client.Execute(context.Background(), admincontract.UpstreamRequest{
				Method: http.MethodGet, Path: "/internal/v1/events/evt_shanghai/applications",
				Assertion: validAssertion(10 * time.Second), RequestID: "req_execute_123456",
			})
			if !errors.Is(err, tc.want) {
				t.Fatalf("error = %v, want %v", err, tc.want)
			}
		})
	}
}

func TestDoNeverFollowsRedirectsOrRetriesSensitiveCalls(t *testing.T) {
	t.Parallel()
	var redirected atomic.Int32
	destination := httptest.NewServer(http.HandlerFunc(func(http.ResponseWriter, *http.Request) {
		redirected.Add(1)
	}))
	defer destination.Close()

	t.Run("redirect", func(t *testing.T) {
		origin := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
			http.Redirect(w, &http.Request{}, destination.URL, http.StatusTemporaryRedirect)
		}))
		defer origin.Close()
		client := newTestClient(t, origin.URL, origin.Client())
		_, _, err := client.Do(context.Background(), testRequest(http.MethodGet, "/internal/v1/events/evt/applications"))
		if !errors.Is(err, ErrProtocol) {
			t.Fatalf("redirect error = %v, want ErrProtocol", err)
		}
		if redirected.Load() != 0 {
			t.Fatalf("redirect destination called %d times", redirected.Load())
		}
	})

	for _, method := range []string{http.MethodGet, http.MethodPost} {
		t.Run(method+" has no status retry", func(t *testing.T) {
			var calls atomic.Int32
			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
				calls.Add(1)
				w.Header().Set("Content-Type", "application/json")
				w.WriteHeader(http.StatusServiceUnavailable)
				_, _ = io.WriteString(w, `{"error":"do not retry"}`)
			}))
			defer server.Close()
			client := newTestClient(t, server.URL, server.Client())
			req := testRequest(method, "/internal/v1/restricted-identity/read")
			if method == http.MethodPost {
				req.Body = map[string]string{"targetId": "participant-secret"}
				req.IdempotencyKey = "idem_0123456789abcdefghijklmnopqrstuv"
			}
			_, _, err := client.Do(context.Background(), req)
			if !errors.Is(err, ErrUnavailable) {
				t.Fatalf("error = %v, want ErrUnavailable", err)
			}
			if calls.Load() != 1 {
				t.Fatalf("calls = %d, want exactly one", calls.Load())
			}
		})
	}
}

func TestDoUsesEarlierOfFiveSecondsAndAssertionExpirySkew(t *testing.T) {
	t.Parallel()
	now := time.Now().UTC()
	var deadlines []time.Time
	transport := roundTripperFunc(func(r *http.Request) (*http.Response, error) {
		deadline, ok := r.Context().Deadline()
		if !ok {
			t.Fatal("request has no deadline")
		}
		deadlines = append(deadlines, deadline)
		return jsonResponse(http.StatusOK, `{"ok":true}`), nil
	})
	client := newTestClient(t, "http://127.0.0.1:18084", &http.Client{Transport: transport}, WithClock(func() time.Time { return now }))

	long := testRequest(http.MethodGet, "/internal/v1/events/evt/applications")
	long.Assertion.ExpiresAt = now.Add(30 * time.Second)
	if _, _, err := client.Do(context.Background(), long); err != nil {
		t.Fatalf("long assertion: %v", err)
	}
	short := testRequest(http.MethodGet, "/internal/v1/events/evt/applications")
	short.Assertion.ExpiresAt = now.Add(7500 * time.Millisecond)
	if _, _, err := client.Do(context.Background(), short); err != nil {
		t.Fatalf("short assertion: %v", err)
	}
	if len(deadlines) != 2 {
		t.Fatalf("deadlines = %d", len(deadlines))
	}
	if delta := deadlines[0].Sub(now); delta != 5*time.Second {
		t.Fatalf("ordinary deadline delta = %s, want 5s", delta)
	}
	if delta := deadlines[1].Sub(now); delta != 2500*time.Millisecond {
		t.Fatalf("expiry-bound deadline delta = %s, want 2.5s", delta)
	}

	expired := testRequest(http.MethodGet, "/internal/v1/events/evt/applications")
	expired.Assertion.ExpiresAt = now.Add(dreamupdelegation.MaxClockSkew)
	if _, _, err := client.Do(context.Background(), expired); !errors.Is(err, ErrAssertionExpired) {
		t.Fatalf("expired assertion error = %v", err)
	}
	if len(deadlines) != 2 {
		t.Fatal("expired assertion reached transport")
	}
}

func TestDoRejectsOversizedOrNonExactJSONResponses(t *testing.T) {
	t.Parallel()
	cases := []struct {
		name        string
		contentType string
		body        string
		want        error
	}{
		{name: "wrong media type", contentType: "text/plain", body: `{"ok":true}`, want: ErrProtocol},
		{name: "unsupported charset", contentType: "application/json; charset=gbk", body: `{"ok":true}`, want: ErrProtocol},
		{name: "trailing value", contentType: "application/json", body: `{"ok":true}{"second":true}`, want: ErrProtocol},
		{name: "non object", contentType: "application/json", body: `[1,2,3]`, want: ErrProtocol},
		{name: "malformed", contentType: "application/json", body: `{"ok":`, want: ErrProtocol},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
				w.Header().Set("Content-Type", tc.contentType)
				_, _ = io.WriteString(w, tc.body)
			}))
			defer server.Close()
			client := newTestClient(t, server.URL, server.Client())
			_, _, err := client.Do(context.Background(), testRequest(http.MethodGet, "/internal/v1/events/evt/applications"))
			if !errors.Is(err, tc.want) {
				t.Fatalf("error = %v, want %v", err, tc.want)
			}
		})
	}

	transport := roundTripperFunc(func(*http.Request) (*http.Response, error) {
		return &http.Response{
			StatusCode:    http.StatusOK,
			Header:        http.Header{"Content-Type": {"application/json"}, "Content-Length": {"8388609"}},
			ContentLength: MaxResponseBytes + 1,
			Body:          io.NopCloser(strings.NewReader(`{"never":"read"}`)),
		}, nil
	})
	client := newTestClient(t, "http://127.0.0.1:18084", &http.Client{Transport: transport})
	if _, _, err := client.Do(context.Background(), testRequest(http.MethodGet, "/internal/v1/events/evt/applications")); !errors.Is(err, ErrResponseTooLarge) {
		t.Fatalf("oversized response error = %v", err)
	}
}

func TestDoHonorsConfiguredResponseCeiling(t *testing.T) {
	t.Parallel()
	const ceiling = int64(1 << 20)
	transport := roundTripperFunc(func(*http.Request) (*http.Response, error) {
		return &http.Response{
			StatusCode:    http.StatusOK,
			Header:        http.Header{"Content-Type": {"application/json"}},
			ContentLength: ceiling + 1,
			Body:          io.NopCloser(strings.NewReader(`{"never":"read"}`)),
		}, nil
	})
	client := newTestClient(t, "http://127.0.0.1:18084", &http.Client{Transport: transport}, WithMaxResponseBytes(ceiling))
	if _, _, err := client.Do(context.Background(), testRequest(http.MethodGet, "/internal/v1/events/evt/applications")); !errors.Is(err, ErrResponseTooLarge) {
		t.Fatalf("configured response ceiling error = %v", err)
	}
}

func TestDoClassifiesHTTPFailuresWithoutReflectingResponseSecrets(t *testing.T) {
	t.Parallel()
	cases := []struct {
		status int
		want   error
	}{
		{http.StatusBadRequest, ErrRejected},
		{http.StatusUnauthorized, ErrUnauthorized},
		{http.StatusForbidden, ErrForbidden},
		{http.StatusNotFound, ErrNotFound},
		{http.StatusConflict, ErrConflict},
		{http.StatusPreconditionFailed, ErrConflict},
		{http.StatusUnprocessableEntity, ErrRejected},
		{http.StatusTeapot, ErrRejected},
		{http.StatusTooManyRequests, ErrRateLimited},
		{http.StatusRequestTimeout, ErrUnavailable},
		{http.StatusInternalServerError, ErrUnavailable},
	}
	for _, tc := range cases {
		t.Run(http.StatusText(tc.status), func(t *testing.T) {
			transport := roundTripperFunc(func(*http.Request) (*http.Response, error) {
				return jsonResponse(tc.status, `{"error":"identity 310000 secret-token"}`), nil
			})
			client := newTestClient(t, "http://127.0.0.1:18084", &http.Client{Transport: transport})
			_, _, err := client.Do(context.Background(), testRequest(http.MethodGet, "/internal/v1/events/evt/applications"))
			if !errors.Is(err, tc.want) {
				t.Fatalf("error = %v, want %v", err, tc.want)
			}
			if strings.Contains(err.Error(), "310000") || strings.Contains(err.Error(), "secret-token") || strings.Contains(err.Error(), "identity") {
				t.Fatalf("error reflected response body: %q", err)
			}
		})
	}
}

func TestValidateIdentityTargetMapsTask8ToTask9AndRejectsResponseDrift(t *testing.T) {
	t.Parallel()
	cases := []struct {
		name           string
		target         identityaccess.TargetRef
		fields         []identityaccess.Field
		wantTargetType string
		wantFields     string
		wantBodySHA    string
	}{
		{
			name:           "application",
			target:         identityaccess.TargetRef{Type: identityaccess.TargetApplication, ID: "app_123"},
			fields:         []identityaccess.Field{identityaccess.FieldLegalName, identityaccess.FieldIdentityNumber, identityaccess.FieldIdentityPhoto, identityaccess.FieldContactEmail, identityaccess.FieldContactMobile},
			wantTargetType: "application",
			wantFields:     `["legal_name","identity_document_number","portrait","email","mobile"]`,
			wantBodySHA:    "3ff70bfc85583e5dce8cfe96c39f393298e5794b46afe81ea59907258ff9d5b1",
		},
		{
			name:           "check in maps to participant",
			target:         identityaccess.TargetRef{Type: identityaccess.TargetCheckIn, ID: "participant_123"},
			fields:         []identityaccess.Field{identityaccess.FieldIdentityNumber},
			wantTargetType: "participant",
			wantFields:     `["identity_document_number"]`,
			wantBodySHA:    "7990c109ec8cde9784a9696508118441afd0ad6d42865e26828e0ee85c268d35",
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			var assertionInput AssertionRequest
			source := AssertionSourceFunc(func(_ context.Context, input AssertionRequest) (dreamupdelegation.SignedAssertion, error) {
				assertionInput = input
				return validAssertion(10 * time.Second), nil
			})
			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				if r.Method != http.MethodPost || r.URL.Path != "/internal/v1/identity-access/targets/validate" {
					t.Fatalf("request = %s %s", r.Method, r.URL.Path)
				}
				if key := r.Header.Get("Idempotency-Key"); !idempotencyKeyPattern.MatchString(key) {
					t.Fatalf("internal idempotency key = %q", key)
				}
				var body struct {
					TargetType string            `json:"targetType"`
					TargetID   string            `json:"targetId"`
					Fields     []json.RawMessage `json:"fields"`
				}
				decoder := json.NewDecoder(r.Body)
				decoder.DisallowUnknownFields()
				if err := decoder.Decode(&body); err != nil {
					t.Fatalf("decode body: %v", err)
				}
				fields, _ := json.Marshal(body.Fields)
				if body.TargetType != tc.wantTargetType || body.TargetID != tc.target.ID || string(fields) != tc.wantFields {
					t.Fatalf("body = type %q id %q fields %s", body.TargetType, body.TargetID, fields)
				}
				w.Header().Set("Content-Type", "application/json; charset=utf-8")
				_, _ = io.WriteString(w, `{"target":{"targetType":"`+tc.wantTargetType+`","targetId":"`+tc.target.ID+`","targetSubjectUserId":"usr_participant"}}`)
			}))
			defer server.Close()
			client := newTestClient(t, server.URL, server.Client(), WithAssertionSource(source))
			ctx := request.WithID(context.Background(), "req_target_123456")
			validated, err := client.ValidateIdentityTarget(ctx, "evt_shanghai", tc.target, tc.fields)
			if err != nil {
				t.Fatalf("ValidateIdentityTarget: %v", err)
			}
			if validated.Target != tc.target || validated.SubjectUserID != "usr_participant" {
				t.Fatalf("validated = %+v", validated)
			}
			if assertionInput.EventID != "evt_shanghai" || assertionInput.Method != http.MethodPost || assertionInput.PathAndQuery != "/internal/v1/identity-access/targets/validate" || assertionInput.RequestID != "req_target_123456" || assertionInput.BodySHA256 != tc.wantBodySHA {
				t.Fatalf("assertion input = %+v", assertionInput)
			}
			if !idempotencyKeyPattern.MatchString(assertionInput.IdempotencyKey) {
				t.Fatalf("assertion idempotency key = %q", assertionInput.IdempotencyKey)
			}
		})
	}

	t.Run("unknown response field", func(t *testing.T) {
		server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
			w.Header().Set("Content-Type", "application/json")
			_, _ = io.WriteString(w, `{"target":{"targetType":"application","targetId":"app_1","targetSubjectUserId":"usr_1","identityNumber":"must not decode"}}`)
		}))
		defer server.Close()
		client := newTestClient(t, server.URL, server.Client(), WithAssertionSource(staticAssertionSource{}))
		ctx := request.WithID(context.Background(), "req_target_123456")
		_, err := client.ValidateIdentityTarget(ctx, "evt_shanghai", identityaccess.TargetRef{Type: identityaccess.TargetApplication, ID: "app_1"}, []identityaccess.Field{identityaccess.FieldLegalName})
		if !errors.Is(err, ErrProtocol) {
			t.Fatalf("unknown response error = %v, want ErrProtocol", err)
		}
	})

	t.Run("mismatched target envelope", func(t *testing.T) {
		server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
			w.Header().Set("Content-Type", "application/json")
			_, _ = io.WriteString(w, `{"target":{"targetType":"participant","targetId":"another_app","targetSubjectUserId":"usr_1"}}`)
		}))
		defer server.Close()
		client := newTestClient(t, server.URL, server.Client(), WithAssertionSource(staticAssertionSource{}))
		ctx := request.WithID(context.Background(), "req_target_123456")
		_, err := client.ValidateIdentityTarget(ctx, "evt_shanghai", identityaccess.TargetRef{Type: identityaccess.TargetApplication, ID: "app_1"}, []identityaccess.Field{identityaccess.FieldLegalName})
		if !errors.Is(err, ErrProtocol) {
			t.Fatalf("mismatched target error = %v, want ErrProtocol", err)
		}
	})
}

func TestLookupOperationReceiptUsesReadOnlyEndpointAndStrictSchema(t *testing.T) {
	t.Parallel()
	idempotencyKey := "idem_0123456789abcdefghijklmnopqrstuv"
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodGet || r.URL.Path != "/internal/v1/events/evt_shanghai/operation-receipts/opreq_12345678" {
			t.Fatalf("request = %s %s", r.Method, r.URL.Path)
		}
		if r.Header.Get("Authorization") != "Bearer delegation-secret" || r.Header.Get("X-Request-ID") != "req_receipt_123456" || r.Header.Get("Idempotency-Key") != idempotencyKey || r.Header.Get("If-Match") != "" {
			t.Fatalf("unsafe receipt headers = %#v", r.Header)
		}
		w.Header().Set("Content-Type", "application/json")
		_, _ = io.WriteString(w, `{"receipt":{"event_id":"evt_shanghai","action":"review","target_type":"application","target_id":"app_1","outcome":"applied","result_version":4,"receipt_hash":"sha256_abcdef","request_id":"req_original_123","created_at":"2026-08-17T12:00:00Z"}}`)
	}))
	defer server.Close()
	client := newTestClient(t, server.URL, server.Client())
	receipt, err := client.LookupOperationReceipt(context.Background(), "evt_shanghai", "opreq_12345678", "req_receipt_123456", idempotencyKey, validAssertion(10*time.Second))
	if err != nil {
		t.Fatalf("LookupOperationReceipt: %v", err)
	}
	if receipt.EventID != "evt_shanghai" || receipt.Action != "review" || receipt.TargetType != "application" || receipt.TargetID != "app_1" || receipt.Outcome != "applied" || receipt.ResultVersion != 4 || receipt.ReceiptHash != "sha256_abcdef" || receipt.RequestID != "req_original_123" || !receipt.CreatedAt.Equal(time.Date(2026, 8, 17, 12, 0, 0, 0, time.UTC)) {
		t.Fatalf("receipt = %+v", receipt)
	}
}

func TestLookupOperationReceiptRejectsMissingOrCrossEventBinding(t *testing.T) {
	t.Parallel()
	const base = `{"receipt":{%s"action":"review","target_type":"application","target_id":"app_1","outcome":"applied","result_version":4,"receipt_hash":"sha256_abcdef","request_id":"req_original_123","created_at":"2026-08-17T12:00:00Z"}}`
	for name, eventField := range map[string]string{
		"missing event": "",
		"cross event":   `"event_id":"evt_beijing",`,
	} {
		t.Run(name, func(t *testing.T) {
			t.Parallel()
			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
				w.Header().Set("Content-Type", "application/json")
				_, _ = io.WriteString(w, fmt.Sprintf(base, eventField))
			}))
			defer server.Close()
			client := newTestClient(t, server.URL, server.Client())
			_, err := client.LookupOperationReceipt(context.Background(), "evt_shanghai", "opreq_12345678", "req_receipt_123456", "idem_0123456789abcdefghijklmnopqrstuv", validAssertion(10*time.Second))
			if !errors.Is(err, ErrProtocol) {
				t.Fatalf("event binding error = %v, want ErrProtocol", err)
			}
		})
	}
}

func TestClientRejectsUnsafeConfigurationAndRequestMetadata(t *testing.T) {
	t.Parallel()
	for _, base := range []string{"", "127.0.0.1:18084", "ftp://127.0.0.1", "http://user:pass@127.0.0.1", "http://127.0.0.1/prefix", "http://127.0.0.1?leak=1", "http://127.0.0.1/#fragment"} {
		if _, err := NewClient(base, &http.Client{}); err == nil {
			t.Errorf("unsafe base %q accepted", base)
		}
	}
	for _, limit := range []int64{0, (1 << 20) - 1, (16 << 20) + 1} {
		if _, err := NewClient("http://127.0.0.1:18084", &http.Client{}, WithMaxResponseBytes(limit)); err == nil {
			t.Errorf("unsafe response limit %d accepted", limit)
		}
	}
	var calls atomic.Int32
	transport := roundTripperFunc(func(*http.Request) (*http.Response, error) {
		calls.Add(1)
		return jsonResponse(http.StatusOK, `{"ok":true}`), nil
	})
	client := newTestClient(t, "http://127.0.0.1:18084", &http.Client{Transport: transport})
	cases := []Request{
		{Method: http.MethodPost, Path: "/internal/v1/events/evt/applications", Assertion: validAssertion(10 * time.Second), RequestID: "req_safe_123"},
		{Method: http.MethodGet, Path: "https://evil.example/internal/v1/x", Assertion: validAssertion(10 * time.Second), RequestID: "req_safe_123"},
		{Method: http.MethodGet, Path: "/internal/v1/../admin", Assertion: validAssertion(10 * time.Second), RequestID: "req_safe_123"},
		{Method: http.MethodGet, Path: "/api/v1/public", Assertion: validAssertion(10 * time.Second), RequestID: "req_safe_123"},
		{Method: http.MethodGet, Path: "/internal/v1/x", Assertion: validAssertion(10 * time.Second), RequestID: "bad\r\nheader"},
		{Method: http.MethodPost, Path: "/internal/v1/x", Assertion: validAssertion(10 * time.Second), RequestID: "req_safe_123", IdempotencyKey: "short"},
		{Method: http.MethodPut, Path: "/internal/v1/x", Assertion: validAssertion(10 * time.Second), RequestID: "req_safe_123", IfMatch: "7"},
	}
	for i, input := range cases {
		if _, _, err := client.Do(context.Background(), input); !errors.Is(err, ErrInvalidRequest) {
			t.Errorf("case %d error = %v", i, err)
		}
	}
	if calls.Load() != 0 {
		t.Fatalf("unsafe inputs reached transport %d times", calls.Load())
	}
}

func TestRequestIDAcceptsTheShared128CharacterBoundary(t *testing.T) {
	if !validRequestID(strings.Repeat("a", 128)) {
		t.Fatal("128-character request ID rejected")
	}
	if validRequestID(strings.Repeat("a", 129)) {
		t.Fatal("129-character request ID accepted")
	}
}

type staticAssertionSource struct{}

func (staticAssertionSource) Sign(context.Context, AssertionRequest) (dreamupdelegation.SignedAssertion, error) {
	return validAssertion(10 * time.Second), nil
}

func validAssertion(ttl time.Duration) dreamupdelegation.SignedAssertion {
	now := time.Now().UTC()
	return dreamupdelegation.SignedAssertion{Token: "delegation-secret", NotBefore: now.Add(-time.Second), ExpiresAt: now.Add(ttl)}
}

func testRequest(method, path string) Request {
	return Request{Method: method, Path: path, Assertion: validAssertion(10 * time.Second), RequestID: "req_test_123456", IdempotencyKey: "idem_0123456789abcdefghijklmnopqrstuv"}
}

func newTestClient(t *testing.T, baseURL string, httpClient *http.Client, options ...Option) *Client {
	t.Helper()
	client, err := NewClient(baseURL, httpClient, options...)
	if err != nil {
		t.Fatalf("NewClient: %v", err)
	}
	return client
}

type roundTripperFunc func(*http.Request) (*http.Response, error)

func (f roundTripperFunc) RoundTrip(request *http.Request) (*http.Response, error) { return f(request) }

func jsonResponse(status int, body string) *http.Response {
	return &http.Response{
		StatusCode: status,
		Header:     http.Header{"Content-Type": {"application/json"}},
		Body:       io.NopCloser(strings.NewReader(body)),
	}
}
