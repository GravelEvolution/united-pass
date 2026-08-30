package httpapi

import (
	"net/http"
	"net/http/httptest"
	"testing"
)

func TestTrustedClientIPIgnoresCallerControlledForwardingHeaders(t *testing.T) {
	middleware, err := TrustedClientIP([]string{"127.0.0.1/32", "::1/128"})
	if err != nil {
		t.Fatal(err)
	}
	handler := middleware(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Observed-Client-IP", clientIP(r))
		if clientIPAbuseEligible(r) {
			w.Header().Set("Abuse-Eligible", "true")
		}
		w.WriteHeader(http.StatusNoContent)
	}))

	request := httptest.NewRequest(http.MethodPost, "/api/v1/registrations", nil)
	request.RemoteAddr = "198.51.100.24:443"
	request.Header.Set("X-Forwarded-For", "203.0.113.9")
	request.Header.Set("Ali-Real-Client-IP", "203.0.113.10")
	request.Header.Set(TrustedClientIPHeader, "203.0.113.11")
	recorder := httptest.NewRecorder()
	handler.ServeHTTP(recorder, request)

	if got := recorder.Header().Get("Observed-Client-IP"); got != "198.51.100.24" {
		t.Fatalf("untrusted peer selected client IP %q", got)
	}
	if got := recorder.Header().Get("Abuse-Eligible"); got != "true" {
		t.Fatalf("direct transport peer unexpectedly ineligible for abuse controls: %q", got)
	}
}

func TestTrustedClientIPAcceptsOnlyOneValidatedGatewayValue(t *testing.T) {
	middleware, err := TrustedClientIP([]string{"127.0.0.1/32", "::1/128"})
	if err != nil {
		t.Fatal(err)
	}
	handler := middleware(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Observed-Client-IP", clientIP(r))
		if clientIPAbuseEligible(r) {
			w.Header().Set("Abuse-Eligible", "true")
		}
		w.WriteHeader(http.StatusNoContent)
	}))

	tests := []struct {
		name     string
		values   []string
		want     string
		eligible bool
	}{
		{name: "valid IPv4", values: []string{"203.0.113.12"}, want: "203.0.113.12", eligible: true},
		{name: "valid IPv6", values: []string{"2001:db8::12"}, want: "2001:db8::12", eligible: true},
		{name: "mapped IPv4 normalized", values: []string{"::ffff:203.0.113.12"}, want: "203.0.113.12", eligible: true},
		{name: "comma chain rejected", values: []string{"203.0.113.12, 198.51.100.4"}, want: "127.0.0.1"},
		{name: "duplicate rejected", values: []string{"203.0.113.12", "198.51.100.4"}, want: "127.0.0.1"},
		{name: "invalid rejected", values: []string{"not-an-address"}, want: "127.0.0.1"},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			request := httptest.NewRequest(http.MethodPost, "/api/v1/registrations", nil)
			request.RemoteAddr = "127.0.0.1:43210"
			for _, value := range test.values {
				request.Header.Add(TrustedClientIPHeader, value)
			}
			recorder := httptest.NewRecorder()
			handler.ServeHTTP(recorder, request)
			if got := recorder.Header().Get("Observed-Client-IP"); got != test.want {
				t.Fatalf("client IP = %q, want %q", got, test.want)
			}
			if got := recorder.Header().Get("Abuse-Eligible") == "true"; got != test.eligible {
				t.Fatalf("abuse eligibility = %v, want %v", got, test.eligible)
			}
		})
	}
}

func TestClientNetworkProducesStableAbuseScope(t *testing.T) {
	tests := []struct {
		address string
		want    string
	}{
		{address: "203.0.113.42", want: "203.0.113.0/24"},
		{address: "203.0.113.220", want: "203.0.113.0/24"},
		{address: "2001:db8:abcd:1234::1", want: "2001:db8:abcd:1200::/56"},
		{address: "invalid", want: "unknown"},
	}
	for _, test := range tests {
		if got := clientNetwork(test.address, 24, 56); got != test.want {
			t.Errorf("clientNetwork(%q) = %q, want %q", test.address, got, test.want)
		}
	}
	if got := clientNetwork("203.0.113.42", 33, 56); got != "unknown" {
		t.Fatalf("invalid prefix produced %q", got)
	}
}

func TestTrustedClientIPRejectsInvalidProxyCIDR(t *testing.T) {
	if _, err := TrustedClientIP([]string{"not-a-cidr"}); err == nil {
		t.Fatal("invalid trusted proxy CIDR accepted")
	}
}
