package captcha

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"image/png"
	"io"
	"math"
	"net/http"
	"strings"
	"testing"
	"time"

	"github.com/GravelEvolution/united-pass/backend/internal/riskdefense"
)

var providerTestNow = time.Date(2026, 8, 26, 1, 2, 3, 0, time.UTC)

type memoryFirstPartyImageStore struct {
	answers map[string]string
}

func (s *memoryFirstPartyImageStore) Create(_ context.Context, challengeID, answer string, _ time.Duration) error {
	if s.answers == nil {
		s.answers = make(map[string]string)
	}
	if _, exists := s.answers[challengeID]; exists {
		return errors.New("duplicate")
	}
	s.answers[challengeID] = answer
	return nil
}

func (s *memoryFirstPartyImageStore) ConsumeIfMatches(_ context.Context, challengeID, answer string) (bool, error) {
	want, exists := s.answers[challengeID]
	if !exists || want != answer {
		return false, nil
	}
	delete(s.answers, challengeID)
	return true, nil
}

func TestFirstPartyImageCaptchaPayloadCannotExposeFixedSVGGridAndConsumesOnce(t *testing.T) {
	store := &memoryFirstPartyImageStore{}
	provider, err := NewFirstPartyImage(FirstPartyImageConfig{
		Store:  store,
		TTL:    5 * time.Minute,
		Random: bytes.NewReader(bytes.Repeat([]byte{7}, 128)),
	})
	if err != nil {
		t.Fatal(err)
	}
	if !provider.Available(t.Context(), riskdefense.ProviderRegionMainlandChina) {
		t.Fatal("first-party image CAPTCHA must be available in mainland China")
	}
	challenge, err := provider.Begin(t.Context(), riskdefense.OperationLogin)
	if err != nil {
		t.Fatal(err)
	}
	if challenge.Provider != FirstPartyImageProviderName || store.answers[challenge.ID] != "77777" {
		t.Fatalf("challenge=%#v stored=%q", challenge, store.answers[challenge.ID])
	}
	var payload firstPartyImagePublicPayload
	if err := json.Unmarshal(challenge.PublicPayload, &payload); err != nil {
		t.Fatal(err)
	}
	if payload.Digits != firstPartyDigitCount || !strings.HasPrefix(payload.ImageDataURL, "data:image/png;base64,") {
		t.Fatalf("public payload=%#v", payload)
	}
	encodedPNG := strings.TrimPrefix(payload.ImageDataURL, "data:image/png;base64,")
	pixels, err := base64.StdEncoding.DecodeString(encodedPNG)
	if err != nil {
		t.Fatal(err)
	}
	decoded, err := png.Decode(bytes.NewReader(pixels))
	if err != nil {
		t.Fatalf("decode CAPTCHA PNG: %v", err)
	}
	if decoded.Bounds().Dx() != firstPartyImageWidth || decoded.Bounds().Dy() != firstPartyImageHeight {
		t.Fatalf("image bounds=%v", decoded.Bounds())
	}
	if bytes.Contains(pixels, []byte("<svg")) || bytes.Contains(pixels, []byte("M22 ")) || bytes.Contains(pixels, []byte("77777")) || bytes.Contains(challenge.PublicPayload, []byte(`"answer"`)) {
		t.Fatal("public payload exposed plaintext or the previous deterministic SVG path grid")
	}
	if err := provider.Verify(t.Context(), challenge.ID, "11111"); !errors.Is(err, riskdefense.ErrInvalidProof) {
		t.Fatalf("wrong proof error=%v", err)
	}
	if err := provider.Verify(t.Context(), challenge.ID, "７ ７ ７ ７ ７"); err != nil {
		t.Fatalf("normalized proof error=%v", err)
	}
	if err := provider.Verify(t.Context(), challenge.ID, "77777"); !errors.Is(err, riskdefense.ErrInvalidProof) {
		t.Fatalf("replayed proof error=%v", err)
	}
}

func TestFirstPartyImageCaptchaRasterChangesForSameAnswer(t *testing.T) {
	challengePayload := func(imageByte byte) []byte {
		randomness := append([]byte{}, bytes.Repeat([]byte{7}, firstPartyDigitCount)...)
		randomness = append(randomness, bytes.Repeat([]byte{1}, 32)...)
		randomness = append(randomness, bytes.Repeat([]byte{imageByte}, 96)...)
		provider, err := NewFirstPartyImage(FirstPartyImageConfig{
			Store: &memoryFirstPartyImageStore{}, TTL: time.Minute, Random: bytes.NewReader(randomness),
		})
		if err != nil {
			t.Fatal(err)
		}
		challenge, err := provider.Begin(t.Context(), riskdefense.OperationRegistration)
		if err != nil {
			t.Fatal(err)
		}
		return challenge.PublicPayload
	}
	first := challengePayload(2)
	second := challengePayload(3)
	if bytes.Equal(first, second) {
		t.Fatal("same answer produced identical raster geometry")
	}
}

func TestRecaptchaRejectsNonFiniteMinimumScore(t *testing.T) {
	for _, score := range []float64{math.NaN(), math.Inf(1), math.Inf(-1)} {
		_, err := NewRecaptcha(RecaptchaConfig{
			SiteKey: "site", SecretKey: "secret", Hostname: "auth.moonstone.org.cn", MinScore: score,
		})
		if err == nil {
			t.Fatalf("minimum score %v accepted", score)
		}
	}
}

func TestTurnstileUsesFixedEndpointAndVerifiesHostnameActionAndCData(t *testing.T) {
	var requestedURL, secret, response, idempotencyKey string
	client := testHTTPClient(func(request *http.Request) (*http.Response, error) {
		requestedURL = request.URL.String()
		if err := request.ParseForm(); err != nil {
			t.Fatal(err)
		}
		secret = request.Form.Get("secret")
		response = request.Form.Get("response")
		idempotencyKey = request.Form.Get("idempotency_key")
		return jsonResponse(http.StatusOK, `{
			"success":true,
			"challenge_ts":"2026-08-26T01:02:02Z",
			"hostname":"auth.moonstone.org.cn",
			"error-codes":[],
			"action":"united_pass_register",
			"cdata":"`+base64Token(24, 7)+`"
		}`), nil
	})
	provider, err := NewTurnstile(TurnstileConfig{
		SiteKey: "site-key", SecretKey: "secret-key", Hostname: "AUTH.MOONSTONE.ORG.CN.",
		Client: client, Now: func() time.Time { return providerTestNow }, Random: bytes.NewReader(bytes.Repeat([]byte{7}, 64)),
	})
	if err != nil {
		t.Fatal(err)
	}
	if provider.Available(t.Context(), riskdefense.ProviderRegionMainlandChina) {
		t.Fatal("Turnstile must be excluded from the Mainland China provider pool")
	}
	if !provider.Available(t.Context(), riskdefense.ProviderRegionGlobal) {
		t.Fatal("Turnstile must be available in the global provider pool")
	}
	challenge, err := provider.Begin(t.Context(), riskdefense.OperationRegistration)
	if err != nil {
		t.Fatal(err)
	}
	if challenge.Provider != TurnstileProviderName || !strings.Contains(string(challenge.PublicPayload), `"siteKey":"site-key"`) {
		t.Fatalf("challenge=%#v", challenge)
	}
	if err := provider.Verify(t.Context(), challenge.ID, "opaque-turnstile-proof"); err != nil {
		t.Fatal(err)
	}
	if requestedURL != turnstileSiteverifyURL || secret != "secret-key" || response != "opaque-turnstile-proof" || !validUUID(idempotencyKey) {
		t.Fatalf("url=%q secret=%q response=%q idempotency=%q", requestedURL, secret, response, idempotencyKey)
	}
}

func TestTurnstileRejectsAProviderSuccessWithMismatchedBindings(t *testing.T) {
	provider := mustTurnstile(t, testHTTPClient(func(*http.Request) (*http.Response, error) {
		return jsonResponse(http.StatusOK, `{
			"success":true,
			"challenge_ts":"2026-08-26T01:02:02Z",
			"hostname":"evil.example",
			"error-codes":[],
			"action":"united_pass_login",
			"cdata":"wrong"
		}`), nil
	}))
	challenge, err := provider.Begin(t.Context(), riskdefense.OperationLogin)
	if err != nil {
		t.Fatal(err)
	}
	if err := provider.Verify(t.Context(), challenge.ID, "proof"); !errors.Is(err, riskdefense.ErrInvalidProof) {
		t.Fatalf("Verify error=%v", err)
	}
}

func TestTurnstileMarksConfigurationAndTransportFailuresUnavailable(t *testing.T) {
	provider := mustTurnstile(t, testHTTPClient(func(*http.Request) (*http.Response, error) {
		return jsonResponse(http.StatusOK, `{"success":false,"error-codes":["invalid-input-secret"]}`), nil
	}))
	challenge, err := provider.Begin(t.Context(), riskdefense.OperationLogin)
	if err != nil {
		t.Fatal(err)
	}
	if err := provider.Verify(t.Context(), challenge.ID, "proof"); !errors.Is(err, riskdefense.ErrUnavailable) {
		t.Fatalf("Verify error=%v", err)
	}
	if provider.Available(t.Context(), riskdefense.ProviderRegionGlobal) {
		t.Fatal("misconfigured provider remained healthy")
	}
}

func TestMalformedProofCannotOpenTheProviderCircuit(t *testing.T) {
	provider := mustTurnstile(t, testHTTPClient(func(*http.Request) (*http.Response, error) {
		return jsonResponse(http.StatusOK, `{"success":false,"error-codes":["bad-request"]}`), nil
	}))
	challenge, err := provider.Begin(t.Context(), riskdefense.OperationLogin)
	if err != nil {
		t.Fatal(err)
	}
	if err := provider.Verify(t.Context(), challenge.ID, "malformed-proof"); !errors.Is(err, riskdefense.ErrInvalidProof) {
		t.Fatalf("Verify error=%v", err)
	}
	if !provider.Available(t.Context(), riskdefense.ProviderRegionGlobal) {
		t.Fatal("attacker-controlled bad-request response opened the provider circuit")
	}
}

func TestProviderInternalErrorIsTemporaryWithoutOpeningTheGlobalCircuit(t *testing.T) {
	provider := mustTurnstile(t, testHTTPClient(func(*http.Request) (*http.Response, error) {
		return jsonResponse(http.StatusOK, `{"success":false,"error-codes":["internal-error"]}`), nil
	}))
	challenge, err := provider.Begin(t.Context(), riskdefense.OperationLogin)
	if err != nil {
		t.Fatal(err)
	}
	if err := provider.Verify(t.Context(), challenge.ID, "proof"); !errors.Is(err, riskdefense.ErrUnavailable) {
		t.Fatalf("Verify error=%v", err)
	}
	if !provider.Available(t.Context(), riskdefense.ProviderRegionGlobal) {
		t.Fatal("proof-path internal-error opened the global provider circuit")
	}
}

func TestRecaptchaUsesRecaptchaNetAndEnforcesScoreActionHostnameAndTimestamp(t *testing.T) {
	var requestedURL, secret, response string
	var issuedAction string
	provider, err := NewRecaptcha(RecaptchaConfig{
		SiteKey: "recaptcha-site", SecretKey: "recaptcha-secret", Hostname: "auth.moonstone.org.cn", MinScore: 0.7,
		Now: func() time.Time { return providerTestNow }, Random: bytes.NewReader(bytes.Repeat([]byte{9}, 32)),
		Client: testHTTPClient(func(request *http.Request) (*http.Response, error) {
			requestedURL = request.URL.String()
			if err := request.ParseForm(); err != nil {
				t.Fatal(err)
			}
			secret, response = request.Form.Get("secret"), request.Form.Get("response")
			return jsonResponse(http.StatusOK, fmt.Sprintf(`{
				"success":true,
				"score":0.91,
				"action":%q,
				"challenge_ts":"2026-08-26T01:02:02Z",
				"hostname":"auth.moonstone.org.cn",
				"error-codes":[]
			}`, issuedAction)), nil
		}),
	})
	if err != nil {
		t.Fatal(err)
	}
	if !provider.Available(t.Context(), riskdefense.ProviderRegionMainlandChina) || !provider.Available(t.Context(), riskdefense.ProviderRegionGlobal) {
		t.Fatal("recaptcha.net fallback must be available in both regional pools")
	}
	challenge, err := provider.Begin(t.Context(), riskdefense.OperationLogin)
	if err != nil {
		t.Fatal(err)
	}
	issuedAction = publicAction(t, challenge.PublicPayload)
	if challenge.Provider != RecaptchaProviderName || !strings.HasPrefix(issuedAction, "united_pass_login_") {
		t.Fatalf("challenge=%#v", challenge)
	}
	if err := provider.Verify(t.Context(), challenge.ID, "recaptcha-proof"); err != nil {
		t.Fatal(err)
	}
	if requestedURL != recaptchaSiteverifyURL || secret != "recaptcha-secret" || response != "recaptcha-proof" {
		t.Fatalf("url=%q secret=%q response=%q", requestedURL, secret, response)
	}
}

func TestRecaptchaProofIsBoundToOneChallengeAction(t *testing.T) {
	var firstAction string
	provider, err := NewRecaptcha(RecaptchaConfig{
		SiteKey: "site", SecretKey: "secret", Hostname: "auth.moonstone.org.cn", MinScore: 0.7,
		Now:    func() time.Time { return providerTestNow },
		Random: bytes.NewReader(append(bytes.Repeat([]byte{1}, 5), bytes.Repeat([]byte{2}, 5)...)),
		Client: testHTTPClient(func(*http.Request) (*http.Response, error) {
			return jsonResponse(http.StatusOK, fmt.Sprintf(`{
				"success":true,"score":0.91,"action":%q,
				"challenge_ts":"2026-08-26T01:02:02Z",
				"hostname":"auth.moonstone.org.cn","error-codes":[]
			}`, firstAction)), nil
		}),
	})
	if err != nil {
		t.Fatal(err)
	}
	first, err := provider.Begin(t.Context(), riskdefense.OperationRegistration)
	if err != nil {
		t.Fatal(err)
	}
	second, err := provider.Begin(t.Context(), riskdefense.OperationRegistration)
	if err != nil {
		t.Fatal(err)
	}
	firstAction = publicAction(t, first.PublicPayload)
	if firstAction == publicAction(t, second.PublicPayload) {
		t.Fatal("two challenges received the same reCAPTCHA action")
	}
	if err := provider.Verify(t.Context(), first.ID, "proof-for-first"); err != nil {
		t.Fatalf("first challenge Verify error=%v", err)
	}
	if err := provider.Verify(t.Context(), second.ID, "proof-for-first"); !errors.Is(err, riskdefense.ErrInvalidProof) {
		t.Fatalf("cross-challenge Verify error=%v", err)
	}
}

func TestRecaptchaFailsClosedOnLowScoreOrQuotaWarning(t *testing.T) {
	cases := []struct {
		name       string
		score      float64
		errorCodes string
	}{
		{name: "low score", score: 0.2, errorCodes: `[]`},
		{name: "quota warning", score: 0.9, errorCodes: `["Over free quota."]`},
	}
	for _, testCase := range cases {
		testCase := testCase
		t.Run(testCase.name, func(t *testing.T) {
			var issuedAction string
			provider, err := NewRecaptcha(RecaptchaConfig{
				SiteKey: "site", SecretKey: "secret", Hostname: "auth.moonstone.org.cn", MinScore: 0.7,
				Now: func() time.Time { return providerTestNow }, Random: bytes.NewReader(bytes.Repeat([]byte{4}, 32)),
				Client: testHTTPClient(func(*http.Request) (*http.Response, error) {
					body := fmt.Sprintf(`{"success":true,"score":%v,"action":%q,"challenge_ts":"2026-08-26T01:02:02Z","hostname":"auth.moonstone.org.cn","error-codes":%s}`,
						testCase.score, issuedAction, testCase.errorCodes)
					return jsonResponse(http.StatusOK, body), nil
				}),
			})
			if err != nil {
				t.Fatal(err)
			}
			challenge, err := provider.Begin(t.Context(), riskdefense.OperationRegistration)
			if err != nil {
				t.Fatal(err)
			}
			issuedAction = publicAction(t, challenge.PublicPayload)
			if err := provider.Verify(t.Context(), challenge.ID, "proof"); !errors.Is(err, riskdefense.ErrInvalidProof) {
				t.Fatalf("Verify error=%v", err)
			}
		})
	}
}

func TestProviderResponseBodyIsBounded(t *testing.T) {
	provider := mustTurnstile(t, testHTTPClient(func(*http.Request) (*http.Response, error) {
		return jsonResponse(http.StatusOK, strings.Repeat("x", maxProviderResponseBytes+1)), nil
	}))
	challenge, err := provider.Begin(t.Context(), riskdefense.OperationLogin)
	if err != nil {
		t.Fatal(err)
	}
	if err := provider.Verify(t.Context(), challenge.ID, "proof"); !errors.Is(err, riskdefense.ErrUnavailable) {
		t.Fatalf("Verify error=%v", err)
	}
}

func mustTurnstile(t *testing.T, client *http.Client) *Turnstile {
	t.Helper()
	provider, err := NewTurnstile(TurnstileConfig{
		SiteKey: "site", SecretKey: "secret", Hostname: "auth.moonstone.org.cn", Client: client,
		Now: func() time.Time { return providerTestNow }, Random: bytes.NewReader(bytes.Repeat([]byte{7}, 64)),
	})
	if err != nil {
		t.Fatal(err)
	}
	return provider
}

type roundTripFunc func(*http.Request) (*http.Response, error)

func (fn roundTripFunc) RoundTrip(request *http.Request) (*http.Response, error) { return fn(request) }

func testHTTPClient(roundTrip roundTripFunc) *http.Client {
	return &http.Client{Transport: roundTrip}
}

func jsonResponse(status int, body string) *http.Response {
	return &http.Response{
		StatusCode: status,
		Header:     http.Header{"Content-Type": {"application/json"}},
		Body:       io.NopCloser(strings.NewReader(body)),
	}
}

func base64Token(size, value int) string {
	return base64.RawURLEncoding.EncodeToString(bytes.Repeat([]byte{byte(value)}, size))
}

func publicAction(t *testing.T, payload json.RawMessage) string {
	t.Helper()
	var value struct {
		Action string `json:"action"`
	}
	if err := json.Unmarshal(payload, &value); err != nil {
		t.Fatal(err)
	}
	return value.Action
}
