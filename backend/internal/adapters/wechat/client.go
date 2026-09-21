// Package wechat implements the server-side WeChat Mini Program proof
// exchange. It never persists or logs app secrets, codes, session keys,
// access tokens, open IDs, union IDs or phone numbers.
package wechat

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/GravelEvolution/united-pass/backend/internal/phoneverify"
	wechatdomain "github.com/GravelEvolution/united-pass/backend/internal/wechat"
)

const (
	maxProviderResponseBytes = 1 << 20
	providerAPIHostname      = "api.weixin.qq.com"
)

// Config is server-only configuration. AppSecret must come from an ignored
// local environment file or deployment secret store, never source control.
type Config struct {
	AppID          string
	AppSecret      string
	APIBaseURL     string
	RequestTimeout time.Duration
}

// Client verifies Mini Program codes with the WeChat platform. httpClient is
// injectable only for deterministic tests.
type Client struct {
	appID     string
	appSecret string
	baseURL   *url.URL
	http      *http.Client
}

func NewClient(cfg Config, httpClient *http.Client) (*Client, error) {
	if strings.TrimSpace(cfg.AppID) == "" || strings.TrimSpace(cfg.AppSecret) == "" {
		return nil, errors.New("wechat: app id and secret are required")
	}
	// A caller-supplied client is a test seam. Production bootstrap always
	// passes nil, which keeps provider credentials pinned to WeChat's official
	// endpoint and prevents configuration from redirecting them to loopback.
	base, err := parseBaseURL(cfg.APIBaseURL, httpClient != nil)
	if err != nil {
		return nil, err
	}
	if cfg.RequestTimeout <= 0 {
		return nil, errors.New("wechat: request timeout must be positive")
	}
	if httpClient == nil {
		httpClient = &http.Client{
			Timeout:       cfg.RequestTimeout,
			CheckRedirect: rejectProviderRedirect,
		}
	} else {
		// Do not mutate a caller-owned client (notably httptest.Client), but
		// ensure the adapter itself always has a bounded provider request and
		// cannot follow a redirect carrying a secret, code or access token.
		copy := *httpClient
		if copy.Timeout <= 0 || copy.Timeout > cfg.RequestTimeout {
			copy.Timeout = cfg.RequestTimeout
		}
		copy.CheckRedirect = rejectProviderRedirect
		httpClient = &copy
	}
	return &Client{appID: cfg.AppID, appSecret: cfg.AppSecret, baseURL: base, http: httpClient}, nil
}

func (c *Client) VerifyLogin(ctx context.Context, loginCode string) (wechatdomain.IdentityProof, error) {
	if err := wechatdomain.ValidateCode(loginCode); err != nil {
		return wechatdomain.IdentityProof{}, err
	}
	identity, err := c.exchangeLoginCode(ctx, loginCode)
	if err != nil {
		return wechatdomain.IdentityProof{}, err
	}
	subject, err := wechatdomain.Subject(identity.UnionID, identity.OpenID)
	if err != nil {
		return wechatdomain.IdentityProof{}, err
	}
	return wechatdomain.IdentityProof{TenantID: c.appID, Subject: subject}, nil
}

func (c *Client) VerifyRegistration(ctx context.Context, loginCode, phoneCode string) (wechatdomain.IdentityProof, error) {
	if err := wechatdomain.ValidateCode(loginCode); err != nil {
		return wechatdomain.IdentityProof{}, err
	}
	if err := wechatdomain.ValidateCode(phoneCode); err != nil {
		return wechatdomain.IdentityProof{}, err
	}
	identity, err := c.exchangeLoginCode(ctx, loginCode)
	if err != nil {
		return wechatdomain.IdentityProof{}, err
	}
	accessToken, err := c.accessToken(ctx)
	if err != nil {
		return wechatdomain.IdentityProof{}, err
	}
	phone, err := c.exchangePhoneCode(ctx, accessToken, phoneCode)
	if err != nil {
		return wechatdomain.IdentityProof{}, err
	}
	subject, err := wechatdomain.Subject(identity.UnionID, identity.OpenID)
	if err != nil {
		return wechatdomain.IdentityProof{}, err
	}
	return wechatdomain.IdentityProof{TenantID: c.appID, Subject: subject, Phone: phone}, nil
}

// VerifyOnboarding requires both the wx.login identity proof and a fresh
// getPhoneNumber proof. Provider rejection or unavailability fails closed;
// onboarding must never downgrade to an identity-only account or session.
func (c *Client) VerifyOnboarding(ctx context.Context, loginCode, phoneCode string) (wechatdomain.IdentityProof, error) {
	if err := wechatdomain.ValidateCode(loginCode); err != nil {
		return wechatdomain.IdentityProof{}, err
	}
	if err := wechatdomain.ValidateCode(phoneCode); err != nil {
		return wechatdomain.IdentityProof{}, errors.Join(wechatdomain.ErrPhoneRequired, err)
	}
	identity, err := c.exchangeLoginCode(ctx, loginCode)
	if err != nil {
		return wechatdomain.IdentityProof{}, err
	}
	accessToken, err := c.accessToken(ctx)
	if err != nil {
		return wechatdomain.IdentityProof{}, err
	}
	phone, err := c.exchangePhoneCode(ctx, accessToken, phoneCode)
	if err != nil {
		if errors.Is(err, wechatdomain.ErrRejected) || errors.Is(err, wechatdomain.ErrInvalidCode) {
			return wechatdomain.IdentityProof{}, errors.Join(wechatdomain.ErrPhoneRequired, err)
		}
		return wechatdomain.IdentityProof{}, err
	}
	subject, err := wechatdomain.Subject(identity.UnionID, identity.OpenID)
	if err != nil {
		return wechatdomain.IdentityProof{}, err
	}
	return wechatdomain.IdentityProof{TenantID: c.appID, Subject: subject, Phone: phone}, nil
}

type loginExchangeResponse struct {
	OpenID     string `json:"openid"`
	UnionID    string `json:"unionid"`
	SessionKey string `json:"session_key"`
	ErrorCode  int    `json:"errcode"`
}

func (c *Client) exchangeLoginCode(ctx context.Context, code string) (loginExchangeResponse, error) {
	query := url.Values{"appid": {c.appID}, "secret": {c.appSecret}, "js_code": {code}, "grant_type": {"authorization_code"}}
	var response loginExchangeResponse
	if err := c.getJSON(ctx, "/sns/jscode2session", query, &response); err != nil {
		return loginExchangeResponse{}, err
	}
	if response.ErrorCode != 0 || response.OpenID == "" || response.SessionKey == "" {
		return loginExchangeResponse{}, wechatdomain.ErrRejected
	}
	return response, nil
}

type accessTokenResponse struct {
	AccessToken string `json:"access_token"`
	ErrorCode   int    `json:"errcode"`
}

func (c *Client) accessToken(ctx context.Context) (string, error) {
	query := url.Values{"grant_type": {"client_credential"}, "appid": {c.appID}, "secret": {c.appSecret}}
	var response accessTokenResponse
	if err := c.getJSON(ctx, "/cgi-bin/token", query, &response); err != nil {
		return "", err
	}
	if response.ErrorCode != 0 || response.AccessToken == "" {
		return "", wechatdomain.ErrUnavailable
	}
	return response.AccessToken, nil
}

type phoneResponse struct {
	PhoneInfo struct {
		PhoneNumber string `json:"phoneNumber"`
	} `json:"phone_info"`
	ErrorCode int `json:"errcode"`
}

func (c *Client) exchangePhoneCode(ctx context.Context, accessToken, code string) (string, error) {
	body, err := json.Marshal(struct {
		Code string `json:"code"`
	}{Code: code})
	if err != nil {
		return "", wechatdomain.ErrUnavailable
	}
	endpoint := c.endpoint("/wxa/business/getuserphonenumber")
	query := endpoint.Query()
	query.Set("access_token", accessToken)
	endpoint.RawQuery = query.Encode()
	request, err := http.NewRequestWithContext(ctx, http.MethodPost, endpoint.String(), bytes.NewReader(body))
	if err != nil {
		return "", wechatdomain.ErrUnavailable
	}
	request.Header.Set("Content-Type", "application/json")
	var response phoneResponse
	if err := c.doJSON(request, &response); err != nil {
		return "", err
	}
	if response.ErrorCode != 0 {
		return "", wechatdomain.ErrRejected
	}
	phone, err := phoneverify.NormalizePhone(response.PhoneInfo.PhoneNumber)
	if err != nil {
		return "", wechatdomain.ErrRejected
	}
	return phone, nil
}

func (c *Client) getJSON(ctx context.Context, path string, query url.Values, target any) error {
	endpoint := c.endpoint(path)
	endpoint.RawQuery = query.Encode()
	request, err := http.NewRequestWithContext(ctx, http.MethodGet, endpoint.String(), nil)
	if err != nil {
		return wechatdomain.ErrUnavailable
	}
	return c.doJSON(request, target)
}

func (c *Client) doJSON(request *http.Request, target any) error {
	response, err := c.http.Do(request)
	if err != nil {
		return wechatdomain.ErrUnavailable
	}
	defer response.Body.Close()
	if response.StatusCode < http.StatusOK || response.StatusCode >= http.StatusMultipleChoices {
		return wechatdomain.ErrUnavailable
	}
	if response.ContentLength > maxProviderResponseBytes {
		return wechatdomain.ErrUnavailable
	}
	payload, err := io.ReadAll(io.LimitReader(response.Body, maxProviderResponseBytes+1))
	if err != nil || len(payload) > maxProviderResponseBytes {
		return wechatdomain.ErrUnavailable
	}
	decoder := json.NewDecoder(bytes.NewReader(payload))
	if err := decoder.Decode(target); err != nil {
		return wechatdomain.ErrUnavailable
	}
	if err := decoder.Decode(&struct{}{}); !errors.Is(err, io.EOF) {
		return wechatdomain.ErrUnavailable
	}
	return nil
}

func rejectProviderRedirect(_ *http.Request, _ []*http.Request) error {
	return http.ErrUseLastResponse
}

func (c *Client) endpoint(path string) *url.URL {
	endpoint := *c.baseURL
	endpoint.Path = strings.TrimRight(endpoint.Path, "/") + path
	endpoint.RawPath = ""
	return &endpoint
}

func parseBaseURL(raw string, allowLoopback bool) (*url.URL, error) {
	base, err := url.Parse(strings.TrimSpace(raw))
	if err != nil || base.Host == "" || base.User != nil || base.RawQuery != "" || base.ForceQuery || base.Fragment != "" || (base.Path != "" && base.Path != "/") {
		return nil, errors.New("wechat: invalid API base URL")
	}
	hostname := base.Hostname()
	if allowLoopback {
		if ip := net.ParseIP(hostname); ip != nil && ip.IsLoopback() && (base.Scheme == "http" || base.Scheme == "https") {
			return base, nil
		}
	}
	if base.Scheme == "https" && strings.EqualFold(hostname, providerAPIHostname) && (base.Port() == "" || base.Port() == "443") {
		return base, nil
	}
	return nil, fmt.Errorf("wechat: API base URL must use the official HTTPS endpoint")
}

var _ wechatdomain.Verifier = (*Client)(nil)
var _ wechatdomain.OnboardingVerifier = (*Client)(nil)
