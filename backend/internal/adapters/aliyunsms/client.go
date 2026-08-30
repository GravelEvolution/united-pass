//
// Copyright (c) 2026 Chen Jiajie(Ariakage)
//
// Author: Chen Jiajie(Ariakage) <ariakage233@gmail.com>
// Date: 2026-08-20
// Description: Aliyun SMS client (SendSms via dysmsapi, V1 HMAC-SHA1 signature)
//

package aliyunsms

import (
	"context"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha1"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"sort"
	"strings"
	"time"
)

const (
	officialEndpoint = "https://dysmsapi.aliyuncs.com/"
	requestTimeout   = 10 * time.Second
)

// Config holds the Aliyun SMS account and template settings.
type Config struct {
	AccessKeyID     string
	AccessKeySecret string
	SignName        string
	TemplateCode    string
	Endpoint        string
}

// Client sends SMS verification codes through Aliyun SendSms.
type Client struct {
	cfg        Config
	httpClient *http.Client
}

// NewClient builds the Aliyun SMS client. Runtime clients are pinned to the
// official Aliyun HTTPS endpoint. A caller-supplied HTTP client permits an
// IP-loopback endpoint solely as a deterministic test seam.
func NewClient(cfg Config, httpClient *http.Client) (*Client, error) {
	required := []struct {
		name  string
		value string
	}{
		{"access key id", cfg.AccessKeyID},
		{"access key secret", cfg.AccessKeySecret},
		{"sign name", cfg.SignName},
		{"template code", cfg.TemplateCode},
	}
	for _, field := range required {
		if field.value == "" || field.value != strings.TrimSpace(field.value) {
			return nil, fmt.Errorf("aliyunsms: %s is required and must be trimmed", field.name)
		}
	}
	if cfg.Endpoint == "" {
		cfg.Endpoint = officialEndpoint
	}
	endpoint, err := parseEndpoint(cfg.Endpoint, httpClient != nil)
	if err != nil {
		return nil, err
	}
	if httpClient == nil {
		httpClient = &http.Client{Timeout: requestTimeout}
	} else {
		// Never mutate a caller-owned client. Tests may supply an httptest
		// transport, but they cannot weaken redirect or timeout handling.
		copy := *httpClient
		if copy.Timeout <= 0 || copy.Timeout > requestTimeout {
			copy.Timeout = requestTimeout
		}
		httpClient = &copy
	}
	httpClient.CheckRedirect = rejectRedirect
	httpClient.Jar = nil
	cfg.Endpoint = endpoint.String()
	return &Client{cfg: cfg, httpClient: httpClient}, nil
}

func parseEndpoint(raw string, allowLoopback bool) (*url.URL, error) {
	if raw == "" || raw != strings.TrimSpace(raw) {
		return nil, errors.New("aliyunsms: endpoint must be non-empty and trimmed")
	}
	endpoint, err := url.Parse(raw)
	if err != nil || strings.Contains(raw, "#") || endpoint.Scheme == "" || endpoint.Host == "" || endpoint.Opaque != "" || endpoint.User != nil || endpoint.RawQuery != "" || endpoint.ForceQuery || endpoint.Fragment != "" || endpoint.RawPath != "" || (endpoint.Path != "" && endpoint.Path != "/") {
		return nil, errors.New("aliyunsms: endpoint must be an origin without userinfo, path, query, or fragment")
	}

	hostname := endpoint.Hostname()
	officialHost := strings.EqualFold(endpoint.Host, "dysmsapi.aliyuncs.com") || strings.EqualFold(endpoint.Host, "dysmsapi.aliyuncs.com:443")
	if endpoint.Scheme == "https" && officialHost {
		return endpoint, nil
	}
	if allowLoopback && (endpoint.Scheme == "http" || endpoint.Scheme == "https") {
		if address := net.ParseIP(hostname); address != nil && address.IsLoopback() {
			return endpoint, nil
		}
	}
	return nil, errors.New("aliyunsms: endpoint must use the official Aliyun HTTPS origin")
}

func rejectRedirect(*http.Request, []*http.Request) error {
	return http.ErrUseLastResponse
}

// SendCode sends an SMS with the verification code to the given phone.
func (c *Client) SendCode(ctx context.Context, phone, code string) error {
	nonce := make([]byte, 16)
	if _, err := rand.Read(nonce); err != nil {
		return fmt.Errorf("aliyunsms: generate nonce: %w", err)
	}
	params := map[string]string{
		"AccessKeyId":      c.cfg.AccessKeyID,
		"Action":           "SendSms",
		"Format":           "JSON",
		"PhoneNumbers":     phone,
		"SignName":         c.cfg.SignName,
		"SignatureMethod":  "HMAC-SHA1",
		"SignatureNonce":   hex.EncodeToString(nonce),
		"SignatureVersion": "1.0",
		"TemplateCode":     c.cfg.TemplateCode,
		"TemplateParam":    fmt.Sprintf(`{"code":%q}`, code),
		"Timestamp":        time.Now().UTC().Format("2006-01-02T15:04:05Z"),
		"Version":          "2017-05-25",
	}
	params["Signature"] = signV1(c.cfg.AccessKeySecret, "POST", "/", params)

	form := url.Values{}
	for k, v := range params {
		form.Set(k, v)
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, c.cfg.Endpoint, strings.NewReader(form.Encode()))
	if err != nil {
		return fmt.Errorf("aliyunsms: build request: %w", err)
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")

	resp, err := c.httpClient.Do(req)
	if err != nil {
		return fmt.Errorf("aliyunsms: send request: %w", err)
	}
	defer resp.Body.Close()
	body, err := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	if err != nil {
		return fmt.Errorf("aliyunsms: read response: %w", err)
	}
	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("aliyunsms: http %d: %s", resp.StatusCode, strings.TrimSpace(string(body)))
	}
	var result struct {
		Code      string `json:"Code"`
		Message   string `json:"Message"`
		RequestID string `json:"RequestId"`
	}
	if err := json.Unmarshal(body, &result); err != nil {
		return fmt.Errorf("aliyunsms: decode response: %w", err)
	}
	if result.Code != "OK" {
		return fmt.Errorf("aliyunsms: %s: %s", result.Code, result.Message)
	}
	return nil
}

// signV1 builds the Aliyun V1 signature for the given parameters.
func signV1(secret, method, path string, params map[string]string) string {
	keys := make([]string, 0, len(params))
	for k := range params {
		if k == "Signature" {
			continue
		}
		keys = append(keys, k)
	}
	sort.Strings(keys)

	var canonical strings.Builder
	for _, k := range keys {
		canonical.WriteString(percentEncode(k))
		canonical.WriteByte('=')
		canonical.WriteString(percentEncode(params[k]))
		canonical.WriteByte('&')
	}
	query := strings.TrimSuffix(canonical.String(), "&")
	stringToSign := method + "&" + percentEncode(path) + "&" + percentEncode(query)

	mac := hmac.New(sha1.New, []byte(secret+"&"))
	mac.Write([]byte(stringToSign))
	return base64.StdEncoding.EncodeToString(mac.Sum(nil))
}

// percentEncode implements the RFC 3986 encoding Aliyun requires.
func percentEncode(s string) string {
	escaped := url.QueryEscape(s)
	escaped = strings.ReplaceAll(escaped, "+", "%20")
	escaped = strings.ReplaceAll(escaped, "*", "%2A")
	escaped = strings.ReplaceAll(escaped, "%7E", "~")
	return escaped
}
