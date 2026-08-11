//
// Copyright (c) 2026 Chen Jiajie(Ariakage)
//
// Author: Chen Jiajie(Ariakage) <ariakage233@gmail.com>
// Date: 2026-08-11
// Description: Feishu OAuth v2 and Contact v3 Provider adapter
//

// Package feishu is the outer adapter for Feishu OAuth login and Contact v3
// directory reads. Tokens are kept only in local memory, never rendered,
// logged or persisted.
package feishu

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/GravelEvolution/united-pass/backend/internal/config"
	"github.com/GravelEvolution/united-pass/backend/internal/providers"
)

const (
	maxResponseBytes = 2 << 20
	maxPages         = 500
	maxPartialErrors = 50
)

type Client struct {
	config     config.FeishuConfig
	httpClient *http.Client
	mu         sync.Mutex
	token      string
	tokenUntil time.Time
}

func NewClient(cfg config.FeishuConfig) (*Client, error) {
	if !cfg.Configured() {
		return nil, providers.ErrNotConfigured
	}
	if _, err := url.Parse(cfg.BaseURL); err != nil {
		return nil, fmt.Errorf("feishu: base URL: %w", err)
	}
	if _, err := url.Parse(cfg.AuthorizeURL); err != nil {
		return nil, fmt.Errorf("feishu: authorize URL: %w", err)
	}
	return &Client{config: cfg, httpClient: &http.Client{Timeout: cfg.RequestTimeout}}, nil
}

func (c *Client) Validate(ctx context.Context) error {
	_, err := c.tenantAccessToken(ctx, true)
	return err
}

func (c *Client) AuthorizationURL(state string) (string, error) {
	if state == "" || len(state) > 512 {
		return "", providers.ErrInvalidInput
	}
	u, err := url.Parse(c.config.AuthorizeURL)
	if err != nil {
		return "", fmt.Errorf("feishu: parse authorize URL: %w", err)
	}
	query := u.Query()
	query.Set("client_id", c.config.AppID)
	query.Set("redirect_uri", c.config.RedirectURL)
	query.Set("response_type", "code")
	query.Set("state", state)
	u.RawQuery = query.Encode()
	return u.String(), nil
}

func (c *Client) ExchangeCode(ctx context.Context, code string) (providers.OAuthUserInfo, error) {
	if code == "" || len(code) > 2048 {
		return providers.OAuthUserInfo{}, providers.ErrInvalidInput
	}
	payload := map[string]string{
		"grant_type": "authorization_code", "client_id": c.config.AppID,
		"client_secret": c.config.AppSecret, "code": code,
		"redirect_uri": c.config.RedirectURL,
	}
	var tokenResponse struct {
		Code        int    `json:"code"`
		AccessToken string `json:"access_token"`
	}
	if err := c.postJSON(ctx, "/open-apis/authen/v2/oauth/token", payload, "", &tokenResponse); err != nil {
		return providers.OAuthUserInfo{}, err
	}
	if tokenResponse.Code != 0 || tokenResponse.AccessToken == "" {
		return providers.OAuthUserInfo{}, providerError("oauth_token", tokenResponse.Code)
	}
	var infoResponse struct {
		Code int `json:"code"`
		Data struct {
			OpenID    string `json:"open_id"`
			UnionID   string `json:"union_id"`
			TenantKey string `json:"tenant_key"`
			Name      string `json:"name"`
			Email     string `json:"email"`
		} `json:"data"`
	}
	if err := c.getJSON(ctx, "/open-apis/authen/v1/user_info", nil, tokenResponse.AccessToken, &infoResponse); err != nil {
		return providers.OAuthUserInfo{}, err
	}
	if infoResponse.Code != 0 || infoResponse.Data.OpenID == "" || infoResponse.Data.TenantKey == "" {
		return providers.OAuthUserInfo{}, providerError("user_info", infoResponse.Code)
	}
	return providers.OAuthUserInfo{
		Subject: infoResponse.Data.OpenID, UnionID: infoResponse.Data.UnionID,
		TenantID: infoResponse.Data.TenantKey, Name: infoResponse.Data.Name,
		Email: infoResponse.Data.Email,
	}, nil
}

func (c *Client) FetchDirectory(ctx context.Context) (providers.DirectorySnapshot, error) {
	token, err := c.tenantAccessToken(ctx, false)
	if err != nil {
		return providers.DirectorySnapshot{}, err
	}
	departments, err := c.fetchDepartments(ctx, token)
	if err != nil {
		return providers.DirectorySnapshot{}, err
	}
	departmentIDs := make([]string, 0, len(departments)+1)
	departmentIDs = append(departmentIDs, "0")
	for _, department := range departments {
		departmentIDs = append(departmentIDs, department.ExternalID)
	}
	usersBySubject := make(map[string]providers.ExternalUser)
	partialErrors := 0
	for _, departmentID := range departmentIDs {
		users, err := c.fetchDepartmentUsers(ctx, token, departmentID)
		if err != nil {
			partialErrors++
			if partialErrors > maxPartialErrors {
				return providers.DirectorySnapshot{}, err
			}
			continue
		}
		for _, user := range users {
			existing, ok := usersBySubject[user.Subject]
			if ok {
				user.DepartmentIDs = mergeStrings(existing.DepartmentIDs, user.DepartmentIDs)
			}
			usersBySubject[user.Subject] = user
		}
	}
	users := make([]providers.ExternalUser, 0, len(usersBySubject))
	for _, user := range usersBySubject {
		users = append(users, user)
	}
	return providers.DirectorySnapshot{
		ProviderID: providers.FeishuProviderID, TenantID: c.config.TenantID,
		Departments: departments, Users: users, Partial: partialErrors > 0,
		FailureClass: map[bool]string{true: "provider", false: ""}[partialErrors > 0],
	}, nil
}

func (c *Client) tenantAccessToken(ctx context.Context, force bool) (string, error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if !force && c.token != "" && time.Now().UTC().Before(c.tokenUntil) {
		return c.token, nil
	}
	var response struct {
		Code   int    `json:"code"`
		Token  string `json:"tenant_access_token"`
		Expire int    `json:"expire"`
	}
	if err := c.postJSON(ctx, "/open-apis/auth/v3/tenant_access_token/internal",
		map[string]string{"app_id": c.config.AppID, "app_secret": c.config.AppSecret}, "", &response); err != nil {
		return "", err
	}
	if response.Code != 0 || response.Token == "" || response.Expire <= 0 {
		return "", providerError("tenant_token", response.Code)
	}
	ttl := time.Duration(response.Expire) * time.Second
	if ttl > time.Minute {
		ttl -= time.Minute
	}
	c.token, c.tokenUntil = response.Token, time.Now().UTC().Add(ttl)
	return c.token, nil
}

func (c *Client) fetchDepartments(ctx context.Context, token string) ([]providers.ExternalDepartment, error) {
	items := make([]providers.ExternalDepartment, 0)
	pageToken := ""
	seen := map[string]struct{}{}
	for page := 0; page < maxPages; page++ {
		query := url.Values{"department_id_type": {"open_department_id"}, "user_id_type": {"open_id"}, "fetch_child": {"true"}, "page_size": {"100"}}
		if pageToken != "" {
			query.Set("page_token", pageToken)
		}
		var response struct {
			Code int `json:"code"`
			Data struct {
				Items []struct {
					Name               string `json:"name"`
					OpenDepartmentID   string `json:"open_department_id"`
					ParentDepartmentID string `json:"parent_department_id"`
					LeaderUserID       string `json:"leader_user_id"`
				} `json:"items"`
				HasMore   bool   `json:"has_more"`
				PageToken string `json:"page_token"`
			} `json:"data"`
		}
		if err := c.getJSON(ctx, "/open-apis/contact/v3/departments/0/children", query, token, &response); err != nil {
			return nil, err
		}
		if response.Code != 0 {
			return nil, providerError("departments", response.Code)
		}
		for _, item := range response.Data.Items {
			if item.OpenDepartmentID == "" {
				return nil, providerError("departments_shape", 0)
			}
			if _, exists := seen[item.OpenDepartmentID]; exists {
				continue
			}
			seen[item.OpenDepartmentID] = struct{}{}
			items = append(items, providers.ExternalDepartment{ExternalID: item.OpenDepartmentID, ParentExternalID: item.ParentDepartmentID, Name: item.Name, LeaderSubject: item.LeaderUserID})
		}
		if !response.Data.HasMore {
			return items, nil
		}
		if response.Data.PageToken == "" || response.Data.PageToken == pageToken {
			return nil, providerError("departments_pagination", 0)
		}
		pageToken = response.Data.PageToken
	}
	return nil, providers.ErrDirectoryTooLarge
}

func (c *Client) fetchDepartmentUsers(ctx context.Context, token, departmentID string) ([]providers.ExternalUser, error) {
	items := make([]providers.ExternalUser, 0)
	pageToken := ""
	for page := 0; page < maxPages; page++ {
		query := url.Values{"department_id": {departmentID}, "department_id_type": {"open_department_id"}, "user_id_type": {"open_id"}, "page_size": {"50"}}
		if pageToken != "" {
			query.Set("page_token", pageToken)
		}
		var response struct {
			Code int `json:"code"`
			Data struct {
				Items []struct {
					OpenID        string   `json:"open_id"`
					UnionID       string   `json:"union_id"`
					UserID        string   `json:"user_id"`
					Name          string   `json:"name"`
					Email         string   `json:"email"`
					EmployeeNo    string   `json:"employee_no"`
					JobTitle      string   `json:"job_title"`
					DepartmentIDs []string `json:"department_ids"`
					Status        struct {
						IsExited   bool `json:"is_exited"`
						IsResigned bool `json:"is_resigned"`
					} `json:"status"`
				} `json:"items"`
				HasMore   bool   `json:"has_more"`
				PageToken string `json:"page_token"`
			} `json:"data"`
		}
		if err := c.getJSON(ctx, "/open-apis/contact/v3/users/find_by_department", query, token, &response); err != nil {
			return nil, err
		}
		if response.Code != 0 {
			return nil, providerError("department_users", response.Code)
		}
		for _, item := range response.Data.Items {
			if item.OpenID == "" {
				continue
			}
			items = append(items, providers.ExternalUser{Subject: item.OpenID, UnionID: item.UnionID, TenantUserID: item.UserID, Name: item.Name, Email: item.Email, EmployeeNumber: item.EmployeeNo, Title: item.JobTitle, DepartmentIDs: item.DepartmentIDs, Active: !item.Status.IsExited && !item.Status.IsResigned})
		}
		if !response.Data.HasMore {
			return items, nil
		}
		if response.Data.PageToken == "" || response.Data.PageToken == pageToken {
			return nil, providerError("users_pagination", 0)
		}
		pageToken = response.Data.PageToken
	}
	return nil, providers.ErrDirectoryTooLarge
}

func (c *Client) getJSON(ctx context.Context, path string, query url.Values, bearer string, destination any) error {
	return c.doJSON(ctx, func() (*http.Request, error) {
		u := strings.TrimRight(c.config.BaseURL, "/") + path
		if len(query) > 0 {
			u += "?" + query.Encode()
		}
		req, err := http.NewRequestWithContext(ctx, http.MethodGet, u, nil)
		if err == nil && bearer != "" {
			req.Header.Set("Authorization", "Bearer "+bearer)
		}
		return req, err
	}, destination)
}

func (c *Client) postJSON(ctx context.Context, path string, payload any, bearer string, destination any) error {
	body, err := json.Marshal(payload)
	if err != nil {
		return fmt.Errorf("feishu: encode request: %w", err)
	}
	return c.doJSON(ctx, func() (*http.Request, error) {
		req, err := http.NewRequestWithContext(ctx, http.MethodPost, strings.TrimRight(c.config.BaseURL, "/")+path, bytes.NewReader(body))
		if err == nil {
			req.Header.Set("Content-Type", "application/json; charset=utf-8")
			if bearer != "" {
				req.Header.Set("Authorization", "Bearer "+bearer)
			}
		}
		return req, err
	}, destination)
}

func (c *Client) doJSON(ctx context.Context, factory func() (*http.Request, error), destination any) error {
	for attempt := 0; attempt < 3; attempt++ {
		req, err := factory()
		if err != nil {
			return fmt.Errorf("feishu: create request: %w", err)
		}
		response, err := c.httpClient.Do(req)
		if err != nil {
			if attempt < 2 && ctx.Err() == nil {
				if err := wait(ctx, time.Duration(attempt+1)*100*time.Millisecond); err != nil {
					return err
				}
				continue
			}
			return fmt.Errorf("feishu: transport: %w", err)
		}
		payload, readErr := io.ReadAll(io.LimitReader(response.Body, maxResponseBytes+1))
		_ = response.Body.Close()
		if readErr != nil {
			return fmt.Errorf("feishu: read response: %w", readErr)
		}
		if len(payload) > maxResponseBytes {
			return providerError("response_too_large", response.StatusCode)
		}
		if (response.StatusCode == http.StatusTooManyRequests || response.StatusCode >= 500) && attempt < 2 {
			delay := retryDelay(response.Header.Get("Retry-After"), attempt)
			if err := wait(ctx, delay); err != nil {
				return err
			}
			continue
		}
		if response.StatusCode < 200 || response.StatusCode >= 300 {
			return providerError("http", response.StatusCode)
		}
		if err := json.Unmarshal(payload, destination); err != nil {
			return providerError("decode", response.StatusCode)
		}
		return nil
	}
	return providerError("retry_exhausted", 0)
}

type stableProviderError struct {
	operation string
	code      int
}

func (e stableProviderError) Error() string {
	return fmt.Sprintf("feishu: %s failed (%d)", e.operation, e.code)
}
func (e stableProviderError) Unwrap() error { return providers.ErrProviderFailure }
func providerError(operation string, code int) error {
	return stableProviderError{operation: operation, code: code}
}

func retryDelay(header string, attempt int) time.Duration {
	if seconds, err := strconv.Atoi(header); err == nil && seconds >= 0 {
		delay := time.Duration(seconds) * time.Second
		if delay > 2*time.Second {
			return 2 * time.Second
		}
		return delay
	}
	return time.Duration(attempt+1) * 100 * time.Millisecond
}

func wait(ctx context.Context, delay time.Duration) error {
	timer := time.NewTimer(delay)
	defer timer.Stop()
	select {
	case <-timer.C:
		return nil
	case <-ctx.Done():
		return ctx.Err()
	}
}

func mergeStrings(left, right []string) []string {
	seen := make(map[string]struct{}, len(left)+len(right))
	merged := make([]string, 0, len(left)+len(right))
	for _, values := range [][]string{left, right} {
		for _, value := range values {
			if value == "" {
				continue
			}
			if _, ok := seen[value]; !ok {
				seen[value] = struct{}{}
				merged = append(merged, value)
			}
		}
	}
	return merged
}

var _ providers.DirectorySource = (*Client)(nil)
var _ providers.OAuthSource = (*Client)(nil)
