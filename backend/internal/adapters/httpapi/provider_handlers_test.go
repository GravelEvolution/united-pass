//
// Copyright (c) 2026 Chen Jiajie(Ariakage)
//
// Author: Chen Jiajie(Ariakage) <ariakage233@gmail.com>
// Date: 2026-08-11
// Description: Phase 6 Provider HTTP authorization and reauthentication tests
//

package httpapi

import (
	"context"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/GravelEvolution/united-pass/backend/internal/auth"
	"github.com/GravelEvolution/united-pass/backend/internal/identity"
	"github.com/GravelEvolution/united-pass/backend/internal/permissions"
	"github.com/GravelEvolution/united-pass/backend/internal/providers"
)

type providerHTTPRepository struct {
	providers.Repository
	enabledCalls int
	deniedEvents int
}

func (r *providerHTTPRepository) GetProvider(context.Context, providers.ProviderID) (providers.ProviderDetail, error) {
	return providers.ProviderDetail{ProviderSummary: providers.ProviderSummary{
		ProviderID: providers.FeishuProviderID, DisplayName: "Feishu",
		Status: providers.ProviderStatusDisabled,
	}}, nil
}

func (r *providerHTTPRepository) SetProviderEnabled(_ context.Context, _ identity.UserID, _ providers.ProviderID, enabled bool, _ string) (providers.ProviderDetail, error) {
	r.enabledCalls++
	return providers.ProviderDetail{ProviderSummary: providers.ProviderSummary{
		ProviderID: providers.FeishuProviderID, DisplayName: "Feishu",
		Status: providers.ProviderStatusActive, LoginEnabled: enabled,
	}}, nil
}

func (r *providerHTTPRepository) RecordAuthorizationDenied(context.Context, identity.UserID, string, string, string, string, string) error {
	r.deniedEvents++
	return nil
}

type providerHTTPSource struct{}

func (providerHTTPSource) Validate(context.Context) error { return nil }
func (providerHTTPSource) FetchDirectory(context.Context) (providers.DirectorySnapshot, error) {
	return providers.DirectorySnapshot{}, nil
}
func (providerHTTPSource) AuthorizationURL(string) (string, error) {
	return "https://example.test", nil
}
func (providerHTTPSource) ExchangeCode(context.Context, string) (providers.OAuthUserInfo, error) {
	return providers.OAuthUserInfo{}, nil
}

func newProviderHandlerForTest(repo *providerHTTPRepository, caps permissions.Capabilities, reauth ReauthVerifier) *ProviderHandlers {
	logger := slog.New(slog.NewTextHandler(io.Discard, nil))
	source := providerHTTPSource{}
	service := providers.NewService(repo, source, source, providers.RuntimeMetadata{
		AppID: "cli_test", RedirectURL: "https://id.example.test/api/v1/auth/providers/feishu/callback",
		ContactScope: "directory", TenantID: "tenant_test", SecretConfigured: true,
	}, logger)
	return NewProviderHandlers(service, &stubPermResolver{caps: caps}, reauth, logger)
}

func TestEnableProviderRequiresExactTargetBoundReauthentication(t *testing.T) {
	repo := &providerHTTPRepository{}
	verifier := &targetReauthVerifier{wantToken: "provider-grant"}
	handler := newProviderHandlerForTest(repo, permissions.AllCapabilities(), verifier)
	req := routeWorkforceRequest(
		workforceRequest(http.MethodPost, "/admin/identity-providers/provider_feishu/enable", ""),
		"/admin/identity-providers/{providerId}/enable")
	recorder := httptest.NewRecorder()
	handler.EnableProvider(recorder, req)
	if recorder.Code != http.StatusForbidden || repo.enabledCalls != 0 {
		t.Fatalf("without grant status=%d mutations=%d", recorder.Code, repo.enabledCalls)
	}

	verifier = &targetReauthVerifier{wantToken: "provider-grant"}
	handler = newProviderHandlerForTest(repo, permissions.AllCapabilities(), verifier)
	req = routeWorkforceRequest(
		workforceRequest(http.MethodPost, "/admin/identity-providers/provider_feishu/enable", ""),
		"/admin/identity-providers/{providerId}/enable")
	req.Header.Set("X-Reauthentication-Token", "provider-grant")
	recorder = httptest.NewRecorder()
	handler.EnableProvider(recorder, req)
	if recorder.Code != http.StatusOK || repo.enabledCalls != 1 {
		t.Fatalf("with grant status=%d mutations=%d body=%s", recorder.Code, repo.enabledCalls, recorder.Body.String())
	}
	if verifier.action != auth.ReauthActionProviderEnable || verifier.target != string(providers.FeishuProviderID) {
		t.Fatalf("grant action=%q target=%q", verifier.action, verifier.target)
	}
}

func TestProviderCapabilityDenialIsAuditedAndDoesNotMutate(t *testing.T) {
	repo := &providerHTTPRepository{}
	handler := newProviderHandlerForTest(repo, permissions.NoCapabilities(), nil)
	req := routeWorkforceRequest(
		workforceRequest(http.MethodPost, "/admin/identity-providers/provider_feishu/enable", ""),
		"/admin/identity-providers/{providerId}/enable")
	recorder := httptest.NewRecorder()
	handler.EnableProvider(recorder, req)
	if recorder.Code != http.StatusForbidden || repo.enabledCalls != 0 || repo.deniedEvents != 1 {
		t.Fatalf("status=%d mutations=%d denied=%d", recorder.Code, repo.enabledCalls, repo.deniedEvents)
	}
}
