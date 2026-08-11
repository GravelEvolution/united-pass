//
// Copyright (c) 2026 Chen Jiajie(Ariakage)
//
// Author: Chen Jiajie(Ariakage) <ariakage233@gmail.com>
// Date: 2026-08-11
// Description: Phase 6 Provider service invariant tests
//

package providers

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/GravelEvolution/united-pass/backend/internal/identity"
)

type fakeRepository struct {
	detail           ProviderDetail
	linkedUser       identity.User
	linkedErr        error
	recordedUnlinked OAuthUserInfo
	setEnabledCalls  int
	claimed          *SyncJob
	applied          *DirectorySnapshot
	failedClass      string
}

func (f *fakeRepository) ListProviders(context.Context, ListQuery) (CursorPage[ProviderSummary], error) {
	return CursorPage[ProviderSummary]{}, nil
}
func (f *fakeRepository) GetProvider(context.Context, ProviderID) (ProviderDetail, error) {
	return f.detail, nil
}
func (f *fakeRepository) SetProviderEnabled(_ context.Context, _ identity.UserID, _ ProviderID, enabled bool, _ string) (ProviderDetail, error) {
	f.setEnabledCalls++
	f.detail.LoginEnabled = enabled
	if enabled {
		f.detail.Status = ProviderStatusActive
	}
	return f.detail, nil
}
func (f *fakeRepository) EnqueueSync(context.Context, identity.UserID, ProviderID, string) (SyncJob, error) {
	return SyncJob{}, nil
}
func (f *fakeRepository) ClaimSync(context.Context, time.Time) (*SyncJob, error) {
	return f.claimed, nil
}
func (f *fakeRepository) ApplySnapshot(_ context.Context, _ SyncJob, snapshot DirectorySnapshot) (SyncJob, error) {
	f.applied = &snapshot
	return SyncJob{}, nil
}
func (f *fakeRepository) FailSync(_ context.Context, _ SyncJob, class string) error {
	f.failedClass = class
	return nil
}
func (f *fakeRepository) ListSyncHistory(context.Context, ProviderID, int) ([]SyncHistoryEntry, error) {
	return nil, nil
}
func (f *fakeRepository) ListConflicts(context.Context, ProviderID, int) ([]SyncConflict, error) {
	return nil, nil
}
func (f *fakeRepository) ResolveConflict(context.Context, identity.UserID, ConflictID, identity.UserID, string) error {
	return nil
}
func (f *fakeRepository) IgnoreConflict(context.Context, identity.UserID, ConflictID, string) error {
	return nil
}
func (f *fakeRepository) RecordUnlinkedIdentity(_ context.Context, _ ProviderID, _ string, info OAuthUserInfo) error {
	f.recordedUnlinked = info
	return nil
}
func (f *fakeRepository) LinkedUser(context.Context, ProviderID, string, string) (identity.User, error) {
	return f.linkedUser, f.linkedErr
}
func (f *fakeRepository) RecordAuthorizationDenied(context.Context, identity.UserID, string, string, string, string, string) error {
	return nil
}

type fakeDirectory struct {
	validateErr error
	snapshot    DirectorySnapshot
	fetchErr    error
}

func (f *fakeDirectory) Validate(context.Context) error { return f.validateErr }
func (f *fakeDirectory) FetchDirectory(context.Context) (DirectorySnapshot, error) {
	return f.snapshot, f.fetchErr
}

type fakeOAuth struct{}

func (*fakeOAuth) AuthorizationURL(string) (string, error) { return "https://example.test", nil }
func (*fakeOAuth) ExchangeCode(context.Context, string) (OAuthUserInfo, error) {
	return OAuthUserInfo{}, nil
}

func configuredService(repo *fakeRepository, directory DirectorySource) *Service {
	return NewService(repo, directory, &fakeOAuth{}, RuntimeMetadata{AppID: "cli_test", RedirectURL: "https://id.example.test/api/v1/auth/providers/feishu/callback", ContactScope: "directory", TenantID: "tenant_test", SecretConfigured: true}, nil)
}

func activeDetail() ProviderDetail {
	return ProviderDetail{ProviderSummary: ProviderSummary{ProviderID: FeishuProviderID, DisplayName: "Feishu", Status: ProviderStatusActive, LoginEnabled: true}}
}

func TestEnableRequiresCompleteServerCredentials(t *testing.T) {
	repo := &fakeRepository{detail: activeDetail()}
	service := NewService(repo, nil, nil, RuntimeMetadata{}, nil)
	_, err := service.SetProviderEnabled(t.Context(), "user_actor", FeishuProviderID, true, "req_test")
	if !errors.Is(err, ErrNotConfigured) {
		t.Fatalf("error = %v, want ErrNotConfigured", err)
	}
	if repo.setEnabledCalls != 0 {
		t.Fatal("repository mutated before credential validation")
	}
}

func TestEnableValidatesProviderBeforeDurableMutation(t *testing.T) {
	repo := &fakeRepository{detail: activeDetail()}
	service := configuredService(repo, &fakeDirectory{validateErr: errors.New("denied")})
	_, err := service.SetProviderEnabled(t.Context(), "user_actor", FeishuProviderID, true, "req_test")
	if !errors.Is(err, ErrProviderFailure) {
		t.Fatalf("error = %v, want provider failure", err)
	}
	if repo.setEnabledCalls != 0 {
		t.Fatal("repository mutated after failed provider validation")
	}
}

func TestResolveOAuthUserNeverMatchesAcrossTenant(t *testing.T) {
	repo := &fakeRepository{detail: activeDetail(), linkedUser: identity.User{ID: "user_wrong"}}
	service := configuredService(repo, &fakeDirectory{})
	_, err := service.ResolveOAuthUser(t.Context(), FeishuProviderID, OAuthUserInfo{Subject: "ou_test", TenantID: "other_tenant", Name: "Test"})
	if !errors.Is(err, ErrTenantMismatch) {
		t.Fatalf("error = %v, want tenant mismatch", err)
	}
	if repo.recordedUnlinked.Subject != "" {
		t.Fatal("cross-tenant identity was staged")
	}
}

func TestResolveOAuthUserRecordsExplicitManualConflict(t *testing.T) {
	repo := &fakeRepository{detail: activeDetail(), linkedErr: ErrNotFound}
	service := configuredService(repo, &fakeDirectory{})
	info := OAuthUserInfo{Subject: "ou_test", TenantID: "tenant_test", Name: "Candidate", Email: "candidate@example.test"}
	_, err := service.ResolveOAuthUser(t.Context(), FeishuProviderID, info)
	if !errors.Is(err, ErrIdentityUnlinked) {
		t.Fatalf("error = %v, want identity unlinked", err)
	}
	if repo.recordedUnlinked.Subject != info.Subject || repo.recordedUnlinked.Email != info.Email {
		t.Fatalf("recorded conflict = %#v", repo.recordedUnlinked)
	}
}

func TestRunOneSyncRejectsWrongTenantBeforeApply(t *testing.T) {
	job := &SyncJob{SyncID: "sync_test", ProviderID: FeishuProviderID, Status: SyncStatusRunning, Attempts: 1}
	repo := &fakeRepository{detail: activeDetail(), claimed: job}
	directory := &fakeDirectory{snapshot: DirectorySnapshot{ProviderID: FeishuProviderID, TenantID: "other_tenant", Users: []ExternalUser{{Subject: "ou_test", Name: "Test", Active: true}}}}
	service := configuredService(repo, directory)
	processed, err := service.RunOneSync(t.Context(), time.Minute)
	if !processed || !errors.Is(err, ErrTenantMismatch) {
		t.Fatalf("processed=%v error=%v", processed, err)
	}
	if repo.applied != nil {
		t.Fatal("cross-tenant snapshot reached repository")
	}
	if repo.failedClass != "tenant" {
		t.Fatalf("failure class = %q", repo.failedClass)
	}
}

func TestRunOneSyncAppliesBoundedSnapshot(t *testing.T) {
	job := &SyncJob{SyncID: "sync_test", ProviderID: FeishuProviderID, Status: SyncStatusRunning, Attempts: 1}
	repo := &fakeRepository{detail: activeDetail(), claimed: job}
	snapshot := DirectorySnapshot{ProviderID: FeishuProviderID, TenantID: "tenant_test", Departments: []ExternalDepartment{{ExternalID: "od_test", Name: "Test"}}, Users: []ExternalUser{{Subject: "ou_test", Name: "Test", Active: true}}}
	service := configuredService(repo, &fakeDirectory{snapshot: snapshot})
	processed, err := service.RunOneSync(t.Context(), time.Minute)
	if err != nil || !processed {
		t.Fatalf("processed=%v error=%v", processed, err)
	}
	if repo.applied == nil || repo.applied.Users[0].Subject != "ou_test" {
		t.Fatalf("applied = %#v", repo.applied)
	}
}
