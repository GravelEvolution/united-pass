//
// Copyright (c) 2026 Chen Jiajie(Ariakage)
//
// Author: Chen Jiajie(Ariakage) <ariakage233@gmail.com>
// Date: 2026-08-11
// Description: Phase 6 Provider administration and reconciliation orchestration
//

package providers

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"time"

	"github.com/GravelEvolution/united-pass/backend/internal/identity"
	"github.com/GravelEvolution/united-pass/backend/internal/platform/observability"
)

type Service struct {
	repo      Repository
	directory DirectorySource
	oauth     OAuthSource
	metadata  RuntimeMetadata
	logger    *slog.Logger
	clock     func() time.Time
}

func NewService(repo Repository, directory DirectorySource, oauth OAuthSource, metadata RuntimeMetadata, logger *slog.Logger) *Service {
	return &Service{repo: repo, directory: directory, oauth: oauth, metadata: metadata, logger: logger, clock: func() time.Time { return time.Now().UTC() }}
}

func (s *Service) ListProviders(ctx context.Context, query ListQuery) (CursorPage[ProviderSummary], error) {
	return s.repo.ListProviders(ctx, query)
}

func (s *Service) GetProvider(ctx context.Context, providerID ProviderID) (ProviderDetail, error) {
	if !HasProviderIDPrefix(string(providerID)) {
		return ProviderDetail{}, ErrInvalidInput
	}
	detail, err := s.repo.GetProvider(ctx, providerID)
	if err != nil {
		return ProviderDetail{}, err
	}
	if providerID == FeishuProviderID {
		detail.AppID = s.metadata.AppID
		detail.SecretConfigured = s.metadata.SecretConfigured
		detail.CallbackURL = s.metadata.RedirectURL
		detail.ContactScope = s.metadata.ContactScope
		if !s.metadata.SecretConfigured {
			detail.LoginEnabled = false
		}
	}
	return detail, nil
}

func (s *Service) SetProviderEnabled(ctx context.Context, actor identity.UserID, providerID ProviderID, enabled bool, requestID string) (ProviderDetail, error) {
	if actor == "" || !HasProviderIDPrefix(string(providerID)) {
		return ProviderDetail{}, ErrInvalidInput
	}
	if providerID != FeishuProviderID {
		return ProviderDetail{}, ErrNotFound
	}
	if enabled {
		if !s.metadata.SecretConfigured || s.directory == nil || s.oauth == nil {
			return ProviderDetail{}, ErrNotConfigured
		}
		if err := s.directory.Validate(ctx); err != nil {
			return ProviderDetail{}, fmt.Errorf("providers: validate provider: %w", ErrProviderFailure)
		}
	}
	detail, err := s.repo.SetProviderEnabled(ctx, actor, providerID, enabled, requestID)
	if err != nil {
		return ProviderDetail{}, err
	}
	return s.GetProvider(ctx, detail.ProviderID)
}

func (s *Service) EnqueueSync(ctx context.Context, actor identity.UserID, providerID ProviderID, requestID string) (SyncJob, error) {
	if actor == "" || !HasProviderIDPrefix(string(providerID)) {
		return SyncJob{}, ErrInvalidInput
	}
	if providerID != FeishuProviderID || !s.metadata.SecretConfigured || s.directory == nil {
		return SyncJob{}, ErrNotConfigured
	}
	return s.repo.EnqueueSync(ctx, actor, providerID, requestID)
}

func (s *Service) ListSyncHistory(ctx context.Context, providerID ProviderID, limit int) ([]SyncHistoryEntry, error) {
	if !HasProviderIDPrefix(string(providerID)) {
		return nil, ErrInvalidInput
	}
	if limit <= 0 || limit > 100 {
		limit = 25
	}
	return s.repo.ListSyncHistory(ctx, providerID, limit)
}

func (s *Service) ListConflicts(ctx context.Context, providerID ProviderID, limit int) ([]SyncConflict, error) {
	if !HasProviderIDPrefix(string(providerID)) {
		return nil, ErrInvalidInput
	}
	if limit <= 0 || limit > 100 {
		limit = 100
	}
	return s.repo.ListConflicts(ctx, providerID, limit)
}

func (s *Service) RecordAuthorizationDenied(ctx context.Context, actor identity.UserID, targetKey, targetID, eventType, operation, requestID string) {
	if eventType == "" {
		return
	}
	if err := s.repo.RecordAuthorizationDenied(ctx, actor, targetKey, targetID, eventType, operation, requestID); err != nil {
		s.lg().Warn("provider authorization denial audit failed",
			"event", eventType, "userId", string(actor),
			"errorClass", observability.ClassifyError(err))
	}
}

func (s *Service) ResolveConflict(ctx context.Context, actor identity.UserID, conflictID ConflictID, userID identity.UserID, requestID string) error {
	if actor == "" || !HasConflictIDPrefix(string(conflictID)) || userID == "" {
		return ErrInvalidInput
	}
	return s.repo.ResolveConflict(ctx, actor, conflictID, userID, requestID)
}

func (s *Service) IgnoreConflict(ctx context.Context, actor identity.UserID, conflictID ConflictID, requestID string) error {
	if actor == "" || !HasConflictIDPrefix(string(conflictID)) {
		return ErrInvalidInput
	}
	return s.repo.IgnoreConflict(ctx, actor, conflictID, requestID)
}

func (s *Service) LinkedUser(ctx context.Context, providerID ProviderID, tenantID, subject string) (identity.User, error) {
	if !HasProviderIDPrefix(string(providerID)) || tenantID == "" || subject == "" {
		return identity.User{}, ErrInvalidInput
	}
	if providerID != FeishuProviderID {
		return identity.User{}, ErrNotFound
	}
	detail, err := s.GetProvider(ctx, providerID)
	if err != nil {
		return identity.User{}, err
	}
	if !detail.LoginEnabled || detail.Status != ProviderStatusActive {
		return identity.User{}, ErrProviderDisabled
	}
	if s.metadata.TenantID == "" || tenantID != s.metadata.TenantID {
		return identity.User{}, ErrTenantMismatch
	}
	user, err := s.repo.LinkedUser(ctx, providerID, tenantID, subject)
	if errors.Is(err, ErrNotFound) {
		return identity.User{}, ErrIdentityUnlinked
	}
	return user, err
}

func (s *Service) ResolveOAuthUser(ctx context.Context, providerID ProviderID, info OAuthUserInfo) (identity.User, error) {
	user, err := s.LinkedUser(ctx, providerID, info.TenantID, info.Subject)
	if errors.Is(err, ErrIdentityUnlinked) {
		if recordErr := s.repo.RecordUnlinkedIdentity(context.WithoutCancel(ctx), providerID, info.TenantID, info); recordErr != nil {
			return identity.User{}, recordErr
		}
	}
	return user, err
}

func (s *Service) OAuthSource() OAuthSource { return s.oauth }

// RunOneSync claims and settles at most one durable job. Provider failures
// leave a terminal failed observation with a stable failure class; no token,
// raw body or provider error string is persisted.
func (s *Service) RunOneSync(ctx context.Context, staleAfter time.Duration) (bool, error) {
	if s.directory == nil {
		return false, nil
	}
	if staleAfter <= 0 {
		staleAfter = 5 * time.Minute
	}
	job, err := s.repo.ClaimSync(ctx, s.clock().Add(-staleAfter))
	if err != nil || job == nil {
		return false, err
	}
	snapshot, err := s.directory.FetchDirectory(ctx)
	if err != nil {
		failureClass := string(observability.ClassifyError(err))
		if recordErr := s.repo.FailSync(context.WithoutCancel(ctx), *job, failureClass); recordErr != nil {
			s.lg().Error("provider sync failure could not be recorded", "syncId", string(job.SyncID), "errorClass", observability.ClassifyError(recordErr))
			return true, recordErr
		}
		return true, fmt.Errorf("providers: fetch directory: %w", ErrProviderFailure)
	}
	if snapshot.ProviderID == "" {
		snapshot.ProviderID = job.ProviderID
	}
	if snapshot.TenantID == "" {
		snapshot.TenantID = s.metadata.TenantID
	}
	if err := ValidateSnapshot(snapshot); err != nil {
		failureClass := string(observability.ClassifyError(err))
		_ = s.repo.FailSync(context.WithoutCancel(ctx), *job, failureClass)
		return true, err
	}
	if snapshot.ProviderID != job.ProviderID || snapshot.TenantID != s.metadata.TenantID {
		_ = s.repo.FailSync(context.WithoutCancel(ctx), *job, "tenant")
		return true, ErrTenantMismatch
	}
	if _, err := s.repo.ApplySnapshot(ctx, *job, snapshot); err != nil {
		return true, err
	}
	return true, nil
}

type Reconciler struct {
	service  *Service
	interval time.Duration
	timeout  time.Duration
	stop     chan struct{}
	done     chan struct{}
}

func NewReconciler(service *Service, interval, timeout time.Duration) *Reconciler {
	if interval <= 0 {
		interval = 15 * time.Second
	}
	if timeout <= 0 {
		timeout = 2 * time.Minute
	}
	return &Reconciler{service: service, interval: interval, timeout: timeout, stop: make(chan struct{}), done: make(chan struct{})}
}

func (r *Reconciler) Start() {
	go func() {
		defer close(r.done)
		r.run()
		ticker := time.NewTicker(r.interval)
		defer ticker.Stop()
		for {
			select {
			case <-ticker.C:
				r.run()
			case <-r.stop:
				return
			}
		}
	}()
}

func (r *Reconciler) Stop() {
	select {
	case <-r.stop:
	default:
		close(r.stop)
	}
	<-r.done
}

func (r *Reconciler) run() {
	ctx, cancel := context.WithTimeout(context.Background(), r.timeout)
	defer cancel()
	if _, err := r.service.RunOneSync(ctx, r.timeout*2); err != nil {
		r.service.lg().Warn("provider directory reconciliation failed", "errorClass", observability.ClassifyError(err))
	}
}

func (s *Service) lg() *slog.Logger {
	if s.logger != nil {
		return s.logger
	}
	return slog.Default()
}
