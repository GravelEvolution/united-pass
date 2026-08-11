//
// Copyright (c) 2026 Chen Jiajie(Ariakage)
//
// Author: Chen Jiajie(Ariakage) <ariakage233@gmail.com>
// Date: 2026-08-11
// Description: Phase 5 identity and workforce use-case orchestration
//

package workforce

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"time"

	"github.com/GravelEvolution/united-pass/backend/internal/identity"
	"github.com/GravelEvolution/united-pass/backend/internal/platform/observability"
)

type Repository interface {
	ListUsers(ctx context.Context, query UserListQuery) (CursorPage[UserSummary], error)
	GetUserDetail(ctx context.Context, userID identity.UserID) (UserDetail, error)
	ListEmployees(ctx context.Context, query EmployeeListQuery) (CursorPage[EmployeeSummary], error)
	GetEmployeeProfile(ctx context.Context, userID identity.UserID) (EmployeeProfile, error)
	ListDepartments(ctx context.Context, query string, limit int) ([]DepartmentSummary, error)
	GetDepartment(ctx context.Context, departmentID DepartmentID) (DepartmentDetail, error)

	ChangeUserStatus(ctx context.Context, mutation UserStatusMutation) (*AccessRevocationJob, error)
	LinkEmployee(ctx context.Context, actor identity.UserID, input EmployeeProfileInput, requestID string) (EmployeeProfile, error)
	UpdateEmployee(ctx context.Context, actor identity.UserID, input EmployeeProfileInput, requestID string) (EmployeeProfile, error)
	OffboardEmployee(ctx context.Context, actor, userID identity.UserID, requestID string) (EmployeeProfile, AccessRevocationJob, error)
	CreateDepartment(ctx context.Context, actor identity.UserID, input DepartmentInput, requestID string) (DepartmentDetail, error)
	UpdateDepartment(ctx context.Context, actor identity.UserID, departmentID DepartmentID, patch DepartmentPatch, requestID string) (DepartmentDetail, error)
	DeleteDepartment(ctx context.Context, actor identity.UserID, departmentID DepartmentID, requestID string) error

	EnqueueSessionRevocation(ctx context.Context, actor, userID identity.UserID, reason AccessRevocationReason, requestID string) (AccessRevocationJob, error)
	ResolveAccessRevocation(ctx context.Context, job AccessRevocationJob, affectedCount int, providerFailureClass string) error
	FailAccessRevocation(ctx context.Context, job AccessRevocationJob, failureClass string) error
	ListPendingAccessRevocations(ctx context.Context, limit int) ([]AccessRevocationJob, error)
	RecordTargetSessionRevocation(ctx context.Context, actor, userID identity.UserID, sessionID, requestID, result, failureClass, providerFailureClass string) error
	RecordAuthorizationDenied(ctx context.Context, actor identity.UserID, targetKey, targetID, eventType, operation, requestID string) error
}

// SessionRevoker is the narrow Redis/provider-session seam consumed by Phase
// 5. Implementations remove only the named stable user's indexed sessions and
// never scan the global keyspace.
type SessionRevoker interface {
	RevokeUserSessionByAdmin(ctx context.Context, userID identity.UserID, sessionID string) (providerFailureClass string, err error)
	RevokeAllUserSessionsByAdmin(ctx context.Context, userID identity.UserID) (affectedCount int, providerFailureClass string, err error)
}

type Service struct {
	repo    Repository
	revoker SessionRevoker
	logger  *slog.Logger
}

func NewService(repo Repository, revoker SessionRevoker, logger *slog.Logger) *Service {
	return &Service{repo: repo, revoker: revoker, logger: logger}
}

func (s *Service) ListUsers(ctx context.Context, query UserListQuery) (CursorPage[UserSummary], error) {
	return s.repo.ListUsers(ctx, query)
}

func (s *Service) GetUserDetail(ctx context.Context, userID identity.UserID) (UserDetail, error) {
	return s.repo.GetUserDetail(ctx, userID)
}

func (s *Service) ListEmployees(ctx context.Context, query EmployeeListQuery) (CursorPage[EmployeeSummary], error) {
	return s.repo.ListEmployees(ctx, query)
}

func (s *Service) GetEmployeeProfile(ctx context.Context, userID identity.UserID) (EmployeeProfile, error) {
	return s.repo.GetEmployeeProfile(ctx, userID)
}

func (s *Service) ListDepartments(ctx context.Context, query string, limit int) ([]DepartmentSummary, error) {
	return s.repo.ListDepartments(ctx, query, limit)
}

func (s *Service) GetDepartment(ctx context.Context, departmentID DepartmentID) (DepartmentDetail, error) {
	return s.repo.GetDepartment(ctx, departmentID)
}

func (s *Service) RecordAuthorizationDenied(ctx context.Context, actor identity.UserID, targetKey, targetID, eventType, operation, requestID string) {
	if eventType == "" {
		return
	}
	if err := s.repo.RecordAuthorizationDenied(ctx, actor, targetKey, targetID, eventType, operation, requestID); err != nil {
		s.lg().Warn("workforce authorization denial audit failed",
			"event", eventType, "userId", string(actor),
			"errorClass", observability.ClassifyError(err))
	}
}

func (s *Service) ChangeUserStatus(ctx context.Context, mutation UserStatusMutation) (cleanupPending bool, err error) {
	if mutation.TargetUserID == "" || !mutation.Status.IsValid() || mutation.Status == identity.UserStatusPending {
		return false, ErrInvalidInput
	}
	job, err := s.repo.ChangeUserStatus(ctx, mutation)
	if err != nil || job == nil {
		return false, err
	}
	pending, settleErr := s.settleAccessRevocation(ctx, *job)
	if settleErr != nil {
		s.lg().Warn("disabled user session cleanup pending",
			"userId", string(mutation.TargetUserID),
			"jobId", string(job.JobID),
			"errorClass", observability.ClassifyError(settleErr),
		)
	}
	// The disabled state, success audit and cleanup job already committed.
	// Report the durable convergence state instead of a false whole-operation
	// failure; the reconciler owns further cleanup attempts.
	return pending, nil
}

func (s *Service) LinkEmployee(ctx context.Context, actor identity.UserID, input EmployeeProfileInput, requestID string) (EmployeeProfile, error) {
	normalized, err := NormalizeEmployeeInput(input)
	if err != nil {
		return EmployeeProfile{}, err
	}
	return s.repo.LinkEmployee(ctx, actor, normalized, requestID)
}

func (s *Service) UpdateEmployee(ctx context.Context, actor identity.UserID, input EmployeeProfileInput, requestID string) (EmployeeProfile, error) {
	normalized, err := NormalizeEmployeeInput(input)
	if err != nil {
		return EmployeeProfile{}, err
	}
	return s.repo.UpdateEmployee(ctx, actor, normalized, requestID)
}

func (s *Service) OffboardEmployee(ctx context.Context, actor, userID identity.UserID, requestID string) (OffboardingResult, error) {
	if userID == "" {
		return OffboardingResult{}, ErrInvalidInput
	}
	profile, job, err := s.repo.OffboardEmployee(ctx, actor, userID, requestID)
	if err != nil {
		return OffboardingResult{}, err
	}
	pending, settleErr := s.settleAccessRevocation(ctx, job)
	if settleErr != nil {
		s.lg().Warn("employee offboarding session cleanup pending",
			"userId", string(userID),
			"jobId", string(job.JobID),
			"errorClass", observability.ClassifyError(settleErr),
		)
	}
	return OffboardingResult{Status: profile.Status, CleanupPending: pending}, nil
}

func (s *Service) CreateDepartment(ctx context.Context, actor identity.UserID, input DepartmentInput, requestID string) (DepartmentDetail, error) {
	normalized, err := NormalizeDepartmentInput(input)
	if err != nil {
		return DepartmentDetail{}, err
	}
	return s.repo.CreateDepartment(ctx, actor, normalized, requestID)
}

func (s *Service) UpdateDepartment(ctx context.Context, actor identity.UserID, departmentID DepartmentID, patch DepartmentPatch, requestID string) (DepartmentDetail, error) {
	if !HasDepartmentIDPrefix(string(departmentID)) || (patch.Name == nil && patch.ParentDepartmentID == nil && patch.OwnerUserID == nil) {
		return DepartmentDetail{}, ErrInvalidInput
	}
	if patch.Name != nil {
		input, err := NormalizeDepartmentInput(DepartmentInput{Name: *patch.Name})
		if err != nil {
			return DepartmentDetail{}, err
		}
		patch.Name = &input.Name
	}
	if patch.ParentDepartmentID != nil && *patch.ParentDepartmentID != "" && !HasDepartmentIDPrefix(string(*patch.ParentDepartmentID)) {
		return DepartmentDetail{}, ErrInvalidInput
	}
	return s.repo.UpdateDepartment(ctx, actor, departmentID, patch, requestID)
}

func (s *Service) DeleteDepartment(ctx context.Context, actor identity.UserID, departmentID DepartmentID, requestID string) error {
	if !HasDepartmentIDPrefix(string(departmentID)) {
		return ErrInvalidInput
	}
	return s.repo.DeleteDepartment(ctx, actor, departmentID, requestID)
}

func (s *Service) RevokeUserSession(ctx context.Context, actor, userID identity.UserID, sessionID, requestID string) error {
	if userID == "" || sessionID == "" || s.revoker == nil {
		return ErrInvalidInput
	}
	providerFailure, err := s.revoker.RevokeUserSessionByAdmin(ctx, userID, sessionID)
	if err != nil {
		_ = s.repo.RecordTargetSessionRevocation(ctx, actor, userID, sessionID, requestID,
			"denied", string(observability.ClassifyError(err)), providerFailure)
		return fmt.Errorf("workforce: revoke user session: %w", err)
	}
	if err := s.repo.RecordTargetSessionRevocation(ctx, actor, userID, sessionID, requestID,
		"success", "", providerFailure); err != nil {
		return fmt.Errorf("workforce: record session revocation: %w", err)
	}
	return nil
}

func (s *Service) RevokeUserSessions(ctx context.Context, actor, userID identity.UserID, requestID string) error {
	if userID == "" {
		return ErrInvalidInput
	}
	job, err := s.repo.EnqueueSessionRevocation(ctx, actor, userID, RevocationAdminSession, requestID)
	if err != nil {
		return err
	}
	pending, err := s.settleAccessRevocation(ctx, job)
	if err != nil {
		return err
	}
	if pending {
		return errors.New("workforce: access revocation pending")
	}
	return nil
}

// settleAccessRevocation runs one synchronous convergence attempt. A failure
// leaves the durable job pending; callers decide whether the already-committed
// authoritative mutation can still report success.
func (s *Service) settleAccessRevocation(ctx context.Context, job AccessRevocationJob) (bool, error) {
	if s.revoker == nil {
		err := errors.New("session revoker unavailable")
		_ = s.repo.FailAccessRevocation(ctx, job, string(observability.ClassifyError(err)))
		return true, err
	}
	count, providerFailure, err := s.revoker.RevokeAllUserSessionsByAdmin(ctx, job.UserID)
	if err != nil {
		failureClass := string(observability.ClassifyError(err))
		if recordErr := s.repo.FailAccessRevocation(ctx, job, failureClass); recordErr != nil {
			s.lg().Error("access revocation failure state could not be recorded",
				"jobId", string(job.JobID), "errorClass", observability.ClassifyError(recordErr))
		}
		return true, fmt.Errorf("workforce: settle access revocation: %w", err)
	}
	if err := s.repo.ResolveAccessRevocation(ctx, job, count, providerFailure); err != nil {
		return true, fmt.Errorf("workforce: resolve access revocation: %w", err)
	}
	return false, nil
}

func (s *Service) lg() *slog.Logger {
	if s.logger != nil {
		return s.logger
	}
	return slog.Default()
}

type Reconciler struct {
	service  *Service
	interval time.Duration
	batch    int
	stop     chan struct{}
	done     chan struct{}
}

func NewReconciler(service *Service, interval time.Duration, batch int) *Reconciler {
	if interval <= 0 {
		interval = 30 * time.Second
	}
	if batch <= 0 {
		batch = 25
	}
	return &Reconciler{service: service, interval: interval, batch: batch, stop: make(chan struct{}), done: make(chan struct{})}
}

func (r *Reconciler) Start() {
	go func() {
		defer close(r.done)
		ticker := time.NewTicker(r.interval)
		defer ticker.Stop()
		for {
			select {
			case <-ticker.C:
				r.runOnce()
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

func (r *Reconciler) runOnce() {
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()
	jobs, err := r.service.repo.ListPendingAccessRevocations(ctx, r.batch)
	if err != nil {
		r.service.lg().Error("access revocation reconciliation list failed", "errorClass", observability.ClassifyError(err))
		return
	}
	for _, job := range jobs {
		if _, err := r.service.settleAccessRevocation(ctx, job); err != nil {
			r.service.lg().Warn("access revocation reconciliation attempt failed",
				"jobId", string(job.JobID), "userId", string(job.UserID),
				"errorClass", observability.ClassifyError(err))
		}
	}
}
