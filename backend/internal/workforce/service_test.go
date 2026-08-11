//
// Copyright (c) 2026 Chen Jiajie(Ariakage)
//
// Author: Chen Jiajie(Ariakage) <ariakage233@gmail.com>
// Date: 2026-08-11
// Description: Phase 5 workforce use-case security and convergence tests
//

package workforce

import (
	"context"
	"errors"
	"io"
	"log/slog"
	"testing"

	"github.com/GravelEvolution/united-pass/backend/internal/identity"
)

type serviceTestRepository struct {
	Repository
	offboardProfile EmployeeProfile
	offboardJob     AccessRevocationJob
	offboardErr     error
	failCalls       int
	resolveCalls    int
	recordedDenied  int
	enqueueJob      AccessRevocationJob
	changeJob       *AccessRevocationJob
}

func (r *serviceTestRepository) OffboardEmployee(_ context.Context, _, _ identity.UserID, _ string) (EmployeeProfile, AccessRevocationJob, error) {
	return r.offboardProfile, r.offboardJob, r.offboardErr
}

func (r *serviceTestRepository) FailAccessRevocation(_ context.Context, _ AccessRevocationJob, _ string) error {
	r.failCalls++
	return nil
}

func (r *serviceTestRepository) ResolveAccessRevocation(_ context.Context, _ AccessRevocationJob, _ int, _ string) error {
	r.resolveCalls++
	return nil
}

func (r *serviceTestRepository) EnqueueSessionRevocation(_ context.Context, _, _ identity.UserID, _ AccessRevocationReason, _ string) (AccessRevocationJob, error) {
	return r.enqueueJob, nil
}

func (r *serviceTestRepository) ChangeUserStatus(_ context.Context, _ UserStatusMutation) (*AccessRevocationJob, error) {
	return r.changeJob, nil
}

func (r *serviceTestRepository) RecordAuthorizationDenied(_ context.Context, _ identity.UserID, _, _, _, _, _ string) error {
	r.recordedDenied++
	return nil
}

type serviceTestRevoker struct {
	allCount       int
	allProvider    string
	allErr         error
	targetProvider string
	targetErr      error
}

func (r *serviceTestRevoker) RevokeUserSessionByAdmin(_ context.Context, _ identity.UserID, _ string) (string, error) {
	return r.targetProvider, r.targetErr
}

func (r *serviceTestRevoker) RevokeAllUserSessionsByAdmin(_ context.Context, _ identity.UserID) (int, string, error) {
	return r.allCount, r.allProvider, r.allErr
}

func testWorkforceLogger() *slog.Logger {
	return slog.New(slog.NewTextHandler(io.Discard, nil))
}

func TestOffboardingCommitsAndReportsCleanupPending(t *testing.T) {
	cleanupErr := errors.New("redis unavailable")
	repo := &serviceTestRepository{
		offboardProfile: EmployeeProfile{UserID: "user_target", Status: EmployeeStatusOffboarding},
		offboardJob:     AccessRevocationJob{JobID: "arj_one", UserID: "user_target", Reason: RevocationEmployeeOffboarded},
	}
	service := NewService(repo, &serviceTestRevoker{allErr: cleanupErr}, testWorkforceLogger())
	result, err := service.OffboardEmployee(context.Background(), "user_actor", "user_target", "req_one")
	if err != nil {
		t.Fatalf("OffboardEmployee returned error after authoritative commit: %v", err)
	}
	if result.Status != EmployeeStatusOffboarding || !result.CleanupPending {
		t.Fatalf("result = %+v, want offboarding + pending", result)
	}
	if repo.failCalls != 1 || repo.resolveCalls != 0 {
		t.Fatalf("failCalls=%d resolveCalls=%d, want 1/0", repo.failCalls, repo.resolveCalls)
	}
}

func TestDisableCommitsAndReportsCleanupPending(t *testing.T) {
	job := &AccessRevocationJob{JobID: "arj_disable", UserID: "user_target", Reason: RevocationUserDisabled}
	repo := &serviceTestRepository{changeJob: job}
	service := NewService(repo, &serviceTestRevoker{allErr: errors.New("redis unavailable")}, testWorkforceLogger())
	pending, err := service.ChangeUserStatus(context.Background(), UserStatusMutation{
		ActorUserID: "user_actor", TargetUserID: "user_target",
		Status: identity.UserStatusDisabled, RevokeSessions: true,
	})
	if err != nil || !pending {
		t.Fatalf("pending=%v err=%v, want committed + cleanup pending", pending, err)
	}
	if repo.failCalls != 1 || repo.resolveCalls != 0 {
		t.Fatalf("failCalls=%d resolveCalls=%d, want 1/0", repo.failCalls, repo.resolveCalls)
	}
}

func TestOffboardingResolvesSynchronousCleanup(t *testing.T) {
	repo := &serviceTestRepository{
		offboardProfile: EmployeeProfile{UserID: "user_target", Status: EmployeeStatusOffboarding},
		offboardJob:     AccessRevocationJob{JobID: "arj_one", UserID: "user_target", Reason: RevocationEmployeeOffboarded},
	}
	service := NewService(repo, &serviceTestRevoker{allCount: 3}, testWorkforceLogger())
	result, err := service.OffboardEmployee(context.Background(), "user_actor", "user_target", "req_one")
	if err != nil || result.CleanupPending {
		t.Fatalf("result=%+v err=%v, want resolved", result, err)
	}
	if repo.resolveCalls != 1 || repo.failCalls != 0 {
		t.Fatalf("resolveCalls=%d failCalls=%d, want 1/0", repo.resolveCalls, repo.failCalls)
	}
}

func TestExplicitBulkRevokeDoesNotReportFalseSuccess(t *testing.T) {
	repo := &serviceTestRepository{enqueueJob: AccessRevocationJob{
		JobID: "arj_bulk", ActorUserID: "user_actor", UserID: "user_target",
		Reason: RevocationAdminSession,
	}}
	service := NewService(repo, &serviceTestRevoker{allErr: errors.New("partial redis walk")}, testWorkforceLogger())
	err := service.RevokeUserSessions(context.Background(), "user_actor", "user_target", "req_bulk")
	if err == nil {
		t.Fatal("RevokeUserSessions returned nil despite incomplete synchronous cleanup")
	}
	if repo.failCalls != 1 {
		t.Fatalf("failCalls=%d, want 1 durable pending update", repo.failCalls)
	}
}

func TestEmployeeInputNeverSelectsIdentityByContactFact(t *testing.T) {
	_, err := NormalizeEmployeeInput(EmployeeProfileInput{
		// UserID deliberately absent even though a title and department exist:
		// the API cannot fall back to email/name/domain matching.
		DepartmentID: "dep_valid", Title: "Engineer",
	})
	if !errors.Is(err, ErrInvalidInput) {
		t.Fatalf("NormalizeEmployeeInput error = %v, want ErrInvalidInput", err)
	}
	_, err = NormalizeEmployeeInput(EmployeeProfileInput{
		UserID: "user_same", DepartmentID: "dep_valid", Title: "Engineer",
		SupervisorUserID: "user_same",
	})
	if !errors.Is(err, ErrInvalidInput) {
		t.Fatalf("self supervisor error = %v, want ErrInvalidInput", err)
	}
}

func TestAuthorizationDenialIsRecordedWithoutGranting(t *testing.T) {
	repo := &serviceTestRepository{}
	service := NewService(repo, nil, testWorkforceLogger())
	service.RecordAuthorizationDenied(context.Background(), "user_actor", "user_id", "user_target",
		EventUserDisabled, "user.disable", "req_denied")
	if repo.recordedDenied != 1 {
		t.Fatalf("recordedDenied=%d, want 1", repo.recordedDenied)
	}
}
