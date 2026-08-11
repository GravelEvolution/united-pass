//
// Copyright (c) 2026 Chen Jiajie(Ariakage)
//
// Author: Chen Jiajie(Ariakage) <ariakage233@gmail.com>
// Date: 2026-08-11
// Description: Real PostgreSQL acceptance for Phase 5 workforce invariants
//

//go:build integration

package postgres

import (
	"context"
	"errors"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/GravelEvolution/united-pass/backend/internal/identity"
	"github.com/GravelEvolution/united-pass/backend/internal/workforce"
)

func setupWorkforceRepo(t *testing.T) (*WorkforceRepository, *UserRepository) {
	t.Helper()
	pool := setupTestPool(t, 8)
	repo, err := NewWorkforceRepository(pool.PgxPool(), testCursorKey(t))
	if err != nil {
		t.Fatalf("create workforce repository: %v", err)
	}
	return repo, NewUserRepository(pool.PgxPool())
}

func createWorkforceUser(t *testing.T, users *UserRepository, id, name string) identity.UserID {
	t.Helper()
	now := time.Now().UTC()
	user := identity.User{
		ID: identity.UserID(id), Status: identity.UserStatusActive,
		DisplayName: name, Email: id + "@example.com", Version: 1,
		CreatedAt: now, UpdatedAt: now,
	}
	if err := users.Create(context.Background(), user); err != nil {
		t.Fatalf("create workforce user %s: %v", id, err)
	}
	if err := users.AddPersona(context.Background(), user.ID, identity.PersonaConsumer); err != nil {
		t.Fatalf("add consumer persona: %v", err)
	}
	return user.ID
}

func TestIntegration_WorkforceRepository(t *testing.T) {
	repo, users := setupWorkforceRepo(t)
	actor := createWorkforceUser(t, users, "user_wf_actor", "Workforce Admin")
	t.Run("link preserves identity and personas", func(t *testing.T) {
		testWorkforceLinkPreservesIdentityAndPersonas(t, repo, users, actor)
	})
	t.Run("concurrent link has single winner", func(t *testing.T) {
		testWorkforceConcurrentLinkHasSingleWinner(t, repo, users, actor)
	})
	t.Run("department cycle and nonempty delete are rejected", func(t *testing.T) {
		testDepartmentCycleAndNonEmptyDeleteAreRejected(t, repo, users, actor)
	})
	t.Run("lifecycle clears assignments and commits cleanup", func(t *testing.T) {
		testLifecycleClearsAssignmentsAndCommitsCleanup(t, repo, users, actor)
	})
	t.Run("cursor binds query state", func(t *testing.T) {
		testWorkforceCursorBindsQueryState(t, repo)
	})
}

func testWorkforceLinkPreservesIdentityAndPersonas(t *testing.T, repo *WorkforceRepository, users *UserRepository, actor identity.UserID) {
	ctx := context.Background()
	target := createWorkforceUser(t, users, "user_wf_target", "Existing Consumer")

	department, err := repo.CreateDepartment(ctx, actor, workforce.DepartmentInput{Name: "Identity Platform"}, "req_wf_create_department")
	if err != nil {
		t.Fatalf("create department: %v", err)
	}
	profile, err := repo.LinkEmployee(ctx, actor, workforce.EmployeeProfileInput{
		UserID: target, DepartmentID: department.DepartmentID, Title: "Engineer",
	}, "req_wf_link")
	if err != nil {
		t.Fatalf("link employee: %v", err)
	}
	if profile.UserID != target || profile.EmployeeNumber == "" || profile.Status != workforce.EmployeeStatusActive {
		t.Fatalf("unexpected linked profile: %+v", profile)
	}
	personas, err := users.GetPersonas(ctx, target)
	if err != nil {
		t.Fatalf("get personas: %v", err)
	}
	if len(personas) != 2 || personas[0] != identity.PersonaConsumer || personas[1] != identity.PersonaEmployee {
		t.Fatalf("personas = %v, want consumer + employee", personas)
	}
	detail, err := repo.GetUserDetail(ctx, target)
	if err != nil {
		t.Fatalf("get user detail: %v", err)
	}
	if detail.User.ID != target || detail.EmployeeProfile == nil || detail.EmployeeProfile.UserID != target {
		t.Fatalf("stable identity was not preserved: %+v", detail)
	}

	// A concurrent or repeated link cannot create a second profile/number.
	_, err = repo.LinkEmployee(ctx, actor, workforce.EmployeeProfileInput{
		UserID: target, DepartmentID: department.DepartmentID, Title: "Engineer",
	}, "req_wf_link_again")
	if !errors.Is(err, workforce.ErrConflict) {
		t.Fatalf("repeated link = %v, want ErrConflict", err)
	}
}

func testWorkforceConcurrentLinkHasSingleWinner(t *testing.T, repo *WorkforceRepository, users *UserRepository, actor identity.UserID) {
	ctx := context.Background()
	target := createWorkforceUser(t, users, "user_wf_concurrent_target", "Concurrent Target")
	department, err := repo.CreateDepartment(ctx, actor, workforce.DepartmentInput{Name: "Concurrency"}, "req_wf_concurrent_department")
	if err != nil {
		t.Fatalf("create department: %v", err)
	}

	start := make(chan struct{})
	errs := make(chan error, 2)
	var wg sync.WaitGroup
	for i := 0; i < 2; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			<-start
			_, err := repo.LinkEmployee(ctx, actor, workforce.EmployeeProfileInput{
				UserID: target, DepartmentID: department.DepartmentID, Title: "Engineer",
			}, "req_wf_concurrent_link")
			errs <- err
		}()
	}
	close(start)
	wg.Wait()
	close(errs)
	successes, conflicts := 0, 0
	for err := range errs {
		switch {
		case err == nil:
			successes++
		case errors.Is(err, workforce.ErrConflict):
			conflicts++
		case isSerializationFailure(err):
			// Serializable isolation can reject the loser before the PK unique
			// check. It is still a single-winner result and callers retry safely.
			conflicts++
		default:
			t.Fatalf("unexpected concurrent link error: %v", err)
		}
	}
	if successes != 1 || conflicts != 1 {
		t.Fatalf("successes=%d conflicts=%d, want 1/1", successes, conflicts)
	}
}

func testDepartmentCycleAndNonEmptyDeleteAreRejected(t *testing.T, repo *WorkforceRepository, users *UserRepository, actor identity.UserID) {
	ctx := context.Background()
	target := createWorkforceUser(t, users, "user_wf_dept_member", "Department Member")
	root, err := repo.CreateDepartment(ctx, actor, workforce.DepartmentInput{Name: "Root"}, "req_root")
	if err != nil {
		t.Fatalf("create root: %v", err)
	}
	child, err := repo.CreateDepartment(ctx, actor, workforce.DepartmentInput{
		Name: "Child", ParentDepartmentID: root.DepartmentID,
	}, "req_child")
	if err != nil {
		t.Fatalf("create child: %v", err)
	}
	parent := child.DepartmentID
	_, err = repo.UpdateDepartment(ctx, actor, root.DepartmentID,
		workforce.DepartmentPatch{ParentDepartmentID: &parent}, "req_cycle")
	if !errors.Is(err, workforce.ErrDepartmentCycle) {
		t.Fatalf("cycle update = %v, want ErrDepartmentCycle", err)
	}
	if err := repo.DeleteDepartment(ctx, actor, root.DepartmentID, "req_delete_parent"); !errors.Is(err, workforce.ErrDepartmentNotEmpty) {
		t.Fatalf("delete parent = %v, want ErrDepartmentNotEmpty", err)
	}
	if _, err := repo.LinkEmployee(ctx, actor, workforce.EmployeeProfileInput{
		UserID: target, DepartmentID: child.DepartmentID, Title: "Engineer",
	}, "req_member"); err != nil {
		t.Fatalf("link member: %v", err)
	}
	if err := repo.DeleteDepartment(ctx, actor, child.DepartmentID, "req_delete_member_department"); !errors.Is(err, workforce.ErrDepartmentNotEmpty) {
		t.Fatalf("delete member department = %v, want ErrDepartmentNotEmpty", err)
	}
}

func testLifecycleClearsAssignmentsAndCommitsCleanup(t *testing.T, repo *WorkforceRepository, users *UserRepository, actor identity.UserID) {
	ctx := context.Background()
	target := createWorkforceUser(t, users, "user_wf_offboard_target", "Offboarding Target")
	subordinate := createWorkforceUser(t, users, "user_wf_offboard_subordinate", "Offboarding Subordinate")
	department, err := repo.CreateDepartment(ctx, actor, workforce.DepartmentInput{Name: "Offboarding"}, "req_offboard_department")
	if err != nil {
		t.Fatalf("create department: %v", err)
	}
	if _, err := repo.LinkEmployee(ctx, actor, workforce.EmployeeProfileInput{
		UserID: target, DepartmentID: department.DepartmentID, Title: "Engineer",
	}, "req_offboard_link"); err != nil {
		t.Fatalf("link employee: %v", err)
	}
	ownedDepartment, err := repo.CreateDepartment(ctx, actor, workforce.DepartmentInput{
		Name: "Owned Before Offboarding", OwnerUserID: target,
	}, "req_offboard_owned_department")
	if err != nil {
		t.Fatalf("create owned department: %v", err)
	}
	if _, err := repo.LinkEmployee(ctx, actor, workforce.EmployeeProfileInput{
		UserID: subordinate, DepartmentID: department.DepartmentID, Title: "Engineer",
		SupervisorUserID: target,
	}, "req_offboard_subordinate"); err != nil {
		t.Fatalf("link subordinate: %v", err)
	}
	subordinateOwned, err := repo.CreateDepartment(ctx, actor, workforce.DepartmentInput{
		Name: "Owned Before Disable", OwnerUserID: subordinate,
	}, "req_disable_owned_department")
	if err != nil {
		t.Fatalf("create subordinate owned department: %v", err)
	}
	profile, job, err := repo.OffboardEmployee(ctx, actor, target, "req_offboard")
	if err != nil {
		t.Fatalf("offboard employee: %v", err)
	}
	if profile.Status != workforce.EmployeeStatusOffboarding || profile.OffboardedAt == nil {
		t.Fatalf("offboarding profile = %+v", profile)
	}
	if job.UserID != target || job.Reason != workforce.RevocationEmployeeOffboarded {
		t.Fatalf("cleanup job = %+v", job)
	}
	ownedDetail, err := repo.GetDepartment(ctx, ownedDepartment.DepartmentID)
	if err != nil || ownedDetail.OwnerUserID != "" {
		t.Fatalf("owned department after offboarding = %+v err=%v, want owner cleared", ownedDetail, err)
	}
	subordinateProfile, err := repo.GetEmployeeProfile(ctx, subordinate)
	if err != nil || subordinateProfile.SupervisorUserID != "" {
		t.Fatalf("subordinate after offboarding = %+v err=%v, want supervisor cleared", subordinateProfile, err)
	}
	pending, err := repo.ListPendingAccessRevocations(ctx, 10)
	if err != nil || len(pending) != 1 || pending[0].JobID != job.JobID {
		t.Fatalf("pending jobs = %+v err=%v", pending, err)
	}
	var eventCount int
	if err := repo.pool.QueryRow(ctx,
		`SELECT COUNT(*) FROM security_events
		  WHERE event_type = 'employee.offboarded'
		    AND payload->>'employee_user_id' = $1`, string(target)).Scan(&eventCount); err != nil {
		t.Fatalf("query offboarding audit: %v", err)
	}
	if eventCount != 1 {
		t.Fatalf("offboarding audit count = %d, want 1", eventCount)
	}
	if err := repo.ResolveAccessRevocation(ctx, job, 2, ""); err != nil {
		t.Fatalf("resolve cleanup job: %v", err)
	}
	pending, err = repo.ListPendingAccessRevocations(ctx, 10)
	if err != nil || len(pending) != 0 {
		t.Fatalf("pending after resolve = %+v err=%v", pending, err)
	}
	disableJob, err := repo.ChangeUserStatus(ctx, workforce.UserStatusMutation{
		ActorUserID: actor, TargetUserID: subordinate, Status: identity.UserStatusDisabled,
		RequestID: "req_disable_subordinate",
	})
	if err != nil || disableJob != nil {
		t.Fatalf("disable subordinate job=%+v err=%v", disableJob, err)
	}
	subordinateOwnedDetail, err := repo.GetDepartment(ctx, subordinateOwned.DepartmentID)
	if err != nil || subordinateOwnedDetail.OwnerUserID != "" {
		t.Fatalf("owned department after disable = %+v err=%v, want owner cleared", subordinateOwnedDetail, err)
	}
}

func testWorkforceCursorBindsQueryState(t *testing.T, repo *WorkforceRepository) {
	ctx := context.Background()
	page, err := repo.ListUsers(ctx, workforce.UserListQuery{Limit: 2, Sort: "displayName"})
	if err != nil {
		t.Fatalf("list first page: %v", err)
	}
	if !page.HasMore || page.NextCursor == "" || len(page.Items) != 2 {
		t.Fatalf("first page = %+v", page)
	}
	_, err = repo.ListUsers(ctx, workforce.UserListQuery{
		Limit: 2, Sort: "displayName", Query: "different", Cursor: page.NextCursor,
	})
	if !errors.Is(err, workforce.ErrInvalidCursor) {
		t.Fatalf("cursor replay with changed query = %v, want ErrInvalidCursor", err)
	}
}

func isSerializationFailure(err error) bool {
	return err != nil && (errors.Is(err, context.DeadlineExceeded) ||
		strings.Contains(err.Error(), "SQLSTATE 40001"))
}
