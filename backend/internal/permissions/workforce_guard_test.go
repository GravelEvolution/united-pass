//
// Copyright (c) 2026 Chen Jiajie(Ariakage)
//
// Author: Chen Jiajie(Ariakage) <ariakage233@gmail.com>
// Date: 2026-08-11
// Description: Mandatory Phase 5 offboarding authorization deny tests
//

package permissions

import (
	"context"
	"errors"
	"testing"

	"github.com/GravelEvolution/united-pass/backend/internal/identity"
	"github.com/GravelEvolution/united-pass/backend/internal/workforce"
)

type guardReader struct {
	profile workforce.EmployeeProfile
	err     error
}

func (r guardReader) GetEmployeeProfile(context.Context, identity.UserID) (workforce.EmployeeProfile, error) {
	return r.profile, r.err
}

type allowResolver struct{}

func (allowResolver) Resolve(context.Context, identity.UserID) (Capabilities, error) {
	return AllCapabilities(), nil
}

func TestWorkforceGuardDeniesOffboardingBeforeBaseAllow(t *testing.T) {
	resolver := NewWorkforceGuardResolver(allowResolver{}, guardReader{
		profile: workforce.EmployeeProfile{Status: workforce.EmployeeStatusOffboarding},
	})
	caps, err := resolver.Resolve(context.Background(), "user_offboarding")
	if err != nil {
		t.Fatalf("Resolve: %v", err)
	}
	if caps != NoCapabilities() {
		t.Fatalf("offboarding capabilities = %+v, want fail-closed", caps)
	}
}

func TestWorkforceGuardPreservesBaseForConsumerOrActiveEmployee(t *testing.T) {
	for _, reader := range []guardReader{
		{err: workforce.ErrNotFound},
		{profile: workforce.EmployeeProfile{Status: workforce.EmployeeStatusActive}},
	} {
		resolver := NewWorkforceGuardResolver(allowResolver{}, reader)
		caps, err := resolver.Resolve(context.Background(), "user_allowed")
		if err != nil || !caps.UserRead || !caps.EmployeeManage {
			t.Fatalf("caps=%+v err=%v, want base allow", caps, err)
		}
	}
}

func TestWorkforceGuardFailsClosedOnRepositoryError(t *testing.T) {
	resolver := NewWorkforceGuardResolver(allowResolver{}, guardReader{err: errors.New("database unavailable")})
	caps, err := resolver.Resolve(context.Background(), "user_error")
	if err == nil || caps != NoCapabilities() {
		t.Fatalf("caps=%+v err=%v, want closed + error", caps, err)
	}
}
