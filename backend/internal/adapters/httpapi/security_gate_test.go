//
// Copyright (c) 2026 Chen Jiajie(Ariakage)
//
// Author: Chen Jiajie(Ariakage) <ariakage233@gmail.com>
// Date: 2026-08-06
// Description: Unit tests for the sensitive-consumption gate on grants and enrollments (ADR-0007 B3, Decision 5)
//

package httpapi

import (
	"context"
	"errors"
	"net/http"
	"testing"
	"time"

	"github.com/GravelEvolution/united-pass/backend/internal/applications"
	"github.com/GravelEvolution/united-pass/backend/internal/auth"
	"github.com/GravelEvolution/united-pass/backend/internal/identity"
	"github.com/GravelEvolution/united-pass/backend/internal/securitystate"
	"github.com/GravelEvolution/united-pass/backend/internal/session"
)

// fakeConsumptionGate is a configurable SensitiveConsumptionGate.
type fakeConsumptionGate struct {
	err error
}

func (g *fakeConsumptionGate) AllowSensitiveConsumption(context.Context, identity.UserID, securitystate.Epoch) error {
	return g.err
}

// TestReauthGrants_SecurityGate covers B3 on grants: a stale epoch stamp or
// a non-terminal mutation intent denies the sensitive consumption fail
// closed, and the grant is consumed either way (no replay after denial).
func TestReauthGrants_SecurityGate(t *testing.T) {
	cases := []struct {
		name    string
		gateErr error
	}{
		{"stale epoch stamp burns the grant", securitystate.ErrEpochStale},
		{"non-terminal mutation intent denies", securitystate.ErrBarrierHeld},
		{"lookup failure fails closed", errors.New("pg down")},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			grants := newMemReauthGrants()
			verifier := NewReauthGrants(grants, &fakeConsumptionGate{err: tc.gateErr})
			ctx := context.Background()

			data := auth.ReauthGrantData{
				UserID:        "user_actor",
				SessionID:     "sess-1",
				Action:        "client.secret.rotate",
				ApplicationID: "app_test1",
				ClientID:      "clt_test1",
				CreatedAt:     time.Now().UTC(),
				SecurityEpoch: 1,
			}
			if err := grants.CreateGrant(ctx, session.HashToken("tok-gate"), data, time.Minute); err != nil {
				t.Fatalf("create grant: %v", err)
			}

			err := verifier.VerifyAndConsume(ctx, "tok-gate", "client.secret.rotate", "sess-1", "", "app_test1", "clt_test1")
			if !errors.Is(err, tc.gateErr) {
				t.Fatalf("gate err = %v, want %v", err, tc.gateErr)
			}
			// The denial consumed the grant: it can never be replayed.
			if err := verifier.VerifyAndConsume(ctx, "tok-gate", "client.secret.rotate", "sess-1", "", "app_test1", "clt_test1"); !errors.Is(err, auth.ErrReauthGrantNotFound) {
				t.Fatalf("replay err = %v, want ErrReauthGrantNotFound", err)
			}
		})
	}

	t.Run("healthy state allows consumption", func(t *testing.T) {
		grants := newMemReauthGrants()
		verifier := NewReauthGrants(grants, &fakeConsumptionGate{})
		ctx := context.Background()
		data := auth.ReauthGrantData{
			UserID:        "user_actor",
			SessionID:     "sess-1",
			Action:        "client.secret.rotate",
			ApplicationID: "app_test1",
			ClientID:      "clt_test1",
			CreatedAt:     time.Now().UTC(),
			SecurityEpoch: 2,
		}
		if err := grants.CreateGrant(ctx, session.HashToken("tok-ok"), data, time.Minute); err != nil {
			t.Fatalf("create grant: %v", err)
		}
		if err := verifier.VerifyAndConsume(ctx, "tok-ok", "client.secret.rotate", "sess-1", "", applications.ApplicationID("app_test1"), applications.OAuthClientID("clt_test1")); err != nil {
			t.Fatalf("consumption err = %v, want nil", err)
		}
	})
}

// TestConfirmTOTPEnrollment_SecurityGate covers B3 on enrollments: a stale
// stamp burns the enrollment (authoritative permanent death), while a
// non-terminal mutation intent releases the claim so the confirmation stays
// retryable after settlement.
func TestConfirmTOTPEnrollment_SecurityGate(t *testing.T) {
	// The gate starts healthy so the begin ceremony (which itself consumes a
	// reauth grant) can mint the enrollment; the denial is armed right before
	// the confirmation.
	newGatedEnv := func() (*securityEnv, *fakeConsumptionGate) {
		factors := &fakeFactorManager{}
		grants := newMemReauthGrants()
		enroll := newMemEnrollments()
		gate := &fakeConsumptionGate{}
		handlers := NewSecurityHandlers(factors, NewReauthGrants(grants, gate), enroll, gate, 5*time.Minute, discardLogger())
		return &securityEnv{handlers: handlers, factors: factors, grants: grants, enroll: enroll}, gate
	}

	t.Run("stale epoch stamp burns the enrollment permanently", func(t *testing.T) {
		env, gate := newGatedEnv()
		token := totpBegin(t, env)
		gate.err = securitystate.ErrEpochStale

		rec := doSecurityJSON(t, env.router(true), http.MethodPost, "/me/security/totp/enrollment/confirm",
			`{"enrollmentToken":"`+token+`","code":"123456"}`, nil)
		if rec.Code != http.StatusForbidden {
			t.Fatalf("status = %d, want 403; body=%s", rec.Code, rec.Body.String())
		}
		if body := decodeErrorBody(t, rec); body.Code != CodeEnrollmentInvalid {
			t.Errorf("code = %q, want %q", body.Code, CodeEnrollmentInvalid)
		}
		if env.enroll.size() != 0 {
			t.Fatal("a stale stamp must consume the enrollment (permanent death)")
		}
		if len(env.factors.confirmTOTPCodes) != 0 {
			t.Fatal("the provider must never be called after a gate denial")
		}
	})

	t.Run("barrier-held releases the claim for retry after settlement", func(t *testing.T) {
		env, gate := newGatedEnv()
		token := totpBegin(t, env)
		gate.err = securitystate.ErrBarrierHeld

		rec := doSecurityJSON(t, env.router(true), http.MethodPost, "/me/security/totp/enrollment/confirm",
			`{"enrollmentToken":"`+token+`","code":"123456"}`, nil)
		if rec.Code != http.StatusForbidden {
			t.Fatalf("status = %d, want 403; body=%s", rec.Code, rec.Body.String())
		}
		if env.enroll.size() != 1 {
			t.Fatal("a non-terminal intent must release the claim, keeping the enrollment retryable")
		}
		if len(env.factors.confirmTOTPCodes) != 0 {
			t.Fatal("the provider must never be called after a gate denial")
		}
	})
}
