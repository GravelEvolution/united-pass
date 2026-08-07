package consent

import (
	"strings"
	"testing"

	"github.com/GravelEvolution/united-pass/backend/internal/applications"
	"github.com/GravelEvolution/united-pass/backend/internal/identity"
)

func TestConsentIDPrefixes(t *testing.T) {
	if id := NewGrantID(); !strings.HasPrefix(string(id), grantIDPrefix) || len(id) <= len(grantIDPrefix) {
		t.Fatalf("bad grant id: %q", id)
	}
	if id := NewDecisionOperationID(); !HasDecisionOperationIDPrefix(string(id)) || len(id) <= len(decisionOperationIDPrefix) {
		t.Fatalf("bad decision operation id: %q", id)
	}
	if NewGrantID() == NewGrantID() {
		t.Fatal("grant ids must be unique")
	}
	if NewDecisionOperationID() == NewDecisionOperationID() {
		t.Fatal("decision operation ids must be unique")
	}
	if HasDecisionOperationIDPrefix("") || HasDecisionOperationIDPrefix("dop_") || HasDecisionOperationIDPrefix("op_x") {
		t.Fatal("prefix check must reject malformed ids")
	}
}

func TestCompletionKindSemantics(t *testing.T) {
	all := []CompletionKind{
		CompletionAllow, CompletionAccessDenied, CompletionLoginRequired,
		CompletionConsentRequired, CompletionAccountSelectionNeeded,
		CompletionRequestNotSupported, CompletionServerError,
		CompletionTemporarilyUnavailable,
	}
	for _, kind := range all {
		if !kind.Valid() {
			t.Fatalf("kind %q must be valid", kind)
		}
	}
	for _, kind := range []CompletionKind{"", "deny", "ALLOW", "create"} {
		if kind.Valid() {
			t.Fatalf("kind %q must be invalid", kind)
		}
	}

	if !CompletionAllow.IsUserDecision() || !CompletionAccessDenied.IsUserDecision() {
		t.Fatal("allow and access_denied are user decisions")
	}
	for _, kind := range all[2:] {
		if kind.IsUserDecision() {
			t.Fatalf("kind %q is an error callback, not a user decision", kind)
		}
	}

	if !CompletionAllow.CreatesGrant() {
		t.Fatal("only allow creates grants")
	}
	for _, kind := range all[1:] {
		if kind.CreatesGrant() {
			t.Fatalf("kind %q must never create a grant", kind)
		}
	}

	// Every non-allow kind maps to its provider error-callback reason.
	wantReasons := map[CompletionKind]CallbackErrorReason{
		CompletionAccessDenied:           ReasonAccessDenied,
		CompletionLoginRequired:          ReasonLoginRequired,
		CompletionConsentRequired:        ReasonConsentRequired,
		CompletionAccountSelectionNeeded: ReasonAccountSelectionRequired,
		CompletionRequestNotSupported:    ReasonRequestNotSupported,
		CompletionServerError:            ReasonServerError,
		CompletionTemporarilyUnavailable: ReasonTemporarilyUnavailable,
	}
	for kind, want := range wantReasons {
		reason, ok := kind.CallbackReason()
		if !ok || reason != want {
			t.Fatalf("kind %q reason = %v, %v; want %v", kind, reason, ok, want)
		}
	}
	if _, ok := CompletionAllow.CallbackReason(); ok {
		t.Fatal("allow completes with a session, never an error callback")
	}
}

func TestDecisionOperationStatusInFlight(t *testing.T) {
	inFlight := []DecisionOperationStatus{
		DecisionOperationPending,
		DecisionOperationProviderSucceeded,
	}
	for _, status := range inFlight {
		if !status.InFlight() {
			t.Fatalf("status %q must be in flight", status)
		}
	}
	terminal := []DecisionOperationStatus{
		DecisionOperationSucceeded,
		DecisionOperationFailed,
	}
	for _, status := range terminal {
		if status.InFlight() {
			t.Fatalf("status %q must be terminal", status)
		}
	}
}

func TestDecisionOperationKeyValidate(t *testing.T) {
	valid := DecisionOperationKey{Provider: "zitadel", AuthRequestID: "V2-1"}
	if err := valid.Validate(); err != nil {
		t.Fatalf("valid key rejected: %v", err)
	}
	if err := (DecisionOperationKey{AuthRequestID: "V2-1"}).Validate(); err == nil {
		t.Fatal("empty provider must be rejected")
	}
	if err := (DecisionOperationKey{Provider: strings.Repeat("p", MaxProviderNameLen+1), AuthRequestID: "V2-1"}).Validate(); err == nil {
		t.Fatal("oversized provider must be rejected")
	}
	if err := (DecisionOperationKey{Provider: "zitadel"}).Validate(); err == nil {
		t.Fatal("empty auth request id must be rejected")
	}
	if err := (DecisionOperationKey{Provider: "zitadel", AuthRequestID: strings.Repeat("x", MaxAuthRequestIDLen+1)}).Validate(); err == nil {
		t.Fatal("oversized auth request id must be rejected")
	}
}

func allowOperation(authRequestID string) DecisionOperation {
	return DecisionOperation{
		ID:             NewDecisionOperationID(),
		Provider:       "zitadel",
		AuthRequestID:  authRequestID,
		CompletionKind: CompletionAllow,
		LocalUserID:    identity.UserID("user-1"),
		ClientID:       applications.OAuthClientID("clt_1"),
		Scopes:         []string{"openid"},
	}
}

func TestValidateForClaimEnforcesCompletionPlans(t *testing.T) {
	if err := allowOperation("V2-1").ValidateForClaim(); err != nil {
		t.Fatalf("valid allow plan rejected: %v", err)
	}

	cases := []struct {
		name   string
		mutate func(*DecisionOperation)
	}{
		{"missing operation id", func(op *DecisionOperation) { op.ID = "" }},
		{"foreign operation id", func(op *DecisionOperation) { op.ID = DecisionOperationID("op_foreign123") }},
		{"missing provider", func(op *DecisionOperation) { op.Provider = "" }},
		{"unknown kind", func(op *DecisionOperation) { op.CompletionKind = CompletionKind("deny") }},
		{"allow without user", func(op *DecisionOperation) { op.LocalUserID = "" }},
		{"allow without client", func(op *DecisionOperation) { op.ClientID = "" }},
		{"allow without scopes", func(op *DecisionOperation) { op.Scopes = nil }},
	}
	for _, tc := range cases {
		op := allowOperation("V2-1")
		tc.mutate(&op)
		if err := op.ValidateForClaim(); err == nil {
			t.Fatalf("%s: must be rejected", tc.name)
		}
	}

	// Deny binds the acting user but needs no scope snapshot.
	deny := allowOperation("V2-2")
	deny.CompletionKind = CompletionAccessDenied
	deny.Scopes = nil
	if err := deny.ValidateForClaim(); err != nil {
		t.Fatalf("valid deny plan rejected: %v", err)
	}
	deny.LocalUserID = ""
	if err := deny.ValidateForClaim(); err == nil {
		t.Fatal("deny without user must be rejected")
	}

	// Error callbacks tolerate a missing user (no session) but must never
	// carry a scope snapshot.
	gateway := allowOperation("V2-3")
	gateway.CompletionKind = CompletionLoginRequired
	gateway.LocalUserID = ""
	gateway.ClientID = ""
	gateway.Scopes = nil
	if err := gateway.ValidateForClaim(); err != nil {
		t.Fatalf("valid session-less error callback rejected: %v", err)
	}
	gateway.Scopes = []string{"openid"}
	if err := gateway.ValidateForClaim(); err == nil {
		t.Fatal("error callback with scopes must be rejected")
	}
}

func TestErrorClassValid(t *testing.T) {
	known := []ErrorClass{
		ClassNotFound, ClassExpired, ClassAlreadyCompleted, ClassInvalidRedirect,
		ClassInvalidScope, ClassProviderConflict, ClassProviderUnavailable,
		ClassRateLimited, ClassInternal, ClassUserNotEligible,
	}
	for _, class := range known {
		if !class.Valid() {
			t.Fatalf("class %q must be valid", class)
		}
	}
	for _, class := range []ErrorClass{"", "denied", "SERVER_ERROR"} {
		if class.Valid() {
			t.Fatalf("class %q must be invalid", class)
		}
	}
}

func TestGrantScopeContainment(t *testing.T) {
	grant := Grant{Scopes: []string{"openid", "profile"}}
	if !grant.HasScope("openid") || grant.HasScope("email") {
		t.Fatal("HasScope mismatch")
	}
	if !grant.ScopesContain([]string{"openid"}) || !grant.ScopesContain(nil) {
		t.Fatal("subset must be contained")
	}
	if grant.ScopesContain([]string{"openid", "offline_access"}) {
		t.Fatal("superset must not be contained")
	}
}
