package consent

import (
	"strings"
	"testing"

	"github.com/GravelEvolution/united-pass/backend/internal/applications"
	"github.com/GravelEvolution/united-pass/backend/internal/identity"
)

func TestNormalizeScopes(t *testing.T) {
	// Duplicates are removed and the result deterministically sorted.
	got, err := NormalizeScopes([]string{"profile", "openid", "profile", "email"})
	if err != nil {
		t.Fatalf("normalize: %v", err)
	}
	if len(got) != 3 || got[0] != "email" || got[1] != "openid" || got[2] != "profile" {
		t.Fatalf("unexpected normalized set: %+v", got)
	}
	// An empty input normalizes to an empty set (callers decide whether
	// that is legal for their kind).
	if empty, err := NormalizeScopes(nil); err != nil || len(empty) != 0 {
		t.Fatalf("empty normalize: %v %v", empty, err)
	}

	rejected := [][]string{
		{""},
		{"", ""},
		{"openid", ""},
		{" "},
		{"open id"},
		{"openid\t"},
		{"\nopenid"},
		{strings.Repeat("s", MaxScopeTokenLen+1)},
	}
	for _, scopes := range rejected {
		if _, err := NormalizeScopes(scopes); err == nil {
			t.Fatalf("scopes %q must be rejected", scopes)
		}
	}

	overflow := make([]string, MaxScopeCount+1)
	for i := range overflow {
		overflow[i] = "scope"
	}
	if _, err := NormalizeScopes(overflow); err == nil {
		t.Fatalf("more than %d scopes must be rejected", MaxScopeCount)
	}
	// Exactly at the limit is fine (duplicates collapse below it).
	atLimit := make([]string, MaxScopeCount)
	for i := range atLimit {
		atLimit[i] = "scope"
	}
	if _, err := NormalizeScopes(atLimit); err != nil {
		t.Fatalf("duplicate set at the limit must normalize: %v", err)
	}
}

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

func TestCompletionKindAuditMapping(t *testing.T) {
	// Allow is the only success; everything else audits as denied.
	if CompletionAllow.AuditEventType() != applications.EventConsentGrantAllowed ||
		CompletionAllow.AuditOperation() != "consent_allow" ||
		CompletionAllow.AuditResult() != applications.SecurityEventSuccess ||
		CompletionAllow.AuditFailureClass() != "" {
		t.Fatalf("allow audit mapping wrong: %q %q %q %q",
			CompletionAllow.AuditEventType(), CompletionAllow.AuditOperation(),
			CompletionAllow.AuditResult(), CompletionAllow.AuditFailureClass())
	}
	if CompletionAccessDenied.AuditEventType() != applications.EventConsentAccessDenied ||
		CompletionAccessDenied.AuditOperation() != "consent_deny" ||
		CompletionAccessDenied.AuditResult() != applications.SecurityEventDenied ||
		CompletionAccessDenied.AuditFailureClass() != "" {
		t.Fatalf("deny audit mapping wrong: %q %q %q %q",
			CompletionAccessDenied.AuditEventType(), CompletionAccessDenied.AuditOperation(),
			CompletionAccessDenied.AuditResult(), CompletionAccessDenied.AuditFailureClass())
	}
	// Error callbacks share the error-completion event type, and the kind
	// itself is the failure class distinguishing them in the payload.
	for _, kind := range []CompletionKind{
		CompletionLoginRequired, CompletionConsentRequired,
		CompletionAccountSelectionNeeded, CompletionRequestNotSupported,
		CompletionServerError, CompletionTemporarilyUnavailable,
	} {
		if kind.AuditEventType() != applications.EventConsentErrorCompleted ||
			kind.AuditOperation() != "consent_error_completion" ||
			kind.AuditResult() != applications.SecurityEventDenied ||
			kind.AuditFailureClass() != string(kind) {
			t.Fatalf("kind %q audit mapping wrong: %q %q %q %q", kind,
				kind.AuditEventType(), kind.AuditOperation(),
				kind.AuditResult(), kind.AuditFailureClass())
		}
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
		{"allow with empty-string scope", func(op *DecisionOperation) { op.Scopes = []string{""} }},
		{"allow with only empty-string scopes", func(op *DecisionOperation) { op.Scopes = []string{"", ""} }},
		{"allow with whitespace scope", func(op *DecisionOperation) { op.Scopes = []string{"open id"} }},
		{"allow with oversized scope token", func(op *DecisionOperation) {
			op.Scopes = []string{strings.Repeat("s", MaxScopeTokenLen+1)}
		}},
		{"allow with too many scopes", func(op *DecisionOperation) {
			scopes := make([]string, MaxScopeCount+1)
			for i := range scopes {
				scopes[i] = "scope-" + strings.Repeat("x", i%7)
			}
			op.Scopes = scopes
		}},
		{"deny with scopes", func(op *DecisionOperation) {
			op.CompletionKind = CompletionAccessDenied
			op.Scopes = []string{"openid"}
		}},
	}
	for _, tc := range cases {
		op := allowOperation("V2-1")
		tc.mutate(&op)
		if err := op.ValidateForClaim(); err == nil {
			t.Fatalf("%s: must be rejected", tc.name)
		}
	}

	// Duplicates with valid scopes normalize fine (validation passes on
	// the normalized set).
	dupes := allowOperation("V2-1")
	dupes.Scopes = []string{"profile", "openid", "profile"}
	if err := dupes.ValidateForClaim(); err != nil {
		t.Fatalf("duplicate scopes must normalize and validate: %v", err)
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
