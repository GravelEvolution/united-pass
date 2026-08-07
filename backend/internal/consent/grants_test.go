package consent

import (
	"strings"
	"testing"
)

func TestConsentIDPrefixes(t *testing.T) {
	if id := NewGrantID(); !strings.HasPrefix(string(id), grantIDPrefix) || len(id) <= len(grantIDPrefix) {
		t.Fatalf("bad grant id: %q", id)
	}
	if id := NewDecisionOperationID(); !strings.HasPrefix(string(id), decisionOperationIDPrefix) || len(id) <= len(decisionOperationIDPrefix) {
		t.Fatalf("bad decision operation id: %q", id)
	}
	if NewGrantID() == NewGrantID() {
		t.Fatal("grant ids must be unique")
	}
	if NewDecisionOperationID() == NewDecisionOperationID() {
		t.Fatal("decision operation ids must be unique")
	}
}

func TestDecisionValid(t *testing.T) {
	for _, decision := range []Decision{DecisionAllow, DecisionDeny} {
		if !decision.Valid() {
			t.Fatalf("decision %q must be valid", decision)
		}
	}
	for _, decision := range []Decision{"", "maybe", "ALLOW"} {
		if decision.Valid() {
			t.Fatalf("decision %q must be invalid", decision)
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
	if err := (DecisionOperationKey{Provider: "zitadel"}).Validate(); err == nil {
		t.Fatal("empty auth request id must be rejected")
	}
	if err := (DecisionOperationKey{Provider: "zitadel", AuthRequestID: strings.Repeat("x", MaxAuthRequestIDLen+1)}).Validate(); err == nil {
		t.Fatal("oversized auth request id must be rejected")
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
