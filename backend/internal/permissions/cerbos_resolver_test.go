package permissions

import (
	"context"
	"errors"
	"fmt"
	"testing"

	"github.com/GravelEvolution/united-pass/backend/internal/adapters/cerbos"
	"github.com/GravelEvolution/united-pass/backend/internal/identity"
	"github.com/GravelEvolution/united-pass/backend/internal/policies"
)

type principalStub struct{ err error }

func (s principalStub) GetPermissionPrincipal(context.Context, identity.UserID) (PrincipalContext, error) {
	return PrincipalContext{Roles: []string{"employee"}, Attributes: map[string]any{"department": "Identity"}}, s.err
}

type policyReaderStub struct {
	byAction map[string][]policies.PublishedPolicy
	err      error
}

func (s policyReaderStub) ListPublished(_ context.Context, action, _ string) ([]policies.PublishedPolicy, error) {
	return s.byAction[action], s.err
}

type decisionStub struct {
	allowed   map[policies.PolicyID]bool
	err       error
	principal cerbos.Principal
	calls     int
	maxBatch  int
}

func (s *decisionStub) Check(_ context.Context, _ string, principal cerbos.Principal, checks []cerbos.ResourceCheck) ([]cerbos.Decision, error) {
	s.principal = principal
	s.calls++
	if len(checks) > s.maxBatch {
		s.maxBatch = len(checks)
	}
	if s.err != nil {
		return nil, s.err
	}
	result := make([]cerbos.Decision, 0, len(checks))
	for _, check := range checks {
		result = append(result, cerbos.Decision{PolicyID: check.PolicyID, Allowed: s.allowed[check.PolicyID]})
	}
	return result, nil
}

func TestCerbosResolverRequiresAllowAndAppliesExplicitDeny(t *testing.T) {
	allow := policies.PublishedPolicy{PolicyID: "pol_allow", Effect: policies.EffectAllow, Version: 1}
	deny := policies.PublishedPolicy{PolicyID: "pol_deny", Effect: policies.EffectDeny, Version: 1}
	reader := policyReaderStub{byAction: map[string][]policies.PublishedPolicy{"application.manage": {allow, deny}, "audit.read": {allow}}}
	client := &decisionStub{allowed: map[policies.PolicyID]bool{"pol_allow": true, "pol_deny": false}}
	resolver := NewCerbosResolver(principalStub{}, reader, client)
	caps, err := resolver.Resolve(context.Background(), "user_1")
	if err != nil {
		t.Fatal(err)
	}
	if caps.ApplicationManage {
		t.Fatal("explicit deny must override matched allow")
	}
	if !caps.AuditRead {
		t.Fatal("matched allow should grant capability")
	}
	if caps.PolicyRead {
		t.Fatal("absence of published allow must deny")
	}
	if client.principal.Attributes["department"] != "Identity" {
		t.Fatal("authoritative principal attributes were not forwarded")
	}
}

func TestCerbosResolverFailsClosedOnDecisionError(t *testing.T) {
	resolver := NewCerbosResolver(principalStub{}, policyReaderStub{byAction: map[string][]policies.PublishedPolicy{"audit.read": {{PolicyID: "pol_allow", Effect: policies.EffectAllow, Version: 1}}}}, &decisionStub{err: errors.New("down")})
	caps, err := resolver.Resolve(context.Background(), "user_1")
	if err == nil {
		t.Fatal("expected error")
	}
	if caps != NoCapabilities() {
		t.Fatalf("caps=%#v", caps)
	}
}

func TestCerbosResolverBoundsCheckResourcesBatches(t *testing.T) {
	published := make([]policies.PublishedPolicy, 0, maxCerbosChecksPerRequest+1)
	allowed := make(map[policies.PolicyID]bool, maxCerbosChecksPerRequest+1)
	for index := 0; index <= maxCerbosChecksPerRequest; index++ {
		id := policies.PolicyID(fmt.Sprintf("pol_%016d", index))
		published = append(published, policies.PublishedPolicy{PolicyID: id, Effect: policies.EffectAllow, Version: 1})
		allowed[id] = true
	}
	client := &decisionStub{allowed: allowed}
	resolver := NewCerbosResolver(principalStub{}, policyReaderStub{byAction: map[string][]policies.PublishedPolicy{"audit.read": published}}, client)
	caps, err := resolver.Resolve(context.Background(), "user_1")
	if err != nil {
		t.Fatal(err)
	}
	if !caps.AuditRead || client.calls != 2 || client.maxBatch != maxCerbosChecksPerRequest {
		t.Fatalf("caps=%#v calls=%d maxBatch=%d", caps, client.calls, client.maxBatch)
	}
}
