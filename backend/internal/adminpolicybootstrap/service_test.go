package adminpolicybootstrap

import (
	"context"
	"errors"
	"fmt"
	"slices"
	"testing"

	"github.com/GravelEvolution/united-pass/backend/internal/adapters/cerbos"
	"github.com/GravelEvolution/united-pass/backend/internal/adminroles"
	"github.com/GravelEvolution/united-pass/backend/internal/identity"
	"github.com/GravelEvolution/united-pass/backend/internal/permissions"
	"github.com/GravelEvolution/united-pass/backend/internal/policies"
)

type catalogPrincipalReader struct{}

func (catalogPrincipalReader) GetPermissionPrincipal(context.Context, identity.UserID) (permissions.PrincipalContext, error) {
	return permissions.PrincipalContext{Roles: []string{"authenticated"}, Attributes: map[string]any{}}, nil
}

type catalogPolicyReader struct {
	registered map[string]string
}

func (r *catalogPolicyReader) ListPublished(_ context.Context, action, resource string) ([]policies.PublishedPolicy, error) {
	if r.registered == nil {
		r.registered = make(map[string]string)
	}
	r.registered[action] = resource
	return nil, nil
}

type unusedDecisionClient struct{}

func (unusedDecisionClient) Check(context.Context, string, cerbos.Principal, []cerbos.ResourceCheck) ([]cerbos.Decision, error) {
	panic("no published policy means the PDP must not be called")
}

func TestFixedCapabilityCatalogMatchesPermissionResolverCatalog(t *testing.T) {
	reader := &catalogPolicyReader{}
	resolver := permissions.NewCerbosResolver(catalogPrincipalReader{}, reader, unusedDecisionClient{})
	if _, err := resolver.Resolve(context.Background(), "user_catalog_check"); err != nil {
		t.Fatal(err)
	}

	fixed := make(map[string]struct{})
	for _, spec := range fixedPolicyCatalog() {
		if spec.kind != policyKindCapability {
			continue
		}
		if spec.input.Resource != "*" {
			t.Fatalf("capability %q resource = %q, want wildcard selector", spec.input.Action, spec.input.Resource)
		}
		fixed[spec.input.Action] = struct{}{}
	}
	if len(fixed) != len(reader.registered) {
		t.Fatalf("fixed capability count = %d, registered = %d; update the reviewed bootstrap catalog", len(fixed), len(reader.registered))
	}
	for action := range reader.registered {
		if _, ok := fixed[action]; !ok {
			t.Fatalf("registered capability %q is missing from the reviewed bootstrap catalog", action)
		}
	}
}

func TestServiceFailsClosedWhenDependenciesAreUnavailable(t *testing.T) {
	tests := []struct {
		name      string
		service   *Service
		wantError error
	}{
		{name: "repository", service: NewService(nil, bootstrapPublisherStub{}, bootstrapDecisionStub{}), wantError: ErrUnavailable},
		{name: "publisher", service: NewService(&bootstrapRepositoryStub{}, nil, bootstrapDecisionStub{}), wantError: ErrUnavailable},
		{name: "PDP", service: NewService(&bootstrapRepositoryStub{}, bootstrapPublisherStub{}, nil), wantError: ErrUnavailable},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			if err := test.service.Ensure(context.Background(), "user_operator", "req_policy_bootstrap"); !errors.Is(err, test.wantError) {
				t.Fatalf("Ensure error = %v, want %v", err, test.wantError)
			}
		})
	}
}

func TestEnsureCreatesPublishesAndReadsBackMissingPolicy(t *testing.T) {
	repository := newMemoryBootstrapRepository()
	publisher := &recordingBootstrapPublisher{}
	pdp := &roleAwareDecisionStub{}
	service := NewService(repository, publisher, pdp)
	service.catalog = []fixedPolicySpec{capabilityPolicy("audit.read")}

	if err := service.Ensure(context.Background(), "user_operator", "req_policy_bootstrap"); err != nil {
		t.Fatal(err)
	}
	if repository.createCalls != 1 || repository.beginCalls != 1 || repository.completeCalls != 1 {
		t.Fatalf("create=%d begin=%d complete=%d", repository.createCalls, repository.beginCalls, repository.completeCalls)
	}
	if len(publisher.policies) != 1 || publisher.policies[0].Action != "audit.read" || publisher.policies[0].Resource != "*" {
		t.Fatalf("published = %#v", publisher.policies)
	}
	if repository.lastActor != "user_operator" || repository.lastRequestID != "req_policy_bootstrap" {
		t.Fatalf("actor=%q request=%q", repository.lastActor, repository.lastRequestID)
	}
	if pdp.calls != 4 {
		t.Fatalf("PDP calls = %d, want super/senior/admin/non-admin readback", pdp.calls)
	}
}

func TestEnsureRecoversConcurrentSameStateCreation(t *testing.T) {
	repository := newMemoryBootstrapRepository()
	spec := capabilityPolicy("audit.read")
	repository.createErr = policies.ErrDuplicateName
	repository.createHook = func() {
		id := policies.PolicyID("pol_9999999999999999")
		repository.byName[spec.input.Name] = id
		repository.details[id] = detailFromInput(id, 1, policies.StatusDraft, spec.input)
	}
	service := NewService(repository, &recordingBootstrapPublisher{}, &roleAwareDecisionStub{})
	service.catalog = []fixedPolicySpec{spec}

	if err := service.Ensure(context.Background(), "user_operator", "req_concurrent"); err != nil {
		t.Fatal(err)
	}
	if repository.createCalls != 1 || repository.beginCalls != 1 || repository.completeCalls != 1 {
		t.Fatalf("create=%d begin=%d complete=%d", repository.createCalls, repository.beginCalls, repository.completeCalls)
	}
}

func TestEnsurePublishedSameStateOnlyPerformsReadback(t *testing.T) {
	repository := newMemoryBootstrapRepository()
	publisher := &recordingBootstrapPublisher{}
	pdp := &roleAwareDecisionStub{}
	service := NewService(repository, publisher, pdp)
	service.catalog = []fixedPolicySpec{capabilityPolicy("audit.read")}
	if err := service.Ensure(context.Background(), "user_operator", "req_first"); err != nil {
		t.Fatal(err)
	}
	create, begin, complete, publish := repository.createCalls, repository.beginCalls, repository.completeCalls, len(publisher.policies)

	if err := service.Ensure(context.Background(), "user_operator", "req_second"); err != nil {
		t.Fatal(err)
	}
	if repository.createCalls != create || repository.beginCalls != begin || repository.completeCalls != complete || len(publisher.policies) != publish {
		t.Fatalf("same state was mutated: create=%d begin=%d complete=%d publish=%d", repository.createCalls, repository.beginCalls, repository.completeCalls, len(publisher.policies))
	}
	if pdp.calls != 8 {
		t.Fatalf("PDP calls = %d, want a fresh four-principal readback on each run", pdp.calls)
	}
}

func TestEnsureRejectsPolicyDriftWithoutOverwrite(t *testing.T) {
	repository := newMemoryBootstrapRepository()
	spec := capabilityPolicy("audit.read")
	id := policies.PolicyID("pol_1234567890123456")
	drift := spec.input
	drift.Principals = append([]policies.Clause(nil), spec.input.Principals...)
	drift.Principals[0].Value = string(adminroles.RoleAdmin)
	repository.byName[spec.input.Name] = id
	repository.details[id] = detailFromInput(id, 1, policies.StatusPublished, drift)
	service := NewService(repository, &recordingBootstrapPublisher{}, &roleAwareDecisionStub{})
	service.catalog = []fixedPolicySpec{spec}

	if err := service.Ensure(context.Background(), "user_operator", "req_drift"); !errors.Is(err, ErrPolicyDrift) {
		t.Fatalf("Ensure error = %v, want drift", err)
	}
	if repository.createCalls != 0 || repository.beginCalls != 0 || repository.completeCalls != 0 {
		t.Fatal("drift must never be overwritten or published")
	}
}

func TestEnsureFailsClosedOnMissingPublishedReadback(t *testing.T) {
	repository := newMemoryBootstrapRepository()
	spec := capabilityPolicy("audit.read")
	seedExactPolicy(repository, spec, policies.StatusPublished, false)
	service := NewService(repository, &recordingBootstrapPublisher{}, &roleAwareDecisionStub{})
	service.catalog = []fixedPolicySpec{spec}

	if err := service.Ensure(context.Background(), "user_operator", "req_missing"); !errors.Is(err, ErrReadback) {
		t.Fatalf("Ensure error = %v, want readback failure", err)
	}
}

func TestEnsureFailsClosedOnUnexpectedAdditionalPublishedPolicy(t *testing.T) {
	repository := newMemoryBootstrapRepository()
	spec := capabilityPolicy("audit.read")
	seedExactPolicy(repository, spec, policies.StatusPublished, true)
	repository.published[spec.input.Action] = append(repository.published[spec.input.Action], policies.PublishedPolicy{
		PolicyID: "pol_8888888888888888", Name: "unexpected broad allow", Resource: "*", Action: spec.input.Action,
		Effect: policies.EffectAllow, Version: 1,
	})
	service := NewService(repository, &recordingBootstrapPublisher{}, &roleAwareDecisionStub{})
	service.catalog = []fixedPolicySpec{spec}

	if err := service.Ensure(context.Background(), "user_operator", "req_extra_policy"); !errors.Is(err, ErrReadback) {
		t.Fatalf("Ensure error = %v, want fail-closed unexpected policy readback", err)
	}
}

func TestEnsureFailsClosedOnPublisherAndPDPFailure(t *testing.T) {
	t.Run("publisher", func(t *testing.T) {
		repository := newMemoryBootstrapRepository()
		publisher := &recordingBootstrapPublisher{err: errors.New("Cerbos Admin API down")}
		service := NewService(repository, publisher, &roleAwareDecisionStub{})
		service.catalog = []fixedPolicySpec{capabilityPolicy("audit.read")}
		if err := service.Ensure(context.Background(), "user_operator", "req_publish_error"); !errors.Is(err, ErrUnavailable) {
			t.Fatalf("Ensure error = %v, want unavailable", err)
		}
		if repository.failCalls != 1 || repository.completeCalls != 0 {
			t.Fatalf("fail=%d complete=%d", repository.failCalls, repository.completeCalls)
		}
	})

	t.Run("PDP", func(t *testing.T) {
		repository := newMemoryBootstrapRepository()
		spec := capabilityPolicy("audit.read")
		seedExactPolicy(repository, spec, policies.StatusPublished, true)
		service := NewService(repository, &recordingBootstrapPublisher{}, &roleAwareDecisionStub{err: errors.New("PDP down")})
		service.catalog = []fixedPolicySpec{spec}
		if err := service.Ensure(context.Background(), "user_operator", "req_pdp_error"); !errors.Is(err, ErrReadback) {
			t.Fatalf("Ensure error = %v, want readback failure", err)
		}
	})

	t.Run("unexpected allow", func(t *testing.T) {
		repository := newMemoryBootstrapRepository()
		spec := capabilityPolicy("audit.read")
		seedExactPolicy(repository, spec, policies.StatusPublished, true)
		allow := true
		service := NewService(repository, &recordingBootstrapPublisher{}, &roleAwareDecisionStub{force: &allow})
		service.catalog = []fixedPolicySpec{spec}
		if err := service.Ensure(context.Background(), "user_operator", "req_pdp_open"); !errors.Is(err, ErrReadback) {
			t.Fatalf("Ensure error = %v, want fail-closed unexpected ordinary allow", err)
		}
	})
}

func TestFixedCatalogIsExplicitValidRoleMatrix(t *testing.T) {
	seen := make(map[string]struct{})
	dreamUPCount := 0
	for _, spec := range fixedPolicyCatalog() {
		if _, duplicate := seen[spec.input.Action]; duplicate {
			t.Fatalf("duplicate action %q", spec.input.Action)
		}
		seen[spec.input.Action] = struct{}{}
		if spec.input.Action == "*" || spec.input.Resource != "*" || spec.input.Effect != policies.EffectAllow {
			t.Fatalf("unsafe fixed policy %#v", spec.input)
		}
		if err := policies.ValidateDraft(spec.input); err != nil {
			t.Fatalf("invalid fixed policy %q: %v", spec.input.Action, err)
		}
		if len(spec.input.Principals) != 1 || spec.input.Principals[0].Attribute != "eventRole" || len(spec.input.Conditions) != 0 {
			t.Fatalf("policy %q is not bound to the authoritative eventRole", spec.input.Action)
		}
		if !slices.Contains(spec.roles, adminroles.RoleSuperAdmin) {
			t.Fatalf("super administrator missing from %q", spec.input.Action)
		}
		if spec.kind != policyKindDreamUP {
			if len(spec.roles) != 1 {
				t.Fatalf("global capability %q broadened beyond super administrator", spec.input.Action)
			}
			continue
		}
		dreamUPCount++
		action := permissions.Action(spec.input.Action)
		for _, role := range []adminroles.Role{adminroles.RoleAdmin, adminroles.RoleSeniorAdmin, adminroles.RoleSuperAdmin} {
			if slices.Contains(spec.roles, role) != permissions.FixedRoleAllows(role, action) {
				t.Fatalf("fixed role matrix drift for role=%s action=%s", role, action)
			}
		}
	}
	if dreamUPCount != 21 {
		t.Fatalf("DreamUP policy count = %d, want the 21 reviewed administrator actions", dreamUPCount)
	}
	if _, serviceOnly := seen[string(permissions.ActionOperationReceiptRead)]; serviceOnly {
		t.Fatal("service-only operation receipt capability must never be granted to an administrator")
	}
}

type bootstrapRepositoryStub struct{}

func (*bootstrapRepositoryStub) List(context.Context, policies.ListQuery) (policies.Page, error) {
	return policies.Page{}, nil
}
func (*bootstrapRepositoryStub) Get(context.Context, policies.PolicyID) (policies.Detail, error) {
	return policies.Detail{}, policies.ErrNotFound
}
func (*bootstrapRepositoryStub) Create(context.Context, identity.UserID, policies.DraftInput) (policies.PolicyID, int, error) {
	return "pol_0123456789abcdef", 1, nil
}
func (*bootstrapRepositoryStub) Update(context.Context, identity.UserID, policies.PolicyID, int, policies.DraftInput) (int, error) {
	return 0, errors.New("unexpected update")
}
func (*bootstrapRepositoryStub) BeginPublication(context.Context, identity.UserID, policies.PolicyID, int, string) (policies.PublicationJob, error) {
	return policies.PublicationJob{}, nil
}
func (*bootstrapRepositoryStub) CompletePublication(context.Context, policies.PublicationJobID) error {
	return nil
}
func (*bootstrapRepositoryStub) FailPublication(context.Context, policies.PublicationJobID, string) error {
	return nil
}
func (*bootstrapRepositoryStub) ClaimPublicationJobs(context.Context, int) ([]policies.PublicationJob, error) {
	return nil, nil
}
func (*bootstrapRepositoryStub) ListPublished(context.Context, string, string) ([]policies.PublishedPolicy, error) {
	return nil, nil
}
func (*bootstrapRepositoryStub) RecordAuthorizationDenied(context.Context, identity.UserID, string, string) error {
	return nil
}

type bootstrapPublisherStub struct{}

func (bootstrapPublisherStub) Publish(context.Context, policies.PublishedPolicy) error { return nil }

type bootstrapDecisionStub struct{}

func (bootstrapDecisionStub) Check(context.Context, string, cerbos.Principal, []cerbos.ResourceCheck) ([]cerbos.Decision, error) {
	return nil, nil
}

type memoryBootstrapRepository struct {
	details        map[policies.PolicyID]policies.Detail
	byName         map[string]policies.PolicyID
	jobs           map[policies.PublicationJobID]policies.PublicationJob
	published      map[string][]policies.PublishedPolicy
	createCalls    int
	beginCalls     int
	completeCalls  int
	lastActor      identity.UserID
	lastRequestID  string
	nextPolicyID   int
	nextPublishJob int
	createErr      error
	createHook     func()
	failCalls      int
}

func newMemoryBootstrapRepository() *memoryBootstrapRepository {
	return &memoryBootstrapRepository{
		details:   make(map[policies.PolicyID]policies.Detail),
		byName:    make(map[string]policies.PolicyID),
		jobs:      make(map[policies.PublicationJobID]policies.PublicationJob),
		published: make(map[string][]policies.PublishedPolicy),
	}
}

func (r *memoryBootstrapRepository) List(_ context.Context, query policies.ListQuery) (policies.Page, error) {
	items := make([]policies.Summary, 0)
	for name, id := range r.byName {
		if name != query.Query {
			continue
		}
		detail := r.details[id]
		items = append(items, policies.Summary{PolicyID: id, Name: detail.Name, Resource: detail.Resource, Version: detail.Version, Status: detail.Status})
	}
	return policies.Page{Items: items}, nil
}

func (r *memoryBootstrapRepository) Get(_ context.Context, id policies.PolicyID) (policies.Detail, error) {
	detail, ok := r.details[id]
	if !ok {
		return policies.Detail{}, policies.ErrNotFound
	}
	return detail, nil
}

func (r *memoryBootstrapRepository) Create(_ context.Context, actor identity.UserID, input policies.DraftInput) (policies.PolicyID, int, error) {
	r.createCalls++
	r.lastActor = actor
	if r.createErr != nil {
		if r.createHook != nil {
			r.createHook()
		}
		return "", 0, r.createErr
	}
	r.nextPolicyID++
	id := policies.PolicyID(fmt.Sprintf("pol_%016d", r.nextPolicyID))
	r.byName[input.Name] = id
	r.details[id] = detailFromInput(id, 1, policies.StatusDraft, input)
	return id, 1, nil
}

func (*memoryBootstrapRepository) Update(context.Context, identity.UserID, policies.PolicyID, int, policies.DraftInput) (int, error) {
	return 0, errors.New("bootstrap must never overwrite policy drift")
}

func (r *memoryBootstrapRepository) BeginPublication(_ context.Context, actor identity.UserID, id policies.PolicyID, version int, requestID string) (policies.PublicationJob, error) {
	r.beginCalls++
	r.lastActor = actor
	r.lastRequestID = requestID
	r.nextPublishJob++
	detail, ok := r.details[id]
	if !ok || detail.Version != version {
		return policies.PublicationJob{}, policies.ErrConflict
	}
	jobID := policies.PublicationJobID(fmt.Sprintf("pub_%016d", r.nextPublishJob))
	job := policies.PublicationJob{JobID: jobID, Policy: publishedFromDetail(detail), ActorID: actor, RequestID: requestID}
	r.jobs[jobID] = job
	return job, nil
}

func (r *memoryBootstrapRepository) CompletePublication(_ context.Context, id policies.PublicationJobID) error {
	r.completeCalls++
	job, ok := r.jobs[id]
	if !ok {
		return policies.ErrPublicationJob
	}
	detail := r.details[job.Policy.PolicyID]
	detail.Status = policies.StatusPublished
	r.details[detail.PolicyID] = detail
	r.published[detail.Action] = append(r.published[detail.Action], job.Policy)
	return nil
}

func (r *memoryBootstrapRepository) FailPublication(context.Context, policies.PublicationJobID, string) error {
	r.failCalls++
	return nil
}

func (*memoryBootstrapRepository) ClaimPublicationJobs(context.Context, int) ([]policies.PublicationJob, error) {
	return nil, nil
}

func (r *memoryBootstrapRepository) ListPublished(_ context.Context, action, _ string) ([]policies.PublishedPolicy, error) {
	return append([]policies.PublishedPolicy(nil), r.published[action]...), nil
}

func (*memoryBootstrapRepository) RecordAuthorizationDenied(context.Context, identity.UserID, string, string) error {
	return nil
}

func detailFromInput(id policies.PolicyID, version int, status policies.Status, input policies.DraftInput) policies.Detail {
	return policies.Detail{
		PolicyID: id, Name: input.Name, Description: input.Description, Resource: input.Resource,
		Action: input.Action, Effect: input.Effect, Version: version, Status: status,
		Principals: append([]policies.Clause(nil), input.Principals...), Conditions: append([]policies.Clause(nil), input.Conditions...),
	}
}

func publishedFromDetail(detail policies.Detail) policies.PublishedPolicy {
	return policies.PublishedPolicy{
		PolicyID: detail.PolicyID, Name: detail.Name, Resource: detail.Resource, Action: detail.Action,
		Effect: detail.Effect, Version: detail.Version,
		Principals: append([]policies.Clause(nil), detail.Principals...), Conditions: append([]policies.Clause(nil), detail.Conditions...),
	}
}

type recordingBootstrapPublisher struct {
	policies []policies.PublishedPolicy
	err      error
}

func (p *recordingBootstrapPublisher) Publish(_ context.Context, policy policies.PublishedPolicy) error {
	p.policies = append(p.policies, policy)
	return p.err
}

type roleAwareDecisionStub struct {
	calls int
	err   error
	force *bool
}

func (p *roleAwareDecisionStub) Check(_ context.Context, _ string, principal cerbos.Principal, checks []cerbos.ResourceCheck) ([]cerbos.Decision, error) {
	p.calls++
	if p.err != nil {
		return nil, p.err
	}
	role, _ := principal.Attributes["eventRole"].(string)
	decisions := make([]cerbos.Decision, 0, len(checks))
	for _, check := range checks {
		allowed := role == "super_admin"
		if p.force != nil {
			allowed = *p.force
		}
		decisions = append(decisions, cerbos.Decision{PolicyID: check.PolicyID, Allowed: allowed})
	}
	return decisions, nil
}

func seedExactPolicy(repository *memoryBootstrapRepository, spec fixedPolicySpec, status policies.Status, published bool) policies.PolicyID {
	id := policies.PolicyID("pol_7777777777777777")
	repository.byName[spec.input.Name] = id
	detail := detailFromInput(id, 1, status, spec.input)
	repository.details[id] = detail
	if published {
		repository.published[spec.input.Action] = []policies.PublishedPolicy{publishedFromDetail(detail)}
	}
	return id
}
