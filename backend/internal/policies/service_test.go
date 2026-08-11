package policies

import (
	"context"
	"errors"
	"io"
	"log/slog"
	"testing"
	"time"

	"github.com/GravelEvolution/united-pass/backend/internal/identity"
)

type serviceRepo struct {
	detail          Detail
	job             PublicationJob
	updatedExpected int
	completed       PublicationJobID
	failed          PublicationJobID
}

func (r *serviceRepo) List(context.Context, ListQuery) (Page, error) { return Page{}, nil }
func (r *serviceRepo) Get(_ context.Context, _ PolicyID) (Detail, error) {
	if r.detail.PolicyID == "" {
		return Detail{}, ErrNotFound
	}
	return r.detail, nil
}
func (r *serviceRepo) Create(context.Context, identity.UserID, DraftInput) (PolicyID, int, error) {
	return "pol_0123456789abcdef", 1, nil
}
func (r *serviceRepo) Update(_ context.Context, _ identity.UserID, _ PolicyID, expected int, _ DraftInput) (int, error) {
	r.updatedExpected = expected
	return expected + 1, nil
}
func (r *serviceRepo) BeginPublication(context.Context, identity.UserID, PolicyID, int, string) (PublicationJob, error) {
	return r.job, nil
}
func (r *serviceRepo) CompletePublication(_ context.Context, id PublicationJobID) error {
	r.completed = id
	return nil
}
func (r *serviceRepo) FailPublication(_ context.Context, id PublicationJobID, _ string) error {
	r.failed = id
	return nil
}
func (r *serviceRepo) ClaimPublicationJobs(context.Context, int) ([]PublicationJob, error) {
	return nil, nil
}
func (r *serviceRepo) ListPublished(context.Context, string, string) ([]PublishedPolicy, error) {
	return nil, nil
}
func (r *serviceRepo) RecordAuthorizationDenied(context.Context, identity.UserID, string, string) error {
	return nil
}

type servicePublisher struct {
	published PublishedPolicy
	err       error
}

func (p *servicePublisher) Publish(_ context.Context, policy PublishedPolicy) error {
	p.published = policy
	return p.err
}

func testPolicyService(repo Repository, publisher Publisher) *Service {
	return NewService(repo, publisher, slog.New(slog.NewTextHandler(io.Discard, nil)))
}

func validDraft() DraftInput {
	return DraftInput{Name: "Admin", Resource: "application:*", Action: "application.manage", Effect: EffectAllow, Principals: []Clause{{Attribute: "department", Operator: OperatorEqual, Value: "Identity"}}}
}

func TestValidateDraftRejectsUnsafeIdentifiersAndPrincipalNumericOperators(t *testing.T) {
	input := validDraft()
	input.Action = `application.manage || true`
	if !errors.Is(ValidateDraft(input), ErrValidation) {
		t.Fatal("unsafe action accepted")
	}
	input = validDraft()
	input.Principals[0].Operator = OperatorGreaterThan
	if !errors.Is(ValidateDraft(input), ErrValidation) {
		t.Fatal("numeric principal operator accepted")
	}
}

func TestServiceUpdatePropagatesOptimisticVersion(t *testing.T) {
	repo := &serviceRepo{}
	service := testPolicyService(repo, &servicePublisher{})
	version, err := service.Update(context.Background(), "user_1", "pol_0123456789abcdef", 7, validDraft())
	if err != nil {
		t.Fatal(err)
	}
	if version != 8 || repo.updatedExpected != 7 {
		t.Fatalf("version=%d expected=%d", version, repo.updatedExpected)
	}
}

func TestServicePublishCompletesOnlyAfterProvider(t *testing.T) {
	job := PublicationJob{JobID: "pub_1", Policy: PublishedPolicy{PolicyID: "pol_0123456789abcdef", Version: 4, Effect: EffectAllow}}
	repo := &serviceRepo{job: job}
	publisher := &servicePublisher{}
	service := testPolicyService(repo, publisher)
	version, err := service.Publish(context.Background(), "user_1", job.Policy.PolicyID, 4, "req")
	if err != nil {
		t.Fatal(err)
	}
	if version != 4 || publisher.published.PolicyID != job.Policy.PolicyID || repo.completed != job.JobID {
		t.Fatalf("publication was not completed in order")
	}
}

func TestServicePublishMarksProviderFailure(t *testing.T) {
	job := PublicationJob{JobID: "pub_1", Policy: PublishedPolicy{PolicyID: "pol_0123456789abcdef", Version: 4}}
	repo := &serviceRepo{job: job}
	service := testPolicyService(repo, &servicePublisher{err: errors.New("down")})
	if _, err := service.Publish(context.Background(), "user_1", job.Policy.PolicyID, 4, "req"); !errors.Is(err, ErrPublisher) {
		t.Fatalf("err=%v", err)
	}
	if repo.failed != job.JobID || repo.completed != "" {
		t.Fatalf("job state failed=%q completed=%q", repo.failed, repo.completed)
	}
}

func TestServiceSimulationDistinguishesNoMatchAndDeny(t *testing.T) {
	repo := &serviceRepo{detail: Detail{PolicyID: "pol_0123456789abcdef", Name: "Deny external", Action: "audit.export", Effect: EffectDeny, Principals: []Clause{{Attribute: "department", Operator: OperatorEqual, Value: "External"}}}}
	service := testPolicyService(repo, &servicePublisher{})
	service.clock = func() time.Time { return time.Unix(1, 0).UTC() }
	matched, err := service.Simulate(context.Background(), repo.detail.PolicyID, SimulationInput{Action: "audit.export", PrincipalAttributes: map[string]string{"department": "External"}, ResourceAttributes: map[string]string{}})
	if err != nil {
		t.Fatal(err)
	}
	if matched.Decision != "deny" || matched.MatchedPolicyID == nil {
		t.Fatalf("matched=%#v", matched)
	}
	miss, err := service.Simulate(context.Background(), repo.detail.PolicyID, SimulationInput{Action: "audit.export", PrincipalAttributes: map[string]string{"department": "Internal"}, ResourceAttributes: map[string]string{}})
	if err != nil {
		t.Fatal(err)
	}
	if miss.Decision != "no_match" || miss.MatchedPolicyID != nil {
		t.Fatalf("miss=%#v", miss)
	}
}
