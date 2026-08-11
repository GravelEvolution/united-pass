//
// Copyright (c) 2026 Chen Jiajie(Ariakage)
//
// Author: Chen Jiajie(Ariakage) <ariakage233@gmail.com>
// Date: 2026-08-11
// Description: Phase 7 policy lifecycle, publication and simulation service
//

package policies

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/GravelEvolution/united-pass/backend/internal/identity"
)

const publicationRecoveryAttemptTimeout = 35 * time.Second

type Service struct {
	repo      Repository
	publisher Publisher
	clock     func() time.Time
	logger    *slog.Logger
}

func NewService(repo Repository, publisher Publisher, logger *slog.Logger) *Service {
	if logger == nil {
		logger = slog.Default()
	}
	return &Service{repo: repo, publisher: publisher, clock: func() time.Time { return time.Now().UTC() }, logger: logger}
}

func (s *Service) List(ctx context.Context, query ListQuery) (Page, error) {
	if query.Limit == 0 {
		query.Limit = 50
	}
	if query.Limit < 1 || query.Limit > 100 || len(query.Query) > 120 || (query.Status != "" && query.Status != StatusDraft && query.Status != StatusPublished) {
		return Page{}, ErrValidation
	}
	return s.repo.List(ctx, query)
}

func (s *Service) Get(ctx context.Context, id PolicyID) (Detail, error) {
	if !HasPolicyIDPrefix(string(id)) {
		return Detail{}, ErrNotFound
	}
	return s.repo.Get(ctx, id)
}

func (s *Service) Create(ctx context.Context, actor identity.UserID, input DraftInput) (PolicyID, int, error) {
	input = normalizeDraft(input)
	if err := ValidateDraft(input); err != nil {
		return "", 0, err
	}
	return s.repo.Create(ctx, actor, input)
}

func (s *Service) Update(ctx context.Context, actor identity.UserID, id PolicyID, expectedVersion int, input DraftInput) (int, error) {
	if !HasPolicyIDPrefix(string(id)) || expectedVersion < 1 {
		return 0, ErrValidation
	}
	input = normalizeDraft(input)
	if err := ValidateDraft(input); err != nil {
		return 0, err
	}
	return s.repo.Update(ctx, actor, id, expectedVersion, input)
}

// Publish installs the exact immutable version into Cerbos before committing
// it as the database-selected version. The durable job is created first; a
// provider-success/database-failure window is recovered idempotently by the
// publication reconciler. Until the DB commit completes the orphan Cerbos
// version is never selected for authorization.
func (s *Service) Publish(ctx context.Context, actor identity.UserID, id PolicyID, expectedVersion int, requestID string) (int, error) {
	if s.publisher == nil {
		return 0, ErrPublisher
	}
	job, err := s.repo.BeginPublication(ctx, actor, id, expectedVersion, requestID)
	if err != nil {
		return 0, err
	}
	if err := s.publisher.Publish(ctx, job.Policy); err != nil {
		_ = s.repo.FailPublication(context.WithoutCancel(ctx), job.JobID, "provider")
		return 0, errors.Join(ErrPublisher, err)
	}
	if err := s.repo.CompletePublication(ctx, job.JobID); err != nil {
		return 0, err
	}
	return job.Policy.Version, nil
}

func (s *Service) Simulate(ctx context.Context, id PolicyID, input SimulationInput) (SimulationResult, error) {
	if err := ValidateSimulation(input); err != nil {
		return SimulationResult{}, err
	}
	detail, err := s.Get(ctx, id)
	if err != nil {
		return SimulationResult{}, err
	}
	result := SimulationResult{Decision: "no_match", EvaluatedAt: s.clock(), Reasons: []string{"策略操作或属性条件未匹配。"}}
	if detail.Action != input.Action {
		return result, nil
	}
	for _, clause := range detail.Principals {
		if !matchesClause(input.PrincipalAttributes[clause.Attribute], clause) {
			return result, nil
		}
	}
	for _, clause := range detail.Conditions {
		if !matchesClause(input.ResourceAttributes[clause.Attribute], clause) {
			return result, nil
		}
	}
	policyID, name := detail.PolicyID, detail.Name
	result.MatchedPolicyID, result.MatchedPolicyName = &policyID, &name
	result.Decision = string(detail.Effect)
	result.Reasons = []string{
		"操作与全部 Principal 条件匹配。",
		"全部资源条件匹配。",
		fmt.Sprintf("策略效果：%s。", detail.Effect),
	}
	return result, nil
}

func (s *Service) RecordAuthorizationDenied(ctx context.Context, actor identity.UserID, action, requestID string) {
	if err := s.repo.RecordAuthorizationDenied(ctx, actor, action, requestID); err != nil {
		s.logger.Error("failed to persist authorization denial", "error", err, "requestId", requestID)
	}
}

func normalizeDraft(input DraftInput) DraftInput {
	input.Name = strings.TrimSpace(input.Name)
	input.Description = strings.TrimSpace(input.Description)
	input.Resource = strings.TrimSpace(input.Resource)
	input.Action = strings.TrimSpace(input.Action)
	for index := range input.Principals {
		input.Principals[index].Attribute = strings.TrimSpace(input.Principals[index].Attribute)
		input.Principals[index].Value = strings.TrimSpace(input.Principals[index].Value)
	}
	for index := range input.Conditions {
		input.Conditions[index].Attribute = strings.TrimSpace(input.Conditions[index].Attribute)
		input.Conditions[index].Value = strings.TrimSpace(input.Conditions[index].Value)
	}
	return input
}

func matchesClause(actual string, clause Clause) bool {
	switch clause.Operator {
	case OperatorEqual:
		return actual == clause.Value
	case OperatorNotEqual:
		return actual != clause.Value
	case OperatorIn:
		return containsValue(clause.Value, actual)
	case OperatorNotIn:
		return !containsValue(clause.Value, actual)
	case OperatorContains:
		return strings.Contains(actual, clause.Value)
	case OperatorGreaterThan, OperatorLessThan:
		left, leftErr := strconv.ParseFloat(actual, 64)
		right, rightErr := strconv.ParseFloat(clause.Value, 64)
		if leftErr != nil || rightErr != nil {
			return false
		}
		if clause.Operator == OperatorGreaterThan {
			return left > right
		}
		return left < right
	default:
		return false
	}
}

func containsValue(csv, expected string) bool {
	for _, item := range strings.Split(csv, ",") {
		if strings.TrimSpace(item) == expected {
			return true
		}
	}
	return false
}

type Reconciler struct {
	service  *Service
	interval time.Duration
	batch    int
	stop     chan struct{}
	done     chan struct{}
	once     sync.Once
}

func NewReconciler(service *Service, interval time.Duration, batch int) *Reconciler {
	return &Reconciler{service: service, interval: interval, batch: batch, stop: make(chan struct{}), done: make(chan struct{})}
}

func (r *Reconciler) Start() {
	go func() {
		defer close(r.done)
		ticker := time.NewTicker(r.interval)
		defer ticker.Stop()
		for {
			select {
			case <-ticker.C:
				r.run()
			case <-r.stop:
				return
			}
		}
	}()
}

func (r *Reconciler) Stop() {
	r.once.Do(func() { close(r.stop); <-r.done })
}

func (r *Reconciler) run() {
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	jobs, err := r.service.repo.ClaimPublicationJobs(ctx, r.batch)
	cancel()
	if err != nil {
		r.service.logger.Error("claim policy publication jobs", "error", err)
		return
	}
	for _, job := range jobs {
		r.runJob(job)
	}
}

func (r *Reconciler) runJob(job PublicationJob) {
	ctx, cancel := context.WithTimeout(context.Background(), publicationRecoveryAttemptTimeout)
	defer cancel()
	if err := r.service.publisher.Publish(ctx, job.Policy); err != nil {
		_ = r.service.repo.FailPublication(context.WithoutCancel(ctx), job.JobID, "provider")
		return
	}
	if err := r.service.repo.CompletePublication(ctx, job.JobID); err != nil {
		r.service.logger.Error("complete policy publication job", "error", err, "jobId", job.JobID)
	}
}
