//
// Copyright (c) 2026 Chen Jiajie(Ariakage)
//
// Author: Chen Jiajie(Ariakage) <ariakage233@gmail.com>
// Date: 2026-08-11
// Description: Phase 7 policy domain contracts and validation
//

package policies

import (
	"context"
	"errors"
	"regexp"
	"strconv"
	"strings"
	"time"

	"github.com/GravelEvolution/united-pass/backend/internal/identity"
)

type PolicyID string
type PublicationJobID string
type Effect string
type Status string
type Operator string

const (
	EffectAllow Effect = "allow"
	EffectDeny  Effect = "deny"

	StatusDraft     Status = "draft"
	StatusPublished Status = "published"

	OperatorEqual       Operator = "eq"
	OperatorNotEqual    Operator = "neq"
	OperatorIn          Operator = "in"
	OperatorNotIn       Operator = "not_in"
	OperatorGreaterThan Operator = "gt"
	OperatorLessThan    Operator = "lt"
	OperatorContains    Operator = "contains"
)

var (
	ErrNotFound       = errors.New("policy not found")
	ErrConflict       = errors.New("policy version conflict")
	ErrDuplicateName  = errors.New("policy name already exists")
	ErrValidation     = errors.New("policy validation failed")
	ErrPublisher      = errors.New("policy publisher unavailable")
	ErrPublicationJob = errors.New("policy publication job unavailable")
)

type Clause struct {
	Attribute string   `json:"attribute"`
	Operator  Operator `json:"operator"`
	Value     string   `json:"value"`
}

type DraftInput struct {
	Name        string   `json:"name"`
	Description string   `json:"description"`
	Resource    string   `json:"resource"`
	Action      string   `json:"action"`
	Effect      Effect   `json:"effect"`
	Principals  []Clause `json:"principals"`
	Conditions  []Clause `json:"conditions"`
}

type Summary struct {
	PolicyID  PolicyID  `json:"policyId"`
	Name      string    `json:"name"`
	Resource  string    `json:"resource"`
	Version   int       `json:"version"`
	Status    Status    `json:"status"`
	UpdatedBy string    `json:"updatedBy"`
	UpdatedAt time.Time `json:"updatedAt"`
}

type VersionSummary struct {
	Version       int       `json:"version"`
	Status        Status    `json:"status"`
	UpdatedBy     string    `json:"updatedBy"`
	UpdatedAt     time.Time `json:"updatedAt"`
	ChangeSummary string    `json:"changeSummary"`
}

type Detail struct {
	PolicyID       PolicyID         `json:"policyId"`
	Name           string           `json:"name"`
	Description    string           `json:"description"`
	Resource       string           `json:"resource"`
	Action         string           `json:"action"`
	Effect         Effect           `json:"effect"`
	Version        int              `json:"version"`
	Status         Status           `json:"status"`
	Principals     []Clause         `json:"principals"`
	Conditions     []Clause         `json:"conditions"`
	UpdatedBy      string           `json:"updatedBy"`
	UpdatedAt      time.Time        `json:"updatedAt"`
	VersionHistory []VersionSummary `json:"versionHistory"`
}

type PublishedPolicy struct {
	PolicyID   PolicyID
	Name       string
	Resource   string
	Action     string
	Effect     Effect
	Version    int
	Principals []Clause
	Conditions []Clause
}

type ListQuery struct {
	Cursor string
	Limit  int
	Query  string
	Status Status
}

type Page struct {
	Items      []Summary
	NextCursor string
	HasMore    bool
}

type SimulationInput struct {
	PrincipalAttributes map[string]string `json:"principalAttributes"`
	ResourceAttributes  map[string]string `json:"resourceAttributes"`
	Action              string            `json:"action"`
}

type SimulationResult struct {
	Decision          string    `json:"decision"`
	MatchedPolicyID   *PolicyID `json:"matchedPolicyId"`
	MatchedPolicyName *string   `json:"matchedPolicyName"`
	EvaluatedAt       time.Time `json:"evaluatedAt"`
	Reasons           []string  `json:"reasons"`
}

type PublicationJob struct {
	JobID     PublicationJobID
	Policy    PublishedPolicy
	ActorID   identity.UserID
	RequestID string
}

type Repository interface {
	List(context.Context, ListQuery) (Page, error)
	Get(context.Context, PolicyID) (Detail, error)
	Create(context.Context, identity.UserID, DraftInput) (PolicyID, int, error)
	Update(context.Context, identity.UserID, PolicyID, int, DraftInput) (int, error)
	BeginPublication(context.Context, identity.UserID, PolicyID, int, string) (PublicationJob, error)
	CompletePublication(context.Context, PublicationJobID) error
	FailPublication(context.Context, PublicationJobID, string) error
	ClaimPublicationJobs(context.Context, int) ([]PublicationJob, error)
	ListPublished(context.Context, string, string) ([]PublishedPolicy, error)
	RecordAuthorizationDenied(context.Context, identity.UserID, string, string) error
}

type Publisher interface {
	Publish(context.Context, PublishedPolicy) error
}

var (
	identifierPattern = regexp.MustCompile(`^[a-z][a-z0-9_.-]{0,127}$`)
	attributePattern  = regexp.MustCompile(`^[a-z][A-Za-z0-9_]{0,63}$`)
)

func HasPolicyIDPrefix(value string) bool {
	return strings.HasPrefix(value, "pol_") && len(value) >= 12 && len(value) <= 80
}

func ValidateDraft(input DraftInput) error {
	if strings.TrimSpace(input.Name) == "" || len(input.Name) > 120 || len(input.Description) > 1000 {
		return ErrValidation
	}
	if !validSelector(input.Resource) || !identifierPattern.MatchString(input.Action) {
		return ErrValidation
	}
	if input.Effect != EffectAllow && input.Effect != EffectDeny {
		return ErrValidation
	}
	if len(input.Principals) > 20 || len(input.Conditions) > 20 {
		return ErrValidation
	}
	for _, clause := range input.Principals {
		if clause.Operator == OperatorGreaterThan || clause.Operator == OperatorLessThan {
			return ErrValidation
		}
	}
	for _, clause := range append(append([]Clause(nil), input.Principals...), input.Conditions...) {
		if !attributePattern.MatchString(clause.Attribute) || clause.Value == "" || len(clause.Value) > 256 || !validOperator(clause.Operator) {
			return ErrValidation
		}
		if clause.Operator == OperatorGreaterThan || clause.Operator == OperatorLessThan {
			if _, err := strconv.ParseFloat(clause.Value, 64); err != nil {
				return ErrValidation
			}
		}
	}
	return nil
}

func ValidateSimulation(input SimulationInput) error {
	if !identifierPattern.MatchString(input.Action) || len(input.PrincipalAttributes) > 30 || len(input.ResourceAttributes) > 30 {
		return ErrValidation
	}
	for key, value := range input.PrincipalAttributes {
		if !attributePattern.MatchString(key) || len(value) > 256 {
			return ErrValidation
		}
	}
	for key, value := range input.ResourceAttributes {
		if !attributePattern.MatchString(key) || len(value) > 256 {
			return ErrValidation
		}
	}
	return nil
}

func validSelector(value string) bool {
	if value == "*" {
		return true
	}
	parts := strings.Split(value, ":")
	if len(parts) != 2 || !identifierPattern.MatchString(parts[0]) {
		return false
	}
	return parts[1] == "*" || identifierPattern.MatchString(parts[1])
}

func validOperator(value Operator) bool {
	switch value {
	case OperatorEqual, OperatorNotEqual, OperatorIn, OperatorNotIn,
		OperatorGreaterThan, OperatorLessThan, OperatorContains:
		return true
	default:
		return false
	}
}
