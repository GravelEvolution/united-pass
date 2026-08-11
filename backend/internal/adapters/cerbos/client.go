//
// Copyright (c) 2026 Chen Jiajie(Ariakage)
//
// Author: Chen Jiajie(Ariakage) <ariakage233@gmail.com>
// Date: 2026-08-11
// Description: Bounded Cerbos PDP and Admin API adapter for Phase 7
//

package cerbos

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"strconv"
	"strings"

	"github.com/GravelEvolution/united-pass/backend/internal/policies"
)

const maxResponseBytes = 1 << 20

var ErrUnavailable = errors.New("cerbos unavailable")

type Client struct {
	pdpURL        string
	adminURL      string
	adminUsername string
	adminPassword string
	http          *http.Client
}

func NewClient(pdpURL, adminURL, username, password string, httpClient *http.Client) (*Client, error) {
	if strings.TrimRight(pdpURL, "/") == "" || strings.TrimRight(adminURL, "/") == "" || username == "" || password == "" || httpClient == nil {
		return nil, errors.New("cerbos: complete PDP/Admin configuration and HTTP client are required")
	}
	return &Client{
		pdpURL: strings.TrimRight(pdpURL, "/"), adminURL: strings.TrimRight(adminURL, "/"),
		adminUsername: username, adminPassword: password, http: httpClient,
	}, nil
}

type Principal struct {
	ID         string
	Roles      []string
	Attributes map[string]any
}

type ResourceCheck struct {
	PolicyID   policies.PolicyID
	Version    int
	Attributes map[string]any
}

type Decision struct {
	PolicyID policies.PolicyID
	Allowed  bool
}

func (c *Client) Check(ctx context.Context, requestID string, principal Principal, checks []ResourceCheck) ([]Decision, error) {
	resources := make([]checkResource, 0, len(checks))
	for _, check := range checks {
		resources = append(resources, checkResource{
			Resource: resource{ID: string(check.PolicyID), Kind: resourceKind(check.PolicyID), PolicyVersion: strconv.Itoa(check.Version), Attr: check.Attributes},
			Actions:  []string{"evaluate"},
		})
	}
	body := checkRequest{RequestID: requestID, Principal: principalRequest{ID: principal.ID, Roles: principal.Roles, Attr: principal.Attributes}, Resources: resources}
	var response checkResponse
	if err := c.doJSON(ctx, http.MethodPost, c.pdpURL+"/api/check/resources", body, &response, false); err != nil {
		return nil, err
	}
	decisions := make([]Decision, 0, len(response.Results))
	for _, result := range response.Results {
		decisions = append(decisions, Decision{PolicyID: policies.PolicyID(result.Resource.ID), Allowed: result.Actions["evaluate"] == "EFFECT_ALLOW"})
	}
	if len(decisions) != len(checks) {
		return nil, fmt.Errorf("%w: incomplete decision response", ErrUnavailable)
	}
	return decisions, nil
}

func (c *Client) Publish(ctx context.Context, policy policies.PublishedPolicy) error {
	document, err := compilePolicy(policy)
	if err != nil {
		return err
	}
	body := struct {
		Policies []resourcePolicyDocument `json:"policies"`
	}{Policies: []resourcePolicyDocument{document}}
	if err := c.doJSON(ctx, http.MethodPut, c.adminURL+"/admin/policy", body, nil, true); err != nil {
		return err
	}
	return nil
}

func (c *Client) Ready(ctx context.Context) error {
	if err := c.checkReadyEndpoint(ctx, c.pdpURL+"/_cerbos/health", false); err != nil {
		return err
	}
	if err := c.checkReadyEndpoint(ctx, c.adminURL+"/admin/policies", true); err != nil {
		return err
	}
	return nil
}

func (c *Client) checkReadyEndpoint(ctx context.Context, endpoint string, admin bool) error {
	request, err := http.NewRequestWithContext(ctx, http.MethodGet, endpoint, nil)
	if err != nil {
		return err
	}
	if admin {
		request.SetBasicAuth(c.adminUsername, c.adminPassword)
	}
	response, err := c.http.Do(request)
	if err != nil {
		return fmt.Errorf("%w: health request", ErrUnavailable)
	}
	defer response.Body.Close()
	_, _ = io.Copy(io.Discard, io.LimitReader(response.Body, maxResponseBytes))
	if response.StatusCode != http.StatusOK {
		return fmt.Errorf("%w: health status %d", ErrUnavailable, response.StatusCode)
	}
	return nil
}

func (c *Client) Name() string { return "cerbos" }

func (c *Client) CheckReady(ctx context.Context) error { return c.Ready(ctx) }

func (c *Client) doJSON(ctx context.Context, method, endpoint string, value any, output any, admin bool) error {
	encoded, err := json.Marshal(value)
	if err != nil {
		return fmt.Errorf("cerbos: encode request: %w", err)
	}
	request, err := http.NewRequestWithContext(ctx, method, endpoint, bytes.NewReader(encoded))
	if err != nil {
		return fmt.Errorf("cerbos: build request: %w", err)
	}
	request.Header.Set("Content-Type", "application/json")
	request.Header.Set("Accept", "application/json")
	if admin {
		request.SetBasicAuth(c.adminUsername, c.adminPassword)
	}
	response, err := c.http.Do(request)
	if err != nil {
		return fmt.Errorf("%w: request failed", ErrUnavailable)
	}
	defer response.Body.Close()
	reader := io.LimitReader(response.Body, maxResponseBytes+1)
	payload, err := io.ReadAll(reader)
	if err != nil || len(payload) > maxResponseBytes {
		return fmt.Errorf("%w: invalid response body", ErrUnavailable)
	}
	if response.StatusCode < 200 || response.StatusCode >= 300 {
		return fmt.Errorf("%w: status %d", ErrUnavailable, response.StatusCode)
	}
	if output != nil {
		if err := json.Unmarshal(payload, output); err != nil {
			return fmt.Errorf("%w: malformed response", ErrUnavailable)
		}
	}
	return nil
}

type checkRequest struct {
	RequestID string           `json:"requestId,omitempty"`
	Principal principalRequest `json:"principal"`
	Resources []checkResource  `json:"resources"`
}

type principalRequest struct {
	ID    string         `json:"id"`
	Roles []string       `json:"roles"`
	Attr  map[string]any `json:"attr"`
}

type checkResource struct {
	Resource resource `json:"resource"`
	Actions  []string `json:"actions"`
}

type resource struct {
	ID            string         `json:"id"`
	Kind          string         `json:"kind"`
	PolicyVersion string         `json:"policyVersion"`
	Attr          map[string]any `json:"attr"`
}

type checkResponse struct {
	Results []struct {
		Resource resource          `json:"resource"`
		Actions  map[string]string `json:"actions"`
	} `json:"results"`
}

type resourcePolicyDocument struct {
	APIVersion     string         `json:"apiVersion"`
	ResourcePolicy resourcePolicy `json:"resourcePolicy"`
}

type resourcePolicy struct {
	Resource string       `json:"resource"`
	Version  string       `json:"version"`
	Rules    []policyRule `json:"rules"`
}

type policyRule struct {
	Name      string           `json:"name"`
	Actions   []string         `json:"actions"`
	Effect    string           `json:"effect"`
	Roles     []string         `json:"roles"`
	Condition *policyCondition `json:"condition,omitempty"`
}

type policyCondition struct {
	Match struct {
		Expr string `json:"expr"`
	} `json:"match"`
}

func compilePolicy(policy policies.PublishedPolicy) (resourcePolicyDocument, error) {
	if !policies.HasPolicyIDPrefix(string(policy.PolicyID)) || policy.Version < 1 {
		return resourcePolicyDocument{}, policies.ErrValidation
	}
	expressions := make([]string, 0, len(policy.Principals)+len(policy.Conditions))
	for _, clause := range policy.Principals {
		expressions = append(expressions, compileClause("request.principal.attr.", clause))
	}
	for _, clause := range policy.Conditions {
		expressions = append(expressions, compileClause("request.resource.attr.", clause))
	}
	condition := (*policyCondition)(nil)
	if len(expressions) > 0 {
		condition = &policyCondition{}
		condition.Match.Expr = strings.Join(expressions, " && ")
	}
	matchEffect := "EFFECT_ALLOW"
	if policy.Effect == policies.EffectDeny {
		matchEffect = "EFFECT_DENY"
	}
	rules := []policyRule{{Name: "united_pass_rule", Actions: []string{"evaluate"}, Effect: matchEffect, Roles: []string{"*"}, Condition: condition}}
	// Cerbos defaults unmatched actions to DENY. A deny document therefore
	// needs an unconditional allow fallback so its DENY result means an
	// explicit matched deny rather than a no-match.
	if policy.Effect == policies.EffectDeny {
		rules = append(rules, policyRule{Name: "united_pass_deny_fallback", Actions: []string{"evaluate"}, Effect: "EFFECT_ALLOW", Roles: []string{"*"}})
	}
	return resourcePolicyDocument{APIVersion: "api.cerbos.dev/v1", ResourcePolicy: resourcePolicy{Resource: resourceKind(policy.PolicyID), Version: strconv.Itoa(policy.Version), Rules: rules}}, nil
}

func compileClause(prefix string, clause policies.Clause) string {
	attribute := prefix + clause.Attribute
	value := strconv.Quote(clause.Value)
	switch clause.Operator {
	case policies.OperatorEqual:
		return attribute + " == " + value
	case policies.OperatorNotEqual:
		return attribute + " != " + value
	case policies.OperatorContains:
		return attribute + ".contains(" + value + ")"
	case policies.OperatorIn, policies.OperatorNotIn:
		values := strings.Split(clause.Value, ",")
		quoted := make([]string, 0, len(values))
		for _, item := range values {
			quoted = append(quoted, strconv.Quote(strings.TrimSpace(item)))
		}
		expression := attribute + " in [" + strings.Join(quoted, ",") + "]"
		if clause.Operator == policies.OperatorNotIn {
			return "!(" + expression + ")"
		}
		return expression
	case policies.OperatorGreaterThan:
		return "double(" + attribute + ") > " + clause.Value
	case policies.OperatorLessThan:
		return "double(" + attribute + ") < " + clause.Value
	default:
		return "false"
	}
}

func resourceKind(id policies.PolicyID) string {
	return "united_pass_" + strings.ReplaceAll(string(id), "-", "_")
}
