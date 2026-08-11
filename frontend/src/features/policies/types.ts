//
// Copyright (c) 2026 Chen Jiajie(Ariakage)
//
// Author: Chen Jiajie(Ariakage) <ariakage233@gmail.com>
// Date: 2026-08-04
// Description: Policies feature contract types
//

export type AuthorizationPolicy = {
  policyId: string;
  name: string;
  resource: string;
  version: number;
  status: "draft" | "published";
  updatedBy: string;
  updatedAt: string;
};

export type PolicyEffect = "allow" | "deny";

export type PolicyCondition = {
  attribute: string;
  operator: "eq" | "neq" | "in" | "not_in" | "gt" | "lt" | "contains";
  value: string;
};

export type PolicyPrincipal = {
  attribute: string;
  operator: "eq" | "neq" | "in" | "not_in" | "contains";
  value: string;
};

export type PolicyDetail = {
  policyId: string;
  name: string;
  description: string;
  resource: string;
  action: string;
  effect: PolicyEffect;
  version: number;
  status: "draft" | "published";
  principals: PolicyPrincipal[];
  conditions: PolicyCondition[];
  updatedBy: string;
  updatedAt: string;
  versionHistory: Array<{
    version: number;
    status: "draft" | "published";
    updatedBy: string;
    updatedAt: string;
    changeSummary: string;
  }>;
};

export type PolicyDraftInput = {
  policyId?: string;
  expectedVersion?: number;
  name: string;
  description: string;
  resource: string;
  action: string;
  effect: PolicyEffect;
  principals: PolicyPrincipal[];
  conditions: PolicyCondition[];
};

export type PolicySimulationInput = {
  principalAttributes: Record<string, string>;
  resourceAttributes: Record<string, string>;
  action: string;
};

export type PolicySimulationResult = {
  decision: "allow" | "deny" | "no_match";
  matchedPolicyId: string | null;
  matchedPolicyName: string | null;
  evaluatedAt: string;
  reasons: string[];
};
