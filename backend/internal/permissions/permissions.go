//
// Copyright (c) 2026 Chen Jiajie(Ariakage)
//
// Author: Chen Jiajie(Ariakage) <ariakage233@gmail.com>
// Date: 2026-08-05
// Description: Permission capability types and the resolver contract
//

// Package permissions defines the permission capability types and the
// PermissionResolver interface. In Phase 1, the resolver is a temporary
// fail-closed implementation. Phase 7 replaces it with Cerbos without
// changing the API contract.
package permissions

import (
	"context"

	"github.com/GravelEvolution/united-pass/backend/internal/identity"
)

// Capabilities is the set of permission capabilities returned by
// GET /api/v1/me/permissions. Field names match the frontend TypeScript type
// exactly. Every field defaults to false (fail-closed).
type Capabilities struct {
	UserRead                bool `json:"userRead"`
	UserDisable             bool `json:"userDisable"`
	EmployeeManage          bool `json:"employeeManage"`
	EmployeeOffboard        bool `json:"employeeOffboard"`
	DepartmentManage        bool `json:"departmentManage"`
	ApplicationRead         bool `json:"applicationRead"`
	ApplicationManage       bool `json:"applicationManage"`
	ApplicationSecretRotate bool `json:"applicationSecretRotate"`
	PolicyRead              bool `json:"policyRead"`
	PolicyManage            bool `json:"policyManage"`
	PolicyPublish           bool `json:"policyPublish"`
	AuditRead               bool `json:"auditRead"`
	AuditExport             bool `json:"auditExport"`
	ProviderRead            bool `json:"providerRead"`
	ProviderManage          bool `json:"providerManage"`
}

// NoCapabilities returns a Capabilities with all fields false. This is the
// fail-closed default.
func NoCapabilities() Capabilities {
	return Capabilities{}
}

// Resolver resolves permission capabilities for a given user. The default
// production implementation returns all-false. A development override can
// grant all capabilities to a configured user ID.
type Resolver interface {
	Resolve(ctx context.Context, userID identity.UserID) (Capabilities, error)
}
