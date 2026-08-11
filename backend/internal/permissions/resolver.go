//
// Copyright (c) 2026 Chen Jiajie(Ariakage)
//
// Author: Chen Jiajie(Ariakage) <ariakage233@gmail.com>
// Date: 2026-08-05
// Description: Phase 1 default (fail-closed) and dev-override permission resolvers
//

// Package permissions also provides the default and dev-override permission
// resolvers for Phase 1. The default resolver is fail-closed (all false).
// The dev-override resolver grants all capabilities to a configured user ID
// in development only. Phase 7 replaces this with Cerbos.
package permissions

import (
	"context"
	"errors"
	"fmt"

	"github.com/GravelEvolution/united-pass/backend/internal/config"
	"github.com/GravelEvolution/united-pass/backend/internal/identity"
	"github.com/GravelEvolution/united-pass/backend/internal/workforce"
)

// DefaultResolver always returns no capabilities (fail-closed). This is the
// production-safe resolver used when no permission system is configured.
type DefaultResolver struct{}

// NewDefaultResolver creates a fail-closed permission resolver.
func NewDefaultResolver() *DefaultResolver {
	return &DefaultResolver{}
}

// Resolve returns no capabilities for any user.
func (r *DefaultResolver) Resolve(ctx context.Context, userID identity.UserID) (Capabilities, error) {
	return NoCapabilities(), nil
}

// AllCapabilities returns a Capabilities with all fields true. This is used
// by the dev-override resolver.
func AllCapabilities() Capabilities {
	return Capabilities{
		UserRead:                true,
		UserDisable:             true,
		EmployeeManage:          true,
		EmployeeOffboard:        true,
		DepartmentManage:        true,
		ApplicationRead:         true,
		ApplicationManage:       true,
		ApplicationSecretRotate: true,
		PolicyRead:              true,
		PolicyManage:            true,
		PolicyPublish:           true,
		AuditRead:               true,
		AuditExport:             true,
		ProviderRead:            true,
		ProviderManage:          true,
	}
}

// DevOverrideResolver wraps a base resolver and grants all capabilities to
// a single configured user ID. This is for local development only — production
// startup fails if the dev override is enabled (enforced by config validation).
type DevOverrideResolver struct {
	base    Resolver
	enabled bool
	userID  identity.UserID
}

// NewDevOverrideResolver creates a resolver that grants all capabilities to
// the configured user ID when the dev override is enabled.
func NewDevOverrideResolver(base Resolver, cfg config.PermissionConfig) *DevOverrideResolver {
	return &DevOverrideResolver{
		base:    base,
		enabled: cfg.DevOverrideEnabled,
		userID:  identity.UserID(cfg.DevOverrideUserID),
	}
}

// Resolve returns all capabilities for the configured dev-override user, and
// delegates to the base resolver for all other users.
func (r *DevOverrideResolver) Resolve(ctx context.Context, userID identity.UserID) (Capabilities, error) {
	if r.enabled && userID == r.userID && r.userID != "" {
		return AllCapabilities(), nil
	}
	if r.base == nil {
		return NoCapabilities(), nil
	}
	caps, err := r.base.Resolve(ctx, userID)
	if err != nil {
		return NoCapabilities(), fmt.Errorf("permission resolve: %w", err)
	}
	return caps, nil
}

// NewResolver creates the appropriate resolver based on configuration. In
// development with the override enabled, it returns a DevOverrideResolver.
// Otherwise it returns the default fail-closed resolver.
func NewResolver(cfg config.Config) Resolver {
	base := NewDefaultResolver()
	if cfg.Permission.DevOverrideEnabled {
		return NewDevOverrideResolver(base, cfg.Permission)
	}
	return base
}

// EmployeeStatusReader is the narrow PostgreSQL-backed workforce view needed
// for the mandatory Phase 5 offboarding deny. It intentionally exposes no
// employee mutation or private field.
type EmployeeStatusReader interface {
	GetEmployeeProfile(ctx context.Context, userID identity.UserID) (workforce.EmployeeProfile, error)
}

// WorkforceGuardResolver enforces the durable offboarding deny before any
// temporary or future policy resolver can grant administration capabilities.
// A user with no employee profile keeps the base result; an offboarding user
// always receives no capabilities. Infrastructure errors fail closed.
type WorkforceGuardResolver struct {
	base   Resolver
	reader EmployeeStatusReader
}

func NewWorkforceGuardResolver(base Resolver, reader EmployeeStatusReader) *WorkforceGuardResolver {
	return &WorkforceGuardResolver{base: base, reader: reader}
}

func (r *WorkforceGuardResolver) Resolve(ctx context.Context, userID identity.UserID) (Capabilities, error) {
	if r.base == nil || r.reader == nil {
		return NoCapabilities(), nil
	}
	profile, err := r.reader.GetEmployeeProfile(ctx, userID)
	if err == nil && profile.Status == workforce.EmployeeStatusOffboarding {
		return NoCapabilities(), nil
	}
	if err != nil && !errors.Is(err, workforce.ErrNotFound) {
		return NoCapabilities(), fmt.Errorf("permission workforce guard: %w", err)
	}
	caps, err := r.base.Resolve(ctx, userID)
	if err != nil {
		return NoCapabilities(), err
	}
	return caps, nil
}
