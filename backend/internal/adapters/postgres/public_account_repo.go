//
// Copyright (c) 2026 Chen Jiajie(Ariakage)
//
// Author: Chen Jiajie(Ariakage) <ariakage233@gmail.com>
// Date: 2026-08-16
// Description: PostgreSQL persistence for public registration and recovery bindings
//

package postgres

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/jackc/pgx/v5"

	"github.com/GravelEvolution/united-pass/backend/internal/auth"
	"github.com/GravelEvolution/united-pass/backend/internal/identity"
)

// CreatePendingRegistration atomically creates the stable United Pass user,
// its consumer persona and the explicit provider identity link. The account
// remains pending until the provider confirms the exact registered email.
func (r *UserRepository) CreatePendingRegistration(
	ctx context.Context,
	userID identity.UserID,
	provider, providerTenantID, username string,
	info identity.ProviderUserInfo,
) error {
	if userID == "" || provider == "" || info.Subject == "" {
		return errors.New("postgres: incomplete pending registration identity")
	}
	tx, err := r.pool.Begin(ctx)
	if err != nil {
		return fmt.Errorf("postgres: begin pending registration: %w", err)
	}
	defer func() { _ = tx.Rollback(ctx) }()

	now := time.Now().UTC()
	user := identity.User{
		ID: userID, Status: identity.UserStatusPending,
		DisplayName: username, Email: info.Email,
		EmailVerified: false, CreatedAt: now, UpdatedAt: now, Version: 1,
	}
	if err := createUserTx(ctx, tx, user); err != nil {
		if isUniqueViolation(err) {
			return auth.ErrRegistrationConflict
		}
		return err
	}
	link := identity.IdentityLink{
		ID: generateLinkID(), UserID: userID, Provider: provider,
		ProviderTenantID: providerTenantID, ProviderSubject: info.Subject,
		CreatedAt: now, LastSeenAt: now,
	}
	if err := createIdentityLinkTx(ctx, tx, link); err != nil {
		if isUniqueViolation(err) {
			return auth.ErrRegistrationConflict
		}
		return err
	}
	if err := addPersonaTx(ctx, tx, userID, identity.PersonaConsumer); err != nil {
		return err
	}
	if err := tx.Commit(ctx); err != nil {
		return fmt.Errorf("postgres: commit pending registration: %w", err)
	}
	return nil
}

// GetPublicAccountBinding resolves a server-issued stable user ID through an
// exact provider/tenant link. Email, username and phone never select the row.
func (r *UserRepository) GetPublicAccountBinding(
	ctx context.Context,
	userID identity.UserID,
	provider, providerTenantID string,
) (auth.PublicAccountBinding, error) {
	var binding auth.PublicAccountBinding
	err := r.pool.QueryRow(ctx, `
		SELECT u.id, l.provider, l.provider_tenant_id, l.provider_subject, u.email, u.status
		  FROM users u
		  JOIN identity_links l ON l.user_id = u.id
		 WHERE u.id = $1 AND l.provider = $2 AND l.provider_tenant_id = $3`,
		string(userID), provider, providerTenantID).
		Scan(&binding.UserID, &binding.Provider, &binding.ProviderTenantID,
			&binding.ProviderSubject, &binding.Email, &binding.Status)
	if errors.Is(err, pgx.ErrNoRows) {
		return auth.PublicAccountBinding{}, auth.ErrPublicAccountNotFound
	}
	if err != nil {
		return auth.PublicAccountBinding{}, fmt.Errorf("postgres: get public account binding: %w", err)
	}
	return binding, nil
}

// FindPasswordResetBinding accepts only a provider subject already bound by
// an explicit identity link. The user must be active and its locally mirrored
// email must already be provider-verified.
func (r *UserRepository) FindPasswordResetBinding(
	ctx context.Context,
	provider, providerTenantID, providerSubject string,
) (auth.PublicAccountBinding, error) {
	var binding auth.PublicAccountBinding
	err := r.pool.QueryRow(ctx, `
		SELECT u.id, l.provider, l.provider_tenant_id, l.provider_subject, u.email, u.status
		  FROM identity_links l
		  JOIN users u ON u.id = l.user_id
		 WHERE l.provider = $1 AND l.provider_tenant_id = $2
		   AND l.provider_subject = $3
		   AND u.status = 'active' AND u.email_verified = TRUE`,
		provider, providerTenantID, providerSubject).
		Scan(&binding.UserID, &binding.Provider, &binding.ProviderTenantID,
			&binding.ProviderSubject, &binding.Email, &binding.Status)
	if errors.Is(err, pgx.ErrNoRows) {
		return auth.PublicAccountBinding{}, auth.ErrPublicAccountNotFound
	}
	if err != nil {
		return auth.PublicAccountBinding{}, fmt.Errorf("postgres: find password reset binding: %w", err)
	}
	return binding, nil
}

// ActivatePendingRegistration mirrors the provider-verified registered email
// and changes only the matching pending account to active. Replays and any
// mismatch are reported as an already-consumed/invalid lifecycle capability.
func (r *UserRepository) ActivatePendingRegistration(
	ctx context.Context,
	binding auth.PublicAccountBinding,
) error {
	tx, err := r.pool.Begin(ctx)
	if err != nil {
		return fmt.Errorf("postgres: begin registration activation: %w", err)
	}
	defer func() { _ = tx.Rollback(ctx) }()

	var status identity.UserStatus
	var email, providerSubject string
	err = tx.QueryRow(ctx, `
		SELECT u.status, u.email, l.provider_subject
		  FROM users u JOIN identity_links l ON l.user_id = u.id
		 WHERE u.id = $1 AND l.provider = $2 AND l.provider_tenant_id = $3
		   AND l.provider_subject = $4
		 FOR UPDATE`, string(binding.UserID), binding.Provider,
		binding.ProviderTenantID, binding.ProviderSubject).
		Scan(&status, &email, &providerSubject)
	if errors.Is(err, pgx.ErrNoRows) {
		return auth.ErrPublicAccountNotFound
	}
	if err != nil {
		return fmt.Errorf("postgres: lock registration activation: %w", err)
	}
	if status != identity.UserStatusPending || providerSubject != binding.ProviderSubject ||
		!strings.EqualFold(email, binding.Email) {
		return auth.ErrLifecycleCodeInvalid
	}
	if _, err := tx.Exec(ctx, `
		UPDATE users
		   SET status = 'active', email_verified = TRUE,
		       updated_at = NOW(), version = version + 1
		 WHERE id = $1 AND status = 'pending'`, string(binding.UserID)); err != nil {
		return fmt.Errorf("postgres: activate registration: %w", err)
	}
	if err := tx.Commit(ctx); err != nil {
		return fmt.Errorf("postgres: commit registration activation: %w", err)
	}
	return nil
}
