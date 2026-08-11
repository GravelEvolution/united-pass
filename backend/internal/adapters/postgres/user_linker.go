//
// Copyright (c) 2026 Chen Jiajie(Ariakage)
//
// Author: Chen Jiajie(Ariakage) <ariakage233@gmail.com>
// Date: 2026-08-05
// Description: PostgreSQL identity linking between local users and provider identities
//

package postgres

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"errors"
	"fmt"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"

	"github.com/GravelEvolution/united-pass/backend/internal/identity"
)

// GetOrCreateUserByProviderSubject implements identity.UserLinker. It resolves
// a provider subject to the stable United Pass user bound via an identity
// link, creating the user, the link, and the consumer persona on first login.
//
// The existing-link path runs without a transaction: the link lookup and the
// subsequent user read (GetByID, which also loads personas) each use the pool
// connection directly, so no nested pool query can ever hold two connections.
// Only first-login creation opens a transaction, and all of its writes share
// the transaction's connection. When a concurrent first login wins the unique
// constraint race, the losing transaction is rolled back explicitly before
// the winner is re-read through the pool, so a pool with MaxConns=1 (or an
// exhausted pool) can never deadlock on itself.
//
// Concurrency is safe: if two requests race on the same provider subject, the
// unique constraint on (provider, provider_tenant_id, provider_subject) makes
// exactly one transaction commit the link; the loser rolls back (discarding
// its partial user row) and re-reads the winner's user.
func (r *UserRepository) GetOrCreateUserByProviderSubject(
	ctx context.Context,
	provider string,
	providerTenantID string,
	info identity.ProviderUserInfo,
) (identity.User, error) {
	// Fast path: an existing identity link needs no transaction.
	link, err := r.GetIdentityLink(ctx, provider, providerTenantID, info.Subject)
	if err == nil {
		// This is the authoritative login-observation clock used by the Phase
		// 5 directory. It updates only the already-explicit provider binding;
		// no email/name matching or identity relinking occurs.
		if _, touchErr := r.pool.Exec(ctx,
			`UPDATE identity_links SET last_seen_at = NOW() WHERE id = $1`, link.ID); touchErr != nil {
			return identity.User{}, fmt.Errorf("postgres: update identity link last seen: %w", touchErr)
		}
		return r.GetByID(ctx, link.UserID)
	}
	if !errors.Is(err, identity.ErrUserNotFound) {
		return identity.User{}, err
	}

	// First login: create user, link and consumer persona atomically. If any
	// step fails, everything is rolled back — no orphan user rows.
	tx, err := r.pool.Begin(ctx)
	if err != nil {
		return identity.User{}, fmt.Errorf("postgres: begin identity link transaction: %w", err)
	}
	defer func() { _ = tx.Rollback(ctx) }() // no-op after Commit

	now := time.Now().UTC()
	userID := identity.UserID(generateUserID())
	user := identity.User{
		ID:            userID,
		Status:        identity.UserStatusActive,
		DisplayName:   info.DisplayName,
		Email:         info.Email,
		EmailVerified: info.EmailVerified,
		Phone:         info.Phone,
		CreatedAt:     now,
		UpdatedAt:     now,
		Version:       1,
	}
	if err := createUserTx(ctx, tx, user); err != nil {
		return identity.User{}, err
	}

	newLink := identity.IdentityLink{
		ID:               generateLinkID(),
		UserID:           userID,
		Provider:         provider,
		ProviderTenantID: providerTenantID,
		ProviderSubject:  info.Subject,
		CreatedAt:        now,
		LastSeenAt:       now,
	}
	if err := createIdentityLinkTx(ctx, tx, newLink); err != nil {
		if isUniqueViolation(err) {
			// A concurrent first login committed first. Release our losing
			// transaction BEFORE reading the winner through the pool: the
			// transaction still holds a connection, and querying the pool
			// while it is held can deadlock when MaxConns=1 or the pool is
			// exhausted. A subsequent deferred Rollback on the closed
			// transaction is a harmless pgx.ErrTxClosed.
			if rollbackErr := tx.Rollback(ctx); rollbackErr != nil &&
				!errors.Is(rollbackErr, pgx.ErrTxClosed) {
				return identity.User{}, fmt.Errorf("postgres: rollback losing identity link transaction: %w", rollbackErr)
			}
			winnerLink, getErr := r.GetIdentityLink(ctx, provider, providerTenantID, info.Subject)
			if getErr != nil {
				return identity.User{}, getErr
			}
			return r.GetByID(ctx, winnerLink.UserID)
		}
		return identity.User{}, err
	}

	// Persona creation is part of the transaction; failures roll back the
	// user and link too.
	if err := addPersonaTx(ctx, tx, userID, identity.PersonaConsumer); err != nil {
		return identity.User{}, err
	}

	if err := tx.Commit(ctx); err != nil {
		return identity.User{}, fmt.Errorf("postgres: commit identity link transaction: %w", err)
	}
	user.Personas = []identity.Persona{identity.PersonaConsumer}
	return user, nil
}

// createUserTx inserts a user within an existing transaction.
func createUserTx(ctx context.Context, tx pgx.Tx, user identity.User) error {
	_, err := tx.Exec(ctx,
		`INSERT INTO users (id, status, display_name, nickname, avatar_url, email,
                            email_verified, phone, phone_verified, created_at,
                            updated_at, version)
         VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12)`,
		string(user.ID),
		string(user.Status),
		user.DisplayName,
		user.Nickname,
		user.AvatarURL,
		user.Email,
		user.EmailVerified,
		user.Phone,
		user.PhoneVerified,
		user.CreatedAt,
		user.UpdatedAt,
		user.Version,
	)
	if err != nil {
		return fmt.Errorf("postgres: create user in transaction: %w", err)
	}
	return nil
}

// createIdentityLinkTx inserts an identity link within an existing
// transaction. The unique constraint on (provider, provider_tenant_id,
// provider_subject) enforces single-winner semantics for concurrent first
// logins.
func createIdentityLinkTx(ctx context.Context, tx pgx.Tx, link identity.IdentityLink) error {
	_, err := tx.Exec(ctx,
		`INSERT INTO identity_links (id, user_id, provider, provider_tenant_id,
                                     provider_subject, created_at, last_seen_at)
         VALUES ($1, $2, $3, $4, $5, $6, $7)`,
		link.ID,
		string(link.UserID),
		link.Provider,
		link.ProviderTenantID,
		link.ProviderSubject,
		link.CreatedAt,
		link.LastSeenAt,
	)
	if err != nil {
		return fmt.Errorf("postgres: create identity link in transaction: %w", err)
	}
	return nil
}

// addPersonaTx associates a persona with a user within an existing
// transaction. It is idempotent (ON CONFLICT DO NOTHING).
func addPersonaTx(ctx context.Context, tx pgx.Tx, userID identity.UserID, persona identity.Persona) error {
	_, err := tx.Exec(ctx,
		`INSERT INTO user_personas (user_id, persona, created_at)
         VALUES ($1, $2, NOW())
         ON CONFLICT (user_id, persona) DO NOTHING`,
		string(userID),
		string(persona),
	)
	if err != nil {
		return fmt.Errorf("postgres: add persona in transaction: %w", err)
	}
	return nil
}

// isUniqueViolation reports whether err wraps a PostgreSQL unique_violation
// (SQLSTATE 23505).
func isUniqueViolation(err error) bool {
	var pgErr *pgconn.PgError
	return errors.As(err, &pgErr) && pgErr.Code == "23505"
}

// generateUserID returns a random stable user ID: "user_" followed by 32 hex
// characters (128 bits of entropy).
func generateUserID() string {
	return "user_" + randomHex(16)
}

// generateLinkID returns a random identity link ID: 32 hex characters.
func generateLinkID() string {
	return randomHex(16)
}

func randomHex(n int) string {
	buf := make([]byte, n)
	if _, err := rand.Read(buf); err != nil {
		// crypto/rand failure is fatal for identity generation.
		panic(fmt.Sprintf("postgres: generate random id: %v", err))
	}
	return hex.EncodeToString(buf)
}
