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
// All writes for a first login happen inside a single transaction: if any step
// fails, everything is rolled back, so no orphan user rows can be left behind.
// Concurrency is safe: if two requests race on the same provider subject, the
// unique constraint on (provider, provider_tenant_id, provider_subject) makes
// exactly one transaction commit the link; the loser rolls back and re-reads
// the winner's user.
func (r *UserRepository) GetOrCreateUserByProviderSubject(
	ctx context.Context,
	provider string,
	providerTenantID string,
	info identity.ProviderUserInfo,
) (identity.User, error) {
	tx, err := r.pool.Begin(ctx)
	if err != nil {
		return identity.User{}, fmt.Errorf("postgres: begin identity link transaction: %w", err)
	}
	defer func() { _ = tx.Rollback(ctx) }() // no-op after Commit

	// 1. Look for an existing link inside the transaction.
	link, err := getIdentityLinkTx(ctx, tx, provider, providerTenantID, info.Subject)
	if err == nil {
		user, getErr := getByIDTx(ctx, tx, link.UserID)
		if getErr != nil {
			return identity.User{}, getErr
		}
		personas, getErr := r.GetPersonas(ctx, link.UserID)
		if getErr != nil {
			return identity.User{}, getErr
		}
		user.Personas = personas
		if err := tx.Commit(ctx); err != nil {
			return identity.User{}, fmt.Errorf("postgres: commit identity link transaction: %w", err)
		}
		return user, nil
	}
	if !errors.Is(err, identity.ErrUserNotFound) {
		return identity.User{}, err
	}

	// 2. First login: create user, link and consumer persona atomically.
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
			// A concurrent first login committed first. Roll back our partial
			// user row and return the winner's user.
			_ = tx.Rollback(ctx)
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

// getIdentityLinkTx loads an identity link within an existing transaction.
func getIdentityLinkTx(ctx context.Context, tx pgx.Tx, provider, providerTenantID, providerSubject string) (identity.IdentityLink, error) {
	row := tx.QueryRow(ctx,
		`SELECT `+identityLinkColumns+`
           FROM identity_links
          WHERE provider = $1
            AND provider_tenant_id = $2
            AND provider_subject = $3`,
		provider, providerTenantID, providerSubject)
	link, err := scanIdentityLink(row)
	if err != nil {
		return identity.IdentityLink{}, mapUserError(err, "get identity link in transaction")
	}
	return link, nil
}

// getByIDTx loads a user by ID within an existing transaction without
// personas.
func getByIDTx(ctx context.Context, tx pgx.Tx, userID identity.UserID) (identity.User, error) {
	row := tx.QueryRow(ctx,
		`SELECT `+userColumns+` FROM users WHERE id = $1`, string(userID))
	user, err := scanUser(row)
	if err != nil {
		return identity.User{}, mapUserError(err, "get user by id in transaction")
	}
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
