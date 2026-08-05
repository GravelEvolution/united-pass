package postgres

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"errors"
	"fmt"
	"time"

	"github.com/jackc/pgx/v5/pgconn"

	"github.com/GravelEvolution/united-pass/backend/internal/identity"
)

// GetOrCreateUserByProviderSubject implements identity.UserLinker. It resolves
// a provider subject to the stable United Pass user bound via an identity
// link, creating the user and the link on first login.
//
// First-login creation is concurrency safe: if two requests race on the same
// provider subject, the unique constraint on
// (provider, provider_tenant_id, provider_subject) makes exactly one link
// succeed; the loser re-reads the winner's link and returns that user.
func (r *UserRepository) GetOrCreateUserByProviderSubject(
	ctx context.Context,
	provider string,
	providerTenantID string,
	info identity.ProviderUserInfo,
) (identity.User, error) {
	link, err := r.GetIdentityLink(ctx, provider, providerTenantID, info.Subject)
	if err == nil {
		return r.GetByID(ctx, link.UserID)
	}
	if !errors.Is(err, identity.ErrUserNotFound) {
		return identity.User{}, err
	}

	// First login: create the local user and bind the provider subject.
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
	if err := r.Create(ctx, user); err != nil {
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
	if err := r.CreateIdentityLink(ctx, newLink); err != nil {
		if isUniqueViolation(err) {
			// Concurrent first login won the race: reuse its link.
			link, getErr := r.GetIdentityLink(ctx, provider, providerTenantID, info.Subject)
			if getErr != nil {
				return identity.User{}, getErr
			}
			return r.GetByID(ctx, link.UserID)
		}
		return identity.User{}, err
	}

	// New accounts default to the consumer persona (idempotent).
	_ = r.AddPersona(ctx, userID, identity.PersonaConsumer)

	return user, nil
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
