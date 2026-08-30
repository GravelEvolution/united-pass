package postgres

import (
	"context"
	"fmt"

	"github.com/GravelEvolution/united-pass/backend/internal/accountcontact"
	"github.com/GravelEvolution/united-pass/backend/internal/identity"
	"github.com/jackc/pgx/v5/pgxpool"
)

// AccountContactRepository mirrors the verified provider email into the local
// identity without changing the stable user ID or identity link.
type AccountContactRepository struct {
	pool     *pgxpool.Pool
	provider string
	tenantID string
}

func NewAccountContactRepository(pool *pgxpool.Pool, provider, tenantID string) *AccountContactRepository {
	return &AccountContactRepository{pool: pool, provider: provider, tenantID: tenantID}
}

func (r *AccountContactRepository) UpdateVerifiedEmail(ctx context.Context, userID identity.UserID, email string) error {
	if r == nil || r.pool == nil || userID == "" || email == "" || r.provider == "" || r.tenantID == "" {
		return accountcontact.ErrUnavailable
	}
	result, err := r.pool.Exec(ctx, `
UPDATE users AS u
   SET email = $2,
       email_verified = TRUE,
       updated_at = NOW(),
       version = version + 1
 WHERE u.id = $1
   AND u.status = 'active'
   AND (u.email IS DISTINCT FROM $2 OR u.email_verified = FALSE)
   AND EXISTS (
       SELECT 1
         FROM identity_links AS l
        WHERE l.user_id = u.id
          AND l.provider = $3
          AND l.provider_tenant_id = $4
   )`, userID, email, r.provider, r.tenantID)
	if err != nil {
		if isUniqueViolation(err) {
			return accountcontact.ErrConflict
		}
		return fmt.Errorf("postgres: update verified account email: %w", err)
	}
	if result.RowsAffected() == 1 {
		return nil
	}
	var alreadyVerified bool
	if err := r.pool.QueryRow(ctx, `
SELECT EXISTS (
    SELECT 1
      FROM users AS u
      JOIN identity_links AS l ON l.user_id = u.id
     WHERE u.id = $1
       AND u.status = 'active'
       AND u.email = $2
       AND u.email_verified = TRUE
       AND l.provider = $3
       AND l.provider_tenant_id = $4
)`, userID, email, r.provider, r.tenantID).Scan(&alreadyVerified); err != nil {
		return fmt.Errorf("postgres: read verified account email: %w", err)
	}
	if !alreadyVerified {
		return accountcontact.ErrUnavailable
	}
	return nil
}

var _ accountcontact.Repository = (*AccountContactRepository)(nil)
