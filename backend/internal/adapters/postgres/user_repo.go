package postgres

import (
	"context"
	"errors"
	"fmt"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/GravelEvolution/united-pass/backend/internal/identity"
)

// userColumns lists the users table columns in the fixed SELECT order used by
// scanUser. Keeping this order stable across all user queries prevents silent
// column-mismatch bugs.
const userColumns = `id, status, display_name, nickname, avatar_url, email,
       email_verified, phone, phone_verified, created_at, updated_at, version`

// identityLinkColumns lists the identity_links table columns in the fixed
// SELECT order used by scanIdentityLink.
const identityLinkColumns = `id, user_id, provider, provider_tenant_id,
       provider_subject, created_at, last_seen_at`

// UserRepository persists and retrieves United Pass user identities, external
// identity links, and personas from PostgreSQL. It wraps *pgxpool.Pool and owns
// all SQL; callers depend on the repository methods, never on pgx types.
type UserRepository struct {
	pool *pgxpool.Pool
}

// NewUserRepository constructs a UserRepository backed by the given pool. The
// pool's search_path runtime parameter must already be set to the configured
// schema (see NewPool).
func NewUserRepository(pool *pgxpool.Pool) *UserRepository {
	return &UserRepository{pool: pool}
}

// GetByID loads a user by stable United Pass user ID, including the user's
// personas. Returns identity.ErrUserNotFound when no row matches.
func (r *UserRepository) GetByID(ctx context.Context, userID identity.UserID) (identity.User, error) {
	row := r.pool.QueryRow(ctx,
		`SELECT `+userColumns+` FROM users WHERE id = $1`, string(userID))

	user, err := scanUser(row)
	if err != nil {
		return identity.User{}, mapUserError(err, "get user by id")
	}

	personas, err := r.GetPersonas(ctx, userID)
	if err != nil {
		return identity.User{}, err
	}
	user.Personas = personas

	return user, nil
}

// GetByIDForUpdate loads a user by ID within an existing transaction, acquiring
// a FOR UPDATE row lock. This is used when the caller is about to mutate the
// user row and must prevent concurrent modifications. Personas are not loaded
// because the caller only needs the locked user row. Returns
// identity.ErrUserNotFound when no row matches.
func (r *UserRepository) GetByIDForUpdate(ctx context.Context, tx pgx.Tx, userID identity.UserID) (identity.User, error) {
	row := tx.QueryRow(ctx,
		`SELECT `+userColumns+` FROM users WHERE id = $1 FOR UPDATE`, string(userID))

	user, err := scanUser(row)
	if err != nil {
		return identity.User{}, mapUserError(err, "get user by id for update")
	}
	return user, nil
}

// Create inserts a new user row. The caller is responsible for generating the
// stable user ID and validating the status before calling this method.
func (r *UserRepository) Create(ctx context.Context, user identity.User) error {
	_, err := r.pool.Exec(ctx,
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
		return fmt.Errorf("postgres: create user: %w", err)
	}
	return nil
}

// UpdateStatus sets the user's status and increments the optimistic-concurrency
// version. Returns identity.ErrUserNotFound when no row matches the given ID.
func (r *UserRepository) UpdateStatus(ctx context.Context, userID identity.UserID, status identity.UserStatus) error {
	tag, err := r.pool.Exec(ctx,
		`UPDATE users
            SET status = $2, updated_at = NOW(), version = version + 1
          WHERE id = $1`,
		string(userID),
		string(status),
	)
	if err != nil {
		return fmt.Errorf("postgres: update user status: %w", err)
	}
	if tag.RowsAffected() == 0 {
		return identity.ErrUserNotFound
	}
	return nil
}

// GetIdentityLink loads the identity link for a specific provider subject
// within a provider tenant. Returns identity.ErrUserNotFound when no link
// matches, since the absence of a link means the external identity is not
// known to United Pass.
func (r *UserRepository) GetIdentityLink(ctx context.Context, provider, providerTenantID, providerSubject string) (identity.IdentityLink, error) {
	row := r.pool.QueryRow(ctx,
		`SELECT `+identityLinkColumns+`
           FROM identity_links
          WHERE provider = $1
            AND provider_tenant_id = $2
            AND provider_subject = $3`,
		provider, providerTenantID, providerSubject)

	link, err := scanIdentityLink(row)
	if err != nil {
		return identity.IdentityLink{}, mapUserError(err, "get identity link")
	}
	return link, nil
}

// GetIdentityLinkByUserID loads the identity link binding a United Pass user
// to a provider subject within a provider tenant. Returns
// identity.ErrUserNotFound when no link matches.
func (r *UserRepository) GetIdentityLinkByUserID(ctx context.Context, provider, providerTenantID string, userID identity.UserID) (identity.IdentityLink, error) {
	row := r.pool.QueryRow(ctx,
		`SELECT `+identityLinkColumns+`
           FROM identity_links
          WHERE provider = $1
            AND provider_tenant_id = $2
            AND user_id = $3`,
		provider, providerTenantID, string(userID))

	link, err := scanIdentityLink(row)
	if err != nil {
		return identity.IdentityLink{}, mapUserError(err, "get identity link by user id")
	}
	return link, nil
}

// CreateIdentityLink inserts a new external identity link binding a provider
// subject to a stable United Pass user ID. The unique constraint on
// (provider, provider_tenant_id, provider_subject) prevents the same external
// identity from linking to multiple users; a violation is wrapped as an error.
func (r *UserRepository) CreateIdentityLink(ctx context.Context, link identity.IdentityLink) error {
	_, err := r.pool.Exec(ctx,
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
		return fmt.Errorf("postgres: create identity link: %w", err)
	}
	return nil
}

// GetPersonas returns all personas (consumer, employee) associated with the
// user, ordered alphabetically. Returns an empty (non-nil) slice when the user
// has no persona rows.
func (r *UserRepository) GetPersonas(ctx context.Context, userID identity.UserID) ([]identity.Persona, error) {
	rows, err := r.pool.Query(ctx,
		`SELECT persona FROM user_personas WHERE user_id = $1 ORDER BY persona`,
		string(userID))
	if err != nil {
		return nil, fmt.Errorf("postgres: get personas: %w", err)
	}
	defer rows.Close()

	personas := make([]identity.Persona, 0)
	for rows.Next() {
		var persona string
		if err := rows.Scan(&persona); err != nil {
			return nil, fmt.Errorf("postgres: scan persona row: %w", err)
		}
		personas = append(personas, identity.Persona(persona))
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("postgres: iterate persona rows: %w", err)
	}
	return personas, nil
}

// AddPersona associates a persona with a user. If the persona already exists
// the operation is a no-op (ON CONFLICT DO NOTHING), making the call idempotent.
func (r *UserRepository) AddPersona(ctx context.Context, userID identity.UserID, persona identity.Persona) error {
	_, err := r.pool.Exec(ctx,
		`INSERT INTO user_personas (user_id, persona, created_at)
         VALUES ($1, $2, NOW())
         ON CONFLICT (user_id, persona) DO NOTHING`,
		string(userID),
		string(persona),
	)
	if err != nil {
		return fmt.Errorf("postgres: add persona: %w", err)
	}
	return nil
}

// scanUser maps a single database row (via pgx.Row) to an identity.User. The
// row must return columns in the order defined by userColumns. Personas are
// not loaded here; the caller is responsible for fetching them separately if
// needed.
func scanUser(row pgx.Row) (identity.User, error) {
	var (
		id     string
		status string
		user   identity.User
	)
	err := row.Scan(
		&id,
		&status,
		&user.DisplayName,
		&user.Nickname,
		&user.AvatarURL,
		&user.Email,
		&user.EmailVerified,
		&user.Phone,
		&user.PhoneVerified,
		&user.CreatedAt,
		&user.UpdatedAt,
		&user.Version,
	)
	if err != nil {
		return identity.User{}, err
	}
	user.ID = identity.UserID(id)
	user.Status = identity.UserStatus(status)
	return user, nil
}

// scanIdentityLink maps a single database row (via pgx.Row) to an
// identity.IdentityLink. The row must return columns in the order defined by
// identityLinkColumns.
func scanIdentityLink(row pgx.Row) (identity.IdentityLink, error) {
	var (
		userID string
		link   identity.IdentityLink
	)
	err := row.Scan(
		&link.ID,
		&userID,
		&link.Provider,
		&link.ProviderTenantID,
		&link.ProviderSubject,
		&link.CreatedAt,
		&link.LastSeenAt,
	)
	if err != nil {
		return identity.IdentityLink{}, err
	}
	link.UserID = identity.UserID(userID)
	return link, nil
}

// mapUserError translates pgx-level errors (notably ErrNoRows) into domain
// errors and wraps unexpected errors with context. op describes the calling
// operation for diagnostic context.
func mapUserError(err error, op string) error {
	if errors.Is(err, pgx.ErrNoRows) {
		return identity.ErrUserNotFound
	}
	return fmt.Errorf("postgres: %s: %w", op, err)
}
