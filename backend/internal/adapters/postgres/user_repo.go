//
// Copyright (c) 2026 Chen Jiajie(Ariakage)
//
// Author: Chen Jiajie(Ariakage) <ariakage233@gmail.com>
// Date: 2026-08-05
// Description: PostgreSQL repository for user accounts
//

package postgres

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/GravelEvolution/united-pass/backend/internal/identity"
	"github.com/GravelEvolution/united-pass/backend/internal/phoneverify"
)

const (
	phoneVerifySnapshotUserSQL = `
SELECT phone
  FROM users
 WHERE id = $1`

	phoneVerifyLockUserSQL = `
SELECT status, phone, phone_verified, version, security_epoch
  FROM users
 WHERE id = $1
 FOR UPDATE`

	phoneVerifyLockOtherOwnerSQL = `
SELECT id
  FROM users
 WHERE phone = $1
   AND id <> $2
 ORDER BY id
 LIMIT 1
 FOR UPDATE`

	phoneVerifyAdvanceUserSQL = `
UPDATE users
   SET phone = $2,
       phone_verified = TRUE,
       updated_at = NOW(),
       version = version + 1,
       security_epoch = security_epoch + 1
 WHERE id = $1
   AND status = 'active'
   AND version = $3
   AND security_epoch = $4
 RETURNING version, security_epoch`
)

const phoneVerifySerializableAttempts = 3

var errPhoneVerifySnapshotChanged = errors.New("postgres: phone authority snapshot changed")

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

// UpdateProfile updates the user's self-service display name and nickname and
// increments the optimistic-concurrency version. Returns
// identity.ErrUserNotFound when no row matches the given ID.
func (r *UserRepository) UpdateProfile(ctx context.Context, userID identity.UserID, displayName, nickname string) error {
	tag, err := r.pool.Exec(ctx,
		`UPDATE users
            SET display_name = $2, nickname = $3, updated_at = NOW(), version = version + 1
          WHERE id = $1`,
		string(userID),
		displayName,
		nickname,
	)
	if err != nil {
		return fmt.Errorf("postgres: update user profile: %w", err)
	}
	if tag.RowsAffected() == 0 {
		return identity.ErrUserNotFound
	}
	return nil
}

// UpdateAvatar updates the user's avatar URL and increments the
// optimistic-concurrency version. Returns identity.ErrUserNotFound when no row
// matches the given ID.
func (r *UserRepository) UpdateAvatar(ctx context.Context, userID identity.UserID, avatarURL string) error {
	tag, err := r.pool.Exec(ctx,
		`UPDATE users
            SET avatar_url = $2, updated_at = NOW(), version = version + 1
          WHERE id = $1`,
		string(userID),
		avatarURL,
	)
	if err != nil {
		return fmt.Errorf("postgres: update user avatar: %w", err)
	}
	if tag.RowsAffected() == 0 {
		return identity.ErrUserNotFound
	}
	return nil
}

// UpdatePhone atomically binds the exact SMS-verified phone to one active user.
// It never selects or merges accounts by phone. The user, previous phone and
// requested phone use the same advisory-lock namespaces as WeChat onboarding;
// another owner therefore fails closed with phoneverify.ErrPhoneConflict.
// A successful authority change advances both version and security_epoch and
// appends its audit plus notification intent in the same transaction.
func (r *UserRepository) UpdatePhone(ctx context.Context, userID identity.UserID, phone string) error {
	if r == nil || r.pool == nil || userID == "" || phone == "" || phone != strings.TrimSpace(phone) {
		return phoneverify.ErrInvalidInput
	}

	var lastErr error
	for attempt := 0; attempt < phoneVerifySerializableAttempts; attempt++ {
		err := r.updatePhoneOnce(ctx, userID, phone)
		if err == nil {
			return nil
		}
		if !isAuthoritySerializationFailure(err) && !errors.Is(err, errPhoneVerifySnapshotChanged) {
			return err
		}
		lastErr = err
		if ctx.Err() != nil {
			return ctx.Err()
		}
	}
	return fmt.Errorf("postgres: serializable SMS phone settlement exhausted: %w", lastErr)
}

func (r *UserRepository) updatePhoneOnce(ctx context.Context, userID identity.UserID, phone string) error {
	tx, err := r.pool.BeginTx(ctx, pgx.TxOptions{IsoLevel: pgx.Serializable})
	if err != nil {
		return fmt.Errorf("postgres: begin SMS phone authority transaction: %w", err)
	}
	defer func() { _ = tx.Rollback(ctx) }()

	// The initial snapshot discovers the previous phone so both releasing it
	// and claiming the requested one participate in the global lock order. A
	// concurrent change is detected after the locks and retried in a fresh
	// serializable transaction.
	var snapshotPhone string
	if err := tx.QueryRow(ctx, phoneVerifySnapshotUserSQL, string(userID)).Scan(&snapshotPhone); errors.Is(err, pgx.ErrNoRows) {
		return identity.ErrUserNotFound
	} else if err != nil {
		return fmt.Errorf("postgres: read SMS phone authority snapshot: %w", err)
	}

	lockKeys := sortedAuthorityLockKeys(
		authorityUserLockKey(userID),
		authorityPhoneLockKey(snapshotPhone),
		authorityPhoneLockKey(phone),
	)
	for _, key := range lockKeys {
		if _, err := tx.Exec(ctx, `SELECT pg_advisory_xact_lock(hashtextextended($1, 0))`, key); err != nil {
			return fmt.Errorf("postgres: lock SMS phone authority key: %w", err)
		}
	}

	var status, currentPhone string
	var phoneVerified bool
	var version int
	var securityEpoch int64
	err = tx.QueryRow(ctx, phoneVerifyLockUserSQL, string(userID)).Scan(
		&status, &currentPhone, &phoneVerified, &version, &securityEpoch,
	)
	if errors.Is(err, pgx.ErrNoRows) {
		return identity.ErrUserNotFound
	}
	if err != nil {
		return fmt.Errorf("postgres: lock SMS phone target: %w", err)
	}
	if status != string(identity.UserStatusActive) {
		return identity.ErrUserNotFound
	}
	if currentPhone != snapshotPhone {
		return errPhoneVerifySnapshotChanged
	}

	var conflictingUserID string
	ownerErr := tx.QueryRow(ctx, phoneVerifyLockOtherOwnerSQL, phone, string(userID)).Scan(&conflictingUserID)
	if ownerErr == nil {
		return phoneverify.ErrPhoneConflict
	}
	if !errors.Is(ownerErr, pgx.ErrNoRows) {
		return fmt.Errorf("postgres: lock SMS phone owner: %w", ownerErr)
	}

	// A consumed SMS proof for the already-verified exact phone is an
	// idempotent no-op. In particular it does not churn security generations
	// or duplicate the notification outbox.
	if currentPhone == phone && phoneVerified {
		return nil
	}

	previousVersion, previousEpoch := version, securityEpoch
	err = tx.QueryRow(ctx, phoneVerifyAdvanceUserSQL,
		string(userID), phone, previousVersion, previousEpoch,
	).Scan(&version, &securityEpoch)
	if errors.Is(err, pgx.ErrNoRows) {
		return identity.ErrUserNotFound
	}
	if err != nil {
		if isUniqueViolation(err) {
			return phoneverify.ErrPhoneConflict
		}
		return fmt.Errorf("postgres: advance SMS phone security state: %w", err)
	}

	digest, err := DeriveWeChatAuthorityReplayDigest(WeChatAuthorityReplayMaterial{
		Flow:             WeChatAuthorityFlowSMSPhoneVerified,
		TargetUserID:     userID,
		AuthorityVersion: int64(previousVersion),
		SecurityEpoch:    previousEpoch,
	})
	if err != nil {
		return fmt.Errorf("postgres: derive SMS phone authority effect: %w", err)
	}
	if _, err := NewWeChatAuthorityEffectStore().RecordTx(ctx, tx, WeChatAuthorityEffect{
		ReplayDigest: digest,
		Kind:         WeChatAuthorityEffectSMSPhoneVerified,
		TargetUserID: userID,
		OccurredAt:   time.Now().UTC(),
	}); err != nil {
		return fmt.Errorf("postgres: append SMS phone authority effect: %w", err)
	}

	if err := tx.Commit(ctx); err != nil {
		return fmt.Errorf("postgres: commit SMS phone authority transaction: %w", err)
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
// identity.ErrUserNotFound when no link matches and
// identity.ErrIdentityLinkConflict when legacy data contains more than one
// candidate. Callers must never select an arbitrary provider subject.
func (r *UserRepository) GetIdentityLinkByUserID(ctx context.Context, provider, providerTenantID string, userID identity.UserID) (identity.IdentityLink, error) {
	rows, err := r.pool.Query(ctx,
		`SELECT `+identityLinkColumns+`
           FROM identity_links
          WHERE provider = $1
            AND provider_tenant_id = $2
			AND user_id = $3
		  ORDER BY id
		  LIMIT 2`,
		provider, providerTenantID, string(userID))
	if err != nil {
		return identity.IdentityLink{}, fmt.Errorf("postgres: get identity link by user id: %w", err)
	}
	defer rows.Close()

	links := make([]identity.IdentityLink, 0, 2)
	for rows.Next() {
		link, scanErr := scanIdentityLink(rows)
		if scanErr != nil {
			return identity.IdentityLink{}, fmt.Errorf("postgres: scan identity link by user id: %w", scanErr)
		}
		links = append(links, link)
	}
	if err := rows.Err(); err != nil {
		return identity.IdentityLink{}, fmt.Errorf("postgres: iterate identity links by user id: %w", err)
	}
	if len(links) == 0 {
		return identity.IdentityLink{}, identity.ErrUserNotFound
	}
	if len(links) != 1 {
		return identity.IdentityLink{}, identity.ErrIdentityLinkConflict
	}
	return links[0], nil
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

var _ phoneverify.Repository = (*UserRepository)(nil)
