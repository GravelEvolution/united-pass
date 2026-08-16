//
// Copyright (c) 2026 Chen Jiajie(Ariakage)
//
// Author: Chen Jiajie(Ariakage) <ariakage233@gmail.com>
// Date: 2026-08-16
// Description: PostgreSQL account self-service persistence
//

package postgres

import (
	"context"
	"errors"
	"fmt"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"

	"github.com/GravelEvolution/united-pass/backend/internal/identity"
)

// UpdateOwnProfile applies only explicitly supplied public profile fields.
// Empty nickname is a valid request (it removes the nickname); display-name
// validation is owned by the use-case boundary before this method is called.
func (r *UserRepository) UpdateOwnProfile(
	ctx context.Context,
	userID identity.UserID,
	displayName, nickname *string,
) error {
	tag, err := r.pool.Exec(ctx, `
		UPDATE users
		   SET display_name = COALESCE($2, display_name),
		       nickname = COALESCE($3, nickname),
		       updated_at = NOW(), version = version + 1
		 WHERE id = $1 AND status = 'active'`,
		string(userID), displayName, nickname)
	if err != nil {
		return fmt.Errorf("postgres: update own profile: %w", err)
	}
	if tag.RowsAffected() == 0 {
		return identity.ErrUserNotFound
	}
	return nil
}

// SaveAvatar atomically replaces the user's controlled avatar bytes and the
// same-origin URL exposed from the users row. A failed transaction can never
// leave a URL pointing at missing media or orphan a newly written blob.
func (r *UserRepository) SaveAvatar(
	ctx context.Context,
	userID identity.UserID,
	avatarID string,
	content []byte,
	etag string,
) (string, error) {
	tx, err := r.pool.Begin(ctx)
	if err != nil {
		return "", fmt.Errorf("postgres: begin avatar replacement: %w", err)
	}
	defer func() { _ = tx.Rollback(ctx) }()

	if _, err := tx.Exec(ctx, `
		INSERT INTO user_avatars (avatar_id, user_id, content_type, content, etag, updated_at)
		VALUES ($1, $2, 'image/png', $3, $4, NOW())
		ON CONFLICT (user_id) DO UPDATE
		SET avatar_id = EXCLUDED.avatar_id,
		    content_type = EXCLUDED.content_type,
		    content = EXCLUDED.content,
		    etag = EXCLUDED.etag,
		    updated_at = NOW()`, avatarID, string(userID), content, etag); err != nil {
		return "", fmt.Errorf("postgres: save avatar: %w", err)
	}

	avatarURL := "/api/v1/media/avatars/" + avatarID + ".png"
	tag, err := tx.Exec(ctx, `
		UPDATE users
		   SET avatar_url = $2, updated_at = NOW(), version = version + 1
		 WHERE id = $1 AND status = 'active'`, string(userID), avatarURL)
	if err != nil {
		return "", fmt.Errorf("postgres: update avatar URL: %w", err)
	}
	if tag.RowsAffected() == 0 {
		return "", identity.ErrUserNotFound
	}
	if err := tx.Commit(ctx); err != nil {
		return "", fmt.Errorf("postgres: commit avatar replacement: %w", err)
	}
	return avatarURL, nil
}

// GetAvatar returns controlled, already-sanitized PNG bytes by opaque media
// ID. Missing IDs intentionally share identity.ErrUserNotFound so the HTTP
// boundary emits its standard non-enumerating 404.
func (r *UserRepository) GetAvatar(ctx context.Context, avatarID string) ([]byte, string, error) {
	var content []byte
	var etag string
	err := r.pool.QueryRow(ctx, `
		SELECT content, etag FROM user_avatars WHERE avatar_id = $1`, avatarID).
		Scan(&content, &etag)
	if errors.Is(err, pgx.ErrNoRows) {
		return nil, "", identity.ErrUserNotFound
	}
	if err != nil {
		return nil, "", fmt.Errorf("postgres: get avatar: %w", err)
	}
	return content, etag, nil
}

// CreateContactChange supersedes any prior active request for the same user
// and contact kind, clears expired PII, then persists the new hashed opaque
// capability. The provider notification is sent only after this succeeds.
func (r *UserRepository) CreateContactChange(ctx context.Context, req identity.ContactChangeRequest) error {
	tx, err := r.pool.Begin(ctx)
	if err != nil {
		return fmt.Errorf("postgres: begin contact change: %w", err)
	}
	defer func() { _ = tx.Rollback(ctx) }()

	if _, err := tx.Exec(ctx, `
		UPDATE contact_change_requests
		   SET status = 'failed', value = '', claim_id = '', claim_expires_at = NULL,
		       updated_at = NOW()
		 WHERE status IN ('pending', 'verifying') AND expires_at <= NOW()`); err != nil {
		return fmt.Errorf("postgres: expire contact changes: %w", err)
	}
	if _, err := tx.Exec(ctx, `
		UPDATE contact_change_requests
		   SET status = 'superseded', value = '', claim_id = '', claim_expires_at = NULL,
		       updated_at = NOW()
		 WHERE user_id = $1 AND kind = $2 AND status IN ('pending', 'verifying')`,
		string(req.UserID), string(req.Kind)); err != nil {
		return fmt.Errorf("postgres: supersede contact change: %w", err)
	}
	if _, err := tx.Exec(ctx, `
		INSERT INTO contact_change_requests
		       (request_id_hash, user_id, session_id, kind, value, expires_at)
		VALUES ($1, $2, $3, $4, $5, $6)`,
		req.RequestIDHash, string(req.UserID), req.SessionID, string(req.Kind), req.Value, req.ExpiresAt); err != nil {
		return fmt.Errorf("postgres: create contact change: %w", err)
	}
	if err := tx.Commit(ctx); err != nil {
		return fmt.Errorf("postgres: commit contact change: %w", err)
	}
	return nil
}

// CancelContactChange terminally clears a request whose provider notification
// could not be created. No verification capability survives a failed begin.
func (r *UserRepository) CancelContactChange(ctx context.Context, requestIDHash string) error {
	_, err := r.pool.Exec(ctx, `
		UPDATE contact_change_requests
		   SET status = 'failed', value = '', claim_id = '', claim_expires_at = NULL,
		       updated_at = NOW()
		 WHERE request_id_hash = $1 AND status IN ('pending', 'verifying')`, requestIDHash)
	if err != nil {
		return fmt.Errorf("postgres: cancel contact change: %w", err)
	}
	return nil
}

// ClaimContactChange leases a pending request to one verification attempt.
// An expired verifying lease is recoverable, while another live claimant is
// distinguished from a missing/expired capability.
func (r *UserRepository) ClaimContactChange(
	ctx context.Context,
	requestIDHash string,
	userID identity.UserID,
	sessionID, claimID string,
	claimTTL time.Duration,
) (identity.ContactChangeRequest, error) {
	now := time.Now().UTC()
	claimExpiresAt := now.Add(claimTTL)
	row := r.pool.QueryRow(ctx, `
		UPDATE contact_change_requests
		   SET status = 'verifying', claim_id = $4, claim_expires_at = $5, updated_at = NOW()
		 WHERE request_id_hash = $1 AND user_id = $2 AND session_id = $3
		   AND expires_at > $6 AND attempts < 5
		   AND (status = 'pending' OR (status = 'verifying' AND claim_expires_at <= $6))
		RETURNING kind, value, attempts, expires_at`,
		requestIDHash, string(userID), sessionID, claimID, claimExpiresAt, now)

	req := identity.ContactChangeRequest{
		RequestIDHash: requestIDHash,
		UserID:        userID,
		SessionID:     sessionID,
	}
	if err := row.Scan(&req.Kind, &req.Value, &req.Attempts, &req.ExpiresAt); err == nil {
		return req, nil
	} else if !errors.Is(err, pgx.ErrNoRows) {
		return identity.ContactChangeRequest{}, fmt.Errorf("postgres: claim contact change: %w", err)
	}

	var status string
	var expiresAt time.Time
	err := r.pool.QueryRow(ctx, `
		SELECT status, expires_at FROM contact_change_requests
		 WHERE request_id_hash = $1 AND user_id = $2 AND session_id = $3`,
		requestIDHash, string(userID), sessionID).Scan(&status, &expiresAt)
	if errors.Is(err, pgx.ErrNoRows) || err == nil && (status != "verifying" || !expiresAt.After(now)) {
		return identity.ContactChangeRequest{}, identity.ErrContactRequestNotFound
	}
	if err != nil {
		return identity.ContactChangeRequest{}, fmt.Errorf("postgres: inspect contact claim: %w", err)
	}
	return identity.ContactChangeRequest{}, identity.ErrContactRequestClaimed
}

// ReleaseContactChange relinquishes a claim after provider rejection or an
// infrastructure failure. Invalid user codes consume an attempt; provider
// failures do not. Five invalid attempts terminally fail and clear the PII.
func (r *UserRepository) ReleaseContactChange(
	ctx context.Context,
	requestIDHash, claimID string,
	invalidCode bool,
) error {
	increment := 0
	if invalidCode {
		increment = 1
	}
	tag, err := r.pool.Exec(ctx, `
		UPDATE contact_change_requests
		   SET attempts = attempts + $3,
		       status = CASE WHEN attempts + $3 >= 5 THEN 'failed' ELSE 'pending' END,
		       value = CASE WHEN attempts + $3 >= 5 THEN '' ELSE value END,
		       claim_id = '', claim_expires_at = NULL, updated_at = NOW()
		 WHERE request_id_hash = $1 AND status = 'verifying' AND claim_id = $2`,
		requestIDHash, claimID, increment)
	if err != nil {
		return fmt.Errorf("postgres: release contact change: %w", err)
	}
	if tag.RowsAffected() == 0 {
		return identity.ErrContactRequestNotFound
	}
	return nil
}

// CompleteContactChange mirrors a provider-verified contact and terminalizes
// the request in one PostgreSQL transaction. A local failure is retryable: the
// provider adapter performs authoritative readback on the next attempt.
func (r *UserRepository) CompleteContactChange(
	ctx context.Context,
	requestIDHash, claimID string,
) error {
	tx, err := r.pool.Begin(ctx)
	if err != nil {
		return fmt.Errorf("postgres: begin contact completion: %w", err)
	}
	defer func() { _ = tx.Rollback(ctx) }()

	var userID identity.UserID
	var kind identity.ContactKind
	var value string
	err = tx.QueryRow(ctx, `
		SELECT user_id, kind, value
		  FROM contact_change_requests
		 WHERE request_id_hash = $1 AND status = 'verifying' AND claim_id = $2
		 FOR UPDATE`, requestIDHash, claimID).Scan(&userID, &kind, &value)
	if errors.Is(err, pgx.ErrNoRows) {
		return identity.ErrContactRequestNotFound
	}
	if err != nil {
		return fmt.Errorf("postgres: lock contact completion: %w", err)
	}

	var tag pgconn.CommandTag
	switch kind {
	case identity.ContactKindEmail:
		tag, err = tx.Exec(ctx, `
			UPDATE users SET email = $2, email_verified = TRUE,
			       updated_at = NOW(), version = version + 1
			 WHERE id = $1 AND status = 'active'`, string(userID), value)
	case identity.ContactKindPhone:
		tag, err = tx.Exec(ctx, `
			UPDATE users SET phone = $2, phone_verified = TRUE,
			       updated_at = NOW(), version = version + 1
			 WHERE id = $1 AND status = 'active'`, string(userID), value)
	default:
		return fmt.Errorf("postgres: unsupported contact kind %q", kind)
	}
	if err != nil {
		return fmt.Errorf("postgres: mirror verified contact: %w", err)
	}
	if tag.RowsAffected() == 0 {
		return identity.ErrUserNotFound
	}

	if _, err := tx.Exec(ctx, `
		UPDATE contact_change_requests
		   SET status = 'completed', value = '', claim_id = '', claim_expires_at = NULL,
		       completed_at = NOW(), updated_at = NOW()
		 WHERE request_id_hash = $1 AND claim_id = $2`, requestIDHash, claimID); err != nil {
		return fmt.Errorf("postgres: complete contact request: %w", err)
	}
	if err := tx.Commit(ctx); err != nil {
		return fmt.Errorf("postgres: commit contact completion: %w", err)
	}
	return nil
}
