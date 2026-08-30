package postgres

import (
	"context"
	"errors"
	"fmt"
	"sort"
	"strings"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/GravelEvolution/united-pass/backend/internal/identity"
	"github.com/GravelEvolution/united-pass/backend/internal/registration"
	"github.com/GravelEvolution/united-pass/backend/internal/wechat"
	"github.com/GravelEvolution/united-pass/backend/internal/wechatregistration"
)

// RegistrationRepository atomically pre-creates pending local identities for
// provider users whose ID is controlled by United Pass. The provider subject
// and local user ID are deliberately identical, preventing first-login
// linking from creating an active account before email verification.
type RegistrationRepository struct {
	pool        *pgxpool.Pool
	provider    string
	tenantID    string
	intentStore weChatRegistrationIntentStore
}

func NewRegistrationRepository(pool *pgxpool.Pool, provider, tenantID string) *RegistrationRepository {
	return &RegistrationRepository{pool: pool, provider: provider, tenantID: tenantID}
}

// NewRegistrationRepositoryWithIntentStore keeps WeChat retry verifiers in a
// separately migrated operational database. Identity, phone, provider link and
// persona writes remain atomic in the unchanged United Pass authority schema.
func NewRegistrationRepositoryWithIntentStore(pool *pgxpool.Pool, provider, tenantID string, intentStore *WeChatRegistrationIntentStore) *RegistrationRepository {
	return &RegistrationRepository{pool: pool, provider: provider, tenantID: tenantID, intentStore: intentStore}
}

func (r *RegistrationRepository) CreatePending(ctx context.Context, input registration.PendingUser) error {
	if r == nil || r.pool == nil || input.UserID == "" || r.provider == "" || r.tenantID == "" || input.Status != registration.StatusPending || input.EmailVerified {
		return registration.ErrUnavailable
	}
	normalizedEmail := strings.ToLower(strings.TrimSpace(input.Email))
	if normalizedEmail == "" {
		return registration.ErrInvalidInput
	}
	tx, err := r.pool.Begin(ctx)
	if err != nil {
		return fmt.Errorf("postgres: begin registration transaction: %w", err)
	}
	defer func() { _ = tx.Rollback(ctx) }()

	// Serialize registrations for the same case-folded email before any
	// provider call can send mail. The advisory lock closes the SELECT/INSERT
	// race without imposing a new unique index on historical duplicate rows.
	if _, err := tx.Exec(ctx, `SELECT pg_advisory_xact_lock(hashtextextended($1, 0))`, normalizedEmail); err != nil {
		return fmt.Errorf("postgres: lock registration email: %w", err)
	}
	var emailExists bool
	if err := tx.QueryRow(ctx, `SELECT EXISTS (SELECT 1 FROM users WHERE LOWER(BTRIM(email)) = $1)`, normalizedEmail).Scan(&emailExists); err != nil {
		return fmt.Errorf("postgres: check registration email: %w", err)
	}
	if emailExists {
		return registration.ErrConflict
	}

	now := time.Now().UTC()
	userID := identity.UserID(input.UserID)
	user := identity.User{
		ID: userID, Status: identity.UserStatusPending, DisplayName: input.DisplayName,
		Email: input.Email, EmailVerified: false, CreatedAt: now, UpdatedAt: now, Version: 1,
	}
	if err := createUserTx(ctx, tx, user); err != nil {
		return mapRegistrationWriteError(err)
	}
	link := identity.IdentityLink{
		ID: generateLinkID(), UserID: userID, Provider: r.provider,
		ProviderTenantID: r.tenantID, ProviderSubject: input.UserID,
		CreatedAt: now, LastSeenAt: now,
	}
	if err := createIdentityLinkTx(ctx, tx, link); err != nil {
		return mapRegistrationWriteError(err)
	}
	if err := addPersonaTx(ctx, tx, userID, identity.PersonaConsumer); err != nil {
		return fmt.Errorf("postgres: create registration persona: %w", err)
	}
	if err := tx.Commit(ctx); err != nil {
		return fmt.Errorf("postgres: commit registration transaction: %w", err)
	}
	return nil
}

// ReservePendingWithWeChat atomically creates the pending user, optional
// verified phone, primary provider link, WeChat link and consumer persona. If
// an earlier provider call failed ambiguously, the same verified WeChat
// subject reuses and reconciles its pending reservation so the caller can
// safely retry the same provider-controlled user ID.
func (r *RegistrationRepository) ReservePendingWithWeChat(ctx context.Context, input wechatregistration.PendingUser) (string, error) {
	if r == nil || r.pool == nil || r.intentStore == nil || r.provider == "" || r.tenantID == "" || input.User.UserID == "" || input.User.Status != registration.StatusPending || input.User.EmailVerified || input.TenantID == "" || input.Subject == "" || input.ProviderIntent.Username == "" || input.ProviderIntent.Password == "" || input.ProviderIntent.DisplayName != input.User.DisplayName || !strings.EqualFold(strings.TrimSpace(input.ProviderIntent.Email), strings.TrimSpace(input.User.Email)) {
		return "", registration.ErrUnavailable
	}
	if input.ExpectedUserID != "" && strings.TrimSpace(input.ExpectedUserID) != input.ExpectedUserID {
		return "", registration.ErrInvalidInput
	}
	normalizedEmail := strings.ToLower(strings.TrimSpace(input.User.Email))
	if normalizedEmail == "" {
		return "", registration.ErrInvalidInput
	}
	tx, err := r.pool.Begin(ctx)
	if err != nil {
		return "", fmt.Errorf("postgres: begin WeChat registration transaction: %w", err)
	}
	defer func() { _ = tx.Rollback(ctx) }()
	// Use the exact same email key as CreatePending, plus the same subject and
	// phone namespaces as existing-account onboarding. Sorting every acquired
	// key prevents cross-flow lock-order inversions.
	lockKeys := []string{normalizedEmail, "wechat:" + input.TenantID + ":" + input.Subject}
	if input.Phone != "" {
		lockKeys = append(lockKeys, "phone:"+input.Phone)
	}
	sort.Strings(lockKeys)
	for _, key := range lockKeys {
		if _, err := tx.Exec(ctx, `SELECT pg_advisory_xact_lock(hashtextextended($1, 0))`, key); err != nil {
			return "", fmt.Errorf("postgres: lock WeChat registration authority key: %w", err)
		}
	}

	var existingUserID, existingStatus, existingEmail, existingPhone string
	var existingEmailVerified, existingPhoneVerified, primaryLinkExists bool
	var existingVersion int
	var existingSecurityEpoch int64
	existingQuery := `
SELECT u.id,
       u.status,
       u.email,
       u.email_verified,
       u.phone,
       u.phone_verified,
       u.version,
       u.security_epoch,
       EXISTS (
           SELECT 1
             FROM identity_links AS primary_link
            WHERE primary_link.user_id = u.id
              AND primary_link.provider = $4
              AND primary_link.provider_tenant_id = $5
              AND primary_link.provider_subject = u.id
       )
  FROM identity_links AS wechat_link
  JOIN users AS u ON u.id = wechat_link.user_id
 WHERE wechat_link.provider = $1
   AND wechat_link.provider_tenant_id = $2
   AND wechat_link.provider_subject = $3
 FOR UPDATE OF u`
	err = tx.QueryRow(ctx, existingQuery, wechat.ProviderName, input.TenantID, input.Subject, r.provider, r.tenantID).Scan(
		&existingUserID, &existingStatus, &existingEmail, &existingEmailVerified,
		&existingPhone, &existingPhoneVerified, &existingVersion, &existingSecurityEpoch,
		&primaryLinkExists,
	)
	switch {
	case err == nil:
		if input.ExpectedUserID != "" && existingUserID != input.ExpectedUserID {
			return "", registration.ErrConflict
		}
		if existingStatus != registration.StatusPending || existingEmailVerified || !strings.EqualFold(strings.TrimSpace(existingEmail), normalizedEmail) || (input.Phone != "" && existingPhone != "" && existingPhone != input.Phone) {
			return "", registration.ErrConflict
		}
		if input.Phone != "" {
			var conflictingUserID string
			phoneErr := tx.QueryRow(ctx, `SELECT id FROM users WHERE phone = $1 AND id <> $2 ORDER BY id LIMIT 1 FOR UPDATE`, input.Phone, existingUserID).Scan(&conflictingUserID)
			if phoneErr == nil {
				return "", registration.ErrConflict
			}
			if !errors.Is(phoneErr, pgx.ErrNoRows) {
				return "", fmt.Errorf("postgres: check retryable WeChat registration phone owner: %w", phoneErr)
			}
		}
		if verifyErr := r.intentStore.VerifyExisting(ctx, input.TenantID, input.Subject, existingUserID, input.ProviderIntent); verifyErr != nil {
			return "", verifyErr
		}
		// Reconcile only the still-pending identity selected by the same
		// server-verified WeChat subject. These repairs are idempotent and
		// remain inside the reservation transaction.
		if input.Phone != "" && (existingPhone != input.Phone || !existingPhoneVerified) {
			phoneVersion := existingVersion
			phoneSecurityEpoch := existingSecurityEpoch
			updateErr := tx.QueryRow(ctx, `
UPDATE users
   SET phone = $2,
       phone_verified = TRUE,
       updated_at = NOW(),
       version = version + 1,
       security_epoch = security_epoch + 1
 WHERE id = $1
   AND status = 'pending'
   AND email_verified = FALSE
   AND (phone = '' OR phone = $2)
   AND version = $3
   AND security_epoch = $4
 RETURNING version, security_epoch`, existingUserID, input.Phone, phoneVersion, phoneSecurityEpoch).Scan(&existingVersion, &existingSecurityEpoch)
			if updateErr != nil {
				if errors.Is(updateErr, pgx.ErrNoRows) {
					return "", registration.ErrConflict
				}
				return "", fmt.Errorf("postgres: reconcile WeChat registration phone: %w", updateErr)
			}
			if effectErr := recordPendingPhoneVerifiedWeChatAuthorityEffect(
				ctx, tx, input.TenantID, input.Subject, identity.UserID(existingUserID),
				phoneVersion, phoneSecurityEpoch, time.Now().UTC(),
			); effectErr != nil {
				return "", effectErr
			}
		}
		userID := identity.UserID(existingUserID)
		if !primaryLinkExists {
			primary := identity.IdentityLink{ID: generateLinkID(), UserID: userID, Provider: r.provider, ProviderTenantID: r.tenantID, ProviderSubject: existingUserID, CreatedAt: time.Now().UTC(), LastSeenAt: time.Now().UTC()}
			if createErr := createIdentityLinkTx(ctx, tx, primary); createErr != nil {
				return "", mapRegistrationWriteError(createErr)
			}
		}
		if personaErr := addPersonaTx(ctx, tx, userID, identity.PersonaConsumer); personaErr != nil {
			return "", fmt.Errorf("postgres: reconcile WeChat registration persona: %w", personaErr)
		}
		if effectErr := recordPendingWeChatAuthorityEffect(ctx, tx, input.TenantID, input.Subject, userID, time.Now().UTC()); effectErr != nil {
			return "", effectErr
		}
		if commitErr := tx.Commit(ctx); commitErr != nil {
			return "", fmt.Errorf("postgres: commit WeChat registration reconciliation: %w", commitErr)
		}
		return existingUserID, nil
	case !errors.Is(err, pgx.ErrNoRows):
		return "", fmt.Errorf("postgres: read retryable WeChat registration: %w", err)
	}
	if input.ExpectedUserID != "" {
		// Recovery is authorized only for the exact pending identity already
		// bound into the encrypted onboarding challenge. Never recreate it or
		// reconcile a different reservation when that row/link disappeared.
		return "", registration.ErrConflict
	}

	var emailExists bool
	if err := tx.QueryRow(ctx, `SELECT EXISTS (SELECT 1 FROM users WHERE LOWER(BTRIM(email)) = $1)`, normalizedEmail).Scan(&emailExists); err != nil {
		return "", fmt.Errorf("postgres: check WeChat registration email: %w", err)
	}
	if emailExists {
		return "", registration.ErrConflict
	}
	if input.Phone != "" {
		var conflictingUserID string
		phoneErr := tx.QueryRow(ctx, `SELECT id FROM users WHERE phone = $1 ORDER BY id LIMIT 1 FOR UPDATE`, input.Phone).Scan(&conflictingUserID)
		if phoneErr == nil {
			return "", registration.ErrConflict
		}
		if !errors.Is(phoneErr, pgx.ErrNoRows) {
			return "", fmt.Errorf("postgres: check WeChat registration phone owner: %w", phoneErr)
		}
	}
	reservedUserID, reserveErr := r.intentStore.ReserveNew(ctx, input.TenantID, input.Subject, input.User.UserID, input.ProviderIntent)
	if reserveErr != nil {
		return "", reserveErr
	}
	input.User.UserID = reservedUserID
	now := time.Now().UTC()
	userID := identity.UserID(input.User.UserID)
	user := identity.User{ID: userID, Status: identity.UserStatusPending, DisplayName: input.User.DisplayName, Email: input.User.Email, EmailVerified: false, Phone: input.Phone, PhoneVerified: input.Phone != "", CreatedAt: now, UpdatedAt: now, Version: 1}
	if err := createUserTx(ctx, tx, user); err != nil {
		return "", mapRegistrationWriteError(err)
	}
	primary := identity.IdentityLink{ID: generateLinkID(), UserID: userID, Provider: r.provider, ProviderTenantID: r.tenantID, ProviderSubject: input.User.UserID, CreatedAt: now, LastSeenAt: now}
	if err := createIdentityLinkTx(ctx, tx, primary); err != nil {
		return "", mapRegistrationWriteError(err)
	}
	wechatLink := identity.IdentityLink{ID: generateLinkID(), UserID: userID, Provider: wechat.ProviderName, ProviderTenantID: input.TenantID, ProviderSubject: input.Subject, CreatedAt: now, LastSeenAt: now}
	if err := createIdentityLinkTx(ctx, tx, wechatLink); err != nil {
		return "", mapRegistrationWriteError(err)
	}
	if err := addPersonaTx(ctx, tx, userID, identity.PersonaConsumer); err != nil {
		return "", fmt.Errorf("postgres: create WeChat registration persona: %w", err)
	}
	if effectErr := recordPendingWeChatAuthorityEffect(ctx, tx, input.TenantID, input.Subject, userID, now); effectErr != nil {
		return "", effectErr
	}
	if err := tx.Commit(ctx); err != nil {
		return "", fmt.Errorf("postgres: commit WeChat registration transaction: %w", err)
	}
	return input.User.UserID, nil
}

func recordPendingWeChatAuthorityEffect(ctx context.Context, tx pgx.Tx, tenantID, subject string, userID identity.UserID, occurredAt time.Time) error {
	digest, err := DeriveWeChatAuthorityReplayDigest(WeChatAuthorityReplayMaterial{
		Flow:             WeChatAuthorityFlowPending,
		TenantID:         tenantID,
		Subject:          subject,
		TargetUserID:     userID,
		AuthorityVersion: 0,
		SecurityEpoch:    0,
	})
	if err != nil {
		return fmt.Errorf("postgres: derive pending WeChat authority effect: %w", err)
	}
	if _, err := NewWeChatAuthorityEffectStore().RecordTx(ctx, tx, WeChatAuthorityEffect{
		ReplayDigest: digest,
		Kind:         WeChatAuthorityEffectPendingReserved,
		TargetUserID: userID,
		OccurredAt:   occurredAt,
	}); err != nil {
		return fmt.Errorf("postgres: append pending WeChat authority effect: %w", err)
	}
	return nil
}

func recordPendingPhoneVerifiedWeChatAuthorityEffect(ctx context.Context, tx pgx.Tx, tenantID, subject string, userID identity.UserID, authorityVersion int, securityEpoch int64, occurredAt time.Time) error {
	digest, err := DeriveWeChatAuthorityReplayDigest(WeChatAuthorityReplayMaterial{
		Flow:             WeChatAuthorityFlowPendingPhoneVerified,
		TenantID:         tenantID,
		Subject:          subject,
		TargetUserID:     userID,
		AuthorityVersion: int64(authorityVersion),
		SecurityEpoch:    securityEpoch,
	})
	if err != nil {
		return fmt.Errorf("postgres: derive pending WeChat phone authority effect: %w", err)
	}
	if _, err := NewWeChatAuthorityEffectStore().RecordTx(ctx, tx, WeChatAuthorityEffect{
		ReplayDigest: digest,
		Kind:         WeChatAuthorityEffectPendingPhoneVerified,
		TargetUserID: userID,
		OccurredAt:   occurredAt,
	}); err != nil {
		return fmt.Errorf("postgres: append pending WeChat phone authority effect: %w", err)
	}
	return nil
}

// DeletePending removes only the exact unverified identity created as a local
// reservation by public registration. It is used to compensate a provider
// creation failure before the account can ever establish a session.
func (r *RegistrationRepository) DeletePending(ctx context.Context, userID string) error {
	if r == nil || r.pool == nil || userID == "" || r.provider == "" || r.tenantID == "" {
		return registration.ErrUnavailable
	}
	tx, err := r.pool.Begin(ctx)
	if err != nil {
		return fmt.Errorf("postgres: begin registration cleanup: %w", err)
	}
	defer func() { _ = tx.Rollback(ctx) }()

	var removable bool
	if err := tx.QueryRow(ctx, `
SELECT EXISTS (
    SELECT 1
      FROM users AS u
      JOIN identity_links AS l ON l.user_id = u.id
     WHERE u.id = $1
       AND u.status = 'pending'
       AND u.email_verified = FALSE
       AND l.provider = $2
       AND l.provider_tenant_id = $3
       AND l.provider_subject = $1
)`, userID, r.provider, r.tenantID).Scan(&removable); err != nil {
		return fmt.Errorf("postgres: read registration cleanup target: %w", err)
	}
	if !removable {
		return tx.Commit(ctx)
	}
	if _, err := tx.Exec(ctx, `DELETE FROM user_personas WHERE user_id = $1`, userID); err != nil {
		return fmt.Errorf("postgres: delete registration persona: %w", err)
	}
	if _, err := tx.Exec(ctx, `DELETE FROM identity_links WHERE user_id = $1`, userID); err != nil {
		return fmt.Errorf("postgres: delete registration identity link: %w", err)
	}
	if _, err := tx.Exec(ctx, `DELETE FROM users WHERE id = $1 AND status = 'pending' AND email_verified = FALSE`, userID); err != nil {
		return fmt.Errorf("postgres: delete pending registration user: %w", err)
	}
	if err := tx.Commit(ctx); err != nil {
		return fmt.Errorf("postgres: commit registration cleanup: %w", err)
	}
	return nil
}

func (r *RegistrationRepository) ActivateVerified(ctx context.Context, userID string) error {
	if r == nil || r.pool == nil || userID == "" || r.provider == "" || r.tenantID == "" {
		return registration.ErrUnavailable
	}
	tx, err := r.pool.Begin(ctx)
	if err != nil {
		return fmt.Errorf("postgres: begin registration activation: %w", err)
	}
	defer func() { _ = tx.Rollback(ctx) }()

	result, err := tx.Exec(ctx, `
UPDATE users AS u
   SET status = 'active', email_verified = TRUE, updated_at = NOW(), version = version + 1
 WHERE u.id = $1
   AND u.status IN ('pending', 'active')
   AND (u.status <> 'active' OR u.email_verified = FALSE)
   AND EXISTS (
       SELECT 1
         FROM identity_links AS l
        WHERE l.user_id = u.id
          AND l.provider = $2
          AND l.provider_tenant_id = $3
          AND l.provider_subject = $1
   )
   AND (
       (
           u.phone = ''
           AND u.phone_verified = FALSE
           AND NOT EXISTS (
               SELECT 1 FROM identity_links AS wx
                WHERE wx.user_id = u.id AND wx.provider = $4
           )
       )
       OR
       (
           EXISTS (
               SELECT 1 FROM identity_links AS wx
                WHERE wx.user_id = u.id
                  AND wx.provider = $4
                  AND wx.provider_tenant_id <> ''
                  AND wx.provider_subject <> ''
           )
           AND (
               (u.phone = '' AND u.phone_verified = FALSE)
               OR (u.phone <> '' AND u.phone_verified = TRUE)
           )
       )
   )`, userID, r.provider, r.tenantID, wechat.ProviderName)
	if err != nil {
		return fmt.Errorf("postgres: activate verified registration: %w", err)
	}
	if result.RowsAffected() == 0 {
		var alreadyActive bool
		err := tx.QueryRow(ctx, `
SELECT EXISTS (
    SELECT 1
      FROM users AS u
      JOIN identity_links AS l ON l.user_id = u.id
     WHERE u.id = $1
       AND u.status = 'active'
       AND u.email_verified = TRUE
       AND l.provider = $2
       AND l.provider_tenant_id = $3
       AND l.provider_subject = $1
       AND (
           (
               u.phone = ''
               AND u.phone_verified = FALSE
               AND NOT EXISTS (
                   SELECT 1 FROM identity_links AS wx
                    WHERE wx.user_id = u.id AND wx.provider = $4
               )
           )
           OR
           (
               EXISTS (
                   SELECT 1 FROM identity_links AS wx
                    WHERE wx.user_id = u.id
                      AND wx.provider = $4
                      AND wx.provider_tenant_id <> ''
                      AND wx.provider_subject <> ''
               )
               AND (
                   (u.phone = '' AND u.phone_verified = FALSE)
                   OR (u.phone <> '' AND u.phone_verified = TRUE)
               )
           )
       )
)`, userID, r.provider, r.tenantID, wechat.ProviderName).Scan(&alreadyActive)
		if err != nil {
			return fmt.Errorf("postgres: read registration activation: %w", err)
		}
		if !alreadyActive {
			return registration.ErrVerificationFailed
		}
	}
	if err := tx.Commit(ctx); err != nil {
		return fmt.Errorf("postgres: commit registration activation: %w", err)
	}
	if r.intentStore != nil {
		cleanupCtx, cancel := context.WithTimeout(context.WithoutCancel(ctx), 5*time.Second)
		// Authority activation is already committed at this point. A transient
		// sidecar cleanup failure must not be reported as a failed activation;
		// the bounded cleanup worker retries active identities independently.
		_ = r.intentStore.Clear(cleanupCtx, userID)
		cancel()
	}
	return nil
}

func mapRegistrationWriteError(err error) error {
	if isUniqueViolation(err) {
		return registration.ErrConflict
	}
	if errors.Is(err, pgx.ErrNoRows) {
		return registration.ErrVerificationFailed
	}
	return err
}
