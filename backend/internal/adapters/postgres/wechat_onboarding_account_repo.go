package postgres

import (
	"context"
	"errors"
	"fmt"
	"sort"
	"strings"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"
	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/GravelEvolution/united-pass/backend/internal/identity"
	"github.com/GravelEvolution/united-pass/backend/internal/securitystate"
	"github.com/GravelEvolution/united-pass/backend/internal/wechat"
	"github.com/GravelEvolution/united-pass/backend/internal/wechatonboarding"
)

const (
	wechatOnboardingFindEmailSQL = `
SELECT ` + userColumns + `, LOWER(BTRIM(email)), security_epoch
  FROM users
 WHERE LOWER(BTRIM(email)) = $1
 ORDER BY id
 LIMIT 2`

	wechatOnboardingLockUserSQL = `
SELECT status, LOWER(BTRIM(email)), phone, phone_verified, version, security_epoch
  FROM users
 WHERE id = $1
 FOR UPDATE`

	wechatOnboardingLockLinksSQL = `
SELECT user_id, provider_subject
  FROM identity_links
 WHERE provider = $1
   AND provider_tenant_id = $2
   AND (provider_subject = $3 OR user_id = $4)
 ORDER BY user_id, provider_subject
 FOR UPDATE`

	wechatOnboardingLockPhoneOwnerSQL = `
SELECT id
  FROM users
 WHERE phone = $1
   AND id <> $2
 ORDER BY id
 LIMIT 1
 FOR UPDATE`

	wechatOnboardingInsertLinkSQL = `
INSERT INTO identity_links
       (id, user_id, provider, provider_tenant_id, provider_subject, created_at, last_seen_at)
VALUES ($1, $2, $3, $4, $5, NOW(), NOW())`

	wechatOnboardingAdvanceUserSQL = `
UPDATE users
   SET phone = CASE WHEN $2 THEN $3 ELSE phone END,
       phone_verified = CASE WHEN $2 THEN TRUE ELSE phone_verified END,
       updated_at = NOW(),
       version = version + 1,
       security_epoch = security_epoch + 1
 WHERE id = $1
   AND status = 'active'
   AND version = $4
   AND security_epoch = $5
 RETURNING version, security_epoch`
)

const wechatOnboardingSerializableAttempts = 3

type wechatOnboardingAuthorityDB interface {
	Query(context.Context, string, ...any) (pgx.Rows, error)
	BeginTx(context.Context, pgx.TxOptions) (pgx.Tx, error)
}

// WeChatOnboardingAccountRepository performs the authority-store portion of
// the explicit onboarding workflow. It never authenticates a password and it
// never selects an account by phone; its caller must first bind the operation
// to a provider-authenticated stable user ID.
type WeChatOnboardingAccountRepository struct {
	db wechatOnboardingAuthorityDB
}

func NewWeChatOnboardingAccountRepository(pool *pgxpool.Pool) *WeChatOnboardingAccountRepository {
	return &WeChatOnboardingAccountRepository{db: pool}
}

// FindByNormalizedEmail resolves exactly one case-folded, whitespace-trimmed
// email owner. Historical duplicate normalized owners fail closed instead of
// choosing an arbitrary account.
func (r *WeChatOnboardingAccountRepository) FindByNormalizedEmail(ctx context.Context, email string) (wechatonboarding.AccountSnapshot, error) {
	if r == nil || r.db == nil {
		return wechatonboarding.AccountSnapshot{}, wechatonboarding.ErrUnavailable
	}
	normalized := strings.ToLower(strings.TrimSpace(email))
	if normalized == "" {
		return wechatonboarding.AccountSnapshot{}, wechatonboarding.ErrInvalidInput
	}
	rows, err := r.db.Query(ctx, wechatOnboardingFindEmailSQL, normalized)
	if err != nil {
		return wechatonboarding.AccountSnapshot{}, fmt.Errorf("postgres: find WeChat onboarding email owner: %w", err)
	}
	defer rows.Close()

	snapshots := make([]wechatonboarding.AccountSnapshot, 0, 2)
	for rows.Next() {
		snapshot, scanErr := scanWeChatOnboardingAccountSnapshot(rows)
		if scanErr != nil {
			return wechatonboarding.AccountSnapshot{}, fmt.Errorf("postgres: scan WeChat onboarding email owner: %w", scanErr)
		}
		snapshots = append(snapshots, snapshot)
	}
	if err := rows.Err(); err != nil {
		return wechatonboarding.AccountSnapshot{}, fmt.Errorf("postgres: iterate WeChat onboarding email owners: %w", err)
	}
	switch len(snapshots) {
	case 0:
		return wechatonboarding.AccountSnapshot{}, identity.ErrUserNotFound
	case 1:
		return snapshots[0], nil
	default:
		return wechatonboarding.AccountSnapshot{}, wechatonboarding.ErrEmailAmbiguous
	}
}

func scanWeChatOnboardingAccountSnapshot(row pgx.Row) (wechatonboarding.AccountSnapshot, error) {
	var id, status string
	var snapshot wechatonboarding.AccountSnapshot
	err := row.Scan(
		&id, &status, &snapshot.User.DisplayName, &snapshot.User.Nickname,
		&snapshot.User.AvatarURL, &snapshot.User.Email, &snapshot.User.EmailVerified,
		&snapshot.User.Phone, &snapshot.User.PhoneVerified, &snapshot.User.CreatedAt,
		&snapshot.User.UpdatedAt, &snapshot.User.Version, &snapshot.NormalizedEmail,
		&snapshot.SecurityEpoch,
	)
	if err != nil {
		return wechatonboarding.AccountSnapshot{}, err
	}
	snapshot.User.ID = identity.UserID(id)
	snapshot.User.Status = identity.UserStatus(status)
	snapshot.Version = snapshot.User.Version
	return snapshot, nil
}

// BindExistingWithWeChat attaches a verified WeChat subject and, optionally,
// a verified phone to one already-authenticated active account. Serializable
// retries are internal so callers receive stable domain conflicts rather than
// raw PostgreSQL concurrency errors.
func (r *WeChatOnboardingAccountRepository) BindExistingWithWeChat(ctx context.Context, input wechatonboarding.BindExistingInput) (wechatonboarding.BindExistingResult, error) {
	if r == nil || r.db == nil {
		return wechatonboarding.BindExistingResult{}, wechatonboarding.ErrUnavailable
	}
	if input.UserID == "" || strings.TrimSpace(input.TenantID) == "" || strings.TrimSpace(input.Subject) == "" || input.TenantID != strings.TrimSpace(input.TenantID) || input.Subject != strings.TrimSpace(input.Subject) || input.Phone != strings.TrimSpace(input.Phone) || input.NormalizedEmail == "" || input.NormalizedEmail != strings.ToLower(strings.TrimSpace(input.NormalizedEmail)) || input.ExpectedVersion <= 0 || input.ExpectedSecurityEpoch <= 0 {
		return wechatonboarding.BindExistingResult{}, wechatonboarding.ErrInvalidInput
	}

	var lastErr error
	for attempt := 0; attempt < wechatOnboardingSerializableAttempts; attempt++ {
		result, err := r.bindExistingWithWeChatOnce(ctx, input)
		if err == nil {
			return result, nil
		}
		if !isWeChatOnboardingSerializationFailure(err) {
			return wechatonboarding.BindExistingResult{}, err
		}
		lastErr = err
		if ctx.Err() != nil {
			return wechatonboarding.BindExistingResult{}, ctx.Err()
		}
	}
	return wechatonboarding.BindExistingResult{}, fmt.Errorf("%w: serializable settlement exhausted: %v", wechatonboarding.ErrIdentityConflict, lastErr)
}

func (r *WeChatOnboardingAccountRepository) bindExistingWithWeChatOnce(ctx context.Context, input wechatonboarding.BindExistingInput) (wechatonboarding.BindExistingResult, error) {
	tx, err := r.db.BeginTx(ctx, pgx.TxOptions{IsoLevel: pgx.Serializable})
	if err != nil {
		return wechatonboarding.BindExistingResult{}, fmt.Errorf("postgres: begin WeChat onboarding authority transaction: %w", err)
	}
	defer func() { _ = tx.Rollback(ctx) }()

	lockKeys := []string{
		"user:" + string(input.UserID),
		"wechat:" + input.TenantID + ":" + input.Subject,
	}
	if input.Phone != "" {
		lockKeys = append(lockKeys, "phone:"+input.Phone)
	}
	sort.Strings(lockKeys)
	for _, key := range lockKeys {
		if _, err := tx.Exec(ctx, `SELECT pg_advisory_xact_lock(hashtextextended($1, 0))`, key); err != nil {
			return wechatonboarding.BindExistingResult{}, fmt.Errorf("postgres: lock WeChat onboarding authority key: %w", err)
		}
	}

	var status, normalizedEmail, existingPhone string
	var phoneVerified bool
	var version int
	var epoch int64
	err = tx.QueryRow(ctx, wechatOnboardingLockUserSQL, string(input.UserID)).Scan(&status, &normalizedEmail, &existingPhone, &phoneVerified, &version, &epoch)
	if errors.Is(err, pgx.ErrNoRows) {
		return wechatonboarding.BindExistingResult{}, identity.ErrUserNotFound
	}
	if err != nil {
		return wechatonboarding.BindExistingResult{}, fmt.Errorf("postgres: lock WeChat onboarding target: %w", err)
	}
	if err := validateWeChatOnboardingAccountSnapshot(status, normalizedEmail, version, securitystate.Epoch(epoch), input); err != nil {
		return wechatonboarding.BindExistingResult{}, err
	}

	rows, err := tx.Query(ctx, wechatOnboardingLockLinksSQL, wechat.ProviderName, input.TenantID, input.Subject, string(input.UserID))
	if err != nil {
		return wechatonboarding.BindExistingResult{}, fmt.Errorf("postgres: lock WeChat onboarding links: %w", err)
	}
	links := make([]wechatOnboardingLink, 0, 2)
	for rows.Next() {
		var link wechatOnboardingLink
		if scanErr := rows.Scan(&link.userID, &link.subject); scanErr != nil {
			rows.Close()
			return wechatonboarding.BindExistingResult{}, fmt.Errorf("postgres: scan WeChat onboarding link: %w", scanErr)
		}
		links = append(links, link)
	}
	rowsErr := rows.Err()
	rows.Close()
	if rowsErr != nil {
		return wechatonboarding.BindExistingResult{}, fmt.Errorf("postgres: iterate WeChat onboarding links: %w", rowsErr)
	}
	alreadyLinked, err := evaluateWeChatOnboardingLinks(links, string(input.UserID), input.Subject)
	if err != nil {
		return wechatonboarding.BindExistingResult{}, err
	}

	phoneAdded, err := decideWeChatOnboardingPhone(existingPhone, phoneVerified, input.Phone)
	if err != nil {
		return wechatonboarding.BindExistingResult{}, err
	}
	if input.Phone != "" {
		var conflictingUserID string
		phoneErr := tx.QueryRow(ctx, wechatOnboardingLockPhoneOwnerSQL, input.Phone, string(input.UserID)).Scan(&conflictingUserID)
		if phoneErr == nil {
			return wechatonboarding.BindExistingResult{}, wechatonboarding.ErrPhoneConflict
		}
		if !errors.Is(phoneErr, pgx.ErrNoRows) {
			return wechatonboarding.BindExistingResult{}, fmt.Errorf("postgres: lock WeChat onboarding phone owner: %w", phoneErr)
		}
	}

	linkAdded := !alreadyLinked
	if linkAdded {
		_, err = tx.Exec(ctx, wechatOnboardingInsertLinkSQL, generateLinkID(), string(input.UserID), wechat.ProviderName, input.TenantID, input.Subject)
		if err != nil {
			if isUniqueViolation(err) {
				return wechatonboarding.BindExistingResult{}, wechatonboarding.ErrIdentityConflict
			}
			return wechatonboarding.BindExistingResult{}, fmt.Errorf("postgres: insert WeChat onboarding link: %w", err)
		}
	}

	if linkAdded || phoneAdded {
		err = tx.QueryRow(ctx, wechatOnboardingAdvanceUserSQL, string(input.UserID), phoneAdded, input.Phone, input.ExpectedVersion, input.ExpectedSecurityEpoch).Scan(&version, &epoch)
		if errors.Is(err, pgx.ErrNoRows) {
			return wechatonboarding.BindExistingResult{}, wechatonboarding.ErrAccountChanged
		}
		if err != nil {
			return wechatonboarding.BindExistingResult{}, fmt.Errorf("postgres: advance WeChat onboarding account security state: %w", err)
		}

		kind := WeChatAuthorityEffectExistingLink
		switch {
		case linkAdded && phoneAdded:
			kind = WeChatAuthorityEffectExistingLinkPhone
		case phoneAdded:
			kind = WeChatAuthorityEffectExistingPhone
		}
		digest, deriveErr := DeriveWeChatAuthorityReplayDigest(WeChatAuthorityReplayMaterial{
			Flow:             WeChatAuthorityFlowExisting,
			TenantID:         input.TenantID,
			Subject:          input.Subject,
			TargetUserID:     input.UserID,
			AuthorityVersion: int64(input.ExpectedVersion),
			SecurityEpoch:    int64(input.ExpectedSecurityEpoch),
		})
		if deriveErr != nil {
			return wechatonboarding.BindExistingResult{}, fmt.Errorf("postgres: derive WeChat onboarding authority effect: %w", deriveErr)
		}
		if _, recordErr := NewWeChatAuthorityEffectStore().RecordTx(ctx, tx, WeChatAuthorityEffect{
			ReplayDigest: digest,
			Kind:         kind,
			TargetUserID: input.UserID,
			OccurredAt:   time.Now().UTC(),
		}); recordErr != nil {
			return wechatonboarding.BindExistingResult{}, fmt.Errorf("postgres: append WeChat onboarding authority effect: %w", recordErr)
		}
	}

	if err := tx.Commit(ctx); err != nil {
		return wechatonboarding.BindExistingResult{}, fmt.Errorf("postgres: commit WeChat onboarding authority transaction: %w", err)
	}
	return wechatonboarding.BindExistingResult{
		UserID: input.UserID, Version: version, SecurityEpoch: securitystate.Epoch(epoch),
		Linked: linkAdded, PhoneAdded: phoneAdded,
	}, nil
}

func validateWeChatOnboardingAccountSnapshot(status, normalizedEmail string, version int, epoch securitystate.Epoch, input wechatonboarding.BindExistingInput) error {
	if status != string(identity.UserStatusActive) {
		return wechatonboarding.ErrAccountInactive
	}
	if normalizedEmail != input.NormalizedEmail || version != input.ExpectedVersion || epoch != input.ExpectedSecurityEpoch {
		return wechatonboarding.ErrAccountChanged
	}
	return nil
}

type wechatOnboardingLink struct {
	userID  string
	subject string
}

func evaluateWeChatOnboardingLinks(links []wechatOnboardingLink, targetUserID, subject string) (bool, error) {
	alreadyLinked := false
	for _, link := range links {
		if link.userID != targetUserID || link.subject != subject || alreadyLinked {
			return false, wechatonboarding.ErrIdentityConflict
		}
		alreadyLinked = true
	}
	return alreadyLinked, nil
}

func decideWeChatOnboardingPhone(existing string, verified bool, proof string) (bool, error) {
	if proof == "" {
		return false, nil
	}
	if existing == "" && !verified {
		return true, nil
	}
	// The provider proof upgrades the exact same legacy contact to verified;
	// it never changes the stored number. This is the only non-empty,
	// non-verified state that onboarding may repair.
	if existing == proof && !verified {
		return true, nil
	}
	if existing == proof && verified {
		return false, nil
	}
	return false, wechatonboarding.ErrPhoneConflict
}

func isWeChatOnboardingSerializationFailure(err error) bool {
	var pgErr *pgconn.PgError
	return errors.As(err, &pgErr) && (pgErr.Code == "40001" || pgErr.Code == "40P01")
}
