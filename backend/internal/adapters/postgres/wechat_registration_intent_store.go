package postgres

import (
	"context"
	"crypto/sha256"
	"encoding/binary"
	"errors"
	"fmt"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/GravelEvolution/united-pass/backend/internal/registration"
	"github.com/GravelEvolution/united-pass/backend/internal/wechatregistration"
)

type weChatRegistrationIntentStore interface {
	ReserveNew(context.Context, string, string, string, wechatregistration.ProviderIntent) (string, error)
	VerifyExisting(context.Context, string, string, string, wechatregistration.ProviderIntent) error
	Clear(context.Context, string) error
}

// WeChatRegistrationIntentStore keeps only a memory-hard request verifier and
// an opaque United Pass user ID in the isolated operational database. The raw
// WeChat subject, password and provider request are never persisted there.
type WeChatRegistrationIntentStore struct {
	pool *pgxpool.Pool
}

func NewWeChatRegistrationIntentStore(pool *pgxpool.Pool) *WeChatRegistrationIntentStore {
	return &WeChatRegistrationIntentStore{pool: pool}
}

func (s *WeChatRegistrationIntentStore) ReserveNew(ctx context.Context, tenantID, subject, proposedUserID string, intent wechatregistration.ProviderIntent) (string, error) {
	if s == nil || s.pool == nil || tenantID == "" || subject == "" || proposedUserID == "" {
		return "", registration.ErrUnavailable
	}
	verifier, err := hashWeChatProviderIntent(intent)
	if err != nil {
		return "", err
	}
	subjectHash := hashWeChatRegistrationSubject(tenantID, subject)
	tx, err := s.pool.BeginTx(ctx, pgx.TxOptions{IsoLevel: pgx.Serializable})
	if err != nil {
		return "", fmt.Errorf("postgres: begin isolated WeChat intent reservation: %w", err)
	}
	defer func() { _ = tx.Rollback(ctx) }()
	if _, err := tx.Exec(ctx, `
INSERT INTO wechat_registration_provider_intents(subject_hash,user_id,request_verifier)
VALUES($1,$2,$3)
ON CONFLICT(subject_hash) DO NOTHING`, subjectHash[:], proposedUserID, verifier); err != nil {
		if isUniqueViolation(err) {
			return "", registration.ErrConflict
		}
		return "", fmt.Errorf("postgres: reserve isolated WeChat intent: %w", err)
	}
	var storedUserID, storedVerifier string
	if err := tx.QueryRow(ctx, `SELECT user_id,request_verifier FROM wechat_registration_provider_intents WHERE subject_hash=$1 FOR UPDATE`, subjectHash[:]).Scan(&storedUserID, &storedVerifier); err != nil {
		return "", fmt.Errorf("postgres: read isolated WeChat intent: %w", err)
	}
	matches, err := verifyWeChatProviderIntent(intent, storedVerifier)
	if err != nil {
		return "", fmt.Errorf("postgres: verify isolated WeChat intent: %w", err)
	}
	if !matches {
		return "", registration.ErrConflict
	}
	if err := tx.Commit(ctx); err != nil {
		return "", fmt.Errorf("postgres: commit isolated WeChat intent reservation: %w", err)
	}
	return storedUserID, nil
}

func (s *WeChatRegistrationIntentStore) VerifyExisting(ctx context.Context, tenantID, subject, expectedUserID string, intent wechatregistration.ProviderIntent) error {
	if s == nil || s.pool == nil || tenantID == "" || subject == "" || expectedUserID == "" {
		return registration.ErrUnavailable
	}
	subjectHash := hashWeChatRegistrationSubject(tenantID, subject)
	var storedUserID, storedVerifier string
	err := s.pool.QueryRow(ctx, `SELECT user_id,request_verifier FROM wechat_registration_provider_intents WHERE subject_hash=$1`, subjectHash[:]).Scan(&storedUserID, &storedVerifier)
	if errors.Is(err, pgx.ErrNoRows) {
		return registration.ErrConflict
	}
	if err != nil {
		return fmt.Errorf("postgres: read existing isolated WeChat intent: %w", err)
	}
	if storedUserID != expectedUserID {
		return registration.ErrConflict
	}
	matches, err := verifyWeChatProviderIntent(intent, storedVerifier)
	if err != nil {
		return fmt.Errorf("postgres: verify existing isolated WeChat intent: %w", err)
	}
	if !matches {
		return registration.ErrConflict
	}
	return nil
}

func (s *WeChatRegistrationIntentStore) Clear(ctx context.Context, userID string) error {
	if s == nil || s.pool == nil || userID == "" {
		return registration.ErrUnavailable
	}
	if _, err := s.pool.Exec(ctx, `DELETE FROM wechat_registration_provider_intents WHERE user_id=$1`, userID); err != nil {
		return fmt.Errorf("postgres: clear isolated WeChat intent: %w", err)
	}
	return nil
}

func hashWeChatRegistrationSubject(tenantID, subject string) [sha256.Size]byte {
	hash := sha256.New()
	_, _ = hash.Write([]byte("united-pass/wechat-registration-subject/v1"))
	for _, field := range []string{tenantID, subject} {
		var length [4]byte
		binary.BigEndian.PutUint32(length[:], uint32(len(field)))
		_, _ = hash.Write(length[:])
		_, _ = hash.Write([]byte(field))
	}
	var digest [sha256.Size]byte
	copy(digest[:], hash.Sum(nil))
	return digest
}

var _ weChatRegistrationIntentStore = (*WeChatRegistrationIntentStore)(nil)
