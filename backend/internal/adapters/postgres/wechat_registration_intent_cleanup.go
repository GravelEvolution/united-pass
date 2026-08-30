package postgres

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/GravelEvolution/united-pass/backend/internal/platform/observability"
)

const (
	defaultWeChatIntentCleanupInterval = 15 * time.Minute
	defaultWeChatIntentCleanupGrace    = time.Hour
	wechatIntentCleanupTimeout         = 30 * time.Second
	wechatIntentCleanupBatchLimit      = 100
)

const weChatIntentCleanupCandidatesSQL = `
SELECT subject_hash,user_id
  FROM wechat_registration_provider_intents
 WHERE created_at<=$1
   AND (cleanup_checked_at IS NULL OR cleanup_checked_at<=$2)
 ORDER BY COALESCE(cleanup_checked_at,created_at),created_at,subject_hash
 LIMIT $3`

const weChatIntentCleanupPendingCheckedSQL = `
UPDATE wechat_registration_provider_intents
   SET cleanup_checked_at=$3
 WHERE subject_hash=$1
   AND user_id=$2`

// CleanupCompleted removes only old isolated intents whose authority identity
// is no longer pending. Pending identities retain their verifier so an
// ambiguous provider creation remains safely retryable. Missing authority
// rows are removed only after the caller-supplied grace cutoff, covering the
// sidecar-commit/main-rollback ambiguity without racing a live reservation.
func (s *WeChatRegistrationIntentStore) CleanupCompleted(ctx context.Context, authority *pgxpool.Pool, createdBefore, recheckBefore time.Time, limit int) (int, error) {
	if s == nil || s.pool == nil || authority == nil || createdBefore.IsZero() || recheckBefore.IsZero() {
		return 0, errors.New("postgres: isolated WeChat intent cleanup is unavailable")
	}
	if limit <= 0 || limit > wechatIntentCleanupBatchLimit {
		limit = wechatIntentCleanupBatchLimit
	}
	rows, err := s.pool.Query(ctx, weChatIntentCleanupCandidatesSQL, createdBefore.UTC(), recheckBefore.UTC(), limit)
	if err != nil {
		return 0, fmt.Errorf("postgres: list isolated WeChat intents for cleanup: %w", err)
	}
	type candidate struct {
		subjectHash []byte
		userID      string
	}
	candidates := make([]candidate, 0, limit)
	for rows.Next() {
		var item candidate
		if err := rows.Scan(&item.subjectHash, &item.userID); err != nil {
			rows.Close()
			return 0, fmt.Errorf("postgres: scan isolated WeChat cleanup candidate: %w", err)
		}
		candidates = append(candidates, item)
	}
	if err := rows.Err(); err != nil {
		rows.Close()
		return 0, fmt.Errorf("postgres: list isolated WeChat intents for cleanup: %w", err)
	}
	rows.Close()

	removed := 0
	var failures []error
	for _, item := range candidates {
		var status string
		err := authority.QueryRow(ctx, `SELECT status FROM users WHERE id=$1`, item.userID).Scan(&status)
		if err == nil && status == "pending" {
			if _, checkedErr := s.pool.Exec(ctx, weChatIntentCleanupPendingCheckedSQL, item.subjectHash, item.userID, time.Now().UTC()); checkedErr != nil {
				failures = append(failures, fmt.Errorf("postgres: defer pending isolated WeChat intent cleanup: %w", checkedErr))
			}
			continue
		}
		if err != nil && !errors.Is(err, pgx.ErrNoRows) {
			failures = append(failures, fmt.Errorf("postgres: read WeChat intent authority state: %w", err))
			continue
		}
		result, deleteErr := s.pool.Exec(ctx, `
DELETE FROM wechat_registration_provider_intents
 WHERE subject_hash=$1
   AND user_id=$2
   AND created_at<=$3`, item.subjectHash, item.userID, createdBefore.UTC())
		if deleteErr != nil {
			failures = append(failures, fmt.Errorf("postgres: delete completed isolated WeChat intent: %w", deleteErr))
			continue
		}
		removed += int(result.RowsAffected())
	}
	return removed, errors.Join(failures...)
}

// WeChatRegistrationIntentCleanupWorker bounds retention of retry verifiers
// after activation or a rolled-back main reservation. It never mutates an
// authority row and preserves every still-pending identity.
type WeChatRegistrationIntentCleanupWorker struct {
	store     *WeChatRegistrationIntentStore
	authority *pgxpool.Pool
	interval  time.Duration
	grace     time.Duration
	logger    *slog.Logger
	now       func() time.Time

	cancel context.CancelFunc
	done   chan struct{}
}

func NewWeChatRegistrationIntentCleanupWorker(store *WeChatRegistrationIntentStore, authority *pgxpool.Pool, interval, grace time.Duration, logger *slog.Logger) *WeChatRegistrationIntentCleanupWorker {
	if interval <= 0 {
		interval = defaultWeChatIntentCleanupInterval
	}
	if grace <= 0 {
		grace = defaultWeChatIntentCleanupGrace
	}
	if logger == nil {
		logger = slog.Default()
	}
	return &WeChatRegistrationIntentCleanupWorker{
		store: store, authority: authority, interval: interval, grace: grace,
		logger: logger, now: time.Now,
	}
}

func (w *WeChatRegistrationIntentCleanupWorker) Start() {
	ctx, cancel := context.WithCancel(context.Background())
	w.cancel = cancel
	w.done = make(chan struct{})
	go w.run(ctx)
}

func (w *WeChatRegistrationIntentCleanupWorker) Stop() {
	if w == nil || w.cancel == nil {
		return
	}
	w.cancel()
	<-w.done
}

func (w *WeChatRegistrationIntentCleanupWorker) run(ctx context.Context) {
	defer close(w.done)
	ticker := time.NewTicker(w.interval)
	defer ticker.Stop()
	w.sweep(ctx)
	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			w.sweep(ctx)
		}
	}
}

func (w *WeChatRegistrationIntentCleanupWorker) sweep(parent context.Context) int {
	if w == nil || w.store == nil || w.authority == nil {
		return 0
	}
	ctx, cancel := context.WithTimeout(parent, wechatIntentCleanupTimeout)
	now := w.now().UTC()
	removed, err := w.store.CleanupCompleted(ctx, w.authority, now.Add(-w.grace), now.Add(-w.interval), wechatIntentCleanupBatchLimit)
	cancel()
	if err != nil {
		w.logger.Warn("isolated WeChat registration intent cleanup failed",
			"errorClass", observability.ClassifyError(err),
			"errorDetail", observability.RedactedError(err, 256),
		)
		return removed
	}
	if removed > 0 {
		w.logger.Info("isolated WeChat registration intents cleaned", "count", removed)
	}
	return removed
}
