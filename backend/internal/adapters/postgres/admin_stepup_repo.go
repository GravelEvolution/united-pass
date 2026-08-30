package postgres

import (
	"context"
	"errors"
	"fmt"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/GravelEvolution/united-pass/backend/internal/adminstepup"
	"github.com/GravelEvolution/united-pass/backend/internal/identity"
)

type AdminStepUpRepository struct {
	exec adminDBTX
	tx   pgx.Tx
}

func NewAdminStepUpRepository(pool *pgxpool.Pool) *AdminStepUpRepository {
	return &AdminStepUpRepository{exec: pool}
}
func newAdminStepUpRepository(tx pgx.Tx) *AdminStepUpRepository {
	return &AdminStepUpRepository{exec: tx, tx: tx}
}

func (r *AdminStepUpRepository) Get(ctx context.Context, userID identity.UserID) (adminstepup.Challenge, error) {
	challenge, err := scanChallenge(r.exec.QueryRow(ctx, `SELECT user_id,status,must_rotate,credential_version,security_epoch,failure_count,failure_window_started_at,locked_until,version,created_at,updated_at FROM admin_challenges WHERE user_id=$1`, string(userID)))
	if errors.Is(err, pgx.ErrNoRows) {
		return adminstepup.Challenge{}, adminstepup.ErrNotFound
	}
	if err != nil {
		return adminstepup.Challenge{}, fmt.Errorf("postgres: get admin challenge: %w", err)
	}
	return challenge, nil
}

func (r *AdminStepUpRepository) GetCredentialForVerification(ctx context.Context, userID identity.UserID) (adminstepup.CredentialMaterial, error) {
	var material adminstepup.CredentialMaterial
	var id, status string
	err := r.exec.QueryRow(ctx, `SELECT user_id,status,must_rotate,credential_version,security_epoch,failure_count,failure_window_started_at,locked_until,version,created_at,updated_at,question_key_id,question_nonce,question_ciphertext,answer_phc,answer_pepper_key_id FROM admin_challenges WHERE user_id=$1 AND status='active'`, string(userID)).Scan(&id, &status, &material.Challenge.MustRotate, &material.Challenge.CredentialVersion, &material.Challenge.SecurityEpoch, &material.Challenge.FailureCount, &material.Challenge.FailureWindowStartedAt, &material.Challenge.LockedUntil, &material.Challenge.Version, &material.Challenge.CreatedAt, &material.Challenge.UpdatedAt, &material.QuestionKeyID, &material.QuestionNonce, &material.QuestionCiphertext, &material.AnswerPHC, &material.AnswerPepperKeyID)
	if errors.Is(err, pgx.ErrNoRows) {
		return adminstepup.CredentialMaterial{}, adminstepup.ErrNotFound
	}
	if err != nil {
		return adminstepup.CredentialMaterial{}, fmt.Errorf("postgres: get admin credential: %w", err)
	}
	material.Challenge.UserID = identity.UserID(id)
	material.Challenge.Status = adminstepup.ChallengeStatus(status)
	return material, nil
}

func (r *AdminStepUpRepository) PutCredential(ctx context.Context, material adminstepup.CredentialMaterial, expectedVersion int64) (adminstepup.Challenge, error) {
	if r.tx == nil {
		return adminstepup.Challenge{}, errors.New("postgres: challenge write requires unit of work")
	}
	if material.Challenge.Status != adminstepup.ChallengeActive || material.QuestionKeyID == "" || len(material.QuestionNonce) == 0 || len(material.QuestionCiphertext) == 0 || material.AnswerPHC == "" || material.AnswerPepperKeyID == "" {
		return adminstepup.Challenge{}, adminstepup.ErrConflict
	}
	now := time.Now().UTC()
	if expectedVersion == 0 {
		if material.Challenge.CredentialVersion == 0 {
			material.Challenge.CredentialVersion = 1
		}
		if material.Challenge.SecurityEpoch == 0 {
			material.Challenge.SecurityEpoch = 1
		}
		_, err := r.tx.Exec(ctx, `INSERT INTO admin_challenges(user_id,status,must_rotate,question_key_id,question_nonce,question_ciphertext,answer_phc,answer_pepper_key_id,credential_version,security_epoch,failure_count,version,created_at,updated_at) VALUES($1,'active',$2,$3,$4,$5,$6,$7,$8,$9,0,1,$10,$10)`, string(material.Challenge.UserID), material.Challenge.MustRotate, material.QuestionKeyID, material.QuestionNonce, material.QuestionCiphertext, material.AnswerPHC, material.AnswerPepperKeyID, material.Challenge.CredentialVersion, material.Challenge.SecurityEpoch, now)
		if err != nil {
			if isUniqueViolation(err) {
				return adminstepup.Challenge{}, adminstepup.ErrConflict
			}
			return adminstepup.Challenge{}, fmt.Errorf("postgres: insert admin credential: %w", err)
		}
	} else {
		tag, err := r.tx.Exec(ctx, `UPDATE admin_challenges SET status='active',must_rotate=$2,question_key_id=$3,question_nonce=$4,question_ciphertext=$5,answer_phc=$6,answer_pepper_key_id=$7,credential_version=credential_version+1,security_epoch=security_epoch+1,failure_count=0,failure_window_started_at=NULL,locked_until=NULL,version=version+1,updated_at=$8 WHERE user_id=$1 AND version=$9`, string(material.Challenge.UserID), material.Challenge.MustRotate, material.QuestionKeyID, material.QuestionNonce, material.QuestionCiphertext, material.AnswerPHC, material.AnswerPepperKeyID, now, expectedVersion)
		if err != nil {
			return adminstepup.Challenge{}, fmt.Errorf("postgres: update admin credential: %w", err)
		}
		if tag.RowsAffected() != 1 {
			return adminstepup.Challenge{}, adminstepup.ErrConflict
		}
	}
	return r.Get(ctx, material.Challenge.UserID)
}

func (r *AdminStepUpRepository) RecordFailure(ctx context.Context, userID identity.UserID, expectedVersion int64, now time.Time) (adminstepup.Challenge, error) {
	if r.tx == nil {
		return adminstepup.Challenge{}, errors.New("postgres: challenge write requires unit of work")
	}
	tag, err := r.tx.Exec(ctx, `UPDATE admin_challenges SET failure_window_started_at=CASE WHEN failure_window_started_at IS NULL OR failure_window_started_at < $3-INTERVAL '15 minutes' THEN $3 ELSE failure_window_started_at END,failure_count=CASE WHEN failure_window_started_at IS NULL OR failure_window_started_at < $3-INTERVAL '15 minutes' THEN 1 ELSE failure_count+1 END,locked_until=CASE WHEN (CASE WHEN failure_window_started_at IS NULL OR failure_window_started_at < $3-INTERVAL '15 minutes' THEN 1 ELSE failure_count+1 END)>=5 THEN $3+INTERVAL '30 minutes' ELSE locked_until END,version=version+1,updated_at=$3 WHERE user_id=$1 AND version=$2`, string(userID), expectedVersion, now)
	if err != nil {
		return adminstepup.Challenge{}, fmt.Errorf("postgres: record challenge failure: %w", err)
	}
	if tag.RowsAffected() != 1 {
		return adminstepup.Challenge{}, adminstepup.ErrConflict
	}
	return r.Get(ctx, userID)
}

func (r *AdminStepUpRepository) PutStepUp(ctx context.Context, state adminstepup.StepUpState) error {
	if r.tx == nil {
		return errors.New("postgres: step-up write requires unit of work")
	}
	// Replace the session/user's active proof inside the same transaction.
	// Re-verifying a high-risk action while the 30-minute general proof is
	// active must not collide with the partial unique index.
	if _, err := r.tx.Exec(ctx, `UPDATE admin_step_up_state SET revoked_at=$3 WHERE session_id=$1 AND user_id=$2 AND revoked_at IS NULL`, state.SessionID, string(state.UserID), state.VerifiedAt); err != nil {
		return fmt.Errorf("postgres: revoke replaced admin step-up state: %w", err)
	}
	tag, err := r.tx.Exec(ctx, `INSERT INTO admin_step_up_state(step_up_id,session_id,user_id,challenge_version,security_epoch,verified_at,expires_at,revoked_at) VALUES($1,$2,$3,$4,$5,$6,$7,$8) ON CONFLICT(step_up_id) DO NOTHING`, state.ID, state.SessionID, string(state.UserID), state.ChallengeVersion, state.SecurityEpoch, state.VerifiedAt, state.ExpiresAt, state.RevokedAt)
	if err != nil {
		if isUniqueViolation(err) {
			return adminstepup.ErrConflict
		}
		return fmt.Errorf("postgres: put admin step-up state: %w", err)
	}
	if tag.RowsAffected() != 1 {
		return adminstepup.ErrConflict
	}
	return nil
}

const adminStepUpActiveReadSQL = `SELECT step_up_id,session_id,user_id,challenge_version,security_epoch,verified_at,expires_at,revoked_at FROM admin_step_up_state WHERE session_id=$1 AND user_id=$2 AND verified_at<=$3 AND expires_at>$3 AND revoked_at IS NULL ORDER BY verified_at DESC LIMIT 1`

// GetActiveForSession returns only a currently valid proof for the exact
// provider-backed browser session and stable user. It intentionally does not
// fall back to another session's proof.
func (r *AdminStepUpRepository) GetActiveForSession(ctx context.Context, sessionID string, userID identity.UserID, now time.Time) (adminstepup.StepUpState, error) {
	var state adminstepup.StepUpState
	var storedUserID string
	err := r.exec.QueryRow(ctx, adminStepUpActiveReadSQL, sessionID, string(userID), now.UTC()).Scan(
		&state.ID, &state.SessionID, &storedUserID, &state.ChallengeVersion, &state.SecurityEpoch,
		&state.VerifiedAt, &state.ExpiresAt, &state.RevokedAt,
	)
	if errors.Is(err, pgx.ErrNoRows) {
		return adminstepup.StepUpState{}, adminstepup.ErrNotFound
	}
	if err != nil {
		return adminstepup.StepUpState{}, fmt.Errorf("postgres: get active admin step-up: %w", err)
	}
	state.UserID = identity.UserID(storedUserID)
	return state, nil
}

func (r *AdminStepUpRepository) RevokeForUser(ctx context.Context, userID identity.UserID, now time.Time) error {
	if r.tx == nil {
		return errors.New("postgres: step-up write requires unit of work")
	}
	_, err := r.tx.Exec(ctx, `UPDATE admin_step_up_state SET revoked_at=$2 WHERE user_id=$1 AND revoked_at IS NULL`, string(userID), now)
	if err != nil {
		return fmt.Errorf("postgres: revoke step-up state: %w", err)
	}
	return nil
}

func (r *AdminStepUpRepository) GetSecurityEpoch(ctx context.Context, userID identity.UserID) (int64, error) {
	var epoch int64
	err := r.exec.QueryRow(ctx, `SELECT security_epoch FROM admin_challenges WHERE user_id=$1`, string(userID)).Scan(&epoch)
	if errors.Is(err, pgx.ErrNoRows) {
		return 0, adminstepup.ErrNotFound
	}
	if err != nil {
		return 0, fmt.Errorf("postgres: get admin security epoch: %w", err)
	}
	return epoch, nil
}
func (r *AdminStepUpRepository) IncrementSecurityEpoch(ctx context.Context, userID identity.UserID, expected int64) (int64, error) {
	if r.tx == nil {
		return 0, errors.New("postgres: epoch write requires unit of work")
	}
	var epoch int64
	err := r.tx.QueryRow(ctx, `UPDATE admin_challenges SET security_epoch=security_epoch+1,version=version+1,updated_at=NOW() WHERE user_id=$1 AND security_epoch=$2 RETURNING security_epoch`, string(userID), expected).Scan(&epoch)
	if errors.Is(err, pgx.ErrNoRows) {
		return 0, adminstepup.ErrConflict
	}
	if err != nil {
		return 0, fmt.Errorf("postgres: increment security epoch: %w", err)
	}
	return epoch, nil
}

type adminSecurityEpochRepository struct{ repo *AdminStepUpRepository }

func (s adminSecurityEpochRepository) Get(ctx context.Context, userID identity.UserID) (int64, error) {
	return s.repo.GetSecurityEpoch(ctx, userID)
}
func (s adminSecurityEpochRepository) Increment(ctx context.Context, userID identity.UserID, expected int64) (int64, error) {
	return s.repo.IncrementSecurityEpoch(ctx, userID, expected)
}

func scanChallenge(row pgx.Row) (adminstepup.Challenge, error) {
	var c adminstepup.Challenge
	var userID, status string
	err := row.Scan(&userID, &status, &c.MustRotate, &c.CredentialVersion, &c.SecurityEpoch, &c.FailureCount, &c.FailureWindowStartedAt, &c.LockedUntil, &c.Version, &c.CreatedAt, &c.UpdatedAt)
	c.UserID = identity.UserID(userID)
	c.Status = adminstepup.ChallengeStatus(status)
	return c, err
}
