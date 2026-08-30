package postgres

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/GravelEvolution/united-pass/backend/internal/adminpagination"
	"github.com/GravelEvolution/united-pass/backend/internal/adminroles"
	"github.com/GravelEvolution/united-pass/backend/internal/adminstepup"
	"github.com/GravelEvolution/united-pass/backend/internal/adminstore"
	"github.com/GravelEvolution/united-pass/backend/internal/applications"
	"github.com/GravelEvolution/united-pass/backend/internal/identity"
	"github.com/GravelEvolution/united-pass/backend/internal/identityaccess"
	"github.com/GravelEvolution/united-pass/backend/internal/securitystate"
)

type adminTxBeginner interface {
	BeginTx(context.Context, pgx.TxOptions) (pgx.Tx, error)
}

type AdminUnitOfWork struct {
	beginner adminTxBeginner
	codec    *adminpagination.CursorCodec
}

// AdminOutboxUnitOfWork owns only the durable cross-system operation ledger.
// It is intentionally separate from AdminUnitOfWork so DreamUP BFF receipts
// may live in a dedicated operational database while roles, challenges and
// permissions continue to use the unchanged United Pass authority database.
type AdminOutboxUnitOfWork struct {
	beginner adminTxBeginner
}

func NewAdminUnitOfWork(pool *pgxpool.Pool, codec *adminpagination.CursorCodec) *AdminUnitOfWork {
	return newAdminUnitOfWork(pool, codec)
}

func newAdminUnitOfWork(beginner adminTxBeginner, codec *adminpagination.CursorCodec) *AdminUnitOfWork {
	return &AdminUnitOfWork{beginner: beginner, codec: codec}
}

func NewAdminOutboxUnitOfWork(pool *pgxpool.Pool) *AdminOutboxUnitOfWork {
	return &AdminOutboxUnitOfWork{beginner: pool}
}

func (u *AdminOutboxUnitOfWork) Within(ctx context.Context, fn func(adminstore.Repositories) error) error {
	if u == nil || u.beginner == nil || fn == nil {
		return errors.New("postgres: isolated outbox unit of work is unavailable")
	}
	tx, err := u.beginner.BeginTx(ctx, pgx.TxOptions{IsoLevel: pgx.Serializable})
	if err != nil {
		return fmt.Errorf("postgres: begin isolated outbox unit of work: %w", err)
	}
	defer func() { _ = tx.Rollback(ctx) }()
	if err := fn(adminstore.Repositories{Outbox: &adminOutboxRepository{tx: tx}}); err != nil {
		return err
	}
	if err := tx.Commit(ctx); err != nil {
		return fmt.Errorf("postgres: commit isolated outbox unit of work: %w", err)
	}
	return nil
}

func (u *AdminUnitOfWork) Within(ctx context.Context, fn func(adminstore.Repositories) error) error {
	if fn == nil {
		return errors.New("postgres: unit of work callback is nil")
	}
	tx, err := u.beginner.BeginTx(ctx, pgx.TxOptions{IsoLevel: pgx.Serializable})
	if err != nil {
		return fmt.Errorf("postgres: begin admin unit of work: %w", err)
	}
	defer func() { _ = tx.Rollback(ctx) }()

	stepup := newAdminStepUpRepository(tx)
	repos := adminstore.Repositories{
		Roles:             newAdminRoleRepository(tx, u.codec),
		EventRegistry:     newDreamUPEventRegistryRepository(tx, u.codec),
		Challenges:        stepup,
		SecurityEpoch:     adminSecurityEpochRepository{repo: stepup},
		IdentityAccess:    newIdentityAccessRepository(tx, u.codec),
		Reasons:           &protectedReasonRepository{tx: tx},
		Outbox:            &adminOutboxRepository{tx: tx},
		OperatorApprovals: &operatorApprovalRepository{tx: tx},
		SecurityEvents:    &transactionSecurityEventStore{exec: tx},
	}
	if err := fn(repos); err != nil {
		return err
	}
	if err := tx.Commit(ctx); err != nil {
		return fmt.Errorf("postgres: commit admin unit of work: %w", err)
	}
	return nil
}

var _ adminstore.UnitOfWork = (*AdminUnitOfWork)(nil)
var _ adminstore.UnitOfWork = (*AdminOutboxUnitOfWork)(nil)
var _ adminroles.RoleMutationUnitOfWork = (*AdminUnitOfWork)(nil)
var _ adminstepup.StepUpMutationUnitOfWork = (*AdminUnitOfWork)(nil)
var _ identityaccess.MutationUnitOfWork = (*AdminUnitOfWork)(nil)

// WithinRoleMutation adapts the broad Task 1 transaction bundle to the four
// narrow ports owned by the adminroles domain. The callback still runs inside
// exactly the same serializable pgx transaction as the role audit and local
// receipt settlement.
func (u *AdminUnitOfWork) WithinRoleMutation(ctx context.Context, fn func(adminroles.RoleMutationRepositories) error) error {
	if fn == nil {
		return errors.New("postgres: role mutation callback is nil")
	}
	return u.Within(ctx, func(repositories adminstore.Repositories) error {
		roleRepository, ok := repositories.Roles.(*AdminRoleRepository)
		if !ok {
			return errors.New("postgres: role authorization repository unavailable")
		}
		reasons, ok := repositories.Reasons.(*protectedReasonRepository)
		if !ok {
			return errors.New("postgres: role protected-reason repository unavailable")
		}
		return fn(adminroles.RoleMutationRepositories{
			Roles:              repositories.Roles,
			ActorAuthorization: roleRepository,
			EventRegistry:      repositories.EventRegistry,
			Reasons:            &adminRoleReasonAdapter{repository: reasons},
			Receipts:           &adminRoleReceiptAdapter{repository: repositories.Outbox},
		})
	})
}

// WithinStepUpMutation adapts the broad transaction bundle to the narrow
// adminstepup-owned ports without creating an adminstepup -> adminstore cycle.
func (u *AdminUnitOfWork) WithinStepUpMutation(ctx context.Context, fn func(adminstepup.StepUpMutationRepositories) error) error {
	if fn == nil {
		return errors.New("postgres: step-up mutation callback is nil")
	}
	return u.Within(ctx, func(repositories adminstore.Repositories) error {
		approvalRepo, ok := repositories.OperatorApprovals.(*operatorApprovalRepository)
		if !ok {
			return errors.New("postgres: step-up approval repository unavailable")
		}
		identityRepo, ok := repositories.IdentityAccess.(*IdentityAccessRepository)
		if !ok {
			return errors.New("postgres: step-up identity-access repository unavailable")
		}
		securityEvents, ok := repositories.SecurityEvents.(*transactionSecurityEventStore)
		if !ok {
			return errors.New("postgres: step-up audit repository unavailable")
		}
		return fn(adminstepup.StepUpMutationRepositories{
			Challenges:      repositories.Challenges,
			AccountSecurity: adminStepUpAccountSecurityReader{tx: securityEvents.exec},
			Receipts:        &adminStepUpReceiptAdapter{repository: repositories.Outbox},
			Approvals:       &adminStepUpApprovalAdapter{repository: approvalRepo, identityAccess: identityRepo},
			Purges:          &adminStepUpPurgeAdapter{repository: repositories.Outbox},
			Audit:           &adminStepUpAuditAdapter{repository: securityEvents},
		})
	})
}

type adminStepUpAccountSecurityReader struct{ tx pgx.Tx }

const adminStepUpAccountSecurityEpochSQL = `SELECT security_epoch FROM users WHERE id=$1 FOR SHARE`

func (r adminStepUpAccountSecurityReader) CurrentEpoch(ctx context.Context, userID identity.UserID) (securitystate.Epoch, error) {
	var epoch int64
	err := r.tx.QueryRow(ctx, adminStepUpAccountSecurityEpochSQL, string(userID)).Scan(&epoch)
	if errors.Is(err, pgx.ErrNoRows) {
		return 0, identity.ErrUserNotFound
	}
	if err != nil {
		return 0, fmt.Errorf("postgres: current account security epoch for admin step-up: %w", err)
	}
	if epoch < 1 {
		return 0, errors.New("postgres: invalid account security epoch")
	}
	return securitystate.Epoch(epoch), nil
}

var _ adminstepup.AccountSecurityEpochReader = adminStepUpAccountSecurityReader{}

// WithinIdentityAccessMutation keeps the OA ledger, its redacted security
// audit and the local idempotency receipt in one serializable transaction.
func (u *AdminUnitOfWork) WithinIdentityAccessMutation(ctx context.Context, fn func(identityaccess.MutationRepositories) error) error {
	if fn == nil {
		return errors.New("postgres: identity access mutation callback is nil")
	}
	return u.Within(ctx, func(repositories adminstore.Repositories) error {
		access, ok := repositories.IdentityAccess.(*IdentityAccessRepository)
		if !ok {
			return errors.New("postgres: identity access repository unavailable")
		}
		return fn(identityaccess.MutationRepositories{
			Access: access, Authorization: access,
			Receipts: &identityAccessReceiptAdapter{repository: repositories.Outbox},
		})
	})
}

type identityAccessReceiptAdapter struct{ repository adminstore.OutboxRepository }

func (a *identityAccessReceiptAdapter) CreateOrReplay(ctx context.Context, receipt identityaccess.LocalOperationReceipt) (identityaccess.LocalOperationReceipt, bool, error) {
	item, replay, err := a.repository.CreateOrReplay(ctx, adminstore.OutboxItem{
		ID: receipt.ID, Kind: adminstore.OperationLocal, IdempotencyKey: receipt.IdempotencyKey,
		Fingerprint: adminstore.Fingerprint{Version: receipt.Fingerprint.Version, KeyID: receipt.Fingerprint.KeyID, Digest: receipt.Fingerprint.Digest},
		Result:      adminstore.AllowlistedResult{Code: receipt.Result.Code, Digest: receipt.Result.Digest, Payload: receipt.Result.Payload},
		State:       receipt.State, Version: receipt.Version, CreatedAt: receipt.CreatedAt, UpdatedAt: receipt.CreatedAt,
	})
	if err != nil {
		return identityaccess.LocalOperationReceipt{}, false, mapIdentityAccessReceiptError(err)
	}
	return identityaccess.LocalOperationReceipt{
		ID: item.ID, IdempotencyKey: item.IdempotencyKey,
		Fingerprint: identityaccess.RequestFingerprint{Version: item.Fingerprint.Version, KeyID: item.Fingerprint.KeyID, Digest: item.Fingerprint.Digest},
		Result:      identityaccess.LocalReceiptResult{Code: item.Result.Code, Digest: item.Result.Digest, Payload: item.Result.Payload},
		State:       item.State, Version: item.Version, CreatedAt: item.CreatedAt, TerminalAt: item.TerminalAt,
	}, replay, nil
}

func (a *identityAccessReceiptAdapter) CompleteLocal(ctx context.Context, id string, expected int64, result identityaccess.LocalReceiptResult, at time.Time) error {
	return mapIdentityAccessReceiptError(a.repository.CompleteLocal(ctx, id, expected, adminstore.AllowlistedResult{Code: result.Code, Digest: result.Digest, Payload: result.Payload}, at))
}

func mapIdentityAccessReceiptError(err error) error {
	if errors.Is(err, adminstore.ErrIdempotencyConflict) {
		return identityaccess.ErrIdempotencyConflict
	}
	if errors.Is(err, adminstore.ErrInvalidOperationResult) {
		return identityaccess.ErrInvalidStoredResult
	}
	return err
}

var _ identityaccess.LocalReceiptRepository = (*identityAccessReceiptAdapter)(nil)

type adminStepUpReceiptAdapter struct{ repository adminstore.OutboxRepository }

func (a *adminStepUpReceiptAdapter) CreateOrReplay(ctx context.Context, receipt adminstepup.LocalOperationReceipt) (adminstepup.LocalOperationReceipt, bool, error) {
	item, replay, err := a.repository.CreateOrReplay(ctx, adminstore.OutboxItem{
		ID: receipt.ID, Kind: adminstore.OperationLocal, IdempotencyKey: receipt.IdempotencyKey,
		Fingerprint: adminstore.Fingerprint{Version: receipt.Fingerprint.Version, KeyID: receipt.Fingerprint.KeyID, Digest: receipt.Fingerprint.Digest},
		Result:      adminstore.AllowlistedResult{Code: receipt.Result.Code, Digest: receipt.Result.Digest, Payload: receipt.Result.Payload},
		State:       receipt.State, Version: receipt.Version, CreatedAt: receipt.CreatedAt, UpdatedAt: receipt.CreatedAt,
	})
	if err != nil {
		return adminstepup.LocalOperationReceipt{}, false, mapStepUpReceiptError(err)
	}
	return adminstepup.LocalOperationReceipt{
		ID: item.ID, IdempotencyKey: item.IdempotencyKey,
		Fingerprint: adminstepup.RequestFingerprint{Version: item.Fingerprint.Version, KeyID: item.Fingerprint.KeyID, Digest: item.Fingerprint.Digest},
		Result:      adminstepup.LocalReceiptResult{Code: item.Result.Code, Digest: item.Result.Digest, Payload: item.Result.Payload},
		State:       item.State, Version: item.Version, CreatedAt: item.CreatedAt, TerminalAt: item.TerminalAt,
	}, replay, nil
}

func (a *adminStepUpReceiptAdapter) CompleteLocal(ctx context.Context, id string, expected int64, result adminstepup.LocalReceiptResult, at time.Time) error {
	return mapStepUpReceiptError(a.repository.CompleteLocal(ctx, id, expected, adminstore.AllowlistedResult{Code: result.Code, Digest: result.Digest, Payload: result.Payload}, at))
}

func mapStepUpReceiptError(err error) error {
	if errors.Is(err, adminstore.ErrIdempotencyConflict) {
		return adminstepup.ErrIdempotencyConflict
	}
	if errors.Is(err, adminstore.ErrInvalidOperationResult) {
		return adminstepup.ErrInvalidStoredReceipt
	}
	return err
}

type adminStepUpApprovalAdapter struct {
	repository     *operatorApprovalRepository
	identityAccess *IdentityAccessRepository
}

func (a *adminStepUpApprovalAdapter) RevokeForUser(ctx context.Context, userID identity.UserID, at time.Time) error {
	if err := a.repository.MarkAllTerminalForOperator(ctx, string(userID), at); err != nil {
		return err
	}
	return a.identityAccess.revokeForSecurityRotation(ctx, userID, at)
}

type adminStepUpPurgeAdapter struct{ repository adminstore.OutboxRepository }

func (a *adminStepUpPurgeAdapter) Enqueue(ctx context.Context, operationID string, userID identity.UserID, fingerprint adminstepup.RequestFingerprint, at time.Time) error {
	_, _, err := a.repository.CreateOrReplay(ctx, adminstore.OutboxItem{
		ID: newAdminID("aop_"), Kind: adminstore.OperationRedisPurge,
		IdempotencyKey: "redis-purge:" + operationID,
		Fingerprint:    adminstore.Fingerprint{Version: fingerprint.Version, KeyID: fingerprint.KeyID, Digest: fingerprint.Digest},
		State:          "pending", Version: 1, NextAttemptAt: at, CreatedAt: at, UpdatedAt: at,
	})
	if err != nil {
		return fmt.Errorf("postgres: enqueue admin step-up redis purge: %w", err)
	}
	return nil
}

type adminStepUpAuditAdapter struct {
	repository *transactionSecurityEventStore
}

func (a *adminStepUpAuditAdapter) Record(ctx context.Context, event adminstepup.AuditEvent) error {
	result := applications.SecurityEventSuccess
	if event.Result != "succeeded" {
		result = applications.SecurityEventDenied
	}
	return a.repository.Record(ctx, applications.SecurityEvent{
		EventID: applications.NewSecurityEventID(), EventType: "admin.challenge.updated",
		ActorUserID: event.ActorID, RequestID: event.RequestID, Operation: event.Action,
		Result: result, TargetKey: "challenge", TargetID: event.Target,
		Extra: map[string]string{"dreamup_event_id": event.EventID, "operation_id": event.ID}, OccurredAt: event.OccurredAt,
	})
}

var _ adminstepup.LocalReceiptRepository = (*adminStepUpReceiptAdapter)(nil)
var _ adminstepup.ApprovalRevoker = (*adminStepUpApprovalAdapter)(nil)
var _ adminstepup.RedisPurgeEnqueuer = (*adminStepUpPurgeAdapter)(nil)
var _ adminstepup.AuditRecorder = (*adminStepUpAuditAdapter)(nil)

type adminRoleReasonAdapter struct {
	repository *protectedReasonRepository
}

func (a *adminRoleReasonAdapter) ConsumeOwned(ctx context.Context, id string, owner identity.UserID, operationKind string, terminal, expires time.Time) error {
	return a.repository.ConsumeOwned(ctx, id, string(owner), operationKind, terminal, expires)
}

type adminRoleReceiptAdapter struct {
	repository adminstore.OutboxRepository
}

var _ adminroles.ProtectedReasonConsumer = (*adminRoleReasonAdapter)(nil)
var _ adminroles.LocalReceiptRepository = (*adminRoleReceiptAdapter)(nil)

func (a *adminRoleReceiptAdapter) CreateOrReplay(ctx context.Context, receipt adminroles.LocalOperationReceipt) (adminroles.LocalOperationReceipt, bool, error) {
	item, replay, err := a.repository.CreateOrReplay(ctx, adminstore.OutboxItem{
		ID: receipt.ID, Kind: adminstore.OperationLocal, IdempotencyKey: receipt.IdempotencyKey,
		Fingerprint: toAdminstoreFingerprint(receipt.Fingerprint),
		Result:      toAdminstoreResult(receipt.Result),
		State:       receipt.State, Version: receipt.Version, CreatedAt: receipt.CreatedAt, UpdatedAt: receipt.CreatedAt,
	})
	if err != nil {
		return adminroles.LocalOperationReceipt{}, false, mapRoleReceiptError(err)
	}
	return fromAdminstoreReceipt(item), replay, nil
}

func (a *adminRoleReceiptAdapter) CompleteLocal(ctx context.Context, id string, expected int64, result adminroles.LocalReceiptResult, at time.Time) error {
	return mapRoleReceiptError(a.repository.CompleteLocal(ctx, id, expected, toAdminstoreResult(result), at))
}

func toAdminstoreFingerprint(value adminroles.RequestFingerprint) adminstore.Fingerprint {
	return adminstore.Fingerprint{Version: value.Version, KeyID: value.KeyID, Digest: value.Digest}
}

func toAdminstoreResult(value adminroles.LocalReceiptResult) adminstore.AllowlistedResult {
	return adminstore.AllowlistedResult{Code: value.Code, Digest: value.Digest, Payload: value.Payload}
}

func fromAdminstoreReceipt(item adminstore.OutboxItem) adminroles.LocalOperationReceipt {
	return adminroles.LocalOperationReceipt{
		ID: item.ID, IdempotencyKey: item.IdempotencyKey,
		Fingerprint: adminroles.RequestFingerprint{Version: item.Fingerprint.Version, KeyID: item.Fingerprint.KeyID, Digest: item.Fingerprint.Digest},
		Result:      adminroles.LocalReceiptResult{Code: item.Result.Code, Digest: item.Result.Digest, Payload: item.Result.Payload},
		State:       item.State, Version: item.Version, CreatedAt: item.CreatedAt, TerminalAt: item.TerminalAt,
	}
}

func mapRoleReceiptError(err error) error {
	if errors.Is(err, adminstore.ErrIdempotencyConflict) {
		return adminroles.ErrRoleIdempotencyConflict
	}
	if errors.Is(err, adminstore.ErrInvalidOperationResult) {
		return adminroles.ErrInvalidStoredRoleResult
	}
	return err
}

type transactionSecurityEventStore struct{ exec pgx.Tx }

func (s *transactionSecurityEventStore) Record(ctx context.Context, event applications.SecurityEvent) error {
	return insertSecurityEvent(ctx, s.exec, event)
}

type protectedReasonRepository struct{ tx pgx.Tx }

func (r *protectedReasonRepository) Create(ctx context.Context, id, owner, keyID string, nonce, ciphertext []byte, created time.Time) error {
	_, err := r.tx.Exec(ctx, `INSERT INTO protected_operation_reasons(reason_id,owner_user_id,operation_kind,key_id,nonce,ciphertext,created_at) VALUES($1,$2,'direct_read',$3,$4,$5,$6)`, id, owner, keyID, nonce, ciphertext, created)
	if err != nil {
		return fmt.Errorf("postgres: create protected reason: %w", err)
	}
	return nil
}

func (r *protectedReasonRepository) MarkTerminal(ctx context.Context, id string, terminal, expires time.Time) error {
	tag, err := r.tx.Exec(ctx, `UPDATE protected_operation_reasons SET consumed_at=COALESCE(consumed_at,$2),terminal_at=$2,expires_at=$3 WHERE reason_id=$1 AND terminal_at IS NULL`, id, terminal, expires)
	if err != nil {
		return err
	}
	if tag.RowsAffected() != 1 {
		return adminstore.ErrIdempotencyConflict
	}
	return nil
}

func (r *protectedReasonRepository) ConsumeOwned(ctx context.Context, id, owner, operationKind string, terminal, expires time.Time) error {
	if id == "" || owner == "" || operationKind == "" || !expires.After(terminal) {
		return adminstore.ErrIdempotencyConflict
	}
	tag, err := r.tx.Exec(ctx, `UPDATE protected_operation_reasons SET consumed_at=$4,terminal_at=$4,expires_at=$5 WHERE reason_id=$1 AND owner_user_id=$2 AND operation_kind=$3 AND consumed_at IS NULL AND terminal_at IS NULL`, id, owner, operationKind, terminal, expires)
	if err != nil {
		return fmt.Errorf("postgres: consume protected reason: %w", err)
	}
	if tag.RowsAffected() != 1 {
		return adminstore.ErrIdempotencyConflict
	}
	return nil
}

func (r *protectedReasonRepository) PurgeExpired(ctx context.Context, now time.Time, limit int) (int, error) {
	if limit <= 0 || limit > 100 {
		limit = 100
	}
	rows, err := r.tx.Query(ctx, `SELECT reason_id FROM protected_operation_reasons WHERE expires_at<=$1 AND purged_at IS NULL ORDER BY expires_at,reason_id LIMIT $2 FOR UPDATE SKIP LOCKED`, now, limit)
	if err != nil {
		return 0, err
	}
	ids := []string{}
	for rows.Next() {
		var id string
		if err := rows.Scan(&id); err != nil {
			rows.Close()
			return 0, err
		}
		ids = append(ids, id)
	}
	rows.Close()
	for _, id := range ids {
		if _, err := r.tx.Exec(ctx, `UPDATE protected_operation_reasons SET key_id=NULL,nonce=NULL,ciphertext=NULL,purged_at=$2 WHERE reason_id=$1 AND purged_at IS NULL`, id, now); err != nil {
			return 0, err
		}
	}
	return len(ids), nil
}

type adminOutboxRepository struct{ tx pgx.Tx }

func (r *adminOutboxRepository) CreateOrReplay(ctx context.Context, item adminstore.OutboxItem) (adminstore.OutboxItem, bool, error) {
	if item.ID == "" {
		item.ID = newAdminID("aop_")
	}
	if item.Version == 0 {
		item.Version = 1
	}
	if item.State == "" {
		item.State = "pending"
	}
	if item.NextAttemptAt.IsZero() {
		item.NextAttemptAt = time.Now().UTC()
	}
	if item.CreatedAt.IsZero() {
		item.CreatedAt = time.Now().UTC()
	}
	if item.UpdatedAt.IsZero() {
		item.UpdatedAt = item.CreatedAt
	}
	if item.DeliveryPhase == "" {
		item.DeliveryPhase = adminstore.DeliveryPhaseNotSent
	}
	if !item.DeliveryPhase.Valid() {
		return adminstore.OutboxItem{}, false, adminstore.ErrInvalidOperationResult
	}
	payload, err := adminstore.EncodeAllowlistedPayload(item.Result.Payload)
	if err != nil {
		return adminstore.OutboxItem{}, false, adminstore.ErrInvalidOperationResult
	}
	if err := adminstore.ValidateOptionalAllowlistedResult(item.Result); err != nil {
		return adminstore.OutboxItem{}, false, err
	}
	tag, err := r.tx.Exec(ctx, `INSERT INTO admin_operation_outbox(operation_id,operation_kind,idempotency_key,request_fingerprint_version,request_fingerprint_key_id,request_fingerprint_hmac,payload_key_id,payload_nonce,payload_ciphertext,result_code,result_digest,result_payload,delivery_state,delivery_phase,attempts,next_attempt_at,version,created_at,updated_at) VALUES($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13,$14,$15,$16,$17,$18,$19) ON CONFLICT(idempotency_key) DO NOTHING`, item.ID, string(item.Kind), item.IdempotencyKey, item.Fingerprint.Version, item.Fingerprint.KeyID, item.Fingerprint.Digest, adminNullableString(item.PayloadKeyID), nullableBytes(item.PayloadNonce), nullableBytes(item.PayloadCiphertext), item.Result.Code, item.Result.Digest, payload, item.State, string(item.DeliveryPhase), item.Attempts, item.NextAttemptAt, item.Version, item.CreatedAt, item.UpdatedAt)
	if err != nil {
		return adminstore.OutboxItem{}, false, fmt.Errorf("postgres: insert admin outbox: %w", err)
	}
	if tag.RowsAffected() == 1 {
		return item, false, nil
	}
	existing, err := r.getByIdempotencyKey(ctx, item.IdempotencyKey)
	if err != nil {
		return adminstore.OutboxItem{}, false, err
	}
	if existing.Fingerprint != item.Fingerprint {
		return adminstore.OutboxItem{}, false, adminstore.ErrIdempotencyConflict
	}
	return adminstore.SanitizeOutboxReplay(existing), true, nil
}

func (r *adminOutboxRepository) getByIdempotencyKey(ctx context.Context, key string) (adminstore.OutboxItem, error) {
	return scanOutbox(r.tx.QueryRow(ctx, outboxSelect+` WHERE idempotency_key=$1`, key))
}

func (r *adminOutboxRepository) GetByIdempotencyKey(ctx context.Context, key string) (adminstore.OutboxItem, error) {
	item, err := r.getByIdempotencyKey(ctx, key)
	if errors.Is(err, pgx.ErrNoRows) {
		return adminstore.OutboxItem{}, adminstore.ErrOperationNotFound
	}
	if err != nil {
		return adminstore.OutboxItem{}, err
	}
	return adminstore.SanitizeOutboxReplay(item), nil
}

const adminOutboxClaimDueSQL = `SELECT operation_id FROM admin_operation_outbox WHERE delivery_state='pending' AND delivery_phase='not_sent' AND next_attempt_at<=$1 ORDER BY next_attempt_at,operation_id LIMIT $2 FOR UPDATE SKIP LOCKED`
const adminOutboxClaimReceiptsDueSQL = `SELECT operation_id FROM admin_operation_outbox WHERE delivery_state='pending' AND delivery_phase IN('indeterminate','sent') AND next_attempt_at<=$1 ORDER BY next_attempt_at,operation_id LIMIT $2 FOR UPDATE SKIP LOCKED`

func (r *adminOutboxRepository) reclaimExpiredClaims(ctx context.Context, now time.Time) error {
	_, err := r.tx.Exec(ctx, `UPDATE admin_operation_outbox SET delivery_state='pending',claim_token_hash=NULL,claim_lease_until=NULL,next_attempt_at=$1,version=version+1,updated_at=$1 WHERE delivery_state='claimed' AND claim_lease_until<=$1`, now)
	return err
}

func (r *adminOutboxRepository) ClaimDue(ctx context.Context, now time.Time, limit int) ([]adminstore.OutboxItem, error) {
	if limit <= 0 || limit > 100 {
		limit = 100
	}
	if err := r.reclaimExpiredClaims(ctx, now); err != nil {
		return nil, err
	}
	rows, err := r.tx.Query(ctx, adminOutboxClaimDueSQL, now, limit)
	if err != nil {
		return nil, err
	}
	ids := []string{}
	for rows.Next() {
		var id string
		if err := rows.Scan(&id); err != nil {
			rows.Close()
			return nil, err
		}
		ids = append(ids, id)
	}
	rows.Close()
	items := make([]adminstore.OutboxItem, 0, len(ids))
	for _, id := range ids {
		raw := make([]byte, 32)
		if _, err := rand.Read(raw); err != nil {
			return nil, err
		}
		token := base64.RawURLEncoding.EncodeToString(raw)
		hash := hashAdminOutboxClaimToken(token)
		lease := now.Add(30 * time.Second)
		tag, err := r.tx.Exec(ctx, `UPDATE admin_operation_outbox SET delivery_state='claimed',claim_token_hash=$2,claim_lease_until=$3,attempts=attempts+1,version=version+1,updated_at=$4 WHERE operation_id=$1 AND delivery_state='pending' AND delivery_phase='not_sent'`, id, hash, lease, now)
		if err != nil {
			return nil, err
		}
		if tag.RowsAffected() != 1 {
			return nil, adminstore.ErrIdempotencyConflict
		}
		item, err := scanOutbox(r.tx.QueryRow(ctx, outboxSelect+` WHERE operation_id=$1`, id))
		if err != nil {
			return nil, err
		}
		item.ClaimToken = token
		items = append(items, item)
	}
	return items, nil
}

func (r *adminOutboxRepository) ClaimExact(ctx context.Context, id string, expected int64, now time.Time, lease time.Duration) (adminstore.OutboxItem, error) {
	if id == "" || expected <= 0 || lease <= 0 || lease > 10*time.Minute {
		return adminstore.OutboxItem{}, adminstore.ErrIdempotencyConflict
	}
	token, hash, err := newAdminOutboxClaimToken()
	if err != nil {
		return adminstore.OutboxItem{}, err
	}
	leaseUntil := now.Add(lease)
	tag, err := r.tx.Exec(ctx, `UPDATE admin_operation_outbox SET delivery_state='claimed',claim_token_hash=$3,claim_lease_until=$4,attempts=attempts+1,version=version+1,updated_at=$5 WHERE operation_id=$1 AND version=$2 AND delivery_state='pending' AND delivery_phase='not_sent'`, id, expected, hash, leaseUntil, now)
	if err != nil {
		return adminstore.OutboxItem{}, err
	}
	if tag.RowsAffected() != 1 {
		return adminstore.OutboxItem{}, adminstore.ErrIdempotencyConflict
	}
	item, err := scanOutbox(r.tx.QueryRow(ctx, outboxSelect+` WHERE operation_id=$1`, id))
	if err != nil {
		return adminstore.OutboxItem{}, err
	}
	item.ClaimToken = token
	return item, nil
}

func (r *adminOutboxRepository) ClaimReceiptsDue(ctx context.Context, now time.Time, limit int, lease time.Duration) ([]adminstore.OutboxItem, error) {
	if limit <= 0 || limit > 100 || lease <= 0 || lease > 10*time.Minute {
		return nil, adminstore.ErrIdempotencyConflict
	}
	if err := r.reclaimExpiredClaims(ctx, now); err != nil {
		return nil, err
	}
	rows, err := r.tx.Query(ctx, adminOutboxClaimReceiptsDueSQL, now, limit)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var ids []string
	for rows.Next() {
		var id string
		if err := rows.Scan(&id); err != nil {
			return nil, err
		}
		ids = append(ids, id)
	}
	if err := rows.Err(); err != nil {
		return nil, err
	}
	items := make([]adminstore.OutboxItem, 0, len(ids))
	for _, id := range ids {
		token, hash, err := newAdminOutboxClaimToken()
		if err != nil {
			return nil, err
		}
		leaseUntil := now.Add(lease)
		tag, err := r.tx.Exec(ctx, `UPDATE admin_operation_outbox SET delivery_state='claimed',claim_token_hash=$2,claim_lease_until=$3,attempts=attempts+1,version=version+1,updated_at=$4 WHERE operation_id=$1 AND delivery_state='pending' AND delivery_phase IN('indeterminate','sent')`, id, hash, leaseUntil, now)
		if err != nil {
			return nil, err
		}
		if tag.RowsAffected() != 1 {
			return nil, adminstore.ErrIdempotencyConflict
		}
		item, err := scanOutbox(r.tx.QueryRow(ctx, outboxSelect+` WHERE operation_id=$1`, id))
		if err != nil {
			return nil, err
		}
		item.ClaimToken = token
		items = append(items, item)
	}
	return items, nil
}

func newAdminOutboxClaimToken() (string, string, error) {
	raw := make([]byte, 32)
	if _, err := rand.Read(raw); err != nil {
		return "", "", err
	}
	token := base64.RawURLEncoding.EncodeToString(raw)
	return token, hashAdminOutboxClaimToken(token), nil
}

func (r *adminOutboxRepository) MarkDeliveryPhase(ctx context.Context, id string, expected int64, claimToken string, phase adminstore.DeliveryPhase, at time.Time) error {
	if claimToken == "" {
		return adminstore.ErrIdempotencyConflict
	}
	var query string
	switch phase {
	case adminstore.DeliveryPhaseIndeterminate:
		query = `UPDATE admin_operation_outbox SET delivery_phase='indeterminate',version=version+1,updated_at=$4 WHERE operation_id=$1 AND version=$2 AND delivery_state='claimed' AND claim_token_hash=$3 AND claim_lease_until>$4 AND delivery_phase='not_sent'`
	case adminstore.DeliveryPhaseSent:
		query = `UPDATE admin_operation_outbox SET delivery_phase='sent',version=version+1,updated_at=$4 WHERE operation_id=$1 AND version=$2 AND delivery_state='claimed' AND claim_token_hash=$3 AND claim_lease_until>$4 AND delivery_phase='indeterminate'`
	default:
		return adminstore.ErrIdempotencyConflict
	}
	tag, err := r.tx.Exec(ctx, query, id, expected, hashAdminOutboxClaimToken(claimToken), at)
	if err != nil {
		return err
	}
	if tag.RowsAffected() != 1 {
		return adminstore.ErrIdempotencyConflict
	}
	return nil
}

func (r *adminOutboxRepository) DeferReceipt(ctx context.Context, id string, expected int64, claimToken string, nextAttempt, at time.Time) error {
	if claimToken == "" || !nextAttempt.After(at) {
		return adminstore.ErrIdempotencyConflict
	}
	tag, err := r.tx.Exec(ctx, `UPDATE admin_operation_outbox SET delivery_state='pending',claim_token_hash=NULL,claim_lease_until=NULL,next_attempt_at=$4,version=version+1,updated_at=$5 WHERE operation_id=$1 AND version=$2 AND delivery_state='claimed' AND delivery_phase IN('indeterminate','sent') AND claim_token_hash=$3 AND claim_lease_until>$5`, id, expected, hashAdminOutboxClaimToken(claimToken), nextAttempt, at)
	if err != nil {
		return err
	}
	if tag.RowsAffected() != 1 {
		return adminstore.ErrIdempotencyConflict
	}
	return nil
}

func (r *adminOutboxRepository) MarkNeedsOperator(ctx context.Context, id string, expected int64, claimToken string, at time.Time) error {
	if claimToken == "" {
		return adminstore.ErrIdempotencyConflict
	}
	tag, err := r.tx.Exec(ctx, `UPDATE admin_operation_outbox SET delivery_state='needs_operator',claim_token_hash=NULL,claim_lease_until=NULL,terminal_at=$4,version=version+1,updated_at=$4 WHERE operation_id=$1 AND version=$2 AND delivery_state='claimed' AND delivery_phase IN('indeterminate','sent') AND claim_token_hash=$3 AND claim_lease_until>$4`, id, expected, hashAdminOutboxClaimToken(claimToken), at)
	if err != nil {
		return err
	}
	if tag.RowsAffected() != 1 {
		return adminstore.ErrIdempotencyConflict
	}
	return nil
}

func (r *adminOutboxRepository) Settle(ctx context.Context, id string, expected int64, claimToken string, result adminstore.AllowlistedResult, at time.Time) error {
	if claimToken == "" {
		return adminstore.ErrIdempotencyConflict
	}
	if err := result.Validate(); err != nil {
		return err
	}
	payload, err := adminstore.EncodeAllowlistedPayload(result.Payload)
	if err != nil {
		return err
	}
	tag, err := r.tx.Exec(ctx, `UPDATE admin_operation_outbox SET delivery_state='succeeded',claim_token_hash=NULL,claim_lease_until=NULL,result_code=$4,result_digest=$5,result_payload=$6,terminal_at=$7,version=version+1,updated_at=$7 WHERE operation_id=$1 AND version=$2 AND delivery_state='claimed' AND delivery_phase='sent' AND claim_token_hash=$3 AND claim_lease_until>$7`, id, expected, hashAdminOutboxClaimToken(claimToken), result.Code, result.Digest, payload, at)
	if err != nil {
		return err
	}
	if tag.RowsAffected() != 1 {
		return adminstore.ErrIdempotencyConflict
	}
	return nil
}

func (r *adminOutboxRepository) Fail(ctx context.Context, id string, expected int64, claimToken string, result adminstore.AllowlistedResult, at time.Time) error {
	if claimToken == "" || result.Code != "operation.failed" {
		return adminstore.ErrIdempotencyConflict
	}
	if err := result.Validate(); err != nil {
		return err
	}
	payload, err := adminstore.EncodeAllowlistedPayload(result.Payload)
	if err != nil {
		return err
	}
	tag, err := r.tx.Exec(ctx, `UPDATE admin_operation_outbox SET delivery_state='failed',claim_token_hash=NULL,claim_lease_until=NULL,result_code=$4,result_digest=$5,result_payload=$6,terminal_at=$7,version=version+1,updated_at=$7 WHERE operation_id=$1 AND version=$2 AND delivery_state='claimed' AND delivery_phase='sent' AND claim_token_hash=$3 AND claim_lease_until>$7`, id, expected, hashAdminOutboxClaimToken(claimToken), result.Code, result.Digest, payload, at)
	if err != nil {
		return err
	}
	if tag.RowsAffected() != 1 {
		return adminstore.ErrIdempotencyConflict
	}
	return nil
}

// CompleteLocal settles a local-only receipt in the same pgx transaction as
// its domain mutation and audit. Local receipts never enter the worker claim
// protocol, so this is deliberately limited to the initial pending version.
func (r *adminOutboxRepository) CompleteLocal(ctx context.Context, id string, expected int64, result adminstore.AllowlistedResult, at time.Time) error {
	if err := result.Validate(); err != nil {
		return err
	}
	payload, err := adminstore.EncodeAllowlistedPayload(result.Payload)
	if err != nil {
		return err
	}
	tag, err := r.tx.Exec(ctx, `UPDATE admin_operation_outbox SET delivery_state='succeeded',result_code=$3,result_digest=$4,result_payload=$5,terminal_at=$6,version=version+1,updated_at=$6 WHERE operation_id=$1 AND version=$2 AND operation_kind='local' AND delivery_state='pending' AND terminal_at IS NULL`, id, expected, result.Code, result.Digest, payload, at)
	if err != nil {
		return fmt.Errorf("postgres: complete local admin operation: %w", err)
	}
	if tag.RowsAffected() != 1 {
		return adminstore.ErrIdempotencyConflict
	}
	return nil
}

func (r *adminOutboxRepository) MarkAuditReconciled(ctx context.Context, id string, expected int64, at time.Time) error {
	expires := adminstore.PayloadRetentionDeadline(at)
	tag, err := r.tx.Exec(ctx, `UPDATE admin_operation_outbox SET audit_reconciled_at=$3,payload_expires_at=$4,version=version+1,updated_at=$3 WHERE operation_id=$1 AND version=$2 AND terminal_at IS NOT NULL AND audit_reconciled_at IS NULL`, id, expected, at, expires)
	if err != nil {
		return err
	}
	if tag.RowsAffected() != 1 {
		return adminstore.ErrIdempotencyConflict
	}
	return nil
}

func (r *adminOutboxRepository) ReleaseExpiredClaim(ctx context.Context, id string, expected int64, now time.Time) error {
	tag, err := r.tx.Exec(ctx, `UPDATE admin_operation_outbox SET delivery_state='pending',claim_token_hash=NULL,claim_lease_until=NULL,next_attempt_at=$3,version=version+1,updated_at=$3 WHERE operation_id=$1 AND version=$2 AND delivery_state='claimed' AND delivery_phase IN('not_sent','indeterminate','sent') AND claim_lease_until<=$3`, id, expected, now)
	if err != nil {
		return err
	}
	if tag.RowsAffected() != 1 {
		return adminstore.ErrIdempotencyConflict
	}
	return nil
}

func (r *adminOutboxRepository) PurgePayload(ctx context.Context, id string, expected int64, now time.Time) error {
	tag, err := r.tx.Exec(ctx, `UPDATE admin_operation_outbox SET payload_key_id=NULL,payload_nonce=NULL,payload_ciphertext=NULL,payload_purged_at=$3,version=version+1,updated_at=$3 WHERE operation_id=$1 AND version=$2 AND payload_expires_at<=$3 AND payload_purged_at IS NULL`, id, expected, now)
	if err != nil {
		return err
	}
	if tag.RowsAffected() != 1 {
		return adminstore.ErrIdempotencyConflict
	}
	return nil
}

const outboxSelect = `SELECT operation_id,operation_kind,idempotency_key,request_fingerprint_version,request_fingerprint_key_id,request_fingerprint_hmac,payload_key_id,payload_nonce,payload_ciphertext,result_code,result_digest,result_payload,delivery_state,delivery_phase,claim_token_hash,claim_lease_until,attempts,next_attempt_at,version,terminal_at,audit_reconciled_at,payload_expires_at,payload_purged_at,created_at,updated_at FROM admin_operation_outbox`

func scanOutbox(row pgx.Row) (adminstore.OutboxItem, error) {
	var item adminstore.OutboxItem
	var kind string
	var deliveryPhase string
	var payload []byte
	var payloadKeyID, claimTokenHash *string
	err := row.Scan(&item.ID, &kind, &item.IdempotencyKey, &item.Fingerprint.Version, &item.Fingerprint.KeyID, &item.Fingerprint.Digest, &payloadKeyID, &item.PayloadNonce, &item.PayloadCiphertext, &item.Result.Code, &item.Result.Digest, &payload, &item.State, &deliveryPhase, &claimTokenHash, &item.ClaimLeaseUntil, &item.Attempts, &item.NextAttemptAt, &item.Version, &item.TerminalAt, &item.AuditReconciledAt, &item.PayloadExpiresAt, &item.PayloadPurgedAt, &item.CreatedAt, &item.UpdatedAt)
	item.Kind = adminstore.OperationKind(kind)
	item.DeliveryPhase = adminstore.DeliveryPhase(deliveryPhase)
	applyNullableOutboxStrings(&item, payloadKeyID, claimTokenHash)
	if err == nil {
		err = json.Unmarshal(payload, &item.Result.Payload)
	}
	return item, err
}

func applyNullableOutboxStrings(item *adminstore.OutboxItem, payloadKeyID, claimTokenHash *string) {
	item.PayloadKeyID = ""
	item.ClaimTokenHash = ""
	if payloadKeyID != nil {
		item.PayloadKeyID = *payloadKeyID
	}
	if claimTokenHash != nil {
		item.ClaimTokenHash = *claimTokenHash
	}
}

type operatorApprovalRepository struct{ tx pgx.Tx }

func (r *operatorApprovalRepository) Create(ctx context.Context, approval adminstore.OperatorApproval) error {
	_, err := r.tx.Exec(ctx, `INSERT INTO admin_operator_approvals(approval_id,request_hash,operator_user_id,key_id,signature,expires_at,terminal_at,created_at) VALUES($1,$2,$3,$4,$5,$6,$7,$8)`, approval.ID, approval.RequestHash, approval.OperatorID, approval.KeyID, approval.Signature, approval.ExpiresAt, approval.TerminalAt, approval.CreatedAt)
	if err != nil {
		if isUniqueViolation(err) {
			return adminstore.ErrIdempotencyConflict
		}
		return err
	}
	return nil
}

func (r *operatorApprovalRepository) ListActive(ctx context.Context, hash string, now time.Time) ([]adminstore.OperatorApproval, error) {
	rows, err := r.tx.Query(ctx, `SELECT approval_id,request_hash,operator_user_id,key_id,signature,expires_at,terminal_at,created_at FROM admin_operator_approvals WHERE request_hash=$1 AND terminal_at IS NULL AND expires_at>$2 ORDER BY approval_id`, hash, now)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	items := []adminstore.OperatorApproval{}
	for rows.Next() {
		var item adminstore.OperatorApproval
		if err := rows.Scan(&item.ID, &item.RequestHash, &item.OperatorID, &item.KeyID, &item.Signature, &item.ExpiresAt, &item.TerminalAt, &item.CreatedAt); err != nil {
			return nil, err
		}
		items = append(items, item)
	}
	return items, rows.Err()
}

func (r *operatorApprovalRepository) MarkTerminal(ctx context.Context, hash string, terminal time.Time) error {
	_, err := r.tx.Exec(ctx, `UPDATE admin_operator_approvals SET terminal_at=$2 WHERE request_hash=$1 AND terminal_at IS NULL`, hash, terminal)
	return err
}

func (r *operatorApprovalRepository) MarkAllTerminalForOperator(ctx context.Context, operatorID string, terminal time.Time) error {
	_, err := r.tx.Exec(ctx, `UPDATE admin_operator_approvals SET terminal_at=$2 WHERE operator_user_id=$1 AND terminal_at IS NULL`, operatorID, terminal)
	return err
}

func adminNullableString(value string) any {
	if value == "" {
		return nil
	}
	return value
}

func hashAdminOutboxClaimToken(token string) string {
	digest := sha256.Sum256([]byte(token))
	return base64.RawURLEncoding.EncodeToString(digest[:])
}

func nullableBytes(value []byte) any {
	if len(value) == 0 {
		return nil
	}
	return value
}
