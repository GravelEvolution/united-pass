package postgres

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"errors"
	"fmt"
	"sort"
	"strings"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/GravelEvolution/united-pass/backend/internal/adminpagination"
	"github.com/GravelEvolution/united-pass/backend/internal/adminroles"
	"github.com/GravelEvolution/united-pass/backend/internal/applications"
	"github.com/GravelEvolution/united-pass/backend/internal/identity"
	"github.com/GravelEvolution/united-pass/backend/internal/identityaccess"
)

type IdentityAccessRepository struct {
	exec  adminDBTX
	tx    pgx.Tx
	codec *adminpagination.CursorCodec
}

const identityAccessRequestColumns = `r.request_id,r.event_id,r.requester_user_id,r.target_subject_user_id,r.approver_user_id,r.target_type,r.target_id,r.status,r.reason_id,r.version,r.created_at,r.updated_at,r.expires_at,r.terminal_at`

const (
	identityAccessDecideLockSQL = `SELECT ` + identityAccessRequestColumns + `,
		ARRAY(SELECT f.field_name::TEXT FROM identity_access_request_fields f WHERE f.request_id=r.request_id ORDER BY f.field_name)
		FROM identity_access_requests r WHERE r.request_id=$1 AND r.event_id=$2 FOR UPDATE`
	identityAccessDecideUpdateSQL = `UPDATE identity_access_requests SET status=$3,approver_user_id=$4,terminal_at=$5,updated_at=$5,version=version+1
		WHERE request_id=$1 AND event_id=$2 AND version=$6 AND status='pending' AND expires_at>$5 RETURNING version`
	identityAccessClaimSQL = `UPDATE identity_access_grants SET status='claimed',claim_nonce_hash=$4,claim_lease_until=$5+INTERVAL '60 seconds',version=version+1,updated_at=$5
		WHERE grant_id=$1 AND event_id=$2 AND requester_user_id=$3
		  AND requester_role_binding_id=$6 AND requester_role_binding_version=$7 AND requester_challenge_version=$8
		  AND version=$9 AND status='active' AND expires_at>$5
		RETURNING version,claim_lease_until,request_id,target_subject_user_id,target_type,target_id,field_set_hash,
		  ARRAY(SELECT f.field_name::TEXT FROM identity_access_grant_fields f WHERE f.grant_id=identity_access_grants.grant_id ORDER BY f.field_name)`
	identityAccessSettleSQL = `UPDATE identity_access_grants SET status='settled',claim_nonce_hash=NULL,claim_lease_until=NULL,response_receipt_hash=$6,terminal_at=$7,updated_at=$7,version=version+1
		WHERE grant_id=$1 AND event_id=$2 AND requester_user_id=$3 AND claim_nonce_hash=$4 AND version=$5
		  AND requester_role_binding_id=$8 AND requester_role_binding_version=$9 AND requester_challenge_version=$10
		  AND status='claimed' AND claim_lease_until>$7 AND expires_at>$7 RETURNING version`
	identityAccessReleaseExpiredClaimSQL = `UPDATE identity_access_grants SET status='active',claim_nonce_hash=NULL,claim_lease_until=NULL,version=version+1,updated_at=NOW()
		WHERE grant_id=$1 AND event_id=$2 AND version=$3 AND status='claimed' AND claim_lease_until<=NOW() AND expires_at>NOW()`
)

var _ identityaccess.Repository = (*IdentityAccessRepository)(nil)
var _ identityaccess.AuthorizationRepository = (*IdentityAccessRepository)(nil)

func NewIdentityAccessRepository(pool *pgxpool.Pool, codec *adminpagination.CursorCodec) *IdentityAccessRepository {
	return &IdentityAccessRepository{exec: pool, codec: codec}
}

func newIdentityAccessRepository(tx pgx.Tx, codec *adminpagination.CursorCodec) *IdentityAccessRepository {
	return &IdentityAccessRepository{exec: tx, tx: tx, codec: codec}
}

func (r *IdentityAccessRepository) CreateRequest(ctx context.Context, request identityaccess.Request, reason identityaccess.ProtectedReason, audit identityaccess.Audit) (identityaccess.Request, error) {
	if r.tx == nil {
		return identityaccess.Request{}, errors.New("postgres: identity access write requires unit of work")
	}
	if err := identityaccess.ValidateRequest(request); err != nil || request.ID == "" || request.ReasonID == "" || request.Status != identityaccess.StatusPending || request.Version != 1 || request.ExpiresAt.IsZero() || !request.ExpiresAt.After(request.CreatedAt) {
		return identityaccess.Request{}, identityaccess.ErrInvalidRequest
	}
	prepareIdentityAccessTimestamps(&request, &reason, request.CreatedAt)
	if reason.ID != request.ReasonID || reason.OwnerID != request.RequesterID || reason.KeyID == "" || len(reason.Nonce) == 0 || len(reason.Ciphertext) == 0 {
		return identityaccess.Request{}, identityaccess.ErrInvalidRequest
	}
	if _, err := r.tx.Exec(ctx, `INSERT INTO protected_operation_reasons(reason_id,owner_user_id,operation_kind,key_id,nonce,ciphertext,created_at) VALUES($1,$2,'identity_access',$3,$4,$5,$6)`, reason.ID, string(reason.OwnerID), reason.KeyID, reason.Nonce, reason.Ciphertext, reason.CreatedAt); err != nil {
		if isUniqueViolation(err) {
			return identityaccess.Request{}, identityaccess.ErrConflict
		}
		return identityaccess.Request{}, fmt.Errorf("postgres: insert protected reason: %w", err)
	}
	_, err := r.tx.Exec(ctx, `INSERT INTO identity_access_requests(request_id,event_id,requester_user_id,target_subject_user_id,target_type,target_id,status,reason_id,version,created_at,updated_at,expires_at) VALUES($1,$2,$3,$4,$5,$6,'pending',$7,$8,$9,$10,$11)`, request.ID, request.EventID, string(request.RequesterID), string(request.TargetSubject), string(request.TargetType), request.TargetID, request.ReasonID, request.Version, request.CreatedAt, request.UpdatedAt, request.ExpiresAt)
	if err != nil {
		if isUniqueViolation(err) {
			return identityaccess.Request{}, identityaccess.ErrConflict
		}
		return identityaccess.Request{}, fmt.Errorf("postgres: insert identity access request: %w", err)
	}
	for _, field := range request.Fields {
		if _, err := r.tx.Exec(ctx, `INSERT INTO identity_access_request_fields(request_id,field_name) VALUES($1,$2)`, request.ID, string(field)); err != nil {
			return identityaccess.Request{}, fmt.Errorf("postgres: insert identity access field: %w", err)
		}
	}
	if err := recordIdentityAccessMutation(ctx, r.tx, audit, "admin.identity_access.requested", request.EventID, "identity_access_request", request.ID); err != nil {
		return identityaccess.Request{}, err
	}
	return request, nil
}

func (r *IdentityAccessRepository) GetRequest(ctx context.Context, eventID, requestID string) (identityaccess.Request, error) {
	request, err := scanIdentityAccessRequestWithFields(r.exec.QueryRow(ctx, `SELECT `+identityAccessRequestColumns+`,ARRAY(SELECT f.field_name::TEXT FROM identity_access_request_fields f WHERE f.request_id=r.request_id ORDER BY f.field_name) FROM identity_access_requests r WHERE r.request_id=$1 AND r.event_id=$2`, requestID, eventID))
	if errors.Is(err, pgx.ErrNoRows) {
		return identityaccess.Request{}, identityaccess.ErrNotFound
	}
	if err != nil {
		return identityaccess.Request{}, fmt.Errorf("postgres: get identity access request: %w", err)
	}
	return request, nil
}

func (r *IdentityAccessRepository) ListOwn(ctx context.Context, userID identity.UserID, query adminpagination.Query) (identityaccess.Page, error) {
	if err := identityaccess.ValidateOwnListQuery(query); err != nil {
		return identityaccess.Page{}, err
	}
	return r.list(ctx, string(userID), false, query)
}

func (r *IdentityAccessRepository) ListApprovalQueue(ctx context.Context, query adminpagination.Query) (identityaccess.Page, error) {
	if err := identityaccess.ValidateApprovalListQuery(query); err != nil {
		return identityaccess.Page{}, err
	}
	return r.list(ctx, "", true, query)
}

func (r *IdentityAccessRepository) list(ctx context.Context, requester string, queue bool, query adminpagination.Query) (identityaccess.Page, error) {
	limit := normalizeAdminLimit(query.Limit)
	sortOrder := query.Sort
	if sortOrder == "" {
		sortOrder = "id:asc"
	}
	if sortOrder != "id:asc" || r.codec == nil {
		return identityaccess.Page{}, adminpagination.ErrInvalidCursor
	}
	status, err := identityAccessStatusFilter(query.Filters, queue)
	if err != nil {
		return identityaccess.Page{}, err
	}
	lastID := ""
	if query.Cursor != "" {
		state, err := r.codec.Decode(query.Cursor, adminExpectation(query, sortOrder, limit))
		if err != nil {
			return identityaccess.Page{}, err
		}
		lastID = state.LastPosition["id"]
	}
	whereActor := "r.requester_user_id=$3"
	if queue {
		whereActor = "$3=''"
	}
	rows, err := r.exec.Query(ctx, `SELECT `+identityAccessRequestColumns+`,ARRAY(SELECT f.field_name::TEXT FROM identity_access_request_fields f WHERE f.request_id=r.request_id ORDER BY f.field_name) FROM identity_access_requests r WHERE r.event_id=$1 AND ($2='' OR r.status=$2) AND `+whereActor+` AND r.request_id>$4 ORDER BY r.request_id ASC LIMIT $5`, query.EventID, status, requester, lastID, limit+1)
	if err != nil {
		return identityaccess.Page{}, fmt.Errorf("postgres: list identity access requests: %w", err)
	}
	defer rows.Close()
	items := make([]identityaccess.Request, 0, limit)
	for rows.Next() {
		item, err := scanIdentityAccessRequestWithFields(rows)
		if err != nil {
			return identityaccess.Page{}, err
		}
		items = append(items, item)
	}
	if err := rows.Err(); err != nil {
		return identityaccess.Page{}, err
	}
	hasMore := len(items) > limit
	if hasMore {
		items = items[:limit]
	}
	page := identityaccess.Page{Items: items, HasMore: hasMore}
	if hasMore {
		now := time.Now().UTC()
		page.NextCursor, err = r.codec.Encode(adminpagination.State{ActorID: query.ActorID, ScopeKind: query.ScopeKind, EventID: query.EventID, ListKind: query.ListKind, Filters: query.Filters, Sort: sortOrder, LastPosition: map[string]string{"id": items[len(items)-1].ID}, IssuedAt: now, ExpiresAt: now.Add(10 * time.Minute), Limit: limit})
		if err != nil {
			return identityaccess.Page{}, err
		}
	}
	return page, nil
}

func identityAccessStatusFilter(filters map[string]string, queue bool) (string, error) {
	if len(filters) > 1 {
		return "", identityaccess.ErrInvalidRequest
	}
	for key := range filters {
		if key != "status" {
			return "", identityaccess.ErrInvalidRequest
		}
	}
	status := strings.TrimSpace(filters["status"])
	if queue && status == "" {
		status = string(identityaccess.StatusPending)
	}
	if status == "" {
		return "", nil
	}
	switch identityaccess.Status(status) {
	case identityaccess.StatusPending, identityaccess.StatusApproved, identityaccess.StatusRejected, identityaccess.StatusRevoked, identityaccess.StatusExpired:
		return status, nil
	default:
		return "", identityaccess.ErrInvalidRequest
	}
}

func (r *IdentityAccessRepository) Decide(ctx context.Context, eventID, requestID string, expectedVersion int64, decision identityaccess.Decision, approvedFields []identityaccess.Field, authorization identityaccess.GrantAuthorization, audit identityaccess.Audit) (identityaccess.DecisionOutcome, error) {
	if r.tx == nil {
		return identityaccess.DecisionOutcome{}, errors.New("postgres: identity access write requires unit of work")
	}
	request, err := scanIdentityAccessRequestWithFields(r.tx.QueryRow(ctx, identityAccessDecideLockSQL, requestID, eventID))
	if errors.Is(err, pgx.ErrNoRows) {
		return identityaccess.DecisionOutcome{}, identityaccess.ErrNotFound
	}
	if err != nil {
		return identityaccess.DecisionOutcome{}, err
	}
	now := decision.DecidedAt.UTC()
	if now.IsZero() {
		now = time.Now().UTC()
	}
	if request.Version != expectedVersion || request.Status != identityaccess.StatusPending || !now.Before(request.ExpiresAt) {
		return identityaccess.DecisionOutcome{}, identityaccess.ErrConflict
	}
	if err := identityaccess.ValidateDecision(request, decision); err != nil {
		return identityaccess.DecisionOutcome{}, err
	}
	if decision.Approved {
		if err := validateApprovedIdentityFields(approvedFields, request.Fields); err != nil {
			return identityaccess.DecisionOutcome{}, err
		}
		if authorization.RoleBindingID == "" || authorization.RoleBindingVersion <= 0 || authorization.ChallengeVersion <= 0 || authorization.FieldSetHash != hashIdentityFields(approvedFields) {
			return identityaccess.DecisionOutcome{}, identityaccess.ErrInvalidDecision
		}
	} else if len(approvedFields) != 0 {
		return identityaccess.DecisionOutcome{}, identityaccess.ErrInvalidDecision
	}
	status := identityaccess.StatusRejected
	if decision.Approved {
		status = identityaccess.StatusApproved
	}
	var nextVersion int64
	if err := r.tx.QueryRow(ctx, identityAccessDecideUpdateSQL, requestID, eventID, string(status), string(decision.ApproverID), now, expectedVersion).Scan(&nextVersion); errors.Is(err, pgx.ErrNoRows) {
		return identityaccess.DecisionOutcome{}, identityaccess.ErrConflict
	} else if err != nil {
		return identityaccess.DecisionOutcome{}, fmt.Errorf("postgres: decide identity access request: %w", err)
	}
	tag, err := r.tx.Exec(ctx, `UPDATE protected_operation_reasons SET consumed_at=$4,terminal_at=$4,expires_at=$4+INTERVAL '24 months' WHERE reason_id=$1 AND owner_user_id=$2 AND operation_kind=$3 AND consumed_at IS NULL AND terminal_at IS NULL`, request.ReasonID, string(request.RequesterID), "identity_access", now)
	if err != nil {
		return identityaccess.DecisionOutcome{}, fmt.Errorf("postgres: terminal protected reason: %w", err)
	}
	if tag.RowsAffected() != 1 {
		return identityaccess.DecisionOutcome{}, identityaccess.ErrConflict
	}
	if err := recordIdentityAccessMutation(ctx, r.tx, audit, "admin.identity_access.decided", eventID, "identity_access_request", requestID); err != nil {
		return identityaccess.DecisionOutcome{}, err
	}
	request.Status, request.ApproverID, request.Version, request.UpdatedAt, request.TerminalAt = status, decision.ApproverID, nextVersion, now, &now
	outcome := identityaccess.DecisionOutcome{Request: request}
	if !decision.Approved {
		return outcome, nil
	}
	grant := identityaccess.Grant{ID: newAdminID("iag_"), RequestID: request.ID, EventID: request.EventID, RequesterID: request.RequesterID, TargetSubject: request.TargetSubject, TargetType: request.TargetType, TargetID: request.TargetID, ApprovedBy: decision.ApproverID, Fields: append([]identityaccess.Field(nil), approvedFields...), Status: identityaccess.GrantActive, Authorization: authorization, ExpiresAt: now.Add(15 * time.Minute), Version: 1}
	_, err = r.tx.Exec(ctx, `INSERT INTO identity_access_grants(grant_id,request_id,event_id,requester_user_id,target_subject_user_id,target_type,target_id,approved_by_user_id,status,requester_role_binding_id,requester_role_binding_version,requester_challenge_version,field_set_hash,version,expires_at,created_at,updated_at) VALUES($1,$2,$3,$4,$5,$6,$7,$8,'active',$9,$10,$11,$12,1,$13,$14,$14)`, grant.ID, request.ID, request.EventID, string(request.RequesterID), string(request.TargetSubject), string(request.TargetType), request.TargetID, string(decision.ApproverID), authorization.RoleBindingID, authorization.RoleBindingVersion, authorization.ChallengeVersion, authorization.FieldSetHash, grant.ExpiresAt, now)
	if err != nil {
		return identityaccess.DecisionOutcome{}, fmt.Errorf("postgres: insert identity access grant: %w", err)
	}
	for _, field := range approvedFields {
		if _, err := r.tx.Exec(ctx, `INSERT INTO identity_access_grant_fields(grant_id,field_name) VALUES($1,$2)`, grant.ID, string(field)); err != nil {
			return identityaccess.DecisionOutcome{}, fmt.Errorf("postgres: insert identity access grant field: %w", err)
		}
	}
	outcome.Grant = &grant
	return outcome, nil
}

func (r *IdentityAccessRepository) Claim(ctx context.Context, eventID, grantID string, requester identity.UserID, expectedVersion int64, authorization identityaccess.AuthorizationEvidence, now time.Time, audit identityaccess.Audit) (identityaccess.Claim, error) {
	if r.tx == nil {
		return identityaccess.Claim{}, errors.New("postgres: identity access write requires unit of work")
	}
	nonce, digest, err := newIdentityClaimNonce()
	if err != nil {
		return identityaccess.Claim{}, err
	}
	var claim identityaccess.Claim
	var requestID, target, targetType, fieldSetHash string
	var fields []string
	err = r.tx.QueryRow(ctx, identityAccessClaimSQL, grantID, eventID, string(requester), digest, now, authorization.BindingID, authorization.BindingVersion, authorization.ChallengeVersion, expectedVersion).Scan(&claim.Version, &claim.LeaseExpiresAt, &requestID, &target, &targetType, &claim.TargetID, &fieldSetHash, &fields)
	if errors.Is(err, pgx.ErrNoRows) {
		return identityaccess.Claim{}, identityaccess.ErrConflict
	}
	if err != nil {
		return identityaccess.Claim{}, fmt.Errorf("postgres: claim identity access grant: %w", err)
	}
	claim.GrantID, claim.EventID, claim.RequesterID, claim.TargetSubject = grantID, eventID, requester, identity.UserID(target)
	claim.TargetType, claim.FieldSetHash, claim.ClaimNonce = identityaccess.TargetType(targetType), fieldSetHash, nonce
	claim.RoleBindingID, claim.RoleBindingVersion, claim.ChallengeVersion = authorization.BindingID, authorization.BindingVersion, authorization.ChallengeVersion
	claim.Fields = stringsToIdentityFields(fields)
	if claim.FieldSetHash != hashIdentityFields(claim.Fields) {
		return identityaccess.Claim{}, identityaccess.ErrConflict
	}
	if err := recordIdentityAccessMutation(ctx, r.tx, audit, "admin.identity_access.claimed", eventID, "identity_access_grant", grantID); err != nil {
		return identityaccess.Claim{}, err
	}
	_ = requestID
	return claim, nil
}

func (r *IdentityAccessRepository) Settle(ctx context.Context, eventID, grantID string, requester identity.UserID, expectedVersion int64, claimNonce, receiptHash string, authorization identityaccess.AuthorizationEvidence, now time.Time, audit identityaccess.Audit) (int64, error) {
	if r.tx == nil {
		return 0, errors.New("postgres: identity access write requires unit of work")
	}
	digest := sha256.Sum256([]byte(claimNonce))
	var version int64
	err := r.tx.QueryRow(ctx, identityAccessSettleSQL, grantID, eventID, string(requester), base64.RawURLEncoding.EncodeToString(digest[:]), expectedVersion, receiptHash, now, authorization.BindingID, authorization.BindingVersion, authorization.ChallengeVersion).Scan(&version)
	if errors.Is(err, pgx.ErrNoRows) {
		return 0, identityaccess.ErrConflict
	}
	if err != nil {
		return 0, fmt.Errorf("postgres: settle identity access grant: %w", err)
	}
	if err := recordIdentityAccessMutation(ctx, r.tx, audit, "admin.identity_access.settled", eventID, "identity_access_grant", grantID); err != nil {
		return 0, err
	}
	return version, nil
}

func (r *IdentityAccessRepository) ReleaseExpiredClaim(ctx context.Context, eventID, grantID string, expectedVersion int64, audit identityaccess.Audit) error {
	if r.tx == nil {
		return errors.New("postgres: identity access write requires unit of work")
	}
	tag, err := r.tx.Exec(ctx, identityAccessReleaseExpiredClaimSQL, grantID, eventID, expectedVersion)
	if err != nil {
		return err
	}
	if tag.RowsAffected() != 1 {
		return identityaccess.ErrConflict
	}
	return recordIdentityAccessMutation(ctx, r.tx, audit, "admin.identity_access.claim_released", eventID, "identity_access_grant", grantID)
}

func (r *IdentityAccessRepository) RevokeForUser(ctx context.Context, userID identity.UserID, audit identityaccess.Audit) error {
	if r.tx == nil {
		return errors.New("postgres: identity access write requires unit of work")
	}
	now := time.Now().UTC()
	if _, err := r.tx.Exec(ctx, `UPDATE identity_access_grants SET status='revoked',claim_nonce_hash=NULL,claim_lease_until=NULL,terminal_at=$2,updated_at=$2,version=version+1 WHERE requester_user_id=$1 AND terminal_at IS NULL`, string(userID), now); err != nil {
		return err
	}
	return recordIdentityAccessMutation(ctx, r.tx, audit, "admin.identity_access.revoked", "system", "identity_access_principal", string(userID))
}

func (r *IdentityAccessRepository) revokeForSecurityRotation(ctx context.Context, userID identity.UserID, now time.Time) error {
	if r.tx == nil {
		return errors.New("postgres: identity access write requires unit of work")
	}
	if _, err := r.tx.Exec(ctx, `UPDATE identity_access_requests SET status='revoked',terminal_at=$2,updated_at=$2,version=version+1 WHERE requester_user_id=$1 AND status='pending' AND terminal_at IS NULL`, string(userID), now); err != nil {
		return fmt.Errorf("postgres: revoke pending identity access requests for security rotation: %w", err)
	}
	if _, err := r.tx.Exec(ctx, `UPDATE identity_access_grants SET status='revoked',claim_nonce_hash=NULL,claim_lease_until=NULL,terminal_at=$2,updated_at=$2,version=version+1 WHERE requester_user_id=$1 AND terminal_at IS NULL`, string(userID), now); err != nil {
		return fmt.Errorf("postgres: revoke identity access grants for security rotation: %w", err)
	}
	return nil
}

func (r *IdentityAccessRepository) Revalidate(ctx context.Context, actor identity.UserID, eventID string, expected identityaccess.AuthorizationEvidence) error {
	if r.tx == nil || actor == "" || eventID == "" || expected.BindingID == "" || expected.BindingVersion <= 0 || expected.ChallengeVersion <= 0 {
		return identityaccess.ErrForbidden
	}
	if err := r.lockActiveIdentityActor(ctx, actor, eventID); err != nil {
		return err
	}
	scopeKind, scopeKey, roleEvent := string(adminroles.ScopeEvent), eventID, any(eventID)
	if expected.Role == adminroles.RoleSuperAdmin || expected.Role == adminroles.RoleTopAdmin {
		scopeKind, scopeKey, roleEvent = string(adminroles.ScopeSystem), "system", nil
	} else if expected.Role != adminroles.RoleSeniorAdmin {
		return identityaccess.ErrForbidden
	}
	var bindingID string
	err := r.tx.QueryRow(ctx, `SELECT binding_id FROM admin_role_bindings WHERE binding_id=$1 AND user_id=$2 AND role=$3 AND scope_kind=$4 AND scope_key=$5 AND event_id IS NOT DISTINCT FROM $6 AND enabled=TRUE AND disabled_at IS NULL AND version=$7 FOR UPDATE`, expected.BindingID, string(actor), string(expected.Role), scopeKind, scopeKey, roleEvent, expected.BindingVersion).Scan(&bindingID)
	if errors.Is(err, pgx.ErrNoRows) {
		return identityaccess.ErrForbidden
	}
	if err != nil {
		return fmt.Errorf("postgres: lock identity access binding: %w", err)
	}
	var challengeVersion int64
	err = r.tx.QueryRow(ctx, `SELECT credential_version FROM admin_challenges WHERE user_id=$1 AND status='active' AND must_rotate=FALSE AND credential_version=$2 FOR UPDATE`, string(actor), expected.ChallengeVersion).Scan(&challengeVersion)
	if errors.Is(err, pgx.ErrNoRows) {
		return identityaccess.ErrForbidden
	}
	if err != nil {
		return fmt.Errorf("postgres: lock identity access challenge: %w", err)
	}
	return nil
}

func (r *IdentityAccessRepository) CurrentGrantAuthorization(ctx context.Context, actor identity.UserID, eventID string) (identityaccess.AuthorizationEvidence, error) {
	if r.tx == nil || actor == "" || eventID == "" {
		return identityaccess.AuthorizationEvidence{}, identityaccess.ErrForbidden
	}
	if err := r.lockActiveIdentityActor(ctx, actor, eventID); err != nil {
		return identityaccess.AuthorizationEvidence{}, err
	}
	var result identityaccess.AuthorizationEvidence
	result.Role = adminroles.RoleSeniorAdmin
	err := r.tx.QueryRow(ctx, `SELECT binding_id,version FROM admin_role_bindings WHERE user_id=$1 AND role='senior_admin' AND scope_kind='event' AND scope_key=$2 AND event_id=$2 AND enabled=TRUE AND disabled_at IS NULL FOR UPDATE`, string(actor), eventID).Scan(&result.BindingID, &result.BindingVersion)
	if errors.Is(err, pgx.ErrNoRows) {
		return identityaccess.AuthorizationEvidence{}, identityaccess.ErrForbidden
	}
	if err != nil {
		return identityaccess.AuthorizationEvidence{}, fmt.Errorf("postgres: lock grant requester binding: %w", err)
	}
	err = r.tx.QueryRow(ctx, `SELECT credential_version FROM admin_challenges WHERE user_id=$1 AND status='active' AND must_rotate=FALSE FOR UPDATE`, string(actor)).Scan(&result.ChallengeVersion)
	if errors.Is(err, pgx.ErrNoRows) {
		return identityaccess.AuthorizationEvidence{}, identityaccess.ErrForbidden
	}
	if err != nil {
		return identityaccess.AuthorizationEvidence{}, fmt.Errorf("postgres: lock grant requester challenge: %w", err)
	}
	if result.BindingID == "" || result.BindingVersion <= 0 || result.ChallengeVersion <= 0 {
		return identityaccess.AuthorizationEvidence{}, identityaccess.ErrForbidden
	}
	return result, nil
}

func (r *IdentityAccessRepository) lockActiveIdentityActor(ctx context.Context, actor identity.UserID, eventID string) error {
	var eventEnabled bool
	if err := r.tx.QueryRow(ctx, `SELECT enabled FROM dreamup_event_registry WHERE event_id=$1 FOR UPDATE`, eventID).Scan(&eventEnabled); err != nil || !eventEnabled {
		if err != nil && !errors.Is(err, pgx.ErrNoRows) {
			return fmt.Errorf("postgres: lock identity access event: %w", err)
		}
		return identityaccess.ErrForbidden
	}
	var accountStatus string
	if err := r.tx.QueryRow(ctx, `SELECT status FROM users WHERE id=$1 FOR UPDATE`, string(actor)).Scan(&accountStatus); err != nil || accountStatus != string(identity.UserStatusActive) {
		if err != nil && !errors.Is(err, pgx.ErrNoRows) {
			return fmt.Errorf("postgres: lock identity access actor: %w", err)
		}
		return identityaccess.ErrForbidden
	}
	var employeeStatus string
	err := r.tx.QueryRow(ctx, `SELECT status FROM employee_profiles WHERE user_id=$1 FOR UPDATE`, string(actor)).Scan(&employeeStatus)
	if err != nil && !errors.Is(err, pgx.ErrNoRows) {
		return fmt.Errorf("postgres: lock identity access employee: %w", err)
	}
	if err == nil && employeeStatus != "active" {
		return identityaccess.ErrForbidden
	}
	return nil
}

func validateApprovedIdentityFields(approved, requested []identityaccess.Field) error {
	if len(approved) == 0 || len(approved) > len(requested) {
		return identityaccess.ErrInvalidDecision
	}
	allowed := make(map[identityaccess.Field]bool, len(requested))
	for _, field := range requested {
		allowed[field] = true
	}
	seen := map[identityaccess.Field]bool{}
	for _, field := range approved {
		if !allowed[field] || seen[field] {
			return identityaccess.ErrInvalidDecision
		}
		seen[field] = true
	}
	return nil
}

func hashIdentityFields(fields []identityaccess.Field) string {
	values := make([]string, len(fields))
	for i, field := range fields {
		values[i] = string(field)
	}
	sort.Strings(values)
	digest := sha256.Sum256([]byte(strings.Join(values, "\x00")))
	return base64.RawURLEncoding.EncodeToString(digest[:])
}

func stringsToIdentityFields(fields []string) []identityaccess.Field {
	result := make([]identityaccess.Field, len(fields))
	for i, field := range fields {
		result[i] = identityaccess.Field(field)
	}
	return result
}

func newIdentityClaimNonce() (string, string, error) {
	raw := make([]byte, 32)
	if _, err := rand.Read(raw); err != nil {
		return "", "", fmt.Errorf("postgres: generate claim nonce: %w", err)
	}
	nonce := base64.RawURLEncoding.EncodeToString(raw)
	digest := sha256.Sum256([]byte(nonce))
	return nonce, base64.RawURLEncoding.EncodeToString(digest[:]), nil
}

func recordIdentityAccessMutation(ctx context.Context, tx pgx.Tx, audit identityaccess.Audit, eventType, eventID, targetKind, targetID string) error {
	if audit.ActorID == "" || audit.RequestID == "" || audit.Action == "" || eventID == "" || targetID == "" {
		return errors.New("postgres: incomplete identity access audit")
	}
	return insertSecurityEvent(ctx, tx, applications.SecurityEvent{EventID: applications.NewSecurityEventID(), EventType: eventType, ActorUserID: audit.ActorID, RequestID: audit.RequestID, Operation: audit.Action, Result: applications.SecurityEventSuccess, TargetKey: targetKind + "_id", TargetID: targetID, Extra: map[string]string{"dreamup_event_id": eventID}, OccurredAt: time.Now().UTC()})
}

func scanIdentityAccessRequestWithFields(row pgx.Row) (identityaccess.Request, error) {
	var request identityaccess.Request
	var requester, target, targetType, status string
	var approver *string
	var fields []string
	err := row.Scan(&request.ID, &request.EventID, &requester, &target, &approver, &targetType, &request.TargetID, &status, &request.ReasonID, &request.Version, &request.CreatedAt, &request.UpdatedAt, &request.ExpiresAt, &request.TerminalAt, &fields)
	request.RequesterID, request.TargetSubject = identity.UserID(requester), identity.UserID(target)
	if approver != nil {
		request.ApproverID = identity.UserID(*approver)
	}
	request.TargetType, request.Status = identityaccess.TargetType(targetType), identityaccess.Status(status)
	request.Fields = stringsToIdentityFields(fields)
	return request, err
}

func prepareIdentityAccessTimestamps(request *identityaccess.Request, reason *identityaccess.ProtectedReason, now time.Time) {
	if request.CreatedAt.IsZero() {
		request.CreatedAt = now
	}
	if request.UpdatedAt.IsZero() {
		request.UpdatedAt = request.CreatedAt
	}
	if reason.CreatedAt.IsZero() {
		reason.CreatedAt = request.CreatedAt
	}
}

func newAdminID(prefix string) string {
	raw := make([]byte, 16)
	if _, err := rand.Read(raw); err != nil {
		panic("postgres: secure random unavailable")
	}
	return prefix + base64.RawURLEncoding.EncodeToString(raw)
}
