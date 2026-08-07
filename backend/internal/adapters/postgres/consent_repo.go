package postgres

import (
	"context"
	"errors"
	"fmt"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/GravelEvolution/united-pass/backend/internal/applications"
	"github.com/GravelEvolution/united-pass/backend/internal/consent"
	"github.com/GravelEvolution/united-pass/backend/internal/identity"
)

// GrantRepository persists consent decision operations and authorization
// grants (ADR-0005 §2, §4, §5). It implements consent.GrantStore. The
// provider call never runs inside a repository transaction: callers follow
// the §5 ordering (claim with the immutable completion plan → provider
// call → proof → commit).
type GrantRepository struct {
	pool *pgxpool.Pool
}

// NewGrantRepository builds the consent grant repository.
func NewGrantRepository(pool *pgxpool.Pool) *GrantRepository {
	return &GrantRepository{pool: pool}
}

// Compile-time proof that the repository satisfies the domain ports.
var (
	_ consent.GrantStore                 = (*GrantRepository)(nil)
	_ consent.InFlightDecisionOperations = (*GrantRepository)(nil)
)

const decisionOperationColumns = `operation_id, provider, provider_tenant_id,
        auth_request_id, completion_kind, status, local_user_id, client_id,
        error_class, provider_succeeded_at, created_at, updated_at`

// ClaimDecisionOperation claims the global single-winner row for the
// operation's auth-request key, persisting the full immutable completion
// plan — kind, bound user, bound client and the scope snapshot — in one
// atomic statement (ADR-0005 §5). The INSERT ... ON CONFLICT DO NOTHING
// makes the claim atomic; the winner receives the row exactly as stored
// (status and timestamps read back from the database), and the losing
// side reads the existing row and receives consent.ErrDecisionConflict
// without ever reaching the provider.
func (r *GrantRepository) ClaimDecisionOperation(ctx context.Context, op consent.DecisionOperation) (consent.DecisionOperation, bool, error) {
	if err := op.ValidateForClaim(); err != nil {
		return consent.DecisionOperation{}, false, err
	}
	// The domain owns scope canonicalization; the persisted snapshot is the
	// normalized set, and provider calls must consume that same result.
	scopes, err := consent.NormalizeScopes(op.Scopes)
	if err != nil {
		return consent.DecisionOperation{}, false, err
	}

	key := consent.DecisionOperationKey{
		Provider:         op.Provider,
		ProviderTenantID: op.ProviderTenantID,
		AuthRequestID:    op.AuthRequestID,
	}

	// Single statement: the plan row and its scope snapshot commit
	// together, or nothing does. The row is read back from the INSERT's
	// RETURNING output — the primary SELECT cannot see the CTE's inserted
	// row through its own snapshot; on the conflict path the RETURNING
	// output is empty and the winner is read back below.
	row := r.pool.QueryRow(ctx,
		`WITH ins AS (
		     INSERT INTO oauth_authorization_decision_operations
		         (operation_id, provider, provider_tenant_id, auth_request_id,
		          completion_kind, status, local_user_id, client_id)
		     VALUES ($1, $2, $3, $4, $5, 'pending', $6, $7)
		     ON CONFLICT (provider, provider_tenant_id, auth_request_id) DO NOTHING
		     RETURNING `+decisionOperationColumns+`
		 ), scope_ins AS (
		     INSERT INTO oauth_authorization_decision_operation_scopes
		         (operation_id, scope)
		     SELECT ins.operation_id, s.scope
		       FROM ins, UNNEST($8::text[]) AS s(scope)
		 )
		 SELECT `+decisionOperationColumns+`
		   FROM ins`,
		string(op.ID), op.Provider, op.ProviderTenantID, op.AuthRequestID,
		string(op.CompletionKind), string(op.LocalUserID), string(op.ClientID),
		scopes)

	stored, err := scanDecisionOperation(row.Scan)
	switch {
	case err == nil:
		stored.Scopes = append([]string(nil), scopes...)
		return stored, true, nil
	case !errors.Is(err, consent.ErrDecisionNotFound):
		return consent.DecisionOperation{}, false, err
	}

	existing, err := r.GetDecisionOperation(ctx, key)
	if err != nil {
		return consent.DecisionOperation{}, false, err
	}
	return existing, false, consent.ErrDecisionConflict
}

// GetDecisionOperation reads the operation row (including its immutable
// scope snapshot) by its global key.
func (r *GrantRepository) GetDecisionOperation(ctx context.Context, key consent.DecisionOperationKey) (consent.DecisionOperation, error) {
	if err := key.Validate(); err != nil {
		return consent.DecisionOperation{}, err
	}
	row := r.pool.QueryRow(ctx,
		`SELECT `+decisionOperationColumns+`
		   FROM oauth_authorization_decision_operations
		  WHERE provider = $1 AND provider_tenant_id = $2 AND auth_request_id = $3`,
		key.Provider, key.ProviderTenantID, key.AuthRequestID)
	op, err := scanDecisionOperation(row.Scan)
	if err != nil {
		return consent.DecisionOperation{}, err
	}
	scopes, err := readDecisionOperationScopes(ctx, r.pool, op.ID)
	if err != nil {
		return consent.DecisionOperation{}, err
	}
	op.Scopes = scopes
	return op, nil
}

// RecordProviderSucceeded persists the provider success proof via a
// pending → provider_succeeded compare-and-set (ADR-0005 §5 step 4). The
// completion kind is already bound on the row from claim time; the proof
// records the time only — never the callback URL.
func (r *GrantRepository) RecordProviderSucceeded(ctx context.Context, opID consent.DecisionOperationID, at time.Time) error {
	tag, err := r.pool.Exec(ctx,
		`UPDATE oauth_authorization_decision_operations
		    SET status = 'provider_succeeded', provider_succeeded_at = $2, updated_at = NOW()
		  WHERE operation_id = $1 AND status = 'pending'`,
		string(opID), at)
	if err != nil {
		return fmt.Errorf("postgres: record provider success proof: %w", err)
	}
	if tag.RowsAffected() != 1 {
		return consent.ErrDecisionStateConflict
	}
	return nil
}

// CommitAllowDecision runs the Allow-side local commit in one transaction
// (ADR-0005 §5 step 5). The operation is locked and verified against its
// bound plan, and the grant is written exclusively from the plan values
// read back from the operation row — the commit input carries no user,
// client or scope facts of its own, so the local state can never drift
// from what the provider completed. The single canonical audit event is
// constructed from the same locked row. Any failure rolls everything back:
// an operation whose grant or audit could not be persisted keeps its proof
// for forward reconciliation (§4).
func (r *GrantRepository) CommitAllowDecision(ctx context.Context, commit consent.AllowCommit) error {
	tx, err := r.pool.Begin(ctx)
	if err != nil {
		return fmt.Errorf("postgres: begin commit allow tx: %w", err)
	}
	defer func() { _ = tx.Rollback(ctx) }()

	op, err := lockDecisionOperationTx(ctx, tx, commit.OperationID)
	if err != nil {
		return err
	}
	if op.Status != consent.DecisionOperationProviderSucceeded ||
		op.CompletionKind != consent.CompletionAllow ||
		op.LocalUserID == "" || op.ClientID == "" || len(op.Scopes) == 0 {
		return consent.ErrDecisionStateConflict
	}
	// Second canonicalization check: the claim-time snapshot is already
	// normalized, but the persisted row is re-verified against the single
	// canonicalization boundary so out-of-band corruption (duplicate,
	// empty, whitespace, oversize or unsorted tokens) fails closed here
	// instead of completing an inconsistent grant (ADR-0005 §4, §5).
	if !consent.ScopesAreCanonical(op.Scopes) {
		return consent.ErrDecisionStateConflict
	}

	grantID, err := upsertGrantTx(ctx, tx, op.LocalUserID, op.ClientID)
	if err != nil {
		return err
	}
	if err := replaceGrantScopesTx(ctx, tx, grantID, op.Scopes); err != nil {
		return err
	}
	if err := insertSecurityEvent(ctx, tx, canonicalCompletionAudit(op)); err != nil {
		return err
	}
	if err := terminalizeDecisionTx(ctx, tx, commit.OperationID); err != nil {
		return err
	}
	if err := tx.Commit(ctx); err != nil {
		return fmt.Errorf("postgres: commit allow decision: %w", err)
	}
	return nil
}

// CommitDenyDecision runs the Deny-side local commit in one transaction:
// the locked operation must carry the proof, the access_denied kind and a
// complete binding (non-empty user — corrupted or legacy rows fail
// closed); the canonical audit + terminal transition commit. Deny creates
// no grant row (ADR-0005 §5).
func (r *GrantRepository) CommitDenyDecision(ctx context.Context, commit consent.DenyCommit) error {
	tx, err := r.pool.Begin(ctx)
	if err != nil {
		return fmt.Errorf("postgres: begin commit deny tx: %w", err)
	}
	defer func() { _ = tx.Rollback(ctx) }()

	op, err := lockDecisionOperationTx(ctx, tx, commit.OperationID)
	if err != nil {
		return err
	}
	if op.Status != consent.DecisionOperationProviderSucceeded ||
		op.CompletionKind != consent.CompletionAccessDenied ||
		op.LocalUserID == "" || len(op.Scopes) != 0 {
		return consent.ErrDecisionStateConflict
	}
	if err := insertSecurityEvent(ctx, tx, canonicalCompletionAudit(op)); err != nil {
		return err
	}
	if err := terminalizeDecisionTx(ctx, tx, commit.OperationID); err != nil {
		return err
	}
	if err := tx.Commit(ctx); err != nil {
		return fmt.Errorf("postgres: commit deny decision: %w", err)
	}
	return nil
}

// CommitErrorCompletion terminates an error-callback completion
// (login_required, consent_required, account_selection_required,
// request_not_supported, server_error, temporarily_unavailable): the
// locked operation must carry the proof, a known non-decision kind and no
// scope snapshot (the per-kind binding rule; corrupted rows fail closed).
// No grant is ever involved.
func (r *GrantRepository) CommitErrorCompletion(ctx context.Context, commit consent.ErrorCompletionCommit) error {
	tx, err := r.pool.Begin(ctx)
	if err != nil {
		return fmt.Errorf("postgres: begin commit error completion tx: %w", err)
	}
	defer func() { _ = tx.Rollback(ctx) }()

	op, err := lockDecisionOperationTx(ctx, tx, commit.OperationID)
	if err != nil {
		return err
	}
	if op.Status != consent.DecisionOperationProviderSucceeded ||
		!op.CompletionKind.Valid() || op.CompletionKind.IsUserDecision() ||
		len(op.Scopes) != 0 {
		return consent.ErrDecisionStateConflict
	}
	if err := insertSecurityEvent(ctx, tx, canonicalCompletionAudit(op)); err != nil {
		return err
	}
	if err := terminalizeDecisionTx(ctx, tx, commit.OperationID); err != nil {
		return err
	}
	if err := tx.Commit(ctx); err != nil {
		return fmt.Errorf("postgres: commit error completion: %w", err)
	}
	return nil
}

// canonicalCompletionAudit builds the ONE audit event of a terminal
// commit entirely from the locked operation row: actor and client come
// from the bound plan, event type / operation / result from the
// completion kind. The request_id column correlates the event with the
// decision operation — reconciled commits have no HTTP request context.
// Nothing here is ever taken from the commit caller.
func canonicalCompletionAudit(op consent.DecisionOperation) applications.SecurityEvent {
	return applications.SecurityEvent{
		EventID:      applications.NewSecurityEventID(),
		EventType:    op.CompletionKind.AuditEventType(),
		ActorUserID:  op.LocalUserID,
		ClientID:     op.ClientID,
		RequestID:    string(op.ID),
		Operation:    op.CompletionKind.AuditOperation(),
		Result:       op.CompletionKind.AuditResult(),
		FailureClass: op.CompletionKind.AuditFailureClass(),
		OccurredAt:   time.Now().UTC(),
	}
}

// FailDecisionOperation terminates a still-pending operation without
// provider success proof (fail-closed, ADR-0005 §4). Rows that already
// carry the proof must be repaired forward by reconciliation instead.
// Only known stable error classes are accepted.
func (r *GrantRepository) FailDecisionOperation(ctx context.Context, opID consent.DecisionOperationID, class consent.ErrorClass) error {
	if !class.Valid() {
		return fmt.Errorf("postgres: unknown error class %q", class)
	}
	tag, err := r.pool.Exec(ctx,
		`UPDATE oauth_authorization_decision_operations
		    SET status = 'failed', error_class = $2, updated_at = NOW()
		  WHERE operation_id = $1 AND status = 'pending'`,
		string(opID), string(class))
	if err != nil {
		return fmt.Errorf("postgres: fail decision operation: %w", err)
	}
	if tag.RowsAffected() != 1 {
		return consent.ErrDecisionStateConflict
	}
	return nil
}

// ListInFlightDecisionOperations enumerates the operations needing
// reconciliation attention (ADR-0005 §4): every provider_succeeded row
// (forward-repair candidate) plus pending rows claimed before the
// staleness horizon (fail-closed candidate), oldest first and capped at
// limit. The scope snapshot is deliberately not read here: commits and
// repairs carry only the operation ID and re-lock the full plan
// themselves, so this stays one index-friendly scan.
func (r *GrantRepository) ListInFlightDecisionOperations(ctx context.Context, staleBefore time.Time, limit int) ([]consent.DecisionOperation, error) {
	if limit <= 0 {
		limit = 100
	}
	rows, err := r.pool.Query(ctx,
		`SELECT `+decisionOperationColumns+`
		   FROM oauth_authorization_decision_operations
		  WHERE status = 'provider_succeeded'
		     OR (status = 'pending' AND created_at < $1)
		  ORDER BY created_at ASC
		  LIMIT $2`,
		staleBefore, limit)
	if err != nil {
		return nil, fmt.Errorf("postgres: list in-flight decision operations: %w", err)
	}
	defer rows.Close()
	ops := make([]consent.DecisionOperation, 0)
	for rows.Next() {
		op, err := scanDecisionOperation(rows.Scan)
		if err != nil {
			return nil, err
		}
		ops = append(ops, op)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("postgres: iterate in-flight decision operations: %w", err)
	}
	return ops, nil
}

// GetGrant reads the (user, client) grant with its consented scopes.
func (r *GrantRepository) GetGrant(ctx context.Context, userID identity.UserID, clientID applications.OAuthClientID) (consent.Grant, error) {
	row := r.pool.QueryRow(ctx,
		`SELECT grant_id, user_id, client_id, status, granted_at, revoked_at, updated_at
		   FROM oauth_authorization_grants
		  WHERE user_id = $1 AND client_id = $2`,
		string(userID), string(clientID))

	var grant consent.Grant
	var grantID, uid, cid, status string
	var revokedAt *time.Time
	if err := row.Scan(&grantID, &uid, &cid, &status, &grant.GrantedAt, &revokedAt, &grant.UpdatedAt); err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return consent.Grant{}, consent.ErrGrantNotFound
		}
		return consent.Grant{}, fmt.Errorf("postgres: read grant: %w", err)
	}
	grant.ID = consent.GrantID(grantID)
	grant.UserID = identity.UserID(uid)
	grant.ClientID = applications.OAuthClientID(cid)
	grant.Status = consent.GrantStatus(status)
	if revokedAt != nil {
		grant.RevokedAt = *revokedAt
	}

	scopes, err := readGrantScopes(ctx, r.pool, grant.ID)
	if err != nil {
		return consent.Grant{}, err
	}
	grant.Scopes = scopes
	return grant, nil
}

// lockDecisionOperationTx locks one operation row for the enclosing
// commit transaction and returns it with its scope snapshot. Locking
// serializes concurrent commits of the same operation; the caller then
// verifies the plan before writing any local state.
func lockDecisionOperationTx(ctx context.Context, tx pgx.Tx, opID consent.DecisionOperationID) (consent.DecisionOperation, error) {
	if !consent.HasDecisionOperationIDPrefix(string(opID)) {
		return consent.DecisionOperation{}, consent.ErrDecisionNotFound
	}
	row := tx.QueryRow(ctx,
		`SELECT `+decisionOperationColumns+`
		   FROM oauth_authorization_decision_operations
		  WHERE operation_id = $1 FOR UPDATE`,
		string(opID))
	op, err := scanDecisionOperation(row.Scan)
	if err != nil {
		return consent.DecisionOperation{}, err
	}
	scopes, err := readDecisionOperationScopes(ctx, tx, op.ID)
	if err != nil {
		return consent.DecisionOperation{}, err
	}
	op.Scopes = scopes
	return op, nil
}

// upsertGrantTx inserts or reactivates the (user, client) grant row and
// returns its ID. A re-consent after revocation reuses the same row,
// refreshes granted_at and clears revoked_at; the unique key makes
// duplicate grants impossible (ADR-0005 §4, §7).
func upsertGrantTx(ctx context.Context, tx pgx.Tx, userID identity.UserID, clientID applications.OAuthClientID) (consent.GrantID, error) {
	grantID := consent.NewGrantID()
	var existingID string
	err := tx.QueryRow(ctx,
		`INSERT INTO oauth_authorization_grants
		     (grant_id, user_id, client_id, status, granted_at, revoked_at, updated_at)
		 VALUES ($1, $2, $3, 'active', NOW(), NULL, NOW())
		 ON CONFLICT (user_id, client_id) DO UPDATE
		    SET status = 'active', granted_at = NOW(), revoked_at = NULL, updated_at = NOW()
		RETURNING grant_id`,
		string(grantID), string(userID), string(clientID)).Scan(&existingID)
	if err != nil {
		return "", fmt.Errorf("postgres: upsert grant: %w", err)
	}
	return consent.GrantID(existingID), nil
}

// replaceGrantScopesTx replaces the consented scope set of a grant.
func replaceGrantScopesTx(ctx context.Context, tx pgx.Tx, grantID consent.GrantID, scopes []string) error {
	if _, err := tx.Exec(ctx,
		`DELETE FROM oauth_authorization_grant_scopes WHERE grant_id = $1`,
		string(grantID)); err != nil {
		return fmt.Errorf("postgres: clear grant scopes: %w", err)
	}
	for _, scope := range scopes {
		if _, err := tx.Exec(ctx,
			`INSERT INTO oauth_authorization_grant_scopes (grant_id, scope)
			 VALUES ($1, $2)
			 ON CONFLICT (grant_id, scope) DO NOTHING`,
			string(grantID), scope); err != nil {
			return fmt.Errorf("postgres: insert grant scope: %w", err)
		}
	}
	return nil
}

// terminalizeDecisionTx runs the provider_succeeded → succeeded
// compare-and-set. The enclosing transaction already holds the row lock
// and has verified the completion plan; the status CAS remains as the
// mechanical last line of defense.
func terminalizeDecisionTx(ctx context.Context, tx pgx.Tx, opID consent.DecisionOperationID) error {
	tag, err := tx.Exec(ctx,
		`UPDATE oauth_authorization_decision_operations
		    SET status = 'succeeded', updated_at = NOW()
		  WHERE operation_id = $1 AND status = 'provider_succeeded'`,
		string(opID))
	if err != nil {
		return fmt.Errorf("postgres: terminalize decision operation: %w", err)
	}
	if tag.RowsAffected() != 1 {
		return consent.ErrDecisionStateConflict
	}
	return nil
}

type decisionRowScan func(dest ...any) error

// scanDecisionOperation maps one operation row from any scanner.
func scanDecisionOperation(scan decisionRowScan) (consent.DecisionOperation, error) {
	var (
		op                                consent.DecisionOperation
		operationID, kind, status, userID string
		clientID, errorClass              string
		providerSucceededAt               *time.Time
	)
	if err := scan(&operationID, &op.Provider, &op.ProviderTenantID, &op.AuthRequestID,
		&kind, &status, &userID, &clientID, &errorClass,
		&providerSucceededAt, &op.CreatedAt, &op.UpdatedAt); err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return consent.DecisionOperation{}, consent.ErrDecisionNotFound
		}
		return consent.DecisionOperation{}, fmt.Errorf("postgres: read decision operation: %w", err)
	}
	op.ID = consent.DecisionOperationID(operationID)
	op.CompletionKind = consent.CompletionKind(kind)
	op.Status = consent.DecisionOperationStatus(status)
	op.LocalUserID = identity.UserID(userID)
	op.ClientID = applications.OAuthClientID(clientID)
	op.ErrorClass = consent.ErrorClass(errorClass)
	if providerSucceededAt != nil {
		op.ProviderSucceededAt = *providerSucceededAt
	}
	return op, nil
}

type consentQuerier interface {
	Query(ctx context.Context, sql string, args ...any) (pgx.Rows, error)
}

// readDecisionOperationScopes reads the immutable scope snapshot of a
// completion plan.
func readDecisionOperationScopes(ctx context.Context, q consentQuerier, opID consent.DecisionOperationID) ([]string, error) {
	rows, err := q.Query(ctx,
		`SELECT scope FROM oauth_authorization_decision_operation_scopes
		  WHERE operation_id = $1 ORDER BY scope`,
		string(opID))
	if err != nil {
		return nil, fmt.Errorf("postgres: read decision operation scopes: %w", err)
	}
	defer rows.Close()
	return collectScopes(rows)
}

// readGrantScopes reads the consented scope set of a grant.
func readGrantScopes(ctx context.Context, q consentQuerier, grantID consent.GrantID) ([]string, error) {
	rows, err := q.Query(ctx,
		`SELECT scope FROM oauth_authorization_grant_scopes
		  WHERE grant_id = $1 ORDER BY scope`,
		string(grantID))
	if err != nil {
		return nil, fmt.Errorf("postgres: read grant scopes: %w", err)
	}
	defer rows.Close()
	return collectScopes(rows)
}

func collectScopes(rows pgx.Rows) ([]string, error) {
	scopes := make([]string, 0)
	for rows.Next() {
		var scope string
		if err := rows.Scan(&scope); err != nil {
			return nil, fmt.Errorf("postgres: scan scope row: %w", err)
		}
		scopes = append(scopes, scope)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("postgres: iterate scope rows: %w", err)
	}
	return scopes, nil
}
