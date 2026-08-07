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
// the §5 ordering (claim → provider call → proof → commit).
type GrantRepository struct {
	pool *pgxpool.Pool
}

// NewGrantRepository builds the consent grant repository.
func NewGrantRepository(pool *pgxpool.Pool) *GrantRepository {
	return &GrantRepository{pool: pool}
}

// Compile-time proof that the repository satisfies the domain port.
var _ consent.GrantStore = (*GrantRepository)(nil)

// ClaimDecisionOperation claims the global single-winner row for the
// operation's auth-request key (ADR-0005 §5). The INSERT ... ON CONFLICT
// DO NOTHING makes the claim atomic; the losing side reads the existing
// row and receives consent.ErrDecisionConflict without ever reaching the
// provider.
func (r *GrantRepository) ClaimDecisionOperation(ctx context.Context, op consent.DecisionOperation) (consent.DecisionOperation, bool, error) {
	if !op.Decision.Valid() {
		return consent.DecisionOperation{}, false, fmt.Errorf("postgres: invalid decision %q", op.Decision)
	}
	if err := (consent.DecisionOperationKey{
		Provider:         op.Provider,
		ProviderTenantID: op.ProviderTenantID,
		AuthRequestID:    op.AuthRequestID,
	}).Validate(); err != nil {
		return consent.DecisionOperation{}, false, err
	}

	tag, err := r.pool.Exec(ctx,
		`INSERT INTO oauth_authorization_decision_operations
		     (operation_id, provider, provider_tenant_id, auth_request_id, decision, status, client_id)
		 VALUES ($1, $2, $3, $4, $5, 'pending', $6)
		 ON CONFLICT (provider, provider_tenant_id, auth_request_id) DO NOTHING`,
		string(op.ID), op.Provider, op.ProviderTenantID, op.AuthRequestID,
		string(op.Decision), string(op.ClientID))
	if err != nil {
		return consent.DecisionOperation{}, false, fmt.Errorf("postgres: claim decision operation: %w", err)
	}
	if tag.RowsAffected() == 1 {
		return op, true, nil
	}

	existing, err := r.GetDecisionOperation(ctx, consent.DecisionOperationKey{
		Provider:         op.Provider,
		ProviderTenantID: op.ProviderTenantID,
		AuthRequestID:    op.AuthRequestID,
	})
	if err != nil {
		return consent.DecisionOperation{}, false, err
	}
	return existing, false, consent.ErrDecisionConflict
}

// GetDecisionOperation reads the operation row by its global key.
func (r *GrantRepository) GetDecisionOperation(ctx context.Context, key consent.DecisionOperationKey) (consent.DecisionOperation, error) {
	if err := key.Validate(); err != nil {
		return consent.DecisionOperation{}, err
	}
	row := r.pool.QueryRow(ctx,
		`SELECT operation_id, provider, provider_tenant_id, auth_request_id,
		        decision, status, local_user_id, client_id, error_class,
		        provider_succeeded_at, created_at, updated_at
		   FROM oauth_authorization_decision_operations
		  WHERE provider = $1 AND provider_tenant_id = $2 AND auth_request_id = $3`,
		key.Provider, key.ProviderTenantID, key.AuthRequestID)
	return scanDecisionOperation(row.Scan)
}

// RecordProviderSucceeded persists the provider success proof via a
// pending → provider_succeeded compare-and-set (ADR-0005 §5 step 4). The
// proof records the decision kind (already on the row) and the time; it
// never stores the callback URL.
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
// (ADR-0005 §5 step 5): grant upsert + scope-set replacement + audit +
// the provider_succeeded → succeeded terminal transition with the winner
// user binding. Any failure rolls everything back: an operation whose
// grant or audit could not be persisted keeps its proof for forward
// reconciliation (§4).
func (r *GrantRepository) CommitAllowDecision(ctx context.Context, commit consent.AllowCommit) error {
	tx, err := r.pool.Begin(ctx)
	if err != nil {
		return fmt.Errorf("postgres: begin commit allow tx: %w", err)
	}
	defer func() { _ = tx.Rollback(ctx) }()

	grantID, err := upsertGrantTx(ctx, tx, commit.UserID, commit.ClientID)
	if err != nil {
		return err
	}
	if err := replaceGrantScopesTx(ctx, tx, grantID, commit.Scopes); err != nil {
		return err
	}
	if err := terminalizeDecisionTx(ctx, tx, commit.OperationID, commit.UserID); err != nil {
		return err
	}
	if err := insertSecurityEventsTx(ctx, tx, commit.Audit); err != nil {
		return err
	}
	if err := tx.Commit(ctx); err != nil {
		return fmt.Errorf("postgres: commit allow decision: %w", err)
	}
	return nil
}

// CommitDenyDecision runs the Deny-side local commit in one transaction:
// audit + terminal transition with the winner binding. Deny creates no
// grant row (ADR-0005 §5).
func (r *GrantRepository) CommitDenyDecision(ctx context.Context, commit consent.DenyCommit) error {
	tx, err := r.pool.Begin(ctx)
	if err != nil {
		return fmt.Errorf("postgres: begin commit deny tx: %w", err)
	}
	defer func() { _ = tx.Rollback(ctx) }()

	if err := terminalizeDecisionTx(ctx, tx, commit.OperationID, commit.UserID); err != nil {
		return err
	}
	if err := insertSecurityEventsTx(ctx, tx, commit.Audit); err != nil {
		return err
	}
	if err := tx.Commit(ctx); err != nil {
		return fmt.Errorf("postgres: commit deny decision: %w", err)
	}
	return nil
}

// FailDecisionOperation terminates a still-pending operation without
// provider success proof (fail-closed, ADR-0005 §4). Rows that already
// carry the proof must be repaired forward by reconciliation instead.
func (r *GrantRepository) FailDecisionOperation(ctx context.Context, opID consent.DecisionOperationID, class consent.ErrorClass) error {
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
// compare-and-set and writes the winner user binding. Committing without
// the proof is a state conflict: the §5 ordering requires the proof row
// before the local commit.
func terminalizeDecisionTx(ctx context.Context, tx pgx.Tx, opID consent.DecisionOperationID, userID identity.UserID) error {
	tag, err := tx.Exec(ctx,
		`UPDATE oauth_authorization_decision_operations
		    SET status = 'succeeded', local_user_id = $2, updated_at = NOW()
		  WHERE operation_id = $1 AND status = 'provider_succeeded'`,
		string(opID), string(userID))
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
		op                                    consent.DecisionOperation
		operationID, decision, status, userID string
		clientID, errorClass                  string
		providerSucceededAt                   *time.Time
	)
	if err := scan(&operationID, &op.Provider, &op.ProviderTenantID, &op.AuthRequestID,
		&decision, &status, &userID, &clientID, &errorClass,
		&providerSucceededAt, &op.CreatedAt, &op.UpdatedAt); err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return consent.DecisionOperation{}, consent.ErrDecisionNotFound
		}
		return consent.DecisionOperation{}, fmt.Errorf("postgres: read decision operation: %w", err)
	}
	op.ID = consent.DecisionOperationID(operationID)
	op.Decision = consent.Decision(decision)
	op.Status = consent.DecisionOperationStatus(status)
	op.LocalUserID = identity.UserID(userID)
	op.ClientID = applications.OAuthClientID(clientID)
	op.ErrorClass = consent.ErrorClass(errorClass)
	if providerSucceededAt != nil {
		op.ProviderSucceededAt = *providerSucceededAt
	}
	return op, nil
}

type scopeQuerier interface {
	Query(ctx context.Context, sql string, args ...any) (pgx.Rows, error)
}

// readGrantScopes reads the consented scope set of a grant.
func readGrantScopes(ctx context.Context, q scopeQuerier, grantID consent.GrantID) ([]string, error) {
	rows, err := q.Query(ctx,
		`SELECT scope FROM oauth_authorization_grant_scopes
		  WHERE grant_id = $1 ORDER BY scope`,
		string(grantID))
	if err != nil {
		return nil, fmt.Errorf("postgres: read grant scopes: %w", err)
	}
	defer rows.Close()

	scopes := make([]string, 0)
	for rows.Next() {
		var scope string
		if err := rows.Scan(&scope); err != nil {
			return nil, fmt.Errorf("postgres: scan grant scope: %w", err)
		}
		scopes = append(scopes, scope)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("postgres: iterate grant scopes: %w", err)
	}
	return scopes, nil
}
