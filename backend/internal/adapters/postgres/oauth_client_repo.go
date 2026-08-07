//
// Copyright (c) 2026 Chen Jiajie(Ariakage)
//
// Author: Chen Jiajie(Ariakage) <ariakage233@gmail.com>
// Date: 2026-08-06
// Description: PostgreSQL repository for the OAuth client lifecycle
//

package postgres

import (
	"context"
	"errors"
	"fmt"
	"time"

	"github.com/jackc/pgx/v5"

	"github.com/GravelEvolution/united-pass/backend/internal/applications"
)

// ClientConfigUpdate aliases the domain client update type.
type ClientConfigUpdate = applications.ClientConfigUpdate

// CreateClientWithOperation inserts a new client (with redirect URIs and
// scopes) and its pending provider operation in one transaction.
func (r *ApplicationRepository) CreateClientWithOperation(
	ctx context.Context,
	client applications.OAuthClient,
	op applications.ProviderOperation,
) error {
	tx, err := r.pool.Begin(ctx)
	if err != nil {
		return fmt.Errorf("postgres: begin create client tx: %w", err)
	}
	defer func() { _ = tx.Rollback(ctx) }()

	if err := insertClientTx(ctx, tx, client); err != nil {
		return err
	}
	if err := insertOperationTx(ctx, tx, op); err != nil {
		return err
	}
	if err := tx.Commit(ctx); err != nil {
		return fmt.Errorf("postgres: commit create client: %w", err)
	}
	return nil
}

// CompleteClientProvisioning flips a single client to provisioned, records
// provider identifiers, marks the operation succeeded and stores optional
// secret metadata — atomically.
func (r *ApplicationRepository) CompleteClientProvisioning(
	ctx context.Context,
	clientID applications.OAuthClientID,
	provider, providerProjectID, providerApplicationID, providerClientID string,
	opID applications.ProviderOperationID,
	secret *applications.ClientSecretRecord,
	audit ...applications.SecurityEvent,
) error {
	tx, err := r.pool.Begin(ctx)
	if err != nil {
		return fmt.Errorf("postgres: begin client provisioning tx: %w", err)
	}
	defer func() { _ = tx.Rollback(ctx) }()

	tag, err := tx.Exec(ctx,
		`UPDATE oauth_clients
		    SET provider = $2, provider_project_id = $3, provider_application_id = $4,
		        provider_client_id = $5, provisioning_status = 'provisioned',
		        updated_at = NOW(), version = version + 1
		  WHERE client_id = $1 AND provisioning_status = 'provisioning' AND deleted_at IS NULL`,
		string(clientID), provider, providerProjectID, providerApplicationID, providerClientID)
	if err != nil {
		return fmt.Errorf("postgres: flip client provisioned: %w", err)
	}
	if tag.RowsAffected() != 1 {
		return applications.ErrConflict
	}
	if err := setOperationOutcomeTx(ctx, tx, opID, applications.ProviderOperationSucceeded, ""); err != nil {
		return err
	}
	if secret != nil {
		if err := insertSecretRecordTx(ctx, tx, *secret); err != nil {
			return err
		}
	}
	if err := insertSecurityEventsTx(ctx, tx, audit); err != nil {
		return err
	}
	if err := tx.Commit(ctx); err != nil {
		return fmt.Errorf("postgres: commit client provisioning: %w", err)
	}
	return nil
}

// MarkClientProvisioningFailed records a provider failure for one client.
func (r *ApplicationRepository) MarkClientProvisioningFailed(
	ctx context.Context,
	clientID applications.OAuthClientID,
	opID applications.ProviderOperationID,
	errorClass string,
) error {
	tx, err := r.pool.Begin(ctx)
	if err != nil {
		return fmt.Errorf("postgres: begin client failure tx: %w", err)
	}
	defer func() { _ = tx.Rollback(ctx) }()

	if _, err := tx.Exec(ctx,
		`UPDATE oauth_clients
		    SET provisioning_status = 'provisioning_failed', updated_at = NOW()
		  WHERE client_id = $1 AND provisioning_status = 'provisioning'`,
		string(clientID)); err != nil {
		return fmt.Errorf("postgres: mark client provisioning failed: %w", err)
	}
	if err := setOperationOutcomeTx(ctx, tx, opID, applications.ProviderOperationFailed, errorClass); err != nil {
		return err
	}
	if err := tx.Commit(ctx); err != nil {
		return fmt.Errorf("postgres: commit client failure: %w", err)
	}
	return nil
}

// GetClient loads one fully hydrated client. The application binding is
// asserted in SQL: a client that does not belong to the path application is
// indistinguishable from a missing one (anti-enumeration).
func (r *ApplicationRepository) GetClient(ctx context.Context, appID applications.ApplicationID, clientID applications.OAuthClientID) (applications.OAuthClient, error) {
	row := r.pool.QueryRow(ctx,
		`SELECT client_id, application_id, name, profile, client_type,
		        token_endpoint_auth_method, consent_mode, logout_uri, status,
		        provider, provider_project_id, provider_application_id,
		        provider_client_id, provisioning_status, version, created_at, updated_at
		   FROM oauth_clients
		  WHERE client_id = $2 AND application_id = $1
		    AND deleted_at IS NULL AND provisioning_status = 'provisioned'`,
		string(appID), string(clientID))
	client, err := scanClient(row)
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return applications.OAuthClient{}, applications.ErrNotFound
		}
		return applications.OAuthClient{}, fmt.Errorf("postgres: get client: %w", err)
	}
	if err := r.hydrateClient(ctx, &client); err != nil {
		return applications.OAuthClient{}, err
	}
	return client, nil
}

// ListClientsByApplication returns all provisioned, live clients of an
// application, each fully hydrated.
func (r *ApplicationRepository) ListClientsByApplication(ctx context.Context, appID applications.ApplicationID) ([]applications.OAuthClient, error) {
	rows, err := r.pool.Query(ctx,
		`SELECT client_id, application_id, name, profile, client_type,
		        token_endpoint_auth_method, consent_mode, logout_uri, status,
		        provider, provider_project_id, provider_application_id,
		        provider_client_id, provisioning_status, version, created_at, updated_at
		   FROM oauth_clients
		  WHERE application_id = $1
		    AND deleted_at IS NULL AND provisioning_status = 'provisioned'
		  ORDER BY created_at ASC, client_id ASC`,
		string(appID))
	if err != nil {
		return nil, fmt.Errorf("postgres: list clients: %w", err)
	}
	defer rows.Close()

	clients := make([]applications.OAuthClient, 0)
	for rows.Next() {
		client, err := scanClient(rows)
		if err != nil {
			return nil, fmt.Errorf("postgres: scan client row: %w", err)
		}
		if err := r.hydrateClient(ctx, &client); err != nil {
			return nil, err
		}
		clients = append(clients, client)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("postgres: iterate client rows: %w", err)
	}
	return clients, nil
}

// ListLiveClientsByApplication returns every client row that is not
// soft-deleted, regardless of provisioning status. Application deletion
// needs this to clean up delete_failed and ambiguously provisioned clients
// that ListClientsByApplication hides.
func (r *ApplicationRepository) ListLiveClientsByApplication(ctx context.Context, appID applications.ApplicationID) ([]applications.OAuthClient, error) {
	rows, err := r.pool.Query(ctx,
		`SELECT client_id, application_id, name, profile, client_type,
		        token_endpoint_auth_method, consent_mode, logout_uri, status,
		        provider, provider_project_id, provider_application_id,
		        provider_client_id, provisioning_status, version, created_at, updated_at
		   FROM oauth_clients
		  WHERE application_id = $1
		    AND deleted_at IS NULL
		  ORDER BY created_at ASC, client_id ASC`,
		string(appID))
	if err != nil {
		return nil, fmt.Errorf("postgres: list live clients: %w", err)
	}
	defer rows.Close()

	clients := make([]applications.OAuthClient, 0)
	for rows.Next() {
		client, err := scanClient(rows)
		if err != nil {
			return nil, fmt.Errorf("postgres: scan client row: %w", err)
		}
		if err := r.hydrateClient(ctx, &client); err != nil {
			return nil, err
		}
		clients = append(clients, client)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("postgres: iterate live client rows: %w", err)
	}
	return clients, nil
}

// UpdateClientConfig applies a client metadata update with optimistic
// concurrency. Redirect URIs and scopes are replaced wholesale. Durable
// success audits commit in the same transaction (ADR-0004 §8).
func (r *ApplicationRepository) UpdateClientConfig(ctx context.Context, clientID applications.OAuthClientID, upd ClientConfigUpdate, expectedVersion int, audit ...applications.SecurityEvent) error {
	tx, err := r.pool.Begin(ctx)
	if err != nil {
		return fmt.Errorf("postgres: begin update client tx: %w", err)
	}
	defer func() { _ = tx.Rollback(ctx) }()

	tag, err := tx.Exec(ctx,
		`UPDATE oauth_clients
		    SET name = $2, logout_uri = $3, consent_mode = $4,
		        updated_at = NOW(), version = version + 1
		  WHERE client_id = $1 AND version = $5
		    AND deleted_at IS NULL AND provisioning_status = 'provisioned'`,
		string(clientID), upd.Name, upd.LogoutURI, string(upd.ConsentMode), expectedVersion)
	if err != nil {
		if isUniqueViolation(err) {
			return ErrDuplicateName
		}
		return fmt.Errorf("postgres: update client: %w", err)
	}
	if tag.RowsAffected() == 0 {
		return r.conflictOrNotFoundClientTx(ctx, tx, clientID)
	}

	if upd.RedirectURIs != nil {
		if _, err := tx.Exec(ctx, `DELETE FROM oauth_client_redirect_uris WHERE client_id = $1`, string(clientID)); err != nil {
			return fmt.Errorf("postgres: clear redirect uris: %w", err)
		}
		for _, uri := range upd.RedirectURIs {
			if _, err := tx.Exec(ctx,
				`INSERT INTO oauth_client_redirect_uris (client_id, uri, is_loopback, added_at)
				 VALUES ($1, $2, $3, $4)`,
				string(clientID), uri.URI, uri.IsLoopback, uri.AddedAt); err != nil {
				return fmt.Errorf("postgres: insert redirect uri: %w", err)
			}
		}
	}
	if upd.Scopes != nil {
		if _, err := tx.Exec(ctx, `DELETE FROM oauth_client_scopes WHERE client_id = $1`, string(clientID)); err != nil {
			return fmt.Errorf("postgres: clear scopes: %w", err)
		}
		for _, scope := range upd.Scopes {
			if _, err := tx.Exec(ctx,
				`INSERT INTO oauth_client_scopes (client_id, scope) VALUES ($1, $2)`,
				string(clientID), scope); err != nil {
				return fmt.Errorf("postgres: insert scope: %w", err)
			}
		}
	}

	if err := insertSecurityEventsTx(ctx, tx, audit); err != nil {
		return err
	}
	if err := tx.Commit(ctx); err != nil {
		return fmt.Errorf("postgres: commit update client: %w", err)
	}
	return nil
}

// SetClientStatus flips the public client status with optimistic
// concurrency. Durable success audits commit in the same transaction as the
// status flip (ADR-0004 §8).
func (r *ApplicationRepository) SetClientStatus(ctx context.Context, clientID applications.OAuthClientID, status applications.Status, expectedVersion int, audit ...applications.SecurityEvent) error {
	tx, err := r.pool.Begin(ctx)
	if err != nil {
		return fmt.Errorf("postgres: begin set client status tx: %w", err)
	}
	defer func() { _ = tx.Rollback(ctx) }()

	tag, err := tx.Exec(ctx,
		`UPDATE oauth_clients
		    SET status = $2, updated_at = NOW(), version = version + 1
		  WHERE client_id = $1 AND version = $3
		    AND deleted_at IS NULL AND provisioning_status = 'provisioned'`,
		string(clientID), string(status), expectedVersion)
	if err != nil {
		return fmt.Errorf("postgres: set client status: %w", err)
	}
	if tag.RowsAffected() == 0 {
		return r.conflictOrNotFoundClientTx(ctx, tx, clientID)
	}
	if err := insertSecurityEventsTx(ctx, tx, audit); err != nil {
		return err
	}
	if err := tx.Commit(ctx); err != nil {
		return fmt.Errorf("postgres: commit set client status: %w", err)
	}
	return nil
}

// MarkClientDeleting arms a client for deletion and records the pending
// delete operation atomically. It accepts provisioned clients as well as
// provisioning/provisioning_failed ones: after an ambiguous provider
// timeout the provider resource may exist and must be cleaned up
// idempotently during application deletion.
func (r *ApplicationRepository) MarkClientDeleting(ctx context.Context, clientID applications.OAuthClientID, op applications.ProviderOperation) error {
	tx, err := r.pool.Begin(ctx)
	if err != nil {
		return fmt.Errorf("postgres: begin mark deleting tx: %w", err)
	}
	defer func() { _ = tx.Rollback(ctx) }()

	tag, err := tx.Exec(ctx,
		`UPDATE oauth_clients
		    SET provisioning_status = 'deleting', updated_at = NOW()
		  WHERE client_id = $1 AND deleted_at IS NULL
		    AND provisioning_status IN ('provisioned', 'provisioning', 'provisioning_failed')`,
		string(clientID))
	if err != nil {
		return fmt.Errorf("postgres: mark client deleting: %w", err)
	}
	if tag.RowsAffected() != 1 {
		return applications.ErrConflict
	}
	if err := insertOperationTx(ctx, tx, op); err != nil {
		return err
	}
	if err := tx.Commit(ctx); err != nil {
		return fmt.Errorf("postgres: commit mark deleting: %w", err)
	}
	return nil
}

// MarkClientDeletingRetry re-arms a client stuck in delete_failed — or still
// in deleting after the provider removal succeeded but the local commit
// crashed — for a delete retry, and records the new pending operation
// atomically. Provider removal is idempotent, so both states are safe to
// re-drive (ADR-0004 §7).
func (r *ApplicationRepository) MarkClientDeletingRetry(ctx context.Context, clientID applications.OAuthClientID, op applications.ProviderOperation) error {
	tx, err := r.pool.Begin(ctx)
	if err != nil {
		return fmt.Errorf("postgres: begin delete retry tx: %w", err)
	}
	defer func() { _ = tx.Rollback(ctx) }()

	tag, err := tx.Exec(ctx,
		`UPDATE oauth_clients
		    SET provisioning_status = 'deleting', updated_at = NOW()
		  WHERE client_id = $1 AND deleted_at IS NULL AND provisioning_status IN ('delete_failed', 'deleting')`,
		string(clientID))
	if err != nil {
		return fmt.Errorf("postgres: re-arm client deleting: %w", err)
	}
	if tag.RowsAffected() != 1 {
		return applications.ErrConflict
	}
	if err := insertOperationTx(ctx, tx, op); err != nil {
		return err
	}
	if err := tx.Commit(ctx); err != nil {
		return fmt.Errorf("postgres: commit delete retry: %w", err)
	}
	return nil
}

// CompleteClientDeletion soft-deletes the client and marks the delete
// operation succeeded atomically. Durable success audits commit in the same
// transaction (ADR-0004 §8).
func (r *ApplicationRepository) CompleteClientDeletion(ctx context.Context, clientID applications.OAuthClientID, opID applications.ProviderOperationID, audit ...applications.SecurityEvent) error {
	tx, err := r.pool.Begin(ctx)
	if err != nil {
		return fmt.Errorf("postgres: begin complete deletion tx: %w", err)
	}
	defer func() { _ = tx.Rollback(ctx) }()

	tag, err := tx.Exec(ctx,
		`UPDATE oauth_clients
		    SET deleted_at = NOW(), updated_at = NOW()
		  WHERE client_id = $1 AND provisioning_status = 'deleting'`,
		string(clientID))
	if err != nil {
		return fmt.Errorf("postgres: soft delete client: %w", err)
	}
	if tag.RowsAffected() != 1 {
		return applications.ErrConflict
	}
	if err := setOperationOutcomeTx(ctx, tx, opID, applications.ProviderOperationSucceeded, ""); err != nil {
		return err
	}
	if err := insertSecurityEventsTx(ctx, tx, audit); err != nil {
		return err
	}
	if err := tx.Commit(ctx); err != nil {
		return fmt.Errorf("postgres: commit complete deletion: %w", err)
	}
	return nil
}

// MarkClientDeleteFailed records a provider delete failure; the client stays
// visible as delete_failed until reconciliation succeeds.
func (r *ApplicationRepository) MarkClientDeleteFailed(ctx context.Context, clientID applications.OAuthClientID, opID applications.ProviderOperationID, errorClass string) error {
	tx, err := r.pool.Begin(ctx)
	if err != nil {
		return fmt.Errorf("postgres: begin delete failure tx: %w", err)
	}
	defer func() { _ = tx.Rollback(ctx) }()

	if _, err := tx.Exec(ctx,
		`UPDATE oauth_clients
		    SET provisioning_status = 'delete_failed', updated_at = NOW()
		  WHERE client_id = $1 AND provisioning_status = 'deleting'`,
		string(clientID)); err != nil {
		return fmt.Errorf("postgres: mark client delete failed: %w", err)
	}
	if err := setOperationOutcomeTx(ctx, tx, opID, applications.ProviderOperationFailed, errorClass); err != nil {
		return err
	}
	if err := tx.Commit(ctx); err != nil {
		return fmt.Errorf("postgres: commit delete failure: %w", err)
	}
	return nil
}

// CreateSecretRecord stores secret metadata (never a secret value).
func (r *ApplicationRepository) CreateSecretRecord(ctx context.Context, rec applications.ClientSecretRecord) error {
	if _, err := r.pool.Exec(ctx,
		`INSERT INTO oauth_client_secret_records (secret_id, client_id, label, created_at, last_rotated_at)
		 VALUES ($1, $2, $3, $4, $5)`,
		string(rec.ID), string(rec.ClientID), rec.Label, rec.CreatedAt, rec.LastRotatedAt); err != nil {
		return fmt.Errorf("postgres: insert secret record: %w", err)
	}
	return nil
}

// MarkSecretRotated stamps the rotation time on a secret metadata record.
func (r *ApplicationRepository) MarkSecretRotated(ctx context.Context, secretID applications.ClientSecretID, rotatedAt time.Time) error {
	tag, err := r.pool.Exec(ctx,
		`UPDATE oauth_client_secret_records SET last_rotated_at = $2 WHERE secret_id = $1`,
		string(secretID), rotatedAt)
	if err != nil {
		return fmt.Errorf("postgres: mark secret rotated: %w", err)
	}
	if tag.RowsAffected() == 0 {
		return applications.ErrNotFound
	}
	return nil
}

// BeginSecretRotation acquires the durable rotation gate: only an idle
// client with the expected version can transition to in_progress, and the
// pending provider operation is recorded in the same transaction (ADR-0004
// §6). Concurrent rotations, stale versions and outcome_unknown clients all
// lose the gate with ErrConflict.
func (r *ApplicationRepository) BeginSecretRotation(ctx context.Context, clientID applications.OAuthClientID, expectedVersion int, op applications.ProviderOperation) error {
	tx, err := r.pool.Begin(ctx)
	if err != nil {
		return fmt.Errorf("postgres: begin secret rotation tx: %w", err)
	}
	defer func() { _ = tx.Rollback(ctx) }()

	tag, err := tx.Exec(ctx,
		`UPDATE oauth_clients
		    SET secret_rotation_status = 'in_progress',
		        secret_rotation_operation_id = $3,
		        secret_rotation_started_at = NOW(),
		        updated_at = NOW(), version = version + 1
		  WHERE client_id = $1 AND version = $2
		    AND deleted_at IS NULL AND provisioning_status = 'provisioned'
		    AND secret_rotation_status = 'idle'`,
		string(clientID), expectedVersion, string(op.ID))
	if err != nil {
		return fmt.Errorf("postgres: begin secret rotation: %w", err)
	}
	if tag.RowsAffected() != 1 {
		return r.conflictOrNotFoundClientTx(ctx, tx, clientID)
	}
	if err := insertOperationTx(ctx, tx, op); err != nil {
		return err
	}
	if err := tx.Commit(ctx); err != nil {
		return fmt.Errorf("postgres: commit begin rotation: %w", err)
	}
	return nil
}

// CompleteSecretRotation commits a successful rotation in one transaction:
// the previous secret record is stamped, the new record inserted, the gate
// released back to idle, the operation marked succeeded and the durable
// success audit persisted (ADR-0004 §6/§8).
func (r *ApplicationRepository) CompleteSecretRotation(ctx context.Context, clientID applications.OAuthClientID, opID applications.ProviderOperationID, rotatedSecretID applications.ClientSecretID, newRec applications.ClientSecretRecord, rotatedAt time.Time, audit ...applications.SecurityEvent) error {
	tx, err := r.pool.Begin(ctx)
	if err != nil {
		return fmt.Errorf("postgres: begin complete rotation tx: %w", err)
	}
	defer func() { _ = tx.Rollback(ctx) }()

	tag, err := tx.Exec(ctx,
		`UPDATE oauth_clients
		    SET secret_rotation_status = 'idle',
		        secret_rotation_operation_id = '',
		        secret_rotation_started_at = NULL,
		        updated_at = NOW(), version = version + 1
		  WHERE client_id = $1 AND deleted_at IS NULL
		    AND secret_rotation_status = 'in_progress'
		    AND secret_rotation_operation_id = $2`,
		string(clientID), string(opID))
	if err != nil {
		return fmt.Errorf("postgres: release rotation gate: %w", err)
	}
	if tag.RowsAffected() != 1 {
		return applications.ErrConflict
	}
	if rotatedSecretID != "" {
		if _, err := tx.Exec(ctx,
			`UPDATE oauth_client_secret_records SET last_rotated_at = $2 WHERE secret_id = $1`,
			string(rotatedSecretID), rotatedAt); err != nil {
			return fmt.Errorf("postgres: mark secret rotated: %w", err)
		}
	}
	if err := insertSecretRecordTx(ctx, tx, newRec); err != nil {
		return err
	}
	if err := setOperationOutcomeTx(ctx, tx, opID, applications.ProviderOperationSucceeded, ""); err != nil {
		return err
	}
	if err := insertSecurityEventsTx(ctx, tx, audit); err != nil {
		return err
	}
	if err := tx.Commit(ctx); err != nil {
		return fmt.Errorf("postgres: commit complete rotation: %w", err)
	}
	return nil
}

// AbortSecretRotation releases the gate after a confirmed provider failure;
// the previous secret stays untouched and the operation is marked failed.
func (r *ApplicationRepository) AbortSecretRotation(ctx context.Context, clientID applications.OAuthClientID, opID applications.ProviderOperationID, errorClass string) error {
	tx, err := r.pool.Begin(ctx)
	if err != nil {
		return fmt.Errorf("postgres: begin abort rotation tx: %w", err)
	}
	defer func() { _ = tx.Rollback(ctx) }()

	if _, err := tx.Exec(ctx,
		`UPDATE oauth_clients
		    SET secret_rotation_status = 'idle',
		        secret_rotation_operation_id = '',
		        secret_rotation_started_at = NULL,
		        updated_at = NOW()
		  WHERE client_id = $1 AND secret_rotation_operation_id = $2
		    AND secret_rotation_status = 'in_progress'`,
		string(clientID), string(opID)); err != nil {
		return fmt.Errorf("postgres: abort rotation: %w", err)
	}
	if err := setOperationOutcomeTx(ctx, tx, opID, applications.ProviderOperationFailed, errorClass); err != nil {
		return err
	}
	if err := tx.Commit(ctx); err != nil {
		return fmt.Errorf("postgres: commit abort rotation: %w", err)
	}
	return nil
}

// FailSecretRotationUnknown parks the rotation in outcome_unknown after an
// ambiguous provider outcome; the operation ID and started_at lease stay
// recorded until reconciliation clears them, and further rotations are
// refused by the idle-only gate.
func (r *ApplicationRepository) FailSecretRotationUnknown(ctx context.Context, clientID applications.OAuthClientID, opID applications.ProviderOperationID, errorClass string) error {
	tx, err := r.pool.Begin(ctx)
	if err != nil {
		return fmt.Errorf("postgres: begin unknown rotation tx: %w", err)
	}
	defer func() { _ = tx.Rollback(ctx) }()

	if _, err := tx.Exec(ctx,
		`UPDATE oauth_clients
		    SET secret_rotation_status = 'outcome_unknown', updated_at = NOW()
		  WHERE client_id = $1 AND secret_rotation_operation_id = $2
		    AND secret_rotation_status = 'in_progress'`,
		string(clientID), string(opID)); err != nil {
		return fmt.Errorf("postgres: park rotation unknown: %w", err)
	}
	if err := setOperationOutcomeTx(ctx, tx, opID, applications.ProviderOperationFailed, errorClass); err != nil {
		return err
	}
	if err := tx.Commit(ctx); err != nil {
		return fmt.Errorf("postgres: commit unknown rotation: %w", err)
	}
	return nil
}

// GetOperationByIdempotencyKey loads a recorded provider operation so a
// retry can reuse its outcome instead of calling the provider twice.
func (r *ApplicationRepository) GetOperationByIdempotencyKey(ctx context.Context, key string) (applications.ProviderOperation, error) {
	row := r.pool.QueryRow(ctx,
		`SELECT operation_id, operation_type, application_id, client_id,
		        idempotency_key, status, error_class
		   FROM oauth_provider_operations WHERE idempotency_key = $1`, key)
	var (
		op              applications.ProviderOperation
		opID, opType    string
		appID, clientID *string
		status          string
	)
	if err := row.Scan(&opID, &opType, &appID, &clientID, &op.IdempotencyKey, &status, &op.ErrorClass); err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return applications.ProviderOperation{}, applications.ErrNotFound
		}
		return applications.ProviderOperation{}, fmt.Errorf("postgres: get operation: %w", err)
	}
	op.ID = applications.ProviderOperationID(opID)
	op.Type = applications.ProviderOperationType(opType)
	if appID != nil {
		op.ApplicationID = applications.ApplicationID(*appID)
	}
	if clientID != nil {
		op.ClientID = applications.OAuthClientID(*clientID)
	}
	op.Status = applications.ProviderOperationStatus(status)
	return op, nil
}

// CreateReconciliationJob records provider-side cleanup that could not be
// completed inline.
func (r *ApplicationRepository) CreateReconciliationJob(ctx context.Context, job applications.ReconciliationJob) error {
	_, err := r.pool.Exec(ctx,
		`INSERT INTO provider_reconciliation_jobs
		     (job_id, application_id, client_id, provider_application_id, reason, desired_status, created_at)
		 VALUES ($1, $2, $3, $4, $5, $6, NOW())`,
		string(job.ID), string(job.ApplicationID), string(job.ClientID),
		job.ProviderApplicationID, job.Reason, job.DesiredStatus)
	if err != nil {
		return fmt.Errorf("postgres: create reconciliation job: %w", err)
	}
	return nil
}

// SetClientReconciliationRequired flags a client whose provider state needs
// reconciliation.
func (r *ApplicationRepository) SetClientReconciliationRequired(ctx context.Context, clientID applications.OAuthClientID) error {
	_, err := r.pool.Exec(ctx,
		`UPDATE oauth_clients SET provider_reconciliation_required = TRUE
		  WHERE client_id = $1`, string(clientID))
	if err != nil {
		return fmt.Errorf("postgres: flag reconciliation: %w", err)
	}
	return nil
}

// --- helpers ---

func insertClientTx(ctx context.Context, tx pgx.Tx, client applications.OAuthClient) error {
	_, err := tx.Exec(ctx,
		`INSERT INTO oauth_clients (client_id, application_id, name, profile, client_type,
		                            token_endpoint_auth_method, consent_mode, logout_uri, status,
		                            provider, provider_project_id, provider_application_id,
		                            provider_client_id, provisioning_status, version,
		                            created_at, updated_at)
		 VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13, $14, $15, $16, $17)`,
		string(client.ID), string(client.ApplicationID), client.Name, string(client.Profile),
		string(client.ClientType), string(client.TokenEndpointAuth), string(client.ConsentMode),
		client.LogoutURI, string(client.Status), client.Provider, client.ProviderProjectID,
		client.ProviderApplicationID, client.ProviderClientID, string(client.Provisioning),
		client.Version, client.CreatedAt, client.UpdatedAt)
	if err != nil {
		if isUniqueViolation(err) {
			return ErrDuplicateName
		}
		return fmt.Errorf("postgres: insert client: %w", err)
	}
	for _, uri := range client.RedirectURIs {
		if _, err := tx.Exec(ctx,
			`INSERT INTO oauth_client_redirect_uris (client_id, uri, is_loopback, added_at)
			 VALUES ($1, $2, $3, $4)`,
			string(client.ID), uri.URI, uri.IsLoopback, uri.AddedAt); err != nil {
			return fmt.Errorf("postgres: insert redirect uri: %w", err)
		}
	}
	for _, scope := range client.Scopes {
		if _, err := tx.Exec(ctx,
			`INSERT INTO oauth_client_scopes (client_id, scope) VALUES ($1, $2)`,
			string(client.ID), scope); err != nil {
			return fmt.Errorf("postgres: insert scope: %w", err)
		}
	}
	return nil
}

func insertOperationTx(ctx context.Context, tx pgx.Tx, op applications.ProviderOperation) error {
	_, err := tx.Exec(ctx,
		`INSERT INTO oauth_provider_operations
		     (operation_id, operation_type, application_id, client_id,
		      idempotency_key, status, error_class)
		 VALUES ($1, $2, $3, $4, $5, $6, $7)`,
		string(op.ID), string(op.Type), nullableString(op.ApplicationID), nullableString(op.ClientID),
		op.IdempotencyKey, string(op.Status), op.ErrorClass)
	if err != nil {
		return fmt.Errorf("postgres: insert operation: %w", err)
	}
	return nil
}

// nullableString maps an empty typed ID to SQL NULL for nullable columns.
func nullableString[T ~string](v T) any {
	if string(v) == "" {
		return nil
	}
	return string(v)
}

func setOperationOutcomeTx(ctx context.Context, tx pgx.Tx, opID applications.ProviderOperationID, status applications.ProviderOperationStatus, errorClass string) error {
	if _, err := tx.Exec(ctx,
		`UPDATE oauth_provider_operations
		    SET status = $2, error_class = $3, updated_at = NOW()
		  WHERE operation_id = $1`,
		string(opID), string(status), errorClass); err != nil {
		return fmt.Errorf("postgres: set operation outcome: %w", err)
	}
	return nil
}

func insertSecretRecordTx(ctx context.Context, tx pgx.Tx, rec applications.ClientSecretRecord) error {
	_, err := tx.Exec(ctx,
		`INSERT INTO oauth_client_secret_records (secret_id, client_id, label, created_at, last_rotated_at)
		 VALUES ($1, $2, $3, $4, $5)`,
		string(rec.ID), string(rec.ClientID), rec.Label, rec.CreatedAt, rec.LastRotatedAt)
	if err != nil {
		return fmt.Errorf("postgres: insert secret record: %w", err)
	}
	return nil
}

type rowScanner interface {
	Scan(dest ...any) error
}

func scanClient(row rowScanner) (applications.OAuthClient, error) {
	var (
		client                                          applications.OAuthClient
		clientID, appID, profile, clientType, tokenAuth string
		consent, status, provider, provProject, provApp string
		provisioning                                    string
	)
	err := row.Scan(&clientID, &appID, &client.Name, &profile, &clientType,
		&tokenAuth, &consent, &client.LogoutURI, &status,
		&provider, &provProject, &provApp, &client.ProviderClientID,
		&provisioning, &client.Version, &client.CreatedAt, &client.UpdatedAt)
	if err != nil {
		return applications.OAuthClient{}, err
	}
	client.ID = applications.OAuthClientID(clientID)
	client.ApplicationID = applications.ApplicationID(appID)
	client.Profile = applications.ClientProfile(profile)
	client.ClientType = applications.ClientType(clientType)
	client.TokenEndpointAuth = applications.TokenEndpointAuthMethod(tokenAuth)
	client.ConsentMode = applications.ConsentMode(consent)
	client.Status = applications.Status(status)
	client.Provider = provider
	client.ProviderProjectID = provProject
	client.ProviderApplicationID = provApp
	client.Provisioning = applications.ProvisioningStatus(provisioning)
	return client, nil
}

// hydrateClient loads redirect URIs, scopes and secret metadata for a client.
func (r *ApplicationRepository) hydrateClient(ctx context.Context, client *applications.OAuthClient) error {
	uris, err := r.getRedirectURIs(ctx, client.ID)
	if err != nil {
		return err
	}
	client.RedirectURIs = uris

	scopes, err := r.getScopes(ctx, client.ID)
	if err != nil {
		return err
	}
	client.Scopes = scopes

	secrets, err := r.GetClientSecretRecords(ctx, client.ID)
	if err != nil {
		return err
	}
	client.SecretRecords = secrets
	return nil
}

func (r *ApplicationRepository) getRedirectURIs(ctx context.Context, clientID applications.OAuthClientID) ([]applications.RedirectURI, error) {
	rows, err := r.pool.Query(ctx,
		`SELECT uri, is_loopback, added_at FROM oauth_client_redirect_uris
		  WHERE client_id = $1 ORDER BY added_at ASC, uri ASC`, string(clientID))
	if err != nil {
		return nil, fmt.Errorf("postgres: get redirect uris: %w", err)
	}
	defer rows.Close()

	uris := make([]applications.RedirectURI, 0)
	for rows.Next() {
		var uri applications.RedirectURI
		if err := rows.Scan(&uri.URI, &uri.IsLoopback, &uri.AddedAt); err != nil {
			return nil, fmt.Errorf("postgres: scan redirect uri: %w", err)
		}
		uris = append(uris, uri)
	}
	return uris, rows.Err()
}

func (r *ApplicationRepository) getScopes(ctx context.Context, clientID applications.OAuthClientID) ([]string, error) {
	rows, err := r.pool.Query(ctx,
		`SELECT scope FROM oauth_client_scopes WHERE client_id = $1 ORDER BY scope`, string(clientID))
	if err != nil {
		return nil, fmt.Errorf("postgres: get scopes: %w", err)
	}
	defer rows.Close()

	scopes := make([]string, 0)
	for rows.Next() {
		var scope string
		if err := rows.Scan(&scope); err != nil {
			return nil, fmt.Errorf("postgres: scan scope: %w", err)
		}
		scopes = append(scopes, scope)
	}
	return scopes, rows.Err()
}

// GetClientSecretRecords returns secret metadata (never secret values).
func (r *ApplicationRepository) GetClientSecretRecords(ctx context.Context, clientID applications.OAuthClientID) ([]applications.ClientSecretRecord, error) {
	rows, err := r.pool.Query(ctx,
		`SELECT secret_id, client_id, label, created_at, last_rotated_at
		   FROM oauth_client_secret_records WHERE client_id = $1
		  ORDER BY created_at DESC`, string(clientID))
	if err != nil {
		return nil, fmt.Errorf("postgres: get secret records: %w", err)
	}
	defer rows.Close()

	records := make([]applications.ClientSecretRecord, 0)
	for rows.Next() {
		var (
			rec           applications.ClientSecretRecord
			secretID, cli string
		)
		if err := rows.Scan(&secretID, &cli, &rec.Label, &rec.CreatedAt, &rec.LastRotatedAt); err != nil {
			return nil, fmt.Errorf("postgres: scan secret record: %w", err)
		}
		rec.ID = applications.ClientSecretID(secretID)
		rec.ClientID = applications.OAuthClientID(cli)
		records = append(records, rec)
	}
	return records, rows.Err()
}

func (r *ApplicationRepository) conflictOrNotFoundClientTx(ctx context.Context, tx pgx.Tx, clientID applications.OAuthClientID) error {
	var exists bool
	err := tx.QueryRow(ctx,
		`SELECT EXISTS (SELECT 1 FROM oauth_clients
		                 WHERE client_id = $1 AND deleted_at IS NULL
		                   AND provisioning_status = 'provisioned')`,
		string(clientID)).Scan(&exists)
	if err != nil {
		return fmt.Errorf("postgres: check client existence: %w", err)
	}
	if !exists {
		return applications.ErrNotFound
	}
	return applications.ErrConflict
}
