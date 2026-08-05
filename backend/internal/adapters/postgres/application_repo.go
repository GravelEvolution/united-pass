package postgres

import (
	"context"
	"errors"
	"fmt"
	"strings"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/GravelEvolution/united-pass/backend/internal/applications"
	"github.com/GravelEvolution/united-pass/backend/internal/identity"
)

// ErrDuplicateName is returned when a unique live-name constraint is hit.
var ErrDuplicateName = errors.New("postgres: duplicate name")

// ApplicationListQuery is the validated list request. All fields are
// optional; Sort defaults to "-updatedAt" and Limit to 20 (1–100).
type ApplicationListQuery struct {
	Cursor   string
	Limit    int
	Query    string
	Sort     string
	Status   string
	Audience string
	OwnerID  string
}

// ApplicationListResult is one page plus continuation state.
type ApplicationListResult struct {
	Items      []applications.ApplicationSummary
	NextCursor string
	HasMore    bool
}

// Supported sort keys for the application list. The ID tie-breaker is
// always appended by the repository (ADR-0004 §9).
var applicationSortKeys = map[string]bool{
	"updatedAt": true, "-updatedAt": true,
	"createdAt": true, "-createdAt": true,
	"name": true, "-name": true,
}

// ApplicationRepository persists OAuth applications and their list view.
// Client persistence lives on the same repository (oauth_client_repo.go).
type ApplicationRepository struct {
	pool   *pgxpool.Pool
	signer *cursorSigner
}

// NewApplicationRepository builds the repository. sessionEncryptionKeyB64
// must be the configured base64 32-byte key; cursor signing fails closed
// without it.
func NewApplicationRepository(pool *pgxpool.Pool, sessionEncryptionKeyB64 string) (*ApplicationRepository, error) {
	signer, err := newCursorSigner(sessionEncryptionKeyB64)
	if err != nil {
		return nil, err
	}
	return &ApplicationRepository{pool: pool, signer: signer}, nil
}

// CreateApplicationWithInitialClient inserts the application, its initial
// client (including redirect URIs and scopes) and the pending provider
// operation in one transaction. All rows start in the provisioning state;
// the provider call happens afterwards, outside any transaction.
func (r *ApplicationRepository) CreateApplicationWithInitialClient(
	ctx context.Context,
	app applications.Application,
	client applications.OAuthClient,
	op applications.ProviderOperation,
) error {
	tx, err := r.pool.Begin(ctx)
	if err != nil {
		return fmt.Errorf("postgres: begin create application tx: %w", err)
	}
	defer func() { _ = tx.Rollback(ctx) }()

	if err := insertApplicationTx(ctx, tx, app); err != nil {
		return err
	}
	if err := insertClientTx(ctx, tx, client); err != nil {
		return err
	}
	if err := insertOperationTx(ctx, tx, op); err != nil {
		return err
	}
	if err := tx.Commit(ctx); err != nil {
		return fmt.Errorf("postgres: commit create application: %w", err)
	}
	return nil
}

// CompleteInitialProvisioning records provider identifiers, flips the
// application and client to provisioned, marks the operation succeeded and
// stores optional secret metadata — atomically.
func (r *ApplicationRepository) CompleteInitialProvisioning(
	ctx context.Context,
	appID applications.ApplicationID,
	clientID applications.OAuthClientID,
	provider, providerProjectID, providerApplicationID, providerClientID string,
	opID applications.ProviderOperationID,
	secret *applications.ClientSecretRecord,
) error {
	tx, err := r.pool.Begin(ctx)
	if err != nil {
		return fmt.Errorf("postgres: begin complete provisioning tx: %w", err)
	}
	defer func() { _ = tx.Rollback(ctx) }()

	tag, err := tx.Exec(ctx,
		`UPDATE oauth_applications
		    SET provisioning_status = 'provisioned', updated_at = NOW(), version = version + 1
		  WHERE application_id = $1 AND provisioning_status = 'provisioning' AND deleted_at IS NULL`,
		string(appID))
	if err != nil {
		return fmt.Errorf("postgres: flip application provisioned: %w", err)
	}
	if tag.RowsAffected() != 1 {
		return applications.ErrConflict
	}

	tag, err = tx.Exec(ctx,
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
	if err := tx.Commit(ctx); err != nil {
		return fmt.Errorf("postgres: commit complete provisioning: %w", err)
	}
	return nil
}

// MarkInitialProvisioningFailed records a provider failure on both rows and
// the operation. Failed rows stay hidden from all listings.
func (r *ApplicationRepository) MarkInitialProvisioningFailed(
	ctx context.Context,
	appID applications.ApplicationID,
	clientID applications.OAuthClientID,
	opID applications.ProviderOperationID,
	errorClass string,
) error {
	tx, err := r.pool.Begin(ctx)
	if err != nil {
		return fmt.Errorf("postgres: begin provisioning failure tx: %w", err)
	}
	defer func() { _ = tx.Rollback(ctx) }()

	if _, err := tx.Exec(ctx,
		`UPDATE oauth_applications
		    SET provisioning_status = 'provisioning_failed', updated_at = NOW()
		  WHERE application_id = $1 AND provisioning_status = 'provisioning'`,
		string(appID)); err != nil {
		return fmt.Errorf("postgres: mark application provisioning failed: %w", err)
	}
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
		return fmt.Errorf("postgres: commit provisioning failure: %w", err)
	}
	return nil
}

// GetApplication loads one application with the owner's display name joined
// server-side. Ownership is the stored owner_user_id, never a display name
// lookup. Returns applications.ErrNotFound for missing, deleted or not yet
// provisioned applications.
func (r *ApplicationRepository) GetApplication(ctx context.Context, appID applications.ApplicationID) (applications.Application, error) {
	row := r.pool.QueryRow(ctx,
		`SELECT a.application_id, a.name, a.description, a.logo_url, a.audience,
		        a.owner_user_id, u.display_name, a.status, a.provisioning_status,
		        a.version, a.created_at, a.updated_at
		   FROM oauth_applications a
		   JOIN users u ON u.id = a.owner_user_id
		  WHERE a.application_id = $1
		    AND a.deleted_at IS NULL
		    AND a.provisioning_status = 'provisioned'`,
		string(appID))
	app, err := scanApplication(row)
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return applications.Application{}, applications.ErrNotFound
		}
		return applications.Application{}, fmt.Errorf("postgres: get application: %w", err)
	}
	return app, nil
}

// ApplicationUpdate carries the merged target values for a PATCH. All fields
// are applied together; the caller validates them beforehand.
type ApplicationUpdate struct {
	Name        string
	Description string
	Audience    applications.ApplicationAudience
	OwnerID     identity.UserID
}

// UpdateApplication applies a metadata update with optimistic concurrency.
// Returns applications.ErrNotFound / applications.ErrConflict.
func (r *ApplicationRepository) UpdateApplication(ctx context.Context, appID applications.ApplicationID, upd ApplicationUpdate, expectedVersion int) error {
	tag, err := r.pool.Exec(ctx,
		`UPDATE oauth_applications
		    SET name = $2, description = $3, audience = $4, owner_user_id = $5,
		        updated_at = NOW(), version = version + 1
		  WHERE application_id = $1 AND version = $6
		    AND deleted_at IS NULL AND provisioning_status = 'provisioned'`,
		string(appID), upd.Name, upd.Description, string(upd.Audience), string(upd.OwnerID), expectedVersion)
	if err != nil {
		if isUniqueViolation(err) {
			return ErrDuplicateName
		}
		return fmt.Errorf("postgres: update application: %w", err)
	}
	if tag.RowsAffected() == 0 {
		return r.conflictOrNotFoundApplication(ctx, appID)
	}
	return nil
}

// SetApplicationStatus flips the public status with optimistic concurrency.
func (r *ApplicationRepository) SetApplicationStatus(ctx context.Context, appID applications.ApplicationID, status applications.Status, expectedVersion int) error {
	tag, err := r.pool.Exec(ctx,
		`UPDATE oauth_applications
		    SET status = $2, updated_at = NOW(), version = version + 1
		  WHERE application_id = $1 AND version = $3
		    AND deleted_at IS NULL AND provisioning_status = 'provisioned'`,
		string(appID), string(status), expectedVersion)
	if err != nil {
		return fmt.Errorf("postgres: set application status: %w", err)
	}
	if tag.RowsAffected() == 0 {
		return r.conflictOrNotFoundApplication(ctx, appID)
	}
	return nil
}

// DeleteApplication soft-deletes an application. It fails with
// applications.ErrConflict while live clients still exist — the use case
// deletes clients first.
func (r *ApplicationRepository) DeleteApplication(ctx context.Context, appID applications.ApplicationID, expectedVersion int) error {
	tag, err := r.pool.Exec(ctx,
		`UPDATE oauth_applications
		    SET deleted_at = NOW(), updated_at = NOW()
		  WHERE application_id = $1 AND version = $2
		    AND deleted_at IS NULL AND provisioning_status = 'provisioned'
		    AND NOT EXISTS (
		        SELECT 1 FROM oauth_clients c
		         WHERE c.application_id = $1 AND c.deleted_at IS NULL)`,
		string(appID), expectedVersion)
	if err != nil {
		return fmt.Errorf("postgres: delete application: %w", err)
	}
	if tag.RowsAffected() == 0 {
		return r.conflictOrNotFoundApplication(ctx, appID)
	}
	return nil
}

// ListApplications returns one page of provisioned applications with
// server-side filters, stable ordering and a signed continuation cursor.
func (r *ApplicationRepository) ListApplications(ctx context.Context, q ApplicationListQuery) (ApplicationListResult, error) {
	limit := q.Limit
	if limit <= 0 {
		limit = 20
	}
	if limit > 100 {
		limit = 100
	}
	sort := q.Sort
	if sort == "" {
		sort = "-updatedAt"
	}
	if !applicationSortKeys[sort] {
		return ApplicationListResult{}, ErrInvalidCursor
	}

	var cur applicationCursor
	if q.Cursor != "" {
		decoded, err := r.signer.decode(q.Cursor)
		if err != nil {
			return ApplicationListResult{}, ErrInvalidCursor
		}
		// Cursors are bound to the exact sort and filter state.
		if decoded.Sort != sort || decoded.Query != q.Query || decoded.Status != q.Status ||
			decoded.Audience != q.Audience || decoded.OwnerID != q.OwnerID {
			return ApplicationListResult{}, ErrInvalidCursor
		}
		cur = decoded
	}

	where := []string{"a.deleted_at IS NULL", "a.provisioning_status = 'provisioned'"}
	args := []any{}
	addArg := func(v any) string {
		args = append(args, v)
		return fmt.Sprintf("$%d", len(args))
	}
	if q.Status != "" {
		where = append(where, "a.status = "+addArg(q.Status))
	}
	if q.Audience != "" {
		where = append(where, "a.audience = "+addArg(q.Audience))
	}
	if q.OwnerID != "" {
		where = append(where, "a.owner_user_id = "+addArg(q.OwnerID))
	}
	if q.Query != "" {
		pattern := "%" + escapeLike(q.Query) + "%"
		where = append(where,
			"(a.name ILIKE "+addArg(pattern)+" OR a.description ILIKE "+addArg(pattern)+")")
	}

	boundary, err := applicationBoundaryClause(sort, cur, &args)
	if err != nil {
		return ApplicationListResult{}, ErrInvalidCursor
	}
	if boundary != "" {
		where = append(where, boundary)
	}

	order, err := applicationOrderClause(sort)
	if err != nil {
		return ApplicationListResult{}, err
	}

	sql := `SELECT a.application_id, a.name, a.description, a.logo_url, a.audience,
	               a.owner_user_id, u.display_name, a.status, a.provisioning_status,
	               a.version, a.created_at, a.updated_at,
	               (SELECT COUNT(*) FROM oauth_clients c
	                 WHERE c.application_id = a.application_id
	                   AND c.deleted_at IS NULL
	                   AND c.provisioning_status = 'provisioned') AS client_count
	          FROM oauth_applications a
	          JOIN users u ON u.id = a.owner_user_id
	         WHERE ` + strings.Join(where, " AND ") + `
	         ORDER BY ` + order + `
	         LIMIT ` + fmt.Sprintf("%d", limit+1)

	rows, err := r.pool.Query(ctx, sql, args...)
	if err != nil {
		return ApplicationListResult{}, fmt.Errorf("postgres: list applications: %w", err)
	}
	defer rows.Close()

	items := make([]applications.ApplicationSummary, 0, limit)
	for rows.Next() {
		var (
			summary                                applications.ApplicationSummary
			appID, audience, ownerID, status, prov string
		)
		if err := rows.Scan(
			&appID, &summary.Name, &summary.Description, &summary.LogoURL,
			&audience, &ownerID, &summary.OwnerName, &status,
			&prov, &summary.Version, &summary.CreatedAt, &summary.UpdatedAt,
			&summary.ClientCount,
		); err != nil {
			return ApplicationListResult{}, fmt.Errorf("postgres: scan application row: %w", err)
		}
		summary.ID = applications.ApplicationID(appID)
		summary.Audience = applications.ApplicationAudience(audience)
		summary.OwnerID = identity.UserID(ownerID)
		summary.Status = applications.Status(status)
		summary.Provisioning = applications.ProvisioningStatus(prov)
		items = append(items, summary)
	}
	if err := rows.Err(); err != nil {
		return ApplicationListResult{}, fmt.Errorf("postgres: iterate application rows: %w", err)
	}

	result := ApplicationListResult{HasMore: len(items) > limit}
	if result.HasMore {
		items = items[:limit]
	}
	result.Items = items
	if result.HasMore && len(items) > 0 {
		last := items[len(items)-1]
		next := applicationCursor{
			Sort: sort, Query: q.Query, Status: q.Status,
			Audience: q.Audience, OwnerID: q.OwnerID,
			ID: string(last.ID), Name: last.Name,
		}
		switch sort {
		case "updatedAt", "-updatedAt":
			next.Value = last.UpdatedAt.UTC().Format("2006-01-02T15:04:05.999999999Z07:00")
		case "createdAt", "-createdAt":
			next.Value = last.CreatedAt.UTC().Format("2006-01-02T15:04:05.999999999Z07:00")
		}
		encoded, err := r.signer.encode(next)
		if err != nil {
			return ApplicationListResult{}, fmt.Errorf("postgres: encode cursor: %w", err)
		}
		result.NextCursor = encoded
	}
	return result, nil
}

// applicationOrderClause maps a sort key to the ORDER BY clause with the ID
// tie-breaker.
func applicationOrderClause(sort string) (string, error) {
	switch sort {
	case "-updatedAt":
		return "a.updated_at DESC, a.application_id DESC", nil
	case "updatedAt":
		return "a.updated_at ASC, a.application_id ASC", nil
	case "-createdAt":
		return "a.created_at DESC, a.application_id DESC", nil
	case "createdAt":
		return "a.created_at ASC, a.application_id ASC", nil
	case "-name":
		return "a.name DESC, a.application_id DESC", nil
	case "name":
		return "a.name ASC, a.application_id ASC", nil
	}
	return "", ErrInvalidCursor
}

// applicationBoundaryClause builds the keyset condition for a decoded
// cursor. args receives the boundary values.
func applicationBoundaryClause(sort string, cur applicationCursor, args *[]any) (string, error) {
	if cur.ID == "" {
		return "", nil
	}
	add := func(v any) string {
		*args = append(*args, v)
		return fmt.Sprintf("$%d", len(*args))
	}
	idArg := add(cur.ID)
	switch sort {
	case "-updatedAt", "updatedAt":
		t, err := parseCursorTime(cur.Value)
		if err != nil {
			return "", err
		}
		op := "<"
		if sort == "updatedAt" {
			op = ">"
		}
		return fmt.Sprintf("(a.updated_at, a.application_id) %s (%s, %s)", op, add(t), idArg), nil
	case "-createdAt", "createdAt":
		t, err := parseCursorTime(cur.Value)
		if err != nil {
			return "", err
		}
		op := "<"
		if sort == "createdAt" {
			op = ">"
		}
		return fmt.Sprintf("(a.created_at, a.application_id) %s (%s, %s)", op, add(t), idArg), nil
	case "-name", "name":
		op := "<"
		if sort == "name" {
			op = ">"
		}
		return fmt.Sprintf("(a.name, a.application_id) %s (%s, %s)", op, add(cur.Name), idArg), nil
	}
	return "", ErrInvalidCursor
}

// conflictOrNotFoundApplication distinguishes 404 from 409 after a
// conditional update affected no rows.
func (r *ApplicationRepository) conflictOrNotFoundApplication(ctx context.Context, appID applications.ApplicationID) error {
	var exists bool
	err := r.pool.QueryRow(ctx,
		`SELECT EXISTS (SELECT 1 FROM oauth_applications
		                 WHERE application_id = $1 AND deleted_at IS NULL
		                   AND provisioning_status = 'provisioned')`,
		string(appID)).Scan(&exists)
	if err != nil {
		return fmt.Errorf("postgres: check application existence: %w", err)
	}
	if !exists {
		return applications.ErrNotFound
	}
	return applications.ErrConflict
}

func insertApplicationTx(ctx context.Context, tx pgx.Tx, app applications.Application) error {
	_, err := tx.Exec(ctx,
		`INSERT INTO oauth_applications (application_id, name, description, logo_url,
		                                 audience, owner_user_id, status, provisioning_status,
		                                 version, created_at, updated_at)
		 VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11)`,
		string(app.ID), app.Name, app.Description, app.LogoURL,
		string(app.Audience), string(app.OwnerID), string(app.Status),
		string(app.Provisioning), app.Version, app.CreatedAt, app.UpdatedAt)
	if err != nil {
		if isUniqueViolation(err) {
			return ErrDuplicateName
		}
		return fmt.Errorf("postgres: insert application: %w", err)
	}
	return nil
}

func scanApplication(row pgx.Row) (applications.Application, error) {
	var (
		appID, audience, ownerID, ownerName, status, provisioning string
		app                                                       applications.Application
	)
	err := row.Scan(&appID, &app.Name, &app.Description, &app.LogoURL,
		&audience, &ownerID, &ownerName, &status, &provisioning,
		&app.Version, &app.CreatedAt, &app.UpdatedAt)
	if err != nil {
		return applications.Application{}, err
	}
	app.ID = applications.ApplicationID(appID)
	app.Audience = applications.ApplicationAudience(audience)
	app.OwnerID = identity.UserID(ownerID)
	app.OwnerName = ownerName
	app.Status = applications.Status(status)
	app.Provisioning = applications.ProvisioningStatus(provisioning)
	return app, nil
}

// escapeLike escapes LIKE/ILIKE metacharacters so user input matches
// literally.
func escapeLike(s string) string {
	r := strings.NewReplacer(`\`, `\\`, `%`, `\%`, `_`, `\_`)
	return r.Replace(s)
}
