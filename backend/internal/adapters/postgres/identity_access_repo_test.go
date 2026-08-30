package postgres

import (
	"context"
	"encoding/base64"
	"errors"
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"

	"github.com/GravelEvolution/united-pass/backend/internal/adminpagination"
	"github.com/GravelEvolution/united-pass/backend/internal/identityaccess"
)

func TestIdentityAccessTerminalMutationQueriesRequireExactEventScope(t *testing.T) {
	for name, query := range map[string]string{
		"decide lock":   identityAccessDecideLockSQL,
		"decide update": identityAccessDecideUpdateSQL,
		"claim":         identityAccessClaimSQL,
		"settle":        identityAccessSettleSQL,
		"release":       identityAccessReleaseExpiredClaimSQL,
	} {
		normalized := strings.Join(strings.Fields(query), " ")
		if !strings.Contains(normalized, "event_id=$2") {
			t.Fatalf("%s is not exact-event scoped: %s", name, normalized)
		}
	}
}

func TestIdentityAccessGrantMutationsBindRoleChallengeVersionAndLease(t *testing.T) {
	claim := strings.Join(strings.Fields(identityAccessClaimSQL), " ")
	for _, term := range []string{"requester_role_binding_id=$", "requester_role_binding_version=$", "requester_challenge_version=$", "INTERVAL '60 seconds'"} {
		if !strings.Contains(claim, term) {
			t.Fatalf("claim SQL missing %q: %s", term, claim)
		}
	}
	settle := strings.Join(strings.Fields(identityAccessSettleSQL), " ")
	for _, term := range []string{"requester_user_id=$", "requester_role_binding_id=$", "requester_role_binding_version=$", "requester_challenge_version=$", "version=$"} {
		if !strings.Contains(settle, term) {
			t.Fatalf("settle SQL missing %q: %s", term, settle)
		}
	}
}

func TestIdentityAccessListLoadsFieldsWithoutASecondConnection(t *testing.T) {
	now := time.Date(2026, 8, 17, 12, 0, 0, 0, time.UTC)
	codec, err := adminpagination.NewCursorCodec(base64.StdEncoding.EncodeToString(make([]byte, 32)), func() time.Time { return now })
	if err != nil {
		t.Fatalf("new cursor codec: %v", err)
	}
	exec := &singleQueryAdminExec{rows: &identityAccessRows{values: []any{
		"iar_1", "evt_shanghai", "user_reviewer", "user_candidate", (*string)(nil), "application", "app_1", "pending", "reason_1", int64(1), now, now, now.Add(24 * time.Hour), (*time.Time)(nil), []string{"identity_photo", "legal_name"},
	}}}
	repo := &IdentityAccessRepository{exec: exec, codec: codec}

	page, err := repo.ListOwn(context.Background(), "user_reviewer", adminpagination.Query{
		ActorID: "user_reviewer", ScopeKind: "event", EventID: "evt_shanghai", ListKind: identityaccess.ListKindOwn,
	})
	if err != nil {
		t.Fatalf("list own identity access: %v", err)
	}
	if exec.queries != 1 {
		t.Fatalf("query count=%d, want 1 so a single pooled connection is sufficient", exec.queries)
	}
	if len(page.Items) != 1 || !reflect.DeepEqual(page.Items[0].Fields, []identityaccess.Field{identityaccess.FieldIdentityPhoto, identityaccess.FieldLegalName}) {
		t.Fatalf("items=%+v", page.Items)
	}
}

func TestIdentityAccessStatusFilterRejectsUnknownFilterKeys(t *testing.T) {
	if _, err := identityAccessStatusFilter(map[string]string{"requester": "someone"}, false); !errors.Is(err, identityaccess.ErrInvalidRequest) {
		t.Fatalf("unknown filter error=%v, want invalid request", err)
	}
}

func TestPrepareIdentityAccessTimestampsUsesTheRequestClockForItsReason(t *testing.T) {
	now := time.Date(2026, 8, 17, 13, 0, 0, 0, time.UTC)
	request := identityaccess.Request{}
	reason := identityaccess.ProtectedReason{}

	prepareIdentityAccessTimestamps(&request, &reason, now)

	if !request.CreatedAt.Equal(now) || !request.UpdatedAt.Equal(now) || !reason.CreatedAt.Equal(now) {
		t.Fatalf("request created=%v updated=%v reason created=%v", request.CreatedAt, request.UpdatedAt, reason.CreatedAt)
	}
}

type singleQueryAdminExec struct {
	queries int
	rows    pgx.Rows
}

func (e *singleQueryAdminExec) Exec(context.Context, string, ...any) (pgconn.CommandTag, error) {
	return pgconn.CommandTag{}, errors.New("unexpected exec")
}

func (e *singleQueryAdminExec) Query(context.Context, string, ...any) (pgx.Rows, error) {
	e.queries++
	if e.queries != 1 {
		return nil, errors.New("a list item triggered a nested query")
	}
	return e.rows, nil
}

func (e *singleQueryAdminExec) QueryRow(context.Context, string, ...any) pgx.Row {
	return failingAdminRow{err: errors.New("unexpected query row")}
}

type failingAdminRow struct{ err error }

func (r failingAdminRow) Scan(...any) error { return r.err }

type identityAccessRows struct {
	values  []any
	visited bool
	closed  bool
}

func (r *identityAccessRows) Close()                                       { r.closed = true }
func (r *identityAccessRows) Err() error                                   { return nil }
func (r *identityAccessRows) CommandTag() pgconn.CommandTag                { return pgconn.CommandTag{} }
func (r *identityAccessRows) FieldDescriptions() []pgconn.FieldDescription { return nil }
func (r *identityAccessRows) Values() ([]any, error)                       { return append([]any(nil), r.values...), nil }
func (r *identityAccessRows) RawValues() [][]byte                          { return nil }
func (r *identityAccessRows) Conn() *pgx.Conn                              { return nil }

func (r *identityAccessRows) Next() bool {
	if r.visited {
		r.closed = true
		return false
	}
	r.visited = true
	return true
}

func (r *identityAccessRows) Scan(dest ...any) error {
	if !r.visited || r.closed || len(dest) != len(r.values) {
		return errors.New("identity access row shape mismatch")
	}
	for i := range dest {
		value := reflect.ValueOf(dest[i])
		if value.Kind() != reflect.Pointer || value.IsNil() {
			return errors.New("identity access row destination is not a pointer")
		}
		if r.values[i] == nil {
			value.Elem().SetZero()
			continue
		}
		source := reflect.ValueOf(r.values[i])
		if !source.Type().AssignableTo(value.Elem().Type()) {
			return errors.New("identity access row destination type mismatch")
		}
		value.Elem().Set(source)
	}
	return nil
}
