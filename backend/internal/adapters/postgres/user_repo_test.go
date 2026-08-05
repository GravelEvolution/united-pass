package postgres

import (
	"errors"
	"fmt"
	"reflect"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"

	"github.com/GravelEvolution/united-pass/backend/internal/identity"
)

// fakeRow implements pgx.Row for unit testing scanUser and scanIdentityLink
// without a real database connection. It populates destination pointers passed
// to Scan with the values slice, in order. If err is non-nil, Scan returns it
// immediately.
type fakeRow struct {
	values []any
	err    error
}

// Scan assigns each value to the corresponding destination pointer using
// reflection. This mirrors how pgx populates scan destinations from column
// values. The number of destinations must match the number of values.
func (f *fakeRow) Scan(dest ...any) error {
	if f.err != nil {
		return f.err
	}
	if len(dest) != len(f.values) {
		return fmt.Errorf("fakeRow: expected %d destinations, got %d", len(f.values), len(dest))
	}
	for i, v := range f.values {
		if err := assignValue(dest[i], v); err != nil {
			return fmt.Errorf("fakeRow: assign index %d (%T <- %T): %w", i, dest[i], v, err)
		}
	}
	return nil
}

// assignValue sets the value pointed to by dest to v using reflection. dest
// must be a pointer; v must be assignable to the pointed-to type.
func assignValue(dest any, value any) error {
	rv := reflect.ValueOf(dest)
	if rv.Kind() != reflect.Ptr {
		return fmt.Errorf("destination must be a pointer, got %T", dest)
	}
	if rv.IsNil() {
		return fmt.Errorf("destination pointer is nil")
	}

	vv := reflect.ValueOf(value)
	elem := rv.Elem()

	// If the types match directly, assign.
	if vv.Type().AssignableTo(elem.Type()) {
		elem.Set(vv)
		return nil
	}

	// Allow integer narrowing (e.g. int -> int for Version field).
	if vv.Kind() >= reflect.Int && vv.Kind() <= reflect.Uint64 &&
		elem.Kind() >= reflect.Int && elem.Kind() <= reflect.Uint64 {
		elem.SetInt(vv.Int())
		return nil
	}

	return fmt.Errorf("type mismatch: dest element %s, value %s", elem.Type(), vv.Type())
}

func TestScanUser_MapsAllFields(t *testing.T) {
	created := time.Date(2026, 1, 15, 10, 30, 0, 0, time.UTC)
	updated := time.Date(2026, 2, 20, 14, 0, 0, 0, time.UTC)

	// Values must be in userColumns order:
	// id, status, display_name, nickname, avatar_url, email,
	// email_verified, phone, phone_verified, created_at, updated_at, version
	row := &fakeRow{
		values: []any{
			"user_01HQAAAAAAAAAAAA",
			"active",
			"Alice Zhang",
			"Alice",
			"https://cdn.example.com/avatars/alice.png",
			"alice@example.com",
			true,
			"+8613800138000",
			false,
			created,
			updated,
			3,
		},
	}

	user, err := scanUser(row)
	if err != nil {
		t.Fatalf("scanUser returned error: %v", err)
	}

	if user.ID != identity.UserID("user_01HQAAAAAAAAAAAA") {
		t.Errorf("ID = %q, want %q", user.ID, "user_01HQAAAAAAAAAAAA")
	}
	if user.Status != identity.UserStatusActive {
		t.Errorf("Status = %q, want %q", user.Status, identity.UserStatusActive)
	}
	if user.DisplayName != "Alice Zhang" {
		t.Errorf("DisplayName = %q, want %q", user.DisplayName, "Alice Zhang")
	}
	if user.Nickname != "Alice" {
		t.Errorf("Nickname = %q, want %q", user.Nickname, "Alice")
	}
	if user.AvatarURL != "https://cdn.example.com/avatars/alice.png" {
		t.Errorf("AvatarURL = %q, want %q", user.AvatarURL, "https://cdn.example.com/avatars/alice.png")
	}
	if user.Email != "alice@example.com" {
		t.Errorf("Email = %q, want %q", user.Email, "alice@example.com")
	}
	if !user.EmailVerified {
		t.Errorf("EmailVerified = false, want true")
	}
	if user.Phone != "+8613800138000" {
		t.Errorf("Phone = %q, want %q", user.Phone, "+8613800138000")
	}
	if user.PhoneVerified {
		t.Errorf("PhoneVerified = true, want false")
	}
	if !user.CreatedAt.Equal(created) {
		t.Errorf("CreatedAt = %v, want %v", user.CreatedAt, created)
	}
	if !user.UpdatedAt.Equal(updated) {
		t.Errorf("UpdatedAt = %v, want %v", user.UpdatedAt, updated)
	}
	if user.Version != 3 {
		t.Errorf("Version = %d, want 3", user.Version)
	}
}

func TestScanUser_MapsPendingStatus(t *testing.T) {
	row := &fakeRow{
		values: []any{
			"user_pending",
			"pending",
			"", // display_name
			"", // nickname
			"", // avatar_url
			"", // email
			false,
			"", // phone
			false,
			time.Now().UTC(),
			time.Now().UTC(),
			1,
		},
	}

	user, err := scanUser(row)
	if err != nil {
		t.Fatalf("scanUser returned error: %v", err)
	}

	if user.Status != identity.UserStatusPending {
		t.Errorf("Status = %q, want %q", user.Status, identity.UserStatusPending)
	}
	if !user.Status.IsValid() {
		t.Errorf("Status %q should be valid", user.Status)
	}
	if user.Status.CanAuthenticate() {
		t.Errorf("pending user should not be able to authenticate")
	}
}

func TestScanUser_MapsDisabledStatus(t *testing.T) {
	row := &fakeRow{
		values: []any{
			"user_disabled",
			"disabled",
			"Bob",
			"",
			"",
			"bob@example.com",
			true,
			"",
			false,
			time.Now().UTC(),
			time.Now().UTC(),
			5,
		},
	}

	user, err := scanUser(row)
	if err != nil {
		t.Fatalf("scanUser returned error: %v", err)
	}

	if user.Status != identity.UserStatusDisabled {
		t.Errorf("Status = %q, want %q", user.Status, identity.UserStatusDisabled)
	}
	if user.Status.CanAuthenticate() {
		t.Errorf("disabled user should not be able to authenticate")
	}
}

func TestScanUser_ReturnsErrNoRows(t *testing.T) {
	row := &fakeRow{err: pgx.ErrNoRows}

	_, err := scanUser(row)
	if err == nil {
		t.Fatal("scanUser returned nil error, expected pgx.ErrNoRows")
	}
	if !errors.Is(err, pgx.ErrNoRows) {
		t.Errorf("scanUser error = %v, expected pgx.ErrNoRows", err)
	}
}

func TestScanUser_ArbitraryScanError(t *testing.T) {
	scanErr := fmt.Errorf("connection reset")
	row := &fakeRow{err: scanErr}

	_, err := scanUser(row)
	if err == nil {
		t.Fatal("scanUser returned nil error, expected scanErr")
	}
	if !errors.Is(err, scanErr) {
		t.Errorf("scanUser error = %v, expected to wrap scanErr", err)
	}
}

func TestScanUser_ColumnCountMismatch(t *testing.T) {
	// Provide only 3 values when 12 destinations are expected.
	row := &fakeRow{
		values: []any{"id", "active", "name"},
	}

	_, err := scanUser(row)
	if err == nil {
		t.Fatal("scanUser returned nil error, expected column count mismatch")
	}
}

func TestScanIdentityLink_MapsAllFields(t *testing.T) {
	created := time.Date(2026, 1, 10, 8, 0, 0, 0, time.UTC)
	lastSeen := time.Date(2026, 3, 1, 16, 45, 0, 0, time.UTC)

	// Values must be in identityLinkColumns order:
	// id, user_id, provider, provider_tenant_id, provider_subject,
	// created_at, last_seen_at
	row := &fakeRow{
		values: []any{
			"link_01HQBBBBBBBBBBBB",
			"user_01HQAAAAAAAAAAAA",
			"feishu",
			"tenant_feishu_001",
			"feishu_subject_abc123",
			created,
			lastSeen,
		},
	}

	link, err := scanIdentityLink(row)
	if err != nil {
		t.Fatalf("scanIdentityLink returned error: %v", err)
	}

	if link.ID != "link_01HQBBBBBBBBBBBB" {
		t.Errorf("ID = %q, want %q", link.ID, "link_01HQBBBBBBBBBBBB")
	}
	if link.UserID != identity.UserID("user_01HQAAAAAAAAAAAA") {
		t.Errorf("UserID = %q, want %q", link.UserID, "user_01HQAAAAAAAAAAAA")
	}
	if link.Provider != "feishu" {
		t.Errorf("Provider = %q, want %q", link.Provider, "feishu")
	}
	if link.ProviderTenantID != "tenant_feishu_001" {
		t.Errorf("ProviderTenantID = %q, want %q", link.ProviderTenantID, "tenant_feishu_001")
	}
	if link.ProviderSubject != "feishu_subject_abc123" {
		t.Errorf("ProviderSubject = %q, want %q", link.ProviderSubject, "feishu_subject_abc123")
	}
	if !link.CreatedAt.Equal(created) {
		t.Errorf("CreatedAt = %v, want %v", link.CreatedAt, created)
	}
	if !link.LastSeenAt.Equal(lastSeen) {
		t.Errorf("LastSeenAt = %v, want %v", link.LastSeenAt, lastSeen)
	}
}

func TestScanIdentityLink_EmptyTenantID(t *testing.T) {
	// Some providers do not expose a tenant concept; ProviderTenantID is
	// stored as an empty string in that case.
	row := &fakeRow{
		values: []any{
			"link_empty_tenant",
			"user_empty_tenant",
			"google",
			"",
			"google_sub_999",
			time.Now().UTC(),
			time.Now().UTC(),
		},
	}

	link, err := scanIdentityLink(row)
	if err != nil {
		t.Fatalf("scanIdentityLink returned error: %v", err)
	}

	if link.ProviderTenantID != "" {
		t.Errorf("ProviderTenantID = %q, want empty string", link.ProviderTenantID)
	}
	if link.Provider != "google" {
		t.Errorf("Provider = %q, want %q", link.Provider, "google")
	}
}

func TestScanIdentityLink_ReturnsErrNoRows(t *testing.T) {
	row := &fakeRow{err: pgx.ErrNoRows}

	_, err := scanIdentityLink(row)
	if err == nil {
		t.Fatal("scanIdentityLink returned nil error, expected pgx.ErrNoRows")
	}
	if !errors.Is(err, pgx.ErrNoRows) {
		t.Errorf("scanIdentityLink error = %v, expected pgx.ErrNoRows", err)
	}
}

func TestMapUserError_TranslatesErrNoRows(t *testing.T) {
	err := mapUserError(pgx.ErrNoRows, "test op")
	if !errors.Is(err, identity.ErrUserNotFound) {
		t.Errorf("mapUserError(pgx.ErrNoRows) = %v, want identity.ErrUserNotFound", err)
	}
}

func TestMapUserError_WrapsOtherErrors(t *testing.T) {
	original := fmt.Errorf("connection refused")
	err := mapUserError(original, "test op")

	if !errors.Is(err, original) {
		t.Errorf("mapUserError should wrap original error, got %v", err)
	}
	// A non-ErrNoRows error must NOT be silently translated to
	// ErrUserNotFound. This guards against overly broad error mapping.
	if errors.Is(err, identity.ErrUserNotFound) {
		t.Errorf("mapUserError should not translate non-ErrNoRows errors to ErrUserNotFound, got %v", err)
	}
}
