package postgres

import (
	"errors"
	"testing"

	"github.com/jackc/pgx/v5/pgconn"

	"github.com/GravelEvolution/united-pass/backend/internal/registration"
)

func TestRegistrationPhoneConflictPreservesGenericConflictClass(t *testing.T) {
	if !errors.Is(registration.ErrPhoneConflict, registration.ErrConflict) {
		t.Fatal("phone conflict must remain compatible with generic registration conflict handlers")
	}
}

func TestIsPhoneUniqueViolationDoesNotMisclassifyOtherAuthorityRaces(t *testing.T) {
	for _, test := range []struct {
		name string
		err  error
		want bool
	}{
		{name: "phone constraint", err: &pgconn.PgError{Code: "23505", ConstraintName: "users_phone_key"}, want: true},
		{name: "phone detail", err: &pgconn.PgError{Code: "23505", Detail: "Key (phone) already exists."}, want: true},
		{name: "user id constraint", err: &pgconn.PgError{Code: "23505", ConstraintName: "users_pkey"}},
		{name: "identity link constraint", err: &pgconn.PgError{Code: "23505", ConstraintName: "identity_links_provider_subject_key"}},
		{name: "not unique", err: &pgconn.PgError{Code: "40001", ConstraintName: "users_phone_key"}},
	} {
		t.Run(test.name, func(t *testing.T) {
			if got := isPhoneUniqueViolation(test.err); got != test.want {
				t.Fatalf("isPhoneUniqueViolation(%v) = %v, want %v", test.err, got, test.want)
			}
		})
	}
}
