package httpapi

import (
	"context"

	"github.com/GravelEvolution/united-pass/backend/internal/session"
)

type contextKey int

const (
	principalKey contextKey = iota
	sessionRecordKey
)

// WithPrincipal stores the authenticated principal in the request context.
// Handlers retrieve it via PrincipalFromContext.
func WithPrincipal(ctx context.Context, p session.Principal) context.Context {
	return context.WithValue(ctx, principalKey, p)
}

// PrincipalFromContext returns the principal placed by RequireSession or
// OptionalSession. Returns ok=false when no principal is present.
func PrincipalFromContext(ctx context.Context) (session.Principal, bool) {
	p, ok := ctx.Value(principalKey).(session.Principal)
	return p, ok
}

// WithSessionRecord stores the full session record in the context so CSRF
// middleware can validate the token hash without re-reading Redis.
func WithSessionRecord(ctx context.Context, r session.SessionRecord) context.Context {
	return context.WithValue(ctx, sessionRecordKey, r)
}

// SessionRecordFromContext returns the session record placed by RequireSession
// or OptionalSession. Returns ok=false when no record is present.
func SessionRecordFromContext(ctx context.Context) (session.SessionRecord, bool) {
	r, ok := ctx.Value(sessionRecordKey).(session.SessionRecord)
	return r, ok
}
