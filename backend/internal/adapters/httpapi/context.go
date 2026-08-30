//
// Copyright (c) 2026 Chen Jiajie(Ariakage)
//
// Author: Chen Jiajie(Ariakage) <ariakage233@gmail.com>
// Date: 2026-08-05
// Description: Request context helpers for the principal and session record
//

package httpapi

import (
	"context"

	"github.com/GravelEvolution/united-pass/backend/internal/session"
)

type contextKey int

const (
	principalKey contextKey = iota
	sessionRecordKey
	sessionTokenKey
	nativeBearerSessionKey
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

// WithSessionToken stores the raw request credential only for the lifetime of
// this request. It is needed by logout and password-rotation handlers; it must
// never be logged, serialized or persisted outside the session store's hash.
func WithSessionToken(ctx context.Context, token string) context.Context {
	return context.WithValue(ctx, sessionTokenKey, token)
}

// SessionTokenFromContext returns the credential validated by RequireSession.
func SessionTokenFromContext(ctx context.Context) (string, bool) {
	token, ok := ctx.Value(sessionTokenKey).(string)
	return token, ok && token != ""
}

// WithNativeBearerSession marks a request authenticated by the explicit
// native Mini Program bearer transport. Only RequireSession may set it after
// both request-shape and stored ClientKind validation have succeeded.
func WithNativeBearerSession(ctx context.Context) context.Context {
	return context.WithValue(ctx, nativeBearerSessionKey, true)
}

// IsNativeBearerSession reports whether RequireSession authenticated the
// request through the native bearer contract.
func IsNativeBearerSession(ctx context.Context) bool {
	native, _ := ctx.Value(nativeBearerSessionKey).(bool)
	return native
}
