// Package request carries per-request values through the handler chain using
// context.Context. Keeping the context key in a dedicated subpackage prevents
// collisions and keeps chi-specific code out of shared helpers.
package request

import "context"

type contextKey struct{}

// idKey is the context key for the request ID.
var idKey = contextKey{}

// WithID stores the request ID in the context and returns the derived context.
func WithID(ctx context.Context, id string) context.Context {
	return context.WithValue(ctx, idKey, id)
}

// ID retrieves the request ID from the context. It returns an empty string when
// no ID has been set, which should only happen for requests that bypassed the
// RequestID middleware.
func ID(ctx context.Context) string {
	if v, ok := ctx.Value(idKey).(string); ok {
		return v
	}
	return ""
}
