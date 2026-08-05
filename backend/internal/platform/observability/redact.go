// Package observability also provides error classification and redaction
// helpers for structured logging. Dependency errors may embed internal URLs,
// hostnames, or connection parameters, so raw error messages must never reach
// operational logs verbatim. Logs record a stable error class; a redacted
// detail string is safe for debug-level output.
package observability

import (
	"context"
	"errors"
	"net"
	"regexp"
)

// ErrorClass is a stable, non-sensitive classification of an error.
type ErrorClass string

const (
	// ErrorClassContext covers cancelled and deadline-exceeded contexts.
	ErrorClassContext ErrorClass = "context"
	// ErrorClassTimeout covers network-level timeouts.
	ErrorClassTimeout ErrorClass = "timeout"
	// ErrorClassNetwork covers connection failures, refused connections and
	// other transport errors.
	ErrorClassNetwork ErrorClass = "network"
	// ErrorClassInternal is the fallback for anything else.
	ErrorClassInternal ErrorClass = "internal"
)

// ClassifyError maps an error to a stable class. It never returns the raw
// error message, so internal hostnames, URLs, or credentials in the wrapped
// error text cannot leak into logs.
func ClassifyError(err error) ErrorClass {
	if err == nil {
		return ErrorClassInternal
	}
	if errors.Is(err, context.Canceled) || errors.Is(err, context.DeadlineExceeded) {
		return ErrorClassContext
	}
	var netErr net.Error
	if errors.As(err, &netErr) {
		if netErr.Timeout() {
			return ErrorClassTimeout
		}
		return ErrorClassNetwork
	}
	return ErrorClassInternal
}

var redactionPatterns = []*regexp.Regexp{
	// URL credentials: scheme://user:pass@host
	regexp.MustCompile(`(://)[^/\s@]+@`),
	// Full URLs
	regexp.MustCompile(`https?://[^\s"']+`),
	// IPv4 addresses with optional port
	regexp.MustCompile(`\b\d{1,3}(?:\.\d{1,3}){3}(?::\d+)?\b`),
}

// RedactedError returns a sanitized version of the error message suitable for
// debug-level logging. URLs, embedded credentials, and IP addresses are
// stripped; the result is truncated to maxLen characters (0 disables
// truncation). The caller must not log the raw error.Error().
func RedactedError(err error, maxLen int) string {
	if err == nil {
		return ""
	}
	msg := err.Error()
	for _, re := range redactionPatterns {
		msg = re.ReplaceAllString(msg, "[redacted]")
	}
	if maxLen > 0 && len(msg) > maxLen {
		msg = msg[:maxLen] + "..."
	}
	return msg
}
