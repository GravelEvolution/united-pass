//
// Copyright (c) 2026 Chen Jiajie(Ariakage)
//
// Author: Chen Jiajie(Ariakage) <ariakage233@gmail.com>
// Date: 2026-08-05
// Description: Structured logging setup (log/slog)
//

// Package observability provides structured logging setup for the United Pass
// API service. Logging uses log/slog so structured fields flow consistently to
// logs, error responses and audit records.
package observability

import (
	"io"
	"log/slog"
	"os"
)

// NewLogger constructs a slog.Logger at the requested level. In development the
// handler emits human-readable text for readability; production uses JSON for
// machine consumption.
func NewLogger(level slog.Level, environment string, out io.Writer) *slog.Logger {
	if out == nil {
		out = os.Stdout
	}
	handlerOpts := &slog.HandlerOptions{Level: level}

	var handler slog.Handler
	if environment == "production" {
		handler = slog.NewJSONHandler(out, handlerOpts)
	} else {
		handler = slog.NewTextHandler(out, handlerOpts)
	}

	logger := slog.New(handler)
	return logger
}
