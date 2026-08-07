//
// Copyright (c) 2026 Chen Jiajie(Ariakage)
//
// Author: Chen Jiajie(Ariakage) <ariakage233@gmail.com>
// Date: 2026-08-05
// Description: Liveness probe handler
//

package httpapi

import (
	"context"
	"encoding/json"
	"net/http"
)

// ReadinessChecker reports whether a dependency is ready to serve traffic.
// Phase 0 has no external dependencies; checkers are registered in later phases
// as database, Cerbos and Provider adapters come online.
type ReadinessChecker interface {
	Name() string
	Check(ctx context.Context) error
}

// HealthHandlers serves the operational health and readiness endpoints. It
// intentionally exposes no dependency details publicly.
type HealthHandlers struct {
	checkers []ReadinessChecker
}

// NewHealthHandlers builds a HealthHandlers with the given readiness checkers.
// nil checkers are ignored so later phases can register optional dependencies.
func NewHealthHandlers(checkers ...ReadinessChecker) *HealthHandlers {
	cleaned := make([]ReadinessChecker, 0, len(checkers))
	for _, c := range checkers {
		if c != nil {
			cleaned = append(cleaned, c)
		}
	}
	return &HealthHandlers{checkers: cleaned}
}

// Healthz reports only that the process is alive and able to respond. It must
// not depend on downstream services so it stays useful during outages.
func (h *HealthHandlers) Healthz(w http.ResponseWriter, r *http.Request) {
	writeJSON(w, http.StatusOK, map[string]string{"status": "ok"})
}

// Readyz reports whether the process is ready to serve traffic. Every
// registered checker must succeed. Failures return 503 without leaking
// dependency internals.
func (h *HealthHandlers) Readyz(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		WriteBadRequest(w, r, "方法不被允许。")
		return
	}

	for _, c := range h.checkers {
		if err := c.Check(r.Context()); err != nil {
			writeJSON(w, http.StatusServiceUnavailable, map[string]string{"status": "not ready"})
			return
		}
	}

	writeJSON(w, http.StatusOK, map[string]string{"status": "ready"})
}

func writeJSON(w http.ResponseWriter, status int, body any) {
	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(body)
}
