//
// Copyright (c) 2026 Chen Jiajie(Ariakage)
//
// Author: Chen Jiajie(Ariakage) <ariakage233@gmail.com>
// Date: 2026-08-11
// Description: Audit filtering, redacted CSV export and export worker
//

package audit

import (
	"bytes"
	"context"
	"encoding/csv"
	"fmt"
	"log/slog"
	"strings"
	"sync"
	"time"

	"github.com/GravelEvolution/united-pass/backend/internal/identity"
)

const MaxExportEvents = 10000

const exportAttemptTimeout = 2 * time.Minute

type Service struct {
	repo   Repository
	logger *slog.Logger
	now    func() time.Time
	ttl    time.Duration
}

func NewService(repo Repository, ttl time.Duration, logger *slog.Logger) *Service {
	if logger == nil {
		logger = slog.Default()
	}
	return &Service{repo: repo, logger: logger, now: func() time.Time { return time.Now().UTC() }, ttl: ttl}
}

func (s *Service) List(ctx context.Context, query Query) (Page, error) {
	if query.Limit == 0 {
		query.Limit = 50
	}
	if err := ValidateQuery(query); err != nil {
		return Page{}, err
	}
	return s.repo.List(ctx, query)
}

func (s *Service) CreateExport(ctx context.Context, actor identity.UserID, requestID string, query Query) (Export, error) {
	query.Cursor = ""
	query.Limit = 0
	if err := ValidateQuery(query); err != nil {
		return Export{}, err
	}
	return s.repo.CreateExport(ctx, actor, requestID, query)
}

func (s *Service) GetExport(ctx context.Context, id ExportID) (Export, error) {
	if !strings.HasPrefix(string(id), "exp_") {
		return Export{}, ErrNotFound
	}
	export, err := s.repo.GetExport(ctx, id)
	if err != nil {
		return Export{}, err
	}
	if export.Status == "completed" && export.ExpiresAt != nil && s.now().Before(*export.ExpiresAt) {
		url := "/api/v1/admin/audit-exports/" + string(id) + "/download"
		export.DownloadURL = &url
	}
	return export, nil
}

func (s *Service) Download(ctx context.Context, id ExportID) ([]byte, error) {
	export, err := s.repo.GetExport(ctx, id)
	if err != nil {
		return nil, err
	}
	if export.Status != "completed" {
		return nil, ErrNotReady
	}
	if export.ExpiresAt == nil || s.now().After(*export.ExpiresAt) {
		return nil, ErrExpired
	}
	return export.Content, nil
}

func (s *Service) RecordAuthorizationDenied(ctx context.Context, actor identity.UserID, action, requestID string) {
	if err := s.repo.RecordAuthorizationDenied(ctx, actor, action, requestID); err != nil {
		s.logger.Error("persist audit authorization denial", "error", err, "requestId", requestID)
	}
}

func ValidateQuery(query Query) error {
	if query.Limit < 0 || query.Limit > 100 || len(query.Cursor) > 512 || len(query.Query) > 200 || len(query.EventType) > 120 || len(query.ActorName) > 120 || len(query.RequestID) > 200 {
		return ErrValidation
	}
	if query.Result != "" && query.Result != "success" && query.Result != "denied" {
		return ErrValidation
	}
	if query.From != nil && query.To != nil && query.From.After(*query.To) {
		return ErrValidation
	}
	return nil
}

type Worker struct {
	service    *Service
	interval   time.Duration
	batch      int
	stop, done chan struct{}
	once       sync.Once
}

func NewWorker(service *Service, interval time.Duration, batch int) *Worker {
	return &Worker{service: service, interval: interval, batch: batch, stop: make(chan struct{}), done: make(chan struct{})}
}
func (w *Worker) Start() {
	go func() {
		defer close(w.done)
		w.run()
		ticker := time.NewTicker(w.interval)
		defer ticker.Stop()
		for {
			select {
			case <-ticker.C:
				w.run()
			case <-w.stop:
				return
			}
		}
	}()
}
func (w *Worker) Stop() { w.once.Do(func() { close(w.stop); <-w.done }) }
func (w *Worker) run() {
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	jobs, err := w.service.repo.ClaimExports(ctx, w.batch)
	cancel()
	if err != nil {
		w.service.logger.Error("claim audit exports", "error", err)
		return
	}
	for _, job := range jobs {
		w.runJob(job)
	}
}

func (w *Worker) runJob(job Export) {
	ctx, cancel := context.WithTimeout(context.Background(), exportAttemptTimeout)
	defer cancel()
	events, err := w.service.repo.ListForExport(ctx, job.Query, MaxExportEvents)
	if err != nil {
		_ = w.service.repo.FailExport(context.WithoutCancel(ctx), job.ExportID, "storage")
		return
	}
	content, err := encodeCSV(events)
	if err != nil {
		_ = w.service.repo.FailExport(context.WithoutCancel(ctx), job.ExportID, "encoding")
		return
	}
	if err := w.service.repo.CompleteExport(ctx, job.ExportID, content, len(events), w.service.now().Add(w.service.ttl)); err != nil {
		w.service.logger.Error("complete audit export", "error", err, "exportId", job.ExportID)
	}
}

func encodeCSV(events []Event) ([]byte, error) {
	var buffer bytes.Buffer
	buffer.Write([]byte{0xEF, 0xBB, 0xBF})
	writer := csv.NewWriter(&buffer)
	if err := writer.Write([]string{"event_id", "event_type", "actor_name", "actor_id", "target", "target_id", "result", "request_id", "occurred_at", "details"}); err != nil {
		return nil, err
	}
	for _, event := range events {
		row := []string{event.EventID, event.EventType, event.ActorName, event.ActorID, event.TargetLabel, event.TargetID, event.Result, event.RequestID, event.OccurredAt.UTC().Format(time.RFC3339Nano), event.Details}
		for index := range row {
			row[index] = spreadsheetSafe(row[index])
		}
		if err := writer.Write(row); err != nil {
			return nil, err
		}
	}
	writer.Flush()
	if err := writer.Error(); err != nil {
		return nil, fmt.Errorf("audit CSV: %w", err)
	}
	return buffer.Bytes(), nil
}

// spreadsheetSafe prevents fields controlled by names or labels from being
// interpreted as formulas when an operator opens the CSV in a spreadsheet.
func spreadsheetSafe(value string) string {
	if value == "" {
		return value
	}
	switch value[0] {
	case '=', '+', '-', '@', '\t', '\r':
		return "'" + value
	default:
		return value
	}
}
