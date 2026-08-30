//
// Copyright (c) 2026 Chen Jiajie(Ariakage)
//
// Author: Chen Jiajie(Ariakage) <ariakage233@gmail.com>
// Date: 2026-08-11
// Description: Phase 8 privacy-rights service and durable workers
//

package privacy

import (
	"context"
	"encoding/json"
	"errors"
	"log/slog"
	"strings"
	"sync"
	"time"

	"github.com/GravelEvolution/united-pass/backend/internal/identity"
)

const (
	ExportTTL       = 15 * time.Minute
	DeletionCooling = 30 * 24 * time.Hour
	exportTimeout   = 2 * time.Minute
	deletionTimeout = 30 * time.Second
)

type SupportedLegalDocument struct {
	Kind          string
	Version       string
	ContentSHA256 string
}

var supportedLegalDocuments = map[string]SupportedLegalDocument{
	"privacy": {Kind: "privacy", Version: "1.2", ContentSHA256: "4cda76af14c0eba4324feb26d45f9e39a8f44e0567f56034d3f97c9b34283703"},
	"terms":   {Kind: "terms", Version: "1.1", ContentSHA256: "d277370701594a556be7d53a965c9d87ef7825296e7f647af2d46451dc3e24fb"},
}

func SupportedDocument(kind string) (SupportedLegalDocument, bool) {
	document, ok := supportedLegalDocuments[kind]
	return document, ok
}

type ProviderAccountDeleter interface {
	DeleteProviderUser(context.Context, string) error
}

type SessionCleaner interface {
	RevokeAllUserSessionsByAdmin(context.Context, identity.UserID) (int, string, error)
}

type Service struct {
	repo      Repository
	provider  ProviderAccountDeleter
	sessions  SessionCleaner
	logger    *slog.Logger
	now       func() time.Time
	exportTTL time.Duration
	cooling   time.Duration
}

func NewService(repo Repository, provider ProviderAccountDeleter, sessions SessionCleaner, logger *slog.Logger) *Service {
	if logger == nil {
		logger = slog.Default()
	}
	return &Service{repo: repo, provider: provider, sessions: sessions, logger: logger,
		now: func() time.Time { return time.Now().UTC() }, exportTTL: ExportTTL, cooling: DeletionCooling}
}

func (s *Service) BeginExport(ctx context.Context, user identity.UserID, requestID string) (Export, error) {
	if user == "" {
		return Export{}, ErrValidation
	}
	return s.repo.BeginExport(ctx, user, requestID)
}

func (s *Service) GetExport(ctx context.Context, user identity.UserID, id ExportID) (Export, error) {
	if !validPrefixedID(string(id), "pexp_") {
		return Export{}, ErrNotFound
	}
	result, err := s.repo.GetExport(ctx, id)
	if err != nil {
		return Export{}, err
	}
	if result.UserID != user {
		return Export{}, ErrNotFound
	}
	if result.Status == "completed" && result.ExpiresAt != nil && s.now().Before(*result.ExpiresAt) {
		url := "/api/v1/me/data-exports/" + string(id) + "/download"
		result.DownloadURL = &url
	}
	return result, nil
}

func (s *Service) Download(ctx context.Context, user identity.UserID, id ExportID) ([]byte, error) {
	result, err := s.GetExport(ctx, user, id)
	if err != nil {
		return nil, err
	}
	if result.Status != "completed" {
		return nil, ErrNotReady
	}
	if result.ExpiresAt == nil || !s.now().Before(*result.ExpiresAt) || len(result.Content) == 0 {
		return nil, ErrExpired
	}
	return result.Content, nil
}

func (s *Service) GetDeletion(ctx context.Context, user identity.UserID) (*Deletion, error) {
	return s.repo.GetDeletion(ctx, user)
}

func (s *Service) RequestDeletion(ctx context.Context, user identity.UserID, requestID string) (Deletion, error) {
	if user == "" {
		return Deletion{}, ErrValidation
	}
	return s.repo.RequestDeletion(ctx, user, requestID, s.now().Add(s.cooling))
}

func (s *Service) CancelDeletion(ctx context.Context, user identity.UserID, requestID string) (Deletion, error) {
	return s.repo.CancelDeletion(ctx, user, requestID)
}

func (s *Service) ListLegalPublications(ctx context.Context) ([]LegalPublication, error) {
	return s.repo.ListLegalPublications(ctx)
}

func (s *Service) PublishLegalDocument(ctx context.Context, input LegalPublicationInput) (LegalPublication, error) {
	supported, ok := SupportedDocument(input.DocumentKind)
	if !ok || input.Version != supported.Version || input.ContentSHA256 != supported.ContentSHA256 ||
		input.PublishedBy == "" || strings.TrimSpace(input.ApprovalReference) == "" ||
		strings.TrimSpace(input.ApprovedBy) == "" || input.EffectiveAt.IsZero() {
		return LegalPublication{}, ErrValidation
	}
	return s.repo.PublishLegalDocument(ctx, input)
}

func validPrefixedID(value, prefix string) bool {
	return strings.HasPrefix(value, prefix) && len(value) > len(prefix)+12 && len(value) < 80
}

type Worker struct {
	service    *Service
	interval   time.Duration
	batch      int
	stop, done chan struct{}
	once       sync.Once
}

func NewWorker(service *Service, interval time.Duration, batch int) *Worker {
	return &Worker{service: service, interval: interval, batch: batch,
		stop: make(chan struct{}), done: make(chan struct{})}
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
	w.runExports()
	w.runDeletions()
}

func (w *Worker) runExports() {
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	jobs, err := w.service.repo.ClaimExports(ctx, w.batch)
	cancel()
	if err != nil {
		w.service.logger.Error("claim personal data exports", "error", err)
		return
	}
	for _, job := range jobs {
		w.runExport(job)
	}
}

func (w *Worker) runExport(job Export) {
	ctx, cancel := context.WithTimeout(context.Background(), exportTimeout)
	defer cancel()
	document, err := w.service.repo.BuildExportDocument(ctx, job.UserID, w.service.now())
	if err != nil {
		_ = w.service.repo.FailExport(context.WithoutCancel(ctx), job.ExportID, "storage")
		return
	}
	content, err := json.MarshalIndent(document, "", "  ")
	if err != nil {
		_ = w.service.repo.FailExport(context.WithoutCancel(ctx), job.ExportID, "encoding")
		return
	}
	content = append(content, '\n')
	sections := 5
	if len(document.ProviderDirectoryProfiles) > 0 {
		sections++
	}
	if document.Employee != nil {
		sections++
	}
	if document.Deletion != nil {
		sections++
	}
	if err := w.service.repo.CompleteExport(ctx, job.ExportID, content, sections, w.service.now().Add(w.service.exportTTL)); err != nil {
		w.service.logger.Error("complete personal data export", "error", err, "exportId", job.ExportID)
	}
}

func (w *Worker) runDeletions() {
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	jobs, err := w.service.repo.ClaimDeletions(ctx, w.batch)
	cancel()
	if err != nil {
		w.service.logger.Error("claim account deletions", "error", err)
		return
	}
	for _, job := range jobs {
		w.runDeletion(job)
	}
}

func (w *Worker) runDeletion(job Deletion) {
	ctx, cancel := context.WithTimeout(context.Background(), deletionTimeout)
	defer cancel()
	if job.Status != "provider_deleted" {
		if w.service.provider == nil || job.ProviderSubject == "" {
			_ = w.service.repo.FailDeletionAttempt(context.WithoutCancel(ctx), job.DeletionID, "provider_configuration")
			return
		}
		if err := w.service.provider.DeleteProviderUser(ctx, job.ProviderSubject); err != nil && !errors.Is(err, ErrNotFound) {
			_ = w.service.repo.FailDeletionAttempt(context.WithoutCancel(ctx), job.DeletionID, "provider")
			return
		}
		if err := w.service.repo.MarkProviderDeleted(ctx, job.DeletionID); err != nil {
			w.service.logger.Error("persist provider deletion proof", "error", err, "deletionId", job.DeletionID)
			return
		}
	}
	if w.service.sessions != nil {
		if _, _, err := w.service.sessions.RevokeAllUserSessionsByAdmin(ctx, job.UserID); err != nil {
			w.service.logger.Warn("purge deleted account sessions", "error", err, "deletionId", job.DeletionID)
			_ = w.service.repo.FailDeletionAttempt(context.WithoutCancel(ctx), job.DeletionID, "session")
			return
		}
	}
	if err := w.service.repo.CompleteDeletion(ctx, job.DeletionID); err != nil {
		w.service.logger.Error("complete local account anonymisation", "error", err, "deletionId", job.DeletionID)
		_ = w.service.repo.FailDeletionAttempt(context.WithoutCancel(ctx), job.DeletionID, "storage")
	}
}
