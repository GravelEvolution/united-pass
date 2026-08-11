//
// Copyright (c) 2026 Chen Jiajie(Ariakage)
// Date: 2026-08-11
// Description: Phase 8 privacy lifecycle orchestration tests
//

package privacy

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/GravelEvolution/united-pass/backend/internal/identity"
)

type fakeRepository struct {
	export            Export
	document          ExportDocument
	completedContent  []byte
	completedSections int
	legalInput        LegalPublicationInput
	sequence          []string
}

func (r *fakeRepository) BeginExport(context.Context, identity.UserID, string) (Export, error) {
	return r.export, nil
}
func (r *fakeRepository) GetExport(context.Context, ExportID) (Export, error) { return r.export, nil }
func (r *fakeRepository) ClaimExports(context.Context, int) ([]Export, error) { return nil, nil }
func (r *fakeRepository) BuildExportDocument(context.Context, identity.UserID, time.Time) (ExportDocument, error) {
	return r.document, nil
}
func (r *fakeRepository) CompleteExport(_ context.Context, _ ExportID, content []byte, sections int, _ time.Time) error {
	r.completedContent = content
	r.completedSections = sections
	return nil
}
func (r *fakeRepository) FailExport(context.Context, ExportID, string) error { return nil }
func (r *fakeRepository) GetDeletion(context.Context, identity.UserID) (*Deletion, error) {
	return nil, nil
}
func (r *fakeRepository) RequestDeletion(_ context.Context, user identity.UserID, _ string, execute time.Time) (Deletion, error) {
	return Deletion{DeletionID: "del_0123456789abcdef", UserID: user, Status: "pending", ExecuteAfter: execute}, nil
}
func (r *fakeRepository) CancelDeletion(context.Context, identity.UserID, string) (Deletion, error) {
	return Deletion{DeletionID: "del_0123456789abcdef", Status: "cancelled"}, nil
}
func (r *fakeRepository) ClaimDeletions(context.Context, int) ([]Deletion, error) { return nil, nil }
func (r *fakeRepository) MarkProviderDeleted(context.Context, DeletionID) error {
	r.sequence = append(r.sequence, "provider-proof")
	return nil
}
func (r *fakeRepository) CompleteDeletion(context.Context, DeletionID) error {
	r.sequence = append(r.sequence, "local-anonymisation")
	return nil
}
func (r *fakeRepository) FailDeletionAttempt(context.Context, DeletionID, string) error { return nil }
func (r *fakeRepository) ListLegalPublications(context.Context) ([]LegalPublication, error) {
	return nil, nil
}
func (r *fakeRepository) PublishLegalDocument(_ context.Context, input LegalPublicationInput) (LegalPublication, error) {
	r.legalInput = input
	return LegalPublication{DocumentKind: input.DocumentKind, Version: input.Version, ContentSHA256: input.ContentSHA256}, nil
}

type fakeProviderDeleter struct {
	sequence *[]string
	calls    int
}

func (d *fakeProviderDeleter) DeleteProviderUser(context.Context, string) error {
	d.calls++
	*d.sequence = append(*d.sequence, "provider-delete")
	return nil
}

type fakeSessionCleaner struct {
	sequence *[]string
	err      error
}

func (c *fakeSessionCleaner) RevokeAllUserSessionsByAdmin(context.Context, identity.UserID) (int, string, error) {
	*c.sequence = append(*c.sequence, "session-purge")
	return 1, "", c.err
}

func TestPublishLegalDocumentRequiresExactApprovedManifest(t *testing.T) {
	repo := &fakeRepository{}
	service := NewService(repo, nil, nil, nil)
	supported, ok := SupportedDocument("privacy")
	if !ok {
		t.Fatal("privacy manifest missing")
	}
	input := LegalPublicationInput{
		DocumentKind: "privacy", Version: supported.Version, ContentSHA256: "wrong",
		EffectiveAt: time.Now().UTC(), ApprovalReference: "LEGAL-42", ApprovedBy: "法务负责人",
		PublishedBy: "usr_1",
	}
	if _, err := service.PublishLegalDocument(context.Background(), input); !errors.Is(err, ErrValidation) {
		t.Fatalf("wrong digest: got %v, want validation", err)
	}
	input.ContentSHA256 = supported.ContentSHA256
	if _, err := service.PublishLegalDocument(context.Background(), input); err != nil {
		t.Fatalf("publish exact approved manifest: %v", err)
	}
	if repo.legalInput.ApprovalReference != "LEGAL-42" {
		t.Fatal("approval reference was not passed to durable repository")
	}
}

func TestSupportedLegalManifestMatchesExactFrontendSourceBytes(t *testing.T) {
	for kind, file := range map[string]string{
		"privacy": "privacy-sections.ts",
		"terms":   "terms-sections.ts",
	} {
		content, err := os.ReadFile(filepath.Join("..", "..", "..", "frontend", "src", "features", "legal", "data", file))
		if err != nil {
			t.Fatalf("read %s: %v", file, err)
		}
		digest := sha256.Sum256(content)
		supported, ok := SupportedDocument(kind)
		if !ok || hex.EncodeToString(digest[:]) != supported.ContentSHA256 {
			t.Fatalf("%s source changed without a reviewed manifest update", kind)
		}
	}
}

func TestGetExportIsOwnerBoundAndShortLived(t *testing.T) {
	now := time.Date(2026, 8, 11, 0, 0, 0, 0, time.UTC)
	expires := now.Add(time.Minute)
	repo := &fakeRepository{export: Export{
		ExportID: "pexp_0123456789abcdef", UserID: "usr_owner", Status: "completed",
		ExpiresAt: &expires, Content: []byte("{}"),
	}}
	service := NewService(repo, nil, nil, nil)
	service.now = func() time.Time { return now }
	result, err := service.GetExport(context.Background(), "usr_owner", repo.export.ExportID)
	if err != nil || result.DownloadURL == nil {
		t.Fatalf("owner export: result=%+v err=%v", result, err)
	}
	if _, err := service.GetExport(context.Background(), "usr_other", repo.export.ExportID); !errors.Is(err, ErrNotFound) {
		t.Fatalf("cross-user lookup: got %v, want not found", err)
	}
	service.now = func() time.Time { return expires }
	if _, err := service.Download(context.Background(), "usr_owner", repo.export.ExportID); !errors.Is(err, ErrExpired) {
		t.Fatalf("expired download: got %v, want expired", err)
	}
}

func TestWorkerBuildsBoundedExportDocument(t *testing.T) {
	repo := &fakeRepository{document: ExportDocument{
		SchemaVersion: "1.0", Profile: ExportProfile{UserID: "usr_owner", Email: "owner@example.com"},
		Personas: []string{"consumer"}, IdentityLinks: []ExportLink{},
		ProviderDirectoryProfiles: []ExportDirectoryProfile{}, Authorizations: []ExportGrant{},
	}}
	service := NewService(repo, nil, nil, nil)
	worker := NewWorker(service, time.Hour, 1)
	worker.runExport(Export{ExportID: "pexp_0123456789abcdef", UserID: "usr_owner"})
	if repo.completedSections != 5 {
		t.Fatalf("sections=%d, want 5", repo.completedSections)
	}
	content := string(repo.completedContent)
	if !strings.Contains(content, `"schemaVersion": "1.0"`) || strings.Contains(content, "password") || strings.Contains(content, "token") {
		t.Fatalf("unexpected export content: %s", content)
	}
}

func TestDeletionWaitsForSessionPurgeBeforeLocalAnonymisation(t *testing.T) {
	repo := &fakeRepository{}
	provider := &fakeProviderDeleter{sequence: &repo.sequence}
	sessions := &fakeSessionCleaner{sequence: &repo.sequence, err: errors.New("redis unavailable")}
	service := NewService(repo, provider, sessions, nil)
	worker := NewWorker(service, time.Hour, 1)
	job := Deletion{DeletionID: "del_0123456789abcdef", UserID: "usr_owner", ProviderSubject: "provider-user", Status: "processing"}
	worker.runDeletion(job)
	if got := strings.Join(repo.sequence, ","); got != "provider-delete,provider-proof,session-purge" {
		t.Fatalf("failure ordering=%q", got)
	}

	repo.sequence = nil
	sessions.err = nil
	job.Status = "provider_deleted"
	worker.runDeletion(job)
	if provider.calls != 1 {
		t.Fatalf("provider deletion calls=%d, want idempotent 1", provider.calls)
	}
	if got := strings.Join(repo.sequence, ","); got != "session-purge,local-anonymisation" {
		t.Fatalf("success ordering=%q", got)
	}
}
