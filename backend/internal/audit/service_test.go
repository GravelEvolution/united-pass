package audit

import (
	"context"
	"io"
	"log/slog"
	"strings"
	"testing"
	"time"

	"github.com/GravelEvolution/united-pass/backend/internal/identity"
)

type auditRepoStub struct {
	export    Export
	events    []Event
	completed chan struct{}
	content   []byte
}

func (r *auditRepoStub) List(context.Context, Query) (Page, error) { return Page{}, nil }
func (r *auditRepoStub) ListForExport(context.Context, Query, int) ([]Event, error) {
	return r.events, nil
}
func (r *auditRepoStub) CreateExport(context.Context, identity.UserID, string, Query) (Export, error) {
	return r.export, nil
}
func (r *auditRepoStub) GetExport(context.Context, ExportID) (Export, error) { return r.export, nil }
func (r *auditRepoStub) ClaimExports(context.Context, int) ([]Export, error) {
	if r.export.ExportID == "" {
		return nil, nil
	}
	job := r.export
	r.export.ExportID = ""
	return []Export{job}, nil
}
func (r *auditRepoStub) CompleteExport(_ context.Context, _ ExportID, content []byte, _ int, _ time.Time) error {
	r.content = content
	if r.completed != nil {
		close(r.completed)
	}
	return nil
}
func (r *auditRepoStub) FailExport(context.Context, ExportID, string) error { return nil }
func (r *auditRepoStub) RecordAuthorizationDenied(context.Context, identity.UserID, string, string) error {
	return nil
}

func testAuditService(repo Repository) *Service {
	return NewService(repo, 15*time.Minute, slog.New(slog.NewTextHandler(io.Discard, nil)))
}

func TestValidateQueryRejectsInvalidRangeAndResult(t *testing.T) {
	from := time.Unix(2, 0)
	to := time.Unix(1, 0)
	if ValidateQuery(Query{From: &from, To: &to}) == nil {
		t.Fatal("reverse range accepted")
	}
	if ValidateQuery(Query{Result: "maybe"}) == nil {
		t.Fatal("unknown result accepted")
	}
}

func TestDownloadRequiresCompletedUnexpiredOwnerArtifact(t *testing.T) {
	now := time.Unix(100, 0).UTC()
	expires := now.Add(time.Minute)
	repo := &auditRepoStub{export: Export{ExportID: "exp_0123456789abcdef", Status: "completed", Content: []byte("csv"), ExpiresAt: &expires}}
	service := testAuditService(repo)
	service.now = func() time.Time { return now }
	content, err := service.Download(context.Background(), repo.export.ExportID)
	if err != nil || string(content) != "csv" {
		t.Fatalf("content=%q err=%v", content, err)
	}
	service.now = func() time.Time { return expires.Add(time.Second) }
	if _, err := service.Download(context.Background(), repo.export.ExportID); err != ErrExpired {
		t.Fatalf("err=%v", err)
	}
}

func TestWorkerBuildsRedactedFixedColumnCSV(t *testing.T) {
	done := make(chan struct{})
	repo := &auditRepoStub{completed: done, export: Export{ExportID: "exp_0123456789abcdef", Status: "pending", Query: Query{}}, events: []Event{{EventID: "evt_1", EventType: "policy.published", ActorName: "=HYPERLINK(\"https://example.invalid\")", ActorID: "user_1", TargetLabel: "policy_id", TargetID: "pol_1", Result: "success", RequestID: "req_1", OccurredAt: time.Unix(1, 0).UTC(), Details: "policy.publish"}}}
	worker := NewWorker(testAuditService(repo), time.Second, 1)
	worker.Start()
	defer worker.Stop()
	select {
	case <-done:
	case <-time.After(time.Second):
		t.Fatal("worker did not complete export")
	}
	csv := string(repo.content)
	if !strings.Contains(csv, "event_id,event_type,actor_name") || !strings.Contains(csv, "policy.published") {
		t.Fatalf("csv=%q", csv)
	}
	if strings.Contains(csv, `,"=HYPERLINK`) || !strings.Contains(csv, `'=HYPERLINK`) {
		t.Fatalf("CSV formula was not neutralized: %q", csv)
	}
	for _, forbidden := range []string{"password", "token", "cookie"} {
		if strings.Contains(strings.ToLower(csv), forbidden) {
			t.Fatalf("CSV contains forbidden field %q", forbidden)
		}
	}
}
