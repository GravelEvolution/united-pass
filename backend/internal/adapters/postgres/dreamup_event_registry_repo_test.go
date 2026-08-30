package postgres

import (
	"errors"
	"testing"
	"time"

	"github.com/GravelEvolution/united-pass/backend/internal/adminroles"
)

func TestValidateRegisteredEventReplacementRequiresImmutableExactReadback(t *testing.T) {
	now := time.Date(2026, 8, 17, 9, 0, 0, 0, time.UTC)
	current := adminroles.RegisteredEvent{EventID: "evt_shanghai", Series: "dreamup", Slug: "shanghai-2026", SourceVersion: "v1", AuthoritativeReadAt: now, Enabled: true, Version: 3}
	next := current
	next.DisplayName = "DreamUP 上海站"
	next.SourceVersion = "v2"
	next.AuthoritativeReadAt = now.Add(time.Minute)
	if err := validateRegisteredEventReplacement(current, next); err != nil {
		t.Fatalf("valid replacement rejected: %v", err)
	}

	tests := []struct {
		name string
		edit func(*adminroles.RegisteredEvent)
	}{
		{"event id", func(e *adminroles.RegisteredEvent) { e.EventID = "evt_other" }},
		{"series", func(e *adminroles.RegisteredEvent) { e.Series = "beijing" }},
		{"slug", func(e *adminroles.RegisteredEvent) { e.Slug = "other" }},
		{"stale readback", func(e *adminroles.RegisteredEvent) { e.AuthoritativeReadAt = now }},
		{"stale version", func(e *adminroles.RegisteredEvent) { e.SourceVersion = "v1" }},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			candidate := next
			tt.edit(&candidate)
			if err := validateRegisteredEventReplacement(current, candidate); !errors.Is(err, adminroles.ErrEventRegistryConflict) {
				t.Fatalf("error=%v", err)
			}
		})
	}
}

func TestValidateRegisteredEventFailsClosedForNonDreamUPSeries(t *testing.T) {
	if err := validateRegisteredEvent(adminroles.RegisteredEvent{EventID: "evt_a", Series: "beijing", Slug: "same", SourceVersion: "v1", AuthoritativeReadAt: time.Now(), Version: 1}); !errors.Is(err, adminroles.ErrInvalidRegisteredEvent) {
		t.Fatalf("error=%v", err)
	}
}

func TestPrepareNewRegisteredEventSetsInitialVersion(t *testing.T) {
	event := adminroles.RegisteredEvent{EventID: "evt_a", Series: "dreamup", Slug: "shanghai", SourceVersion: "source-v1", AuthoritativeReadAt: time.Now()}
	prepared := prepareNewRegisteredEvent(event)
	if prepared.Version != 1 {
		t.Fatalf("version=%d, want 1", prepared.Version)
	}
}
