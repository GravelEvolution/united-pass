package identityaccess_test

import (
	"testing"

	"github.com/GravelEvolution/united-pass/backend/internal/adminpagination"
	"github.com/GravelEvolution/united-pass/backend/internal/identity"
	"github.com/GravelEvolution/united-pass/backend/internal/identityaccess"
)

func TestRequestValidationRestrictsTargetsFieldsAndActors(t *testing.T) {
	valid := identityaccess.Request{
		EventID:       "evt_shanghai",
		RequesterID:   identity.UserID("user_reviewer"),
		TargetSubject: identity.UserID("user_candidate"),
		TargetType:    identityaccess.TargetApplication,
		TargetID:      "app_1",
		Fields:        []identityaccess.Field{identityaccess.FieldLegalName, identityaccess.FieldIdentityPhoto},
	}
	if err := identityaccess.ValidateRequest(valid); err != nil {
		t.Fatalf("valid request rejected: %v", err)
	}

	tests := []struct {
		name string
		edit func(*identityaccess.Request)
	}{
		{"requester cannot target self", func(r *identityaccess.Request) { r.TargetSubject = r.RequesterID }},
		{"unknown target type", func(r *identityaccess.Request) { r.TargetType = identityaccess.TargetType("user") }},
		{"unknown field", func(r *identityaccess.Request) { r.Fields = []identityaccess.Field{"answers_json"} }},
		{"empty fields", func(r *identityaccess.Request) { r.Fields = nil }},
		{"duplicate fields", func(r *identityaccess.Request) {
			r.Fields = []identityaccess.Field{identityaccess.FieldLegalName, identityaccess.FieldLegalName}
		}},
		{"missing event", func(r *identityaccess.Request) { r.EventID = "" }},
		{"missing target", func(r *identityaccess.Request) { r.TargetID = "" }},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			candidate := valid
			candidate.Fields = append([]identityaccess.Field(nil), valid.Fields...)
			tt.edit(&candidate)
			if err := identityaccess.ValidateRequest(candidate); err == nil {
				t.Fatal("invalid request accepted")
			}
		})
	}
}

func TestEventOwnedListsRequireExactEventScopeAndDistinctKinds(t *testing.T) {
	own := adminpagination.Query{ScopeKind: "event", EventID: "evt_shanghai", ListKind: identityaccess.ListKindOwn}
	if err := identityaccess.ValidateOwnListQuery(own); err != nil {
		t.Fatalf("valid own-list query rejected: %v", err)
	}
	queue := adminpagination.Query{ScopeKind: "event", EventID: "evt_shanghai", ListKind: identityaccess.ListKindApprovalQueue}
	if err := identityaccess.ValidateApprovalListQuery(queue); err != nil {
		t.Fatalf("valid approval-list query rejected: %v", err)
	}

	if err := identityaccess.ValidateApprovalListQuery(own); err == nil {
		t.Fatal("own-list cursor context accepted by approval queue")
	}
	if err := identityaccess.ValidateOwnListQuery(queue); err == nil {
		t.Fatal("approval-list cursor context accepted by own list")
	}
	for _, query := range []adminpagination.Query{
		{ScopeKind: "event", ListKind: identityaccess.ListKindOwn},
		{ScopeKind: "system", ListKind: identityaccess.ListKindOwn},
		{ScopeKind: "event", EventID: "evt_shanghai", ListKind: "roles"},
	} {
		if err := identityaccess.ValidateOwnListQuery(query); err == nil {
			t.Fatalf("unscoped/mismatched query accepted: %+v", query)
		}
	}
}

func TestDecisionRequiresDistinctApproverAndTarget(t *testing.T) {
	req := identityaccess.Request{
		RequesterID:   identity.UserID("user_requester"),
		TargetSubject: identity.UserID("user_target"),
	}
	if err := identityaccess.ValidateDecision(req, identityaccess.Decision{ApproverID: identity.UserID("user_super"), Approved: true}); err != nil {
		t.Fatalf("valid decision rejected: %v", err)
	}
	for _, approver := range []identity.UserID{req.RequesterID, req.TargetSubject, ""} {
		if err := identityaccess.ValidateDecision(req, identityaccess.Decision{ApproverID: approver, Approved: true}); err == nil {
			t.Fatalf("approver %q accepted", approver)
		}
	}
}

func TestDecisionAuditActorMustBeApprover(t *testing.T) {
	decision := identityaccess.Decision{ApproverID: "user_super", Approved: true}
	if err := identityaccess.ValidateDecisionAudit(decision, identityaccess.Audit{ActorID: "user_super", ReasonID: "reason_1", RequestID: "req_1", Action: "identity_access.decide"}); err != nil {
		t.Fatalf("matching audit rejected: %v", err)
	}
	if err := identityaccess.ValidateDecisionAudit(decision, identityaccess.Audit{ActorID: "user_other", ReasonID: "reason_1", RequestID: "req_1", Action: "identity_access.decide"}); err == nil {
		t.Fatal("different audit actor accepted")
	}
}
