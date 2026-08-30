package identityaccess

import (
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/base64"
	"errors"
	"reflect"
	"sort"
	"sync"
	"testing"
	"time"

	"github.com/GravelEvolution/united-pass/backend/internal/adminpagination"
	"github.com/GravelEvolution/united-pass/backend/internal/adminroles"
	"github.com/GravelEvolution/united-pass/backend/internal/adminstepup"
	"github.com/GravelEvolution/united-pass/backend/internal/auth"
	"github.com/GravelEvolution/united-pass/backend/internal/identity"
	"github.com/GravelEvolution/united-pass/backend/internal/permissions"
)

var identityAccessTestNow = time.Date(2026, 8, 17, 8, 0, 0, 0, time.UTC)

type accessAuthorizerStub struct {
	decisions map[permissions.Action]permissions.Decision
	err       error
}

func (a accessAuthorizerStub) Check(_ context.Context, _ identity.UserID, action permissions.Action, _ permissions.Resource) (permissions.Decision, error) {
	return a.decisions[action], a.err
}

type accessTargetValidatorStub struct {
	subject identity.UserID
	err     error
}

func (v accessTargetValidatorStub) ValidateIdentityTarget(_ context.Context, _ string, target TargetRef, _ []Field) (TargetValidation, error) {
	return TargetValidation{Target: target, SubjectUserID: v.subject}, v.err
}

type accessCipherStub struct{ plaintexts []string }

func (c *accessCipherStub) Encrypt(_ adminstepup.EncryptionPurpose, _, _ string, _ int64, plaintext string) (adminstepup.EncryptedValue, error) {
	c.plaintexts = append(c.plaintexts, plaintext)
	return adminstepup.EncryptedValue{KeyID: "reason-key", Nonce: []byte("opaque-nonce"), Ciphertext: []byte("opaque-ciphertext")}, nil
}

type accessFingerprinterStub struct{ key []byte }

func (f accessFingerprinterStub) Fingerprint(purpose string, canonical []byte) (RequestFingerprint, error) {
	mac := hmac.New(sha256.New, f.key)
	_, _ = mac.Write([]byte(purpose + "\x00"))
	_, _ = mac.Write(canonical)
	return RequestFingerprint{Version: "hmac-sha256-v1", KeyID: "fp-key", Digest: base64.RawURLEncoding.EncodeToString(mac.Sum(nil))}, nil
}

type accessMemoryState struct {
	requests       map[string]Request
	grants         map[string]Grant
	receipts       map[string]LocalOperationReceipt
	authorizations map[identity.UserID]AuthorizationEvidence
	audits         []Audit
	reasons        map[string]ProtectedReason
	failAudit      bool
}

func newAccessMemoryState() *accessMemoryState {
	return &accessMemoryState{
		requests: map[string]Request{}, grants: map[string]Grant{}, receipts: map[string]LocalOperationReceipt{},
		authorizations: map[identity.UserID]AuthorizationEvidence{
			"senior": {Role: adminroles.RoleSeniorAdmin, BindingID: "arb_senior", BindingVersion: 3, ChallengeVersion: 7},
			"super":  {Role: adminroles.RoleSuperAdmin, BindingID: "arb_super", BindingVersion: 4, ChallengeVersion: 11},
		},
		reasons: map[string]ProtectedReason{},
	}
}

func (s *accessMemoryState) clone() *accessMemoryState {
	n := newAccessMemoryState()
	n.failAudit = s.failAudit
	n.audits = append([]Audit(nil), s.audits...)
	n.authorizations = make(map[identity.UserID]AuthorizationEvidence, len(s.authorizations))
	for k, v := range s.authorizations {
		n.authorizations[k] = v
	}
	for k, v := range s.requests {
		v.Fields = append([]Field(nil), v.Fields...)
		n.requests[k] = v
	}
	for k, v := range s.grants {
		v.Fields = append([]Field(nil), v.Fields...)
		n.grants[k] = v
	}
	for k, v := range s.receipts {
		n.receipts[k] = v
	}
	for k, v := range s.reasons {
		n.reasons[k] = v
	}
	return n
}

type accessMemoryUOW struct {
	mu    sync.Mutex
	state *accessMemoryState
}

func (u *accessMemoryUOW) WithinIdentityAccessMutation(ctx context.Context, fn func(MutationRepositories) error) error {
	u.mu.Lock()
	defer u.mu.Unlock()
	working := u.state.clone()
	repository := &accessMemoryRepository{state: working}
	if err := fn(MutationRepositories{Access: repository, Authorization: repository, Receipts: repository}); err != nil {
		return err
	}
	u.state = working
	return nil
}

type accessMemoryRepository struct{ state *accessMemoryState }

func (r *accessMemoryRepository) CreateRequest(_ context.Context, request Request, reason ProtectedReason, audit Audit) (Request, error) {
	for _, existing := range r.state.requests {
		if existing.EventID == request.EventID && existing.RequesterID == request.RequesterID && existing.TargetType == request.TargetType && existing.TargetID == request.TargetID && existing.Status == StatusPending {
			return Request{}, ErrConflict
		}
	}
	if r.state.failAudit {
		return Request{}, errors.New("audit unavailable")
	}
	r.state.requests[request.ID], r.state.reasons[reason.ID] = request, reason
	r.state.audits = append(r.state.audits, audit)
	return request, nil
}

func (r *accessMemoryRepository) GetRequest(_ context.Context, eventID, requestID string) (Request, error) {
	request, ok := r.state.requests[requestID]
	if !ok || request.EventID != eventID {
		return Request{}, ErrNotFound
	}
	return request, nil
}

func (r *accessMemoryRepository) ListOwn(_ context.Context, actor identity.UserID, _ adminpagination.Query) (Page, error) {
	items := []Request{}
	for _, item := range r.state.requests {
		if item.RequesterID == actor {
			items = append(items, item)
		}
	}
	return Page{Items: items}, nil
}

func (r *accessMemoryRepository) ListApprovalQueue(_ context.Context, _ adminpagination.Query) (Page, error) {
	items := []Request{}
	for _, item := range r.state.requests {
		if item.Status == StatusPending {
			items = append(items, item)
		}
	}
	return Page{Items: items}, nil
}

func (r *accessMemoryRepository) Decide(_ context.Context, eventID, requestID string, expected int64, decision Decision, approved []Field, authorization GrantAuthorization, audit Audit) (DecisionOutcome, error) {
	request, ok := r.state.requests[requestID]
	if !ok || request.EventID != eventID {
		return DecisionOutcome{}, ErrNotFound
	}
	if request.Status != StatusPending || request.Version != expected || !identityAccessTestNow.Before(request.ExpiresAt) {
		return DecisionOutcome{}, ErrConflict
	}
	if r.state.failAudit {
		return DecisionOutcome{}, errors.New("audit unavailable")
	}
	request.Version++
	request.ApproverID = decision.ApproverID
	request.UpdatedAt, request.TerminalAt = decision.DecidedAt, &decision.DecidedAt
	request.Status = StatusRejected
	if decision.Approved {
		request.Status = StatusApproved
	}
	r.state.requests[requestID] = request
	r.state.audits = append(r.state.audits, audit)
	if !decision.Approved {
		return DecisionOutcome{Request: request}, nil
	}
	grant := Grant{ID: "iag_1", RequestID: request.ID, EventID: request.EventID, RequesterID: request.RequesterID, TargetSubject: request.TargetSubject, TargetType: request.TargetType, TargetID: request.TargetID, ApprovedBy: decision.ApproverID, Fields: append([]Field(nil), approved...), ExpiresAt: decision.DecidedAt.Add(15 * time.Minute), Version: 1, Status: GrantActive, Authorization: authorization}
	r.state.grants[grant.ID] = grant
	return DecisionOutcome{Request: request, Grant: &grant}, nil
}

func (r *accessMemoryRepository) Claim(_ context.Context, eventID, grantID string, requester identity.UserID, expected int64, authorization AuthorizationEvidence, now time.Time, audit Audit) (Claim, error) {
	grant, ok := r.state.grants[grantID]
	if !ok || grant.EventID != eventID || grant.RequesterID != requester || grant.Version != expected || grant.Status != GrantActive || !now.Before(grant.ExpiresAt) || grant.Authorization.RoleBindingID != authorization.BindingID || grant.Authorization.RoleBindingVersion != authorization.BindingVersion || grant.Authorization.ChallengeVersion != authorization.ChallengeVersion {
		return Claim{}, ErrConflict
	}
	if r.state.failAudit {
		return Claim{}, errors.New("audit unavailable")
	}
	grant.Status, grant.Version = GrantClaimed, grant.Version+1
	r.state.grants[grantID] = grant
	r.state.audits = append(r.state.audits, audit)
	return Claim{GrantID: grant.ID, EventID: grant.EventID, RequesterID: grant.RequesterID, TargetSubject: grant.TargetSubject, TargetType: grant.TargetType, TargetID: grant.TargetID, Fields: append([]Field(nil), grant.Fields...), FieldSetHash: grant.Authorization.FieldSetHash, RoleBindingID: grant.Authorization.RoleBindingID, RoleBindingVersion: grant.Authorization.RoleBindingVersion, ChallengeVersion: grant.Authorization.ChallengeVersion, ClaimNonce: "only-first-response", LeaseExpiresAt: now.Add(time.Minute), Version: grant.Version}, nil
}

func (r *accessMemoryRepository) Settle(_ context.Context, eventID, grantID string, requester identity.UserID, expected int64, claimNonce, _ string, authorization AuthorizationEvidence, now time.Time, audit Audit) (int64, error) {
	grant, ok := r.state.grants[grantID]
	if !ok || grant.EventID != eventID || grant.RequesterID != requester || grant.Version != expected || grant.Status != GrantClaimed || claimNonce != "only-first-response" || grant.Authorization.RoleBindingID != authorization.BindingID || grant.Authorization.RoleBindingVersion != authorization.BindingVersion || grant.Authorization.ChallengeVersion != authorization.ChallengeVersion {
		return 0, ErrConflict
	}
	if r.state.failAudit {
		return 0, errors.New("audit unavailable")
	}
	grant.Status, grant.Version = GrantSettled, grant.Version+1
	grant.TerminalAt = &now
	r.state.grants[grantID] = grant
	r.state.audits = append(r.state.audits, audit)
	return grant.Version, nil
}

func (r *accessMemoryRepository) ReleaseExpiredClaim(context.Context, string, string, int64, Audit) error {
	return nil
}
func (r *accessMemoryRepository) RevokeForUser(context.Context, identity.UserID, Audit) error {
	return nil
}

func (r *accessMemoryRepository) Revalidate(_ context.Context, actor identity.UserID, _ string, expected AuthorizationEvidence) error {
	if current, ok := r.state.authorizations[actor]; !ok || current != expected {
		return ErrForbidden
	}
	return nil
}

func (r *accessMemoryRepository) CurrentGrantAuthorization(_ context.Context, actor identity.UserID, _ string) (AuthorizationEvidence, error) {
	current, ok := r.state.authorizations[actor]
	if !ok {
		return AuthorizationEvidence{}, ErrForbidden
	}
	return current, nil
}

func (r *accessMemoryRepository) CreateOrReplay(_ context.Context, receipt LocalOperationReceipt) (LocalOperationReceipt, bool, error) {
	if existing, ok := r.state.receipts[receipt.IdempotencyKey]; ok {
		if existing.Fingerprint != receipt.Fingerprint {
			return LocalOperationReceipt{}, false, ErrIdempotencyConflict
		}
		return existing, true, nil
	}
	r.state.receipts[receipt.IdempotencyKey] = receipt
	return receipt, false, nil
}

func (r *accessMemoryRepository) CompleteLocal(_ context.Context, id string, expected int64, result LocalReceiptResult, at time.Time) error {
	for key, receipt := range r.state.receipts {
		if receipt.ID == id && receipt.Version == expected {
			receipt.Result, receipt.State, receipt.Version, receipt.TerminalAt = result, "succeeded", expected+1, &at
			r.state.receipts[key] = receipt
			return nil
		}
	}
	return ErrIdempotencyConflict
}

func newAccessTestService(t *testing.T, role adminroles.Role) (*Service, *accessMemoryUOW, *accessCipherStub) {
	t.Helper()
	state := newAccessMemoryState()
	uow := &accessMemoryUOW{state: state}
	cipher := &accessCipherStub{}
	decisions := map[permissions.Action]permissions.Decision{
		permissions.ActionIdentityAccessRequest: {Allowed: true, Role: role, BindingID: "arb_senior", BindingVersion: 3, ChallengeVersion: 7},
		permissions.ActionIdentityAccessApprove: {Allowed: true, Role: adminroles.RoleSuperAdmin, BindingID: "arb_super", BindingVersion: 4, ChallengeVersion: 11},
		permissions.ActionIdentityGrantConsume:  {Allowed: true, Role: adminroles.RoleSeniorAdmin, BindingID: "arb_senior", BindingVersion: 3, ChallengeVersion: 7},
	}
	service := NewService(ServiceDependencies{Repository: &accessMemoryRepository{state: state}, UnitOfWork: uow, Authorizer: accessAuthorizerStub{decisions: decisions}, TargetValidator: accessTargetValidatorStub{subject: "candidate"}, ReasonCipher: cipher, Fingerprinter: accessFingerprinterStub{key: []byte("0123456789abcdef0123456789abcdef")}}, WithClock(func() time.Time { return identityAccessTestNow }), WithIDGenerator(func(prefix string) (string, error) { return prefix + "1", nil }))
	return service, uow, cipher
}

func validCreateInput() CreateRequestInput {
	return CreateRequestInput{ActorID: "senior", EventID: "evt_shanghai", Target: TargetRef{Type: TargetApplication, ID: "app_1"}, Fields: []Field{FieldIdentityPhoto, FieldLegalName}, Reason: "  为了核对选手身份，确认现场签到信息与报名材料保持一致。  ", CorrelationID: "req_http_1", IdempotencyKey: "abcdefghijklmnopqrstuvwxyzABCDEF"}
}

func TestCreateRequestRequiresSeniorScopeEncryptsNormalizedReasonAndIsIdempotent(t *testing.T) {
	service, uow, cipher := newAccessTestService(t, adminroles.RoleSeniorAdmin)
	first, err := service.CreateRequest(context.Background(), validCreateInput())
	if err != nil {
		t.Fatalf("create request: %v", err)
	}
	if first.Request.Status != StatusPending || first.Request.Version != 1 || first.Request.TargetSubject != "candidate" || first.Replayed {
		t.Fatalf("result=%+v", first)
	}
	if len(cipher.plaintexts) != 1 || cipher.plaintexts[0] != "为了核对选手身份,确认现场签到信息与报名材料保持一致。" {
		t.Fatalf("cipher plaintexts=%q", cipher.plaintexts)
	}
	stored := uow.state.reasons[first.Request.ReasonID]
	if string(stored.Ciphertext) == cipher.plaintexts[0] || len(uow.state.audits) != 1 {
		t.Fatalf("reason/audits not safely stored: %+v %d", stored, len(uow.state.audits))
	}
	replay, err := service.CreateRequest(context.Background(), validCreateInput())
	if err != nil || !replay.Replayed || replay.Request.ID != first.Request.ID || len(uow.state.requests) != 1 || len(uow.state.audits) != 1 {
		t.Fatalf("replay=%+v err=%v", replay, err)
	}
	changed := validCreateInput()
	changed.Fields = []Field{FieldContactEmail}
	if _, err := service.CreateRequest(context.Background(), changed); !errors.Is(err, ErrIdempotencyConflict) {
		t.Fatalf("different replay err=%v", err)
	}
}

func TestCreateRequestDeniesAdminAndSuperAndRejectsReasonOrFieldOutsideContract(t *testing.T) {
	for _, role := range []adminroles.Role{adminroles.RoleAdmin, adminroles.RoleSuperAdmin} {
		service, _, _ := newAccessTestService(t, role)
		if _, err := service.CreateRequest(context.Background(), validCreateInput()); !errors.Is(err, ErrForbidden) {
			t.Fatalf("role %s err=%v", role, err)
		}
	}
	service, _, _ := newAccessTestService(t, adminroles.RoleSeniorAdmin)
	for _, reason := range []string{"太短", "包含\u202e双向控制符的说明文字应该被拒绝以保护审计边界", string(make([]rune, 501))} {
		input := validCreateInput()
		input.Reason = reason
		if _, err := service.CreateRequest(context.Background(), input); !errors.Is(err, ErrInvalidReason) {
			t.Fatalf("reason %q err=%v", reason, err)
		}
	}
	input := validCreateInput()
	input.Fields = []Field{"legal_document"}
	if _, err := service.CreateRequest(context.Background(), input); !errors.Is(err, ErrInvalidRequest) {
		t.Fatalf("legal field err=%v", err)
	}
}

func createPendingForDecision(t *testing.T, service *Service) Request {
	t.Helper()
	result, err := service.CreateRequest(context.Background(), validCreateInput())
	if err != nil {
		t.Fatalf("seed request: %v", err)
	}
	return result.Request
}

func TestDecisionRequiresFreshSuperStepUpActorSeparationAndMayOnlyShrinkFields(t *testing.T) {
	service, uow, _ := newAccessTestService(t, adminroles.RoleSeniorAdmin)
	request := createPendingForDecision(t, service)
	stepup := auth.ReauthGrantData{GrantID: "reauth_1", UserID: "super", SessionID: "session_1", Action: auth.ReauthActionAdminOAApproval, Target: request.ID, CreatedAt: identityAccessTestNow.Add(-4 * time.Minute), ChallengeVersion: 11}
	input := DecideInput{ActorID: "super", EventID: request.EventID, AccessRequestID: request.ID, Approved: true, Fields: []Field{FieldLegalName}, ExpectedVersion: request.Version, StepUp: stepup, CorrelationID: "req_http_2", IdempotencyKey: "bcdefghijklmnopqrstuvwxyzABCDEFG"}
	result, err := service.Decide(context.Background(), input)
	if err != nil {
		t.Fatalf("approve: %v", err)
	}
	if result.Request.Status != StatusApproved || result.Grant == nil || !reflect.DeepEqual(result.Grant.Fields, []Field{FieldLegalName}) || result.Grant.ExpiresAt.Sub(identityAccessTestNow) > 15*time.Minute {
		t.Fatalf("result=%+v", result)
	}
	if result.Grant.Authorization.RoleBindingID != "arb_senior" || result.Grant.Authorization.ChallengeVersion != 7 {
		t.Fatalf("grant auth=%+v", result.Grant.Authorization)
	}
	if len(uow.state.audits) != 2 {
		t.Fatalf("audits=%d", len(uow.state.audits))
	}

	for name, edit := range map[string]func(*DecideInput){
		"stale stepup":    func(v *DecideInput) { v.StepUp.CreatedAt = identityAccessTestNow.Add(-5*time.Minute - time.Nanosecond) },
		"field expansion": func(v *DecideInput) { v.Fields = []Field{FieldLegalName, FieldContactMobile} },
	} {
		t.Run(name, func(t *testing.T) {
			fresh, _, _ := newAccessTestService(t, adminroles.RoleSeniorAdmin)
			seeded := createPendingForDecision(t, fresh)
			candidate := input
			candidate.AccessRequestID = seeded.ID
			candidate.EventID = seeded.EventID
			candidate.ExpectedVersion = seeded.Version
			candidate.StepUp.Target = seeded.ID
			candidate.IdempotencyKey = "cdefghijklmnopqrstuvwxyzABCDEFGH"
			edit(&candidate)
			if _, err := fresh.Decide(context.Background(), candidate); err == nil {
				t.Fatal("unsafe decision accepted")
			}
		})
	}
	targetService, targetUOW, _ := newAccessTestService(t, adminroles.RoleSeniorAdmin)
	targetRequest := createPendingForDecision(t, targetService)
	mutated := targetUOW.state.requests[targetRequest.ID]
	mutated.TargetSubject = "super"
	targetUOW.state.requests[targetRequest.ID] = mutated
	if _, err := targetService.Decide(context.Background(), DecideInput{ActorID: "super", EventID: targetRequest.EventID, AccessRequestID: targetRequest.ID, Approved: true, Fields: targetRequest.Fields, ExpectedVersion: targetRequest.Version, StepUp: auth.ReauthGrantData{GrantID: "reauth_target", UserID: "super", SessionID: "session_1", Action: auth.ReauthActionAdminOAApproval, Target: targetRequest.ID, CreatedAt: identityAccessTestNow, ChallengeVersion: 11}, CorrelationID: "req_target", IdempotencyKey: "hijklmnopqrstuvwxyzABCDEFGHIJKLM"}); !errors.Is(err, ErrInvalidDecision) {
		t.Fatalf("target/approver separation err=%v", err)
	}
}

func TestClaimBindsGrantToExactRoleChallengeAndNeverReplaysNonce(t *testing.T) {
	service, uow, _ := newAccessTestService(t, adminroles.RoleSeniorAdmin)
	request := createPendingForDecision(t, service)
	decision, err := service.Decide(context.Background(), DecideInput{ActorID: "super", EventID: request.EventID, AccessRequestID: request.ID, Approved: true, Fields: request.Fields, ExpectedVersion: request.Version, StepUp: auth.ReauthGrantData{GrantID: "reauth_1", UserID: "super", SessionID: "session_1", Action: auth.ReauthActionAdminOAApproval, Target: request.ID, CreatedAt: identityAccessTestNow, ChallengeVersion: 11}, CorrelationID: "req_http_2", IdempotencyKey: "defghijklmnopqrstuvwxyzABCDEFGHI"})
	if err != nil {
		t.Fatalf("approve: %v", err)
	}
	input := ClaimInput{ActorID: "senior", EventID: request.EventID, GrantID: decision.Grant.ID, ExpectedVersion: decision.Grant.Version, CorrelationID: "req_http_3", IdempotencyKey: "efghijklmnopqrstuvwxyzABCDEFGHIJ"}
	first, err := service.Claim(context.Background(), input)
	if err != nil || first.Claim.ClaimNonce == "" || first.Replayed {
		t.Fatalf("first=%+v err=%v", first, err)
	}
	replay, err := service.Claim(context.Background(), input)
	if err != nil || !replay.Replayed || replay.Claim.ClaimNonce != "" {
		t.Fatalf("replay leaked/rejected: %+v err=%v", replay, err)
	}

	service2, uow2, _ := newAccessTestService(t, adminroles.RoleSeniorAdmin)
	request2 := createPendingForDecision(t, service2)
	decision2, _ := service2.Decide(context.Background(), DecideInput{ActorID: "super", EventID: request2.EventID, AccessRequestID: request2.ID, Approved: true, Fields: request2.Fields, ExpectedVersion: request2.Version, StepUp: auth.ReauthGrantData{GrantID: "reauth_2", UserID: "super", SessionID: "s", Action: auth.ReauthActionAdminOAApproval, Target: request2.ID, CreatedAt: identityAccessTestNow, ChallengeVersion: 11}, CorrelationID: "req_http_4", IdempotencyKey: "fghijklmnopqrstuvwxyzABCDEFGHIJK"})
	evidence := uow2.state.authorizations["senior"]
	evidence.ChallengeVersion++
	uow2.state.authorizations["senior"] = evidence
	if _, err := service2.Claim(context.Background(), ClaimInput{ActorID: "senior", EventID: request2.EventID, GrantID: decision2.Grant.ID, ExpectedVersion: 1, CorrelationID: "req_http_5", IdempotencyKey: "ghijklmnopqrstuvwxyzABCDEFGHIJKL"}); !errors.Is(err, ErrForbidden) {
		t.Fatalf("changed challenge err=%v", err)
	}
	if uow.state.grants[decision.Grant.ID].Status != GrantClaimed {
		t.Fatalf("grant status=%s", uow.state.grants[decision.Grant.ID].Status)
	}
}

func TestAuditFailureRollsBackIdentityAccessMutationAndReceipt(t *testing.T) {
	service, uow, _ := newAccessTestService(t, adminroles.RoleSeniorAdmin)
	uow.state.failAudit = true
	if _, err := service.CreateRequest(context.Background(), validCreateInput()); err == nil {
		t.Fatal("audit failure accepted")
	}
	if len(uow.state.requests) != 0 || len(uow.state.receipts) != 0 || len(uow.state.reasons) != 0 {
		t.Fatalf("partial commit: %+v", uow.state)
	}
}

func TestNormalizeFieldsIsStableForFingerprintsAndStorage(t *testing.T) {
	fields, err := normalizeFields([]Field{FieldLegalName, FieldIdentityPhoto})
	if err != nil {
		t.Fatal(err)
	}
	if !sort.SliceIsSorted(fields, func(i, j int) bool { return fields[i] < fields[j] }) {
		t.Fatalf("fields=%v", fields)
	}
}
