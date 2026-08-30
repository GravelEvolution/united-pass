package adminroles

import (
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/base64"
	"errors"
	"fmt"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/GravelEvolution/united-pass/backend/internal/adminpagination"
	"github.com/GravelEvolution/united-pass/backend/internal/identity"
)

type roleGateStub struct {
	mu         sync.Mutex
	allowed    bool
	err        error
	events     []string
	afterCheck func()
}

func (g *roleGateStub) CheckRoleManagement(_ context.Context, _ identity.UserID, eventID string) (RoleManagementDecision, error) {
	g.mu.Lock()
	g.events = append(g.events, eventID)
	allowed, err, afterCheck := g.allowed, g.err, g.afterCheck
	g.mu.Unlock()
	decision := RoleManagementDecision{Allowed: allowed, Role: RoleSuperAdmin, BindingID: "arb_actor", BindingVersion: 1, Scope: Scope{Kind: ScopeSystem}}
	if afterCheck != nil {
		afterCheck()
	}
	return decision, err
}

func (g *roleGateStub) eventCount() int {
	g.mu.Lock()
	defer g.mu.Unlock()
	return len(g.events)
}

type roleMemoryState struct {
	bindings            map[string]Binding
	receipts            map[string]LocalOperationReceipt
	events              map[string]RegisteredEvent
	reasonEnds          map[string]time.Time
	actorAuthorizations map[identity.UserID]RoleManagementDecision
	accountStatus       string
	employeeStatus      string
	auditCount          int
	failRoleAudit       bool
}

func newRoleMemoryState() *roleMemoryState {
	return &roleMemoryState{bindings: map[string]Binding{}, receipts: map[string]LocalOperationReceipt{}, events: map[string]RegisteredEvent{
		"evt_a": {EventID: "evt_a", Series: "dreamup", Slug: "a", SourceVersion: "v1", AuthoritativeReadAt: time.Now(), Enabled: true, Version: 1},
		"evt_b": {EventID: "evt_b", Series: "dreamup", Slug: "b", SourceVersion: "v1", AuthoritativeReadAt: time.Now(), Enabled: true, Version: 1},
	}, reasonEnds: map[string]time.Time{}, actorAuthorizations: map[identity.UserID]RoleManagementDecision{
		"user_actor": {Allowed: true, Role: RoleSuperAdmin, BindingID: "arb_actor", BindingVersion: 1, Scope: Scope{Kind: ScopeSystem}},
	}, accountStatus: "active", employeeStatus: "active"}
}

func (s *roleMemoryState) clone() *roleMemoryState {
	next := &roleMemoryState{bindings: map[string]Binding{}, receipts: map[string]LocalOperationReceipt{}, events: map[string]RegisteredEvent{}, reasonEnds: map[string]time.Time{}, actorAuthorizations: map[identity.UserID]RoleManagementDecision{}, accountStatus: s.accountStatus, employeeStatus: s.employeeStatus, auditCount: s.auditCount, failRoleAudit: s.failRoleAudit}
	for key, value := range s.bindings {
		next.bindings[key] = value
	}
	for key, value := range s.receipts {
		next.receipts[key] = value
	}
	for key, value := range s.events {
		next.events[key] = value
	}
	for key, value := range s.reasonEnds {
		next.reasonEnds[key] = value
	}
	for key, value := range s.actorAuthorizations {
		next.actorAuthorizations[key] = value
	}
	return next
}

type roleMemoryUOW struct {
	mu    sync.Mutex
	state *roleMemoryState
}

func (u *roleMemoryUOW) WithinRoleMutation(ctx context.Context, fn func(RoleMutationRepositories) error) error {
	u.mu.Lock()
	defer u.mu.Unlock()
	working := u.state.clone()
	repos := RoleMutationRepositories{
		Roles:              &roleMemoryRepository{state: working},
		ActorAuthorization: roleMemoryActorAuthorization{state: working},
		EventRegistry:      roleMemoryRegistry{state: working},
		Reasons:            roleMemoryReasons{state: working},
		Receipts:           roleMemoryOutbox{state: working},
	}
	if err := fn(repos); err != nil {
		return err
	}
	u.state = working
	return nil
}

type roleMemoryActorAuthorization struct{ state *roleMemoryState }

func (r roleMemoryActorAuthorization) Revalidate(_ context.Context, actorID identity.UserID, eventID string, decision RoleManagementDecision) error {
	stored, ok := r.state.actorAuthorizations[actorID]
	if !ok || stored != decision || !decision.Allowed || r.state.accountStatus != "active" || r.state.employeeStatus == "offboarding" {
		return ErrRoleMutationForbidden
	}
	if decision.Role == RoleSuperAdmin && decision.Scope.Kind != ScopeSystem {
		return ErrRoleMutationForbidden
	}
	if decision.Role != RoleSuperAdmin && decision.Scope != (Scope{Kind: ScopeEvent, EventID: eventID}) {
		return ErrRoleMutationForbidden
	}
	return nil
}

type roleMemoryRepository struct{ state *roleMemoryState }

func bindingScopeKey(userID identity.UserID, scope Scope) string {
	key, _ := scope.Key()
	return string(userID) + ":" + string(scope.Kind) + ":" + key
}

func (r *roleMemoryRepository) GetForScope(_ context.Context, userID identity.UserID, scope Scope) (Binding, error) {
	binding, ok := r.state.bindings[bindingScopeKey(userID, scope)]
	if !ok || binding.DisabledAt != nil {
		return Binding{}, ErrBindingNotFound
	}
	return binding, nil
}
func (*roleMemoryRepository) ListForUser(context.Context, identity.UserID, adminpagination.Query) (adminpagination.Page[Binding], error) {
	panic("unexpected list")
}
func (*roleMemoryRepository) ListForEvent(context.Context, string, adminpagination.Query) (adminpagination.Page[Binding], error) {
	panic("unexpected list")
}
func (r *roleMemoryRepository) Create(_ context.Context, binding Binding, audit MutationAudit) (Binding, error) {
	key := bindingScopeKey(binding.UserID, binding.Scope)
	if _, exists := r.state.bindings[key]; exists {
		return Binding{}, ErrBindingConflict
	}
	binding.Enabled, binding.Version = true, 1
	r.state.bindings[key] = binding
	if r.state.failRoleAudit {
		return Binding{}, errors.New("audit failed")
	}
	if audit.ActorID == "" || audit.RequestID == "" || audit.ReasonID == "" {
		return Binding{}, errors.New("incomplete audit")
	}
	r.state.auditCount++
	return binding, nil
}
func (r *roleMemoryRepository) Update(_ context.Context, binding Binding, expected int64, audit MutationAudit) (Binding, error) {
	key := bindingScopeKey(binding.UserID, binding.Scope)
	current, ok := r.state.bindings[key]
	if !ok || current.ID != binding.ID || current.Version != expected {
		return Binding{}, ErrBindingConflict
	}
	binding.Enabled, binding.Version = true, expected+1
	r.state.bindings[key] = binding
	if r.state.failRoleAudit {
		return Binding{}, errors.New("audit failed")
	}
	if audit.ActorID == "" || audit.RequestID == "" || audit.ReasonID == "" {
		return Binding{}, errors.New("incomplete audit")
	}
	r.state.auditCount++
	return binding, nil
}
func (r *roleMemoryRepository) Disable(_ context.Context, id string, expected int64, audit MutationAudit) (Binding, error) {
	for key, binding := range r.state.bindings {
		if binding.ID != id {
			continue
		}
		if binding.Version != expected {
			return Binding{}, ErrBindingConflict
		}
		now := time.Now()
		binding.Enabled, binding.DisabledAt, binding.Version = false, &now, expected+1
		r.state.bindings[key] = binding
		if r.state.failRoleAudit {
			return Binding{}, errors.New("audit failed")
		}
		if audit.ActorID == "" || audit.RequestID == "" || audit.ReasonID == "" {
			return Binding{}, errors.New("incomplete audit")
		}
		r.state.auditCount++
		return binding, nil
	}
	return Binding{}, ErrBindingNotFound
}

type roleMemoryRegistry struct{ state *roleMemoryState }

func (r roleMemoryRegistry) GetExact(_ context.Context, eventID string) (RegisteredEvent, error) {
	event, ok := r.state.events[eventID]
	if !ok {
		return RegisteredEvent{}, ErrEventRegistryNotFound
	}
	if !event.Enabled {
		return RegisteredEvent{}, ErrEventRegistryDisabled
	}
	return event, nil
}
func (roleMemoryRegistry) ListEnabled(context.Context, adminpagination.Query) (adminpagination.Page[RegisteredEvent], error) {
	panic("unexpected list")
}
func (roleMemoryRegistry) PutExact(context.Context, RegisteredEvent, MutationAudit) (RegisteredEvent, error) {
	panic("unexpected put")
}
func (roleMemoryRegistry) SetEnabled(context.Context, string, bool, int64, MutationAudit) (RegisteredEvent, error) {
	panic("unexpected set")
}

type roleMemoryReasons struct{ state *roleMemoryState }

func (roleMemoryReasons) Create(context.Context, string, string, string, []byte, []byte, time.Time) error {
	panic("unexpected create")
}
func (r roleMemoryReasons) ConsumeOwned(_ context.Context, id string, owner identity.UserID, operationKind string, terminal, expires time.Time) error {
	if id == "" || owner != "user_actor" || operationKind != "role" || !expires.After(terminal) {
		return errors.New("invalid reason terminal")
	}
	r.state.reasonEnds[id] = expires
	return nil
}

func TestRoleServiceProtectedReasonMustMatchActorAndRoleOperation(t *testing.T) {
	state := newRoleMemoryState()
	state.actorAuthorizations["user_other"] = state.actorAuthorizations["user_actor"]
	service, uow, _ := newRoleServiceForTest(t, state)
	input := validCreate("evt_a", "user_target", "YWFhYWFhYWFhYWFhYWFhYWFhYWFhYWFhYWFhYWFhYWE")
	input.ActorID = "user_other"
	if _, err := service.CreateRole(context.Background(), input); err == nil {
		t.Fatal("role mutation consumed another actor's protected reason")
	}
	if len(uow.state.bindings) != 0 || len(uow.state.receipts) != 0 || len(uow.state.reasonEnds) != 0 {
		t.Fatalf("reason ownership failure leaked transaction state: %+v", uow.state)
	}
}

func TestRoleServiceRevalidatesExactActorBindingAndLifecycleInsideMutationTransaction(t *testing.T) {
	for _, test := range []struct {
		name   string
		revoke func(*roleMemoryState)
	}{
		{name: "binding version changed", revoke: func(state *roleMemoryState) {
			decision := state.actorAuthorizations["user_actor"]
			decision.BindingVersion++
			state.actorAuthorizations["user_actor"] = decision
		}},
		{name: "binding disabled", revoke: func(state *roleMemoryState) { delete(state.actorAuthorizations, "user_actor") }},
		{name: "account disabled", revoke: func(state *roleMemoryState) { state.accountStatus = "disabled" }},
		{name: "employee offboarding", revoke: func(state *roleMemoryState) { state.employeeStatus = "offboarding" }},
	} {
		t.Run(test.name, func(t *testing.T) {
			service, uow, gate := newRoleServiceForTest(t, newRoleMemoryState())
			gate.afterCheck = func() {
				uow.mu.Lock()
				defer uow.mu.Unlock()
				test.revoke(uow.state)
			}
			_, err := service.CreateRole(context.Background(), validCreate("evt_a", "user_target", "YWFhYWFhYWFhYWFhYWFhYWFhYWFhYWFhYWFhYWFhYWE"))
			if !errors.Is(err, ErrRoleMutationForbidden) {
				t.Fatalf("error=%v want forbidden", err)
			}
			if len(uow.state.bindings) != 0 || len(uow.state.receipts) != 0 || uow.state.auditCount != 0 {
				t.Fatalf("revoked actor mutation leaked state: %+v", uow.state)
			}
		})
	}
}
func (roleMemoryReasons) PurgeExpired(context.Context, time.Time, int) (int, error) {
	panic("unexpected purge")
}

type roleMemoryOutbox struct{ state *roleMemoryState }

func (r roleMemoryOutbox) CreateOrReplay(_ context.Context, item LocalOperationReceipt) (LocalOperationReceipt, bool, error) {
	if existing, ok := r.state.receipts[item.IdempotencyKey]; ok {
		if existing.Fingerprint != item.Fingerprint {
			return LocalOperationReceipt{}, false, ErrRoleIdempotencyConflict
		}
		return existing, true, nil
	}
	item.Version, item.State = 1, "pending"
	r.state.receipts[item.IdempotencyKey] = item
	return item, false, nil
}
func (r roleMemoryOutbox) CompleteLocal(_ context.Context, id string, expected int64, result LocalReceiptResult, at time.Time) error {
	if result.Code == "" || result.Digest == "" || result.Payload["binding_id"] == "" {
		return ErrInvalidStoredRoleResult
	}
	for key, item := range r.state.receipts {
		if item.ID == id && item.Version == expected && item.State == "pending" {
			item.Result, item.State, item.Version = result, "succeeded", item.Version+1
			item.TerminalAt = &at
			r.state.receipts[key] = item
			return nil
		}
	}
	return ErrRoleIdempotencyConflict
}

type roleTestFingerprinter struct{ key []byte }

func (f roleTestFingerprinter) Fingerprint(purpose string, canonical []byte) (RequestFingerprint, error) {
	mac := hmac.New(sha256.New, f.key)
	_, _ = mac.Write([]byte(purpose))
	_, _ = mac.Write([]byte{0})
	_, _ = mac.Write(canonical)
	return RequestFingerprint{Version: "hmac-sha256-v1", KeyID: "k1", Digest: base64.RawURLEncoding.EncodeToString(mac.Sum(nil))}, nil
}

func newRoleServiceForTest(t *testing.T, state *roleMemoryState) (*Service, *roleMemoryUOW, *roleGateStub) {
	t.Helper()
	uow := &roleMemoryUOW{state: state}
	gate := &roleGateStub{allowed: true}
	var ids atomic.Int64
	service := NewService(uow, gate, roleTestFingerprinter{key: []byte("0123456789abcdef0123456789abcdef")},
		WithRoleClock(func() time.Time { return time.Date(2026, 8, 17, 16, 0, 0, 0, time.UTC) }),
		WithRoleIDGenerator(func(prefix string) (string, error) { return fmt.Sprintf("%s%d", prefix, ids.Add(1)), nil }))
	return service, uow, gate
}

func validCreate(eventID, target, key string) CreateRoleInput {
	return CreateRoleInput{ActorID: "user_actor", TargetUserID: identity.UserID(target), EventID: eventID, Role: RoleAdmin, ReasonID: "reason_1", RequestID: "request_1", IdempotencyKey: key}
}

func TestRoleServiceCreatesDistinctEventBindingsAndReplaysSafeResult(t *testing.T) {
	service, uow, gate := newRoleServiceForTest(t, newRoleMemoryState())
	first, err := service.CreateRole(context.Background(), validCreate("evt_a", "user_target", "YWFhYWFhYWFhYWFhYWFhYWFhYWFhYWFhYWFhYWFhYWE"))
	if err != nil {
		t.Fatal(err)
	}
	replay, err := service.CreateRole(context.Background(), validCreate("evt_a", "user_target", "YWFhYWFhYWFhYWFhYWFhYWFhYWFhYWFhYWFhYWFhYWE"))
	if err != nil || replay != first {
		t.Fatalf("replay=%+v first=%+v err=%v", replay, first, err)
	}
	second, err := service.CreateRole(context.Background(), validCreate("evt_b", "user_target", "YmJiYmJiYmJiYmJiYmJiYmJiYmJiYmJiYmJiYmJiYmI"))
	if err != nil {
		t.Fatal(err)
	}
	if first.BindingID == second.BindingID || len(uow.state.bindings) != 2 || uow.state.auditCount != 2 || gate.eventCount() != 3 {
		t.Fatalf("first=%+v second=%+v bindings=%d audits=%d event-count=%d", first, second, len(uow.state.bindings), uow.state.auditCount, gate.eventCount())
	}
}

func TestRoleServiceUpdatesAndDisablesWithOptimisticVersions(t *testing.T) {
	service, uow, _ := newRoleServiceForTest(t, newRoleMemoryState())
	created, err := service.CreateRole(context.Background(), validCreate("evt_a", "user_target", "YWFhYWFhYWFhYWFhYWFhYWFhYWFhYWFhYWFhYWFhYWE"))
	if err != nil {
		t.Fatal(err)
	}
	update := UpdateRoleInput{ActorID: "user_actor", TargetUserID: "user_target", BindingID: created.BindingID, EventID: "evt_a", Role: RoleSeniorAdmin, ReasonID: "reason_2", RequestID: "request_2", IdempotencyKey: "YmJiYmJiYmJiYmJiYmJiYmJiYmJiYmJiYmJiYmJiYmI", ExpectedVersion: created.Version}
	updated, err := service.UpdateRole(context.Background(), update)
	if err != nil || updated.Version != 2 {
		t.Fatalf("updated=%+v err=%v", updated, err)
	}
	retry := update
	retry.RequestID = "request_retry"
	updatedReplay, err := service.UpdateRole(context.Background(), retry)
	if err != nil || updatedReplay != updated {
		t.Fatalf("update replay=%+v want=%+v err=%v", updatedReplay, updated, err)
	}
	disabled, err := service.DisableRole(context.Background(), DisableRoleInput{ActorID: "user_actor", TargetUserID: "user_target", BindingID: created.BindingID, EventID: "evt_a", ReasonID: "reason_3", RequestID: "request_3", IdempotencyKey: "Y2NjY2NjY2NjY2NjY2NjY2NjY2NjY2NjY2NjY2NjY2M", ExpectedVersion: updated.Version})
	if err != nil || disabled.Version != 3 {
		t.Fatalf("disabled=%+v err=%v", disabled, err)
	}
	binding := uow.state.bindings[bindingScopeKey("user_target", Scope{Kind: ScopeEvent, EventID: "evt_a"})]
	if binding.Enabled || binding.DisabledAt == nil || binding.Role != RoleSeniorAdmin || len(uow.state.receipts) != 3 || uow.state.auditCount != 3 {
		t.Fatalf("binding=%+v receipts=%d audits=%d", binding, len(uow.state.receipts), uow.state.auditCount)
	}
}

func TestRoleServiceRejectsSuperSelfWeakKeyAndMissingIfMatch(t *testing.T) {
	service, _, _ := newRoleServiceForTest(t, newRoleMemoryState())
	cases := []struct {
		name string
		run  func() error
		want error
	}{
		{name: "grant super", run: func() error {
			input := validCreate("evt_a", "user_target", "YWFhYWFhYWFhYWFhYWFhYWFhYWFhYWFhYWFhYWFhYWE")
			input.Role = RoleSuperAdmin
			_, err := service.CreateRole(context.Background(), input)
			return err
		}, want: ErrOrdinarySuperAdminMutation},
		{name: "self create", run: func() error {
			input := validCreate("evt_a", "user_actor", "YWFhYWFhYWFhYWFhYWFhYWFhYWFhYWFhYWFhYWFhYWE")
			_, err := service.CreateRole(context.Background(), input)
			return err
		}, want: ErrSelfRoleMutation},
		{name: "weak key", run: func() error {
			_, err := service.CreateRole(context.Background(), validCreate("evt_a", "user_target", "short"))
			return err
		}, want: ErrInvalidIdempotencyKey},
		{name: "promote super", run: func() error {
			_, err := service.UpdateRole(context.Background(), UpdateRoleInput{ActorID: "user_actor", TargetUserID: "user_target", BindingID: "arb_1", EventID: "evt_a", Role: RoleSuperAdmin, ReasonID: "reason_1", RequestID: "request_1", IdempotencyKey: "YWFhYWFhYWFhYWFhYWFhYWFhYWFhYWFhYWFhYWFhYWE", ExpectedVersion: 1})
			return err
		}, want: ErrOrdinarySuperAdminMutation},
		{name: "missing update if-match", run: func() error {
			_, err := service.UpdateRole(context.Background(), UpdateRoleInput{ActorID: "user_actor", TargetUserID: "user_target", BindingID: "arb_1", EventID: "evt_a", Role: RoleAdmin, ReasonID: "reason_1", RequestID: "request_1", IdempotencyKey: "YWFhYWFhYWFhYWFhYWFhYWFhYWFhYWFhYWFhYWFhYWE"})
			return err
		}, want: ErrIfMatchRequired},
		{name: "missing disable if-match", run: func() error {
			_, err := service.DisableRole(context.Background(), DisableRoleInput{ActorID: "user_actor", TargetUserID: "user_target", BindingID: "arb_1", EventID: "evt_a", ReasonID: "reason_1", RequestID: "request_1", IdempotencyKey: "YWFhYWFhYWFhYWFhYWFhYWFhYWFhYWFhYWFhYWFhYWE"})
			return err
		}, want: ErrIfMatchRequired},
		{name: "missing update key", run: func() error {
			_, err := service.UpdateRole(context.Background(), UpdateRoleInput{ActorID: "user_actor", TargetUserID: "user_target", BindingID: "arb_1", EventID: "evt_a", Role: RoleAdmin, ReasonID: "reason_1", RequestID: "request_1", ExpectedVersion: 1})
			return err
		}, want: ErrInvalidIdempotencyKey},
		{name: "missing disable key", run: func() error {
			_, err := service.DisableRole(context.Background(), DisableRoleInput{ActorID: "user_actor", TargetUserID: "user_target", BindingID: "arb_1", EventID: "evt_a", ReasonID: "reason_1", RequestID: "request_1", ExpectedVersion: 1})
			return err
		}, want: ErrInvalidIdempotencyKey},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if err := tc.run(); !errors.Is(err, tc.want) {
				t.Fatalf("error=%v want=%v", err, tc.want)
			}
		})
	}
}

func TestRoleServiceRequiresAuthorizationAndExactRegisteredEvent(t *testing.T) {
	service, uow, gate := newRoleServiceForTest(t, newRoleMemoryState())
	gate.allowed = false
	if _, err := service.CreateRole(context.Background(), validCreate("evt_a", "user_target", "YWFhYWFhYWFhYWFhYWFhYWFhYWFhYWFhYWFhYWFhYWE")); !errors.Is(err, ErrRoleMutationForbidden) {
		t.Fatalf("denied error=%v", err)
	}
	gate.allowed = true
	if _, err := service.CreateRole(context.Background(), validCreate("evt_missing", "user_target", "YmJiYmJiYmJiYmJiYmJiYmJiYmJiYmJiYmJiYmJiYmI")); !errors.Is(err, ErrEventRegistryNotFound) {
		t.Fatalf("missing event error=%v", err)
	}
	if len(uow.state.bindings) != 0 || len(uow.state.receipts) != 0 {
		t.Fatalf("denied/unregistered mutation wrote state: %+v", uow.state)
	}
}

func TestRoleServiceSameKeyConcurrencyConflictAndStaleVersion(t *testing.T) {
	service, uow, _ := newRoleServiceForTest(t, newRoleMemoryState())
	input := validCreate("evt_a", "user_target", "YWFhYWFhYWFhYWFhYWFhYWFhYWFhYWFhYWFhYWFhYWE")
	results := make(chan RoleMutationResult, 2)
	errs := make(chan error, 2)
	for range 2 {
		go func() { result, err := service.CreateRole(context.Background(), input); results <- result; errs <- err }()
	}
	first, second := <-results, <-results
	if err := <-errs; err != nil {
		t.Fatal(err)
	}
	if err := <-errs; err != nil {
		t.Fatal(err)
	}
	if first != second || len(uow.state.bindings) != 1 || uow.state.auditCount != 1 {
		t.Fatalf("first=%+v second=%+v state=%+v", first, second, uow.state)
	}

	different := input
	different.Role = RoleSeniorAdmin
	if _, err := service.CreateRole(context.Background(), different); !errors.Is(err, ErrRoleIdempotencyConflict) {
		t.Fatalf("different fingerprint error=%v", err)
	}
	if _, err := service.UpdateRole(context.Background(), UpdateRoleInput{ActorID: "user_actor", TargetUserID: "user_target", BindingID: first.BindingID, EventID: "evt_a", Role: RoleSeniorAdmin, ReasonID: "reason_2", RequestID: "request_2", IdempotencyKey: "YmJiYmJiYmJiYmJiYmJiYmJiYmJiYmJiYmJiYmJiYmI", ExpectedVersion: 99}); !errors.Is(err, ErrBindingConflict) {
		t.Fatalf("stale version error=%v", err)
	}
}

func TestRoleServiceAuditFailureRollsBackBindingAndReceipt(t *testing.T) {
	state := newRoleMemoryState()
	state.failRoleAudit = true
	service, uow, _ := newRoleServiceForTest(t, state)
	_, err := service.CreateRole(context.Background(), validCreate("evt_a", "user_target", "YWFhYWFhYWFhYWFhYWFhYWFhYWFhYWFhYWFhYWFhYWE"))
	if err == nil {
		t.Fatal("expected audit failure")
	}
	if len(uow.state.bindings) != 0 || len(uow.state.receipts) != 0 || len(uow.state.reasonEnds) != 0 {
		t.Fatalf("failed mutation leaked state: %+v", uow.state)
	}
}

func TestRoleServiceUpdateDisableRejectSelfAndSuperRevoke(t *testing.T) {
	state := newRoleMemoryState()
	scope := Scope{Kind: ScopeEvent, EventID: "evt_a"}
	state.bindings[bindingScopeKey("user_actor", scope)] = Binding{ID: "arb_self", UserID: "user_actor", Role: RoleAdmin, Scope: scope, Enabled: true, Version: 1}
	state.bindings[bindingScopeKey("user_target", scope)] = Binding{ID: "arb_super", UserID: "user_target", Role: RoleSuperAdmin, Scope: scope, Enabled: true, Version: 1}
	service, _, _ := newRoleServiceForTest(t, state)
	key := "YWFhYWFhYWFhYWFhYWFhYWFhYWFhYWFhYWFhYWFhYWE"
	if _, err := service.UpdateRole(context.Background(), UpdateRoleInput{ActorID: "user_actor", TargetUserID: "user_actor", BindingID: "arb_self", EventID: "evt_a", Role: RoleSeniorAdmin, ReasonID: "reason_1", RequestID: "request_1", IdempotencyKey: key, ExpectedVersion: 1}); !errors.Is(err, ErrSelfRoleMutation) {
		t.Fatalf("self update error=%v", err)
	}
	if _, err := service.DisableRole(context.Background(), DisableRoleInput{ActorID: "user_actor", TargetUserID: "user_actor", BindingID: "arb_self", EventID: "evt_a", ReasonID: "reason_1", RequestID: "request_1", IdempotencyKey: key, ExpectedVersion: 1}); !errors.Is(err, ErrSelfRoleMutation) {
		t.Fatalf("self disable error=%v", err)
	}
	if _, err := service.DisableRole(context.Background(), DisableRoleInput{ActorID: "user_actor", TargetUserID: "user_target", BindingID: "arb_super", EventID: "evt_a", ReasonID: "reason_1", RequestID: "request_1", IdempotencyKey: key, ExpectedVersion: 1}); !errors.Is(err, ErrOrdinarySuperAdminMutation) {
		t.Fatalf("super revoke error=%v", err)
	}
}
