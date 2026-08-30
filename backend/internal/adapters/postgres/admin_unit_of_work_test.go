package postgres

import (
	"context"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"

	"github.com/GravelEvolution/united-pass/backend/internal/adminroles"
	"github.com/GravelEvolution/united-pass/backend/internal/adminstepup"
	"github.com/GravelEvolution/united-pass/backend/internal/adminstore"
)

type recordingAdminTx struct {
	pgx.Tx
	commits, rollbacks int
	seenQueries        int
	lastQuery          string
	queries            []string
	lastArgs           []any
	rowsAffected       int64
}

func (t *recordingAdminTx) Exec(_ context.Context, query string, args ...any) (pgconn.CommandTag, error) {
	t.seenQueries++
	t.lastQuery = query
	t.queries = append(t.queries, query)
	t.lastArgs = append([]any(nil), args...)
	rows := t.rowsAffected
	if rows < 0 {
		return pgconn.NewCommandTag("UPDATE 0"), nil
	}
	if rows == 0 {
		rows = 1
	}
	return pgconn.NewCommandTag("UPDATE 1"), nil
}

func (t *recordingAdminTx) Commit(context.Context) error { t.commits++; return nil }
func (t *recordingAdminTx) Rollback(context.Context) error {
	if t.commits == 0 {
		t.rollbacks++
	}
	return nil
}

type recordingAdminBeginner struct{ tx *recordingAdminTx }

func (b recordingAdminBeginner) BeginTx(context.Context, pgx.TxOptions) (pgx.Tx, error) {
	return b.tx, nil
}

func TestAdminUnitOfWorkSharesOneTransactionAndCommitsOnce(t *testing.T) {
	tx := &recordingAdminTx{}
	uow := newAdminUnitOfWork(recordingAdminBeginner{tx: tx}, nil)
	err := uow.Within(context.Background(), func(repos adminstore.Repositories) error {
		if !repositoriesUseTx(repos, tx) {
			t.Fatal("repositories do not share one pgx.Tx")
		}
		_, err := repos.Roles.(*AdminRoleRepository).exec.Exec(context.Background(), "role mutation")
		if err != nil {
			return err
		}
		_, err = repos.SecurityEvents.(*transactionSecurityEventStore).exec.Exec(context.Background(), "audit mutation")
		return err
	})
	if err != nil {
		t.Fatal(err)
	}
	if tx.commits != 1 || tx.rollbacks != 0 || tx.seenQueries != 2 {
		t.Fatalf("commits=%d rollbacks=%d queries=%d", tx.commits, tx.rollbacks, tx.seenQueries)
	}
}

func TestAdminUnitOfWorkRollsBackCallbackOrAuditFailure(t *testing.T) {
	for _, failure := range []error{errors.New("domain failed"), errors.New("audit failed")} {
		tx := &recordingAdminTx{}
		uow := newAdminUnitOfWork(recordingAdminBeginner{tx: tx}, nil)
		err := uow.Within(context.Background(), func(adminstore.Repositories) error { return failure })
		if !errors.Is(err, failure) {
			t.Fatalf("error=%v, want %v", err, failure)
		}
		if tx.commits != 0 || tx.rollbacks != 1 {
			t.Fatalf("commits=%d rollbacks=%d", tx.commits, tx.rollbacks)
		}
	}
}

func TestIsolatedAdminOutboxUnitOfWorkExposesOnlyOutbox(t *testing.T) {
	tx := &recordingAdminTx{}
	uow := &AdminOutboxUnitOfWork{beginner: recordingAdminBeginner{tx: tx}}
	err := uow.Within(context.Background(), func(repositories adminstore.Repositories) error {
		outbox, ok := repositories.Outbox.(*adminOutboxRepository)
		if !ok || outbox.tx != tx {
			t.Fatal("isolated unit of work did not bind the outbox to its transaction")
		}
		if repositories.Roles != nil || repositories.EventRegistry != nil || repositories.Challenges != nil ||
			repositories.SecurityEpoch != nil || repositories.IdentityAccess != nil || repositories.Reasons != nil ||
			repositories.OperatorApprovals != nil || repositories.SecurityEvents != nil {
			t.Fatal("isolated unit of work exposed an authority repository")
		}
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
	if tx.commits != 1 || tx.rollbacks != 0 {
		t.Fatalf("commits=%d rollbacks=%d", tx.commits, tx.rollbacks)
	}
}

func TestAdminRoleMutationUnitOfWorkUsesSameTransactionAndRollsBack(t *testing.T) {
	tx := &recordingAdminTx{}
	uow := newAdminUnitOfWork(recordingAdminBeginner{tx: tx}, nil)
	failure := errors.New("role mutation failed")
	err := uow.WithinRoleMutation(context.Background(), func(repositories adminroles.RoleMutationRepositories) error {
		reason, reasonOK := repositories.Reasons.(*adminRoleReasonAdapter)
		receipt, receiptOK := repositories.Receipts.(*adminRoleReceiptAdapter)
		actor, actorOK := repositories.ActorAuthorization.(*AdminRoleRepository)
		if !reasonOK || !receiptOK || !actorOK || actor.tx != tx || reason.repository.tx != tx || receipt.repository.(*adminOutboxRepository).tx != tx {
			t.Fatal("role mutation ports do not share the unit-of-work pgx.Tx")
		}
		return failure
	})
	if !errors.Is(err, failure) {
		t.Fatalf("error=%v want=%v", err, failure)
	}
	if tx.commits != 0 || tx.rollbacks != 1 {
		t.Fatalf("commits=%d rollbacks=%d", tx.commits, tx.rollbacks)
	}
}

func TestRoleMutationActorRevalidationSQLLocksExactBindingAndLifecycleRows(t *testing.T) {
	binding := strings.Join(strings.Fields(adminRoleActorBindingLockSQL), " ")
	if !strings.Contains(binding, "binding_id=$1") || !strings.Contains(binding, "user_id=$2") || !strings.Contains(binding, "version=$3") ||
		!strings.Contains(binding, "enabled=TRUE") || !strings.Contains(binding, "disabled_at IS NULL") || !strings.Contains(binding, "FOR UPDATE") {
		t.Fatalf("actor binding revalidation is not exact and locked: %s", binding)
	}
	user := strings.Join(strings.Fields(adminRoleActorUserLockSQL), " ")
	employee := strings.Join(strings.Fields(adminRoleActorEmployeeLockSQL), " ")
	if !strings.Contains(user, "status") || !strings.Contains(user, "FOR UPDATE") ||
		!strings.Contains(employee, "status") || !strings.Contains(employee, "FOR UPDATE") {
		t.Fatalf("actor lifecycle revalidation is not locked: user=%s employee=%s", user, employee)
	}
}

func TestAdminStepUpMutationUnitOfWorkUsesSameTransactionAndRollsBack(t *testing.T) {
	tx := &recordingAdminTx{}
	uow := newAdminUnitOfWork(recordingAdminBeginner{tx: tx}, nil)
	failure := errors.New("step-up audit failed")
	err := uow.WithinStepUpMutation(context.Background(), func(repositories adminstepup.StepUpMutationRepositories) error {
		receipt, receiptOK := repositories.Receipts.(*adminStepUpReceiptAdapter)
		accountSecurity, accountSecurityOK := repositories.AccountSecurity.(adminStepUpAccountSecurityReader)
		approval, approvalOK := repositories.Approvals.(*adminStepUpApprovalAdapter)
		purge, purgeOK := repositories.Purges.(*adminStepUpPurgeAdapter)
		audit, auditOK := repositories.Audit.(*adminStepUpAuditAdapter)
		if !receiptOK || !accountSecurityOK || !approvalOK || !purgeOK || !auditOK ||
			receipt.repository.(*adminOutboxRepository).tx != tx || approval.repository.tx != tx || approval.identityAccess.tx != tx ||
			purge.repository.(*adminOutboxRepository).tx != tx || audit.repository.exec != tx || accountSecurity.tx != tx {
			t.Fatal("step-up mutation ports do not share the unit-of-work pgx.Tx")
		}
		return failure
	})
	if !errors.Is(err, failure) {
		t.Fatalf("error=%v want=%v", err, failure)
	}
	if tx.commits != 0 || tx.rollbacks != 1 {
		t.Fatalf("commits=%d rollbacks=%d", tx.commits, tx.rollbacks)
	}
}

func TestAdminStepUpAccountEpochLocksAuthoritativeUserRow(t *testing.T) {
	query := strings.Join(strings.Fields(adminStepUpAccountSecurityEpochSQL), " ")
	for _, fragment := range []string{"SELECT security_epoch FROM users", "id=$1", "FOR SHARE"} {
		if !strings.Contains(query, fragment) {
			t.Fatalf("account epoch query missing %q: %s", fragment, query)
		}
	}
}

func TestAdminStepUpRotationRevokesOAAndOperatorApprovalsInSameTransaction(t *testing.T) {
	tx := &recordingAdminTx{}
	uow := newAdminUnitOfWork(recordingAdminBeginner{tx: tx}, nil)
	now := time.Date(2026, 8, 17, 15, 0, 0, 0, time.UTC)
	err := uow.WithinStepUpMutation(context.Background(), func(repositories adminstepup.StepUpMutationRepositories) error {
		return repositories.Approvals.RevokeForUser(context.Background(), "user_actor", now)
	})
	if err != nil {
		t.Fatal(err)
	}
	joined := strings.Join(tx.queries, "\n")
	for _, table := range []string{"admin_operator_approvals", "identity_access_requests", "identity_access_grants"} {
		if !strings.Contains(joined, table) {
			t.Errorf("rotation revocation missing %s: %s", table, joined)
		}
	}
	if tx.commits != 1 || tx.rollbacks != 0 {
		t.Fatalf("commits=%d rollbacks=%d", tx.commits, tx.rollbacks)
	}
}

func repositoriesUseTx(repos adminstore.Repositories, tx pgx.Tx) bool {
	roles, rolesOK := repos.Roles.(*AdminRoleRepository)
	registry, registryOK := repos.EventRegistry.(*DreamUPEventRegistryRepository)
	stepup, stepupOK := repos.Challenges.(*AdminStepUpRepository)
	identityRepo, identityOK := repos.IdentityAccess.(*IdentityAccessRepository)
	reasons, reasonsOK := repos.Reasons.(*protectedReasonRepository)
	outbox, outboxOK := repos.Outbox.(*adminOutboxRepository)
	approvals, approvalsOK := repos.OperatorApprovals.(*operatorApprovalRepository)
	audit, auditOK := repos.SecurityEvents.(*transactionSecurityEventStore)
	return rolesOK && registryOK && stepupOK && identityOK && reasonsOK && outboxOK && approvalsOK && auditOK &&
		roles.tx == tx && registry.tx == tx && stepup.tx == tx && identityRepo.tx == tx &&
		reasons.tx == tx && outbox.tx == tx && approvals.tx == tx && audit.exec == tx
}

func TestApplyNullableOutboxStringsHandlesSQLNulls(t *testing.T) {
	item := adminstore.OutboxItem{PayloadKeyID: "stale", ClaimTokenHash: "stale"}
	applyNullableOutboxStrings(&item, nil, nil)
	if item.PayloadKeyID != "" || item.ClaimTokenHash != "" {
		t.Fatalf("SQL nulls left stale values: %+v", item)
	}
	key, claim := "key_1", "claim_hash"
	applyNullableOutboxStrings(&item, &key, &claim)
	if item.PayloadKeyID != key || item.ClaimTokenHash != claim {
		t.Fatalf("non-null values lost: %+v", item)
	}
}

func TestAdminOutboxClaimTokenDigestIsStableAndNotRaw(t *testing.T) {
	first := hashAdminOutboxClaimToken("claim-token")
	second := hashAdminOutboxClaimToken("claim-token")
	if first == "" || first == "claim-token" || first != second {
		t.Fatalf("claim token digest=%q second=%q", first, second)
	}
	if first == hashAdminOutboxClaimToken("different-token") {
		t.Fatal("different claim tokens produced the same digest")
	}
}

func TestAdminOutboxCompleteLocalUsesPendingLocalCAS(t *testing.T) {
	tx := &recordingAdminTx{}
	repo := &adminOutboxRepository{tx: tx}
	at := time.Date(2026, 8, 17, 15, 0, 0, 0, time.UTC)
	result := adminstore.AllowlistedResult{Code: "role.created", Payload: map[string]string{"binding_id": "arb_1", "version": "1"}}
	if err := repo.CompleteLocal(context.Background(), "aop_1", 7, result, at); err != nil {
		t.Fatal(err)
	}
	for _, fragment := range []string{"operation_kind='local'", "delivery_state='pending'", "version=$2", "delivery_state='succeeded'"} {
		if !strings.Contains(tx.lastQuery, fragment) {
			t.Fatalf("query missing %q: %s", fragment, tx.lastQuery)
		}
	}
	if len(tx.lastArgs) < 2 || tx.lastArgs[0] != "aop_1" || tx.lastArgs[1] != int64(7) {
		t.Fatalf("CAS args=%v", tx.lastArgs)
	}
}

func TestAdminOutboxCompleteLocalRejectsInvalidResultAndStaleCAS(t *testing.T) {
	tx := &recordingAdminTx{}
	repo := &adminOutboxRepository{tx: tx}
	if err := repo.CompleteLocal(context.Background(), "aop_1", 1, adminstore.AllowlistedResult{Code: "unsafe"}, time.Now()); !errors.Is(err, adminstore.ErrInvalidOperationResult) {
		t.Fatalf("invalid result error=%v", err)
	}
	tx.rowsAffected = -1
	result := adminstore.AllowlistedResult{Code: "role.updated", Payload: map[string]string{"binding_id": "arb_1", "version": "2"}}
	if err := repo.CompleteLocal(context.Background(), "aop_1", 1, result, time.Now()); !errors.Is(err, adminstore.ErrIdempotencyConflict) {
		t.Fatalf("stale CAS error=%v", err)
	}
}

func TestAdminOutboxClaimDueNeverClaimsOperatorOrAmbiguousDelivery(t *testing.T) {
	for _, fragment := range []string{"delivery_state='pending'", "delivery_phase='not_sent'"} {
		if !strings.Contains(adminOutboxClaimDueSQL, fragment) {
			t.Fatalf("claim query missing %q: %s", fragment, adminOutboxClaimDueSQL)
		}
	}
	if strings.Contains(adminOutboxClaimDueSQL, "needs_operator") {
		t.Fatalf("operator-owned row is worker-claimable: %s", adminOutboxClaimDueSQL)
	}
}

func TestAdminOutboxReceiptClaimIsReceiptOnlyAndFenced(t *testing.T) {
	for _, fragment := range []string{"delivery_state='pending'", "delivery_phase IN('indeterminate','sent')", "FOR UPDATE SKIP LOCKED"} {
		if !strings.Contains(adminOutboxClaimReceiptsDueSQL, fragment) {
			t.Fatalf("receipt claim query missing %q: %s", fragment, adminOutboxClaimReceiptsDueSQL)
		}
	}
	if strings.Contains(adminOutboxClaimReceiptsDueSQL, "not_sent") || strings.Contains(adminOutboxClaimReceiptsDueSQL, "needs_operator") {
		t.Fatalf("receipt claim can replay unsafe work: %s", adminOutboxClaimReceiptsDueSQL)
	}
}

func TestAdminOutboxDeliveryPhaseTransitionsAndExpiredClaimsAreSafelyRecoverable(t *testing.T) {
	tx := &recordingAdminTx{}
	repo := &adminOutboxRepository{tx: tx}
	now := time.Date(2026, 8, 17, 16, 0, 0, 0, time.UTC)
	if err := repo.MarkDeliveryPhase(context.Background(), "aop_1", 2, "claim", adminstore.DeliveryPhaseIndeterminate, now); err != nil {
		t.Fatal(err)
	}
	for _, fragment := range []string{"delivery_phase='indeterminate'", "delivery_phase='not_sent'", "delivery_state='claimed'", "claim_token_hash=$3"} {
		if !strings.Contains(tx.lastQuery, fragment) {
			t.Fatalf("phase transition missing %q: %s", fragment, tx.lastQuery)
		}
	}
	if err := repo.Settle(context.Background(), "aop_1", 3, "claim", adminstore.AllowlistedResult{Code: "operation.settled"}, now); err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(tx.lastQuery, "delivery_phase='sent'") {
		t.Fatalf("settlement did not require confirmed sent phase: %s", tx.lastQuery)
	}
	if err := repo.ReleaseExpiredClaim(context.Background(), "aop_1", 3, now); err != nil {
		t.Fatal(err)
	}
	for _, fragment := range []string{"delivery_state='pending'", "delivery_phase IN('not_sent','indeterminate','sent')", "claim_token_hash=NULL", "claim_lease_until=NULL"} {
		if !strings.Contains(tx.lastQuery, fragment) {
			t.Fatalf("expired claim handling missing %q: %s", fragment, tx.lastQuery)
		}
	}
	if strings.Contains(tx.lastQuery, "needs_operator") {
		t.Fatalf("expired ambiguous claim bypassed receipt reconciliation: %s", tx.lastQuery)
	}
	if err := repo.reclaimExpiredClaims(context.Background(), now); err != nil {
		t.Fatal(err)
	}
	for _, fragment := range []string{"delivery_state='claimed'", "claim_lease_until<=$1", "delivery_state='pending'"} {
		if !strings.Contains(tx.lastQuery, fragment) {
			t.Fatalf("batch reclaim missing %q: %s", fragment, tx.lastQuery)
		}
	}
}

func TestAdminOutboxDeterministicFailureRequiresConfirmedSentPhase(t *testing.T) {
	tx := &recordingAdminTx{}
	repo := &adminOutboxRepository{tx: tx}
	result := adminstore.AllowlistedResult{Code: "operation.failed", Payload: map[string]string{"event_id": "evt_shanghai", "operation_request_id": "req_operation_1", "actor_id": "user_1", "response_status": "409"}}
	if err := repo.Fail(context.Background(), "aop_1", 4, "claim", result, time.Now().UTC()); err != nil {
		t.Fatal(err)
	}
	for _, fragment := range []string{"delivery_state='failed'", "delivery_phase='sent'", "claim_token_hash=$3", "terminal_at=$7"} {
		if !strings.Contains(tx.lastQuery, fragment) {
			t.Fatalf("failure transition missing %q: %s", fragment, tx.lastQuery)
		}
	}
}

type noWriteAdminTx struct{ recordingAdminTx }

func (t *noWriteAdminTx) Exec(context.Context, string, ...any) (pgconn.CommandTag, error) {
	return pgconn.NewCommandTag("INSERT 0 0"), nil
}

func TestPutStepUpRejectsConflictingIdentifierReplay(t *testing.T) {
	tx := &noWriteAdminTx{}
	repo := newAdminStepUpRepository(tx)
	now := time.Date(2026, 8, 17, 14, 0, 0, 0, time.UTC)
	err := repo.PutStepUp(context.Background(), adminstepup.StepUpState{ID: "step_1", SessionID: "session_1", UserID: "user_1", ChallengeVersion: 1, SecurityEpoch: 1, VerifiedAt: now, ExpiresAt: now.Add(time.Minute)})
	if !errors.Is(err, adminstepup.ErrConflict) {
		t.Fatalf("error=%v, want conflict", err)
	}
}

func TestPutStepUpAtomicallyReplacesAnyActivePriorSessionProofBeforeInsert(t *testing.T) {
	tx := &recordingAdminTx{}
	repo := newAdminStepUpRepository(tx)
	now := time.Date(2026, 8, 17, 14, 0, 0, 0, time.UTC)
	err := repo.PutStepUp(context.Background(), adminstepup.StepUpState{ID: "asu_2", SessionID: "session_1", UserID: "user_1", ChallengeVersion: 2, SecurityEpoch: 2, VerifiedAt: now, ExpiresAt: now.Add(5 * time.Minute)})
	if err != nil {
		t.Fatal(err)
	}
	if len(tx.queries) != 2 || !strings.Contains(tx.queries[0], "revoked_at=$3") || !strings.Contains(tx.queries[0], "session_id=$1 AND user_id=$2") || strings.Contains(tx.queries[0], "expires_at") || !strings.Contains(tx.queries[1], "INSERT INTO admin_step_up_state") {
		t.Fatalf("queries=%v", tx.queries)
	}
}

func TestProtectedReasonConsumeRequiresExactOwnerKindAndUnusedCAS(t *testing.T) {
	tx := &recordingAdminTx{}
	repository := &protectedReasonRepository{tx: tx}
	now := time.Date(2026, 8, 17, 14, 0, 0, 0, time.UTC)
	if err := repository.ConsumeOwned(context.Background(), "reason_1", "user_actor", "role", now, now.AddDate(2, 0, 0)); err != nil {
		t.Fatal(err)
	}
	for _, fragment := range []string{"reason_id=$1", "owner_user_id=$2", "operation_kind=$3", "consumed_at IS NULL", "terminal_at IS NULL"} {
		if !strings.Contains(tx.lastQuery, fragment) {
			t.Fatalf("query missing %q: %s", fragment, tx.lastQuery)
		}
	}
	if len(tx.lastArgs) != 5 || tx.lastArgs[0] != "reason_1" || tx.lastArgs[1] != "user_actor" || tx.lastArgs[2] != "role" {
		t.Fatalf("exact reason arguments=%v", tx.lastArgs)
	}
	tx.rowsAffected = -1
	if err := repository.ConsumeOwned(context.Background(), "reason_1", "wrong_owner", "role", now, now.AddDate(2, 0, 0)); !errors.Is(err, adminstore.ErrIdempotencyConflict) {
		t.Fatalf("mismatched or consumed reason error=%v", err)
	}
}
