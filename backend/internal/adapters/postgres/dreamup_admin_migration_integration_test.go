//go:build integration

package postgres

import (
	"context"
	"database/sql"
	"strings"
	"testing"
	"time"

	"github.com/pressly/goose/v3"
)

func TestDreamUPAdministrationMigration(t *testing.T) {
	db := openMigrationTestDB(t)
	ctx := context.Background()
	migrations := findMigrationsDir(t)
	if err := goose.UpToContext(ctx, db, migrations, 11); err != nil {
		t.Fatalf("migrate to v11: %v", err)
	}
	if tableExists(t, db, "admin_role_bindings") {
		t.Fatal("DreamUP table exists before lineage bridge")
	}
	if err := goose.UpToContext(ctx, db, migrations, 12); err != nil {
		t.Fatalf("migrate v11 to v12: %v", err)
	}
	if !tableExists(t, db, "user_avatars") || !tableExists(t, db, "contact_change_requests") {
		t.Fatal("public v12 account self-service tables are missing")
	}
	if tableExists(t, db, "admin_role_bindings") {
		t.Fatal("public v12 unexpectedly created DreamUP administration tables")
	}
	version, err := goose.GetDBVersion(db)
	if err != nil || version != 12 {
		t.Fatalf("public lineage version=%d err=%v", version, err)
	}
	if err := goose.UpToContext(ctx, db, migrations, 13); err != nil {
		t.Fatalf("migrate public v12 through lineage bridge: %v", err)
	}
	assertDreamUPAdminConstraints(t, db)
	if !tableExists(t, db, "identity_access_grant_fields") {
		t.Fatal("identity-access workflow table is missing after lineage bridge")
	}
	version, err = goose.GetDBVersion(db)
	if err != nil || version != 13 {
		t.Fatalf("version=%d err=%v", version, err)
	}
	// Startup uses only Up; the bridge's aborting Down cannot be reached by this path.
}

func TestPublicV12LineagePreservesAccountDataThroughV16(t *testing.T) {
	db := openMigrationTestDB(t)
	ctx := context.Background()
	migrations := findMigrationsDir(t)
	if err := goose.UpToContext(ctx, db, migrations, 12); err != nil {
		t.Fatalf("migrate to public v12: %v", err)
	}
	createIntegrationUser(t, db, "u_public_v12")
	if _, err := db.Exec(`INSERT INTO user_avatars(avatar_id,user_id,content_type,content,etag)
		VALUES('avt_0123456789abcdef0123456789abcdef','u_public_v12','image/png',decode('01','hex'),repeat('a',64))`); err != nil {
		t.Fatalf("insert public-v12 avatar fixture: %v", err)
	}
	if _, err := db.Exec(`INSERT INTO contact_change_requests(request_id_hash,user_id,session_id,kind,value,expires_at)
		VALUES(repeat('b',64),'u_public_v12','session-public-v12','email','next@example.test',NOW()+INTERVAL '1 hour')`); err != nil {
		t.Fatalf("insert public-v12 contact fixture: %v", err)
	}
	if err := goose.UpToContext(ctx, db, migrations, 16); err != nil {
		t.Fatalf("migrate public v12 to v16: %v", err)
	}
	for table := range map[string]struct{}{"user_avatars": {}, "contact_change_requests": {}} {
		var count int
		if err := db.QueryRow(`SELECT COUNT(*) FROM ` + table + ` WHERE user_id='u_public_v12'`).Scan(&count); err != nil || count != 1 {
			t.Fatalf("preserved %s rows=%d err=%v", table, count, err)
		}
	}
}

func TestProductionV13LineageReconcilesAccountTablesAtV16(t *testing.T) {
	db := openMigrationTestDB(t)
	ctx := context.Background()
	migrations := findMigrationsDir(t)
	if err := goose.UpToContext(ctx, db, migrations, 13); err != nil {
		t.Fatalf("build v13 schema fixture: %v", err)
	}
	createIntegrationUser(t, db, "u_production_v13")
	if _, err := db.Exec(`INSERT INTO dreamup_event_registry(event_id,series,slug,display_name,source_version,authoritative_read_at)
		VALUES('evt_production_v13','dreamup','production-v13','Production V13','fixture-v1',NOW())`); err != nil {
		t.Fatalf("insert production-v13 DreamUP fixture: %v", err)
	}
	// Production used v12/v13 for DreamUP and identity access, so its physical
	// v13 schema has no account tables even though Goose records versions 12/13.
	if _, err := db.Exec(`DROP TABLE contact_change_requests, user_avatars`); err != nil {
		t.Fatalf("shape production-v13 fixture: %v", err)
	}
	if err := goose.UpToContext(ctx, db, migrations, 16); err != nil {
		t.Fatalf("migrate production v13 to v16: %v", err)
	}
	if !tableExists(t, db, "user_avatars") || !tableExists(t, db, "contact_change_requests") {
		t.Fatal("v16 did not reconcile production account tables")
	}
	var eventCount int
	if err := db.QueryRow(`SELECT COUNT(*) FROM dreamup_event_registry WHERE event_id='evt_production_v13'`).Scan(&eventCount); err != nil || eventCount != 1 {
		t.Fatalf("production DreamUP data was not preserved: count=%d err=%v", eventCount, err)
	}
	version, err := goose.GetDBVersion(db)
	if err != nil || version != 16 {
		t.Fatalf("production lineage version=%d err=%v", version, err)
	}
	if err := goose.DownContext(ctx, db, migrations); err == nil {
		t.Fatal("forward-only lineage reconciliation unexpectedly rolled back")
	}
	version, err = goose.GetDBVersion(db)
	if err != nil || version != 16 {
		t.Fatalf("failed v16 Down drifted migration version=%d err=%v", version, err)
	}
}

func TestDreamUPOperationRecoveryMigration(t *testing.T) {
	db := openMigrationTestDB(t)
	ctx := context.Background()
	migrations := findMigrationsDir(t)
	if err := goose.UpToContext(ctx, db, migrations, 14); err != nil {
		t.Fatalf("migrate to v14: %v", err)
	}
	if _, err := db.Exec(`INSERT INTO admin_operation_outbox(operation_id,operation_kind,idempotency_key,request_fingerprint_version,request_fingerprint_key_id,request_fingerprint_hmac,delivery_state,next_attempt_at,version) VALUES('out_pre15_operator','cross_system','idem-pre15-operator','hmac-sha256-v1','fingerprint-v1','signed-fingerprint-value-pre15-operator','needs_operator',NOW(),1)`); err != nil {
		t.Fatalf("insert v14 needs_operator fixture: %v", err)
	}
	if err := goose.UpToContext(ctx, db, migrations, 15); err != nil {
		t.Fatalf("migrate v14 to v15: %v", err)
	}
	var terminal *time.Time
	if err := db.QueryRow(`SELECT terminal_at FROM admin_operation_outbox WHERE operation_id='out_pre15_operator'`).Scan(&terminal); err != nil || terminal == nil {
		t.Fatalf("needs_operator terminal_at=%v err=%v", terminal, err)
	}
	base := `INSERT INTO admin_operation_outbox(operation_id,operation_kind,idempotency_key,request_fingerprint_version,request_fingerprint_key_id,request_fingerprint_hmac,result_code,result_digest,result_payload,delivery_state,terminal_at,next_attempt_at,version) VALUES($1,'cross_system',$2,'hmac-sha256-v1','fingerprint-v1','signed-fingerprint-value-recovery-000001',$3,$4,$5::jsonb,$6,$7,NOW(),1)`
	validPayload := `{"event_id":"evt_shanghai","operation_request_id":":trace-admin_123","actor_id":"user_1","receipt_action":"application.review_saved","receipt_target_type":"application","receipt_target_id":"app_1","response_status":"200","result_version":"2"}`
	if _, err := db.Exec(base, "out_recovery_ok", "idem-recovery-ok-000000000000000001", "operation.settled", strings.Repeat("a", 64), validPayload, "succeeded", time.Now().UTC()); err != nil {
		t.Fatalf("valid recovery result rejected: %v", err)
	}
	for name, payload := range map[string]string{
		"body":   `{"event_id":"evt_shanghai","operation_request_id":"req_operation_2","actor_id":"user_1","response_body":"secret"}`,
		"actor":  `{"event_id":"evt_shanghai","operation_request_id":"req_operation_2","actor_id":"admin"}`,
		"status": `{"event_id":"evt_shanghai","operation_request_id":"req_operation_2","actor_id":"user_1","response_status":"099"}`,
	} {
		t.Run(name, func(t *testing.T) {
			if _, err := db.Exec(base, "out_bad_"+name, "idem-recovery-bad-"+name+"-000000000000000", "operation.failed", "", payload, "failed", time.Now().UTC()); err == nil {
				t.Fatal("invalid recovery metadata accepted")
			}
		})
	}
	if _, err := db.Exec(`INSERT INTO admin_operation_outbox(operation_id,operation_kind,idempotency_key,request_fingerprint_version,request_fingerprint_key_id,request_fingerprint_hmac,delivery_state,next_attempt_at,version) VALUES('out_operator_without_terminal','cross_system','idem-operator-without-terminal','hmac-sha256-v1','fingerprint-v1','signed-fingerprint-value-operator-terminal','needs_operator',NOW(),1)`); err == nil {
		t.Fatal("v15 accepted nonterminal needs_operator row")
	}
	var indexExists bool
	if err := db.QueryRow(`SELECT EXISTS (SELECT 1 FROM pg_indexes WHERE schemaname=current_schema() AND indexname='idx_admin_operation_outbox_receipt_due')`).Scan(&indexExists); err != nil || !indexExists {
		t.Fatalf("receipt due index exists=%v err=%v", indexExists, err)
	}
	if err := goose.DownContext(ctx, db, migrations); err == nil {
		t.Fatal("forward-only recovery migration unexpectedly rolled back")
	}
	version, err := goose.GetDBVersion(db)
	if err != nil || version != 15 {
		t.Fatalf("failed Down drifted migration version=%d err=%v", version, err)
	}
	if err := db.QueryRow(`SELECT EXISTS (SELECT 1 FROM pg_indexes WHERE schemaname=current_schema() AND indexname='idx_admin_operation_outbox_receipt_due')`).Scan(&indexExists); err != nil || !indexExists {
		t.Fatalf("failed Down drifted v15 schema: index exists=%v err=%v", indexExists, err)
	}
}

func assertDreamUPAdminConstraints(t *testing.T, db *sql.DB) {
	t.Helper()
	for _, table := range []string{"admin_role_bindings", "dreamup_event_registry", "admin_challenges", "admin_step_up_state", "protected_operation_reasons", "identity_access_requests", "identity_access_request_fields", "identity_access_grants", "admin_operation_outbox", "admin_operator_approvals", "admin_security_event_vocabulary"} {
		if !tableExists(t, db, table) {
			t.Fatalf("table %s missing", table)
		}
	}
	createIntegrationUser(t, db, "u_super")
	createIntegrationUser(t, db, "u_admin")
	createIntegrationUser(t, db, "u_target")
	createIntegrationUser(t, db, "u_approver")
	if _, err := db.Exec(`INSERT INTO admin_role_bindings (binding_id,user_id,role,scope_kind,scope_key,enabled,version,granted_by,reason_id,created_at,updated_at) VALUES ('b1','u_super','super_admin','system','system',TRUE,1,'u_super','r1',NOW(),NOW())`); err != nil {
		t.Fatalf("insert system super: %v", err)
	}
	if _, err := db.Exec(`INSERT INTO admin_role_bindings (binding_id,user_id,role,scope_kind,scope_key,event_id,enabled,version,granted_by,reason_id,created_at,updated_at) VALUES ('b2','u_admin','admin','event','evt_shanghai','evt_shanghai',TRUE,1,'u_super','r2',NOW(),NOW())`); err != nil {
		t.Fatalf("insert event admin: %v", err)
	}
	if _, err := db.Exec(`INSERT INTO admin_role_bindings (binding_id,user_id,role,scope_kind,scope_key,enabled,version,granted_by,reason_id,created_at,updated_at) VALUES ('bad','u_admin','admin','system','system',TRUE,1,'u_super','r3',NOW(),NOW())`); err == nil {
		t.Fatal("system admin constraint accepted")
	}
	if _, err := db.Exec(`INSERT INTO admin_role_bindings (binding_id,user_id,role,scope_kind,scope_key,event_id,enabled,version,granted_by,reason_id,created_at,updated_at) VALUES ('dup','u_admin','senior_admin','event','evt_shanghai','evt_shanghai',TRUE,1,'u_super','r4',NOW(),NOW())`); err == nil {
		t.Fatal("duplicate active binding accepted")
	}
	if _, err := db.Exec(`UPDATE admin_role_bindings SET disabled_at=NOW(), enabled=FALSE WHERE binding_id='b2'`); err != nil {
		t.Fatal(err)
	}
	if _, err := db.Exec(`INSERT INTO admin_role_bindings (binding_id,user_id,role,scope_kind,scope_key,event_id,enabled,version,granted_by,reason_id,created_at,updated_at) VALUES ('b3','u_admin','senior_admin','event','evt_shanghai','evt_shanghai',TRUE,1,'u_super','r5',NOW(),NOW())`); err != nil {
		t.Fatalf("disabled history blocked replacement: %v", err)
	}
	if _, err := db.Exec(`INSERT INTO admin_role_bindings (binding_id,user_id,role,scope_kind,scope_key,enabled,version,granted_by,reason_id,created_at,updated_at) VALUES ('nullscope','u_target','super_admin','system',NULL,TRUE,1,'u_super','r6',NOW(),NOW())`); err == nil {
		t.Fatal("nullable system scope sentinel accepted")
	}

	if _, err := db.Exec(`INSERT INTO dreamup_event_registry(event_id,series,slug,display_name,source_version,authoritative_read_at,enabled,version) VALUES('evt_shanghai','dreamup','shanghai-2026','Shanghai','source-v1',NOW(),TRUE,1)`); err != nil {
		t.Fatalf("insert DreamUP registry event: %v", err)
	}
	if _, err := db.Exec(`UPDATE dreamup_event_registry SET event_id='evt_other' WHERE event_id='evt_shanghai'`); err == nil {
		t.Fatal("immutable registry event id changed")
	}
	if _, err := db.Exec(`INSERT INTO dreamup_event_registry(event_id,series,slug,display_name,source_version,authoritative_read_at,enabled,version) VALUES('evt_wrong','beijing','shanghai-copy','Wrong','source-v1',NOW(),TRUE,1)`); err == nil {
		t.Fatal("non-DreamUP authoritative event accepted")
	}

	if _, err := db.Exec(`INSERT INTO admin_challenges(user_id,status,must_rotate,question_key_id,question_nonce,question_ciphertext,answer_phc,answer_pepper_key_id,credential_version,security_epoch,version) VALUES('u_admin','active',TRUE,'enc-v1',decode('0102','hex'),decode('0304','hex'),'$argon2id$v=19$m=1,t=1,p=1$c2FsdA$ZGlnaWVzdA','pepper-v1',1,1,1)`); err != nil {
		t.Fatalf("insert active challenge metadata: %v", err)
	}
	if _, err := db.Exec(`INSERT INTO admin_challenges(user_id,status,must_rotate,question_key_id,question_nonce,question_ciphertext,answer_phc,answer_pepper_key_id,credential_version,security_epoch,version) VALUES('u_target','recovery_pending',TRUE,'enc-v1',decode('01','hex'),decode('02','hex'),'phc','pepper-v1',1,1,1)`); err == nil {
		t.Fatal("recovery challenge retained secret columns")
	}
	if _, err := db.Exec(`INSERT INTO admin_step_up_state(step_up_id,session_id,user_id,challenge_version,security_epoch,verified_at,expires_at) VALUES('step_1','session_1','u_admin',1,1,NOW(),NOW()+INTERVAL '5 minutes')`); err != nil {
		t.Fatalf("insert step-up state: %v", err)
	}
	if _, err := db.Exec(`INSERT INTO admin_step_up_state(step_up_id,session_id,user_id,challenge_version,security_epoch,verified_at,expires_at) VALUES('step_bad','session_2','u_admin',1,1,NOW(),NOW())`); err == nil {
		t.Fatal("non-positive step-up lifetime accepted")
	}

	if _, err := db.Exec(`INSERT INTO protected_operation_reasons(reason_id,owner_user_id,operation_kind,key_id,nonce,ciphertext,created_at) VALUES('reason_1','u_admin','identity_access','reason-v1',decode('01','hex'),decode('02','hex'),NOW())`); err != nil {
		t.Fatalf("insert protected reason: %v", err)
	}

	if _, err := db.Exec(`INSERT INTO identity_access_requests (request_id,event_id,requester_user_id,target_subject_user_id,target_type,target_id,status,version,reason_id,created_at,updated_at) VALUES ('iar1','evt_shanghai','u_admin','u_target','application','app_1','pending',1,'reason_1',NOW(),NOW())`); err != nil {
		t.Fatalf("insert OA request: %v", err)
	}
	if _, err := db.Exec(`INSERT INTO identity_access_request_fields (request_id,field_name) VALUES ('iar1','answers_json')`); err == nil {
		t.Fatal("unknown OA field accepted")
	}
	if _, err := db.Exec(`INSERT INTO identity_access_request_fields (request_id,field_name) VALUES ('iar1','legal_name')`); err != nil {
		t.Fatalf("valid OA field rejected: %v", err)
	}
	if _, err := db.Exec(`INSERT INTO identity_access_requests (request_id,event_id,requester_user_id,target_subject_user_id,target_type,target_id,status,version,reason_id,created_at,updated_at) VALUES ('self','evt_shanghai','u_admin','u_admin','application','app_1','pending',1,'reason_2',NOW(),NOW())`); err == nil {
		t.Fatal("self-target OA request accepted")
	}
	if _, err := db.Exec(`INSERT INTO identity_access_requests (request_id,event_id,requester_user_id,target_subject_user_id,target_type,target_id,status,version,reason_id,created_at,updated_at) VALUES ('badtype','evt_shanghai','u_admin','u_target','user','app_1','pending',1,'reason_2',NOW(),NOW())`); err == nil {
		t.Fatal("unknown OA target type accepted")
	}
	if _, err := db.Exec(`INSERT INTO identity_access_requests (request_id,event_id,requester_user_id,target_subject_user_id,target_type,target_id,status,version,reason_id,terminal_at,created_at,updated_at) VALUES ('missing_approver','evt_shanghai','u_admin','u_target','application','app_1','approved',1,'reason_2',NOW(),NOW()-INTERVAL '1 minute',NOW())`); err == nil {
		t.Fatal("approved OA request without a distinct approver accepted")
	}

	if _, err := db.Exec(`INSERT INTO identity_access_requests (request_id,event_id,requester_user_id,target_subject_user_id,target_type,target_id,status,approver_user_id,version,reason_id,terminal_at,created_at,updated_at) VALUES ('iar_grant_1','evt_shanghai','u_admin','u_target','application','app_claim','approved','u_approver',1,'reason_g1',NOW(),NOW()-INTERVAL '1 minute',NOW())`); err != nil {
		t.Fatalf("insert approved OA request: %v", err)
	}
	if _, err := db.Exec(`INSERT INTO identity_access_grants(grant_id,request_id,event_id,requester_user_id,target_subject_user_id,target_type,target_id,approved_by_user_id,status,claim_nonce_hash,claim_lease_until,version,expires_at,created_at,updated_at) VALUES('grant_1','iar_grant_1','evt_shanghai','u_admin','u_target','application','app_claim','u_approver','claimed','nonce-hash',NOW()+INTERVAL '1 minute',1,NOW()+INTERVAL '5 minutes',NOW(),NOW())`); err != nil {
		t.Fatalf("insert claimed OA grant: %v", err)
	}
	if _, err := db.Exec(`INSERT INTO identity_access_requests (request_id,event_id,requester_user_id,target_subject_user_id,target_type,target_id,status,approver_user_id,version,reason_id,terminal_at,created_at,updated_at) VALUES ('iar_grant_2','evt_shanghai','u_admin','u_target','application','app_claim','approved','u_approver',1,'reason_g2',NOW(),NOW()-INTERVAL '1 minute',NOW())`); err != nil {
		t.Fatalf("insert second approved request: %v", err)
	}
	if _, err := db.Exec(`INSERT INTO identity_access_grants(grant_id,request_id,event_id,requester_user_id,target_subject_user_id,target_type,target_id,approved_by_user_id,status,claim_nonce_hash,claim_lease_until,version,expires_at,created_at,updated_at) VALUES('grant_2','iar_grant_2','evt_shanghai','u_admin','u_target','application','app_claim','u_approver','claimed','other-nonce',NOW()+INTERVAL '1 minute',1,NOW()+INTERVAL '5 minutes',NOW(),NOW())`); err == nil {
		t.Fatal("second active claim for same requester/target accepted")
	}
	if _, err := db.Exec(`INSERT INTO identity_access_requests (request_id,event_id,requester_user_id,target_subject_user_id,target_type,target_id,status,approver_user_id,version,reason_id,terminal_at,created_at,updated_at) VALUES ('iar_grant_self','evt_shanghai','u_admin','u_target','application','app_other','approved','u_approver',1,'reason_self',NOW(),NOW()-INTERVAL '1 minute',NOW())`); err != nil {
		t.Fatalf("insert self-approval fixture request: %v", err)
	}
	if _, err := db.Exec(`INSERT INTO identity_access_grants(grant_id,request_id,event_id,requester_user_id,target_subject_user_id,target_type,target_id,approved_by_user_id,status,version,expires_at,created_at,updated_at) VALUES('grant_self','iar_grant_self','evt_shanghai','u_admin','u_target','application','app_other','u_admin','active',1,NOW()+INTERVAL '5 minutes',NOW(),NOW())`); err == nil {
		t.Fatal("requester approved their own grant")
	}

	if _, err := db.Exec(`INSERT INTO admin_operation_outbox(operation_id,operation_kind,idempotency_key,request_fingerprint_version,request_fingerprint_key_id,request_fingerprint_hmac,delivery_state,next_attempt_at,version) VALUES('out_1','local','idem-000000000001','hmac-sha256-v1','fingerprint-v1','signed-fingerprint-value-000000000000','pending',NOW(),1)`); err != nil {
		t.Fatalf("insert pending outbox: %v", err)
	}
	if _, err := db.Exec(`INSERT INTO admin_operation_outbox(operation_id,operation_kind,idempotency_key,request_fingerprint_version,request_fingerprint_key_id,request_fingerprint_hmac,delivery_state,next_attempt_at,version) VALUES('out_dup','local','idem-000000000001','hmac-sha256-v1','fingerprint-v1','different-signed-fingerprint-00000000','pending',NOW(),1)`); err == nil {
		t.Fatal("duplicate idempotency tombstone accepted")
	}
	concurrentResults := make(chan error, 2)
	for _, operationID := range []string{"out_race_1", "out_race_2"} {
		go func(id string) {
			_, err := db.Exec(`INSERT INTO admin_operation_outbox(operation_id,operation_kind,idempotency_key,request_fingerprint_version,request_fingerprint_key_id,request_fingerprint_hmac,delivery_state,next_attempt_at,version) VALUES($1,'local','idem-concurrent-000001','hmac-sha256-v1','fingerprint-v1','signed-fingerprint-concurrent-000001','pending',NOW(),1)`, id)
			concurrentResults <- err
		}(operationID)
	}
	winners := 0
	for range 2 {
		if err := <-concurrentResults; err == nil {
			winners++
		}
	}
	if winners != 1 {
		t.Fatalf("concurrent idempotency winners=%d, want exactly 1", winners)
	}
	if _, err := db.Exec(`INSERT INTO admin_operation_outbox(operation_id,operation_kind,idempotency_key,request_fingerprint_version,request_fingerprint_key_id,request_fingerprint_hmac,delivery_state,next_attempt_at,version) VALUES('out_claim_bad','cross_system','idem-000000000002','hmac-sha256-v1','fingerprint-v1','signed-fingerprint-value-000000000001','claimed',NOW(),1)`); err == nil {
		t.Fatal("claimed outbox without claim token/lease accepted")
	}
	if _, err := db.Exec(`INSERT INTO admin_operation_outbox(operation_id,operation_kind,idempotency_key,request_fingerprint_version,request_fingerprint_key_id,request_fingerprint_hmac,result_code,result_payload,delivery_state,terminal_at,next_attempt_at,version) VALUES('out_payload_bad','local','idem-000000000003','hmac-sha256-v1','fingerprint-v1','signed-fingerprint-value-000000000002','operation.settled','{"answer":"not allowed"}'::jsonb,'succeeded',NOW(),NOW(),1)`); err == nil {
		t.Fatal("sensitive result payload key accepted")
	}
	if _, err := db.Exec(`INSERT INTO admin_operation_outbox(operation_id,operation_kind,idempotency_key,request_fingerprint_version,request_fingerprint_key_id,request_fingerprint_hmac,result_code,result_payload,delivery_state,terminal_at,next_attempt_at,version) VALUES('out_payload_disguised','local','idem-000000000003b','hmac-sha256-v1','fingerprint-v1','signed-fingerprint-value-000000000002b','operation.settled','{"binding_id":"raw secret"}'::jsonb,'succeeded',NOW(),NOW(),1)`); err == nil {
		t.Fatal("sensitive result payload value disguised as an allowlisted key accepted")
	}
	if _, err := db.Exec(`INSERT INTO admin_operation_outbox(operation_id,operation_kind,idempotency_key,request_fingerprint_version,request_fingerprint_key_id,request_fingerprint_hmac,delivery_state,attempts,next_attempt_at,version) VALUES('out_operator','cross_system','idem-000000000004','hmac-sha256-v1','fingerprint-v1','signed-fingerprint-value-000000000003','needs_operator',999,NOW(),1)`); err != nil {
		t.Fatalf("needs_operator row was terminalized by attempt count: %v", err)
	}
	if _, err := db.Exec(`INSERT INTO admin_operation_outbox(operation_id,operation_kind,idempotency_key,request_fingerprint_version,request_fingerprint_key_id,request_fingerprint_hmac,payload_key_id,delivery_state,next_attempt_at,version) VALUES('out_payload_partial','cross_system','idem-000000000005','hmac-sha256-v1','fingerprint-v1','signed-fingerprint-value-000000000004','payload-v1','pending',NOW(),1)`); err == nil {
		t.Fatal("partial encrypted outbox payload accepted")
	}

	if _, err := db.Exec(`INSERT INTO admin_operator_approvals (approval_id,request_hash,operator_user_id,key_id,signature,expires_at,created_at) VALUES ('op1','request-hash-0001','u_super','k1','sig',NOW()+INTERVAL '1 hour',NOW())`); err != nil {
		t.Fatal(err)
	}
	if _, err := db.Exec(`INSERT INTO admin_operator_approvals (approval_id,request_hash,operator_user_id,key_id,signature,expires_at,created_at) VALUES ('op2','request-hash-0001','u_super','k1','sig2',NOW()+INTERVAL '1 hour',NOW())`); err == nil {
		t.Fatal("operator replay accepted")
	}

	var nullableTerminal *time.Time
	if err := db.QueryRow(`SELECT terminal_at FROM identity_access_requests WHERE request_id='iar1'`).Scan(&nullableTerminal); err != nil || nullableTerminal != nil {
		t.Fatalf("pending terminal_at=%v err=%v", nullableTerminal, err)
	}
	if err := db.QueryRow(`SELECT terminal_at FROM admin_operator_approvals WHERE approval_id='op1'`).Scan(&nullableTerminal); err != nil || nullableTerminal != nil {
		t.Fatalf("active operator terminal_at=%v err=%v", nullableTerminal, err)
	}
	assertDreamUPAdminIndexPlans(t, db)
}

func assertDreamUPAdminIndexPlans(t *testing.T, db *sql.DB) {
	t.Helper()
	if _, err := db.Exec(`SET enable_seqscan = off`); err != nil {
		t.Fatalf("disable seqscan for index contract: %v", err)
	}
	tests := []struct{ index, query string }{
		{"idx_admin_role_bindings_retention", `SELECT binding_id FROM admin_role_bindings WHERE disabled_at IS NOT NULL ORDER BY disabled_at,binding_id LIMIT 10`},
		{"idx_protected_operation_reasons_retention", `SELECT reason_id FROM protected_operation_reasons WHERE expires_at IS NOT NULL AND purged_at IS NULL ORDER BY expires_at,reason_id LIMIT 10`},
		{"idx_identity_access_requests_retention", `SELECT request_id FROM identity_access_requests WHERE terminal_at IS NOT NULL ORDER BY terminal_at,request_id LIMIT 10`},
		{"idx_identity_access_grants_retention", `SELECT grant_id FROM identity_access_grants WHERE terminal_at IS NOT NULL ORDER BY terminal_at,grant_id LIMIT 10`},
		{"idx_admin_operation_outbox_due", `SELECT operation_id FROM admin_operation_outbox WHERE delivery_state='pending' AND delivery_phase='not_sent' AND next_attempt_at<=NOW() ORDER BY next_attempt_at,operation_id LIMIT 10`},
		{"idx_admin_operation_outbox_expired_claim", `SELECT operation_id FROM admin_operation_outbox WHERE delivery_state='claimed' ORDER BY claim_lease_until,operation_id LIMIT 10`},
		{"idx_admin_operation_outbox_payload_retention", `SELECT operation_id FROM admin_operation_outbox WHERE payload_expires_at IS NOT NULL AND payload_purged_at IS NULL ORDER BY payload_expires_at,operation_id LIMIT 10`},
		{"idx_admin_operator_approvals_retention", `SELECT approval_id FROM admin_operator_approvals WHERE terminal_at IS NOT NULL ORDER BY terminal_at,approval_id LIMIT 10`},
	}
	for _, tt := range tests {
		rows, err := db.Query(`EXPLAIN (COSTS OFF) ` + tt.query)
		if err != nil {
			t.Fatalf("explain %s: %v", tt.index, err)
		}
		var plan strings.Builder
		for rows.Next() {
			var line string
			if err := rows.Scan(&line); err != nil {
				rows.Close()
				t.Fatal(err)
			}
			plan.WriteString(line)
			plan.WriteByte('\n')
		}
		rows.Close()
		if !strings.Contains(plan.String(), tt.index) {
			t.Fatalf("query plan did not use %s:\n%s", tt.index, plan.String())
		}
	}
}

func createIntegrationUser(t *testing.T, db *sql.DB, id string) {
	t.Helper()
	if _, err := db.Exec(`INSERT INTO users (id,status,version,created_at,updated_at) VALUES ($1,'active',1,NOW(),NOW())`, id); err != nil {
		t.Fatalf("create user %s: %v", id, err)
	}
}
