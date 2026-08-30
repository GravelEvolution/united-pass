--
-- Copyright (c) 2026 Chen Jiajie(Ariakage)
--
-- Description: durable DreamUP mutation outcome recovery metadata and claim reclaim support
--

-- +goose Up
-- +goose StatementBegin

-- This forward-only repair takes short table locks while replacing inherited
-- CHECK constraints. Fail instead of waiting behind live administration
-- traffic, and bound validation/index work so an unsafe rollout rolls back.
SET LOCAL lock_timeout = '5s';
SET LOCAL statement_timeout = '2min';

ALTER TABLE admin_operation_outbox
    DROP CONSTRAINT admin_operation_outbox_result_payload_check,
    DROP CONSTRAINT ck_admin_operation_outbox_result,
    DROP CONSTRAINT ck_admin_operation_outbox_result_values,
    DROP CONSTRAINT ck_admin_operation_outbox_terminal;

-- needs_operator is a terminal automated-reconciliation result. Earlier code
-- already wrote terminal_at, but the v12 constraint incorrectly rejected it.
UPDATE admin_operation_outbox
   SET terminal_at = COALESCE(terminal_at, updated_at)
 WHERE delivery_state = 'needs_operator';

ALTER TABLE admin_operation_outbox
    ADD CONSTRAINT ck_admin_operation_outbox_result_payload CHECK (
        jsonb_typeof(result_payload) = 'object'
        AND result_payload - ARRAY[
            'binding_id','request_id','operation_request_id','grant_id','event_id','actor_id',
            'response_status','result_version','receipt_action','receipt_target_type','receipt_target_id',
            'status','version','credential_version'
        ]::text[] = '{}'::jsonb
    ),
    ADD CONSTRAINT ck_admin_operation_outbox_result CHECK (
        result_code IN ('', 'role.created', 'role.updated', 'role.disabled',
            'registry.updated', 'challenge.updated', 'challenge.enrolled', 'challenge.verified',
            'challenge.rotated', 'challenge.rejected', 'challenge.locked', 'identity_access.requested',
            'identity_access.decided', 'identity_access.claimed', 'identity_access.settled',
            'operation.pending', 'operation.settled', 'operation.failed', 'redis.purged')
        AND (result_digest = '' OR result_digest ~ '^[A-Za-z0-9_-]{8,240}$')
    ),
    ADD CONSTRAINT ck_admin_operation_outbox_result_values CHECK (
        (NOT (result_payload ? 'binding_id') OR (jsonb_typeof(result_payload -> 'binding_id') = 'string' AND result_payload ->> 'binding_id' ~ '^arb_[A-Za-z0-9_-]{1,156}$'))
        AND (NOT (result_payload ? 'request_id') OR (jsonb_typeof(result_payload -> 'request_id') = 'string' AND result_payload ->> 'request_id' ~ '^iar_[A-Za-z0-9_-]{1,156}$'))
        AND (NOT (result_payload ? 'operation_request_id') OR (jsonb_typeof(result_payload -> 'operation_request_id') = 'string' AND result_payload ->> 'operation_request_id' ~ '^[A-Za-z0-9._:-]{8,128}$'))
        AND (NOT (result_payload ? 'grant_id') OR (jsonb_typeof(result_payload -> 'grant_id') = 'string' AND result_payload ->> 'grant_id' ~ '^iag_[A-Za-z0-9_-]{1,156}$'))
        AND (NOT (result_payload ? 'event_id') OR (jsonb_typeof(result_payload -> 'event_id') = 'string' AND result_payload ->> 'event_id' ~ '^evt_[A-Za-z0-9_-]{1,156}$'))
        AND (NOT (result_payload ? 'actor_id') OR (jsonb_typeof(result_payload -> 'actor_id') = 'string' AND result_payload ->> 'actor_id' ~ '^user_[A-Za-z0-9_-]{1,155}$'))
        AND (NOT (result_payload ? 'response_status') OR (jsonb_typeof(result_payload -> 'response_status') = 'string' AND result_payload ->> 'response_status' ~ '^[2-5][0-9]{2}$'))
        AND (NOT (result_payload ? 'result_version') OR (jsonb_typeof(result_payload -> 'result_version') = 'string' AND result_payload ->> 'result_version' ~ '^[1-9][0-9]{0,18}$'))
        AND (NOT (result_payload ? 'receipt_action') OR (jsonb_typeof(result_payload -> 'receipt_action') = 'string' AND result_payload ->> 'receipt_action' ~ '^[A-Za-z0-9][A-Za-z0-9._:-]{0,254}$'))
        AND (NOT (result_payload ? 'receipt_target_type') OR (jsonb_typeof(result_payload -> 'receipt_target_type') = 'string' AND result_payload ->> 'receipt_target_type' ~ '^[A-Za-z0-9][A-Za-z0-9._:-]{0,254}$'))
        AND (NOT (result_payload ? 'receipt_target_id') OR (jsonb_typeof(result_payload -> 'receipt_target_id') = 'string' AND result_payload ->> 'receipt_target_id' ~ '^[A-Za-z0-9][A-Za-z0-9._:-]{0,254}$'))
        AND (NOT (result_payload ? 'status') OR (jsonb_typeof(result_payload -> 'status') = 'string' AND result_payload ->> 'status' IN ('pending', 'approved', 'rejected', 'revoked', 'claimed', 'settled', 'disabled', 'enabled', 'active', 'must_rotate', 'recovery_pending')))
        AND (NOT (result_payload ? 'version') OR (jsonb_typeof(result_payload -> 'version') = 'string' AND result_payload ->> 'version' ~ '^[1-9][0-9]{0,18}$'))
        AND (NOT (result_payload ? 'credential_version') OR (jsonb_typeof(result_payload -> 'credential_version') = 'string' AND result_payload ->> 'credential_version' ~ '^[1-9][0-9]{0,18}$'))
    ),
    ADD CONSTRAINT ck_admin_operation_outbox_terminal CHECK (
        (delivery_state IN ('pending', 'claimed') AND terminal_at IS NULL)
        OR (delivery_state IN ('succeeded', 'failed', 'needs_operator') AND terminal_at IS NOT NULL)
    );

CREATE INDEX idx_admin_operation_outbox_receipt_due
    ON admin_operation_outbox(next_attempt_at, operation_id)
    WHERE delivery_state = 'pending' AND delivery_phase IN ('indeterminate', 'sent');

-- +goose StatementEnd

-- +goose Down
-- +goose StatementBegin

-- Goose records a successful no-op Down as version 14 while leaving the v15
-- schema in place. Abort explicitly so both schema and goose_db_version remain
-- at v15; rollback requires a separately reviewed forward repair.
DO $$
BEGIN
    RAISE EXCEPTION 'migration 00015 is forward-only; apply a reviewed forward repair';
END
$$;

-- +goose StatementEnd
