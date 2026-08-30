-- +goose Up
-- +goose StatementBegin

-- This schema is deployed only to the dedicated DreamUP/Mini Program
-- operational database. It deliberately has no foreign keys into the United
-- Pass authority database, so applying it can never alter identity, role or
-- permission tables.
CREATE TABLE wechat_registration_provider_intents (
    subject_hash       BYTEA       PRIMARY KEY CHECK (octet_length(subject_hash) = 32),
    user_id            TEXT        NOT NULL UNIQUE CHECK (user_id ~ '^user_[0-9a-f]{32}$'),
    request_verifier   TEXT        NOT NULL
                                  CHECK (request_verifier ~ '^\$argon2id\$v=19\$m=32768,t=2,p=1\$[A-Za-z0-9+/]{22}\$[A-Za-z0-9+/]{43}$'),
    created_at         TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    cleanup_checked_at TIMESTAMPTZ,
    CHECK (cleanup_checked_at IS NULL OR cleanup_checked_at >= created_at)
);

CREATE TABLE admin_operation_outbox (
    operation_id                TEXT        PRIMARY KEY CHECK (operation_id ~ '^aop_[A-Za-z0-9_-]{8,156}$'),
    operation_kind              TEXT        NOT NULL CHECK (operation_kind = 'cross_system'),
    idempotency_key             TEXT        NOT NULL UNIQUE CHECK (char_length(idempotency_key) BETWEEN 1 AND 240),
    request_fingerprint_version TEXT        NOT NULL CHECK (request_fingerprint_version = 'hmac-sha256-v1'),
    request_fingerprint_key_id  TEXT        NOT NULL CHECK (char_length(request_fingerprint_key_id) BETWEEN 1 AND 160),
    request_fingerprint_hmac    TEXT        NOT NULL CHECK (char_length(request_fingerprint_hmac) BETWEEN 32 AND 160),
    payload_key_id              TEXT,
    payload_nonce               BYTEA,
    payload_ciphertext          BYTEA,
    result_code                 TEXT        NOT NULL DEFAULT '',
    result_digest               TEXT        NOT NULL DEFAULT '',
    result_payload              JSONB       NOT NULL DEFAULT '{}'::jsonb,
    delivery_state              TEXT        NOT NULL DEFAULT 'pending'
                                           CHECK (delivery_state IN ('pending','claimed','succeeded','failed','needs_operator')),
    delivery_phase              TEXT        NOT NULL DEFAULT 'not_sent'
                                           CHECK (delivery_phase IN ('not_sent','indeterminate','sent')),
    claim_token_hash            TEXT,
    claim_lease_until           TIMESTAMPTZ,
    attempts                    INTEGER     NOT NULL DEFAULT 0 CHECK (attempts >= 0),
    next_attempt_at             TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    version                     BIGINT      NOT NULL DEFAULT 1 CHECK (version > 0),
    terminal_at                 TIMESTAMPTZ,
    audit_reconciled_at         TIMESTAMPTZ,
    payload_expires_at          TIMESTAMPTZ,
    payload_purged_at           TIMESTAMPTZ,
    created_at                  TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at                  TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    CONSTRAINT ck_isolated_admin_outbox_no_payload CHECK (
        payload_key_id IS NULL AND payload_nonce IS NULL AND payload_ciphertext IS NULL
    ),
    CONSTRAINT ck_isolated_admin_outbox_claim CHECK (
        (delivery_state = 'claimed' AND claim_token_hash IS NOT NULL AND claim_lease_until IS NOT NULL)
        OR (delivery_state <> 'claimed' AND claim_token_hash IS NULL AND claim_lease_until IS NULL)
    ),
    CONSTRAINT ck_isolated_admin_outbox_result_payload CHECK (
        jsonb_typeof(result_payload) = 'object'
        AND result_payload - ARRAY[
            'operation_request_id','event_id','actor_id','response_status','result_version',
            'receipt_action','receipt_target_type','receipt_target_id'
        ]::text[] = '{}'::jsonb
    ),
    CONSTRAINT ck_isolated_admin_outbox_result CHECK (
        result_code IN ('operation.pending','operation.settled','operation.failed')
        AND (result_digest = '' OR result_digest ~ '^[A-Za-z0-9_-]{8,240}$')
    ),
    CONSTRAINT ck_isolated_admin_outbox_result_values CHECK (
        (NOT (result_payload ? 'operation_request_id') OR (jsonb_typeof(result_payload -> 'operation_request_id') = 'string' AND result_payload ->> 'operation_request_id' ~ '^[A-Za-z0-9._:-]{8,128}$'))
        AND (NOT (result_payload ? 'event_id') OR (jsonb_typeof(result_payload -> 'event_id') = 'string' AND result_payload ->> 'event_id' ~ '^evt_[A-Za-z0-9_-]{1,156}$'))
        AND (NOT (result_payload ? 'actor_id') OR (jsonb_typeof(result_payload -> 'actor_id') = 'string' AND result_payload ->> 'actor_id' ~ '^user_[A-Za-z0-9_-]{1,155}$'))
        AND (NOT (result_payload ? 'response_status') OR (jsonb_typeof(result_payload -> 'response_status') = 'string' AND result_payload ->> 'response_status' ~ '^[2-5][0-9]{2}$'))
        AND (NOT (result_payload ? 'result_version') OR (jsonb_typeof(result_payload -> 'result_version') = 'string' AND result_payload ->> 'result_version' ~ '^[1-9][0-9]{0,18}$'))
        AND (NOT (result_payload ? 'receipt_action') OR (jsonb_typeof(result_payload -> 'receipt_action') = 'string' AND result_payload ->> 'receipt_action' ~ '^[A-Za-z0-9][A-Za-z0-9._:-]{0,254}$'))
        AND (NOT (result_payload ? 'receipt_target_type') OR (jsonb_typeof(result_payload -> 'receipt_target_type') = 'string' AND result_payload ->> 'receipt_target_type' ~ '^[A-Za-z0-9][A-Za-z0-9._:-]{0,254}$'))
        AND (NOT (result_payload ? 'receipt_target_id') OR (jsonb_typeof(result_payload -> 'receipt_target_id') = 'string' AND result_payload ->> 'receipt_target_id' ~ '^[A-Za-z0-9][A-Za-z0-9._:-]{0,254}$'))
    ),
    CONSTRAINT ck_isolated_admin_outbox_terminal CHECK (
        (delivery_state IN ('pending','claimed') AND terminal_at IS NULL)
        OR (delivery_state IN ('succeeded','failed','needs_operator') AND terminal_at IS NOT NULL)
    ),
    CHECK (audit_reconciled_at IS NULL OR terminal_at IS NOT NULL),
    CHECK (payload_expires_at IS NULL OR (audit_reconciled_at IS NOT NULL AND payload_expires_at > audit_reconciled_at)),
    CHECK (payload_purged_at IS NULL),
    CHECK (updated_at >= created_at)
);

CREATE INDEX idx_isolated_admin_outbox_due
    ON admin_operation_outbox(next_attempt_at, operation_id)
    WHERE delivery_state = 'pending' AND delivery_phase = 'not_sent';
CREATE INDEX idx_isolated_admin_outbox_receipt_due
    ON admin_operation_outbox(next_attempt_at, operation_id)
    WHERE delivery_state = 'pending' AND delivery_phase IN ('indeterminate','sent');
CREATE INDEX idx_isolated_admin_outbox_expired_claim
    ON admin_operation_outbox(claim_lease_until, operation_id)
    WHERE delivery_state = 'claimed';

-- +goose StatementEnd

-- +goose Down
-- +goose StatementBegin

DO $$
BEGIN
    RAISE EXCEPTION 'isolated operational store migration is forward-only; restore a reviewed backup instead';
END
$$;

-- +goose StatementEnd
