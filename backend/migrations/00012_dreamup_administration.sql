--
-- Copyright (c) 2026 Chen Jiajie(Ariakage)
--
-- Description: DreamUP event administration, step-up, OA and operation persistence
--

-- +goose Up
-- +goose StatementBegin

CREATE TABLE admin_role_bindings (
    binding_id     TEXT        PRIMARY KEY,
    user_id        TEXT        NOT NULL,
    role           TEXT        NOT NULL CHECK (role IN ('super_admin', 'senior_admin', 'admin')),
    scope_kind     TEXT        NOT NULL CHECK (scope_kind IN ('system', 'event')),
    scope_key      TEXT        NOT NULL CHECK (char_length(scope_key) BETWEEN 1 AND 160),
    event_id       TEXT,
    enabled        BOOLEAN     NOT NULL DEFAULT TRUE,
    version        BIGINT      NOT NULL DEFAULT 1 CHECK (version > 0),
    granted_by     TEXT        NOT NULL CHECK (char_length(granted_by) BETWEEN 1 AND 160),
    reason_id      TEXT        NOT NULL CHECK (char_length(reason_id) BETWEEN 1 AND 160),
    disabled_at    TIMESTAMPTZ,
    created_at     TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at     TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    CONSTRAINT fk_admin_role_bindings_user FOREIGN KEY (user_id) REFERENCES users(id),
    CONSTRAINT ck_admin_role_bindings_scope CHECK (
        (role = 'super_admin' AND scope_kind = 'system' AND scope_key = 'system' AND event_id IS NULL)
        OR
        (role IN ('senior_admin', 'admin') AND scope_kind = 'event'
            AND event_id IS NOT NULL AND scope_key = event_id AND scope_key <> 'system')
    ),
    CONSTRAINT ck_admin_role_bindings_lifecycle CHECK (
        (enabled = TRUE AND disabled_at IS NULL)
        OR (enabled = FALSE AND disabled_at IS NOT NULL AND disabled_at >= created_at)
    )
);

CREATE UNIQUE INDEX uq_admin_role_bindings_active_scope
    ON admin_role_bindings(user_id, scope_kind, scope_key)
    WHERE disabled_at IS NULL;
CREATE INDEX idx_admin_role_bindings_event_active
    ON admin_role_bindings(event_id, role, binding_id)
    WHERE disabled_at IS NULL;
CREATE INDEX idx_admin_role_bindings_retention
    ON admin_role_bindings(disabled_at, binding_id)
    WHERE disabled_at IS NOT NULL;

CREATE TABLE dreamup_event_registry (
    event_id               TEXT        PRIMARY KEY,
    series                 TEXT        NOT NULL CHECK (series = 'dreamup'),
    slug                   TEXT        NOT NULL UNIQUE CHECK (char_length(slug) BETWEEN 1 AND 160),
    display_name           TEXT        NOT NULL DEFAULT '' CHECK (char_length(display_name) <= 240),
    source_version         TEXT        NOT NULL CHECK (char_length(source_version) BETWEEN 1 AND 160),
    authoritative_read_at  TIMESTAMPTZ NOT NULL,
    enabled                BOOLEAN     NOT NULL DEFAULT TRUE,
    version                BIGINT      NOT NULL DEFAULT 1 CHECK (version > 0),
    created_at             TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at             TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    CHECK (updated_at >= created_at)
);

CREATE INDEX idx_dreamup_event_registry_enabled
    ON dreamup_event_registry(event_id)
    WHERE enabled = TRUE;

CREATE FUNCTION reject_dreamup_event_identity_change()
RETURNS TRIGGER
LANGUAGE plpgsql
AS $$
BEGIN
    IF NEW.event_id IS DISTINCT FROM OLD.event_id
       OR NEW.series IS DISTINCT FROM OLD.series
       OR NEW.slug IS DISTINCT FROM OLD.slug THEN
        RAISE EXCEPTION 'dreamup event identity is immutable' USING ERRCODE = '23514';
    END IF;
    RETURN NEW;
END;
$$;

CREATE TRIGGER trg_dreamup_event_registry_immutable
    BEFORE UPDATE ON dreamup_event_registry
    FOR EACH ROW EXECUTE FUNCTION reject_dreamup_event_identity_change();

CREATE TABLE admin_challenges (
    user_id                    TEXT        PRIMARY KEY,
    status                     TEXT        NOT NULL CHECK (status IN ('active', 'recovery_pending', 'revoked')),
    must_rotate                BOOLEAN     NOT NULL DEFAULT TRUE,
    question_key_id            TEXT,
    question_nonce             BYTEA,
    question_ciphertext        BYTEA,
    answer_phc                 TEXT,
    answer_pepper_key_id       TEXT,
    credential_version         BIGINT      NOT NULL DEFAULT 1 CHECK (credential_version > 0),
    security_epoch             BIGINT      NOT NULL DEFAULT 1 CHECK (security_epoch > 0),
    failure_count              INTEGER     NOT NULL DEFAULT 0 CHECK (failure_count >= 0),
    failure_window_started_at  TIMESTAMPTZ,
    locked_until               TIMESTAMPTZ,
    version                    BIGINT      NOT NULL DEFAULT 1 CHECK (version > 0),
    created_at                 TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at                 TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    CONSTRAINT fk_admin_challenges_user FOREIGN KEY (user_id) REFERENCES users(id),
    CONSTRAINT ck_admin_challenges_secret_lifecycle CHECK (
        (status = 'active'
            AND question_key_id IS NOT NULL AND question_nonce IS NOT NULL
            AND question_ciphertext IS NOT NULL AND answer_phc IS NOT NULL
            AND answer_pepper_key_id IS NOT NULL)
        OR
        (status <> 'active'
            AND question_key_id IS NULL AND question_nonce IS NULL
            AND question_ciphertext IS NULL AND answer_phc IS NULL
            AND answer_pepper_key_id IS NULL)
    ),
    CHECK (failure_count = 0 OR failure_window_started_at IS NOT NULL),
    CHECK (updated_at >= created_at)
);

CREATE TABLE admin_step_up_state (
    step_up_id          TEXT        PRIMARY KEY,
    session_id          TEXT        NOT NULL CHECK (char_length(session_id) BETWEEN 1 AND 240),
    user_id             TEXT        NOT NULL,
    challenge_version   BIGINT      NOT NULL CHECK (challenge_version > 0),
    security_epoch      BIGINT      NOT NULL CHECK (security_epoch > 0),
    verified_at         TIMESTAMPTZ NOT NULL,
    expires_at          TIMESTAMPTZ NOT NULL,
    revoked_at          TIMESTAMPTZ,
    created_at          TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    CONSTRAINT fk_admin_step_up_state_user FOREIGN KEY (user_id) REFERENCES users(id),
    CHECK (expires_at > verified_at),
    CHECK (revoked_at IS NULL OR revoked_at >= verified_at)
);

CREATE UNIQUE INDEX uq_admin_step_up_state_active_session
    ON admin_step_up_state(session_id, user_id)
    WHERE revoked_at IS NULL;
CREATE INDEX idx_admin_step_up_state_expiry
    ON admin_step_up_state(expires_at, step_up_id)
    WHERE revoked_at IS NULL;

CREATE TABLE protected_operation_reasons (
    reason_id           TEXT        PRIMARY KEY,
    owner_user_id       TEXT        NOT NULL CHECK (char_length(owner_user_id) BETWEEN 1 AND 160),
    operation_kind      TEXT        NOT NULL CHECK (operation_kind IN ('role', 'challenge', 'identity_access', 'registry', 'direct_read', 'export')),
    key_id              TEXT,
    nonce               BYTEA,
    ciphertext          BYTEA,
    consumed_at         TIMESTAMPTZ,
    terminal_at         TIMESTAMPTZ,
    expires_at          TIMESTAMPTZ,
    purged_at           TIMESTAMPTZ,
    created_at          TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    CONSTRAINT ck_protected_operation_reasons_crypto_lifecycle CHECK (
        (purged_at IS NULL AND key_id IS NOT NULL AND nonce IS NOT NULL AND ciphertext IS NOT NULL)
        OR
        (purged_at IS NOT NULL AND key_id IS NULL AND nonce IS NULL AND ciphertext IS NULL
            AND expires_at IS NOT NULL AND purged_at >= expires_at)
    ),
    CHECK (consumed_at IS NULL OR consumed_at >= created_at),
    CHECK (terminal_at IS NULL OR (consumed_at IS NOT NULL AND terminal_at >= consumed_at)),
    CHECK (expires_at IS NULL OR (terminal_at IS NOT NULL AND expires_at > terminal_at))
);

CREATE INDEX idx_protected_operation_reasons_retention
    ON protected_operation_reasons(expires_at, reason_id)
    WHERE expires_at IS NOT NULL AND purged_at IS NULL;

CREATE TABLE identity_access_requests (
    request_id               TEXT        PRIMARY KEY,
    event_id                 TEXT        NOT NULL CHECK (char_length(event_id) BETWEEN 1 AND 160),
    requester_user_id        TEXT        NOT NULL,
    target_subject_user_id   TEXT        NOT NULL,
    target_type              TEXT        NOT NULL CHECK (target_type IN ('application', 'check_in')),
    target_id                TEXT        NOT NULL CHECK (char_length(target_id) BETWEEN 1 AND 240),
    status                   TEXT        NOT NULL DEFAULT 'pending'
                                      CHECK (status IN ('pending', 'approved', 'rejected', 'revoked', 'expired')),
    approver_user_id         TEXT,
    reason_id                TEXT        NOT NULL CHECK (char_length(reason_id) BETWEEN 1 AND 160),
    version                  BIGINT      NOT NULL DEFAULT 1 CHECK (version > 0),
    terminal_at              TIMESTAMPTZ,
    created_at               TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at               TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    CONSTRAINT fk_identity_access_requests_requester FOREIGN KEY (requester_user_id) REFERENCES users(id),
    CONSTRAINT fk_identity_access_requests_target_subject FOREIGN KEY (target_subject_user_id) REFERENCES users(id),
    CONSTRAINT ck_identity_access_requests_actor_separation CHECK (
        requester_user_id <> target_subject_user_id
        AND (approver_user_id IS NULL OR (approver_user_id <> requester_user_id AND approver_user_id <> target_subject_user_id))
    ),
    CONSTRAINT ck_identity_access_requests_terminal_actors CHECK (
        (status = 'pending' AND terminal_at IS NULL AND approver_user_id IS NULL)
        OR (status IN ('approved', 'rejected') AND terminal_at IS NOT NULL AND approver_user_id IS NOT NULL)
        OR (status IN ('revoked', 'expired') AND terminal_at IS NOT NULL)
    ),
    CHECK (terminal_at IS NULL OR terminal_at >= created_at),
    CHECK (updated_at >= created_at)
);

CREATE TABLE identity_access_request_fields (
    request_id    TEXT NOT NULL,
    field_name    TEXT NOT NULL CHECK (field_name IN ('legal_name', 'identity_number', 'identity_photo', 'contact_email', 'contact_mobile')),
    PRIMARY KEY (request_id, field_name),
    CONSTRAINT fk_identity_access_request_fields_request FOREIGN KEY (request_id) REFERENCES identity_access_requests(request_id) ON DELETE CASCADE
);

CREATE INDEX idx_identity_access_requests_requester
    ON identity_access_requests(requester_user_id, created_at DESC, request_id DESC);
CREATE INDEX idx_identity_access_requests_approval_queue
    ON identity_access_requests(event_id, created_at, request_id)
    WHERE status = 'pending';
CREATE INDEX idx_identity_access_requests_retention
    ON identity_access_requests(terminal_at, request_id)
    WHERE terminal_at IS NOT NULL;

CREATE TABLE identity_access_grants (
    grant_id                 TEXT        PRIMARY KEY,
    request_id               TEXT        NOT NULL UNIQUE,
    event_id                 TEXT        NOT NULL CHECK (char_length(event_id) BETWEEN 1 AND 160),
    requester_user_id        TEXT        NOT NULL,
    target_subject_user_id   TEXT        NOT NULL,
    target_type              TEXT        NOT NULL CHECK (target_type IN ('application', 'check_in')),
    target_id                TEXT        NOT NULL CHECK (char_length(target_id) BETWEEN 1 AND 240),
    approved_by_user_id      TEXT        NOT NULL CHECK (char_length(approved_by_user_id) BETWEEN 1 AND 160),
    status                   TEXT        NOT NULL DEFAULT 'active'
                                      CHECK (status IN ('active', 'claimed', 'settled', 'revoked', 'expired')),
    claim_nonce_hash         TEXT,
    claim_lease_until        TIMESTAMPTZ,
    response_receipt_hash    TEXT,
    version                  BIGINT      NOT NULL DEFAULT 1 CHECK (version > 0),
    expires_at               TIMESTAMPTZ NOT NULL,
    terminal_at              TIMESTAMPTZ,
    created_at               TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at               TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    CONSTRAINT fk_identity_access_grants_request FOREIGN KEY (request_id) REFERENCES identity_access_requests(request_id),
    CONSTRAINT fk_identity_access_grants_requester FOREIGN KEY (requester_user_id) REFERENCES users(id),
    CONSTRAINT fk_identity_access_grants_target_subject FOREIGN KEY (target_subject_user_id) REFERENCES users(id),
    CONSTRAINT ck_identity_access_grants_actor_separation CHECK (
        requester_user_id <> target_subject_user_id
        AND approved_by_user_id <> requester_user_id
        AND approved_by_user_id <> target_subject_user_id
    ),
    CONSTRAINT ck_identity_access_grants_claim CHECK (
        (status = 'claimed' AND claim_nonce_hash IS NOT NULL AND claim_lease_until IS NOT NULL AND terminal_at IS NULL)
        OR
        (status = 'active' AND claim_nonce_hash IS NULL AND claim_lease_until IS NULL AND terminal_at IS NULL)
        OR
        (status IN ('settled', 'revoked', 'expired') AND terminal_at IS NOT NULL)
    ),
    CHECK (expires_at > created_at),
    CHECK (terminal_at IS NULL OR terminal_at >= created_at),
    CHECK (updated_at >= created_at)
);

CREATE UNIQUE INDEX uq_identity_access_grants_active_claim
    ON identity_access_grants(event_id, target_type, target_id, requester_user_id)
    WHERE claim_nonce_hash IS NOT NULL AND terminal_at IS NULL;
CREATE INDEX idx_identity_access_grants_expiry
    ON identity_access_grants(expires_at, grant_id)
    WHERE terminal_at IS NULL;
CREATE INDEX idx_identity_access_grants_retention
    ON identity_access_grants(terminal_at, grant_id)
    WHERE terminal_at IS NOT NULL;

CREATE TABLE admin_operation_outbox (
    operation_id               TEXT        PRIMARY KEY,
    operation_kind             TEXT        NOT NULL CHECK (operation_kind IN ('local', 'cross_system', 'redis_purge')),
    idempotency_key            TEXT        NOT NULL UNIQUE CHECK (char_length(idempotency_key) BETWEEN 1 AND 240),
    request_fingerprint_version TEXT       NOT NULL CHECK (request_fingerprint_version = 'hmac-sha256-v1'),
    request_fingerprint_key_id TEXT        NOT NULL CHECK (char_length(request_fingerprint_key_id) BETWEEN 1 AND 160),
    request_fingerprint_hmac   TEXT        NOT NULL CHECK (char_length(request_fingerprint_hmac) BETWEEN 32 AND 160),
    payload_key_id             TEXT,
    payload_nonce              BYTEA,
    payload_ciphertext         BYTEA,
    result_code                TEXT        NOT NULL DEFAULT '',
    result_digest              TEXT        NOT NULL DEFAULT '',
    result_payload             JSONB       NOT NULL DEFAULT '{}'::jsonb
                                       CHECK (jsonb_typeof(result_payload) = 'object'
                                           AND result_payload - ARRAY['binding_id','request_id','grant_id','event_id','status','version','credential_version']::text[] = '{}'::jsonb),
    delivery_state             TEXT        NOT NULL DEFAULT 'pending'
                                       CHECK (delivery_state IN ('pending', 'claimed', 'succeeded', 'failed', 'needs_operator')),
    delivery_phase             TEXT        NOT NULL DEFAULT 'not_sent'
                                       CHECK (delivery_phase IN ('not_sent', 'indeterminate', 'sent')),
    claim_token_hash           TEXT,
    claim_lease_until          TIMESTAMPTZ,
    attempts                   INTEGER     NOT NULL DEFAULT 0 CHECK (attempts >= 0),
    next_attempt_at            TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    version                    BIGINT      NOT NULL DEFAULT 1 CHECK (version > 0),
    terminal_at                TIMESTAMPTZ,
    audit_reconciled_at        TIMESTAMPTZ,
    payload_expires_at         TIMESTAMPTZ,
    payload_purged_at          TIMESTAMPTZ,
    created_at                 TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at                 TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    CONSTRAINT ck_admin_operation_outbox_claim CHECK (
        (delivery_state = 'claimed' AND claim_token_hash IS NOT NULL AND claim_lease_until IS NOT NULL)
        OR (delivery_state <> 'claimed' AND claim_token_hash IS NULL AND claim_lease_until IS NULL)
    ),
    CONSTRAINT ck_admin_operation_outbox_result CHECK (
        result_code IN ('', 'role.created', 'role.updated', 'role.disabled',
            'registry.updated', 'challenge.updated', 'challenge.enrolled', 'challenge.verified',
            'challenge.rotated', 'challenge.rejected', 'challenge.locked', 'identity_access.requested',
            'identity_access.decided', 'identity_access.claimed', 'identity_access.settled',
            'operation.settled', 'redis.purged')
        AND (result_digest = '' OR result_digest ~ '^[A-Za-z0-9_-]{8,240}$')
    ),
    CONSTRAINT ck_admin_operation_outbox_result_values CHECK (
        (NOT (result_payload ? 'binding_id') OR (jsonb_typeof(result_payload -> 'binding_id') = 'string' AND result_payload ->> 'binding_id' ~ '^arb_[A-Za-z0-9_-]{1,156}$'))
        AND (NOT (result_payload ? 'request_id') OR (jsonb_typeof(result_payload -> 'request_id') = 'string' AND result_payload ->> 'request_id' ~ '^iar_[A-Za-z0-9_-]{1,156}$'))
        AND (NOT (result_payload ? 'grant_id') OR (jsonb_typeof(result_payload -> 'grant_id') = 'string' AND result_payload ->> 'grant_id' ~ '^iag_[A-Za-z0-9_-]{1,156}$'))
        AND (NOT (result_payload ? 'event_id') OR (jsonb_typeof(result_payload -> 'event_id') = 'string' AND result_payload ->> 'event_id' ~ '^evt_[A-Za-z0-9_-]{1,156}$'))
        AND (NOT (result_payload ? 'status') OR (jsonb_typeof(result_payload -> 'status') = 'string' AND result_payload ->> 'status' IN ('pending', 'approved', 'rejected', 'revoked', 'claimed', 'settled', 'disabled', 'enabled', 'active', 'must_rotate', 'recovery_pending')))
        AND (NOT (result_payload ? 'version') OR (jsonb_typeof(result_payload -> 'version') = 'string' AND result_payload ->> 'version' ~ '^[1-9][0-9]{0,18}$'))
        AND (NOT (result_payload ? 'credential_version') OR (jsonb_typeof(result_payload -> 'credential_version') = 'string' AND result_payload ->> 'credential_version' ~ '^[1-9][0-9]{0,18}$'))
    ),
    CONSTRAINT ck_admin_operation_outbox_terminal CHECK (
        (delivery_state IN ('pending', 'claimed', 'needs_operator') AND terminal_at IS NULL)
        OR (delivery_state IN ('succeeded', 'failed') AND terminal_at IS NOT NULL)
    ),
    CONSTRAINT ck_admin_operation_outbox_payload_shape CHECK (
        (payload_key_id IS NULL AND payload_nonce IS NULL AND payload_ciphertext IS NULL)
        OR (payload_key_id IS NOT NULL AND payload_nonce IS NOT NULL AND payload_ciphertext IS NOT NULL)
    ),
    CONSTRAINT ck_admin_operation_outbox_payload_lifecycle CHECK (
        (payload_purged_at IS NULL)
        OR (payload_purged_at IS NOT NULL AND payload_key_id IS NULL AND payload_nonce IS NULL
            AND payload_ciphertext IS NULL AND payload_expires_at IS NOT NULL
            AND payload_purged_at >= payload_expires_at)
    ),
    CHECK (audit_reconciled_at IS NULL OR terminal_at IS NOT NULL),
    CHECK (payload_expires_at IS NULL OR (audit_reconciled_at IS NOT NULL AND payload_expires_at > audit_reconciled_at)),
    CHECK (updated_at >= created_at)
);

CREATE INDEX idx_admin_operation_outbox_due
    ON admin_operation_outbox(next_attempt_at, operation_id)
    WHERE delivery_state = 'pending' AND delivery_phase = 'not_sent';
CREATE INDEX idx_admin_operation_outbox_expired_claim
    ON admin_operation_outbox(claim_lease_until, operation_id)
    WHERE delivery_state = 'claimed';
CREATE INDEX idx_admin_operation_outbox_payload_retention
    ON admin_operation_outbox(payload_expires_at, operation_id)
    WHERE payload_expires_at IS NOT NULL AND payload_purged_at IS NULL;

CREATE TABLE admin_operator_approvals (
    approval_id       TEXT        PRIMARY KEY,
    request_hash      TEXT        NOT NULL CHECK (char_length(request_hash) BETWEEN 16 AND 240),
    operator_user_id  TEXT        NOT NULL,
    key_id            TEXT        NOT NULL CHECK (char_length(key_id) BETWEEN 1 AND 160),
    signature         BYTEA       NOT NULL,
    expires_at        TIMESTAMPTZ NOT NULL,
    terminal_at       TIMESTAMPTZ,
    created_at        TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    CONSTRAINT fk_admin_operator_approvals_operator FOREIGN KEY (operator_user_id) REFERENCES users(id),
    CHECK (expires_at > created_at),
    CHECK (terminal_at IS NULL OR terminal_at >= created_at)
);

CREATE UNIQUE INDEX uq_admin_operator_approvals_request_operator
    ON admin_operator_approvals(request_hash, operator_user_id);
CREATE INDEX idx_admin_operator_approvals_active
    ON admin_operator_approvals(request_hash, expires_at, approval_id)
    WHERE terminal_at IS NULL;
CREATE INDEX idx_admin_operator_approvals_retention
    ON admin_operator_approvals(terminal_at, approval_id)
    WHERE terminal_at IS NOT NULL;

CREATE TABLE admin_security_event_vocabulary (
    event_type       TEXT        PRIMARY KEY CHECK (event_type ~ '^[a-z][a-z0-9_.]{2,119}$'),
    target_kind      TEXT        NOT NULL CHECK (target_kind IN ('role_binding', 'event_registry', 'challenge', 'identity_access', 'operation')),
    active           BOOLEAN     NOT NULL DEFAULT TRUE,
    created_at       TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

INSERT INTO admin_security_event_vocabulary (event_type, target_kind) VALUES
    ('admin.role.created', 'role_binding'),
    ('admin.role.updated', 'role_binding'),
    ('admin.role.disabled', 'role_binding'),
    ('admin.registry.updated', 'event_registry'),
    ('admin.challenge.updated', 'challenge'),
    ('admin.identity_access.requested', 'identity_access'),
    ('admin.identity_access.decided', 'identity_access'),
    ('admin.operation.settled', 'operation');

-- +goose StatementEnd

-- +goose Down
-- +goose StatementBegin

-- This security migration is intentionally irreversible. Restore only from a
-- reviewed backup and a separately approved forward migration.

-- +goose StatementEnd
