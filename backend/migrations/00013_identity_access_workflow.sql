--
-- Copyright (c) 2026 Chen Jiajie(Ariakage)
--
-- Description: Complete the event-scoped restricted identity access ledger
--

-- +goose Up
-- +goose StatementBegin

ALTER TABLE identity_access_requests
    ADD COLUMN expires_at TIMESTAMPTZ;

UPDATE identity_access_requests
SET expires_at = created_at + INTERVAL '24 hours'
WHERE expires_at IS NULL;

ALTER TABLE identity_access_requests
    ALTER COLUMN expires_at SET NOT NULL,
    ALTER COLUMN expires_at SET DEFAULT (NOW() + INTERVAL '24 hours'),
    ADD CONSTRAINT ck_identity_access_requests_expiry CHECK (expires_at > created_at);

CREATE UNIQUE INDEX uq_identity_access_requests_pending_target
    ON identity_access_requests(event_id, requester_user_id, target_type, target_id)
    WHERE status = 'pending' AND terminal_at IS NULL;

ALTER TABLE identity_access_grants
    ADD COLUMN requester_role_binding_id TEXT,
    ADD COLUMN requester_role_binding_version BIGINT,
    ADD COLUMN requester_challenge_version BIGINT,
    ADD COLUMN field_set_hash TEXT;

ALTER TABLE identity_access_grants
    ADD CONSTRAINT ck_identity_access_grants_authorization_stamp CHECK (
        (requester_role_binding_id IS NULL
            AND requester_role_binding_version IS NULL
            AND requester_challenge_version IS NULL
            AND field_set_hash IS NULL)
        OR
        (char_length(requester_role_binding_id) BETWEEN 1 AND 160
            AND requester_role_binding_version > 0
            AND requester_challenge_version > 0
            AND field_set_hash ~ '^[A-Za-z0-9_-]{43}$')
    );

CREATE TABLE identity_access_grant_fields (
    grant_id     TEXT NOT NULL,
    field_name   TEXT NOT NULL CHECK (field_name IN ('legal_name', 'identity_number', 'identity_photo', 'contact_email', 'contact_mobile')),
    PRIMARY KEY (grant_id, field_name),
    CONSTRAINT fk_identity_access_grant_fields_grant FOREIGN KEY (grant_id) REFERENCES identity_access_grants(grant_id) ON DELETE CASCADE
);

-- +goose StatementEnd

-- +goose Down
-- +goose StatementBegin

-- This security migration is intentionally irreversible. Restore only from a
-- reviewed backup and a separately approved forward migration.

-- +goose StatementEnd
