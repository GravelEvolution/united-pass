--
-- Copyright (c) 2026 Chen Jiajie(Ariakage)
--
-- Author: Chen Jiajie(Ariakage) <ariakage233@gmail.com>
-- Date: 2026-08-11
-- Description: Phase 7 Cerbos policy authority and durable audit exports
--

-- +goose Up
-- +goose StatementBegin

CREATE TABLE authorization_policies (
    policy_id          TEXT        PRIMARY KEY,
    name               TEXT        NOT NULL CHECK (char_length(name) BETWEEN 1 AND 120),
    description        TEXT        NOT NULL DEFAULT '' CHECK (char_length(description) <= 1000),
    resource           TEXT        NOT NULL CHECK (char_length(resource) BETWEEN 1 AND 128),
    action             TEXT        NOT NULL CHECK (char_length(action) BETWEEN 1 AND 128),
    effect             TEXT        NOT NULL CHECK (effect IN ('allow', 'deny')),
    current_version    INTEGER     NOT NULL CHECK (current_version > 0),
    published_version  INTEGER     CHECK (published_version > 0 AND published_version <= current_version),
    status             TEXT        NOT NULL CHECK (status IN ('draft', 'published')),
    updated_by_user_id TEXT        NOT NULL REFERENCES users(id),
    created_at         TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at         TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE UNIQUE INDEX uq_authorization_policies_name ON authorization_policies(lower(name));
CREATE INDEX idx_authorization_policies_list
    ON authorization_policies(updated_at DESC, policy_id DESC);
CREATE INDEX idx_authorization_policies_resolution
    ON authorization_policies(action, resource)
    WHERE status = 'published';

CREATE TABLE authorization_policy_versions (
    policy_id          TEXT        NOT NULL REFERENCES authorization_policies(policy_id),
    version            INTEGER     NOT NULL CHECK (version > 0),
    name               TEXT        NOT NULL,
    description        TEXT        NOT NULL DEFAULT '',
    resource           TEXT        NOT NULL,
    action             TEXT        NOT NULL,
    effect             TEXT        NOT NULL CHECK (effect IN ('allow', 'deny')),
    principals         JSONB       NOT NULL DEFAULT '[]',
    conditions         JSONB       NOT NULL DEFAULT '[]',
    status             TEXT        NOT NULL CHECK (status IN ('draft', 'published')),
    change_summary     TEXT        NOT NULL DEFAULT '',
    updated_by_user_id TEXT        NOT NULL REFERENCES users(id),
    created_at         TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    published_at       TIMESTAMPTZ,
    PRIMARY KEY (policy_id, version)
);

CREATE TABLE policy_publication_jobs (
    job_id             TEXT        PRIMARY KEY,
    policy_id          TEXT        NOT NULL,
    version            INTEGER     NOT NULL,
    actor_user_id      TEXT        NOT NULL REFERENCES users(id),
    request_id         TEXT        NOT NULL DEFAULT '',
    status             TEXT        NOT NULL DEFAULT 'pending'
                                  CHECK (status IN ('pending', 'running', 'completed', 'failed')),
    attempts           INTEGER     NOT NULL DEFAULT 0 CHECK (attempts >= 0),
    failure_class      TEXT        NOT NULL DEFAULT '',
    created_at         TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at         TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    completed_at       TIMESTAMPTZ,
    FOREIGN KEY (policy_id, version)
        REFERENCES authorization_policy_versions(policy_id, version)
);

CREATE UNIQUE INDEX uq_policy_publication_jobs_active
    ON policy_publication_jobs(policy_id)
    WHERE status IN ('pending', 'running');
CREATE INDEX idx_policy_publication_jobs_pending
    ON policy_publication_jobs(created_at, job_id)
    WHERE status = 'pending';

CREATE TABLE audit_export_jobs (
    export_id          TEXT        PRIMARY KEY,
    actor_user_id      TEXT        NOT NULL REFERENCES users(id),
    request_id         TEXT        NOT NULL DEFAULT '',
    status             TEXT        NOT NULL DEFAULT 'pending'
                                  CHECK (status IN ('pending', 'processing', 'completed', 'failed')),
    filters            JSONB       NOT NULL DEFAULT '{}',
    content            BYTEA,
    total_events       INTEGER     NOT NULL DEFAULT 0 CHECK (total_events >= 0),
    failure_class      TEXT        NOT NULL DEFAULT '',
    requested_at       TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at         TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    completed_at       TIMESTAMPTZ,
    expires_at         TIMESTAMPTZ
);

CREATE INDEX idx_audit_export_jobs_pending
    ON audit_export_jobs(requested_at, export_id)
    WHERE status = 'pending';
CREATE INDEX idx_audit_export_jobs_actor
    ON audit_export_jobs(actor_user_id, requested_at DESC);
CREATE INDEX idx_audit_export_jobs_expiry
    ON audit_export_jobs(expires_at)
    WHERE status = 'completed' AND content IS NOT NULL;

-- Typed target columns make audit filtering/indexing deterministic. Existing
-- rows retain their application/client columns and safe JSON payload.
ALTER TABLE security_events
    ADD COLUMN target_kind TEXT NOT NULL DEFAULT '',
    ADD COLUMN target_id   TEXT NOT NULL DEFAULT '';

CREATE INDEX idx_security_events_actor ON security_events(actor_user_id, occurred_at DESC);
CREATE INDEX idx_security_events_request ON security_events(request_id, occurred_at DESC);
CREATE INDEX idx_security_events_target ON security_events(target_kind, target_id, occurred_at DESC);
CREATE INDEX idx_security_events_occurred ON security_events(occurred_at DESC, event_id DESC);

-- +goose StatementEnd

-- +goose Down
-- +goose StatementBegin

DROP INDEX IF EXISTS idx_security_events_occurred;
DROP INDEX IF EXISTS idx_security_events_target;
DROP INDEX IF EXISTS idx_security_events_request;
DROP INDEX IF EXISTS idx_security_events_actor;
ALTER TABLE security_events DROP COLUMN IF EXISTS target_id;
ALTER TABLE security_events DROP COLUMN IF EXISTS target_kind;
DROP TABLE IF EXISTS audit_export_jobs;
DROP TABLE IF EXISTS policy_publication_jobs;
DROP TABLE IF EXISTS authorization_policy_versions;
DROP TABLE IF EXISTS authorization_policies;

-- +goose StatementEnd
