--
-- Copyright (c) 2026 Chen Jiajie(Ariakage)
--
-- Author: Chen Jiajie(Ariakage) <ariakage233@gmail.com>
-- Date: 2026-08-11
-- Description: Phase 6 Feishu Provider, directory staging, conflict and job schema
--

-- +goose Up
-- +goose StatementBegin

-- Safe Provider metadata only. App secrets, tenant/user access tokens,
-- authorization codes and refresh tokens never enter PostgreSQL.
CREATE TABLE identity_providers (
    provider_id        TEXT        PRIMARY KEY,
    display_name       TEXT        NOT NULL CHECK (char_length(display_name) BETWEEN 1 AND 120),
    vendor             TEXT        NOT NULL CHECK (vendor IN ('feishu', 'generic')),
    integration_label  TEXT        NOT NULL CHECK (char_length(integration_label) BETWEEN 1 AND 160),
    status             TEXT        NOT NULL DEFAULT 'disabled'
                       CHECK (status IN ('planned', 'active', 'disabled')),
    login_enabled      BOOLEAN     NOT NULL DEFAULT FALSE,
    last_validated_at  TIMESTAMPTZ,
    created_at         TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at         TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    CHECK (login_enabled = FALSE OR status = 'active')
);

INSERT INTO identity_providers
    (provider_id, display_name, vendor, integration_label, status, login_enabled)
VALUES
    ('provider_feishu', '飞书', 'feishu', 'OAuth 2.0 + 通讯录 OpenAPI', 'disabled', FALSE);

-- An active provider subject may resolve to only one stable United Pass user
-- (the original uniqueness rule), and one stable user may have only one
-- Feishu subject per tenant. This closes accidental many-to-one merges during
-- concurrent manual conflict resolution without changing other providers.
CREATE UNIQUE INDEX uq_identity_links_feishu_user_tenant
    ON identity_links(user_id, provider, provider_tenant_id)
    WHERE provider = 'provider_feishu';

CREATE TABLE provider_sync_jobs (
    sync_id                 TEXT        PRIMARY KEY,
    provider_id             TEXT        NOT NULL REFERENCES identity_providers(provider_id),
    actor_user_id           TEXT        NOT NULL REFERENCES users(id),
    request_id              TEXT        NOT NULL DEFAULT '',
    status                  TEXT        NOT NULL DEFAULT 'pending'
                            CHECK (status IN ('pending', 'running', 'success', 'partial', 'failed')),
    departments_added       INTEGER     NOT NULL DEFAULT 0 CHECK (departments_added >= 0),
    departments_updated     INTEGER     NOT NULL DEFAULT 0 CHECK (departments_updated >= 0),
    employees_added         INTEGER     NOT NULL DEFAULT 0 CHECK (employees_added >= 0),
    employees_updated       INTEGER     NOT NULL DEFAULT 0 CHECK (employees_updated >= 0),
    employees_offboarded    INTEGER     NOT NULL DEFAULT 0 CHECK (employees_offboarded >= 0),
    conflicts_detected      INTEGER     NOT NULL DEFAULT 0 CHECK (conflicts_detected >= 0),
    attempts                INTEGER     NOT NULL DEFAULT 0 CHECK (attempts >= 0),
    failure_class           TEXT        NOT NULL DEFAULT '',
    started_at              TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    completed_at            TIMESTAMPTZ,
    created_at              TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at              TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE UNIQUE INDEX uq_provider_sync_jobs_active
    ON provider_sync_jobs(provider_id)
    WHERE status IN ('pending', 'running');
CREATE INDEX idx_provider_sync_jobs_claim
    ON provider_sync_jobs(status, updated_at, sync_id);
CREATE INDEX idx_provider_sync_jobs_history
    ON provider_sync_jobs(provider_id, started_at DESC, sync_id DESC);

-- Provider directory rows are an external staging view, not United Pass
-- departments or employee profiles. Importing them does not grant a persona,
-- department membership or permission.
CREATE TABLE provider_directory_departments (
    provider_id              TEXT        NOT NULL REFERENCES identity_providers(provider_id),
    provider_tenant_id       TEXT        NOT NULL,
    external_department_id   TEXT        NOT NULL,
    parent_external_id       TEXT        NOT NULL DEFAULT '',
    name                     TEXT        NOT NULL,
    leader_subject           TEXT        NOT NULL DEFAULT '',
    checksum                 TEXT        NOT NULL,
    active                   BOOLEAN     NOT NULL DEFAULT TRUE,
    last_seen_sync_id        TEXT        NOT NULL REFERENCES provider_sync_jobs(sync_id),
    created_at               TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at               TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    PRIMARY KEY (provider_id, provider_tenant_id, external_department_id)
);

CREATE TABLE provider_directory_users (
    provider_id          TEXT        NOT NULL REFERENCES identity_providers(provider_id),
    provider_tenant_id   TEXT        NOT NULL,
    external_subject     TEXT        NOT NULL,
    union_id             TEXT        NOT NULL DEFAULT '',
    tenant_user_id       TEXT        NOT NULL DEFAULT '',
    display_name         TEXT        NOT NULL,
    email                TEXT        NOT NULL DEFAULT '',
    employee_number      TEXT        NOT NULL DEFAULT '',
    title                TEXT        NOT NULL DEFAULT '',
    department_ids       JSONB       NOT NULL DEFAULT '[]',
    checksum             TEXT        NOT NULL,
    active               BOOLEAN     NOT NULL DEFAULT TRUE,
    last_seen_sync_id    TEXT        NOT NULL REFERENCES provider_sync_jobs(sync_id),
    created_at           TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at           TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    PRIMARY KEY (provider_id, provider_tenant_id, external_subject)
);

CREATE INDEX idx_provider_directory_users_email
    ON provider_directory_users(provider_id, provider_tenant_id, lower(email))
    WHERE email <> '';

CREATE TABLE provider_sync_conflicts (
    conflict_id          TEXT        PRIMARY KEY,
    provider_id          TEXT        NOT NULL REFERENCES identity_providers(provider_id),
    provider_tenant_id   TEXT        NOT NULL,
    external_subject     TEXT        NOT NULL,
    external_name        TEXT        NOT NULL,
    external_email       TEXT        NOT NULL DEFAULT '',
    matched_user_id      TEXT        REFERENCES users(id),
    match_reason         TEXT        NOT NULL DEFAULT 'manual'
                         CHECK (match_reason IN ('email', 'name', 'manual')),
    status               TEXT        NOT NULL DEFAULT 'pending'
                         CHECK (status IN ('pending', 'resolved', 'ignored')),
    detected_at          TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    resolved_at          TIMESTAMPTZ,
    resolved_by_user_id  TEXT        REFERENCES users(id),
    created_at           TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at           TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    UNIQUE (provider_id, provider_tenant_id, external_subject)
);

CREATE INDEX idx_provider_sync_conflicts_list
    ON provider_sync_conflicts(provider_id, status, detected_at DESC, conflict_id DESC);

-- +goose StatementEnd

-- +goose Down
-- +goose StatementBegin

DROP TABLE IF EXISTS provider_sync_conflicts;
DROP TABLE IF EXISTS provider_directory_users;
DROP TABLE IF EXISTS provider_directory_departments;
DROP TABLE IF EXISTS provider_sync_jobs;
DROP INDEX IF EXISTS uq_identity_links_feishu_user_tenant;
DROP TABLE IF EXISTS identity_providers;

-- +goose StatementEnd
