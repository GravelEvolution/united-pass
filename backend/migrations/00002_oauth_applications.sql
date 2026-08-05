-- +goose Up
-- +goose StatementBegin

-- United Pass Phase 2 schema: OAuth application and client management plane
-- (ADR-0004). This migration never touches Phase 1 tables.
--
-- Secrets are never stored anywhere: oauth_client_secret_records holds
-- metadata only. Provider identifiers are mapping columns only and are
-- never United Pass identities.
--
-- Client name uniqueness per application (P2.2 decision, ADR-0004 §1
-- follow-up): duplicate client names under one application confuse
-- operators and audit trails; enforced with a partial unique index.

-- oauth_applications: application aggregate root.
CREATE TABLE oauth_applications (
    application_id  TEXT        PRIMARY KEY,
    name            TEXT        NOT NULL,
    description     TEXT        NOT NULL DEFAULT '',
    logo_url        TEXT        NOT NULL DEFAULT '',
    audience        TEXT        NOT NULL
                    CHECK (audience IN ('internal', 'external', 'hybrid')),
    owner_user_id   TEXT        NOT NULL REFERENCES users(id),
    status          TEXT        NOT NULL DEFAULT 'active'
                    CHECK (status IN ('active', 'disabled')),
    provisioning_status TEXT    NOT NULL DEFAULT 'provisioning'
                    CHECK (provisioning_status IN
                           ('provisioning', 'provisioned', 'provisioning_failed')),
    version         INTEGER     NOT NULL DEFAULT 1,
    created_at      TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at      TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    deleted_at      TIMESTAMPTZ
);

CREATE UNIQUE INDEX uq_oauth_applications_name_live
    ON oauth_applications (name) WHERE deleted_at IS NULL;
CREATE INDEX idx_oauth_applications_owner ON oauth_applications(owner_user_id);
CREATE INDEX idx_oauth_applications_list
    ON oauth_applications (updated_at DESC, application_id DESC)
    WHERE deleted_at IS NULL AND provisioning_status = 'provisioned';

-- oauth_clients: OAuth clients nested under an application.
-- provisioning_status is the internal cross-store consistency state; the
-- public status column only ever holds active/disabled.
CREATE TABLE oauth_clients (
    client_id                 TEXT        PRIMARY KEY,
    application_id            TEXT        NOT NULL REFERENCES oauth_applications(application_id),
    name                      TEXT        NOT NULL,
    profile                   TEXT        NOT NULL
                              CHECK (profile IN ('web_server', 'spa_mobile', 'server_to_server')),
    client_type               TEXT        NOT NULL
                              CHECK (client_type IN ('public', 'confidential')),
    token_endpoint_auth_method TEXT       NOT NULL
                              CHECK (token_endpoint_auth_method IN ('client_secret_basic', 'none')),
    consent_mode              TEXT        NOT NULL
                              CHECK (consent_mode IN ('always', 'first_authorization')),
    logout_uri                TEXT        NOT NULL DEFAULT '',
    status                    TEXT        NOT NULL DEFAULT 'active'
                              CHECK (status IN ('active', 'disabled')),
    provider                  TEXT        NOT NULL DEFAULT '',
    provider_project_id       TEXT        NOT NULL DEFAULT '',
    provider_application_id   TEXT        NOT NULL DEFAULT '',
    provider_client_id        TEXT        NOT NULL DEFAULT '',
    provisioning_status       TEXT        NOT NULL DEFAULT 'provisioning'
                              CHECK (provisioning_status IN
                                     ('provisioning', 'provisioned', 'provisioning_failed',
                                      'deleting', 'delete_failed')),
    provider_reconciliation_required BOOLEAN NOT NULL DEFAULT FALSE,
    version                   INTEGER     NOT NULL DEFAULT 1,
    created_at                TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at                TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    deleted_at                TIMESTAMPTZ
);

CREATE UNIQUE INDEX uq_oauth_clients_name_per_app_live
    ON oauth_clients (application_id, name) WHERE deleted_at IS NULL;
CREATE UNIQUE INDEX uq_oauth_clients_provider_client
    ON oauth_clients (provider, provider_client_id)
    WHERE provider != '' AND provider_client_id != '' AND deleted_at IS NULL;
CREATE INDEX idx_oauth_clients_application ON oauth_clients(application_id);

-- oauth_client_redirect_uris: exact-match registry. Values are stored
-- verbatim; no normalization is ever applied.
CREATE TABLE oauth_client_redirect_uris (
    client_id   TEXT        NOT NULL REFERENCES oauth_clients(client_id),
    uri         TEXT        NOT NULL CHECK (length(uri) <= 2048),
    is_loopback BOOLEAN     NOT NULL DEFAULT FALSE,
    added_at    TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    PRIMARY KEY (client_id, uri)
);

-- oauth_client_scopes: registered scope IDs only; enforced in code against
-- the authoritative catalog.
CREATE TABLE oauth_client_scopes (
    client_id TEXT NOT NULL REFERENCES oauth_clients(client_id),
    scope     TEXT NOT NULL,
    PRIMARY KEY (client_id, scope)
);

-- oauth_client_secret_records: secret metadata only. Never a secret value.
CREATE TABLE oauth_client_secret_records (
    secret_id       TEXT        PRIMARY KEY,
    client_id       TEXT        NOT NULL REFERENCES oauth_clients(client_id),
    label           TEXT        NOT NULL DEFAULT '',
    created_at      TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    last_rotated_at TIMESTAMPTZ
);

CREATE INDEX idx_oauth_client_secret_records_client ON oauth_client_secret_records(client_id);

-- oauth_provider_operations: durable record of provider calls for
-- idempotent retries and reconciliation.
CREATE TABLE oauth_provider_operations (
    operation_id    TEXT        PRIMARY KEY,
    operation_type  TEXT        NOT NULL
                    CHECK (operation_type IN
                           ('provision_client', 'update_client', 'enable_client',
                            'disable_client', 'delete_client', 'rotate_client_secret')),
    application_id  TEXT,
    client_id       TEXT,
    idempotency_key TEXT        NOT NULL UNIQUE,
    status          TEXT        NOT NULL DEFAULT 'pending'
                    CHECK (status IN ('pending', 'succeeded', 'failed')),
    error_class     TEXT        NOT NULL DEFAULT '',
    created_at      TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at      TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

-- provider_reconciliation_jobs: recoverable provider-side cleanup that
-- could not be completed inline (e.g. compensation failure).
CREATE TABLE provider_reconciliation_jobs (
    job_id                  TEXT        PRIMARY KEY,
    application_id          TEXT        NOT NULL DEFAULT '',
    client_id               TEXT        NOT NULL DEFAULT '',
    provider_application_id TEXT        NOT NULL DEFAULT '',
    reason                  TEXT        NOT NULL DEFAULT '',
    created_at              TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    resolved_at             TIMESTAMPTZ
);

-- security_events: real audit persistence boundary (ADR-0004 §8). Payloads
-- never contain secrets, tokens, cookies, passwords or raw provider errors.
CREATE TABLE security_events (
    event_id       TEXT        PRIMARY KEY,
    event_type     TEXT        NOT NULL,
    actor_user_id  TEXT        NOT NULL DEFAULT '',
    application_id TEXT        NOT NULL DEFAULT '',
    client_id      TEXT        NOT NULL DEFAULT '',
    request_id     TEXT        NOT NULL DEFAULT '',
    operation      TEXT        NOT NULL DEFAULT '',
    result         TEXT        NOT NULL
                   CHECK (result IN ('success', 'denied')),
    payload        JSONB       NOT NULL DEFAULT '{}',
    occurred_at    TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE INDEX idx_security_events_application ON security_events(application_id, occurred_at DESC);
CREATE INDEX idx_security_events_client ON security_events(client_id, occurred_at DESC);
CREATE INDEX idx_security_events_type ON security_events(event_type, occurred_at DESC);

-- +goose StatementEnd

-- +goose Down
-- +goose StatementBegin

DROP TABLE IF EXISTS security_events;
DROP TABLE IF EXISTS provider_reconciliation_jobs;
DROP TABLE IF EXISTS oauth_provider_operations;
DROP TABLE IF EXISTS oauth_client_secret_records;
DROP TABLE IF EXISTS oauth_client_scopes;
DROP TABLE IF EXISTS oauth_client_redirect_uris;
DROP TABLE IF EXISTS oauth_clients;
DROP TABLE IF EXISTS oauth_applications;

-- +goose StatementEnd
