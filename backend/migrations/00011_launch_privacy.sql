--
-- Copyright (c) 2026 Chen Jiajie(Ariakage)
--
-- Author: Chen Jiajie(Ariakage) <ariakage233@gmail.com>
-- Date: 2026-08-11
-- Description: Phase 8 legal publication and privacy-rights lifecycle
--

-- +goose Up
-- +goose StatementBegin

-- A publication stores only the immutable identity of content reviewed
-- outside the product. The document itself remains in the versioned frontend
-- source; the SHA-256 digest binds the approval record to those exact bytes.
CREATE TABLE legal_document_publications (
    document_kind       TEXT        NOT NULL
                                CHECK (document_kind IN ('privacy', 'terms')),
    version             TEXT        NOT NULL
                                CHECK (char_length(version) BETWEEN 1 AND 32),
    content_sha256      TEXT        NOT NULL
                                CHECK (content_sha256 ~ '^[0-9a-f]{64}$'),
    effective_at        TIMESTAMPTZ NOT NULL,
    approval_reference  TEXT        NOT NULL
                                CHECK (char_length(approval_reference) BETWEEN 1 AND 200),
    approved_by         TEXT        NOT NULL
                                CHECK (char_length(approved_by) BETWEEN 1 AND 120),
    published_by_user_id TEXT       NOT NULL REFERENCES users(id),
    published_at        TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    superseded_at       TIMESTAMPTZ,
    PRIMARY KEY (document_kind, version),
    CHECK (superseded_at IS NULL OR superseded_at >= published_at)
);

CREATE UNIQUE INDEX uq_legal_document_publications_current
    ON legal_document_publications(document_kind)
    WHERE superseded_at IS NULL;

-- Personal-data artifacts are short lived, requester-owned JSON files. They
-- never contain provider/session credentials, password material or other
-- users' audit data. Expired bytes are physically purged by the worker.
CREATE TABLE personal_data_export_jobs (
    export_id           TEXT        PRIMARY KEY,
    user_id             TEXT        NOT NULL REFERENCES users(id),
    request_id          TEXT        NOT NULL DEFAULT '',
    status              TEXT        NOT NULL DEFAULT 'pending'
                                CHECK (status IN ('pending', 'processing', 'completed', 'failed')),
    content             BYTEA,
    total_sections      INTEGER     NOT NULL DEFAULT 0 CHECK (total_sections >= 0),
    failure_class       TEXT        NOT NULL DEFAULT '',
    requested_at        TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at          TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    completed_at        TIMESTAMPTZ,
    expires_at          TIMESTAMPTZ
);

CREATE UNIQUE INDEX uq_personal_data_export_jobs_active
    ON personal_data_export_jobs(user_id)
    WHERE status IN ('pending', 'processing');
CREATE INDEX idx_personal_data_export_jobs_pending
    ON personal_data_export_jobs(requested_at, export_id)
    WHERE status = 'pending';
CREATE INDEX idx_personal_data_export_jobs_expiry
    ON personal_data_export_jobs(expires_at)
    WHERE status = 'completed' AND content IS NOT NULL;

-- Deletion is a durable, cancellable 30-day lifecycle. The provider subject
-- is needed only until provider deletion succeeds and is cleared by the local
-- anonymisation transaction. Stable user IDs and security events are retained
-- as non-profile integrity references.
CREATE TABLE account_deletion_requests (
    deletion_id         TEXT        PRIMARY KEY,
    user_id             TEXT        NOT NULL UNIQUE REFERENCES users(id),
    provider_subject    TEXT        NOT NULL DEFAULT '',
    request_id          TEXT        NOT NULL DEFAULT '',
    status              TEXT        NOT NULL DEFAULT 'pending'
                                CHECK (status IN
                                    ('pending', 'processing', 'provider_deleted',
                                     'completed', 'cancelled', 'failed')),
    attempts            INTEGER     NOT NULL DEFAULT 0 CHECK (attempts >= 0),
    failure_class       TEXT        NOT NULL DEFAULT '',
    requested_at        TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    execute_after       TIMESTAMPTZ NOT NULL,
    updated_at          TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    cancelled_at        TIMESTAMPTZ,
    provider_deleted_at TIMESTAMPTZ,
    completed_at        TIMESTAMPTZ,
    CHECK (execute_after > requested_at)
);

CREATE INDEX idx_account_deletion_requests_due
    ON account_deletion_requests(execute_after, deletion_id)
    WHERE status IN ('pending', 'processing', 'provider_deleted');

-- +goose StatementEnd

-- +goose Down
-- +goose StatementBegin

DROP TABLE IF EXISTS account_deletion_requests;
DROP TABLE IF EXISTS personal_data_export_jobs;
DROP TABLE IF EXISTS legal_document_publications;

-- +goose StatementEnd
