--
-- Copyright (c) 2026 Chen Jiajie(Ariakage)
--
-- Author: Chen Jiajie(Ariakage) <ariakage233@gmail.com>
-- Date: 2026-08-11
-- Description: Phase 5 identity and workforce management schema
--

-- +goose Up
-- +goose StatementBegin

-- Department identifiers and employee numbers are local United Pass facts.
-- Neither is derived from email, phone, display name or provider attributes.
CREATE TABLE departments (
    department_id       TEXT        PRIMARY KEY,
    name                TEXT        NOT NULL CHECK (char_length(name) BETWEEN 1 AND 120),
    parent_department_id TEXT       REFERENCES departments(department_id),
    owner_user_id       TEXT        REFERENCES users(id),
    version             INTEGER     NOT NULL DEFAULT 1,
    created_at          TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at          TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    CHECK (parent_department_id IS NULL OR parent_department_id <> department_id)
);

-- PostgreSQL treats NULLs as distinct in ordinary UNIQUE constraints. The
-- expression index makes root-department names unique too.
CREATE UNIQUE INDEX uq_departments_sibling_name
    ON departments (COALESCE(parent_department_id, ''), lower(name));
CREATE INDEX idx_departments_parent ON departments(parent_department_id);

CREATE SEQUENCE employee_number_seq START WITH 1;

CREATE TABLE employee_profiles (
    user_id             TEXT        PRIMARY KEY REFERENCES users(id),
    employee_number     TEXT        NOT NULL UNIQUE,
    department_id       TEXT        NOT NULL REFERENCES departments(department_id),
    title               TEXT        NOT NULL CHECK (char_length(title) BETWEEN 1 AND 120),
    supervisor_user_id  TEXT        REFERENCES users(id),
    status              TEXT        NOT NULL DEFAULT 'active'
                        CHECK (status IN ('active', 'offboarding')),
    onboarded_at        TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    offboarded_at       TIMESTAMPTZ,
    version             INTEGER     NOT NULL DEFAULT 1,
    created_at          TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at          TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    CHECK (supervisor_user_id IS NULL OR supervisor_user_id <> user_id),
    CHECK ((status = 'active' AND offboarded_at IS NULL)
        OR (status = 'offboarding' AND offboarded_at IS NOT NULL))
);

CREATE INDEX idx_employee_profiles_department ON employee_profiles(department_id);
CREATE INDEX idx_employee_profiles_supervisor ON employee_profiles(supervisor_user_id);
CREATE INDEX idx_employee_profiles_list
    ON employee_profiles(updated_at DESC, user_id DESC);

-- Durable convergence ledger for PostgreSQL-authoritative access changes
-- followed by local Redis cleanup and best-effort provider revocation. It
-- stores no credential or provider-session material and only a stable failure
-- class.
CREATE TABLE access_revocation_jobs (
    job_id              TEXT        PRIMARY KEY,
    actor_user_id       TEXT        NOT NULL REFERENCES users(id),
    user_id             TEXT        NOT NULL REFERENCES users(id),
    request_id          TEXT        NOT NULL DEFAULT '',
    reason              TEXT        NOT NULL
                        CHECK (reason IN
                               ('user_disabled', 'employee_offboarded',
                                'admin_session_revoke')),
    status              TEXT        NOT NULL DEFAULT 'pending'
                        CHECK (status IN ('pending', 'resolved')),
    attempts            INTEGER     NOT NULL DEFAULT 0 CHECK (attempts >= 0),
    failure_class       TEXT        NOT NULL DEFAULT '',
    created_at          TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at          TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    resolved_at         TIMESTAMPTZ
);

CREATE INDEX idx_access_revocation_jobs_pending
    ON access_revocation_jobs(created_at, job_id)
    WHERE status = 'pending';

-- A user may have only one unresolved cleanup for the same reason. Repeated
-- high-risk requests converge on the existing job instead of multiplying
-- background work.
CREATE UNIQUE INDEX uq_access_revocation_jobs_pending_reason
    ON access_revocation_jobs(user_id, reason)
    WHERE status = 'pending';

-- +goose StatementEnd

-- +goose Down
-- +goose StatementBegin

DROP TABLE IF EXISTS access_revocation_jobs;
DROP TABLE IF EXISTS employee_profiles;
DROP SEQUENCE IF EXISTS employee_number_seq;
DROP TABLE IF EXISTS departments;

-- +goose StatementEnd
