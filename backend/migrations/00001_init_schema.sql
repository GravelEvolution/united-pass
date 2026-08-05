-- +goose Up
-- +goose StatementBegin

-- United Pass Phase 1 schema: users, identity-links, user_personas.
-- This migration creates the minimal tables needed for session and current
-- user functionality. Employee profiles, departments, applications, OAuth
-- clients, consent, policies and audit are added in later phases.
--
-- The schema and search_path must be set by the migration runner (cmd/migrate
-- or the integration test harness) before executing this migration. Tables
-- are created unqualified so they land in whatever search_path is active.

-- users: stable United Pass user identity.
-- Does NOT store passwords, MFA secrets, or provider tokens.
CREATE TABLE users (
    id              TEXT        PRIMARY KEY,
    status          TEXT        NOT NULL DEFAULT 'pending'
                    CHECK (status IN ('pending', 'active', 'disabled')),
    display_name    TEXT        NOT NULL DEFAULT '',
    nickname        TEXT        NOT NULL DEFAULT '',
    avatar_url      TEXT        NOT NULL DEFAULT '',
    email           TEXT        NOT NULL DEFAULT '',
    email_verified  BOOLEAN     NOT NULL DEFAULT FALSE,
    phone           TEXT        NOT NULL DEFAULT '',
    phone_verified  BOOLEAN     NOT NULL DEFAULT FALSE,
    created_at      TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at      TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    version         INTEGER     NOT NULL DEFAULT 1
);

-- identity_links: explicit binding of external provider identities to
-- stable United Pass user IDs. The same provider subject cannot bind to
-- multiple users.
CREATE TABLE identity_links (
    id                  TEXT        PRIMARY KEY,
    user_id             TEXT        NOT NULL REFERENCES users(id),
    provider            TEXT        NOT NULL,
    provider_tenant_id  TEXT        NOT NULL DEFAULT '',
    provider_subject    TEXT        NOT NULL,
    created_at          TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    last_seen_at        TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    UNIQUE (provider, provider_tenant_id, provider_subject)
);

-- user_personas: tracks which personas (consumer, employee) a user has.
-- Phase 1 creates only 'consumer' personas for new users.
CREATE TABLE user_personas (
    user_id     TEXT        NOT NULL REFERENCES users(id),
    persona     TEXT        NOT NULL CHECK (persona IN ('consumer', 'employee')),
    created_at  TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    PRIMARY KEY (user_id, persona)
);

-- Indexes for common lookups.
CREATE INDEX idx_users_email ON users(email) WHERE email != '';
CREATE INDEX idx_identity_links_user_id ON identity_links(user_id);

-- +goose StatementEnd

-- +goose Down
-- +goose StatementBegin

DROP TABLE IF EXISTS user_personas;
DROP TABLE IF EXISTS identity_links;
DROP TABLE IF EXISTS users;

-- +goose StatementEnd
