--
-- Copyright (c) 2026 Chen Jiajie(Ariakage)
--
-- Author: Chen Jiajie(Ariakage) <ariakage233@gmail.com>
-- Date: 2026-08-07
-- Description: OAuth authorization grants and decision operations schema
--

-- +goose Up
-- +goose StatementBegin

-- United Pass Phase 3 schema: authorization grants and the global consent
-- decision operation (ADR-0005 §2, §4, §5). This migration never touches
-- Phase 1/2 tables.
--
-- Provider request payloads, state, nonce, PKCE material, tokens and
-- provider callback URLs are never written to PostgreSQL (ADR-0005 §2, §5):
-- the decision operation records the auth request identity, the decision
-- kind and the provider_succeeded proof time — nothing more.

-- oauth_authorization_decision_operations: the global single-winner claim
-- for an authorization request (ADR-0005 §5). Exactly one row exists per
-- (provider, provider_tenant_id, auth_request_id); concurrent decisions —
-- including the same auth request open in two browsers logged in as
-- different users — serialize on the unique key before any provider call.
-- local_user_id is a binding written by the winner, never part of the
-- unique key.
--
-- Status machine (compare-and-set transitions only):
--   pending            claimed locally; the provider CreateCallback is in
--                      flight or has not run yet
--   provider_succeeded CreateCallback returned; the proof (decision kind +
--                      time, never the callback URL) is persisted and the
--                      local commit is pending
--   succeeded          grant + audit + terminal state committed
--   failed             terminal failure without provider success proof;
--                      reconciliation fails closed from this state and
--                      never backfills a grant (ADR-0005 §4)
CREATE TABLE oauth_authorization_decision_operations (
    operation_id          TEXT        PRIMARY KEY,
    provider              TEXT        NOT NULL,
    provider_tenant_id    TEXT        NOT NULL DEFAULT '',
    auth_request_id       TEXT        NOT NULL
                          CHECK (char_length(auth_request_id)
                                 BETWEEN 1 AND 200),
    decision              TEXT        NOT NULL
                          CHECK (decision IN ('allow', 'deny')),
    status                TEXT        NOT NULL DEFAULT 'pending'
                          CHECK (status IN
                                 ('pending', 'provider_succeeded',
                                  'succeeded', 'failed')),
    -- Winner binding; empty until the winner commits.
    local_user_id         TEXT        NOT NULL DEFAULT '',
    -- The United Pass client resolved for the request (display/audit only;
    -- intentionally not a foreign key, mirroring oauth_provider_operations).
    client_id             TEXT        NOT NULL DEFAULT '',
    -- Stable error class on terminal failure (contract §8); empty otherwise.
    error_class           TEXT        NOT NULL DEFAULT '',
    -- provider_succeeded proof time; NULL until the proof is persisted.
    provider_succeeded_at TIMESTAMPTZ,
    created_at            TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at            TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    UNIQUE (provider, provider_tenant_id, auth_request_id)
);

-- Reconciliation scan path: only in-flight rows need recovery attention.
CREATE INDEX idx_consent_decision_ops_recovery
    ON oauth_authorization_decision_operations (created_at)
    WHERE status IN ('pending', 'provider_succeeded');

-- oauth_authorization_grants: the United Pass user-consent ledger
-- (ADR-0005 §4). A grant row implies consent, not live tokens. Grants are
-- aggregated per OAuth client and upserted per (user, client): the unique
-- key makes duplicate grants impossible; re-authorization after revocation
-- or scope expansion reactivates the same row with the new scope set.
CREATE TABLE oauth_authorization_grants (
    grant_id   TEXT        PRIMARY KEY,
    user_id    TEXT        NOT NULL REFERENCES users(id),
    client_id  TEXT        NOT NULL REFERENCES oauth_clients(client_id),
    status     TEXT        NOT NULL DEFAULT 'active'
               CHECK (status IN ('active', 'revoked')),
    granted_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    revoked_at TIMESTAMPTZ,
    updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    UNIQUE (user_id, client_id)
);

CREATE INDEX idx_oauth_authorization_grants_user
    ON oauth_authorization_grants(user_id);

-- oauth_authorization_grant_scopes: the consented scope set of a grant.
-- The full set is replaced on every re-consent (scope expansion, ADR-0005
-- §7); offline_access appears here only when it was explicitly consented.
CREATE TABLE oauth_authorization_grant_scopes (
    grant_id TEXT NOT NULL
             REFERENCES oauth_authorization_grants(grant_id) ON DELETE CASCADE,
    scope    TEXT NOT NULL,
    PRIMARY KEY (grant_id, scope)
);

-- +goose StatementEnd

-- +goose Down
-- +goose StatementBegin

DROP TABLE IF EXISTS oauth_authorization_grant_scopes;
DROP TABLE IF EXISTS oauth_authorization_grants;
DROP TABLE IF EXISTS oauth_authorization_decision_operations;

-- +goose StatementEnd
