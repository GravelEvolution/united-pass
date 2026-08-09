--
-- Copyright (c) 2026 Chen Jiajie(Ariakage)
--
-- Author: Chen Jiajie(Ariakage) <ariakage233@gmail.com>
-- Date: 2026-08-06
-- Description: Security generation (epoch) and the durable password mutation intent ledger (ADR-0007)
--

-- +goose Up
-- +goose StatementBegin

-- ADR-0007 Decision 1: the authoritative security generation. Every user
-- carries a monotonic epoch starting at 1; it advances by exactly one in
-- the same transaction that records a password-mutation provider outcome
-- of success or unknown. Sessions, reauth challenges/grants and enrollment
-- tokens are stamped with it; anything stamped with an older epoch is
-- treated as if it did not exist. The epoch never lives in Redis.
ALTER TABLE users
    ADD COLUMN security_epoch INTEGER NOT NULL DEFAULT 1 CHECK (security_epoch >= 1);

-- Monotonic intent identifiers: every acquisition draws the next value so a
-- takeover/recovery CAS can fence exactly on (user_id, intent_id, status).
CREATE SEQUENCE password_mutation_intent_seq;

-- ADR-0007 Decision 3: the durable, per-user password mutation intent
-- ledger. One row per user (the single-writer fence): the lifecycle is
-- active -> outcome_recorded -> local_settlement -> settled, every
-- transition CAS-fenced on (user_id, intent_id, status). No password
-- material ever enters this table.
CREATE TABLE password_mutation_intents (
    user_id             TEXT        PRIMARY KEY REFERENCES users(id),
    intent_id           BIGINT      NOT NULL,
    status              TEXT        NOT NULL
                        CHECK (status IN ('active', 'outcome_recorded', 'local_settlement', 'settled')),
    epoch_at_acquire    INTEGER     NOT NULL CHECK (epoch_at_acquire >= 1),
    provider_outcome    TEXT        NOT NULL DEFAULT ''
                        CHECK (provider_outcome IN ('', 'success', 'confirmed_failure', 'unknown')),
    settlement_outcome  TEXT        NOT NULL DEFAULT ''
                        CHECK (settlement_outcome IN ('', 'settled', 'settled_relogin', 'degraded')),
    lease_expires_at    TIMESTAMPTZ,
    settlement_attempts INTEGER     NOT NULL DEFAULT 0,
    created_at          TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at          TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    settled_at          TIMESTAMPTZ
);

-- +goose StatementEnd

-- +goose Down
-- +goose StatementBegin

DROP TABLE IF EXISTS password_mutation_intents;
DROP SEQUENCE IF EXISTS password_mutation_intent_seq;
ALTER TABLE users DROP COLUMN IF EXISTS security_epoch;

-- +goose StatementEnd
