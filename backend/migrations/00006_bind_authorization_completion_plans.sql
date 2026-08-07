--
-- Copyright (c) 2026 Chen Jiajie(Ariakage)
--
-- Author: Chen Jiajie(Ariakage) <ariakage233@gmail.com>
-- Date: 2026-08-07
-- Description: Bind authorization completion plans durably to decision operations
--

-- +goose Up
-- +goose StatementBegin

-- United Pass Phase 3 schema evolution: bind authorization completion
-- plans durably (fix over the initial 00005). The decision operation's
-- `decision` column becomes `completion_kind` so the row can express all
-- one-shot provider CreateCallback completions — the two user decisions
-- and the six gateway/provider error callbacks — and the immutable scope
-- snapshot gains its own table.
--
-- Fail-closed policy: Phase 3 has not launched, so no production data may
-- exist in these tables. Legacy rows written by the original 00005 cannot
-- be upgraded honestly — their completion kind is ambiguous ('deny'
-- conflated every non-allow path) and no scope snapshot can be recovered
-- from them. The migration therefore refuses to run against a populated
-- table instead of pretending to repair history.

DO $$
BEGIN
    -- A database that applied the unreleased rewritten 00005 already has
    -- completion_kind; goose recorded that version as applied and will not
    -- re-run it. Refuse loudly instead of diverging silently.
    IF EXISTS (
        SELECT 1 FROM information_schema.columns
         WHERE table_schema = current_schema()
           AND table_name = 'oauth_authorization_decision_operations'
           AND column_name = 'completion_kind'
    ) THEN
        RAISE EXCEPTION
            'oauth_authorization_decision_operations already has completion_kind: this database applied an unreleased rewritten 00005; rebuild the schema (Phase 3 has not launched)';
    END IF;

    IF EXISTS (SELECT 1 FROM oauth_authorization_decision_operations) THEN
        RAISE EXCEPTION
            'oauth_authorization_decision_operations contains legacy rows from the pre-completion-plan schema; Phase 3 has not launched — truncate the table and re-run the migration (scope snapshots cannot be recovered from legacy rows)';
    END IF;
END $$;

-- decision -> completion_kind. The table is verified empty above, so no
-- value mapping runs: legacy 'deny' rows are unrecoverable (they may have
-- been user denials OR any gateway error callback) and are never silently
-- rewritten into access_denied.
ALTER TABLE oauth_authorization_decision_operations
    DROP CONSTRAINT oauth_authorization_decision_operations_decision_check;

ALTER TABLE oauth_authorization_decision_operations
    RENAME COLUMN decision TO completion_kind;

-- All eight one-shot completion kinds (ADR-0005 §5, §9, §12): the two
-- user decisions plus every gateway/provider error-callback reason.
ALTER TABLE oauth_authorization_decision_operations
    ADD CONSTRAINT oauth_authorization_decision_operations_completion_kind_check
    CHECK (completion_kind IN
           ('allow', 'access_denied',
            'login_required', 'consent_required',
            'account_selection_required', 'request_not_supported',
            'server_error', 'temporarily_unavailable'));

-- Bound the provider identifier (mirrors the domain validation).
ALTER TABLE oauth_authorization_decision_operations
    ADD CONSTRAINT oauth_authorization_decision_operations_provider_check
    CHECK (char_length(provider) BETWEEN 1 AND 64);

-- The immutable scope snapshot of an Allow completion plan, persisted at
-- claim time BEFORE the provider call (ADR-0005 §5). Forward
-- reconciliation after a crash between provider success and local commit
-- completes the grant from the operation row and this snapshot alone.
-- Non-allow completions never carry scope rows.
CREATE TABLE oauth_authorization_decision_operation_scopes (
    operation_id TEXT NOT NULL
                 REFERENCES oauth_authorization_decision_operations(operation_id)
                 ON DELETE CASCADE,
    scope        TEXT NOT NULL,
    PRIMARY KEY (operation_id, scope)
);

-- +goose StatementEnd

-- +goose Down
-- +goose StatementBegin

-- Fail closed in both directions: reverting with rows present would
-- silently drop scope snapshots and conflate completion kinds back into
-- the ambiguous decision column.
DO $$
BEGIN
    IF EXISTS (SELECT 1 FROM oauth_authorization_decision_operations) THEN
        RAISE EXCEPTION
            'cannot revert the completion-plan schema while decision-operation rows exist; clean the table first (Phase 3 has not launched)';
    END IF;
END $$;

DROP TABLE IF EXISTS oauth_authorization_decision_operation_scopes;

ALTER TABLE oauth_authorization_decision_operations
    DROP CONSTRAINT oauth_authorization_decision_operations_completion_kind_check;

ALTER TABLE oauth_authorization_decision_operations
    DROP CONSTRAINT oauth_authorization_decision_operations_provider_check;

ALTER TABLE oauth_authorization_decision_operations
    RENAME COLUMN completion_kind TO decision;

ALTER TABLE oauth_authorization_decision_operations
    ADD CONSTRAINT oauth_authorization_decision_operations_decision_check
    CHECK (decision IN ('allow', 'deny'));

-- +goose StatementEnd
