-- +goose Up
-- +goose StatementBegin

-- P2 security-review fix 2: durable secret-rotation operation state.
--
-- The previous "single-winner" gate only bumped the optimistic-concurrency
-- version, which serialized readers of the SAME version but allowed two
-- sequential rotations (A bumps to v3 and calls the provider; B reads v3,
-- bumps to v4 and calls the provider again). ZITADEL rotation is
-- non-idempotent, and a provider timeout cannot distinguish success from
-- failure, so the rotation lifecycle needs explicit durable state:
--
--   idle            no rotation in flight; a new rotation may start
--   in_progress     exactly one holder acquired the gate and is calling
--                   the provider (lease: started_at + operation_id)
--   outcome_unknown the provider call timed out / failed ambiguously or the
--                   local completion failed after provider success; further
--                   rotations are blocked until reconciliation resolves it
--
-- Only the atomic conditional UPDATE idle -> in_progress grants execution.

ALTER TABLE oauth_clients
    ADD COLUMN secret_rotation_status TEXT NOT NULL DEFAULT 'idle'
        CHECK (secret_rotation_status IN ('idle', 'in_progress', 'outcome_unknown'));

-- Lease metadata for the in-progress holder: the provider operation record and
-- the acquisition time. Stale in_progress rows (crashed holders) are detected
-- by reconciliation from started_at.
ALTER TABLE oauth_clients
    ADD COLUMN secret_rotation_operation_id TEXT NOT NULL DEFAULT '';

ALTER TABLE oauth_clients
    ADD COLUMN secret_rotation_started_at TIMESTAMPTZ;

-- +goose StatementEnd

-- +goose Down
-- +goose StatementBegin

ALTER TABLE oauth_clients DROP COLUMN IF EXISTS secret_rotation_started_at;
ALTER TABLE oauth_clients DROP COLUMN IF EXISTS secret_rotation_operation_id;
ALTER TABLE oauth_clients DROP COLUMN IF EXISTS secret_rotation_status;

-- +goose StatementEnd
