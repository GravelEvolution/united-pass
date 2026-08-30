--
-- Copyright (c) 2026 Chen Jiajie(Ariakage)
--
-- Description: Bind retryable WeChat registrations to one provider request
--

-- +goose Up
-- +goose StatementBegin

CREATE TABLE wechat_registration_provider_intents (
    user_id             TEXT        PRIMARY KEY REFERENCES users(id) ON DELETE CASCADE,
    request_verifier    TEXT        NOT NULL
                                    CHECK (request_verifier ~ '^\$argon2id\$v=19\$m=32768,t=2,p=1\$[A-Za-z0-9+/]{22}\$[A-Za-z0-9+/]{43}$'),
    created_at          TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

-- +goose StatementEnd

-- +goose Down
-- +goose StatementBegin

-- This security migration is intentionally irreversible. Restore only from a
-- reviewed backup and a separately approved forward migration.

-- +goose StatementEnd
