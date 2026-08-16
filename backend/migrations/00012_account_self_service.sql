--
-- Copyright (c) 2026 Chen Jiajie(Ariakage)
--
-- Author: Chen Jiajie(Ariakage) <ariakage233@gmail.com>
-- Date: 2026-08-16
-- Description: Durable account profile media and verified contact changes
--

-- +goose Up
-- +goose StatementBegin

-- Avatar bytes are server-decoded, resized and re-encoded PNG data. The
-- browser-visible identifier is random and does not disclose the user ID.
CREATE TABLE user_avatars (
    avatar_id      TEXT        PRIMARY KEY
                              CHECK (avatar_id ~ '^avt_[0-9a-f]{32}$'),
    user_id        TEXT        NOT NULL UNIQUE REFERENCES users(id) ON DELETE CASCADE,
    content_type   TEXT        NOT NULL CHECK (content_type = 'image/png'),
    content        BYTEA       NOT NULL
                              CHECK (octet_length(content) BETWEEN 1 AND 5242880),
    etag           TEXT        NOT NULL CHECK (etag ~ '^[0-9a-f]{64}$'),
    updated_at     TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

-- The raw request capability is returned once to the browser; only its
-- SHA-256 hash is stored. Requests are bound to the user and browser session.
-- A short verifying lease prevents concurrent provider verification while
-- permitting retry after a crashed worker.
CREATE TABLE contact_change_requests (
    request_id_hash TEXT        PRIMARY KEY CHECK (request_id_hash ~ '^[0-9a-f]{64}$'),
    user_id         TEXT        NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    session_id      TEXT        NOT NULL CHECK (char_length(session_id) BETWEEN 1 AND 160),
    kind            TEXT        NOT NULL CHECK (kind IN ('email', 'phone')),
    value           TEXT        NOT NULL,
    status          TEXT        NOT NULL DEFAULT 'pending'
                               CHECK (status IN ('pending', 'verifying', 'completed', 'failed', 'superseded')),
    attempts        INTEGER     NOT NULL DEFAULT 0 CHECK (attempts BETWEEN 0 AND 5),
    claim_id        TEXT        NOT NULL DEFAULT '',
    claim_expires_at TIMESTAMPTZ,
    expires_at      TIMESTAMPTZ NOT NULL,
    created_at      TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at      TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    completed_at    TIMESTAMPTZ,
    CHECK ((status = 'verifying') = (claim_id <> '' AND claim_expires_at IS NOT NULL)),
    -- Active requests retain the destination required for provider
    -- verification; every terminal state must erase it.
    CHECK (
        (status IN ('pending', 'verifying') AND char_length(value) BETWEEN 1 AND 320)
        OR
        (status IN ('completed', 'failed', 'superseded') AND value = '')
    )
);

CREATE UNIQUE INDEX uq_contact_change_requests_active
    ON contact_change_requests(user_id, kind)
    WHERE status IN ('pending', 'verifying');
CREATE INDEX idx_contact_change_requests_expiry
    ON contact_change_requests(expires_at)
    WHERE status IN ('pending', 'verifying');

-- +goose StatementEnd

-- +goose Down
-- +goose StatementBegin
DROP TABLE IF EXISTS contact_change_requests;
DROP TABLE IF EXISTS user_avatars;
-- +goose StatementEnd
