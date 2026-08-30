--
-- Copyright (c) 2026 Chen Jiajie(Ariakage)
--
-- Author: Chen Jiajie(Ariakage) <ariakage233@gmail.com>
-- Date: 2026-08-30
-- Description: Reconcile account self-service objects across migration lineages
--

-- +goose Up
-- +goose StatementBegin

-- Public and fresh databases already created these objects in migration 12.
-- The production lineage used versions 12 and 13 for DreamUP administration,
-- so it reaches this migration without them.  IF NOT EXISTS makes the public
-- path a no-op and creates the same schema on the production path.

SET LOCAL lock_timeout = '5s';
SET LOCAL statement_timeout = '2min';

DO $lineage$
DECLARE
    existing_tables INTEGER;
BEGIN
    SELECT COUNT(*)
      INTO existing_tables
      FROM information_schema.tables
     WHERE table_schema = current_schema()
       AND table_name = ANY (ARRAY['user_avatars', 'contact_change_requests']);

    IF existing_tables = 1 THEN
        RAISE EXCEPTION 'migration 00016: partial account self-service lineage detected';
    END IF;
END
$lineage$;

-- Avatar bytes are server-decoded, resized and re-encoded PNG data. The
-- browser-visible identifier is random and does not disclose the user ID.
CREATE TABLE IF NOT EXISTS user_avatars (
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
CREATE TABLE IF NOT EXISTS contact_change_requests (
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

CREATE UNIQUE INDEX IF NOT EXISTS uq_contact_change_requests_active
    ON contact_change_requests(user_id, kind)
    WHERE status IN ('pending', 'verifying');
CREATE INDEX IF NOT EXISTS idx_contact_change_requests_expiry
    ON contact_change_requests(expires_at)
    WHERE status IN ('pending', 'verifying');

DO $lineage$
DECLARE
	avatar_columns TEXT[];
	avatar_constraints INTEGER;
	contact_columns TEXT[];
	contact_constraints INTEGER;
	lineage_indexes INTEGER;
	head_objects INTEGER;
BEGIN
	SELECT ARRAY_AGG(
	           column_name || ':' || udt_name || ':' || is_nullable || ':' ||
	           COALESCE(column_default, '<null>')
	           ORDER BY ordinal_position)
	  INTO avatar_columns
	  FROM information_schema.columns
     WHERE table_schema = current_schema()
       AND table_name = 'user_avatars';

	SELECT ARRAY_AGG(
	           column_name || ':' || udt_name || ':' || is_nullable || ':' ||
	           COALESCE(column_default, '<null>')
	           ORDER BY ordinal_position)
	  INTO contact_columns
      FROM information_schema.columns
     WHERE table_schema = current_schema()
       AND table_name = 'contact_change_requests';

    SELECT COUNT(*)
      INTO avatar_constraints
      FROM pg_constraint
     WHERE conrelid = to_regclass(current_schema() || '.user_avatars');

    SELECT COUNT(*)
      INTO contact_constraints
      FROM pg_constraint
     WHERE conrelid = to_regclass(current_schema() || '.contact_change_requests');

	SELECT COUNT(*)
	  INTO lineage_indexes
      FROM pg_indexes
     WHERE schemaname = current_schema()
       AND indexname = ANY (ARRAY[
           'uq_contact_change_requests_active',
           'idx_contact_change_requests_expiry'
	       ]);

	SELECT COUNT(*)
	  INTO head_objects
	  FROM pg_class AS rel
	  JOIN pg_namespace AS ns ON ns.oid = rel.relnamespace
	 WHERE ns.nspname = current_schema()
	   AND rel.relname = ANY (ARRAY[
	       'admin_role_bindings',
	       'identity_access_grant_fields',
	       'wechat_registration_provider_intents',
	       'idx_admin_operation_outbox_receipt_due'
	   ]);

	IF avatar_columns IS DISTINCT FROM ARRAY[
	       'avatar_id:text:NO:<null>',
	       'user_id:text:NO:<null>',
	       'content_type:text:NO:<null>',
	       'content:bytea:NO:<null>',
	       'etag:text:NO:<null>',
	       'updated_at:timestamptz:NO:now()'
	   ]
	   OR avatar_constraints <> 7
	   OR contact_columns IS DISTINCT FROM ARRAY[
	       'request_id_hash:text:NO:<null>',
	       'user_id:text:NO:<null>',
	       'session_id:text:NO:<null>',
	       'kind:text:NO:<null>',
	       'value:text:NO:<null>',
	       'status:text:NO:''pending''::text',
	       'attempts:int4:NO:0',
	       'claim_id:text:NO:''''::text',
	       'claim_expires_at:timestamptz:YES:<null>',
	       'expires_at:timestamptz:NO:<null>',
	       'created_at:timestamptz:NO:now()',
	       'updated_at:timestamptz:NO:now()',
	       'completed_at:timestamptz:YES:<null>'
	   ]
	   OR contact_constraints <> 9
	   OR lineage_indexes <> 2
	   OR head_objects <> 4 THEN
        RAISE EXCEPTION 'migration 00016: account self-service schema is incomplete or drifted';
    END IF;
END
$lineage$;

-- +goose StatementEnd

-- +goose Down
-- +goose StatementBegin
-- A destructive Down cannot determine whether migration 12 or migration 16
-- owns these tables on the current database lineage. Abort so the schema and
-- goose_db_version remain truthful.
DO $$
BEGIN
    RAISE EXCEPTION 'migration 00016 is forward-only; apply a reviewed forward repair';
END
$$;
-- +goose StatementEnd
