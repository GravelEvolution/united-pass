--
-- Copyright (c) 2026 Chen Jiajie(Ariakage)
--
-- Author: Chen Jiajie(Ariakage) <ariakage233@gmail.com>
-- Date: 2026-08-06
-- Description: Reconciliation desired-status schema
--

-- +goose Up
-- +goose StatementBegin

-- P2 security-review round 2 fix 1: reconciliation jobs must record the
-- expected provider state, not only a free-text reason.
--
-- Application status switches fan out to every client at the provider. When
-- the switch fails mid-way (or the local commit fails afterwards) the
-- already-switched clients drift; the recovery path needs the desired target
-- status to converge on. Empty string means "not a status transition job"
-- (e.g. deletion cleanup).

ALTER TABLE provider_reconciliation_jobs
    ADD COLUMN desired_status TEXT NOT NULL DEFAULT '';

-- +goose StatementEnd

-- +goose Down
-- +goose StatementBegin

ALTER TABLE provider_reconciliation_jobs DROP COLUMN IF EXISTS desired_status;

-- +goose StatementEnd
