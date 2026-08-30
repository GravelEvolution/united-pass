# Phase 8 production launch runbook

## Status boundary

Technical implementation can be deployed before legal activation. As of
2026-08-11, privacy v1.2 and terms v1.1 remain **Draft / Not Effective**.
Do not run `legal-publish` without external legal sign-off covering the exact
digest. Real production cutover is a separate operator decision.

## Pre-deploy

1. Back up PostgreSQL and verify restore procedure.
2. Apply migration v11 with `go run ./cmd/migrate up`; verify version/status.
3. Require PostgreSQL, Redis and ZITADEL readiness. Production must not use the
   fake provider.
4. Verify frontend and backend manifests match the source bytes:

   ```bash
   shasum -a 256 \
     ../frontend/src/features/legal/data/privacy-sections.ts \
     ../frontend/src/features/legal/data/terms-sections.ts
   ```

   Expected hashes are
   `4cda76af14c0eba4324feb26d45f9e39a8f44e0567f56034d3f97c9b34283703`
   and
   `d277370701594a556be7d53a965c9d87ef7825296e7f647af2d46451dc3e24fb`.
5. Smoke-test requester ownership, 15-minute expiry, deletion cancellation and
   worker recovery in the production-like environment.

## Legal activation (only after approval)

Run once per approved document from `backend/`, using the real approval ticket,
approver, effective time and an existing operator user ID:

```bash
go run ./cmd/legal-publish \
  --kind privacy \
  --effective-at 2026-09-01T00:00:00+08:00 \
  --approval-reference LEGAL-TICKET-ID \
  --approved-by 'Legal approver/team' \
  --actor-user-id usr_operator \
  --confirm-approved
```

Repeat with `--kind terms`. Confirm `/api/v1/legal-documents` returns the exact
version/digest and the intended `scheduled` or `effective` state. The public
pages must remain “暂未生效” when this record is absent or mismatched.

## Monitoring and incident response

- Alert on deletion jobs in `processing` for over five minutes, `failed`, or
  provider/session dependency errors.
- Alert on export jobs stuck in `processing` for over five minutes and verify
  expired `content` is cleared. Terminal export-job metadata is pruned after
  30 days; security-event and completed-deletion proof retention follows the
  externally approved record-retention schedule and must not be shortened
  ad hoc during an incident.
- Never manually mark deletion `completed`. Restore the dependency and allow
  the worker to resume from durable state.
- If a legal release is wrong, stop the cutover and deploy a newly approved
  version/digest. Do not mutate the historical approval row.
- Preserve the security event chain and approval ticket during incident review;
  do not put credentials or substantive personal data in the ticket.

## External sign-offs still required

- legal approval for both exact legal documents;
- production HTTPS/secrets/readiness review;
- backup/restore evidence and incident on-call ownership;
- real ZITADEL destructive-flow acceptance with a disposable production-like
  user;
- explicit go/no-go and traffic cutover.
