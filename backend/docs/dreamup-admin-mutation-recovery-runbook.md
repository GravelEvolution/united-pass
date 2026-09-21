# DreamUP administrator mutation recovery runbook

This runbook covers the current production topology: United Pass authority
PostgreSQL remains at migration v13, while DreamUP cross-system mutation
receipts live in a physically distinct operational PostgreSQL database at
isolated migration v1. Do not run authority migration 00014 or 00015 for this
topology.

## Client behavior

Generate one cryptographically random 32–160 character idempotency key for each
logical mutation and retain it until the outcome is terminal. Never generate a
new key merely because the request timed out, returned 502, or the connection
closed without a complete response.

When the mutation response is ambiguous or an exact retry returns a conflict,
call:

```http
GET /api/v1/admin/dreamup/events/{eventId}/operations/status
Idempotency-Key: <the original key>
```

Use the same authenticated United Pass account and an active administrator
step-up session. The operation is also checked against the account's current
event dashboard binding.

- `pending`: do not send the mutation again. Poll with bounded exponential
  backoff and jitter.
- `succeeded`: retire the key only after refetching the affected authoritative
  DreamUP resource and updating the local version.
- `failed`: the downstream request was definitively rejected. Show the mapped
  failure and refetch before a separately initiated retry with a new key.
- `needs_operator`: stop automatic retries and escalate with the returned
  request ID. Do not include the idempotency key in tickets or logs.
- `404`: the key is absent or is not bound to this actor/event. Treat this as a
  release-blocking client-state mismatch; do not guess alternate keys.

The response never contains the original response body or the private DreamUP
receipt hash. `responseStatus` and `resultVersion` may be null when success was
recovered exclusively from the authoritative receipt.

## Operator investigation

1. Use the safe request ID and event ID to locate structured United Pass and
   DreamUP logs. Do not copy bearer tokens, assertions, receipt hashes, request
   bodies, or idempotency keys into an incident system.
2. Inspect the United Pass outbox row through an approved read-only operational
   view and confirm event/actor bindings, delivery phase, attempts and timestamps.
3. Inspect the DreamUP administrative operation receipt through its service-only
   path or approved database read-only tooling. Confirm its action, target type
   and any pre-bound target ID match the United Pass intent; request ID alone is
   not sufficient evidence.
4. If DreamUP has a valid success receipt, repair only through a reviewed
   forward reconciliation workflow. Never replay the mutation manually.
5. If no receipt exists and the downstream rejection is proven deterministic,
   use a separately reviewed terminal-failure repair. Otherwise preserve
   `needs_operator` and investigate further.

## Deployment gate

Before enabling traffic:

1. Verify the authority database reports Goose version 13. Do not run
   `cmd/migrate up` as a routine release step when it already reports v13. The
   command is capped at v13 and must fail if pointed at a legacy schema above
   that ceiling; never use migration 00014/00015 to prepare current production.
2. Verify `UP_ISOLATED_DATABASE_URL` identifies a different physical database
   from `UP_DATABASE_URL`, take and checksum a fresh isolated-database backup,
   and record its restore procedure. A second schema in the authority database
   is not an acceptable substitute.
3. If the dedicated operational database is new, run
   `go run ./cmd/migrate-isolated up` against that target only. If it already
   reports isolated migration version 1, do not rerun or rebuild it. The API
   startup contract must confirm that its selected schema contains exactly the
   Goose metadata plus `wechat_registration_provider_intents` and
   `admin_operation_outbox`, with no authority or unrelated business table.
4. Before replacing an API process that may own a cross-system claim, stop new
   DreamUP administrator mutations and allow in-flight requests to drain. Keep
   the existing operational database in place across the binary switch; do not
   drop, recreate or copy its outbox into authority PostgreSQL.
5. Run the PostgreSQL integration suite against disposable authority-v13 and
   isolated-v1 targets twice in succession to prove cleanup, fresh isolated
   migration recreation, local authority receipts and cross-system outbox
   recovery.
6. Exercise direct success, deterministic 4xx, timeout followed by receipt
   success, expired-claim reclamation, same-actor status, cross-actor not-found,
   and needs-operator paths in the isolated candidate environment. Include a
   check-in scan whose response is discarded, then prove the original operation
   request ID and idempotency key recover the `checkin.completed` receipt; exact
   replay must return the original result and changed input with that key must
   conflict without a second check-in or audit event.
7. Confirm no response or structured log echoes the idempotency key or receipt
   hash. Enable traffic only after authority v13, isolated v1, both readiness
   checks, backup integrity and the normal human release review all succeed.

### Retired shared-store compatibility note

`migrations/00015_dreamup_operation_recovery.sql` remains in source history for
an installation that had already placed the DreamUP outbox in its shared
authority schema. It is forward-only and its Down deliberately raises an error.
It is not a current production migration and must not be invoked to launch this
management panel. Any repair of such a legacy installation requires a separate
authorization, fresh verified backup, exclusive maintenance window and reviewed
forward migration plan.
