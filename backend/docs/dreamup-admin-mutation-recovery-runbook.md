# DreamUP administrator mutation recovery runbook

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

1. In an approved maintenance window, stop every United Pass API and worker
   instance, plus any other process that reads or writes
   `admin_operation_outbox`. Confirm there are no live outbox claims or
   database sessions using that table, then apply migration
   `00015_dreamup_operation_recovery.sql` with the explicit migration command;
   API startup never runs migrations. The migration fails after five seconds
   of lock contention and gives each SQL statement a two-minute timeout. The
   ACCESS EXCLUSIVE table lock is held until the whole Goose transaction
   commits, so the timeout does not bound total migration duration and all
   shared outbox traffic must remain stopped until migration completion.
2. Verify the migration reaches version 15, the receipt-due partial index exists,
   and existing `needs_operator` rows have non-null `terminal_at`.
   Inventory any pre-v15 nonterminal cross-system row that lacks the persisted
   receipt action/target binding; do not synthesize metadata for it. It must be
   investigated through the operator workflow before traffic resumes.
3. Run the PostgreSQL integration suite against a dedicated test schema twice in
   succession to prove cleanup and fresh migration recreation.
4. Exercise direct success, deterministic 4xx, timeout followed by receipt
   success, expired-claim reclamation, same-actor status, cross-actor not-found,
   and needs-operator paths in the isolated candidate environment. Include a
   check-in scan whose response is discarded, then prove the original operation
   request ID and idempotency key recover the `checkin.completed` receipt; exact
   replay must return the original result and changed input with that key must
   conflict without a second check-in or audit event.
5. Confirm no response or structured log echoes the idempotency key or receipt
   hash, restart the stopped API/worker processes only after version and schema
   verification succeeds, then complete the normal human release review.

Do not invoke Goose Down for migration 00015. It deliberately raises an error
so `goose_db_version` cannot claim v14 while the v15 constraints remain. Any
rollback must be a separately reviewed forward migration.
