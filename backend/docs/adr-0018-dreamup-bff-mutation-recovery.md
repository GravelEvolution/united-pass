# ADR-0018: DreamUP BFF mutation recovery uses an authoritative outcome ledger

Status: Accepted

Date: 2026-08-27

## Context

DreamUP administration mutations cross the United Pass and DreamUP process
boundary. United Pass already persisted an idempotency intent before sending a
mutation and DreamUP already persisted a service-only operation receipt. The
United Pass row, however, did not persist enough safe outcome metadata for a
different API process to answer what happened. A process could also die after
DreamUP committed but before United Pass settled its row, leaving a claimed row
that the live reconciler never reclaimed.

Persisting and replaying arbitrary DreamUP response bodies would expand the PII
and schema-retention boundary. Reissuing an indeterminate mutation would risk a
second side effect. Treating every upstream error as indeterminate also leaves
deterministic 4xx rejections waiting for a receipt that cannot exist.

## Decision

The PostgreSQL `admin_operation_outbox` is the authoritative United Pass
mutation outcome ledger. Every DreamUP mutation row binds the event, initiating
United Pass user and original operation request ID to the existing keyed request
fingerprint and idempotency key. It also binds the expected receipt action,
target type and, when known before execution, target ID.

The ledger stores only allowlisted outcome metadata:

- state: pending, succeeded, failed, or needs operator;
- original request ID;
- expected receipt action, target type and optional pre-known target ID;
- optional HTTP response status;
- optional positive DreamUP result version; and
- a SHA-256 digest of a directly received success body, or the validated
  DreamUP receipt hash after reconciliation.

It never stores a request or response body, reauthentication grant, or
delegation assertion. A validated private receipt hash may occupy the generic
internal digest column as outcome evidence; the API never returns that digest,
the idempotency key, or the receipt hash.

`GET /api/v1/admin/dreamup/events/{eventId}/operations/status` is the recovery
surface. It requires the original `Idempotency-Key` header, the same initiating
account, a current authoritative dashboard binding for the event, and active
administrator step-up. Actor/event mismatch is returned as not found. The
response is no-store and contains only the safe status metadata. A succeeded
result tells the client to refetch the authoritative DreamUP resource; it does
not pretend to reproduce a route-specific response body.

Before an upstream call, United Pass commits the intent and changes its delivery
phase to indeterminate. Therefore an expired indeterminate or sent claim is
returned to pending receipt reconciliation and is never mutation-deliverable.
The reconciler reads the existing DreamUP service-only receipt bound to event,
idempotency key and operation request ID. It additionally requires the receipt
action and target type, plus any pre-known target ID, to match the durable
intent. This extra binding fails closed against the legacy identity-access
fallback that is request-ID based. It accepts only an exact JSON receipt with a
success outcome, a lowercase 64-hex receipt hash, a valid optional result
version, the original request ID, and a plausible epoch-millisecond creation
time matching DreamUP's persisted receipt contract.

An upstream 4xx mapped to validation, forbidden, not found, or conflict is a
deterministic terminal failure and is durably recorded without receipt lookup.
HTTP 408, rate limiting, transport/protocol failures and 5xx outcomes remain
indeterminate and are reconciled from the authoritative DreamUP receipt. Local
settlement uses a short context detached from caller cancellation. If the
process still dies or the database is unavailable, lease reclamation restores
the receipt workflow.

## Consequences

- Exact retry keys never cause an indeterminate mutation to be sent again.
- A different United Pass process can answer recovery status after a crash.
- Clients must keep the original idempotency key until a terminal status and
  must refetch the affected DreamUP resource after success.
- The status endpoint is outcome replay, not arbitrary HTTP-body replay.
- `needs_operator` is a terminal automated-reconciliation state with
  `terminal_at`; an operator must investigate DreamUP and the ledger before any
  separately approved repair.
- Check-in scan requires the request-bound `Idempotency-Key` and atomically
  commits its check-in, audit event, and `checkin.completed` operation receipt.
  Its unknown application target is learned from that receipt, so an ambiguous
  response follows the same authoritative reconciliation path as every other
  DreamUP administration mutation and is never blindly sent again. The receipt
  hash binds the learned target and persisted operation metadata; exact replay
  returns the original check-in, while a new key against an already checked-in
  credential writes a separate `checkin.terminal_state_confirmed` audit event.
- Migration 00015 repairs the earlier result allowlist/terminal constraint drift
  and adds a receipt-due index. It is intentionally forward-only: its Down
  raises an error so Goose cannot record a false v14 schema version. The Up
  uses bounded lock/per-statement timeouts and requires a maintenance window
  with every API/worker process that accesses the shared outbox stopped; its
  table lock lasts until the Goose transaction commits.

## Rejected alternatives

- **Blindly retry the mutation:** unsafe after a lost response.
- **Persist full response bodies:** unnecessarily retains route-specific and
  potentially personal data.
- **Use process memory or Redis as authority:** neither provides the required
  durable cross-process audit record.
- **Trust a client-supplied actor, request ID, or outcome:** all bindings and
  state transitions must remain server-authored.
