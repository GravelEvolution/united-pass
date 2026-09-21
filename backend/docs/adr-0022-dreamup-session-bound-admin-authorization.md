# ADR-0022: DreamUP administrator session-bound authorization

- Status: Accepted
- Date: 2026-09-03
- Owners: United Pass backend team and DreamUP operations

## Context

DreamUP's browser administration surface required an additional United Pass
password/MFA reauthentication before reads and mutations classified as high
risk. The extra prompt repeatedly blocked authenticated operators even after a
correct password. DreamUP's native Mini Program had already established a
session-bound alternative for the same signed downstream assertion contract.

The product decision is to remove this additional prompt from DreamUP
administration without changing reauthentication requirements for United Pass
account, identity-provider, application-secret, policy-publication, or other
platform operations.

## Decision

When a DreamUP administrator request does not provide an explicit one-shot
reauthentication token, the BFF authorizes both browser-cookie and native
Mini Program transports from the current server-validated session. Before
signing a downstream assertion it must still verify:

- the transport is an accepted DreamUP administrator transport;
- the login is no older than 30 minutes and is not future-dated;
- the session security epoch is positive and exactly matches the current
  authoritative account security epoch;
- the requested event has an active role binding with a positive version;
- policy, fixed-role, resource-kind, resource-ID and event-ID checks allow the
  exact action;
- mutations retain CSRF, `If-Match`, idempotency, request-body digest, durable
  operation receipt and audit requirements.

After those checks the BFF creates a cryptographically random, request-scoped
`asa_*` internal authorization ID and binds it, the current time, the method,
canonical path and query, body digest, role and role version into the existing
short-lived signed Worker assertion.

If a client explicitly supplies a one-shot reauthentication token, the strict
action-and-target-bound consumption path remains authoritative. An invalid,
expired, reused or mismatched token fails closed and never downgrades to session
authorization.

## Alternatives Considered

- Remove only the React prompt. Rejected because the BFF would continue to
  reject the request and no DreamUP function would recover.
- Change the signer and Worker assertion schema immediately. Rejected for this
  repair because it would require a coordinated multi-service cutover without
  improving the effective authorization boundary.
- Disable all high-risk controls. Rejected. Current login age, authoritative
  epoch, event RBAC, object authorization, CSRF, concurrency and audit controls
  remain mandatory.

## Consequences

DreamUP operators are no longer asked to re-enter their United Pass password or
complete MFA while their current session remains valid. A password change,
session revocation, security-epoch advance, stale login, role removal or policy
denial still blocks the operation.

The existing `reauth_grant_id` claim temporarily carries an `asa_*` internal
session-authorization ID. This is a schema-compatibility debt; a future
assertion version should name the authorization context explicitly. The shared
United Pass reauthentication API and persistence remain in place for unrelated
platform security operations and rollback compatibility.

## Security Considerations

The ID uses 144 bits of CSPRNG output and is emitted only inside the signed,
short-lived service assertion. It is not accepted from an untrusted request.
Explicit tokens cannot be used as a downgrade oracle. Authentication and
authorization failures occur before signing or calling DreamUP.

## Implementation Notes

The policy change is intentionally confined to
`internal/dreamupadmin.Service.Proxy`. The signer and DreamUP Worker continue to
validate the existing request-bound assertion format. Frontend step-up code may
be removed independently after the server change is fully adopted because new
requests no longer receive `admin_stepup.required` for a valid current session.

## Follow-up

- Introduce an assertion version with an explicit session-authorization claim
  before retiring the compatibility field.
- Remove unreachable DreamUP-only password/MFA prompt code after the API
  release has passed production verification.
