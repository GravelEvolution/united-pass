# ADR-0015: DreamUP administrator challenge step-up

- Status: Accepted
- Date: 2026-08-17
- Owners: United Pass security and DreamUP administration

## Context

DreamUP administrators need a second, local proof before sensitive event-scoped
operations. The proof supplements—never replaces—the provider-backed United
Pass session, the account's existing MFA, event-scoped authorization, optimistic
concurrency, and downstream object-level checks. A leaked answer must not become
a reusable password, a cross-event authorization, or a way to recover an
account without the identity provider.

The design must also survive retries, concurrent requests, key rotation, Redis
outages, role revocation, credential rotation, and a lost HTTP response without
replaying a bearer token or leaving PostgreSQL and Redis security state in an
ambiguous order.

## Decision

### Default-off surface

`UP_DREAMUP_ADMIN_ENABLED` defaults to `false`. Bootstrap tests the flag before
opening any new keyring or constructing the service. When false, none of the
four browser routes is registered and the namespace returns 404. Explicitly
enabling it requires PostgreSQL, Redis, browser sessions, and all five
purpose-specific keyrings.

The enabled owner-only routes are:

- `GET /api/v1/admin/step-up/challenge`;
- `POST /api/v1/admin/step-up/enroll`;
- `POST /api/v1/admin/step-up/verify`;
- `POST /api/v1/admin/step-up/rotate`.

Enrollment always requires a provider-backed session whose provider login is
no more than five minutes old. Existing TOTP, passkey, or recovery MFA is
accepted. The sole bootstrap exception permits a first enrollment without
existing MFA only when the authority database confirms an active
system-scoped `super_admin` or `top_admin` binding and confirms that no
challenge material exists. Event-scoped administrators, ordinary roles,
missing bindings, disabled bindings, stale logins, and identities with any
existing challenge fail closed. Registration and recovery remain
provider-owned; this challenge cannot create or recover a United Pass
identity. A federated session without the provider session reference and
credential needed for fresh-login validation receives the stable
`session.reauthentication_required` response and must reauthenticate; it is
not treated as bootstrap authorization.

### Text and credential handling

Question and answer text is normalized with NFKC and counted with UAX #29
grapheme clusters. Questions contain 5–200 clusters. Answers are outer-trimmed
after normalization and contain 7–256 clusters. Control, format, bidi,
zero-width, ZWJ, and other Unicode `C` category code points are rejected. A
normalized question cannot equal its normalized answer.

Answers are stored only as:

`Argon2id(HMAC-SHA-256(answer-pepper, normalized-answer), random-salt, params)`

with reviewed 64 MiB / three-iteration / two-lane write parameters and a
bounded process-wide concurrency slot. The PHC parser accepts only bounded
Argon2id parameters and comparison uses a constant-time seam. The stored pepper
key ID selects a retained read key; unknown or disabled IDs fail closed.

Questions use AES-256-GCM with random nonces and AAD containing the purpose,
immutable user owner, immutable record ID, and credential version. Protected
operation reasons use a separate AES keyring and distinct AAD purpose. The
challenge-encryption, answer-pepper, protected-reason, rate-limit, operation-
fingerprint, and existing session-encryption material may not be reused across
purposes, including retained keys.

### State, freshness, and lockout

One credential follows `pending_enrollment`, `recovery_pending`, `active`,
`must_rotate`, or `disabled`. It is shared by the administrator identity across
events, while access still requires an active event binding (or active system
super binding) for the requested event. A `must_rotate` identity may prove only
the fixed challenge-rotation action until rotation succeeds.

Before Argon2 work, one atomic Redis script advances two independently keyed
HMAC counters: immutable user and normalized client fingerprint. Redis stores
neither raw user IDs, addresses, nor user agents. Changing clients cannot reset
the user budget, and distributing users behind one abusive client cannot reset
the client budget. Redis failure denies before hashing. Five failed proofs in a
15-minute credential window lock the challenge for 30 minutes.

Successful verification replaces any prior unrevoked proof for the same
session and user in the same PostgreSQL transaction, including a still-active
general proof that would otherwise occupy the partial unique index. Every
successful answer refreshes this durable general proof for 30 minutes. A
high-risk verification additionally mints a separate, action-and-target-bound
single-use grant capped at five minutes; it does not shorten or substitute the
general proof.

The provider-backed login timestamp carried by a cross-service assertion is
accepted for at most 30 minutes. The answer-verification endpoint applies that
same boundary before decoding or checking an answer and returns the stable
`session.reauthentication_required` error for a stale login.

Every mutation defaults fail-safe to a high-risk proof. Application review,
admission approval, application decision, registration management, check-in
scan, contact-submission management and content management are all explicit
high-risk capabilities. Together with check-in-window management,
identity-access consumption, restricted-identity and legal reads, application
export, audit read and role-migration read, they require a proof no older than
five minutes. The corresponding fixed management actions for roles, event
registry, OA approval, restricted/legal viewing, export, challenge rotation
and check-in-window management are also high risk.

Native Mini Program bearer requests always require the action-and-target-bound
single-use grant, including when the request omits its token. The existing
DreamUP cookie website predates that header contract. For that exact
authenticated transport only, a request without the header may reuse the
durable administrator proof bound to the same user and browser session, but
only for five minutes after verification. The HTTP boundary records the
validated transport explicitly; a native credential and Mini Program request
shape must agree, and an unknown or mismatched transport fails closed. The
fallback revalidates the proof ID, session, user, challenge version, exact
equality between its security-epoch stamp and the current account-wide
`users.security_epoch`, login ordering, revocation, expiry and five-minute age
before signing.
Its stable step-up ID occupies the existing `reauth_grant_id` assertion claim,
so the private DreamUP verifier and worker claim schema do not change. A cookie
request that supplies a one-shot token uses the strict consumption path and
cannot downgrade to the durable proof after a missing, reused or invalid token.

### Single-use grants and idempotency

High-risk verification creates a cryptographically random bearer and an
independent random stable grant ID for native and upgraded cookie clients.
Redis locates the grant by bearer hash and stores exact user, session, fixed
action, target, the account-wide
`users.security_epoch`, administrator challenge credential version, and grant
ID. The account epoch is read with a row lock inside the same serializable
PostgreSQL unit of work as the durable proof and receipt; it is never copied
from `admin_challenges.security_epoch`. Atomic consumption returns those stable fields once;
the compatibility API consumes and discards them. Downstream callers must
re-read authoritative challenge/security state and require exact equality
before signing or performing a protected operation. Neither bearer nor grant
ID is derived from the other, and neither is logged.

Enroll, verify, and rotate require a globally random `Idempotency-Key`; rotate
also requires a strong quoted `If-Match` row version. The operation fingerprint
is a purpose-separated HMAC over the complete normalized semantic input,
including answers and the privacy client fingerprint. PostgreSQL persists only
the keyed digest. Same key and input return an allowlisted non-sensitive
receipt; different input conflicts. A successful verify replay never returns
or mints another bearer.

Grant creation occurs before the enclosing PostgreSQL verification unit of
work commits. A Redis creation failure therefore rolls back the step-up row,
audit and receipt, so the exact idempotency key can safely retry. If Redis
succeeds but PostgreSQL later fails, the caller never receives the raw bearer;
only an unreachable hashed grant remains until its short TTL expires.

DreamUP BFF targets are canonical JSON tuples of the form
`["dreamup-admin-target/v1", eventId, resourceKind, resourceId]`. Event-scoped
operations use `event` and repeat the event ID as the resource ID. Object
operations include both the event and object identifier, so equal application
or contact-submission IDs in different events cannot share a grant. The BFF
derives this tuple from its matched route; it never trusts a client-supplied
path or resource projection. The verification endpoint accepts the same
canonical high-risk capability set used by delegation signing and rejects
non-canonical JSON, a different event, extra tuple members, unsafe identifiers
or an action/resource-kind mismatch before rate limiting or answer hashing.
Legacy `dreamup.admin.*` grants retain their original direct-consumer target
contracts and cannot be substituted for a BFF capability grant.

### Atomic rotation and reason consumption

Rotation proves the old answer and uses one serializable PostgreSQL unit of
work to compare the row version, replace encrypted question/hash material,
increment the administrator challenge credential and local revocation generations, revoke persisted
freshness and operator approvals, append the typed audit, enqueue the Redis
purge, and terminalize the allowlisted receipt. Any failure rolls the entire
unit back. The incremented challenge version denies stale administrator grants
before physical purge completes; password and other account-epoch-advancing changes independently advance
`users.security_epoch` and invalidate every old grant by exact equality.

A role mutation consumes its one-use protected reason in the same unit of work
with an exact compare-and-set over reason ID, actor owner, operation kind,
`consumed_at IS NULL`, and `terminal_at IS NULL`. An opaque reason ID alone is
never authority; mismatched, reused, or terminal reasons roll back the role,
audit, and receipt together.

## Alternatives Considered

- Rely only on provider MFA. Rejected because it cannot bind a fresh proof to
  one DreamUP administrator session, action, target, and credential version.
- Store the challenge answer with reversible encryption or a fast digest.
  Rejected because a database or encryption-key disclosure would make offline
  guessing substantially cheaper and would expose recoverable answer material.
- Treat Redis as the authorization authority. Rejected because purge delivery
  can be delayed; PostgreSQL security and credential generations must deny
  stale material at the commit boundary.
- Reuse the browser-session or audit key material. Rejected because key reuse
  couples unrelated compromise domains and weakens purpose separation.

## Security Considerations

- Offline answer guessing: Argon2id, independent pepper custody, bounded work.
- Unicode ambiguity: NFKC, UAX #29 limits, forbidden invisible/control code points.
- Cross-purpose ciphertext/key reuse: purpose AAD and distinct complete keyrings.
- Retry/replay: keyed semantic fingerprints and terminal allowlisted receipts.
- Lost verify response: receipt replay has no bearer; a new key requires a new proof.
- Client/IP rotation and shared-client spraying: independent atomic rate buckets.
- Redis outage or stale cache: fail closed before Argon2; PostgreSQL security epoch is authoritative.
- Transport downgrade: native bearer requests always require a one-shot grant;
  ambiguous transport markers and rejected supplied tokens never reach the
  cookie compatibility fallback.
- Legacy cookie replay scope: the fallback remains bound to one server-side
  browser session and is capped at five minutes even though the ordinary
  durable dashboard proof lives longer. Password and other account-security
  changes invalidate it immediately through the authoritative epoch match.
- Concurrent verification: transactional replacement of the active session proof.
- Concurrent rotation: strong `If-Match`, row CAS, and serializable unit of work.
- Reason-ID substitution: owner/kind/unused CAS in the owning mutation transaction.
- Secret disclosure: no PHC, salt, pepper ID, answer, bearer, raw rate key, or encrypted metadata in browser DTOs, receipts, logs, or audits.

## Consequences

The extra local factor adds operational key custody and Redis availability to
administrator proof flows. This is intentional: unavailable security
dependencies deny sensitive operations instead of silently weakening them.
Old encryption and pepper keys must remain readable until all corresponding
records rotate or expire. Physical Redis purge is asynchronous, but generation
checks make revocation effective at the PostgreSQL commit boundary.

## Implementation Notes

The domain package owns narrow ports for challenge mutation, protected-reason
consumption, hashing, rate limiting, and idempotency. PostgreSQL and Redis
adapters implement those ports so the domain does not depend on infrastructure
packages. PostgreSQL mutations use serializable transactions and exact
compare-and-set predicates; the Redis limiter and grant consumer use atomic Lua
scripts. Compile-time adapter assertions and rollback tests protect the unit of
work boundary.

The default-off bootstrap branch is evaluated before keyring loading or route
registration. Enabled deployments must provide separate immutable keyring
files with restrictive host permissions. Retired read keys remain present but
disabled for writes until all dependent rows have rotated or expired.

## Follow-up

- Add the Redis purge worker and operational dashboards before enabling the
  feature in a production environment.
- Exercise the PostgreSQL and Redis integration suites against the isolated CI
  services, including concurrent rotation and retry scenarios.
- Document key ceremony, retained-key retirement, alert thresholds, and
  emergency disable procedures in the operator runbook.
- Reassess Argon2id parameters on the production hardware before first enable
  and during the regular security review cycle.
