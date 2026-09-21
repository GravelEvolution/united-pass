# WeChat Mini Program onboarding production acceptance

- Review date: 2026-08-29
- Scope: United Pass API onboarding, ZITADEL integration, DreamUP Mini Program client handoff
- Production boundary: no authority or operational schema migration; no DreamUP or United Pass web deployment
- Required outcome: P0 = 0, P1 = 0, P2 < 3

> Security addendum (2026-09-01): this acceptance record is amended to require
> a fresh verified phone. ADR-0020 removes the `wx.login`-only session route and
> rejects legacy phone-empty challenges before any account or session path.

## Decision

The candidate is acceptable for a gated production rollout after a fresh,
checksum-verified pre-cutover backup. The onboarding route remains independently
controlled by `UP_WECHAT_MINIPROGRAM_ONBOARDING_ENABLED`. It may create a
pending authority identity and ZITADEL user for a new account, or add the
explicit WeChat link and mandatory verified phone to an existing account only
after password and provider MFA verification. It introduces no database DDL.

Cutover prerequisite: pause new QR challenges and approvals, drain the maximum
QR challenge TTL (or clear only that dedicated namespace), then deploy and
reopen QR traffic. This prevents a pre-cutover approval from being consumed as
a version-2 QR browser session.

Final pre-cutover finding count:

- P0: 0
- P1: 0
- P2: 1 accepted, bounded privacy signal described below

## Review rounds

### 1. Change-scope and migration review

Compared the complete Git worktree and separately inspected `migrations/` and
`isolated-migrations/`. No migration file, module dependency, DreamUP service,
or United Pass web file changed. The rollout is restricted to the API binary,
one feature environment file, and the Mini Program package.

### 2. HTTP and OpenAPI contract review

Reviewed the onboarding start, completion, MFA and session response contracts,
stable error mapping, request limits and legacy-route isolation. Contract tests
cover malformed input, missing or replayed challenges, mismatch wording, MFA,
and non-mounted routes while the independent feature gate is disabled.

### 3. WeChat proof-boundary review

Confirmed the client sends only fresh `wx.login` and mandatory phone codes. The
server derives AppID-scoped identity through the WeChat server API; OpenID,
UnionID, phone number, `session_key`, and Mini Program secret are not accepted
as client assertions. Phone denial or malformed/consumed proof creates no
account, challenge or session; infrastructure failures remain provider
unavailable rather than being misreported as consent denial.

### 4. New-account and ZITADEL lifecycle review

Confirmed a new email uses the existing password policy, provider-registration
and email-verification lifecycle. The reservation uses a deterministic provider
intent and can reconcile only the same pending WeChat subject. No normal
business session is returned before completion of the required lifecycle.

### 5. Existing-account authentication review

Confirmed account selection is by normalized email only, while password proof
is addressed to the resolved stable user ID. The submitted password is never
copied, changed, or read from PostgreSQL. Existing profile, email, roles,
persona, avatar and workforce information remain authoritative and unchanged.

### 6. Provider MFA and abandoned-session review

Confirmed provider MFA state is stored only in a dedicated encrypted challenge.
Cleanup obligations use AEAD, an indexed due queue, HA-safe claims, bounded
retry and a two-phase promotion lease. A local-session or promotion failure
revokes the provider session; ZITADEL `NotFound` is treated as idempotent
revocation while authorization and transport failures remain errors.

### 7. Challenge cryptography and key-rotation review

Confirmed Redis keys contain only token hashes and encrypted payloads bind
purpose, kind and token hash. Production startup requires a distinct 32-byte
current key and key ID, rejects session-key reuse and malformed or duplicate
retained keys, and preserves old decryption keys for the cleanup horizon.

### 8. PostgreSQL concurrency and mutation-allowlist review

Confirmed existing-account settlement uses a serializable transaction,
deterministic advisory locks, exact version/security-epoch comparisons and
conflict checks. The mutation allowlist is limited to the explicit WeChat link,
mandatory exact verified phone, and corresponding version/security-epoch
increments. Competing identity or phone ownership fails closed.

### 9. Audit, notification and partial-effect review

Confirmed every successful authority mutation appends deterministic audit and
notification facts in the same transaction. Pending-phone reconciliation has a
separate idempotent effect and cannot be absorbed by a replayed reservation.
The worker resolves email only in memory, avoids PII logs, uses deterministic
message identifiers, and production startup fails closed without usable SMTP.

### 10. Abuse-control and privacy review

Confirmed completion rate limiting runs only after possession and atomic claim
of a valid onboarding challenge. Independent IP, network, email, subject, token
and stable target-user buckets plus a five-attempt ceiling bound password and
MFA guessing. Invalid arbitrary tokens cannot exhaust a victim email bucket.

### 11. DreamUP administrator one-shot grant review

Confirmed all 14 high-risk operations require action-and-canonical-target-bound
single-use grants for native Mini Program requests. Target tuples reject
cross-event IDs, unexpected fields, unsafe resource kinds and action/kind
mismatches. The shared permissions package owns the delegated and high-risk
action sets to prevent signer/consumer drift.

### 12. Legacy browser compatibility review

Confirmed the existing DreamUP cookie transport remains compatible without a
DreamUP deployment. Its no-header fallback is restricted to the same browser
session and user, a provider-backed login and durable proof no older than five
minutes, the current challenge version and exact current account security
epoch. Any supplied invalid one-shot token fails and cannot downgrade to the
fallback. Native/bearer transport never receives this compatibility path.

### 13. Security-question enrollment and Mini Program handoff review

Confirmed first enrollment without existing MFA is allowed only for the first
active system `super_admin` or `top_admin` with no existing challenge and a
fresh provider-backed login. Event administrators, ordinary users, stale
logins, missing bindings and existing challenges fail closed. A provider-backed
session that cannot prove freshness returns `session.reauthentication_required`;
the Mini Program routes the administrator to password reauthentication and
rechecks enrollment after return instead of looping.

### 14. Mini Program client, rendering and package review

The Mini Program completed TypeScript checking, 173 contract tests, security
verification, 18 template checks, package verification and release preflight.
The release artifact is generated from Git source, excludes local secret
configuration, and remains within the main-package and subpackage limits.

### 15. Repetition and static-analysis review

The following final checks passed on the shared candidate tree:

```text
go test ./... -count=1
go vet ./...
go build ./...
go test -tags=integration -c ./internal/adapters/postgres -o NUL
go test -tags=integration -c ./internal/adapters/redis -o NUL
go vet -tags=integration ./...
go test ./internal/adminstepup ./internal/dreamupadmin \
  ./internal/dreamupdelegation ./internal/adapters/httpapi -count=20
gofmt -l <all changed Go files>
git diff --check
```

The integration-tag commands were compile/static checks only and did not
connect to production. Race instrumentation was unavailable in the Windows
build environment because no supported C compiler was installed; concurrency
behavior is instead covered by repeated deterministic unit tests and adapter
contract tests.

### 16. Backup, rollback and production-isolation review

The cutover requires fresh logical dumps of authority, ZITADEL and operational
PostgreSQL, globals, runtime configuration and the prior API release. The backup
must be copied off-host and both manifests verified before enablement. The only
permitted service restart is `moonstone-up-api.service`. Rollback restores the
prior API symlink and feature environment, without erasing valid user-authorized
links. DreamUP and United Pass web symlinks and service activation timestamps
must remain unchanged.

## Accepted residual finding

### P2-01: product-required existing-email signal

The exact required message `此邮箱已存在账号，请设定原始密码以进行绑定`
reveals that an email is registered. Exploitation requires a verified WeChat
subject and a valid short-lived claimed challenge, and is bounded by independent
source, token, subject and stable-target rate limits plus the challenge attempt
ceiling. The current flow deliberately reserves the normalized-email public
create budget for genuinely new accounts; ADR-0020 supersedes the older limiter
description recorded by this 2026-08-29 acceptance report. The existence signal
remains an explicit product decision and the sole accepted P2 finding.

The current Mini Program UI completes TOTP only for provider MFA. Passkey-only
and recovery-code-only accounts fail closed and must use the browser account
path before binding; this is a functional limitation, not an authorization
bypass. The five-minute legacy cookie compatibility path is likewise a
documented same-session step-up behavior with current-epoch invalidation, not a
native-client fallback.

## Release evidence

- Mini Program release ID: `dreamup-mini-20260829-r4`
- Mini Program source commit: `5706e1f742eb3e63123ed00cd93eae2a58ee6562`
- Mini Program source tree: `0883933af33530795bcc042afebcaa07ac65bd53`
- Main package: 1,543,607 bytes
- Partner subpackage: 1,069,195 bytes
- Total uploaded code: 2,612,802 bytes

Production backup identifiers, API release identity, post-cutover health,
schema versions and before/after row counts are recorded separately as cutover
evidence so this source-controlled preflight decision remains immutable.
