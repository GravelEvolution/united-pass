# ADR-0020: WeChat Mini Program onboarding and existing-account linking

- Status: Accepted — production rollout authorized after verified pre-change backup
- Date: 2026-08-28
- Last amended: 2026-09-01 — verified phone made mandatory; identity-only session route removed
- Owners: United Pass backend team

## Context

DreamUP exposes one WeChat sign-in action. The same action must carry a fresh
WeChat phone authorization. Rejecting, omitting or failing that proof must not
fall back to an identity-only account or session. A first-time WeChat identity must complete the
United Pass email, password and account fields before receiving normal access.
If the email already belongs to an account, that account's current password and
registered MFA must be verified before the WeChat identity is attached.
Existing account data remains authoritative.

The legacy identity-only `/auth/wechat/sessions` contract is removed from route
composition and OpenAPI because it could mint a bearer from `wx.login` alone.
The legacy WeChat registration route and the onboarding route both require a
phone proof. The new behavior remains isolated under dedicated, default-off
onboarding routes and token types.

## Decision

### One action and server-derived identity

The Mini Program uses one `getPhoneNumber` callback and obtains a fresh
`wx.login` code in that callback. It sends both one-time codes. It never sends an OpenID, UnionID, plaintext
phone, `session_key` or Mini Program secret.

The server exchanges `wx.login` first and derives the AppID-scoped subject. A
missing, rejected, malformed or consumed phone code fails closed with
`wechat.phone_required`; provider transport/server failures remain
`provider.unavailable`. Neither outcome creates an account, challenge or
session. A returned mainland local number is canonicalized through the same
`+86` normalization as the SMS verification path. The WeChat consent surface is
not hidden or bypassed.

An active account with the same explicit WeChat link receives the ordinary Mini
Program session response only after the transaction re-checks that link and
adds an empty phone, verifies the identical legacy phone, or confirms the
identical verified phone. A different phone or phone owned by another account
returns `wechat.phone_conflict`; no automatic merge occurs. An unlinked subject receives only an opaque,
single-use onboarding challenge; it receives no account or business session.
If the exact subject is linked to an unverified pending reservation left by a
prior provider or token-store interruption, the challenge is bound to that
pending user and may reconcile only that reservation.

Every strict WeChat native session is stamped with the server-only
`wechat_phone_verified` authentication assurance. Native Mini Program records
whose provider is `wechat` but which lack that marker are pre-cutover
identity-only sessions; session promotion deletes and rejects them. This makes
the policy effective immediately without scanning Redis or migrating records.

### Restricted challenge storage and abandoned-session cleanup

The service stores onboarding challenges for 15 minutes and MFA challenges for
five minutes. Redis keys contain only a SHA-256 token hash. The subject,
verified phone, purpose, token binding and creation time are stored
together in an AEAD-encrypted payload. A dedicated 32-byte onboarding key and
key identifier are required whenever the route is enabled; startup rejects
missing, malformed or session-key-equivalent material. The store rejects
unknown, wrong-purpose, moved or malformed ciphertext. Raw WeChat codes and raw
challenge tokens are never persisted.

Challenge claim, release, consume and attempt operations are atomic. The token
is accepted only by the onboarding completion route; a separate token is used
for onboarding MFA. Neither token is accepted by current-account, DreamUP, QR,
administrator or general account-management middleware.

Browser sessions produced by QR handoff are versioned at the same cutover.
New handoffs use provider stamp `wechat_miniprogram_qr_v2`; both required and
optional session promotion delete the legacy `wechat_miniprogram_qr` cookie
record because it may have been approved by a pre-cutover identity-only bearer.
The QR v2 stamp is a generic handoff version, not a phone assurance: password-
authenticated Mini Program sessions can continue approving new challenges.

An MFA challenge atomically creates a separately encrypted provider-session
cleanup obligation and a due-time index. Successful provider authentication
uses a short promotion lease: only durable local-session creation removes the
obligation. A failed or crashed promotion becomes due, and an HA-safe leased
worker revokes the abandoned provider session with bounded retry. Redis never
stores the provider session identifier in plaintext.

Onboarding encryption uses a current write key plus an explicit retained-read
keyring. A rotated key remains available for decryption until the due index and
cleanup-obligation namespace have both been proven empty after the maximum
retry horizon. Removing an old key while any obligation can still reference it
is a prohibited deployment operation; startup rejects duplicate key IDs,
duplicate key material and reuse of the ordinary session-encryption key.

### New and existing email branches

The server normalizes the supplied email and resolves zero or one authority
owner. Historical duplicate normalized owners fail closed. Phone and profile
data are never account selectors.

For a new email, the current new-account password policy is enforced and the
existing provider-registration and email-verification lifecycle creates a
pending account. The verified WeChat subject and verified phone are mandatory
at the service and repository boundaries. No code path may create a new
identity-only reservation.

For an existing email, the password is credential proof only. The provider user
is resolved from the existing account's stable United Pass user ID; the password
is never read from the database, set, changed or copied. A legacy password that
does not meet today's new-account policy can still prove its existing account.
Invalid credentials return `wechat.onboarding_email_password_mismatch`, which
the client renders exactly as:

```text
此邮箱已存在账号，请设定原始密码以进行绑定
```

This is an email-existence signal because the product-required wording is shown
before mailbox verification. The accepted residual privacy risk is bounded by
the claimed onboarding token/source-IP bucket, verified WeChat subject bucket,
opaque stable target-account bucket and the five-attempt challenge limit.

### Existing-account MFA and merge

Password success is not terminal when the account has MFA. The server retains
the provider session only in the encrypted MFA challenge, binds it to the target
user and verified WeChat proof, and requires one of the provider-advertised
methods. A returned user ID must equal the bound target before settlement.

Authority settlement runs in a serializable transaction with deterministic
advisory locks for the target user, WeChat subject and verified phone. It
re-reads the active target and compares the exact pre-authentication normalized
email, authority version and security epoch. The mutation allowlist is:

- insert the explicit WeChat identity link if absent;
- add a verified phone only when the target is empty, or mark the exact same
  legacy phone verified; an identical verified phone is a no-op;
- increment `version` and `security_epoch` when link or phone state changes.

A different phone, a phone owned by another user, a subject linked elsewhere,
multiple links, a disabled target or a concurrent winner fails closed. The
transaction never updates email, display name, avatar, status, persona,
workforce data, roles, permissions or administrator bindings. After settlement
the Mini Program reloads `/me`; it does not push provisional profile fields.

### Limits, idempotency, audit and notification

Onboarding start reuses the WeChat login limiter. Completion and MFA first
require a valid claimed token, then apply independent credential buckets for
the source IP/token and a digest of the verified AppID/subject. Existing-account
password and MFA verification additionally share an opaque stable user-ID
bucket across subjects, email spellings and source addresses, and each
onboarding challenge permits at most five credential attempts. Existing-account
password/MFA attempts never consume public account-creation budgets. After a
unique-email lookup selects the genuinely new-account branch, the server first
validates the complete new-account profile and password policy and only then
advances the ordinary registration IP, network, normalized-email and IP/email
buckets. Invalid tokens, existing-account credential attempts, incomplete
profiles and weak new-account passwords therefore cannot exhaust a victim's
public creation budget. Exact pending-reservation recovery does not use the
stable target-account credential bucket or five-attempt password loop; it is
instead restricted to the encrypted target user, exact verified WeChat subject
and the client/token plus subject limits.

The compatible `/registrations/wechat` route uses a separate atomic source-IP
gate plus global one-time login-code and phone-code claims before any provider
exchange. The source-IP counter is advanced first; an over-budget source never
creates attacker-selected per-code keys. Only after WeChat verifies both proofs
does the route advance the ordinary registration IP, network,
normalized-email and IP/email buckets and call the proof-only `CreateVerified`
path. Random format-valid codes therefore cannot touch a victim email bucket.

New-account retries use the isolated operational-PostgreSQL provider-intent
store and deterministic ZITADEL user ID. An exact pending subject may reconcile
only that reservation. Historical phone-empty challenges left in Redis are
consumed and rejected before email lookup, password verification or MFA; they
cannot be used after cutover. When a fresh proof repairs an earlier durable
identity-only pending reservation created by an older release, the phone write advances both `version` and
`security_epoch` and appends a separate `wechat.pending_phone_verified` audit
and notification intent derived from the pre-write revisions; replaying the
original `wechat.pending_reserved` effect cannot absorb it. No authority
migration or new authority table is used.

Every successful authority mutation appends a deterministic security event and
notification intent in the same transaction. The append-only outbox resolves a
verified destination only in worker memory and uses a deterministic notification
identifier and RFC Message-ID. SMTP delivery remains at-least-once: a relay that
does not honor the idempotency header may deliver a duplicate after a process
crash between provider acceptance and the terminal outbox event. The onboarding
gate fails startup validation unless a bounded SMTP endpoint, port and sender
address are configured, so production cannot accept durable notification
intents with no delivery worker.

## Production authorization and rollback boundary

The product owner explicitly authorized this onboarding rollout to perform the
following narrowly scoped production effects:

- create the minimum pending authority rows and ZITADEL identity for a new
  account, followed by the existing email-verification activation lifecycle;
- add an explicit WeChat link to a password/MFA-verified existing account;
- conditionally add or verify the exact WeChat-proven phone and advance that
  account's version/security epoch;
- append the same-transaction audit and notification-outbox facts.

No authority schema migration is introduced. The independent
`UP_WECHAT_MINIPROGRAM_ONBOARDING_ENABLED` gate is the immediate kill switch;
the older WeChat flags do not mount these routes by themselves. Before
enablement, physical and logical backups of both PostgreSQL clusters, runtime
configuration and the current API release were created, copied off-host and
checksum-verified.

The QR cutover must also drain pre-version handoffs: stop creating/approving QR
challenges, wait at least the configured maximum QR challenge TTL (or delete
only the dedicated QR challenge namespace), deploy the provider-v2 session
stamp and legacy-session gates, then reopen QR traffic. Otherwise a challenge
approved by a pre-cutover identity-only bearer could be consumed after deploy
and incorrectly receive the v2 stamp.

Ordinary rollback disables the feature and restores the prior binary. It does
not erase valid user-authorized links. The database backup is disaster recovery,
not a routine rollback tool.

## Accepted residual constraints

- The exact existing-email mismatch wording is an email-existence signal after
  a verified and heavily rate-limited WeChat challenge.
- The current Mini Program UI completes TOTP only. Passkey-only and
  recovery-code-only accounts fail closed and must use the browser account path
  before binding; no weaker fallback is attempted.

## Consequences

- Phone denial or provider failure blocks WeChat onboarding and creates no
  identity-only fallback account or session.
- A provisional identity cannot access DreamUP or United Pass business
  functions before account completion.
- Existing-account password, MFA and profile data are preserved.
- The legacy identity-only WeChat login route is intentionally removed; the
  legacy verified-phone account-management route remains available.
- Pre-cutover identity-only native bearers and QR browser sessions are rejected
  by assurance/provider-version gates on first use, without a Redis scan.
- Successful authority changes are idempotent, auditable and recoverable
  without broad writes to existing account data.
