# ADR-0020: WeChat Mini Program onboarding and existing-account linking

- Status: Accepted — production rollout authorized after verified pre-change backup
- Date: 2026-08-28
- Owners: United Pass backend team

## Context

DreamUP exposes one WeChat sign-in action. The same action may carry a WeChat
phone authorization, but rejecting or failing that optional proof must not
create a second client flow. A first-time WeChat identity must complete the
United Pass email, password and account fields before receiving normal access.
If the email already belongs to an account, that account's current password and
registered MFA must be verified before the WeChat identity is attached.
Existing account data remains authoritative.

The legacy contracts stay unchanged: `/auth/wechat/sessions` restores only an
already-linked active account, and the legacy WeChat registration route still
requires a phone proof. The new behavior is isolated under dedicated,
default-off onboarding routes and token types.

## Decision

### One action and server-derived identity

The Mini Program uses one `getPhoneNumber` callback and obtains a fresh
`wx.login` code in that callback. It sends the one-time login code and, when
present, the one-time phone code. It never sends an OpenID, UnionID, plaintext
phone, `session_key` or Mini Program secret.

The server exchanges `wx.login` first and derives the AppID-scoped subject. A
missing, rejected, malformed, consumed or temporarily unavailable phone code is
represented as an empty optional phone while the verified WeChat subject
continues. A returned mainland local number is canonicalized through the same
`+86` normalization as the SMS verification path. The WeChat consent surface is
not hidden or bypassed.

An active account with the same explicit WeChat link receives the ordinary Mini
Program session response. An unlinked subject receives only an opaque,
single-use onboarding challenge; it receives no account or business session.
If the exact subject is linked to an unverified pending reservation left by a
prior provider or token-store interruption, the challenge is bound to that
pending user and may reconcile only that reservation.

### Restricted challenge storage and abandoned-session cleanup

The service stores onboarding challenges for 15 minutes and MFA challenges for
five minutes. Redis keys contain only a SHA-256 token hash. The subject,
optional verified phone, purpose, token binding and creation time are stored
together in an AEAD-encrypted payload. A dedicated 32-byte onboarding key and
key identifier are required whenever the route is enabled; startup rejects
missing, malformed or session-key-equivalent material. The store rejects
unknown, wrong-purpose, moved or malformed ciphertext. Raw WeChat codes and raw
challenge tokens are never persisted.

Challenge claim, release, consume and attempt operations are atomic. The token
is accepted only by the onboarding completion route; a separate token is used
for onboarding MFA. Neither token is accepted by current-account, DreamUP, QR,
administrator or general account-management middleware.

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
pending account. The verified WeChat subject is mandatory and the verified
phone is optional. This does not relax the old phone-required registration
endpoint.

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
the verified WeChat subject, source, token, normalized-email and stable
target-account rate buckets plus the five-attempt challenge limit.

### Existing-account MFA and merge

Password success is not terminal when the account has MFA. The server retains
the provider session only in the encrypted MFA challenge, binds it to the target
user and verified WeChat proof, and requires one of the provider-advertised
methods. A returned user ID must equal the bound target before settlement.

Authority settlement runs in a serializable transaction with deterministic
advisory locks for the target user, WeChat subject and optional phone. It
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
bucket across subjects, email spellings and source addresses. Completion also
applies the ordinary registration IP, network, normalized-email and IP/email
buckets only after claim, so forged invalid tokens cannot exhaust a victim
email bucket. A challenge permits at most five credential attempts.

New-account retries use the isolated operational-PostgreSQL provider-intent
store and deterministic ZITADEL user ID. An exact pending subject may reconcile
only that reservation. When a retry adds a verified phone to an earlier
identity-only reservation, the phone write advances both `version` and
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

- Phone denial does not block WeChat onboarding and creates no extra UI branch.
- A provisional identity cannot access DreamUP or United Pass business
  functions before account completion.
- Existing-account password, MFA and profile data are preserved.
- The legacy WeChat login and registration contracts remain compatible.
- Successful authority changes are idempotent, auditable and recoverable
  without broad writes to existing account data.
