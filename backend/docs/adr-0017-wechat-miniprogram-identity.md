# ADR-0017: WeChat Mini Program identity and QR-assisted United Pass sign-in

- Status: Proposed — local isolation branch only
- Date: 2026-08-24

## Context

DreamUP needs a WeChat Mini Program that shares the existing United Pass
identity and DreamUP business data. The application must support WeChat
authorization, verified WeChat phone number collection, a mandatory WeChat
binding during Mini Program registration, and a Mini Program-assisted QR sign
in for United Pass.

The existing public registration flow (ADR-0016) proves email ownership and
creates a ZITADEL password identity. It cannot be reused as a Mini Program
registration endpoint: it has no WeChat proof, its browser Origin rule is
intentionally strict, and allowing a client to send an `openId`, `unionId`, or
phone number would permit identity forgery.

## Decision

### Identity proof

Only the server-side WeChat adapter may exchange a short-lived code with
WeChat. The Mini Program may submit only a one-time `code` from `wx.login` or
`getPhoneNumber`; it must never submit `openId`, `unionId`, `session_key`,
phone number plaintext, or any WeChat application secret.

The adapter validates the response shape, requires a non-empty stable subject
(`unionId` when supplied, otherwise the app-scoped `openId`), and never logs
codes, session keys, open IDs, union IDs, phone numbers, or WeChat error
payloads. `session_key` is used only in-process to call the phone endpoint and
is discarded before any repository, session, audit, or error operation.

### Explicit binding model

WeChat is represented as a dedicated external-identity provider, not as an
email or phone match:

```text
identity_links
  provider             = provider_wechat_miniprogram
  provider_tenant_id   = configured Mini Program app ID
  provider_subject     = union ID, or app-scoped open ID
```

The existing unique provider-subject constraint remains the single-winner
binding guard. A verified WeChat phone can be written only after the
authenticated user's own bound WeChat subject has successfully completed a
fresh code exchange; it cannot select or merge another United Pass account.
No automatic linking by email, display name, or phone is allowed.

### Registration invariant

A Mini Program registration must reach this state atomically before any
account is active:

```text
stable United Pass user
  + verified WeChat identity link
  + verified WeChat phone
  + consumer persona
  + provider-owned credential identity
```

The existing ZITADEL registration flow and the new WeChat proof must be
coordinated by a dedicated onboarding use case. A partial reservation remains
`pending` and cannot establish a session. Compensation and reconciliation are
mandatory for every cross-system failure; no endpoint may quietly fall back to
the password-only public registration route.

### Sessions and QR approval

United Pass retains the existing opaque, server-side session model. A WeChat
result may only establish a session after a completed binding resolves to an
active United Pass account. Provider credentials are never returned to the
Mini Program.

QR sign-in uses an opaque, short-lived, single-use server record. A trusted
browser creates the record and displays only its random public identifier;
the browser separately receives an HttpOnly receiver secret. The Mini Program
scans the identifier, requires a current authenticated United Pass session and
CSRF proof, then submits an approval. A browser POST with the receiver secret
consumes the approval once to create a normal browser session. Redis stores
only hashes of the challenge and receiver secret. QR approval never transfers
a Mini Program session token to the browser.

DreamUP participant assertions use a dedicated Ed25519 delegation keyring.
The API publishes only its public verification material at
`GET/HEAD /.well-known/dreamup-mobile-jwks.json`; that route, keyring path and
current KID must remain distinct from DreamUP administrator delegation. The
public proxy must expose this exact well-known route whenever the mobile
bridge is enabled.

### Transport, rate limits and audit

- Production WeChat endpoints require HTTPS and an explicitly configured app
  ID and secret; they remain unmounted when configuration is incomplete.
- Every code exchange gets a dedicated per-IP and hashed-code rate-limit
  namespace and fails closed when Redis is unavailable. QR challenge creation
  has its own per-IP Redis namespace, configurable bound and fail-closed
  behavior; it never consumes the password-login limiter. The browser page
  renders only the opaque challenge identifier as a QR code and polls the
  receiver-proof consume route using the HttpOnly cookie. QR approval
  requests, receiver-proof success and receiver-proof rejection are written
  to the durable security ledger with only a one-way challenge correlation
  value; a successful receiver proof cannot create a browser session if that
  audit write fails. This remains a local-isolation design until an external
  production review approves it.
- State-changing endpoints require the same authenticated-session and CSRF
  policy as existing United Pass endpoints once a session exists.
- Identity binding, QR approval and terminal failure classes receive safe,
  non-secret audit events. Raw code/identity/contact data never enters audit
  payloads.

## Non-goals

- This ADR does not implement a custom OAuth/OIDC authorization server.
- It does not make the WeChat app secret or session key available to clients.
- It does not alter production configuration or deploy a provider.
- It does not authorize DreamUP administration based on a Mini Program UI
  flag; existing capability checks remain authoritative.

## Required implementation gates

1. Add a machine-readable API contract and negative HTTP tests first.
2. Add a migration only after the smallest durable binding/QR state is
   specified; it must be additive and reversible.
3. Implement a fake WeChat adapter for isolated tests and a hardened HTTP
   adapter for the real platform.
4. Prove code replay, cross-account linking, missing-phone registration,
   expired/duplicate QR approval, CSRF, rate-limit, logging and migration
   failure cases fail closed.
5. Perform a production design review before enabling any non-local config.
