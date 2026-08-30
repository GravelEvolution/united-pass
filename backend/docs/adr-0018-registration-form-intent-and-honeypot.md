# ADR-0018: Registration form intent and high-confidence honeypot handling

- Status: Accepted
- Date: 2026-08-25

## Context

The public registration endpoint previously accepted a valid-looking JSON body
without proving that the caller had first loaded the registration form. A DOM
honeypot by itself would only catch unsophisticated autofill: a direct API
client could omit it. Treating a missing field as an attack would also punish
people using a cached frontend during a coordinated release.

Temporary-mail providers rotate mailbox domains, so a static domain denylist
also failed when a new domain continued to use the same provider-operated MX.

## Decision

Before submitting a registration, the browser obtains a short-lived, opaque,
single-use form-intent token. Redis stores only the token digest and binds it to
digests of the user agent, the trusted client network, and the optional
server-issued `up_risk_device` cookie. A token has a small minimum age and a
bounded lifetime. Consumption is atomic, so it cannot be replayed.

Device binding is conditional on what existed when the intent was issued. If
the intent already contains a device digest, any replacement is rejected. If
it was issued before the browser had a device cookie, the one automatic retry
after risk step-up may carry the first server-issued device cookie; user-agent
and trusted-network binding remain strict throughout that transition.

Intent issuance has its own atomic Redis budget keyed by the trusted client
network digest: 20 issues per five minutes. This budget is intentionally
separate from account creation, email, verification, and resend budgets so a
person may refresh a stale form without consuming scarce create attempts.
Exhaustion returns 429 with `Retry-After`; Redis failure denies issuance.
If a configured trusted proxy omits its validated client-IP assertion, intent
issuance fails closed instead of silently assigning every visitor to the
proxy's shared 20-request bucket.

Every new registration request must include both `formIntentToken` and
`automationBrief`. The legitimate browser always submits `automationBrief` as
an empty string. Missing fields and invalid, expired, too-young, or replayed
intents return a recoverable HTTP 422 response that asks the browser to refresh
its form intent. They are not recorded as high-confidence abuse and do not
create a block.

A non-empty or oversized `automationBrief` is a high-confidence honeypot hit.
The request never reaches account provisioning. After a small bounded delay,
the endpoint returns the same verification-required shape with a decoy token,
so callers cannot cheaply tune themselves against the trap. The server writes
a durable security event containing only digests and safe reason codes.

Blocks are timed and reversible. A server-issued device dimension is blocked
immediately after a high-confidence hit and automatically expires after 24
hours. An unverified email from the request body is never a honeypot block or
audit-target dimension: otherwise an attacker could frame any third party.
Email still has its independent create-rate and disposable-provider policies.
The trusted client IP is not
permanently blocked on one event: strikes escalate to a short block and then a
longer block only after repeated hits. Only the client identity produced by the
trusted-proxy middleware is eligible; caller-supplied forwarding headers are
never trusted directly. If a configured proxy omits or corrupts its overwritten
client-IP assertion, the shared proxy address is explicitly ineligible for IP
strikes, while an existing server-issued device control remains active.

False-positive recovery uses a dedicated administrator endpoint behind the
existing United Pass session and CSRF middleware. The handler additionally
requires an active system-scoped `super_admin` or `top_admin` binding, an
active account, and a principal that is not offboarding. The existing
authoritative permission resolver must also grant both `policy.manage` and
`audit.read`, so a Cerbos deny remains authoritative. This paired capability
check is an internal compatibility bridge until a dedicated
`system.registration_defense.manage` action is introduced. Every mutation also
consumes a single-use `registration.abuse.unblock` reauthentication grant bound
to `<dimension>_<sha256>`. A dedicated Redis budget limits attempts per hashed
administrator identity independently from login and reauthentication budgets.

The request accepts exactly one fixed dimension (`ip` or `device`) and requires
an explicit value encoding. Raw IP values are canonicalized with `netip` and
hashed at the HTTP boundary. A raw device value must be an exact server-issued
256-bit base64url token and is also hashed at the boundary. Because the device
cookie is HttpOnly, an operator may instead submit the exact 64-character
lowercase SHA-256 digest already stored in the abuse audit; digest encoding is
never accepted for IP. Only the validated digest and typed dimension reach
Redis. Redis key prefixes are private to the adapter, so the endpoint cannot be
turned into an arbitrary key deletion primitive. A fixed reason code and
encoding are durably audited before the mutation. Audit target IDs use a
purpose-separated HMAC derived from the server secret; the raw fingerprint and
the enumerable plain SHA-256 of an IPv4 address never enter the audit store.
The terminal success or failure is audited separately. If the pre-mutation
audit is unavailable, recovery fails closed. The pre-mutation `requested`
event is the authoritative command record (actor, target pseudonym and reason),
not a claim that Redis changed. If the idempotent Redis deletion succeeds but
the terminal audit cannot be persisted, the API returns 500 so an operator can
safely retry and complete the outcome trail.

Temporary-email enforcement combines normalized domain checks with MX
operator suffix checks. This blocks rotating domains that continue to deliver
through Mail.tm-operated MX hosts while keeping the policy maintainable.
The composition root injects the same cached delivery validator into both
public registration and the account-email-change flow. Email change validates
before the identity provider sets the pending email or sends a message; a
definitive rejection is invalid input and a transient DNS failure fails closed
as temporarily unavailable. It is deliberately not queried again after the
identity provider verifies the address: a post-verification DNS outage must not
leave the provider's verified address split from the local account mirror.
Phone changes do not use this policy.

The interactive CAPTCHA boundary additionally supports a server-selected
provider pool. Provider identity is stored inside the server challenge; the
client submits only the challenge ID and opaque proof and cannot select or
switch providers. An empty or temporarily unavailable pool safely falls back
to a stronger, satisfiable automation-cost challenge; it never emits an
interactive challenge that the client cannot complete.

This revision supplies two opt-in adapters. Cloudflare Turnstile is eligible
only in the `global` pool. Its verifier uses the fixed Siteverify endpoint and
requires HTTP 200, `success`, exact hostname, server-issued action and cdata,
fresh timestamp, and no error codes. Google reCAPTCHA v3 uses only the fixed
`recaptcha.net` endpoint and requires HTTP 200, `success`, exact hostname,
the unique server-issued action, fresh timestamp, configured minimum score,
and no error codes. A success response carrying a quota warning is rejected.
Both adapters use bounded timeouts and response bodies, reject redirects, and
open a short circuit after transport or provider-configuration failures.

Provider configuration is atomic: incomplete site-key, server-secret, or
exact-hostname tuples fail startup validation and no secrets enter the public
challenge. `recaptcha.net` is a best-effort fixed-host fallback in the
`mainland_china` pool, not an availability guarantee. Turnstile is excluded
there because Cloudflare does not support it in Mainland China. Alibaba Cloud
CAPTCHA 2.0 is not implemented in this revision; a production-grade mainland
pool still requires its official signed verifier and browser integration.

## Alternatives Considered

- Static honeypot only: rejected because direct API clients can omit it.
- Treat missing fields as an attack: rejected because cached clients and
  partially rolled-out releases would be falsely blocked.
- Permanent IP block on the first hit: rejected because NAT, mobile carriers,
  schools, and offices share public addresses.
- Static temporary-mail domain list only: rejected because mailbox domains
  rotate faster than deployments.
- Let the browser choose a CAPTCHA provider: rejected because it permits
  downgrade and provider-switch attacks.

## Consequences

- Normal login is unchanged; the form-intent contract applies only to public
  registration.
- A disposable domain cannot be introduced later through account email
  change, and a DNS outage prevents the change before any provider side effect.
- Registration API clients must first issue and then consume a form intent and
  must explicitly send an empty honeypot field.
- A coordinated frontend/backend release is required. Cached clients recover
  with 422 rather than being classified as attackers.
- Redis receives short-lived intent, strike, and block keys; no raw email,
  address, user agent, device ID, or token is used as a key.
- Repeated intent rendering cannot create unbounded 20-minute Redis keys from
  one network; the separate five-minute issuance counter fails closed.
- Vendor-specific interactive verification is enabled only for a reviewed
  adapter with a complete credential/hostname tuple. Provider verification
  failures never become a client-side success.
- False-positive block recovery is restricted to active system administrators,
  accepts no Redis key, permits an audited digest only for the device dimension,
  and records no raw IP or device token in its durable audit events.

## Implementation Notes

- Domain policy: `internal/registration/email_policy.go`
- MX operator policy: `internal/registration/email_delivery_policy.go`
- Email-change policy port: `internal/accountcontact/service.go`
- Intent and abuse policy: `internal/registration/form_defense.go`
- Redis atomic storage: `internal/adapters/redis/registration_form_defense.go`
- HTTP boundary: `internal/adapters/httpapi/registration_handlers.go`
- Durable audit wiring: `internal/bootstrap/server.go`
- Audited recovery API: `internal/adapters/httpapi/registration_block_handlers.go`
- Provider selection seam: `internal/riskdefense/provider_pool.go`
- Provider adapters: `internal/adapters/captcha/providers.go`
- Provider configuration/bootstrap: `internal/config/config.go`,
  `internal/bootstrap/risk_captcha.go`
- Contract: `openapi/openapi.yaml`

## Follow-up

- Replace the temporary `policy.manage + audit.read` compatibility bridge with
  a dedicated `system.registration_defense.manage` Cerbos action and policy
  after the frozen capability contract is versioned for it.
- Add Alibaba Cloud CAPTCHA 2.0 through the official ACS3-signed
  `VerifyIntelligentCaptcha` contract and V3 browser SDK. Require
  `VerifyResult=true`, `VerifyCode=T001`, exact scene/certify binding, and
  explicitly reject test result `T005` before declaring the mainland pool
  production-ready.
