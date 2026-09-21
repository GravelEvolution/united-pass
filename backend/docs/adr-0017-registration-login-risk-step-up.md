# ADR-0017: Objective registration and login risk step-up

- Status: Accepted
- Date: 2026-08-25

## Decision

United Pass keeps low-risk registration and password login responses unchanged.
The optional `UP_RISK_DEFENSE_ENABLED` gate observes only server-issued device
state, short-lived session/device trust, operation rates, challenge failures,
and replay state. It never scores names, display names, prose, writing style,
or other subjective content. Login does not use a client network signal.
Registration receives only the canonical network digest already produced by
the trusted-proxy/form-intent boundary; risk defense never parses a forwarded
header or accepts a browser-supplied address itself.

The browser receives a server-issued, HttpOnly `up_risk_device` cookie. Redis
counts attempts within that device namespace and stores no raw identifier:
identifiers, device IDs, challenge tokens, and trust tokens reach Redis only as
SHA-256 digests. An operator allowlist likewise accepts only normalized
identifier SHA-256 digests through `UP_RISK_ALLOWLIST_SHA256`. Operators form
the digest from the UTF-8 bytes of the identifier after trimming surrounding
space and lower-casing it, matching the HTTP boundary. Login rate or elapsed
time can never trigger step-up alone: medium login risk requires rate plus at
least one independent server-verifiable protocol, session, replay, or explicit
email-risk signal; high login risk requires two independent anomaly dimensions.
Public registration uses a narrower policy: every exact form-intent tuple must
complete the interactive image challenge before account creation. The tuple
binds the normalized email, form-intent token, Origin, server-issued device and
trusted client-network digest. Registration-to-verification speed, names and
prose are not classifiers.

Medium risk returns HTTP 403 using the canonical error envelope:

```json
{
  "error": {
    "code": "step_up_required",
    "message": "需要完成额外验证后继续。",
    "requestId": "req_…",
    "stepUp": {
      "challengeToken": "opaque-single-use-token",
      "level": "medium",
      "method": "automation_cost",
      "algorithm": "sha256_leading_zero_bits",
      "difficulty": 18,
      "expiresAt": "2026-08-25T10:05:00Z",
      "providerReady": true
    }
  }
}
```

`automation_cost` is only a computational anti-automation cost. It is not
CAPTCHA, proof of humanity, identity verification, or evidence about who wrote
any submitted text.

High risk uses the distinct `interactive_captcha` method. The provider seam is
`riskdefense.InteractiveVerifier`; the built-in `moonstone_image_digits`,
Turnstile and reCAPTCHA adapters implement `Begin` and `Verify` without letting
the browser select a provider. Login may fall back to stronger
`automation_cost` when every eligible provider is unavailable. Public browser
registration never takes that fallback: every exact form-intent tuple requires
the built-in interactive image provider and fails closed if it cannot begin.

The browser completes either challenge at `POST /api/v1/auth/step-up`. A
successful, atomically consumed challenge sets a short-lived HttpOnly
`up_device_trust` cookie, after which the browser retries the original request.
Every trust record is bound to both operation and identifier. Registration
trust is additionally bound through its composite identifier to the exact form
intent, normalized email and Origin; it cannot exempt a login or another
registration. Login trust cannot cross to a different login identifier.
An authentication session counts as trust only while its authentication time is
within the same short trust window. Challenge claims are single-winner, proofs
are rate limited, and consumed or expired challenges cannot be replayed.

Registration challenge issuance is also single-active per exact composite
identifier, device and trusted network. Redis elects one short-lived issuer
before the CAPTCHA provider is called; concurrent or repeated requests receive
HTTP 429 and cannot allocate another provider answer. The active ownership is
promoted atomically to the challenge TTL and released only by its owner on
failure or successful consume. Device-wide and network-wide issuance budgets
limit form-intent rotation. Proof attempts retain the per-challenge budget and
also consume device-wide and network-wide registration completion budgets, so
waiting for expiry or minting a new challenge cannot reset the guess budget.

For login-time MFA, the existing opaque, single-use MFA challenge remains the
preferred account-aware step-up after credentials have been accepted. The
pre-authentication risk gate must not query whether an identifier has MFA,
because doing so would create an account-enumeration oracle. Existing
reauthentication remains the preferred step-up for authenticated sensitive
operations.
