# ADR-0017: Objective registration and login risk step-up

- Status: Accepted
- Date: 2026-08-25

## Decision

United Pass keeps low-risk registration and password login responses unchanged.
The optional `UP_RISK_DEFENSE_ENABLED` gate observes only server-issued device
state, short-lived session/device trust, operation rates, challenge failures,
and replay state. It never scores names, display names, prose, writing style,
or other subjective content. It also does not use `X-Forwarded-For`, IP
addresses, or network prefixes: the currently deployed edge does not provide a
cryptographically trustworthy real-client-IP assertion suitable for a risk
decision.

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
Public registration uses a narrower policy: the first and low-frequency
submissions remain transparent, while repeated submissions from the same
server-issued device progress to an automation cost at
`RegistrationMediumAfter` and high risk at `RegistrationHighAfter`.
Registration-to-verification speed, names, prose, and global five-minute
registration volume are not classifiers.

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

High risk prefers the distinct `interactive_captcha` method. The provider seam
is `riskdefense.InteractiveVerifier`; reviewed Turnstile and reCAPTCHA adapters
implement `Begin` and `Verify` without changing the browser contract. Alibaba
Cloud CAPTCHA 2.0 remains a follow-up for a production-grade mainland pool.
Until an eligible provider is configured, or when provider challenge creation
is temporarily unavailable, the server returns a satisfiable
`automation_cost` challenge at a stronger difficulty instead of an impossible
`providerReady: false` response. This fallback is computational throttling, not
human verification.

The browser completes either challenge at `POST /api/v1/auth/step-up`. A
successful, atomically consumed challenge sets a short-lived HttpOnly
`up_device_trust` cookie, after which the browser retries the original request.
For registration, that trust is bound to the challenged normalized identifier;
solving one challenge cannot exempt unrelated account creations on the same
device.
An authentication session counts as trust only while its authentication time is
within the same short trust window. Challenge claims are single-winner, proofs
are rate limited, and consumed or expired challenges cannot be replayed.

For login-time MFA, the existing opaque, single-use MFA challenge remains the
preferred account-aware step-up after credentials have been accepted. The
pre-authentication risk gate must not query whether an identifier has MFA,
because doing so would create an account-enumeration oracle. Existing
reauthentication remains the preferred step-up for authenticated sensitive
operations.
