# ADR-0010: Objective risk step-up in the browser

- Status: Accepted
- Date: 2026-08-25
- Owners: United Pass frontend team

## Context

Registration and password login can now return a server-issued
`step_up_required` challenge when objective protocol and device signals show
automation risk. Normal responses must remain unchanged. A challenge must not
be treated as evidence that a person used AI or that prose was machine-written.

The browser must preserve a user's submitted form, complete the bounded
challenge, and retry the same intent without allowing an infinite retry loop or
an arbitrary completion URL. High-risk interactive verification also needs a
provider seam because the backend verifier may be configured separately from
the frontend SDK.

## Decision

`browser-http-client.ts` strictly narrows `error.stepUp`. Only the three
same-origin completion paths in the OpenAPI contract are accepted. For
`automation_cost`, a dedicated Web Worker searches for a nonce whose
`SHA-256(challengeToken + ":" + nonce)` digest has the requested leading zero
bits. This is an automation cost, not proof of humanity.

After a successful 204 completion, the client retries the original request
exactly once. The prepared body and caller-provided `Idempotency-Key` are reused.
A second challenge is surfaced as an error and never starts another loop.

`RiskStepUpProvider` supplies one application-level, keyboard-operable Semi
Design modal. Interactive CAPTCHA SDKs register through
`registerInteractiveCaptchaAdapter`; only the adapter's opaque proof is sent to
the backend. When `providerReady` is false or no client adapter is installed,
the modal says verification is unavailable and fails closed. It never creates
a fake success. Existing login MFA and authenticated reauthentication retain
their account-aware contracts and UI.

## Alternatives Considered

- Solving the automation cost on the main thread: rejected because it can make
  login and registration controls unresponsive.
- Retrying until the backend allows the request: rejected because it creates an
  unbounded loop and can amplify load.
- Loading a provider script directly in the HTTP client: rejected because it
  couples transport code to one vendor and makes provider failure look like
  transport success.
- Scoring writing style in the browser: rejected because it is unreliable,
  invasive, and outside the objective abuse-defense contract.

## Consequences

- Low-risk users see no new UI.
- Medium-risk work happens off the main thread where Worker is available; a
  cooperative fallback exists for older shells and unit tests.
- High-risk requests remain blocked until both the backend verifier and the
  matching browser adapter are configured.
- Challenge tokens and proofs remain ephemeral and are never persisted or
  logged by the frontend.

## Implementation Notes

- Error contract: `src/lib/api/api-error.ts`
- Retry boundary: `src/lib/api/browser/browser-http-client.ts`
- Worker host: `src/lib/security/automation-cost.ts`; standalone worker asset:
  `public/up-automation-cost-worker.js`
- Provider seam: `src/lib/security/interactive-captcha-adapter.ts`
- Modal bridge: `src/features/auth/components/risk-step-up-provider.tsx`
- Root registration: `src/app/layout.tsx`

## Follow-up

- Register the reviewed Alibaba Cloud CAPTCHA 2.0 browser adapter only after
  its backend verifier and public configuration are available.
- Re-run keyboard, dark-mode, and provider-specific acceptance tests when that
  adapter is introduced.
