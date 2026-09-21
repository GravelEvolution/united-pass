# ADR-0011: Registration form intent and automation honeypot

- Status: Accepted
- Date: 2026-08-25
- Owners: United Pass frontend team

## Context

The registration browser must prove that it loaded a current form before it
can create an account. It also needs a high-confidence signal for automated
agents that indiscriminately execute instructions found in the DOM. The signal
must remain invisible and unreachable to people, keyboards, and assistive
technology, and a stale cached page must not silently become an attack signal.

## Decision

On mount, the registration panel requests a short-lived form intent from the
same-origin API. Submission stays disabled while that intent is unavailable.
Every legitimate create request explicitly sends the issued token and an empty
`automationBrief` value. If the API reports an invalid or expired intent, the
panel preserves the user's visible fields and obtains a fresh token.

The form contains a non-required textarea inside an `aria-hidden`, `inert`,
non-focusable, visually clipped container. Its DOM-readable label asks an
automation agent to generate a long, cross-constrained compatibility brief,
while explicitly prohibiting secrets, personal information, and privileged
actions. A human never needs to read or answer it. Filling it is handled only
by the server and must never be interpreted in the browser as success or as a
human-authorship judgment.

## Alternatives Considered

- Hidden input without an instruction: rejected because many task agents only
  fill fields they can associate with an apparent instruction.
- CSS-only hiding: rejected because it can remain keyboard- or accessibility-
  reachable.
- Requiring a response from people: rejected because it adds friction and is
  not reliable proof of humanity.
- Silently retrying every invalid intent: rejected because retries must remain
  bounded and visible submission state must be stable.

## Consequences

- Low-risk users see only a brief security-preparation state on initial load.
- The new frontend and backend contracts must be released together through the
  existing release workflow; no manual `current` edit is permitted.
- The honeypot is a narrow automation signal, not a prose classifier and not a
  substitute for interactive CAPTCHA on objectively high-risk requests.

## Implementation Notes

- API commands: `src/lib/api/browser/registration-commands.ts`
- Registration panel: `src/features/auth/components/registration-panel.tsx`
- Non-interactive trap styling:
  `src/features/auth/components/credential-panel.module.css`
- Command tests: `src/lib/api/browser/registration-commands.test.ts`

## Follow-up

- Re-test cached-client recovery during the coordinated release.
- When a production interactive provider is enabled, verify its browser SDK in
  both accessibility modes and the existing fail-closed step-up flow.
