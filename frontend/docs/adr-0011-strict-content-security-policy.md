# ADR-0011: Strict per-request content security policy

- Status: Accepted
- Date: 2026-08-28
- Owners: United Pass frontend team

## Context

The public authentication and legal-document responses did not carry a
`Content-Security-Policy` header. This left the browser without an application
policy for script injection, framing, plugin content, form targets, or remote
resource origins. A static policy with `script-src 'unsafe-inline'` would keep
Next.js prerendering, but would not provide an adequate script boundary for an
identity portal.

The root layout contains a static pre-hydration theme script. Next.js also
emits framework bootstrap scripts, the UI uses React/Semi style attributes, a
same-origin Web Worker performs bounded automation-cost work, and the reviewed
Aliyun CAPTCHA adapter loads one third-party SDK. That SDK delegates resources
to exact AliCDN hosts and contacts its exact mainland device, identity, upload,
image, and primary/backup ESA service origins.

## Decision

`src/proxy.ts` now runs for document routes, not only `/admin/*`. It creates a
fresh cryptographic nonce for every request, overwrites the internal `x-nonce`
and CSP request headers, and returns the same CSP on every success, redirect,
and error response. The existing administration authorization gate still runs
only for `/admin` and descendants. API ownership and Next.js static/image paths
remain outside the matcher. The `/admin/:path*` matcher is first and
unconditional, so a filename-like dot in an administration identifier cannot
bypass the pre-render gate. The general document matcher does not trust the
caller-controlled `Accept` header. It excludes only the exact `/api` and
`/_next/static`/`/_next/image` ownership boundaries and the exact reviewed files
in `public/`; application documents, dotted HTML 404s, and paths that merely
look like static assets therefore keep CSP for every `Accept` value while known
static assets remain outside.

The root layout reads the internal nonce and passes it to the static theme
`Script`. This intentionally makes document rendering dynamic so Next.js can
nonce its framework and application scripts. Nonce-bearing documents are
`no-store`.

Production `script-src` requires the request nonce and `strict-dynamic`; it
does not contain `unsafe-inline` or `unsafe-eval`. Development alone adds
`unsafe-eval`, hot-reload WebSocket access, and inline development styles for
React/Next.js debugging. These development allowances are absent from the
production policy. Script attributes are denied. Inline style attributes
remain allowed through the explicit, style-only `style-src-attr 'unsafe-inline'`
compatibility rule because existing React, Next Image, and Semi components
require them. This rule does not authorize `<style>` elements or script.
First-party style elements require self or the request nonce. The reviewed
vendor SDK creates four nonce-less inline `<style>` elements at runtime;
its style-loader first attaches three of them while empty. Production pins the
empty bootstrap and four retained bodies by exact SHA-256 sources in
`style-src-elem`, alongside the exact AliCDN resource hosts. A vendor CSS change
therefore fails closed until reviewed. Production `script-src` remains nonce
plus `strict-dynamic` and contains neither `unsafe-inline` nor `unsafe-eval`.

Remote access is restricted to the existing Moonstone application-logo origin
and exact Aliyun origins. There are no bare `https:` or hostname wildcard
source expressions. The mainland list follows
[Aliyun's client-access FAQ](https://help.aliyun.com/zh/captcha/captcha2-0/user-guide/captcha-2-0-client-access-faq)
and a real SDK browser trace for the configured `esa-rijvhs6c3b` identity;
connect, image, and frame sources are kept separate. Workers are same-origin. Objects
and media are denied; base URLs, form targets, framing, referrers, MIME
sniffing, DNS prefetch, legacy cross-domain policy files, and unneeded browser
capabilities receive explicit restrictions. Production also sets HSTS and
upgrades insecure subresources.

## Alternatives Considered

- Static CSP with `script-src 'unsafe-inline'`: rejected because injected
  inline script would remain executable.
- Production `unsafe-eval`: rejected because Next.js and React do not require
  it in production; the allowance is isolated to development.
- Monkey-patching DOM creation to add a nonce to vendor styles: rejected as a
  brittle dependency on obfuscated third-party implementation details. Exact
  style hashes preserve the style-element boundary without changing vendor
  runtime behavior.
- Experimental build-time SRI: rejected because the installed Next.js guide
  marks it experimental and it does not cover the inline theme bootstrap or
  dynamically loaded CAPTCHA SDK.
- A broad `https:` or wildcard CDN allowlist: rejected because it would turn
  any allowed HTTPS host into part of the execution or data-exfiltration
  boundary.

## Consequences

- `/privacy`, `/terms`, authentication, account, and administration documents
  receive a consistent enforceable CSP before rendering.
- Document responses are dynamically rendered and cannot use shared CDN HTML
  caching. Static assets remain cacheable because they are outside the document
  matcher where appropriate.
- The Aliyun CAPTCHA SDK is an explicit third-party trust dependency. Any new
  SDK, service origin, or runtime style body requires a policy review and
  contract-test update.
- `style-src-attr 'unsafe-inline'` is a deliberate style-only compatibility
  exception for existing React/Next/Semi rendering. It does not relax
  `style-src-elem`, `script-src`, or `script-src-attr`.
- CSP violation reporting is not enabled until a reviewed same-origin report
  ingestion, retention, rate-limit, and privacy design exists.

## Implementation Notes

- Policy and headers: `src/lib/security/content-security-policy.ts`
- Shared CAPTCHA origins: `src/lib/security/aliyun-captcha-config.ts`
- Per-request enforcement and admin gate: `src/proxy.ts`
- Dynamic nonce consumption: `src/app/layout.tsx`
- Production runtime contract: `scripts/smoke-standalone.mjs`
- Real vendor browser contract: `playwright.csp.config.ts` and
  `e2e-production/aliyun-captcha-csp.spec.ts`

## Follow-up

- Re-run the self-building browser acceptance test when the CAPTCHA provider
  changes its asset topology or runtime CSS; do not solve violations by adding
  broad wildcard or style-element `unsafe-inline` sources.
- Add same-origin CSP reporting only after its abuse and privacy boundaries are
  approved.
