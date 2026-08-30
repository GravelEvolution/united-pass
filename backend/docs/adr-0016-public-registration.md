# ADR-0016: Pending public registration and fragment email verification

- Status: Accepted
- Date: 2026-08-18

## Context

United Pass previously linked an unknown ZITADEL subject on first login by
creating an active local user. Public registration cannot rely on that path:
an unverified provider user could otherwise log in and be promoted locally
before proving control of the email address. Verification codes must also stay
out of browser, application and reverse-proxy URL logs.

## Decision

Public registration is closed by default and enabled only with
`UP_PUBLIC_REGISTRATION_ENABLED=true`. Enabling requires PostgreSQL, Redis,
ZITADEL service-account configuration, `UP_AUTH_PROVIDER_PROJECT_ID`, the
distinct `UP_AUTH_PROVIDER_ORGANIZATION_ID`, and the public OAuth origin.

United Pass generates the stable `user_` ID. Before contacting ZITADEL, one
PostgreSQL transaction takes an advisory lock for the case-folded email,
rejects any existing local email, and creates a `pending`, unverified local
user, an exact
`(zitadel, projectId, userId)` identity link whose provider subject is that same
ID, and the consumer persona. Only after that reservation commits does United
Pass supply the stable ID to ZITADEL UserService v2 `CreateUser`, which may send
the verification email. Provider failure triggers best-effort deletion of both
the provider user and the exact local pending reservation. As a final fail-safe,
the existing first-login
linker now creates an unverified provider identity as pending rather than
active, so a failed compensation cannot reopen the bypass. Pending status
remains ineligible for session use.

ZITADEL sends the verification code to:

```text
https://<public-origin>/verify-email#userId={{.UserID}}&code={{.Code}}&requestId=<escaped opaque request>
```

The client reads the fragment and immediately removes it with
`history.replaceState` before posting JSON to the verification endpoint. After
provider verification, one PostgreSQL transaction verifies the exact identity
link and activates the local account. Provider email readback makes retries
idempotent when the provider accepted a one-time code but local activation
temporarily failed.

Email resend accepts only a short-lived random registration token. Redis keys
contain only its SHA-256 hash; values contain only `userId` and the validated
OAuth request ID. No endpoint accepts an arbitrary resend user ID.

All three public mutations use the same pre-session browser-mutation guard as
password login: exact configured `Origin`, same-origin Fetch Metadata when the
browser supplies it, strict JSON, a 16 KiB body limit, and generic
non-enumerating errors. Passwords and verification codes are never logged.

`X-Forwarded-For` and provider-specific headers are never application trust
inputs. The gateway authenticates the edge-to-origin hop, selects the real
client address, and overwrites the dedicated `X-Moonstone-Client-IP` header.
The application accepts that single validated address only when the TCP peer
belongs to `UP_TRUSTED_PROXY_CIDRS`; otherwise it uses the transport peer.
Malformed, duplicate, or comma-separated values fail safely to the peer.

Registration limits are independent from login limits. Creation atomically
advances four Redis buckets with separately configurable limits and windows:
exact client address, IPv4/IPv6 network prefix, normalized email, and the
client/email pair. This prevents a caller from resetting the cross-account
budget by rotating email addresses. Email verification and resend have their
own budgets. Redis failure denies the request. The existing PostgreSQL
case-folded email advisory lock and existence check still commit before any
provider call that can send mail.

## Consequences

- First OIDC login cannot turn an unverified registration into an active local
  account.
- The local reservation prevents repeated or concurrent provider email sends
  for an email already known to United Pass. The system still has explicit
  compensation, not impossible cross-system atomicity; cleanup failures require
  operator reconciliation.
- SMTP remains ZITADEL instance configuration. United Pass stores no SMTP
  password and does not send verification mail itself.
