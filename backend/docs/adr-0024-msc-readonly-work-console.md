# ADR-0024: MSC read-only work-console integration

- Status: Accepted
- Date: 2026-09-19
- Owners: United Pass backend team and MSC work-console operations

## Context

The MSC work console (`internal-msc.moonstone.org.cn`) is an approved-admin
back office for the MoonStone organization. Operators asked for the United
Pass user, employee, department and audit datasets to be visible inside that
console instead of requiring a second login into the United Pass portal.

The console already authenticates operators with its own Feishu OAuth session
and already ships the client half of this contract: an Express BFF that signs
an Ed25519 request assertion per call, and server-side read endpoints that map
one to one onto United Pass directory and audit resources.

United Pass must therefore expose a read-only, service-to-service surface. The
surface must not depend on a human United Pass session, must not accept a
browser credential, and must not grant anything beyond the four read
capabilities the console needs.

## Decision

United Pass mounts six read-only routes under `/internal/v1/msc/` behind a
request-bound Ed25519 assertion:

| Route | Capability |
| --- | --- |
| `GET /internal/v1/msc/users` | `msc.admin.user.read` |
| `GET /internal/v1/msc/users/{userId}` | `msc.admin.user.read` |
| `GET /internal/v1/msc/employees` | `msc.admin.employee.read` |
| `GET /internal/v1/msc/departments` | `msc.admin.department.read` |
| `GET /internal/v1/msc/departments/{departmentId}` | `msc.admin.department.read` |
| `GET /internal/v1/msc/audit-events` | `msc.admin.audit.read` |

The routes are mounted only when `UP_MSC_INTEGRATION_ENABLED` is true and a
strict public-only JWKS loads successfully. Any load failure aborts startup,
so the surface fails closed.

Assertion verification (`internal/mscaccess`) requires:

- `EdDSA` over `base64url(header).base64url(payload)` with a JWKS `kid`;
- exact `iss`, `aud` and `sub` matches against `UP_MSC_*` configuration;
- `actor_kind=service`, and a `capability` equal to the route capability;
- `htm=GET`, `htu` equal to the received path and query, empty-body
  `body_sha256`, and no request body;
- `iat`/`nbf`/`exp` inside a 25-second maximum lifetime with a five-second
  clock tolerance, and `jti` matching `^req_[a-f0-9]{32}$` and equal to the
  `X-Request-ID` header;
- strict JSON: unknown members, duplicate members and trailing content are
  rejected in both the JWT header and payload.

Reads reuse the existing workforce and audit services. The handlers add no
write path, expose no phone number, identity link, session or authorization
collection, and always emit `Cache-Control: no-store`. Audit detail bodies
are emptied before leaving the process.

## Alternatives Considered

- **Reuse the browser admin API with a stored super-admin session.** Rejected:
  it would place a full-privilege operator credential on the MSC host, require
  session replay, and grant write authority far beyond read-only reporting.
- **Expose the read-only endpoints without an assertion, restricted by source
  IP only.** Rejected: network position is not an identity, and the console
  runs outside the United Pass host.
- **Let the MSC BFF read PostgreSQL directly.** Rejected: it would bypass the
  domain services, audit and capability model, and require a cross-host
  database grant.
- **Publish a ZITADEL machine token instead of a bespoke assertion.** Rejected:
  the provider token describes the provider, not the United Pass capability or
  the exact request being authorized.

## Consequences

- The console renders United Pass directory and audit data without a second
  operator login, while the browser never receives assertion material.
- United Pass gains one more internal surface to keep in the deployment
  topology; it must remain outside the public `/api/v1` proxy rules and be
  reachable only by the MSC host.
- The employee and department tables are currently empty in production, so
  those two panels render empty lists until workforce data exists.
- Assertion keys rotate by replacing the JWKS file and restarting the API;
  multiple keys are accepted so the MSC side can rotate without downtime.

## Security Considerations

- The JWKS must be a regular non-symlink file, at most 16 KiB, owned and
  readable only by the service user; the loader rejects anything else.
- The assertion is bound to method, exact path and query, and to an empty body,
  so a captured assertion cannot be replayed against another resource.
- Replay of an unmodified assertion is limited to the remaining lifetime of the
  assertion (20 seconds as configured by the MSC signer). A consumed-`jti`
  store is intentionally not introduced; the console issues one assertion per
  request and never retries a stale one.
- Read-only capabilities cannot mutate United Pass state, including by a
  compromised MSC host.
- Failures return `401` with the standard error envelope and never echo
  assertion material or JWKS contents.

## Implementation Notes

- `internal/mscaccess`: configuration, strict JWKS loading and assertion
  verification; unit tested for signature, capability, target, time, request
  identifier, body, algorithm and JWKS strictness.
- `internal/adapters/httpapi/msc_readonly_handlers.go`: six handlers that
  reuse `workforce.Service` and `audit.Service` plus the existing response
  mappers.
- `internal/bootstrap/server.go`: mounts the routes after validating the
  JWKS, and refuses to start when the integration is enabled without the
  workforce and audit services.
- `UP_MSC_INTEGRATION_ENABLED`, `UP_MSC_PUBLIC_JWKS_PATH`,
  `UP_MSC_JWT_ISSUER`, `UP_MSC_JWT_AUDIENCE`, `UP_MSC_JWT_SUBJECT`.

## Follow-up

- Add workforce data (departments and employee profiles) so those panels show
  real rows.
- Consider a Redis-backed `jti` replay cache if the assertion lifetime is ever
  raised above the current 25-second ceiling.
- Record denied-assertion attempts as security events once an operator-facing
  alerting path exists for them.
