# United Pass Backend

United Pass is a security-sensitive unified identity, account, organization, OAuth application, authorization, Provider synchronization and audit platform.

This directory contains the Go backend API service.

## Development Environment Requirements

- Go 1.26.5 (the version declared in `go.mod`)
- macOS / Linux
- PostgreSQL 16+ (Phase 1 onwards)
- Redis 7+ (Phase 1 onwards)
- SSH access to the server hosting PostgreSQL and Redis (for the development tunnel)

Remote test services are available, but the API must never connect to them over plaintext on the public network. Use the SSH tunnel described in [Secure Remote Access](#secure-remote-access-ssh-tunnel), TLS, or a VPN. Never downgrade to plaintext connections for convenience.

## Secure Remote Access (SSH Tunnel)

The remote PostgreSQL and Redis instances do not expose TLS. To comply with ADR-0002 (no plaintext over public network connections), development traffic is tunneled through SSH so the API connects to localhost only. Plaintext stays on the loopback interface; the public network is only reached through the encrypted SSH transport.

### One-command startup

```bash
# Start the tunnel, apply pending migrations, and run the API server
./scripts/dev.sh up --migrate

# Tunnel + migrations only
./scripts/dev.sh migrate

# Stop the tunnel
./scripts/dev.sh down

# Show tunnel state
./scripts/dev.sh status
```

`up` runs the API server in the foreground; stopping it (Ctrl+C) also stops the tunnel it started.

### Tunnel management

```bash
./scripts/tunnel.sh start     # establish SSH tunnels for PostgreSQL and Redis
./scripts/tunnel.sh stop      # tear the tunnels down
./scripts/tunnel.sh restart
./scripts/tunnel.sh status    # tunnel process and local port readiness
```

The tunnel maps:

| Local endpoint | Remote endpoint |
| --- | --- |
| `127.0.0.1:15432` | PostgreSQL `127.0.0.1:5432` on the SSH host |
| `127.0.0.1:16379` | Redis `127.0.0.1:6379` on the SSH host |

Configure the SSH target in `.env` (see `UP_SSH_*` below). The database and Redis URLs in `.env` must point at the local tunnel ports, never at the public IP. The tunnel keeps both services reachable without exposing credentials on the public network.

CI does not use the tunnel: the workflow runs PostgreSQL and Redis as service containers inside the isolated GitHub Actions runner and connects with `sslmode=disable` / `redis://localhost`.

## Running the Service

```bash
# Run with development defaults (listens on :8080)
go run ./cmd/api

# Run with explicit configuration
UP_ENVIRONMENT=development UP_HTTP_ADDR=:9090 UP_LOG_LEVEL=debug go run ./cmd/api
```

Local development may use an ignored `.env` file for configuration. Never commit `.env`.

Operational endpoints:

| Endpoint | Method | Purpose |
| --- | --- | --- |
| `/healthz` | GET | Process is alive (never depends on downstream services) |
| `/readyz` | GET | Process is ready to serve traffic (checks PostgreSQL, Redis, and auth provider) |

## Database Migrations

Migrations are NOT executed automatically at API server startup. Use the explicit migration command:

```bash
# Apply all pending migrations
go run ./cmd/migrate up

# Show migration status
go run ./cmd/migrate status

# Show current migration version
go run ./cmd/migrate version

# Roll back all migrations (requires --confirm, destructive)
go run ./cmd/migrate reset --confirm
```

Migrations live in `migrations/` and are managed by [goose](https://github.com/pressly/goose).

## Environment Variables

All configuration is loaded once at startup through `internal/config`. Variables are prefixed with `UP_`.

| Variable | Default | Description |
| --- | --- | --- |
| `UP_ENVIRONMENT` | `development` | `development` or `production`. Production enforces stricter validation. |
| `UP_HTTP_ADDR` | `:8080` | HTTP listen address. |
| `UP_READ_HEADER_TIMEOUT` | `5s` | Time to read request headers. |
| `UP_READ_TIMEOUT` | `15s` | Time to read the full request (headers + body). |
| `UP_WRITE_TIMEOUT` | `30s` | Maximum duration before timing out writes of the response. |
| `UP_IDLE_TIMEOUT` | `60s` | Maximum amount of time to wait for the next request. |
| `UP_SHUTDOWN_TIMEOUT` | `30s` | Graceful shutdown deadline. Production caps at 60s. |
| `UP_MAX_REQUEST_BODY_BYTES` | `1048576` (1 MiB) | Maximum request body size. Production caps at 16 MiB. |
| `UP_LOG_LEVEL` | `info` | `debug`, `info`, `warn` or `error`. |
| `UP_DATABASE_URL` | | PostgreSQL connection URL. Password must be URL-encoded. Use `sslmode=disable` only for localhost (e.g. through the SSH tunnel) or isolated CI. |
| `UP_DATABASE_SCHEMA` | `united_pass` | PostgreSQL schema for United Pass tables. Must be a valid PostgreSQL identifier. |
| `UP_DATABASE_MAX_CONNS` | `10` | Maximum pool connections. |
| `UP_DATABASE_MIN_CONNS` | `1` | Minimum pool connections. |
| `UP_DATABASE_CONNECT_TIMEOUT` | `10s` | Connection timeout. |
| `UP_REDIS_URL` | | Redis connection URL. Use `rediss://` for TLS. Password must be URL-encoded. |
| `UP_REDIS_KEY_PREFIX` | `up:development:` | Key prefix for Redis namespace isolation. |
| `UP_REDIS_POOL_SIZE` | `10` | Redis connection pool size. |
| `UP_REDIS_CONNECT_TIMEOUT` | `10s` | Redis connect timeout. |
| `UP_REDIS_READ_TIMEOUT` | `3s` | Redis read timeout. |
| `UP_REDIS_WRITE_TIMEOUT` | `3s` | Redis write timeout. |
| `UP_SESSION_TTL` | `12h` | Session absolute TTL. |
| `UP_SESSION_REMEMBER_TTL` | `720h` | Session TTL when "remember me" is set. |
| `UP_SESSION_IDLE_TTL` | `2h` | Session idle timeout. |
| `UP_SESSION_TOUCH_INTERVAL` | `5m` | Minimum interval between Redis session touches. |
| `UP_SESSION_COOKIE_SECURE` | `false` | Set `true` in production. |
| `UP_SESSION_COOKIE_SAME_SITE` | `lax` | Cookie SameSite attribute. |
| `UP_SESSION_ENCRYPTION_KEY` | | Base64-encoded 32-byte key for encrypting provider session credentials (AES-256-GCM). Required in production. |
| `UP_SESSION_ENCRYPTION_KEY_ID` | | Key identifier for rotation. |
| `UP_MFA_CHALLENGE_TTL` | `5m` | MFA challenge token TTL. |
| `UP_MFA_MAX_ATTEMPTS` | `5` | Maximum MFA verification attempts. |
| `UP_LOGIN_RATE_LIMIT` | `10` | Maximum login attempts per window. |
| `UP_LOGIN_RATE_WINDOW` | `15m` | Login rate limit window. |
| `UP_MFA_RATE_LIMIT` | `10` | Maximum MFA attempts per window. |
| `UP_MFA_RATE_WINDOW` | `15m` | MFA rate limit window. |
| `UP_REAUTH_CHALLENGE_TTL` | `5m` | Reauthentication challenge token TTL. |
| `UP_REAUTH_GRANT_TTL` | `5m` | Reauthentication grant (single-use token) TTL. |
| `UP_REAUTH_MAX_ATTEMPTS` | `5` | Maximum reauthentication MFA attempts per challenge. |
| `UP_REAUTH_RATE_LIMIT` | `10` | Maximum reauthentication attempts per window. |
| `UP_REAUTH_RATE_WINDOW` | `15m` | Reauthentication rate limit window. |
| `UP_SECRET_ROTATION_GRACE_PERIOD` | `0s` | Overlap window during which the previous client secret stays valid after rotation (ZITADEL v2.71 has no native grace period). Must not be negative. |
| `UP_SECRET_ROTATION_RATE_LIMIT` | `3` | Maximum secret rotations per window per client. |
| `UP_SECRET_ROTATION_RATE_WINDOW` | `15m` | Secret rotation rate limit window. |
| `UP_PERMISSION_DEV_OVERRIDE` | `false` | Development only: grant full capabilities to the user in `UP_PERMISSION_DEV_OVERRIDE_USER_ID`. Rejected in production. |
| `UP_PERMISSION_DEV_OVERRIDE_USER_ID` | | Local user ID targeted by the development permission override. |
| `UP_AUTH_PROVIDER` | | Authentication provider name: `fake` (development only) or `zitadel`. Unknown values fail startup in all environments. |
| `UP_AUTH_PROVIDER_BASE_URL` | | Authentication provider base URL. HTTPS required in production; local dev may use `http://localhost:8080`. |
| `UP_AUTH_PROVIDER_PROJECT_ID` | | Authentication provider project ID (tenant scope for identity links). |
| `UP_AUTH_PROVIDER_CLIENT_ID` | | Authentication provider client ID. |
| `UP_AUTH_PROVIDER_CLIENT_SECRET` | | Authentication provider client secret. |
| `UP_AUTH_PROVIDER_SERVICE_ACCOUNT_KEY_FILE` | | Path to the ZITADEL service account key.json (JWT profile auth). Required for `zitadel`. |
| `UP_AUTH_PROVIDER_DOMAIN` | | WebAuthn relying-party domain for passkey challenges. Empty disables passkey challenges. |
| `UP_OAUTH_PUBLIC_ORIGIN` | | Public OAuth origin the reverse proxy serves the protocol endpoints on (browser-visible issuer origin), e.g. `https://id.example.com`. Strict origin syntax: scheme + host (+ port) only — no path, userinfo, query or fragment. HTTPS required in production, where the variable is mandatory. The ZITADEL LoginV2 Interaction Base URI is derived as `<origin>/_interaction`. Do not reuse `UP_AUTH_PROVIDER_BASE_URL` for this value. |
| `UP_FEISHU_BASE_URL` | `https://open.feishu.cn` | Feishu OpenAPI origin. HTTPS is required in production. |
| `UP_FEISHU_AUTHORIZE_URL` | `https://accounts.feishu.cn/open-apis/authen/v1/authorize` | Feishu browser authorization endpoint. |
| `UP_FEISHU_APP_ID` | | Feishu application ID. Must be configured atomically with App Secret, tenant ID and redirect URL. |
| `UP_FEISHU_APP_SECRET` | | Server-only Feishu App Secret. Never expose it to the browser, logs or persistence. |
| `UP_FEISHU_TENANT_ID` | | Expected Feishu tenant key; OAuth login fails closed on mismatch. |
| `UP_FEISHU_REDIRECT_URL` | | Exact callback URL ending in `/api/v1/auth/providers/feishu/callback`. HTTPS is required in production. |
| `UP_FEISHU_CONTACT_SCOPE` | `应用通讯录授权范围` | Non-secret display label for the app's configured Contact API scope. |
| `UP_FEISHU_OAUTH_STATE_TTL` | `5m` | Redis-backed single-use login-state TTL; maximum 15 minutes. |
| `UP_FEISHU_REQUEST_TIMEOUT` | `15s` | Per-request Feishu HTTP timeout. |
| `UP_FEISHU_RECONCILE_INTERVAL` | `15s` | Durable directory-job worker interval. |
| `UP_FEISHU_SYNC_TIMEOUT` | `2m` | One directory reconciliation attempt deadline. |
| `UP_CERBOS_PDP_URL` | | Cerbos PDP HTTP origin. Complete Cerbos configuration is required in production. |
| `UP_CERBOS_ADMIN_URL` | | Mutable Cerbos Admin API origin; HTTPS required in production. |
| `UP_CERBOS_ADMIN_USERNAME` | | Non-default, server-only Admin API Basic authentication username. |
| `UP_CERBOS_ADMIN_PASSWORD` | | Server-only Admin API password. Default Cerbos credentials are rejected. |
| `UP_CERBOS_REQUEST_TIMEOUT` | `3s` | Bounded PDP/Admin request timeout; maximum 30 seconds. |
| `UP_CERBOS_RECONCILE_INTERVAL` | `30s` | Durable policy publication reconciliation interval. |
| `UP_SSH_HOST` | | SSH host for the development tunnel (`scripts/tunnel.sh`). |
| `UP_SSH_PORT` | `22` | SSH port for the development tunnel. |
| `UP_SSH_USER` | | SSH user for the development tunnel. |
| `UP_SSH_KEY` | `~/.ssh/id_ed25519` | SSH private key for the development tunnel (preferred). |
| `UP_SSH_PASSWORD` | | Optional SSH password for the development tunnel via `sshpass`. When set, `tunnel.sh` uses password authentication instead of a key (requires `brew install sshpass`). The password is passed to `sshpass` through the `SSHPASS` environment variable (`sshpass -e`) only — never as a process argument — and is unset right after the tunnel starts. Never commit the real password. |
| `UP_LOCAL_PG_PORT` | `15432` | Local tunnel port for PostgreSQL. |
| `UP_LOCAL_REDIS_PORT` | `16379` | Local tunnel port for Redis. |

### Integration Test Variables

| Variable | Description |
| --- | --- |
| `UP_TEST_DATABASE_URL` | PostgreSQL URL for integration tests. |
| `UP_TEST_DATABASE_SCHEMA` | PostgreSQL schema for integration tests (default: `united_pass_test`). |
| `UP_TEST_REDIS_URL` | Redis URL for integration tests. |
| `UP_TEST_REDIS_KEY_PREFIX` | Redis key prefix for integration tests (default: `up:test:`). |

Integration tests skip when these variables are absent. They never fall back to the development database or Redis.

### Security Notes

- `.env` is for local development only and must never be committed.
- `.env.template` is the committed template with placeholder values.
- PostgreSQL is the persistent source of truth for user identity.
- Redis holds only ephemeral data: sessions, MFA challenges, and rate-limit counters.
- Redis data loss only invalidates sessions — it does not delete users.
- Never connect to public network services with plaintext. Development uses the SSH tunnel; production requires TLS.
- CI does not connect to remote shared databases.

## Test Commands

```bash
# Unit tests (no external dependencies required)
go mod tidy
go fmt ./...
go vet ./...
go test ./...
go test -race ./...
go build ./...

# Static hygiene check for the SSH tunnel script (password fallback must
# never place the password in process arguments, logs, or PID files)
./scripts/tunnel-hygiene-check.sh

# Integration tests (require UP_TEST_DATABASE_URL and UP_TEST_REDIS_URL,
# which point at the local SSH tunnel ports; start the tunnel first)
./scripts/tunnel.sh start
go test -tags integration -race ./internal/adapters/postgres/... ./internal/adapters/redis/...
./scripts/tunnel.sh stop
```

Integration tests never run `FLUSHALL`, `FLUSHDB`, or `DROP DATABASE`. They only delete keys under the configured test prefix and only drop tables in the test schema.

## Current Implementation Scope (Phase 0–8 plus production seam completion)

Phase 0 established the HTTP foundation. Phase 1 adds session management, authentication, and current user endpoints. Phase 2 adds the OAuth Application and OAuth Client management plane (see [ADR-0004](docs/adr-0004.md)).

### Implemented in Phase 0

- Go module `github.com/GravelEvolution/united-pass/backend`
- Entry point at `cmd/api/main.go`
- Typed, validated configuration (`internal/config`)
- Structured logging with `log/slog` (`internal/platform/observability`)
- `http.Server` with configurable timeouts
- Chi router with standard `net/http` middleware interfaces
- Request ID, panic recovery, access logging, security headers
- Request body size limit
- Unified API error envelope matching the frontend contract
- `GET /healthz` and `GET /readyz`
- Graceful shutdown via `SIGINT`/`SIGTERM`
- ADR-0001 documenting the foundation architecture
- GitHub Actions CI workflow
- OpenAPI 3.1 specification

### Implemented in Phase 1

- **PostgreSQL persistence**: users, identity_links, user_personas tables with goose migrations
- **Redis ephemeral state**: session store, MFA challenge store, rate limiter
- **Opaque server-side sessions**: 256-bit tokens, SHA-256 hashed in Redis, TTL with idle timeout
- **Session Cookie** (`up_session`): HttpOnly, SameSite=Lax, Secure in production
- **CSRF protection** (`up_csrf` + `X-CSRF-Token`): session-bound, constant-time comparison
- **Login**: `POST /api/v1/auth/sessions` with rate limiting and generic error responses
- **MFA challenge**: `POST /api/v1/auth/sessions/mfa` with one-time tokens, atomic single-winner claim (concurrent replays rejected), attempt limits, and short processing TTL
- **Logout**: `DELETE /api/v1/auth/session` with session and CSRF validation
- **Current user**: `GET /api/v1/me` with masked phone, personas, null employee profile
- **Permissions**: `GET /api/v1/me/permissions` with fail-closed default resolver
- **Session middleware**: `RequireSession`, `OptionalSession`, `RequireCSRF`
- **Readiness checks**: PostgreSQL, Redis, and auth provider connectivity
- **Authentication provider adapter**: `auth.Authenticator` interface + ZITADEL LoginV2 adapter (`internal/adapters/zitadel`, Phase 1.2) + development-only fake
- **Identity mapping**: `identity.UserLinker` — first login creates the local user and binds the provider subject via `identity_links` (concurrency safe)
- **Provider session reference encryption**: AES-256-GCM at rest (`UP_SESSION_ENCRYPTION_KEY`), decrypted only for logout revocation
- **Redacted dependency logging**: stable error classes instead of raw provider/DB error text
- **Permission resolver**: fail-closed default with optional development override
- **Migration command**: `cmd/migrate/main.go` with explicit up/status/version/reset
- **Development tooling**: `scripts/tunnel.sh` (SSH tunnel manager), `scripts/dev.sh` (one-command startup), `docker-compose.zitadel.yml` + `scripts/zitadel-init.sh` (local ZITADEL instance)
- ADR-0002 documenting session, PostgreSQL, Redis, and authentication provider architecture
- ADR-0003 documenting the ZITADEL provider selection and API mapping
- OpenAPI specification updated with all Phase 1 endpoints
- Unit tests, HTTP tests, and integration tests (PostgreSQL and Redis)

### Implemented in Phase 2

- **OAuth Application / Client domain** (`internal/applications`): application + client lifecycle state machines, confidential/public profiles, consent modes, scope catalog validation, soft delete
- **Parent lifecycle enforcement**: a Client's effective state is `application.status == active && client.status == active`; while the Application is disabled, client creation/enable/config update/secret rotation are rejected (state-matrix tested)
- **PostgreSQL schema v2**: `oauth_applications`, `oauth_clients`, `oauth_client_secret_records`, `provider_operations`, `provider_reconciliation_jobs`, `security_events` (schema v3 adds durable secret-rotation operation state)
- **ZITADEL provisioning adapter**: OIDC app create/update/disable/remove + secret rotation against the Management API, with a capability-equivalent fake provider for tests; all provider failures mapped to stable error classes (fail closed); provider display names are globally unique (`{application} · {client} · {shortClientId}`) so interrupted provisioning recovers the original provider app instead of conflicting
- **Application API**: create with initial client, list (cursor pagination), get/update, enable/disable, delete
- **Client API**: create/get/update/enable/disable/delete with profile-based validation (redirect URIs, token endpoint auth, scopes)
- **Reauthentication** (`POST /api/v1/auth/reauthentication` + `/mfa`): password + TOTP step-up for high-risk actions; single-use grants bound to action and resource, submitted via `X-Reauthentication-Token`; temporary provider sessions are best-effort revoked at every terminal state
- **Secret rotation**: durable rotation operation state (`idle` / `in_progress` / `outcome_unknown`) serializes winners; provider timeouts land in `outcome_unknown` + reconciliation instead of assuming the old secret survived; one-time secret display (`Cache-Control: no-store`), rate limiting, rotation audit
- **Compensation**: provider outcomes for delete/enable/disable/update/rotation are recorded; provider success + local failure leaves `provider_reconciliation_required` flags, reconciliation jobs, and durable audit events; failed deletions are retryable
- **Durable audit**: success events for every high-risk management-plane action commit in the same transaction as the state change; an audit write failure aborts the operation (log-based audit is not a substitute)
- **Provider capability gating**: `server_to_server` clients are rejected with 422 on ZITADEL v2.71 (client_credentials is not served for project apps; verified in P2.8 acceptance)
- **Readiness**: `/readyz` covers PostgreSQL, Redis, auth provider connectivity, and provisioning project readability (`GetProjectByID`); the `PROJECT_OWNER` membership required for `RemoveApp` cannot be probed without side effects and remains a deployment acceptance check
- ADR-0004 documenting the Phase 2 management-plane architecture
- Real-provider acceptance against ZITADEL v2.71 (confidential + public client provisioning, rotation, delete, compensation); see [P2.8 acceptance record](docs/p28-acceptance-record.md)

### Implemented in Phase 6

- **Feishu OAuth login**: server-side v2 code exchange, user-info lookup, Redis
  single-use state and exact tenant/subject identity-link resolution.
- **Server-only credentials**: App Secret stays in typed runtime configuration;
  tenant tokens are cached only in memory and user tokens are discarded after
  callback lookup.
- **Durable directory jobs**: idempotent single-active enqueue, stale-claim
  recovery, bounded retry and synchronization history.
- **Safe directory staging**: normalized Feishu departments/users are stored
  separately from workforce authority; partial snapshots never retire unseen
  rows and synchronization never grants employee/persona/permission state.
- **Explicit conflict resolution**: email/name are suggestions only; a
  target-bound reauthentication grant and selected stable `userId` create the
  exact identity link atomically with audit.
- **Real frontend seam**: Provider list/detail/history/conflicts, 202 job UX,
  enable/disable and manual resolution, plus optional Feishu login entry.
- Architecture and acceptance contract: [ADR-0012](docs/adr-0012.md).

### Implemented in Phase 7

- Cerbos-backed fail-closed capability resolution, versioned policy drafts,
  durable publication jobs, simulation and canonical audit search/export.
- Architecture: [ADR-0013](docs/adr-0013.md).

### Implemented in Phase 8

- Controlled legal publication bound to an external approval reference and the
  exact frontend source SHA-256; code deployment alone cannot activate text.
- Step-up protected personal-data JSON exports, owner-bound download and
  15-minute artifact expiry.
- Step-up protected account deletion with a 30-day cancellable cooling period,
  provider-first durable convergence, session purge and local anonymisation.
- Architecture and operations: [ADR-0014](docs/adr-0014.md) and
  [Phase 8 launch runbook](docs/p8-launch-runbook.md).
- Legal approval and real production cutover remain external Pending items.

### Production seam completion (2026-08-16)

- **Public account lifecycle**: ZITADEL-owned registration credentials and
  email/password-reset codes; pending stable user + Consumer Persona + exact
  provider identity link; compensation on local failure; anti-enumerating reset
  request; encrypted short-lived lifecycle capabilities; password-reset security
  epoch advancement and old-session invalidation.
- **Account self-service**: constrained profile patch, server-decoded/resized/
  metadata-stripped PNG avatar storage, and durable user/session-bound email or
  phone verification with claim leases, attempt limits and provider readback.
- **Administration overview**: real PostgreSQL aggregates independently scoped
  to user, application and audit read capabilities.
- **Final frontend integration**: every production data seam calls real HTTP;
  explicit fixtures cannot manufacture a session or silently persist writes.
- **Security closure**: logged-out credential submissions require JSON plus an
  exact same-origin Origin, forwarding headers are not trusted for rate-limit
  identity, Redis construction failure aborts startup, and shutdown returns
  joined HTTP/Redis/provider close errors.
- Architecture: [ADR-0015](docs/adr-0015.md). Machine contract:
  [OpenAPI 0.9.0](openapi/openapi.yaml).

### Status and remaining external acceptance

**Phase 1 status: implementation complete; local real-instance acceptance passed.**
The session, current user, MFA (atomic consumption, opaque server-generated
MFA tokens that never carry provider credentials), provider-reference
encryption, logging redaction, production safety guardrails, and the ZITADEL
provider adapter (Phase 1.2) are implemented. The adapter has been accepted
against a local real ZITADEL v2.71.0 instance (password + TOTP login,
first-login identity mapping, logout revocation, HTTP smoke flow, passkey
fail-closed security remediation); details in [ADR-0003 Operational
Sign-off](docs/adr-0003.md). Production deployments can start with the
ZITADEL adapter once the HTTPS instance and secrets are provisioned (see
[Local ZITADEL Instance](#local-zitadel-instance)).

**Phase 2 status: frozen (2026-08-07).**

- Phase 2 implementation: complete
- Phase 2 local real-provider acceptance: passed
- Phase 2 local code review: passed
- GitHub Actions verification: pending quota recovery
- Production operational sign-off: pending

The OAuth Application/Client management plane (provisioning, reauthentication,
secret rotation, deletion, compensation, durable audit) is implemented and the
real-provider acceptance covers both confidential and public clients against
ZITADEL v2.71.0; details in [ADR-0004](docs/adr-0004.md) and the
[P2.8 acceptance record](docs/p28-acceptance-record.md). A security review
reopened the freeze and identified 10 remediation items (parent lifecycle
enforcement, durable rotation serialization, globally unique provisioning
identity, provider-success reconciliation, reauth session revocation,
frontend contract sync, server_to_server rejection, public-client acceptance,
same-transaction success audit, provisioning project readiness); all items
are implemented and regression-tested. A second review round then required
three more fixes: partial application status switches now roll back (enable)
or record fail-safe drift with desired status (disable), abandoned/expired
reauthentication challenges are cleaned up by an index-driven worker
(create-time guard + idempotent sweep), and the frontend disables the
unsupported `server_to_server` profile. The post-remediation re-acceptance
(P2.8b, schema version 4) passed 70/70 against the real provider. A final
hardening round closed the remaining edge cases: challenge creation writes
the record and its cleanup-index entry atomically (Lua), provider session
revocation runs on a detached context, and the revocation-failure audit uses
its own fresh deadline so a provider timeout can never drop the security
event. All code-level review findings are closed; the freeze was granted
2026-08-07. Note: the
ZITADEL service account must hold `PROJECT_OWNER` membership on the
provisioning project — organization-level `ORG_OWNER` alone is not sufficient
for `RemoveApp` on v2.71.

- Production HTTPS instance + Secret Manager rollout (Phase 1.2 production operational sign-off)
- gRPC error-code calibration follow-ups on the production instance (see `internal/adapters/zitadel/errors.go`; local codes are recorded in ADR-0003)
- Destructive live acceptance for registration/email delivery, password reset
  and email/SMS contact changes against the designated production-like ZITADEL tenant
- Recovery Code management (provider capability remains unsupported)
- Legal sign-off, production backup/restore exercise, real production-like
  destructive account-deletion acceptance and traffic cutover

## Local ZITADEL Instance

Phase 1.2 authenticates against ZITADEL via the LoginV2 API. For local
development and integration tests, a disposable instance runs in Docker:

```bash
docker compose -f docker-compose.zitadel.yml up -d
./scripts/zitadel-init.sh
```

`zitadel-init.sh` creates a human test user (password + TOTP), a service
account, and its API key (`key.json`), then prints the `UP_TEST_ZITADEL_*`
variables. Configure the service to use it:

```bash
UP_AUTH_PROVIDER=zitadel \
UP_AUTH_PROVIDER_BASE_URL=http://localhost:8080 \
UP_AUTH_PROVIDER_SERVICE_ACCOUNT_KEY_FILE=/path/to/.zitadel/sa-key.json \
UP_AUTH_PROVIDER_DOMAIN=localhost \
go run ./cmd/api
```

Run the E2E tests against the instance (TOTP code is computed automatically
from the secret saved in `.zitadel/init-state.json`; set
`UP_TEST_DATABASE_URL` to also validate first-login identity mapping against a
real PostgreSQL schema migrated with `cmd/migrate`):

```bash
UP_TEST_ZITADEL_BASE_URL=http://localhost:8080 \
UP_TEST_ZITADEL_KEY_FILE=.zitadel/sa-key.json \
UP_TEST_ZITADEL_USER=zhixing.lin@example.com \
UP_TEST_ZITADEL_PASSWORD='TestPassword123!' \
UP_TEST_ZITADEL_TOTP_SECRET=$(jq -r .totpSecret .zitadel/init-state.json) \
UP_TEST_DATABASE_URL='postgres://...' \
go test -tags integration ./internal/adapters/zitadel/...
```

Production ZITADEL requires an HTTPS endpoint and the service account key
delivered via secrets management; the key file must never be committed
(`.zitadel/` is gitignored). Config validation rejects any non-HTTPS provider
base URL in production.

## API Endpoints (Phase 1)

| Endpoint | Method | Auth | CSRF | Description |
| --- | --- | --- | --- | --- |
| `/api/v1/auth/sessions` | POST | None | No (origin check) | Login with identifier and password |
| `/api/v1/auth/sessions/mfa` | POST | None | No | Complete MFA challenge |
| `/api/v1/auth/session` | DELETE | Session | Yes | Logout and clear cookies |
| `/api/v1/me` | GET | Session | No | Get current user profile |
| `/api/v1/me/permissions` | GET | Session | No | Get permission capabilities |
| `/healthz` | GET | None | No | Process liveness |
| `/readyz` | GET | None | No | Dependency readiness |

## API Endpoints (Phase 2)

All Phase 2 endpoints require a session; state-changing endpoints require CSRF.
High-risk operations additionally require a fresh reauthentication grant
(`X-Reauthentication-Token`).

| Endpoint | Method | Reauth | Description |
| --- | --- | --- | --- |
| `/api/v1/auth/reauthentication` | POST | No | Start step-up verification for a high-risk action |
| `/api/v1/auth/reauthentication/mfa` | POST | No | Complete a reauthentication challenge (TOTP/passkey) |
| `/api/v1/admin/scopes` | GET | No | Authoritative OAuth scope catalog |
| `/api/v1/admin/applications/with-initial-client` | POST | No | Create application with its initial client (one-time secret) |
| `/api/v1/admin/applications` | GET | No | List applications (cursor pagination) |
| `/api/v1/admin/applications/{applicationId}` | GET / PATCH / DELETE | DELETE | Get / update / delete application |
| `/api/v1/admin/applications/{applicationId}/enable` | POST | No | Enable application |
| `/api/v1/admin/applications/{applicationId}/disable` | POST | No | Disable application |
| `/api/v1/admin/applications/{applicationId}/clients` | POST | No | Add client (one-time secret for confidential profiles) |
| `/api/v1/admin/applications/{applicationId}/clients/{clientId}` | GET / PATCH / DELETE | DELETE | Get / update / delete client |
| `/api/v1/admin/applications/{applicationId}/clients/{clientId}/enable` | POST | No | Enable client |
| `/api/v1/admin/applications/{applicationId}/clients/{clientId}/disable` | POST | No | Disable client |
| `/api/v1/admin/applications/{applicationId}/clients/{clientId}/secret-rotations` | POST | Yes | Rotate confidential client secret (one-time display) |

## API Endpoints (production seam completion)

Logged-out credential endpoints require `application/json` and the exact public
Origin. Session-authenticated writes require CSRF. Verification capabilities
and provider codes are sensitive and must not be logged.

| Endpoint | Method | Auth | Description |
| --- | --- | --- | --- |
| `/api/v1/registrations` | POST | None + same-origin | Create provider credential and pending linked user |
| `/api/v1/password-reset-requests` | POST | None + same-origin | Enumeration-safe reset notification request |
| `/api/v1/password-resets` | POST | None + same-origin | Provider-verified reset and old-session invalidation |
| `/api/v1/email-verifications` | POST | None + same-origin | Verify registration email and activate pending user |
| `/api/v1/me` | PATCH | Session + CSRF | Update display name and/or nickname |
| `/api/v1/me/avatar` | POST multipart | Session + CSRF | Decode, sanitize and store avatar |
| `/api/v1/media/avatars/{avatarFile}` | GET | None | Serve controlled immutable PNG media |
| `/api/v1/me/email-change-requests` | POST | Session + CSRF | Begin Provider-verified email change |
| `/api/v1/me/email-change-requests/{requestId}/verify` | POST | Session + CSRF | Verify and commit exact email change |
| `/api/v1/me/phone-change-requests` | POST | Session + CSRF | Begin Provider-verified phone change |
| `/api/v1/me/phone-change-requests/{requestId}/verify` | POST | Session + CSRF | Verify and commit exact phone change |
| `/api/v1/admin/dashboard` | GET | Session + capability | Return only independently authorized aggregates |

## API Endpoints (Phase 8)

| Endpoint | Method | Reauth | Description |
| --- | --- | --- | --- |
| `/api/v1/legal-documents` | GET | No | Public effective/scheduled legal document identity |
| `/api/v1/me/data-exports` | POST | Yes | Request a personal-data export |
| `/api/v1/me/data-exports/{exportId}` | GET | No | Poll an owner-bound export job |
| `/api/v1/me/data-exports/{exportId}/download` | GET | No | Download an unexpired JSON artifact |
| `/api/v1/me/account-deletion` | GET / POST / DELETE | POST | Read, request, or cancel delayed deletion |

## Cookie and CSRF Conventions

Per ADR-0006:

- **Session cookie**: `up_session` (HttpOnly, SameSite=Lax, Secure in production)
- **CSRF cookie**: `up_csrf` (readable by JavaScript, SameSite=Lax, Secure in production)
- **CSRF header**: `X-CSRF-Token`

CSRF tokens are bound to sessions: the token hash is stored in the Redis session record and validated with constant-time comparison on every state-changing request.

## Relationship with `../frontend/`

The frontend directory is the frozen source of truth for API contracts, request/response field names, error structures, cursor pagination, permission capabilities, OAuth Application/Client models, cookie and CSRF conventions. The backend implements to that contract.

Contract priority:

1. `backend/openapi/openapi.yaml` — machine-readable contract (authoritative once established)
2. `../frontend/docs/api-contracts.md` — human-readable detailed contract (Frozen v1)
3. `../frontend/docs/frontend-freeze-v1.md` — handoff summary (defers to api-contracts.md for paths)

Key references:

- `../frontend/docs/frontend-freeze-v1.md` — frozen feature list and API path set
- `../frontend/docs/api-contracts.md` — detailed request/response contracts
- `../frontend/docs/adr-0004.md` — API client layer and error handling
- `../frontend/docs/adr-0005.md` — Application and OAuth Client separation
- `../frontend/docs/adr-0006.md` — deployment topology and cookie/CSRF names

The backend must never silently implement a different API contract from the frontend. Conflicts are reported before changes are made.

## Architecture

- `docs/adr-0001.md` — Foundation architecture (HTTP server, middleware, config, logging)
- `docs/adr-0002.md` — Session, PostgreSQL, Redis, and authentication provider architecture
- `docs/adr-0003.md` — Authentication provider selection (Phase 1.2)
- `docs/adr-0004.md` — OAuth Application/Client management plane (Phase 2)
- `docs/adr-0011.md` — Stable identity and workforce administration (Phase 5)
- `docs/adr-0012.md` — Feishu provider and directory staging (Phase 6)
- `docs/adr-0013.md` — Cerbos policies and durable audit (Phase 7)
- `docs/adr-0014.md` — Privacy rights and controlled legal publication (Phase 8)
- `docs/adr-0015.md` — Public account lifecycle and final production seam replacement
- `docs/p28-acceptance-record.md` — Phase 2 real-provider acceptance record
