# United Pass Backend

United Pass is a security-sensitive unified identity, account, organization, OAuth application, authorization, Provider synchronization and audit platform.

This directory contains the Go backend API service.

## Development Environment Requirements

- Go 1.26.5 (the version declared in `go.mod`)
- macOS / Linux
- No external services are required for Phase 0 (no database, Redis, or message broker)

## Running the Service

```bash
# Run with development defaults (listens on :8080)
go run ./cmd/api

# Run with explicit configuration
UP_ENVIRONMENT=development UP_HTTP_ADDR=:9090 UP_LOG_LEVEL=debug go run ./cmd/api
```

Operational endpoints:

| Endpoint | Method | Purpose |
| --- | --- | --- |
| `/healthz` | GET | Process is alive (never depends on downstream services) |
| `/readyz` | GET | Process is ready to serve traffic |

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

Local development may use an ignored `.env` file. Never commit secrets.

## Test Commands

```bash
go mod tidy
go fmt ./...
go vet ./...
go test ./...
go test -race ./...
go build ./...
```

## Current Implementation Scope (Phase 0)

Phase 0 establishes the foundation only. No business logic, database, OAuth, Feishu, Cerbos or user/session endpoints are implemented yet.

Implemented:

- Go module `github.com/GravelEvolution/united-pass/backend`
- Entry point at `cmd/api/main.go`
- Typed, validated configuration (`internal/config`)
- Structured logging with `log/slog` (`internal/platform/observability`)
- `http.Server` with configurable timeouts
- Chi router with standard `net/http` middleware interfaces
- Request ID middleware (accepts valid upstream IDs or generates cryptographically random ones)
- Panic recovery middleware
- Structured access logging middleware
- Security response headers
- Request body size limit
- Unified API error envelope matching the frontend contract
- `GET /healthz` and `GET /readyz` (extensible readiness checks, no dependencies in Phase 0)
- Graceful shutdown via `SIGINT`/`SIGTERM`
- ADR-0001 documenting the foundation architecture
- GitHub Actions CI workflow
- Tests covering health endpoints, request IDs, error envelope, panic recovery, body limits, config validation and graceful shutdown

Not yet implemented (later phases):

- Authentication, sessions, CSRF, `GET /api/v1/me`
- OAuth Application and Client management
- Consent orchestration
- Account security (password, TOTP, Passkeys, recovery codes)
- Identity, workforce, departments
- Feishu Provider synchronization
- Cerbos policies and audit
- PostgreSQL persistence and migrations
- OpenAPI specification

## Relationship with `../frontend/`

The frontend directory is the frozen source of truth for API contracts, request/response field names, error structures, cursor pagination, permission capabilities, OAuth Application/Client models, cookie and CSRF conventions. The backend implements to that contract.

Key references:

- `../frontend/docs/frontend-freeze-v1.md` — frozen feature list and API path set
- `../frontend/docs/api-contracts.md` — detailed request/response contracts
- `../frontend/docs/adr-0004.md` — API client layer and error handling
- `../frontend/docs/adr-0005.md` — Application and OAuth Client separation
- `../frontend/docs/adr-0006.md` — deployment topology and cookie/CSRF names

Cookie names (per ADR-0006):

- Session cookie: `up_session` (HttpOnly)
- CSRF cookie: `up_csrf` (readable by JS)
- CSRF header: `X-CSRF-Token`

The backend must never silently implement a different API contract from the frontend. Conflicts are reported before changes are made.

## Architecture

See `docs/adr-0001.md` for the full foundation architecture decision record.
