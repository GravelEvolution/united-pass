# United Pass Backend Engineering Rules

This file applies to all files under `backend/` unless a more specific `AGENTS.md` exists in a nested directory.

United Pass is a security-sensitive unified identity, account, organization, OAuth application, authorization, Provider synchronization, and audit platform.

The backend must prioritize:

* Correctness
* Security
* Explicit domain boundaries
* Stable API contracts
* Auditable behavior
* Maintainable Go code
* Compatibility with the frozen frontend contract

Do not optimize for rapid code generation at the expense of identity integrity, security, or maintainability.

## 1. Repository Access and Required Reading

The backend Agent is explicitly allowed and expected to read files outside `backend/` when they are relevant to the backend contract.

In particular, the Agent may read:

```text
../frontend/
```

The frontend directory is the primary source of truth for:

* Existing user-facing behavior
* API contracts
* Request and response field names
* Error structures
* Cursor pagination
* Permission capabilities
* OAuth Application and Client models
* Cookie and CSRF conventions
* Accepted frontend ADRs
* Mock behavior that the backend must replace

Before implementing backend behavior, read the relevant frontend files.

At the beginning of backend work, always inspect:

```text
../frontend/docs/frontend-freeze-v1.md
../frontend/docs/api-contracts.md
../frontend/docs/adr-0004.md
../frontend/docs/adr-0005.md
../frontend/docs/adr-0006.md
../frontend/src/lib/api/united-pass-data-source.ts
../frontend/src/types/
```

When implementing a particular feature, also inspect its corresponding frontend:

```text
../frontend/src/features/
../frontend/src/app/
../frontend/src/lib/api/
```

Examples:

* For account APIs, read `../frontend/src/features/account/`.
* For OAuth Application APIs, read `../frontend/src/features/applications/`.
* For consent APIs, read `../frontend/src/features/authorization/`.
* For Provider APIs, read the Provider administration components and types.
* For policy APIs, read `../frontend/src/features/policies/`.
* For audit APIs, read the audit page, filters, and types.

### Frontend Modification Boundary

Reading `../frontend/` is permitted by default.

Do not modify files under `../frontend/` unless the user explicitly requests a frontend change or a contract synchronization change.

When a backend implementation reveals a required frontend contract change:

1. Report the conflict immediately.
2. Explain why the current contract cannot be implemented safely or correctly.
3. Propose the smallest contract change.
4. Update the backend ADR first when the decision is architectural.
5. Modify frontend files only when explicitly permitted.
6. Keep the frontend contract, OpenAPI specification, and backend implementation synchronized.

Never silently implement a different API contract from the frontend.

## 2. Required Reading Order

Before writing or modifying backend code:

1. Read the nearest `AGENTS.md`.
2. Read `go.mod`.
3. Read existing backend ADRs under `docs/`.
4. Read `../frontend/docs/frontend-freeze-v1.md`.
5. Read `../frontend/docs/api-contracts.md`.
6. Read the relevant frontend types and feature components.
7. Inspect existing backend packages, tests, migrations, and OpenAPI definitions.
8. Search the repository for an existing implementation before creating a new abstraction.

The frontend freeze document and API contract are the current product contract.

Do not silently change:

* API paths
* Request fields
* Response fields
* Error codes
* Error structure
* Pagination behavior
* Cookie names
* CSRF behavior
* Permission capabilities
* OAuth Client profiles
* Consent behavior
* Identity invariants

## 3. Product Invariants

The following invariants must always hold.

### Stable User Identity

Every user has one stable United Pass user ID.

The stable user ID:

* Is generated and controlled by United Pass.
* Is not an email address.
* Is not a phone number.
* Is not a Feishu identifier.
* Does not change when the user becomes an employee.
* Remains stable when an external identity Provider changes.
* Is used as the primary internal identity reference.
* Is the basis of the OIDC subject exposed by United Pass.

### Consumer and Employee Personas

An employee is not a separate account.

The identity model is:

```text
User
├── Consumer persona
└── Optional employee profile
```

An external user who becomes an employee keeps the same stable user ID.

When an employee leaves:

* Employee access is revoked.
* Employee sessions and internal grants are revoked according to policy.
* The employee profile is marked inactive or departed.
* The consumer persona is preserved by default.
* Public application data remains associated with the same stable user ID.
* The entire account is not deleted unless a separate account-deletion process requires it.

### External Identity Linking

External identities must use an explicit identity-link model.

Conceptually:

```text
identity_links
- user_id
- provider
- provider_tenant_id
- provider_subject
- provider_user_id
- provider_union_id
- provider_open_id
```

Never silently merge identities using only:

* Email
* Phone number
* Display name
* Email domain
* Department
* Employee number

Ambiguous matches must create a resolvable identity-link conflict.

### Application and OAuth Client Separation

An Application and an OAuth Client are different resources.

```text
Application
├── Web OAuth Client
├── SPA OAuth Client
├── Mobile OAuth Client
└── Service OAuth Client
```

One Application may own multiple OAuth Clients.

Do not collapse Application and OAuth Client back into one entity.

### Scope and Business Authorization

OAuth Scopes describe delegated data access.

OAuth Scopes do not grant business-management permissions.

Business authorization is evaluated and enforced separately through the backend authorization layer and Cerbos policies.

### Frontend Checks Are Not Security Controls

Frontend navigation visibility, disabled buttons, and permission labels are user-experience features only.

Every protected backend operation must independently:

1. Authenticate the caller.
2. Load authoritative attributes.
3. Authorize the requested action.
4. Enforce the decision.
5. Audit the operation when required.

## 4. Service Boundaries

Unless superseded by an accepted ADR, use the following ownership boundaries.

### Authentication and OAuth Provider

ZITADEL or the selected authentication provider owns protocol-level authentication behavior, including:

* Password credential verification
* Authentication sessions
* MFA
* Passkeys
* OAuth 2.0 protocol operations
* OpenID Connect
* Authorization codes
* Token issuance
* Refresh tokens
* JWKS
* Discovery metadata
* PKCE verification

Do not implement a new OAuth 2.0 or OpenID Connect authorization server from scratch in the United Pass Go service.

The backend may orchestrate, proxy, map, and extend provider functionality through reviewed adapters.

### United Pass Go Backend

The Go backend owns:

* Stable United Pass user identities
* Consumer and employee persona relationships
* Employee profiles
* Departments and organization relationships
* External identity links
* Identity Provider metadata
* Feishu organization synchronization
* Application metadata
* OAuth Client business metadata
* Consent orchestration
* Authorization grant views
* Permission capability calculation
* ABAC context construction
* Audit records
* Account administration
* APIs consumed by the frontend

### Cerbos

Cerbos is the policy decision point for ABAC authorization.

The Go backend must:

1. Authenticate the caller.
2. Load authoritative principal attributes.
3. Load authoritative resource attributes.
4. Construct a policy request.
5. Call Cerbos.
6. Enforce the returned decision.
7. Record relevant security events.

The frontend must never provide authoritative permission, department, employee, owner, role, or trust attributes.

### PostgreSQL

PostgreSQL stores United Pass domain data.

Authentication-provider internal data remains owned by the authentication provider unless an accepted ADR explicitly states otherwise.

## 5. Approved HTTP Stack

Use:

* `net/http` for the HTTP server, handlers, middleware contracts, and tests
* `github.com/go-chi/chi/v5` for routing and route composition
* `log/slog` for structured logging
* `net/http/httptest` for HTTP tests

Chi is the approved initial router.

Do not introduce another router or a full Web Framework such as:

* Gin
* Fiber
* Echo
* Beego
* Iris

without an accepted ADR and explicit approval.

All handlers and middleware must remain compatible with standard library types:

```go
http.Handler
http.HandlerFunc
func(http.Handler) http.Handler
```

Chi-specific types must remain inside the HTTP adapter and bootstrap layers.

Domain and application packages must not import Chi.

Route parameters may be read with `chi.URLParam` only in HTTP adapter code.

Use `http.Server` directly.

Configure at least:

* Address
* ReadHeaderTimeout
* ReadTimeout
* WriteTimeout
* IdleTimeout
* Maximum request-body sizes
* Graceful shutdown

Do not use bare `http.ListenAndServe` as production startup code.

## 6. Go Runtime and Module

Use the Go version declared in `go.mod`.

Do not upgrade or downgrade Go as an unrelated change.

The intended module path is:

```text
github.com/GravelEvolution/united-pass/backend
```

Run commands from `backend/`:

```bash
go mod tidy
go fmt ./...
go vet ./...
go test ./...
go test -race ./...
go build ./...
```

Never claim that a command passed unless it was actually executed successfully.

## 7. Project Structure

Use this direction unless an accepted ADR establishes another layout:

```text
backend/
├── cmd/
│   └── api/
│       └── main.go
├── internal/
│   ├── bootstrap/
│   ├── config/
│   ├── identity/
│   ├── account/
│   ├── workforce/
│   ├── organization/
│   ├── applications/
│   ├── consent/
│   ├── providers/
│   ├── policies/
│   ├── audit/
│   ├── adapters/
│   │   ├── httpapi/
│   │   ├── postgres/
│   │   ├── zitadel/
│   │   ├── cerbos/
│   │   └── feishu/
│   └── platform/
│       ├── clock/
│       ├── id/
│       └── observability/
├── migrations/
├── openapi/
├── docs/
├── tests/
│   ├── integration/
│   └── contract/
├── go.mod
└── go.sum
```

Do not create empty directories solely to imitate this structure.

Add packages only when they have a real responsibility.

Avoid generic dumping-ground packages such as:

```text
utils
helpers
common
models
services
misc
```

Every package must have a clear domain or infrastructure purpose.

## 8. Dependency Direction

Dependencies point inward:

```text
HTTP / PostgreSQL / Feishu / ZITADEL / Cerbos adapters
                            ↓
                     application use cases
                            ↓
                         domain rules
```

Domain packages must not import:

* HTTP handlers
* Chi
* SQL implementations
* Feishu SDKs
* ZITADEL SDKs
* Cerbos SDKs
* Environment-variable readers
* Logging implementations

HTTP handlers must not contain SQL.

Database adapters must not contain HTTP response logic.

External-provider adapters must not decide United Pass business authorization.

`cmd/api/main.go` must only:

* Load configuration
* Construct infrastructure
* Wire dependencies
* Start the server
* Handle graceful shutdown

Do not place business logic in `main.go`.

Define interfaces close to the application code that consumes them.

Do not create an interface merely to wrap every concrete type.

## 9. Domain Modeling

Prefer explicit domain types.

Avoid:

```go
map[string]any
```

for known domain data.

Prefer:

```go
type UserID string
type ApplicationID string
type OAuthClientID string
type DepartmentID string
type ProviderID string
type GrantID string
type SessionID string
```

Use typed status values and validate transitions.

Example:

```go
type UserStatus string

const (
	UserStatusPending  UserStatus = "pending"
	UserStatusActive   UserStatus = "active"
	UserStatusDisabled UserStatus = "disabled"
)
```

Invalid state transitions must be rejected before persistence.

Do not use persistence rows as HTTP response models.

Keep separate representations for:

* Domain entities
* Persistence rows
* API requests
* API responses
* External Provider payloads

## 10. API Contract

The backend API is versioned under:

```text
/api/v1
```

The current human-readable contract is:

```text
../frontend/docs/api-contracts.md
../frontend/docs/frontend-freeze-v1.md
```

When OpenAPI is introduced, the machine-readable contract belongs under:

```text
openapi/
```

The OpenAPI specification, frontend TypeScript contracts, documentation, and implementation must remain synchronized.

### JSON

Use JSON for ordinary API requests and responses.

Use multipart where required, such as avatar upload.

Set explicit request-body limits.

Reject malformed or oversized input.

Do not accept unknown fields when doing so could hide client mistakes or security-sensitive configuration errors.

### Error Format

Return errors in this shape:

```json
{
  "error": {
    "code": "session.reauthentication_required",
    "message": "请重新验证身份后继续。",
    "requestId": "req_01...",
    "fieldErrors": [
      {
        "field": "redirectUris[0]",
        "message": "该重定向地址无效。"
      }
    ]
  }
}
```

Requirements:

* `code` is stable and machine-readable.
* `message` is safe for user display.
* `requestId` supports troubleshooting and audit correlation.
* `fieldErrors` is an array.
* Internal implementation details are never exposed.

Do not expose:

* SQL messages
* Stack traces
* Internal hostnames
* Tokens
* Cookies
* Provider responses
* Secrets
* Raw internal errors

Use consistent status codes:

```text
400 malformed request
401 unauthenticated
403 unauthorized
404 resource not found or inaccessible
409 state, version, or uniqueness conflict
422 validation or domain rule failure
429 rate limited
5xx unexpected server failure
```

Do not return `200 OK` for failed operations.

### Cursor Pagination

Large collections use opaque cursor pagination.

```json
{
  "items": [],
  "page": {
    "nextCursor": null,
    "hasMore": false
  }
}
```

Cursors must:

* Be opaque to clients.
* Not expose raw offsets or sensitive keys.
* Bind the relevant sorting and filtering state.
* Be validated before use.

Do not load full production collections and filter them in memory.

### Request IDs

Every HTTP request must have a request ID.

Accept a valid upstream request ID or generate a new one.

Return the request ID in a response header.

Include it in:

* Structured logs
* API error responses
* Relevant audit records
* Calls to internal or external dependencies where appropriate

## 11. Session, Cookie, and CSRF Rules

Use the accepted names:

```text
Session Cookie: up_session
CSRF Cookie:    up_csrf
CSRF Header:    X-CSRF-Token
```

Do not introduce different names without updating:

* Backend ADRs
* Frontend constants
* Frontend API documentation
* Legal documentation

Session Cookies must use appropriate production settings:

* HttpOnly
* Secure
* Explicit SameSite behavior
* Restricted Path
* Appropriate lifetime
* Server-side revocation

The browser must not receive raw authentication-provider Refresh Tokens or long-lived authentication tokens.

All browser-originated state-changing requests using Cookie authentication require CSRF validation.

Safe HTTP methods must not mutate state.

Do not disable CSRF globally to make an endpoint pass.

## 12. Authentication and Account Security

Authentication errors must not reveal whether an account, email, or phone number exists.

Password-reset and recovery requests must return generic responses.

Apply rate limits to at least:

* Login
* MFA verification
* Registration
* Password-reset requests
* Email verification
* Phone verification
* Provider callbacks
* Consent decisions
* Client Secret rotation
* Policy simulation when abuse is possible

Never log:

* Passwords
* TOTP secrets
* Recovery codes
* Authorization codes
* Access Tokens
* Refresh Tokens
* ID Tokens
* Client Secrets
* Provider Secrets
* Verification codes

High-risk operations must support reauthentication.

Examples:

* Password changes
* MFA removal
* Recovery-code generation
* Client Secret rotation
* Application deletion
* Policy publication
* Employee offboarding
* Bulk session revocation
* Identity Provider enabling

## 13. OAuth 2.0 and OpenID Connect

Never weaken protocol validation for convenience.

Required protections include:

* Exact Redirect URI validation
* State validation
* Nonce validation for OIDC
* PKCE for public clients
* Authorization-code expiry
* Single-use authorization codes
* Client authentication
* Scope validation
* Audience validation
* Issuer validation
* Token expiry
* Replay protection where applicable

Public clients must not receive Client Secrets.

Client Secrets:

* Use cryptographically secure randomness.
* Are displayed only once.
* Are never stored in plaintext after creation.
* Are returned later only as safe metadata.
* Support controlled rotation and overlap periods.
* Must not be returned by list or detail endpoints.

Creating an Application and its initial OAuth Client must be atomic.

Service-to-service clients using Client Credentials:

* Do not require Redirect URIs.
* Do not use user consent.
* Do not receive a user subject.
* Must not request `openid`.

Do not reintroduce `trusted_first_party` consent bypass until the backend implements:

* Explicit trust-management permission
* Reauthentication
* Audit logging
* Policy validation
* An accepted ADR

## 14. Authorization and Cerbos

Every protected use case must have an explicit action.

Examples:

```text
user.read
user.disable
employee.manage
employee.offboard
department.manage
application.read
application.manage
application.secret.rotate
policy.read
policy.manage
policy.publish
audit.read
audit.export
provider.read
provider.manage
```

Do not use broad checks such as:

```go
if user.Role == "admin"
```

Build authorization context from authoritative backend data.

Relevant attributes may include:

* Stable user ID
* Employee status
* Department ID
* Organization path
* Application ownership
* Provider tenancy
* Resource status
* Requested action
* Reauthentication state

The backend must enforce the final decision before performing a mutation.

Frontend permission capabilities are a summary for user experience and are not authoritative.

## 15. PostgreSQL and Migrations

Use schema migrations for all database changes.

Migrations must:

* Be committed with dependent code.
* Have deterministic ordered versions.
* Be reviewable.
* Avoid destructive changes without a migration plan.
* Avoid silently dropping data.
* Add database constraints for important invariants.

Use constraints where practical for:

* External identity-link uniqueness
* Employee-number uniqueness within its scope
* Application and Client ownership
* Organization relationships
* Version uniqueness
* Idempotency-key uniqueness
* Grant ownership
* Session ownership

Do not automatically execute destructive production migrations at process startup.

Select the migration tool through an ADR before committing the first persistent schema.

## 16. Transactions, Concurrency, and Idempotency

Use transactions when multiple changes must succeed or fail together.

Examples:

* Application plus initial OAuth Client creation
* Employee-profile linking
* Employee offboarding and access revocation
* Consent decision and grant creation
* Client Secret rotation
* Policy publication and version creation
* Provider conflict resolution
* Security-sensitive mutation plus audit record

Do not return success before durable commit.

Use optimistic concurrency or version checks for editable versioned resources such as policy drafts.

Long-running operations must use explicit jobs:

* Feishu directory synchronization
* Audit export
* Data export
* Bulk revocation

Do not keep an HTTP request open for long-running work.

Use idempotency where duplicate execution would be harmful.

## 17. Feishu Provider and Directory Synchronization

Feishu login and organization synchronization are separate capabilities.

### Login Provider

The Provider proves an external identity.

It does not directly grant:

* Employee status
* Department membership
* Administrative permission
* Application ownership

### Directory Synchronization

Directory synchronization may import:

* Departments
* Department hierarchy
* Employees
* Employee numbers
* Positions
* Managers
* Employment status
* Provider identity references

Synchronization must be:

* Idempotent
* Tenant-aware
* Auditable
* Safe to retry
* Capable of reporting partial failures
* Capable of manual conflict resolution

Store Provider identifiers explicitly.

Do not use display names or email addresses as synchronization keys.

A conflict must not silently overwrite an existing United Pass identity link.

Provider credentials exist only in server-side secret storage.

The frontend may receive metadata such as:

```text
secretConfigured
lastValidatedAt
lastSyncAt
status
```

Never return Provider secrets to the frontend.

## 18. Configuration and Secrets

Load configuration through one typed configuration package.

Validate required configuration at startup.

Do not scatter `os.Getenv` calls throughout the codebase.

Local development may use an ignored environment file.

Never commit:

* Database passwords
* Cookie signing keys
* Encryption keys
* OAuth Client Secrets
* Provider Secrets
* SMTP credentials
* SMS credentials
* ZITADEL management tokens
* Cerbos credentials
* Private keys

Do not use weak production fallback secrets.

Fail startup when required production secrets are missing.

## 19. Logging, Metrics, and Audit

Use structured logging with `log/slog` unless an accepted ADR selects another implementation.

Log fields may include:

* Request ID
* Route
* Method
* Status
* Duration
* Actor ID
* Target ID
* Event type
* Result
* Error code

Never log:

* Passwords
* Authorization headers
* Cookies
* Tokens
* Authorization codes
* Verification codes
* TOTP secrets
* Recovery codes
* Client Secrets
* Provider Secrets
* Full sensitive request bodies

Operational logs and audit records are separate systems.

Audit meaningful security and administration events, including:

* Login outcomes
* MFA changes
* Session revocation
* Consent decisions
* Grant revocation
* Application and Client changes
* Secret rotation
* User enable and disable
* Employee onboarding and offboarding
* Provider synchronization
* Identity-link conflict resolution
* Policy publication
* Audit export requests

Audit payloads must be intentionally designed and redacted.

## 20. HTTP Server Requirements

The HTTP server must include:

* Graceful shutdown
* Read timeout
* Read-header timeout
* Write timeout
* Idle timeout
* Request-body limits
* Panic recovery
* Request-ID middleware
* Structured access logging
* Security headers where appropriate
* Health endpoint
* Readiness endpoint

Operational endpoints:

```text
GET /healthz
GET /readyz
```

`/healthz` indicates that the process is alive.

`/readyz` indicates that required dependencies are ready.

Do not expose sensitive dependency details through public health responses.

## 21. Dependency Policy

Prefer the standard library where it provides a clear implementation.

Approved initial dependencies include:

```text
github.com/go-chi/chi/v5
```

Before adding a substantial dependency such as:

* ORM
* SQL builder
* Migration framework
* Dependency-injection framework
* Validation framework
* Background-job framework
* Authentication SDK
* Policy SDK
* Feishu SDK

the Agent must:

1. Check whether the existing stack can satisfy the requirement.
2. Review maintenance and security implications.
3. Explain the reason to the user.
4. Record the decision in an ADR when architectural.
5. Avoid overlapping libraries.

Do not add a large framework merely to reduce a small amount of explicit Go code.

## 22. Testing Requirements

Tests accompany behavior.

### Unit Tests

Prioritize:

* Domain validation
* State transitions
* OAuth Client-profile rules
* Consent behavior
* Identity-link rules
* Employee onboarding and offboarding
* Cursor encoding and decoding
* Error mapping
* Authorization-context construction
* Provider conflict resolution

### HTTP Tests

Test:

* Request parsing
* Authentication requirements
* Authorization denial
* Field errors
* Status codes
* Error envelopes
* CSRF behavior
* Rate limiting
* Request IDs
* Body-size limits
* Panic recovery

### Repository Integration Tests

Test repository behavior against a real PostgreSQL-compatible test environment.

Test:

* Transactions
* Constraints
* Pagination ordering
* Concurrent updates
* Version conflicts
* Idempotency
* Rollbacks

### Contract Tests

Backend responses must match:

```text
../frontend/docs/api-contracts.md
../frontend/docs/frontend-freeze-v1.md
```

and OpenAPI once introduced.

Every security fix requires a regression test.

Do not delete or weaken tests merely to make CI pass.

## 23. Go Code Quality

Follow standard Go conventions.

Requirements:

* Format all code.
* Handle errors explicitly.
* Wrap errors with useful context.
* Use `errors.Is` and `errors.As` where appropriate.
* Accept `context.Context` for request-scoped and cancellable operations.
* Pass context through repository and Provider calls.
* Do not store request contexts in structs.
* Do not start unbounded goroutines.
* Close resources deterministically.
* Avoid global mutable state.
* Avoid package-level service locators.
* Avoid `panic` for ordinary application errors.
* Prefer typed options over unclear boolean arguments.
* Keep exported APIs small.
* Explain why, not what, in non-obvious comments.

Do not suppress compiler, vet, race, or static-analysis problems without a narrow documented reason.

## 24. Progress Updates

Keep the user informed during multi-step work.

Before substantial work:

* Summarize the goal.
* State which frontend contract or ADR governs it.
* Identify important assumptions.

During work:

* Report meaningful milestones.
* Report architecture conflicts immediately.
* Report security findings immediately.
* Report partial working results when available.
* Do not narrate every trivial command.

After work:

* Summarize implemented behavior.
* List important files changed.
* List checks actually executed.
* State checks that could not be executed.
* State remaining risks and follow-up work.

Never claim a test, build, migration, or commit succeeded unless it actually did.

## 25. Git Branch Rules

Work on the currently checked-out branch by default.

Do not create, rename, or switch branches unless the user explicitly requests it.

Never automatically create branches such as:

```text
codex/*
agent/*
ai/*
feature/*
```

Do not create a `codex/` branch unless the user explicitly requests that exact branch.

Do not:

* Force-push
* Rebase shared history
* Reset or discard user changes
* Amend existing commits without approval
* Stage unrelated files
* Use destructive Git commands without approval

Inspect the current branch, `git status`, and the relevant diff before every commit.

## 26. Commit Rules

Create commits regularly after coherent units of work are complete.

Use Conventional Commits:

```text
type(scope): concise imperative summary
```

Examples:

```text
chore(backend): scaffold api service
docs(adr): define backend service boundaries
feat(identity): add stable user model
feat(auth): establish browser session
feat(applications): create application with initial client
feat(provider): synchronize feishu directory
feat(policy): integrate cerbos decisions
fix(consent): reject replayed authorization decision
test(identity): cover employee offboarding
```

Do not use vague messages such as:

```text
update
changes
fix stuff
wip
backend work
```

After each commit, report:

* Commit hash
* Commit message
* Main contents
* Checks executed

Do not mix unrelated work into one commit.

## 27. Architecture Decision Records

Store backend ADRs under:

```text
docs/adr-{version}.md
```

Because this file is inside `backend/`, the full repository path is:

```text
backend/docs/adr-{version}.md
```

Use increasing zero-padded versions:

```text
docs/adr-0001.md
docs/adr-0002.md
docs/adr-0003.md
```

Before creating an ADR:

1. Inspect existing ADRs.
2. Determine the latest version.
3. Decide whether to update, supersede, or create a decision.
4. Avoid duplicate ADRs.

Use this structure:

```markdown
# ADR-{version}: Decision title

- Status: Proposed | Accepted | Superseded | Deprecated
- Date: YYYY-MM-DD
- Owners: United Pass backend team

## Context

## Decision

## Alternatives Considered

## Consequences

## Security Considerations

## Implementation Notes

## Follow-up
```

Create or update ADRs for material choices involving:

* Backend package boundaries
* Chi routing structure
* ZITADEL integration
* Cerbos integration
* PostgreSQL access
* Migration tooling
* OpenAPI generation
* Session architecture
* Cookie and CSRF behavior
* ID generation
* Secret storage
* Background jobs
* Feishu synchronization
* Audit durability
* Deployment topology

Do not create ADRs for trivial formatting, renames, or typo fixes.

Code and ADRs must remain synchronized.

Include an ADR in the same coherent commit as the implementation it governs whenever practical.

## 28. Documentation

Update documentation whenever a change affects:

* API paths
* Requests or responses
* Error codes
* Environment variables
* Cookie behavior
* Permissions
* Database schema
* OAuth Client behavior
* Provider synchronization
* Policy behavior
* Deployment
* Development commands

The OpenAPI specification, frontend contract, backend documentation, and implementation must not knowingly contradict each other.

## 29. Definition of Done

A backend task is complete only when:

* Requested behavior is implemented.
* Product invariants are preserved.
* Authentication is enforced.
* Authorization is enforced.
* Input is validated.
* Errors follow the standard envelope.
* Sensitive data is not exposed or logged.
* Transactions are used where required.
* Audit behavior is implemented where required.
* Tests cover the behavior.
* Code is formatted.
* `go vet ./...` passes.
* `go test ./...` passes.
* `go test -race ./...` passes when practical.
* `go build ./...` passes.
* API and ADR documentation are synchronized.
* A coherent Conventional Commit is created.
* The user receives a truthful summary.

## 30. Initial Implementation Order

Do not implement the entire backend in one change.

Use this order unless the user explicitly changes priorities.

### Phase 0: Foundation

* Correct Go Module path
* Move entry point to `cmd/api/main.go`
* Configuration loading
* Structured logging
* Chi Router
* Configured `http.Server`
* Graceful shutdown
* Request IDs
* Panic recovery
* Access logging
* API-error envelope
* `/healthz`
* `/readyz`
* Backend CI
* Initial OpenAPI skeleton
* ADR-0001 for backend boundaries

### Phase 1: Session and Current User

* Authentication-provider adapter
* Session establishment
* Session Cookie
* CSRF validation
* Logout
* `GET /api/v1/me`
* Permission capabilities
* Current-user authorization

### Phase 2: Application and OAuth Client

* PostgreSQL schema
* Application model
* OAuth Client model
* Atomic Application plus initial Client creation
* Client-profile validation
* Secret creation and rotation
* List and detail APIs
* Cursor pagination

### Phase 3: Authorization Consent

* Authorization transaction lookup
* Login resume
* Consent allow and deny
* Replay protection
* Grant creation
* Safe Redirect URI handling

### Phase 4: Account Security

* Profile updates
* Avatar processing
* Sessions
* Password change orchestration
* TOTP
* Passkeys
* Recovery codes
* Contact verification

### Phase 5: Identity and Workforce

* User administration
* Employee profiles
* Departments
* Employee linking
* Offboarding
* Access revocation

### Phase 6: Feishu Provider

* Login Provider adapter
* Directory synchronization
* Sync history
* Conflict resolution
* Manual identity linking
* Reconciliation jobs

### Phase 7: Policies and Audit

* Cerbos integration
* Permission context
* Policy simulation
* Policy publication
* Audit persistence
* Audit filtering
* Audit export jobs

Do not begin a later phase by bypassing security, API-contract, or infrastructure requirements from an earlier phase.
