<!-- BEGIN:nextjs-agent-rules -->

# This is NOT the Next.js you know

This version has breaking changes — APIs, conventions, and file structure may all differ from your training data. Read the relevant guide in `node_modules/next/dist/docs/` (resolved from this file's directory; in monorepos the `next` package may not be visible from the repo root) before writing any code. Heed deprecation notices.

This block is written and re-added by `next dev` — verify at `node_modules/next/dist/server/lib/generate-agent-files.js`. Removing it from a diff only re-creates the uncommitted change; committing it with your work keeps the tree clean.

<!-- END:nextjs-agent-rules -->
# United Pass Frontend Engineering Rules

This directory contains the frontend for **United Pass**, the company's unified identity, account, application, and access-management product.

These instructions apply to all files under `frontend/` unless a more specific `AGENTS.md` exists in a nested directory.

## 1. Product Context

United Pass serves two categories of users:

* Internal employees
* External users, including ordinary product users

A user may begin as an external user and later become an employee. This transition must preserve the same underlying account and stable user identity.

The frontend may eventually include:

* Sign-in and registration
* OAuth 2.0 / OpenID Connect authorization consent
* User account center
* Security and session management
* Employee and department management
* OAuth application management
* External identity Provider management
* Fine-grained authorization policy management
* Audit and security event views

The initial protocol scope is:

* OAuth 2.0
* OpenID Connect

Do not add CAS, SAML, LDAP, SCIM, or identity-federation functionality unless explicitly requested.

## 2. Required Technology Stack

Use the technologies already configured in this project.

The intended frontend stack is:

* Next.js with App Router
* React
* TypeScript
* Semi Design
* CSS Modules and CSS variables
* pnpm

Before adding a library:

1. Check whether the requirement can be met with the existing dependencies.
2. Check the installed Next.js documentation under `node_modules/next/dist/docs/`.
3. Explain the purpose of any substantial new dependency in the change summary.
4. Avoid adding libraries that duplicate existing functionality.

Do not replace Next.js, React, Semi Design, or pnpm without explicit approval.

Do not introduce Tailwind CSS, another full UI framework, or a second design-token system unless explicitly requested.

## 3. Package Manager and Runtime

Use the package manager indicated by the existing lockfile and `package.json`.

For this project:

* Prefer `pnpm`.
* Never generate `package-lock.json` or `yarn.lock`.
* Do not delete or regenerate `pnpm-lock.yaml` without a dependency-related reason.
* Do not upgrade Node.js, Next.js, React, TypeScript, or Semi Design as an unrelated change.
* Respect the Node.js version files and `engines` field when present.
* Never assume globally installed command-line tools are available.

Run package scripts through pnpm:

```bash
pnpm dev
pnpm build
pnpm lint
pnpm test
```

Use the scripts declared in `package.json` instead of inventing replacement commands.

## 4. Read Before Editing

Before making changes:

1. Read the nearest `AGENTS.md`.
2. Read `package.json`.
3. Inspect the relevant route, feature, component, and type definitions.
4. Inspect the installed Next.js documentation for APIs that will be used.
5. Search the codebase for an existing implementation before creating a new abstraction.
6. Confirm whether the file is a Server Component or Client Component.

Do not rely on remembered Next.js behavior when installed documentation is available.

Do not modify generated files unless the generating tool or project workflow requires it.

## 5. Application Architecture

Prefer a feature-oriented structure with clear boundaries.

A recommended direction is:

```text
src/
├── app/
├── components/
│   ├── common/
│   └── layouts/
├── features/
├── lib/
│   ├── api/
│   ├── auth/
│   ├── query/
│   └── utils/
├── styles/
└── types/
```

### `src/app`

Contains routing, layouts, route-level loading states, error boundaries, metadata, and route composition.

Route files should remain thin. Do not place large business workflows directly in `page.tsx` or `layout.tsx`.

### `src/features`

Contains product-domain functionality.

Examples:

```text
features/
├── account/
├── applications/
├── authorization/
├── departments/
├── employees/
├── policies/
├── security/
├── sessions/
└── users/
```

A feature may contain:

```text
feature-name/
├── api/
├── components/
├── hooks/
├── schemas/
├── types/
└── utils/
```

Do not create every subdirectory preemptively. Add them only when the feature needs them.

### `src/components/common`

Contains genuinely reusable, product-agnostic components.

Do not move a component into `common` merely because it is used twice. Keep domain-specific components inside their feature.

### `src/components/layouts`

Contains shared page shells and structural layouts, such as:

* Authentication shell
* Account-center shell
* Administration shell

### `src/lib`

Contains infrastructure and integration code, not product-domain UI.

Examples include:

* API client configuration
* Authentication client integration
* Query client configuration
* Date and formatting helpers
* Environment configuration
* Generic utility functions

### `src/types`

Use this directory only for types shared across multiple unrelated features.

Keep feature-specific types next to the feature that owns them.

## 6. Server and Client Components

Use Server Components by default.

Add `"use client"` only when the component requires client-side behavior such as:

* React state
* React effects
* Browser-only APIs
* Event handlers
* Client-side navigation hooks
* Semi Design components that require client execution
* Client-side data libraries

Keep the client boundary as low as reasonably possible.

Do not mark an entire page or layout as a Client Component merely because one nested control is interactive.

When a Client Component grows large, separate it into:

* A Server Component responsible for data and composition
* A smaller Client Component responsible for interaction

Never import server-only modules into Client Components.

Never expose secrets, private environment variables, database access, or privileged backend credentials to the browser bundle.

## 7. TypeScript Requirements

All new source code must use TypeScript.

Follow these rules:

* Keep TypeScript strict.
* Do not weaken compiler settings to make an error disappear.
* Avoid `any`.
* Use `unknown` for untrusted values and narrow it safely.
* Do not use `as any`.
* Avoid broad type assertions.
* Prefer discriminated unions for states and variants.
* Prefer explicit domain types over unstructured dictionaries.
* Use `satisfies` when validating object shapes without losing inference.
* Use `import type` for type-only imports.
* Do not use TypeScript enums unless interoperability requires them.
* Prefer string literal unions or constant objects.
* Model nullable and optional fields intentionally.
* Do not use non-null assertions unless the invariant is clearly established.

Bad:

```ts
const user = response as any;
```

Preferred:

```ts
const result: unknown = await response.json();
const user = userSchema.parse(result);
```

Names must communicate domain meaning. Avoid vague identifiers such as:

```text
data
info
item
obj
temp
handler
```

when a more specific name is available.

## 8. React Requirements

Use functional components and hooks.

Follow these rules:

* Keep render logic pure.
* Do not trigger network requests or mutations during render.
* Do not store derived values in state.
* Prefer composition over large collections of boolean props.
* Keep effects narrowly scoped.
* Avoid using `useEffect` for ordinary data transformation.
* Do not duplicate server state into local state without a clear reason.
* Use stable keys based on entity identifiers.
* Do not use array indexes as keys for mutable lists.
* Keep forms and mutation states explicit.
* Prevent accidental duplicate submissions.
* Display actionable error messages.
* Preserve user-entered form data after recoverable errors.

Do not prematurely add a global state manager.

Use, in order of preference:

1. URL state
2. Server-rendered data
3. Component state
4. Context for a genuinely shared local concern
5. A global state library only after a demonstrated need

## 9. Next.js Routing Conventions

Use the App Router conventions supported by the installed Next.js version.

Prefer route groups to separate major product surfaces without changing URLs:

```text
app/
├── (auth)/
├── (account)/
└── (admin)/
```

Keep URLs stable, readable, and resource-oriented.

Examples:

```text
/login
/register
/authorize
/account
/account/security
/account/sessions
/admin
/admin/users
/admin/employees
/admin/departments
/admin/applications
/admin/policies
/admin/audit
```

Use dynamic route names that describe the resource:

```text
[applicationId]
[userId]
[policyId]
```

Avoid vague dynamic segment names such as `[id]` when the resource type is known.

Every substantial route should consider:

* `loading.tsx`
* `error.tsx`
* Empty state
* Unauthorized state
* Not-found state

Do not redirect unauthorized users only in client-side effects when server-side enforcement is possible.

## 10. Semi Design Requirements

Use Semi Design as the primary component system.

Prefer existing Semi components before building replacements for:

* Buttons
* Inputs
* Selects
* Tables
* Forms
* Modals
* Side sheets
* Navigation
* Notifications
* Tooltips
* Tabs
* Tags
* Avatars
* Skeletons
* Empty states

Do not wrap every Semi component in a custom abstraction.

Create wrappers only when they provide meaningful project-wide behavior, such as:

* Permission-aware actions
* Standardized destructive confirmations
* Standard page headers
* Standard entity-status displays
* Shared application branding

Use Semi Design tokens and CSS variables rather than copying fixed colors throughout the project.

Avoid deep selectors that depend on Semi Design's internal DOM structure or unstable class names.

When component behavior is unclear, consult the installed package types and official component API rather than guessing.

## 11. Styling Requirements

Use:

* Semi Design tokens
* CSS variables
* CSS Modules
* Minimal global CSS

Do not introduce:

* Inline hard-coded colors throughout the codebase
* Large global stylesheets for feature-specific UI
* CSS selectors tied to fragile generated class names
* Arbitrary `z-index` values without an established scale
* Multiple competing spacing or color systems

Inline styles are acceptable for small dynamic values, but reusable layout and visual rules should live in CSS Modules.

Design for:

* Desktop administration interfaces
* Smaller laptop displays
* Mobile account and authentication flows

Do not assume all users have a 1440-pixel-wide display.

Important pages must remain usable at common viewport widths.

## 12. Design and UX Principles

United Pass is a security-sensitive product. Interfaces must prioritize clarity over decoration.

Use concise and explicit language for:

* Permissions
* Consent
* Session revocation
* Account disabling
* Employee onboarding and offboarding
* OAuth client secrets
* Redirect URI configuration
* Destructive actions
* Policy decisions

A destructive action must clearly state:

* What will change
* Which users or applications are affected
* Whether the action is reversible
* Whether sessions or credentials will be revoked

Do not use generic confirmation copy such as:

```text
Are you sure?
```

Prefer:

```text
Disable this user and revoke all active sessions?
```

Never display a client secret again after its one-time creation view unless the backend explicitly supports retrieval, which it normally should not.

Use empty states that explain the next meaningful action.

Do not show fake success states before an operation has completed.

## 13. Identity Model Requirements

Do not model employee and external-user identities as unrelated accounts.

A single user may have multiple personas:

```ts
type UserPersona = "consumer" | "employee";
```

The stable user identifier must not change when an external user becomes an employee.

The frontend should represent the model as:

```text
User
├── Consumer capabilities
└── Employee profile, when present
```

Do not assume that every user has an employee profile.

Do not assume that an employee loses access to public-user functionality.

Do not use email addresses as stable user identifiers.

Do not infer employee status solely from an email domain.

## 14. OAuth and OpenID Connect Boundaries

The frontend must not implement OAuth or OpenID Connect protocol logic from scratch.

Use a reviewed client integration when real authentication is introduced.

Never:

* Store client secrets in frontend code
* Put private OAuth clients in browser-only applications
* Disable `state` validation
* Disable `nonce` validation
* Disable PKCE
* Accept arbitrary redirect URLs
* Treat an ID Token as an API Access Token
* Treat an Access Token as proof of user identity without validation
* Store long-lived credentials in insecure browser storage without an explicit architecture decision
* Log authorization codes, Access Tokens, Refresh Tokens, ID Tokens, passwords, or secrets

OAuth authorization and consent pages must display:

* Requesting application
* Requested permissions
* User identity currently in use
* Allow and deny actions
* Clear consequences of granting access

Do not claim that a Scope grants a business permission. OAuth Scopes and application-level ABAC permissions are separate concepts.

### External Identity Provider Management

The administration surface includes `/admin/providers` for external identity Provider inventory and lifecycle management.

The first planned vendor Provider is **Feishu (飞书)**. Until a backend contract and security review are complete:

* Represent Feishu as `planned` and keep login disabled.
* Do not claim that Feishu authentication, account linking, or organization synchronization is implemented.
* Keep Provider management separate from OAuth application management; an external identity source is not a client application registered against United Pass.
* Never expose Provider client secrets, vendor access tokens, signing material, callback credentials, or raw claims to browser code.
* Perform authorization redirects, callback validation, code exchange, replay protection, and credential rotation on the backend.
* Require exact allowlisted callback URLs and the protocol protections applicable to the reviewed integration.
* Link external subjects to the existing stable `userId` through an explicit, auditable flow. Never merge accounts solely by email address, phone number, domain, or display name.
* Never infer employee status, department membership, roles, or management permissions directly from Feishu attributes without an explicit backend policy and reviewed mapping.
* Treat frontend Provider visibility and controls as UX only; the backend remains authoritative for configuration access, activation, linking, and authorization.

Do not expand the Provider scope to SAML, CAS, LDAP, SCIM, directory synchronization, or other federation protocols without a further explicit request and a new or updated ADR.

## 15. Authorization UI Requirements

United Pass intends to support fine-grained attribute-based access control.

Frontend permission checks are for user experience only.

They may be used to:

* Hide unavailable navigation
* Disable unavailable controls
* Explain why an action is unavailable

They must never be treated as the actual security boundary.

Every protected action must also be enforced by the backend.

Prefer explicit permission identifiers:

```text
application.read
application.manage
employee.invite
employee.disable
policy.publish
audit.read
```

Do not spread raw role-name comparisons throughout components.

Bad:

```tsx
if (user.role === "admin") {
  // ...
}
```

Preferred:

```tsx
if (permissions.canManageApplications) {
  // ...
}
```

The backend remains authoritative.

## 16. API Integration Requirements

Keep API access behind a clearly defined client layer.

Components should not construct API URLs repeatedly.

Prefer:

```text
src/lib/api/
src/features/<feature>/api/
```

The API layer must:

* Handle the configured API base URL
* Send credentials only when required
* Parse successful responses
* Normalize errors
* Support request cancellation where appropriate
* Preserve typed response contracts
* Avoid leaking transport details into UI components

Use OpenAPI-generated types or clients when the backend contract becomes available.

Do not manually duplicate backend schemas across many frontend files.

Validate untrusted runtime data at important trust boundaries when generated validation is not available.

Do not silently ignore unknown API errors.

Map backend errors into user-facing messages without exposing sensitive implementation details.

## 17. Mocking Policy

Do not introduce mock APIs, fake authentication, hard-coded product records, MSW, local JSON databases, or placeholder authorization behavior unless explicitly requested.

When mock implementation is requested later:

* Keep mock data outside page components.
* Preserve the same interface expected from the real API layer.
* Make it easy to replace mocks with the real backend.
* Clearly mark mock-only code.
* Never let mock authorization behavior be mistaken for a security implementation.

Until then, focus on project structure, reusable UI, contracts, and static page composition only when requested.

## 18. Environment Variables

Document all public environment variables in an example environment file when introduced.

Browser-exposed variables must use the prefix required by Next.js.

Never expose:

* OAuth client secrets
* Signing keys
* Database credentials
* Management API tokens
* Encryption keys
* SMTP passwords
* Internal service credentials

Access environment variables through a centralized configuration module when possible.

Validate required environment variables at startup or build time.

Do not scatter direct `process.env` access throughout feature code.

## 19. Error Handling

Every asynchronous screen must consider:

* Initial loading
* Empty result
* Recoverable failure
* Permission denied
* Authentication required
* Unexpected failure
* Retry behavior

Errors should be useful but must not expose:

* Stack traces
* SQL messages
* Internal hostnames
* Token contents
* Secret identifiers
* Private policy details
* Raw backend exceptions

Use route-level error boundaries for unexpected failures and component-level states for expected API errors.

Log technical details only through the approved logging mechanism.

## 20. Accessibility

All interactive elements must be keyboard accessible.

Requirements include:

* Use semantic HTML.
* Provide accessible names for icon-only controls.
* Associate labels with form fields.
* Preserve visible focus indicators.
* Do not rely on color alone to express status.
* Provide descriptive error messages.
* Use appropriate heading hierarchy.
* Ensure dialogs can be operated by keyboard.
* Return focus appropriately after modal interactions.
* Provide text alternatives for meaningful images.

Use buttons for actions and links for navigation.

Do not attach click handlers to non-interactive elements when a semantic element exists.

## 21. Security Requirements

Treat all frontend input and backend output as untrusted.

Do not:

* Render unsanitized HTML
* Use `dangerouslySetInnerHTML` without a reviewed requirement and sanitization strategy
* Put secrets in source code
* Commit `.env` files containing real credentials
* Log credentials or tokens
* Trust frontend authorization checks
* Build redirect URLs from unvalidated user input
* Display sensitive employee fields to unauthorized users
* Persist sensitive data longer than necessary

User-managed avatars must be file uploads, not user-entered external URLs. Accept only the explicitly supported raster formats, constrain bytes, dimensions, and total pixels, verify the actual file signature, and re-encode before preview or storage. SVG and other active formats are not allowed. Frontend validation is for early rejection only; the backend must independently decode, validate, strip metadata, re-encode, and serve the result from a controlled origin.

For links opened in a new tab, use the appropriate `rel` protection.

For external redirects, use an allowlist or backend-provided validated destination.

Sensitive actions should support re-authentication or stronger confirmation when the backend exposes that capability.

## 22. Data Privacy

Collect and display only data required by the current interface.

Employee information and ordinary-user information must remain clearly separated by access policy.

Avoid exposing fields such as:

* Employee number
* Department path
* Supervisor
* Internal status
* Security events
* Authentication factors
* Session details

unless the current user is authorized to view them.

Mask or truncate sensitive values where full display is unnecessary.

Do not place personal data in URLs, analytics event names, or browser logs.

## 23. Date and Time Handling

Backend timestamps should be treated as ISO 8601 values.

Keep transport values in UTC where possible and localize them only for display.

Use a centralized formatting helper rather than repeating locale logic across pages.

For security events, display enough information to avoid ambiguity:

* Full date
* Time
* Time zone or clearly localized presentation

Do not compare timestamps as formatted strings.

## 24. Forms and Validation

Use shared schemas when forms and API contracts represent the same domain model.

Validation must occur:

* In the browser for immediate usability
* Again on the backend for security and correctness

Frontend validation must not be treated as authoritative.

Forms must:

* Show field-level errors near the affected field
* Preserve entered values after validation failures
* Disable duplicate submission while pending
* Distinguish validation errors from network failures
* Clearly mark optional and required fields
* Use confirmation for destructive changes

Redirect URI forms must not silently normalize values in ways that change their security meaning.

## 25. Tables and Management Screens

Management tables should support the needs of the domain rather than adding controls automatically.

Consider:

* Search
* Filtering
* Pagination
* Sorting
* Empty states
* Loading states
* Column readability
* Row-level actions
* Bulk actions only when genuinely needed

Do not add bulk destructive actions without a clear product requirement.

Do not hide critical status information only inside a detail drawer.

Large datasets must eventually use server-side pagination rather than loading all records into the browser.

## 26. Performance

Avoid premature optimization, but follow sound defaults:

* Use Server Components where appropriate.
* Keep Client Components focused.
* Avoid unnecessary large dependencies.
* Avoid importing entire icon or utility libraries when selective imports are available.
* Prevent repeated requests for the same data.
* Use image optimization appropriately.
* Lazy-load heavy, non-critical interfaces.
* Keep administration pages responsive during mutations.

Do not memoize every value or callback automatically. Add memoization only when it solves a measured or obvious rendering problem.

## 27. Testing Requirements

When a test setup exists, add tests appropriate to the change.

Prioritize:

1. Domain utilities
2. Validation schemas
3. Permission-derived UI behavior
4. Forms with meaningful branching
5. Critical account and security flows
6. Regression tests for fixed bugs

Do not write tests that merely snapshot large component trees without checking behavior.

For authentication and authorization screens, test both allowed and denied paths.

Never disable or delete failing tests merely to make a change pass.

If testing infrastructure has not yet been configured, do not introduce an entire testing stack as an unrelated change.

## 28. Code Quality

Before considering work complete, run the relevant available checks:

```bash
pnpm lint
pnpm build
```

Also run tests and type-check scripts when they exist.

Fix errors introduced by the change.

Do not hide errors using:

* `eslint-disable` without a narrow justification
* `@ts-ignore`
* `@ts-nocheck`
* Broad type assertions
* Disabled build checks
* Suppressed promise rejections

Keep functions and components focused.

Extract helpers when they clarify domain behavior, not solely to reduce line count.

Comments should explain why a decision exists, not restate obvious code.

## 29. Naming Conventions

Use:

* `PascalCase` for React components and exported component types
* `camelCase` for variables and functions
* `SCREAMING_SNAKE_CASE` only for true constants
* `kebab-case` for route and general file names
* Domain-specific names for types and modules

Examples:

```text
application-detail.tsx
employee-status-tag.tsx
authorization-consent.tsx
session-list.tsx
```

Avoid generic component names such as:

```text
box.tsx
data.tsx
item.tsx
wrapper.tsx
manager.tsx
```

unless the abstraction is genuinely generic and well-defined.

## 30. Import Rules

Use the configured path alias for cross-feature and cross-directory imports.

Prefer relative imports only for nearby files within the same feature or component folder.

Avoid deep import chains such as:

```ts
../../../../../lib/api/client
```

Do not create barrel files that cause circular dependencies or hide expensive imports.

Avoid importing from another feature's internal implementation. Expose an intentional public boundary when cross-feature reuse is required.

## 31. Generated and External Code

Do not manually edit generated API clients, generated types, lockfiles, or framework-generated agent blocks unless required by their generating workflow.

When generated code must change:

1. Change its source definition.
2. Run the generator.
3. Commit the source and generated output together.

Do not copy substantial third-party source code into this repository.

Keep third-party license obligations in mind when adding assets or code.

## 32. Scope Discipline

Make the smallest coherent change that satisfies the request.

Do not:

* Reformat unrelated files
* Rename unrelated modules
* Upgrade dependencies opportunistically
* Replace existing architectural choices without approval
* Add speculative abstractions
* Implement unrequested backend behavior
* Add mock systems before they are requested
* Add CAS support
* Add a second UI framework
* Add premature micro-frontend architecture

If a broader refactor is genuinely necessary, explain why before performing it.

## 33. Documentation

Update documentation when a change introduces or alters:

* Routes
* Environment variables
* Development commands
* Authentication behavior
* Authorization behavior
* API contracts
* Project structure
* Major dependencies
* Architectural decisions

Keep README instructions executable and current.

For substantial architecture decisions, prefer a short ADR under the project's documentation directory when such a convention exists.

## 34. Definition of Done

A frontend task is complete when:

* The requested behavior is implemented.
* The change follows the installed Next.js version's documented conventions.
* Types are accurate.
* Loading, empty, error, and permission states are considered where applicable.
* Sensitive information is not exposed.
* Accessibility requirements are respected.
* Relevant tests pass when available.
* Linting passes.
* The production build passes.
* Documentation is updated when required.
* No unrelated dependency, formatting, or architecture changes are included.
* The final summary states what changed and which checks were run.

## 35. Agent Response Requirements

After changing code, report:

1. What was changed
2. Important architectural decisions
3. Files added or modified
4. Commands or checks executed
5. Any checks that could not be completed
6. Remaining risks or follow-up work

Never claim that a command, test, lint check, or build passed unless it was actually executed successfully.

## 36. Progress Updates

Keep the user informed throughout the task.

For work involving multiple files, architectural decisions, dependency changes, or commands that may take time:

* Send a concise update before beginning substantial work.
* Continue sending short updates after meaningful milestones.
* Report important findings as soon as they are discovered.
* Explain architectural decisions before or while applying them.
* Do not remain silent during long-running work.
* Do not report every trivial file operation or command.
* Group related implementation details into clear progress updates.

Updates should describe outcomes and decisions rather than low-level activity.

Good examples:

```text
The application shell and route structure are now in place. I am moving on to the shared Semi Design components and responsive behavior.
```

```text
I found that this page must be a Client Component because the selected Semi Design controls depend on browser-side interaction. The surrounding layout will remain server-rendered.
```

Never claim that work is complete, a command passed, or a commit was created unless it actually happened.

## 37. Git Workflow and Commits

Use Git carefully and keep the repository history understandable.

### Branch Rules

Do not create, rename, or switch to a new branch unless the user explicitly requests it.

In particular, never create automatically generated branches such as:

```text
codex/*
agent/*
ai/*
feature/*
```

Do not create a `codex/` branch under any circumstances unless the user explicitly asks for that exact branch.

Work on the currently checked-out branch by default.

Before making a commit:

1. Check the current branch.
2. Inspect `git status`.
3. Inspect the relevant diff.
4. Ensure unrelated user changes are not included.
5. Run the relevant checks when available.
6. Confirm that no credentials, tokens, `.env` secrets, generated junk, or temporary files are staged.

Do not:

* Reset or discard user changes.
* Amend an existing commit unless explicitly requested.
* Force-push.
* Rebase shared history.
* Use destructive Git commands without explicit permission.
* Stage unrelated files with broad commands when the working tree contains unrelated changes.
* Commit lockfile changes unless dependencies actually changed.
* Commit failing code while claiming it is complete.

### Commit Frequency

Create commits regularly as coherent units of work are completed.

A commit should represent one understandable change, such as:

* Project initialization
* Route architecture
* Shared layout implementation
* A single feature
* A design-system foundation
* Documentation or ADR updates
* A focused bug fix
* Test coverage for one behavior

Do not create a commit for every tiny edit.

Do not wait until a large unrelated set of changes has accumulated into one commit.

When possible, commit after:

1. A coherent change is finished.
2. Relevant checks pass.
3. Documentation and ADR changes are synchronized.
4. The diff has been reviewed.

If the environment or user permissions prevent creating a commit, report that clearly instead of pretending a commit exists.

### Commit Message Format

Use Conventional Commits syntax:

```text
type(scope): concise imperative summary
```

Supported common types include:

```text
feat
fix
refactor
docs
style
test
build
ci
chore
perf
revert
```

Examples:

```text
feat(auth): add authorization consent layout
feat(admin): add application management routes
fix(account): preserve session filter state
refactor(ui): extract shared page header
docs(adr): record frontend routing architecture
build(frontend): configure Semi Design transpilation
chore(deps): add TanStack Query
```

Commit subjects must:

* Use lowercase type names.
* Be concise.
* Describe the actual change.
* Use an imperative form.
* Avoid ending with a period.
* Avoid vague messages such as `update`, `changes`, `fix stuff`, or `wip`.

Use a commit body when the reason, migration impact, or architectural tradeoff is not obvious.

Breaking changes must use either:

```text
feat(scope)!: summary
```

or a `BREAKING CHANGE:` footer.

After each commit, report:

* The commit hash
* The commit message
* The main contents of the commit

## 38. Architecture Decision Records

Continuously document meaningful frontend architecture decisions.

ADR files belong under:

```text
./docs/adr-{version}.md
```

Use a monotonically increasing zero-padded version unless the project already uses another established version format.

Examples:

```text
docs/adr-0001.md
docs/adr-0002.md
docs/adr-0003.md
```

Before creating a new ADR:

1. Inspect existing `docs/adr-*.md` files.
2. Determine the latest version.
3. Decide whether the new decision belongs in an existing ADR or requires a new one.
4. Avoid duplicating an already-recorded decision.

Update an existing ADR when:

* The same decision is being clarified.
* Implementation details changed without replacing the original architectural direction.
* New consequences or constraints were discovered.
* The original decision remains valid.

Create a new ADR when:

* A new architectural choice is introduced.
* An existing architectural decision is replaced.
* A major dependency or framework strategy changes.
* Authentication, authorization, routing, state management, API integration, design-system usage, deployment, or testing architecture changes materially.

Each ADR should use this structure:

```markdown
# ADR-{version}: Decision title

- Status: Proposed | Accepted | Superseded | Deprecated
- Date: YYYY-MM-DD
- Owners: United Pass frontend team

## Context

Describe the problem, constraints, and relevant project state.

## Decision

State the chosen approach clearly.

## Alternatives Considered

Describe meaningful alternatives and why they were not selected.

## Consequences

Describe benefits, tradeoffs, risks, and maintenance impact.

## Implementation Notes

Record important file locations, boundaries, and enforcement details.

## Follow-up

List unresolved work or conditions that may require revisiting the decision.
```

When an ADR replaces an earlier ADR:

* Mark the old ADR as `Superseded`.
* Reference the newer ADR.
* Reference the superseded ADR from the new document.

Do not create ADRs for trivial styling tweaks, typo fixes, or ordinary component implementation details.

The code and ADR must remain synchronized. If a change contradicts an accepted ADR, either update the ADR or create a superseding ADR in the same coherent change.

Include ADR files in the same commit as the architectural implementation they describe whenever practical.

## 39. Semi Design as the Product Design Foundation

Semi Design is the required and primary design system for United Pass.

United Pass should visually and behaviorally align with ByteDance Semi Design rather than merely importing isolated Semi components.

All page and component design must begin by considering whether Semi Design already provides the required:

* Component
* Interaction pattern
* Layout primitive
* Design token
* Form behavior
* Feedback pattern
* Navigation pattern
* Data-display pattern
* Accessibility behavior

Use Semi Design for:

* Navigation
* Buttons
* Forms
* Inputs
* Selects
* Tables
* Cards
* Tabs
* Tags
* Avatars
* Modals
* Side sheets
* Dropdowns
* Tooltips
* Notifications
* Toasts
* Popconfirm interactions
* Empty states
* Skeletons
* Typography
* Pagination
* Breadcrumbs
* Date and time inputs
* Upload interfaces
* Status presentation

Do not recreate a Semi Design component using raw HTML and custom CSS unless:

1. Semi Design does not provide the required behavior.
2. The custom implementation is necessary for a United Pass-specific interaction.
3. The new component still uses Semi Design tokens and follows its interaction language.
4. The reason is documented when the decision is substantial.

### Visual Language

The interface should reflect Semi Design's qualities:

* Clear information hierarchy
* Restrained decoration
* Structured spacing
* Neutral surfaces
* Strong but controlled emphasis
* Consistent interaction feedback
* Dense but readable management interfaces
* Predictable form behavior
* Clear status semantics

Avoid producing a generic AI-dashboard appearance.

Do not add decorative gradients, excessive glass effects, arbitrary glowing borders, oversized rounded cards, or unrelated visual trends unless explicitly required by the product design.

Do not imitate another design system while using Semi Design components underneath.

### Tokens and Theming

Prefer Semi Design tokens for:

* Colors
* Typography
* Borders
* Shadows
* Backgrounds
* Disabled states
* Hover states
* Focus states
* Status colors

Project-specific variables may extend Semi Design, but they must not replace or contradict its token system.

Good:

```css
.page {
  color: var(--semi-color-text-0);
  background: var(--semi-color-bg-0);
  border: 1px solid var(--semi-color-border);
}
```

Avoid:

```css
.page {
  color: #1f2329;
  background: #ffffff;
  border: 1px solid #e5e6eb;
}
```

unless the exact fixed value is part of an approved brand requirement.

### Component Composition

Prefer composing Semi Design components over wrapping every component.

A project wrapper is appropriate when it standardizes meaningful product behavior, for example:

* `PageHeader`
* `EntityStatusTag`
* `DangerConfirm`
* `PermissionGuard`
* `ApplicationAvatar`
* `SecurityEventSeverity`
* `ClientSecretReveal`
* `EmptyState`

Do not create wrappers that merely rename Semi props or obscure its API.

### Forms

Use Semi Design form patterns consistently.

Forms should:

* Use aligned labels and control widths.
* Display validation near the affected field.
* Use Semi feedback states.
* Distinguish help text from validation errors.
* Preserve values after recoverable failures.
* Disable submission while pending.
* Use confirmations for destructive security changes.
* Clearly identify fields that contain sensitive values.

OAuth fields such as Redirect URIs, Client IDs, Scopes, and Secrets must use precise wording and must not be visually simplified in ways that obscure their security meaning.

### Tables and Administration Interfaces

Semi Design tables and management patterns should be the default for administrative data.

Keep:

* Column density intentional
* Actions discoverable
* Status visible
* Filters consistent
* Pagination predictable
* Empty states actionable
* Loading behavior stable

Do not fill every row with many visible buttons. Prefer a primary action plus a controlled overflow menu where appropriate.

### Custom Theme Work

Do not introduce a custom Semi Design theme as an incidental change.

When a custom theme is requested:

1. Record the decision in an ADR.
2. Define brand requirements.
3. Centralize theme configuration.
4. Verify contrast and accessibility.
5. Avoid per-page token overrides.
6. Test major forms, tables, dialogs, navigation, and status colors.

### Light and Dark Modes

United Pass must support both light and dark color modes across authentication, account, authorization, and administration surfaces.

Follow these rules:

1. Use centralized semantic CSS variables for product colors; do not maintain separate per-page palettes.
2. Store only the explicit `light` or `dark` preference in browser storage. When no preference exists, follow `prefers-color-scheme`.
3. Apply the resolved theme before first paint so server-rendered pages do not flash the wrong color mode.
4. Keep the project theme attribute and Semi Design's `theme-mode` attribute synchronized.
5. Theme initialization scripts must be static, contain no user-controlled interpolation, and be reviewed again when a Content Security Policy is introduced.
6. Theme controls must be keyboard accessible, have an accessible name, and communicate through more than color alone.
7. New components must be reviewed in both modes, including focus states, text contrast, status colors, tables, forms, overlays, empty states, and destructive actions.
8. Do not use a dark-mode implementation that weakens Server Component boundaries or forces the root layout to become dynamic solely to read a theme cookie.

### Documentation

When introducing a reusable design pattern, record it in the appropriate project documentation.

Architecturally meaningful design-system choices must also be reflected in the current `docs/adr-{version}.md`.
