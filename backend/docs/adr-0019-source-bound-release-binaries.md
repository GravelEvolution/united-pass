# ADR-0019: Production API binaries are bound to reviewed source objects

- Status: Accepted
- Date: 2026-08-28
- Owners: United Pass backend team

## Context

The running production API archive contains a binary but not its exact source
checkout. Its Go build metadata identifies a modified revision that is absent
from the reviewed repository, so binary behavior cannot be traced back to one
clean source tree. Building the integrated module from a parent monorepository
also does not reliably add Go's automatic VCS settings.

An external artifact signature is still required, but reviewers also need a
small, deterministic way to confirm the source commit and tree embedded in the
candidate binary before it is staged.

## Decision

The API command exposes an exact `--build-info` operation. It prints one JSON
object containing only the 40-character lowercase Git commit and tree object
IDs, the build profile, Go version and target platform. It never loads runtime
configuration and never prints environment values.

Release builders must compile a clean reviewed checkout and set all three
values with Go linker `-X` options:

```text
main.buildSourceCommit=<reviewed HEAD>
main.buildSourceTree=<reviewed HEAD^{tree}>
main.buildProfile=release
```

A process configured with `UP_ENVIRONMENT=production` refuses to start unless
the profile is `release` and both object IDs are canonical lowercase SHA-1
identifiers. Ordinary development and tests retain the explicit
`development/unversioned` default.

The immutable external builder attestation remains authoritative. It must bind
the candidate byte length and SHA-256 to the same reviewed source objects. The
embedded metadata is defense in depth and does not replace two-person review,
artifact signing, secret rotation or deployment receipts.

## Alternatives Considered

- Trust the filename or deployment directory: neither is cryptographically
  bound to binary bytes.
- Depend only on Go automatic VCS metadata: it is absent for some integrated
  repository layouts and therefore fails closed too late.
- Expose metadata from an HTTP health route: that broadens the public contract
  and unnecessarily discloses deployment details to remote callers.

## Consequences

- Production builds without explicit reviewed source bindings no longer start.
- Operators can inspect a candidate offline without credentials or network
  access.
- Rollback artifacts must retain their own matching external attestation and
  embedded source objects.

## Implementation Notes

- CLI implementation: `cmd/api/build_info.go`
- Startup enforcement: `cmd/api/main.go`
- Regression tests: `cmd/api/build_info_test.go`

## Follow-up

- The protected builder must invoke `--build-info` after compilation and bind
  the exact output, binary SHA-256 and byte length into its signed release
  attestation.
