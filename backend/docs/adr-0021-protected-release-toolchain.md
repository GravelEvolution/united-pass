# ADR-0021: Formal API releases pin the complete build toolchain and offline cache

- Status: Accepted
- Date: 2026-09-01
- Owners: United Pass backend and release engineering

## Context

The source-bound binary design in ADR-0019 proves that a candidate reports the
reviewed commit and tree, but those linker values do not prove which compiler
produced the remaining machine code. The first formal builder still resolved
`git` and `go` through ambient `PATH` and inherited `GOCACHE`, `GOMODCACHE`,
`GOPATH` and temporary-directory variables. A different compiler or mutable
module cache could therefore produce unreviewed bytes that retained valid
`--build-info` output. A later trusted `go version -m` inspection cannot recover
the identity of the compiler that actually built those bytes.

## Decision

The United Pass API formal release chain accepts only:

- the absolute Node executable currently running the builder or signer, pinned
  by protected CI SHA-256 and exact version on Linux/x64;
- an absolute, read-only, singly linked native Git executable isolated from
  sibling commands and pinned by protected CI SHA-256 and version;
- an absolute `bin/go` inside a recursively read-only complete Go toolchain,
  with both the executable and canonical complete-tree manifest pinned by
  protected CI;
- an external recursively read-only complete offline module cache pinned by its
  canonical tree manifest; and
- fresh private HOME, XDG, temporary, GOPATH and build-cache directories with a
  fixed no-network/no-CGO release environment and no inherited `PATH` or cache
  variables.

The builder checks the Node, Git, Go toolchain and module-cache identities before
and after compilation. It records their versions, digests, counts and byte lengths,
plus the canonical environment-policy digest, in build-record schema v2. The
signer fails on a non-Linux/x64 host before inspecting any path, independently
rehashes the same protected inputs before opening the signing key, copies every
identity into the signed schema-v2 envelope, and performs static Go metadata
inspection only with the pinned `bin/go`. The production gate compares all
signed identities and versions to its own protected CI pins.

The formal output is built outside its requested final path, copied into a
random pending sibling, sealed, and atomically renamed into place. A failed
build or post-publication check quarantines and removes only the initially
captured directory object. A path replacement is preserved and causes a hard
failure rather than a recursive delete.

`GOTOOLCHAIN=local`, `GOPROXY=off`, `GOSUMDB=off`, `GOVCS=*:off`, `GOENV=off`,
`GOWORK=off` and `CGO_ENABLED=0` are defense in depth. The protected runner also
denies network egress.

## Consequences

- Existing API build records without complete toolchain, module-cache and
  environment identities are invalid and must be rebuilt; there is no silent
  legacy fallback.
- Release preparation must provision immutable Node, Git, Go and module-cache inputs
  before the no-key build stage and expose the same pins to the signer and gate.
- Ephemeral Go build caches are intentionally not release inputs: they are
  created inside the private capsule and discarded. The immutable module cache
  is a release input and is always hashed completely.
- Copying only `bin/go`, trusting a version string, or inspecting the finished
  binary with a different Go installation is insufficient.

## Verification

- `scripts/build-release.test.mjs` checks host-first failure, minimal
  environments, absence of bare `git`/`go` invocation, required Node/toolchain
  bindings, atomic publication, identity-safe cleanup, cache drift and hard-link rejection.
- `_release/production-gate.test.mjs` mutates and resigns Node, Git, Go, toolchain,
  module-cache and environment fields and confirms the production gate fails.
- `_release/production-gate-verifier.test.mjs` requires the top-level verifier
  to consume the exact Node version, every protected Go pin and the independently
  measured Git version.
