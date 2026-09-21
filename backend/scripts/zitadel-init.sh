#!/usr/bin/env bash
# Compatibility entrypoint for the single, security-reviewed Go bootstrap.
#
# The Go implementation rejects non-loopback/bare-origin URLs, disables proxy
# inheritance in its HTTP transport, keeps bearer/password/key material out of
# process arguments and logs, and atomically persists protected secret state.

set -euo pipefail

command -v go >/dev/null 2>&1 || {
  printf '%s\n' '[zitadel-init] error: go is required' >&2
  exit 1
}

SCRIPT_DIR="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd -P)"
BACKEND_ROOT="$(cd -- "${SCRIPT_DIR}/.." && pwd -P)"

cd -- "${BACKEND_ROOT}"
exec go run ./cmd/zitadel-bootstrap "$@"
