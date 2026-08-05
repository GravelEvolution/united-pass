#!/usr/bin/env bash
set -euo pipefail

# United Pass local development launcher.
#
# Orchestrates the SSH tunnel, database migrations, and the API server so a
# developer can go from a clean shell to a running service in one command.
#
# Usage:
#   ./scripts/dev.sh up [--migrate]   # tunnel + (migrate) + API server (foreground)
#   ./scripts/dev.sh migrate          # apply pending migrations through the tunnel
#   ./scripts/dev.sh down             # stop the SSH tunnel
#   ./scripts/dev.sh status           # tunnel state and local port readiness

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
BACKEND_DIR="$(cd "${SCRIPT_DIR}/.." && pwd)"
TUNNEL="${SCRIPT_DIR}/tunnel.sh"

require_env() {
  if [[ ! -f "${BACKEND_DIR}/.env" ]]; then
    echo "error: ${BACKEND_DIR}/.env not found" >&2
    echo "hint: cp .env.template .env and fill in UP_SSH_USER / UP_SSH_KEY and the database credentials" >&2
    exit 1
  fi
}

up() {
  local do_migrate=false
  if [[ "${1:-}" == "--migrate" ]]; then
    do_migrate=true
  fi

  require_env
  "${TUNNEL}" start

  # Stop the tunnel when the API server exits (Ctrl+C or crash).
  trap '"'"${TUNNEL}"'" stop' EXIT

  if [[ "${do_migrate}" == "true" ]]; then
    echo "==> applying migrations"
    (cd "${BACKEND_DIR}" && go run ./cmd/migrate up)
  fi

  echo "==> starting API server (Ctrl+C to stop)"
  (cd "${BACKEND_DIR}" && go run ./cmd/api)
}

migrate() {
  require_env
  "${TUNNEL}" start
  trap '"'"${TUNNEL}"'" stop' EXIT
  (cd "${BACKEND_DIR}" && go run ./cmd/migrate up)
}

down() {
  "${TUNNEL}" stop
}

status() {
  "${TUNNEL}" status
}

case "${1:-}" in
  up)
    up "${2:-}"
    ;;
  migrate)
    migrate
    ;;
  down)
    down
    ;;
  status)
    status
    ;;
  *)
    echo "usage: $0 {up [--migrate]|migrate|down|status}" >&2
    exit 1
    ;;
esac
