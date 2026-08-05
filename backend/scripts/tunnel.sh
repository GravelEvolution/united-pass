#!/usr/bin/env bash
set -euo pipefail

# United Pass development SSH tunnel manager.
#
# Maps the remote PostgreSQL and Redis ports to localhost so the API server
# and integration tests connect over the loopback interface only. Plaintext
# traffic never leaves the local machine; the public network is only reached
# through the SSH transport layer, which is encrypted.
#
# This satisfies ADR-0002: "No downgrade to plaintext for public network
# connections." The database URLs in .env must point at the local tunnel
# ports (e.g. 127.0.0.1:15432, 127.0.0.1:16379), never at the public IP.
#
# Usage:
#   ./scripts/tunnel.sh start     # establish the tunnels
#   ./scripts/tunnel.sh stop      # tear the tunnels down
#   ./scripts/tunnel.sh status    # report tunnel and port state
#   ./scripts/tunnel.sh restart   # stop, then start

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
BACKEND_DIR="$(cd "${SCRIPT_DIR}/.." && pwd)"

# Load .env without overriding variables that are already exported.
if [[ -f "${BACKEND_DIR}/.env" ]]; then
  set -a
  # shellcheck disable=SC1091
  source "${BACKEND_DIR}/.env"
  set +a
fi

# --- Configuration (override via environment or .env) ---
SSH_HOST="${UP_SSH_HOST:-}"
SSH_PORT="${UP_SSH_PORT:-22}"
SSH_USER="${UP_SSH_USER:-}"
SSH_KEY="${UP_SSH_KEY:-${HOME}/.ssh/id_ed25519}"

LOCAL_PG_PORT="${UP_LOCAL_PG_PORT:-15432}"
LOCAL_REDIS_PORT="${UP_LOCAL_REDIS_PORT:-16379}"
REMOTE_PG_PORT="${UP_REMOTE_PG_PORT:-5432}"
REMOTE_REDIS_PORT="${UP_REMOTE_REDIS_PORT:-6379}"
# Remote services are assumed to listen on 127.0.0.1 on the server. Change
# these if they bind elsewhere (e.g. a docker network address).
REMOTE_DB_BIND="${UP_REMOTE_DB_BIND:-127.0.0.1}"
REMOTE_REDIS_BIND="${UP_REMOTE_REDIS_BIND:-127.0.0.1}"

# Tunnel runtime state (both are gitignored).
PID_FILE="${BACKEND_DIR}/.tunnel.pid"
LOG_FILE="${BACKEND_DIR}/.tunnel.log"

TUNNEL_READY_TIMEOUT=30 # seconds

require_config() {
  if [[ -z "${SSH_HOST}" || -z "${SSH_USER}" ]]; then
    echo "error: SSH tunnel requires UP_SSH_HOST and UP_SSH_USER (set them in .env)" >&2
    exit 1
  fi
  if [[ ! -f "${SSH_KEY}" ]]; then
    echo "error: SSH key not found: ${SSH_KEY} (set UP_SSH_KEY)" >&2
    exit 1
  fi
}

tunnel_pid() {
  if [[ -f "${PID_FILE}" ]]; then
    cat "${PID_FILE}"
  fi
}

is_running() {
  local pid
  pid="$(tunnel_pid)"
  [[ -n "${pid}" ]] && kill -0 "${pid}" 2>/dev/null
}

port_ready() {
  local host="$1" port="$2"
  (exec 3<>"/dev/tcp/${host}/${port}") 2>/dev/null
}

wait_for_tunnel() {
  local deadline=$((SECONDS + TUNNEL_READY_TIMEOUT))
  while ((SECONDS < deadline)); do
    if port_ready 127.0.0.1 "${LOCAL_PG_PORT}" && port_ready 127.0.0.1 "${LOCAL_REDIS_PORT}"; then
      echo "tunnel ready: both local ports are accepting connections"
      return 0
    fi
    sleep 1
  done
  echo "error: tunnel did not become ready within ${TUNNEL_READY_TIMEOUT}s" >&2
  echo "--- last tunnel log lines ---" >&2
  tail -n 20 "${LOG_FILE}" >&2 2>/dev/null || true
  stop >/dev/null 2>&1 || true
  return 1
}

start() {
  require_config
  if is_running; then
    echo "tunnel already running (pid $(tunnel_pid))"
    return 0
  fi

  echo "starting SSH tunnel ${SSH_USER}@${SSH_HOST}:${SSH_PORT} ->"
  echo "  postgres 127.0.0.1:${LOCAL_PG_PORT} -> ${REMOTE_DB_BIND}:${REMOTE_PG_PORT}"
  echo "  redis    127.0.0.1:${LOCAL_REDIS_PORT} -> ${REMOTE_REDIS_BIND}:${REMOTE_REDIS_PORT}"

  nohup ssh \
    -i "${SSH_KEY}" \
    -p "${SSH_PORT}" \
    -N \
    -L "127.0.0.1:${LOCAL_PG_PORT}:${REMOTE_DB_BIND}:${REMOTE_PG_PORT}" \
    -L "127.0.0.1:${LOCAL_REDIS_PORT}:${REMOTE_REDIS_BIND}:${REMOTE_REDIS_PORT}" \
    -o ExitOnForwardFailure=yes \
    -o ServerAliveInterval=30 \
    -o ServerAliveCountMax=3 \
    -o ControlMaster=no \
    -o ConnectTimeout=10 \
    "${SSH_USER}@${SSH_HOST}" >"${LOG_FILE}" 2>&1 &

  echo $! > "${PID_FILE}"

  wait_for_tunnel
}

stop() {
  local pid
  pid="$(tunnel_pid)"

  if [[ -z "${pid}" ]] || ! kill -0 "${pid}" 2>/dev/null; then
    echo "tunnel is not running"
    rm -f "${PID_FILE}"
    return 0
  fi

  echo "stopping tunnel (pid ${pid})"
  kill "${pid}" 2>/dev/null || true
  for _ in $(seq 1 20); do
    if ! kill -0 "${pid}" 2>/dev/null; then
      break
    fi
    sleep 0.2
  done
  if kill -0 "${pid}" 2>/dev/null; then
    echo "warning: tunnel did not exit cleanly; sending SIGKILL" >&2
    kill -9 "${pid}" 2>/dev/null || true
  fi
  rm -f "${PID_FILE}"
  echo "tunnel stopped"
}

status() {
  if is_running; then
    echo "tunnel: running (pid $(tunnel_pid))"
  else
    echo "tunnel: not running"
  fi
  echo "postgres 127.0.0.1:${LOCAL_PG_PORT}: $(port_ready 127.0.0.1 "${LOCAL_PG_PORT}" && echo open || echo closed)"
  echo "redis    127.0.0.1:${LOCAL_REDIS_PORT}: $(port_ready 127.0.0.1 "${LOCAL_REDIS_PORT}" && echo open || echo closed)"
}

case "${1:-}" in
  start)
    start
    ;;
  stop)
    stop
    ;;
  restart)
    stop
    start
    ;;
  status)
    status
    ;;
  *)
    echo "usage: $0 {start|stop|restart|status}" >&2
    exit 1
    ;;
esac
