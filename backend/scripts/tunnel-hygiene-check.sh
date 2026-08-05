#!/usr/bin/env bash
set -euo pipefail

# Static hygiene check for scripts/tunnel.sh.
#
# Verifies that the SSH password fallback never places the password in
# process arguments (sshpass -p), prints it, or writes it to logs. The
# password must only be passed through the SSHPASS environment variable
# (sshpass -e) and be unset from the controlling shell after startup.
#
# Usage:
#   ./scripts/tunnel-hygiene-check.sh

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
TUNNEL_SCRIPT="${SCRIPT_DIR}/tunnel.sh"

fail() {
  echo "FAIL: $1" >&2
  exit 1
}

[[ -f "${TUNNEL_SCRIPT}" ]] || fail "tunnel.sh not found at ${TUNNEL_SCRIPT}"

# 1. The script must be syntactically valid bash.
bash -n "${TUNNEL_SCRIPT}" || fail "tunnel.sh has a syntax error"

# 2. The password must never be passed as a process argument (sshpass -p).
if grep -nE 'sshpass[[:space:]]+-p' "${TUNNEL_SCRIPT}"; then
  fail "tunnel.sh passes the SSH password as a process argument (sshpass -p)"
fi

# 3. Password mode must use the SSHPASS environment variable (sshpass -e).
grep -qE 'sshpass[[:space:]]+-e' "${TUNNEL_SCRIPT}" \
  || fail "tunnel.sh does not use 'sshpass -e' (SSHPASS environment mode)"

# 4. The password must be dropped from the shell environment after startup.
grep -qE 'unset[[:space:]]+[^#]*SSHPASS' "${TUNNEL_SCRIPT}" \
  || fail "tunnel.sh does not unset SSHPASS after starting the tunnel"

# 5. The password must never be echoed or otherwise printed.
if grep -nE '(echo|printf)[^|]*\$\{?(SSH_PASSWORD|UP_SSH_PASSWORD|SSHPASS)\b' "${TUNNEL_SCRIPT}"; then
  fail "tunnel.sh prints an SSH password variable"
fi

# 6. The password must never be appended to the tunnel log or PID file.
if grep -nE '>>?"\$\{?LOG_FILE\}?[^|]*\$\{?(SSH_PASSWORD|UP_SSH_PASSWORD|SSHPASS)\b' "${TUNNEL_SCRIPT}"; then
  fail "tunnel.sh writes an SSH password variable to the log file"
fi

echo "tunnel.sh hygiene check: passed"
