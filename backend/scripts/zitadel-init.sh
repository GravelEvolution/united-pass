#!/usr/bin/env bash
set -euo pipefail

# ZITADEL development instance initializer.
#
# Bootstraps the local ZITADEL (docker-compose.zitadel.yml) with everything
# the Phase 1.2 integration tests and local development need:
#   - a human test user with password + TOTP
#   - a service account with an API key (key.json) used by the backend
#   - the service account authorized on the organization
#
# Requires: curl, jq, python3 (for TOTP code generation).
#
# Usage:
#   docker compose -f docker-compose.zitadel.yml up -d
#   ./scripts/zitadel-init.sh
#
# The script is idempotent-ish: entities are created only if absent.

BASE_URL="${ZITADEL_BASE_URL:-http://localhost:8080}"
ADMIN_USER="${ZITADEL_ADMIN_USER:-admin@zitadel.localhost}"
ADMIN_PASSWORD="${ZITADEL_ADMIN_PASSWORD:-AdminPassword1!}"

TEST_USER="${ZITADEL_TEST_USER:-zhixing.lin}"
TEST_USER_FULL="${TEST_USER}@zitadel.localhost"
TEST_PASSWORD="${ZITADEL_TEST_PASSWORD:-TestPassword123!}"
TEST_EMAIL="${TEST_USER}@example.com"

OUT_DIR="${BACKEND_DIR:-$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)}/.zitadel"
SA_KEY_FILE="${OUT_DIR}/sa-key.json"
STATE_FILE="${OUT_DIR}/init-state.json"

log() { echo "[zitadel-init] $*"; }
die() { echo "[zitadel-init] error: $*" >&2; exit 1; }

command -v curl >/dev/null || die "curl is required"
command -v jq >/dev/null || die "jq is required"
command -v python3 >/dev/null || die "python3 is required (for TOTP code generation)"

mkdir -p "${OUT_DIR}"

# --- wait for readiness ------------------------------------------------------
log "waiting for ZITADEL at ${BASE_URL}"
for i in $(seq 1 60); do
  if curl -sf "${BASE_URL}/debug/ready" >/dev/null 2>&1; then
    break
  fi
  if [[ "$i" == 60 ]]; then
    die "ZITADEL did not become ready at ${BASE_URL}"
  fi
  sleep 5
done
log "ZITADEL is ready"

# --- get an admin token (password grant, ZITADEL API audience) --------------
admin_token() {
  curl -sf -X POST "${BASE_URL}/oauth/v2/token" \
    -H 'Content-Type: application/x-www-form-urlencoded' \
    --data-urlencode "grant_type=password" \
    --data-urlencode "username=${ADMIN_USER}" \
    --data-urlencode "password=${ADMIN_PASSWORD}" \
    --data-urlencode "scope=openid urn:zitadel:iam:org:project:id:zitadel:aud" \
    | jq -r '.access_token'
}

TOKEN="$(admin_token)" || die "admin login failed (is the firstuser configured?)"
log "admin token acquired"

api() { # method path json-body
  local method="$1" path="$2" body="${3:-}"
  if [[ -n "${body}" ]]; then
    curl -sf -X "${method}" "${BASE_URL}${path}" \
      -H "Authorization: Bearer ${TOKEN}" \
      -H 'Content-Type: application/json' \
      -d "${body}"
  else
    curl -sf -X "${method}" "${BASE_URL}${path}" \
      -H "Authorization: Bearer ${TOKEN}" \
      -H 'Content-Type: application/json'
  fi
}

# --- find or create the test human user --------------------------------------
find_user_by_name() {
  local name="$1"
  local resp
  resp="$(api GET "/v2/users?userName=${name}" 2>/dev/null || true)"
  [[ -n "${resp}" ]] && echo "${resp}" | jq -r '.result[0].userId // empty'
}

USER_ID="$(find_user_by_name "${TEST_USER_FULL}")"
if [[ -z "${USER_ID}" ]]; then
  log "creating test user ${TEST_USER_FULL}"
  USER_ID="$(api POST /v2/users \
    "{\"userName\":\"${TEST_USER_FULL}\",\"profile\":{\"givenName\":\"Zhixing\",\"familyName\":\"Lin\",\"displayName\":\"Zhixing Lin\"},\"email\":{\"email\":\"${TEST_EMAIL}\",\"isVerified\":true},\"password\":{\"password\":\"${TEST_PASSWORD}\"}}" \
    | jq -r '.userId')"
  log "created user ${USER_ID}"
else
  log "user ${TEST_USER_FULL} already exists (${USER_ID})"
fi

# --- register TOTP on the test user (skips if already registered) -----------
totp_code() { # secret
  python3 -c "
import base64, hashlib, hmac, struct, time, sys
secret = sys.argv[1]
key = base64.b32decode(secret.upper())
counter = int(time.time()) // 30
msg = struct.pack('>Q', counter)
digest = hmac.new(key, msg, hashlib.sha1).digest()
offset = digest[-1] & 0x0F
code = (struct.unpack('>I', digest[offset:offset+4])[0] & 0x7FFFFFFF) % 1000000
print(f'{code:06d}')
" "$1"
}

TOTP_URI="$(api POST "/v2/users/${USER_ID}/totp" '{}' 2>/dev/null | jq -r '.uri // empty' || true)"
if [[ -z "${TOTP_URI}" ]]; then
  log "TOTP already registered on ${TEST_USER_FULL}"
else
  SECRET="$(echo "${TOTP_URI}" | sed -n 's/.*secret=\([^&]*\).*/\1/p')"
  CODE="$(totp_code "${SECRET}")"
  api POST "/v2/users/${USER_ID}/totp/verify" "{\"code\":\"${CODE}\"}" >/dev/null
  log "TOTP registered on ${TEST_USER_FULL}"
fi

# --- find or create the service account and its key --------------------------
SA_ID="$(find_user_by_name "up-backend-sa@zitadel.localhost")"
if [[ -z "${SA_ID}" ]]; then
  log "creating service account"
  SA_ID="$(api POST /v2/users \
    '{"userName":"up-backend-sa@zitadel.localhost","serviceAccount":{"description":"United Pass backend API service account"}}' \
    | jq -r '.userId')"
  log "created service account ${SA_ID}"

  # Authorize the service account on the organization (ORG_OWNER grants the
  # user/session API access for the development org).
  api POST /management/v1/orgs/me/members \
    "{\"userId\":\"${SA_ID}\",\"roles\":[\"ORG_OWNER\"]}" >/dev/null || \
    log "warning: could not add service account as org member (manual authorization may be needed)"
fi

if [[ ! -f "${SA_KEY_FILE}" ]]; then
  log "creating service account key"
  api POST "/v2/users/${SA_ID}/keys" '{"type":"KEY_TYPE_JSON"}' > "${SA_KEY_FILE}"
  log "saved service account key to ${SA_KEY_FILE}"
else
  log "service account key already exists at ${SA_KEY_FILE}"
fi

# --- persist state for integration tests -------------------------------------
cat > "${STATE_FILE}" <<EOF
{
  "baseUrl": "${BASE_URL}",
  "keyFile": "${SA_KEY_FILE}",
  "user": "${TEST_USER_FULL}",
  "password": "${TEST_PASSWORD}",
  "userId": "${USER_ID}"
}
EOF
log "state written to ${STATE_FILE}"
log "done. Service account key: ${SA_KEY_FILE}"
log "Integration test env:"
echo "  UP_TEST_ZITADEL_BASE_URL=${BASE_URL}"
echo "  UP_TEST_ZITADEL_KEY_FILE=${SA_KEY_FILE}"
echo "  UP_TEST_ZITADEL_USER=${TEST_USER_FULL}"
echo "  UP_TEST_ZITADEL_PASSWORD=${TEST_PASSWORD}"
echo "  UP_TEST_ZITADEL_TOTP_CODE=<current code from your authenticator app>"
