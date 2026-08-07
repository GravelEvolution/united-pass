#!/usr/bin/env bash
#
# Copyright (c) 2026 Chen Jiajie(Ariakage)
#
# Author: Chen Jiajie(Ariakage) <ariakage233@gmail.com>
# Date: 2026-08-05
# Description: One-time ZITADEL instance bootstrap (org, project, service account)
#

set -euo pipefail

# ZITADEL development instance initializer.
#
# Bootstraps the local ZITADEL (docker-compose.zitadel.yml) with everything
# the Phase 1.2 integration tests and local development need:
#   - a human test user with password + TOTP
#   - a service account (machine user) with an API key (sa-key.json)
#   - the service account authorized on the organization
#
# API facts (verified against zitadel.user.v2):
#   - list users:      POST /v2/users        body {"queries":[...]}  -> result[].userId
#   - create human:    POST /v2/users/human  -> userId
#   - create machine:  POST /v2/users/new    -> id
#   - add key:         POST /v2/users/{id}/keys  -> {keyId, keyContent}
#                      keyContent IS the key.json (type/keyId/key/userId)
#   - register TOTP:   POST /v2/users/{id}/totp -> {uri, secret}
#   - verify TOTP:     POST /v2/users/{id}/totp/verify -> {code}
#
# Requires: curl, jq, python3 (for TOTP code generation).
#
# Usage:
#   docker compose -f docker-compose.zitadel.yml up -d
#   ./scripts/zitadel-init.sh
#
# The script is idempotent-ish: entities are created only if absent. State
# (including the TOTP secret for unattended E2E runs) is written to
# .zitadel/init-state.json.

BASE_URL="${ZITADEL_BASE_URL:-http://localhost:8080}"
ADMIN_USER="${ZITADEL_ADMIN_USER:-admin@zitadel.localhost}"
ADMIN_PASSWORD="${ZITADEL_ADMIN_PASSWORD:-AdminPassword1!}"

TEST_USER="${ZITADEL_TEST_USER:-zhixing.lin}"
TEST_USER_FULL="${TEST_USER}@zitadel.localhost"
TEST_PASSWORD="${ZITADEL_TEST_PASSWORD:-TestPassword123!}"
TEST_EMAIL="${TEST_USER}@example.com"
TEST_FIRST_NAME="${ZITADEL_TEST_FIRST_NAME:-Zhixing}"
TEST_LAST_NAME="${ZITADEL_TEST_LAST_NAME:-Lin}"
TEST_DISPLAY_NAME="${ZITADEL_TEST_DISPLAY_NAME:-Zhixing Lin}"

OUT_DIR="${BACKEND_DIR:-$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)}/.zitadel"
SA_KEY_FILE="${OUT_DIR}/sa-key.json"
STATE_FILE="${OUT_DIR}/init-state.json"
# IAM_OWNER service account key pre-provisioned by docker-compose.zitadel.yml
# (ZITADEL_FIRSTINSTANCE_ORG_MACHINE_MACHINEKEY_TYPE=1 +
# ZITADEL_FIRSTINSTANCE_MACHINEKEYPATH). It is used with JWT profile because
# ZITADEL v2.71+ rejects the resource-owner password grant by default.
INIT_SA_KEY_FILE="${ZITADEL_INIT_SA_KEY_FILE:-${OUT_DIR}/init-sa.json}"

log() { echo "[zitadel-init] $*"; }
die() { echo "[zitadel-init] error: $*" >&2; exit 1; }

command -v curl >/dev/null || die "curl is required"
command -v jq >/dev/null || die "jq is required"
command -v python3 >/dev/null || die "python3 is required (for TOTP code generation)"
command -v openssl >/dev/null || die "openssl is required (for JWT profile signing)"

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

# --- acquire an admin token via JWT profile (service account key) ------------
# The init service account is IAM_OWNER on the default instance. ZITADEL
# v2.71+ disables the resource-owner password grant by default, so we use the
# urn:ietf:params:oauth:grant-type:jwt-bearer grant with the pre-provisioned
# JSON key instead of admin username/password.
b64url() { openssl base64 -A | tr '+/' '-_' | tr -d '='; }

admin_token() {
  local key_id user_id now header payload signing_input sig assertion key_tmp
  [[ -f "${INIT_SA_KEY_FILE}" ]] || die "init service account key missing: ${INIT_SA_KEY_FILE} (start docker-compose.zitadel.yml first)"
  key_id="$(jq -r '.keyId' "${INIT_SA_KEY_FILE}")"
  user_id="$(jq -r '.userId' "${INIT_SA_KEY_FILE}")"
  jq -e '.key != null' "${INIT_SA_KEY_FILE}" >/dev/null || die "init service account key has no private key material"

  now="$(date +%s)"
  header="$(printf '{"alg":"RS256","kid":"%s"}' "${key_id}" | b64url)"
  payload="$(printf '{"iss":"%s","sub":"%s","aud":"%s","iat":%s,"exp":%s}' \
    "${user_id}" "${user_id}" "${BASE_URL}" "$((now-10))" "$((now+600))" | b64url)"
  signing_input="${header}.${payload}"
  key_tmp="$(mktemp)"
  jq -r '.key' "${INIT_SA_KEY_FILE}" > "${key_tmp}"
  chmod 600 "${key_tmp}"
  sig="$(printf '%s' "${signing_input}" | openssl dgst -sha256 -sign "${key_tmp}" | b64url)"
  rm -f "${key_tmp}"
  assertion="${signing_input}.${sig}"

  curl -sf -X POST "${BASE_URL}/oauth/v2/token" \
    -H 'Content-Type: application/x-www-form-urlencoded' \
    --data-urlencode "grant_type=urn:ietf:params:oauth:grant-type:jwt-bearer" \
    --data-urlencode "assertion=${assertion}" \
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
# ZITADEL user v2 lists users via POST /v2/users. The userNameQuery filter is
# unreliable for instance-level tokens in v2.71, so list all users and match
# by preferredLoginName (prefix match on the short name covers the org or
# email domain suffix).
find_user_by_name() {
  local name="$1"
  local resp
  resp="$(curl -sf -X POST "${BASE_URL}/v2/users" \
    -H "Authorization: Bearer ${TOKEN}" \
    -H 'Content-Type: application/json' \
    -d '{}' 2>/dev/null || true)"
  [[ -n "${resp}" ]] && echo "${resp}" | jq -r --arg n "${name}" \
    '.result[] | select((.preferredLoginName // "") | startswith($n)) | .userId // empty' | head -1
}

USER_ID="$(find_user_by_name "${TEST_USER}")"
if [[ -z "${USER_ID}" ]]; then
  log "creating test user ${TEST_USER_FULL}"
  # AddHumanUser: POST /v2/users/human -> {userId}
  USER_ID="$(api POST /v2/users/human \
    "{\"userName\":\"${TEST_USER_FULL}\",\"profile\":{\"givenName\":\"${TEST_FIRST_NAME}\",\"familyName\":\"${TEST_LAST_NAME}\",\"displayName\":\"${TEST_DISPLAY_NAME}\"},\"email\":{\"email\":\"${TEST_EMAIL}\",\"isVerified\":true},\"password\":{\"password\":\"${TEST_PASSWORD}\"}}" \
    | jq -r '.userId')"
  log "created user ${USER_ID}"
else
  log "user ${TEST_USER_FULL} already exists (${USER_ID})"
fi

# --- register TOTP on the test user (skips if already registered) ------------
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

register_totp() {
  local resp secret code
  resp="$(curl -sf -X POST "${BASE_URL}/v2/users/${USER_ID}/totp" \
    -H "Authorization: Bearer ${TOKEN}" \
    -H 'Content-Type: application/json' \
    -d '{}')"
  secret="$(echo "${resp}" | jq -r '.secret')"
  code="$(totp_code "${secret}")"
  curl -sf -X POST "${BASE_URL}/v2/users/${USER_ID}/totp/verify" \
    -H "Authorization: Bearer ${TOKEN}" \
    -H 'Content-Type: application/json' \
    -d "{\"code\":\"${code}\"}" >/dev/null
  echo "${secret}"
}

TOTP_RESP="$(curl -sf -X POST "${BASE_URL}/v2/users/${USER_ID}/totp" \
  -H "Authorization: Bearer ${TOKEN}" \
  -H 'Content-Type: application/json' \
  -d '{}' 2>/dev/null || true)"
TOTP_SECRET="$(echo "${TOTP_RESP}" | jq -r '.secret // empty')"
if [[ -z "${TOTP_SECRET}" ]]; then
  log "TOTP already registered on ${TEST_USER_FULL}"
  # Recover the secret from a previous init-state so E2E stays unattended.
  TOTP_SECRET="$(jq -r '.totpSecret // empty' "${STATE_FILE}" 2>/dev/null || true)"
  if [[ -z "${TOTP_SECRET}" ]]; then
    # No recoverable secret (e.g. init-state from a failed earlier run):
    # remove the stale TOTP and register a fresh one.
    log "no recoverable TOTP secret; re-registering"
    curl -sf -X DELETE "${BASE_URL}/v2/users/${USER_ID}/totp" \
      -H "Authorization: Bearer ${TOKEN}" >/dev/null 2>&1 || true
    TOTP_SECRET="$(register_totp)"
    log "TOTP re-registered on ${TEST_USER_FULL}"
  fi
else
  CODE="$(totp_code "${TOTP_SECRET}")"
  curl -sf -X POST "${BASE_URL}/v2/users/${USER_ID}/totp/verify" \
    -H "Authorization: Bearer ${TOKEN}" \
    -H 'Content-Type: application/json' \
    -d "{\"code\":\"${CODE}\"}" >/dev/null
  log "TOTP registered on ${TEST_USER_FULL}"
fi

# --- find or create the service account and its key --------------------------
SA_ID="$(find_user_by_name "up-backend-sa")"
if [[ -z "${SA_ID}" ]]; then
  log "creating service account (machine user)"
  # Create a machine user. The v2 users API has no machine endpoint in
  # v2.71 (POST /v2/users/new is gone), so use the management v1 API.
  SA_ID="$(api POST /management/v1/users/machine \
    '{"userName":"up-backend-sa@zitadel.localhost","name":"United Pass backend","description":"United Pass backend API service account"}' \
    | jq -r '.userId')"
  log "created service account ${SA_ID}"
fi

# Authorize the service account on the org that owns the test user
# (ORG_OWNER grants session/user API access). The org member endpoint is
# fixed at /orgs/me/members and requires the X-Zitadel-Orgid header to
# target a specific org (IAM-level token context differs from the org).
ORG_ID="$(curl -sf -X POST "${BASE_URL}/v2/users" \
  -H "Authorization: Bearer ${TOKEN}" \
  -H 'Content-Type: application/json' \
  -d '{}' | jq -r --arg u "${USER_ID}" '.result[] | select(.userId == $u) | .details.resourceOwner')"
if [[ -n "${ORG_ID}" ]] && ! curl -sf -X POST "${BASE_URL}/management/v1/orgs/me/members" \
  -H "Authorization: Bearer ${TOKEN}" \
  -H 'Content-Type: application/json' \
  -H "X-Zitadel-Orgid: ${ORG_ID}" \
  -d "{\"userId\":\"${SA_ID}\",\"roles\":[\"ORG_OWNER\"]}" >/dev/null 2>&1; then
  log "warning: could not add service account as org member (manual authorization may be needed)"
fi

if [[ ! -f "${SA_KEY_FILE}" ]]; then
  log "creating service account key"
  # AddKey: POST /management/v1/users/{id}/keys -> {keyId, keyDetails}.
  # keyDetails is a []byte field, which ProtoJSON serializes as a Base64
  # string. It encodes the key.json (type/keyId/key/expirationDate/userId)
  # expected by the SDK and loadServiceAccountKey, so decode it before saving.
  # (The v2 users API has no AddKey endpoint in v2.71.)
  KEY_RESP="$(api POST "/management/v1/users/${SA_ID}/keys" '{"type":1}')"
  echo "${KEY_RESP}" | jq -r '.keyDetails | @base64d' > "${SA_KEY_FILE}"
  chmod 600 "${SA_KEY_FILE}"
  # Validate the decoded key matches the SDK KeyFile shape.
  jq -e '.keyId != null and .key != null and .userId != null' "${SA_KEY_FILE}" >/dev/null \
    || die "generated service account key has an invalid format"
  log "saved service account key to ${SA_KEY_FILE}"
else
  log "service account key already exists at ${SA_KEY_FILE}"
fi

# --- persist state for unattended integration tests --------------------------
cat > "${STATE_FILE}" <<EOF
{
  "baseUrl": "${BASE_URL}",
  "keyFile": "${SA_KEY_FILE}",
  "user": "${TEST_USER_FULL}",
  "password": "${TEST_PASSWORD}",
  "userId": "${USER_ID}",
  "totpSecret": "${TOTP_SECRET}"
}
EOF
log "state written to ${STATE_FILE}"

log "done. Service account key: ${SA_KEY_FILE}"
log "Integration test env:"
echo "  UP_TEST_ZITADEL_BASE_URL=${BASE_URL}"
echo "  UP_TEST_ZITADEL_KEY_FILE=${SA_KEY_FILE}"
echo "  UP_TEST_ZITADEL_USER=${TEST_USER_FULL}"
echo "  UP_TEST_ZITADEL_PASSWORD=${TEST_PASSWORD}"
echo "  UP_TEST_ZITADEL_TOTP_SECRET=${TOTP_SECRET}"
