#!/usr/bin/env bash
#
# Copyright (c) 2026 Chen Jiajie(Ariakage)
#
# Author: Chen Jiajie(Ariakage) <ariakage233@gmail.com>
# Date: 2026-08-07
# Description: Live OAuth topology probe: discovery endpoints and LoginV2
#              interaction path-prefix preservation (ADR-0005 §1)
#

set -euo pipefail

# OAuth endpoint topology probe (ADR-0005 §1, P3.6 acceptance).
#
# Empirically verifies three things against a live provider instance,
# failing closed (exit non-zero) on every violation (P3.8 hardening):
#
#   1. Discovery: the issuer and every protocol endpoint the reverse proxy
#      must expose verbatim (authorization_endpoint, token_endpoint,
#      jwks_uri, userinfo_endpoint, end_session_endpoint,
#      device_authorization_endpoint). A missing issuer or endpoint fails
#      the probe; the displayed "(absent)" marker is never a verdict.
#
#   2. Public-origin integrity: the issuer must equal the probed origin,
#      and every endpoint must be a parseable absolute URL whose origin
#      (scheme://host[:port] — the port is part of the public origin)
#      equals the probed origin. A malformed endpoint URL fails the probe
#      as a parse failure, never as a plain mismatch; a URL carrying a
#      userinfo section (user:password@) is rejected outright — never
#      stripped and accepted, never echoed into the probe's own output.
#
#   3. Path-prefix preservation: an authorization request for an app
#      configured with LoginVersion = LoginV2 and BaseURI =
#      <interaction-base> must redirect to
#      <interaction-base>/login?authRequest=…  — i.e. ZITADEL's
#      url.URL.JoinPath keeps the /_interaction prefix. If the prefix is
#      dropped or re-encoded, the deployment must fall back to a dedicated
#      interaction host (ADR-0005 §1).
#
# Preconditions:
#   - The probe app already exists with LoginVersion = LoginV2 and the
#     derived Interaction Base URI (provisioner, Phase 3.6).
#   - UP_PROBE_REDIRECT_URI is registered on that app.
#
# Side effect: the probe creates ONE pending auth request that is never
# completed and expires unused. No secrets are printed; the observed
# authRequest value is redacted.
#
# Requires: curl, jq.
#
# Usage:
#   UP_PROBE_ORIGIN=http://localhost:8080 \
#   UP_PROBE_CLIENT_ID=<oidc-client-id> \
#   UP_PROBE_REDIRECT_URI=<registered-redirect-uri> \
#   ./scripts/topology-probe.sh
#
# UP_PROBE_INTERACTION_BASE overrides the derived interaction base URI for
# probe-only purposes; production derives it exclusively from
# UP_OAUTH_PUBLIC_ORIGIN (config.OAuthConfig.InteractionBaseURI).

PROBE_ORIGIN="${UP_PROBE_ORIGIN:-http://localhost:8080}"
PROBE_ORIGIN="${PROBE_ORIGIN%/}"
INTERACTION_BASE="${UP_PROBE_INTERACTION_BASE:-${PROBE_ORIGIN}/_interaction}"
INTERACTION_BASE="${INTERACTION_BASE%/}"
CLIENT_ID="${UP_PROBE_CLIENT_ID:-}"
REDIRECT_URI="${UP_PROBE_REDIRECT_URI:-}"

log() { echo "[topology-probe] $*"; }
die() { echo "[topology-probe] error: $*" >&2; exit 1; }

command -v curl >/dev/null || die "curl is required"
command -v jq >/dev/null || die "jq is required"

[[ -n "${CLIENT_ID}" ]] || die "UP_PROBE_CLIENT_ID is required (LoginV2 app provisioned with BaseURI=${INTERACTION_BASE})"
[[ -n "${REDIRECT_URI}" ]] || die "UP_PROBE_REDIRECT_URI is required (must be registered on the probe app)"

log "origin:          ${PROBE_ORIGIN}"
log "interaction base: ${INTERACTION_BASE}"

# --- step 1: discovery -------------------------------------------------------
log "fetching discovery document"
DISCOVERY="$(curl -sf "${PROBE_ORIGIN}/.well-known/openid-configuration")" \
  || die "discovery document unreachable at ${PROBE_ORIGIN}/.well-known/openid-configuration"

endpoint() { echo "${DISCOVERY}" | jq -r --arg k "$1" '.[$k] // "(absent)"'; }

ISSUER="$(endpoint issuer)"

# --- step 1b: fail-closed discovery checks -----------------------------------
# UNTRUSTED-INPUT DISCIPLINE: every discovery value below is printed ONLY
# after it has passed its fail-closed check, never before. A hostile
# discovery document (e.g. an issuer or endpoint carrying user:password@)
# must not be able to smuggle anything into the probe's own output.
#
# The issuer is the probed origin itself; behind the reverse proxy it must
# equal UP_OAUTH_PUBLIC_ORIGIN. Any deviation fails the probe — and the
# offending (untrusted) issuer value is never echoed.
if [[ "${ISSUER}" != "${PROBE_ORIGIN}" ]]; then
  die "discovery issuer does not equal the probed origin ${PROBE_ORIGIN} (behind the reverse proxy the issuer must equal UP_OAUTH_PUBLIC_ORIGIN)"
fi

# url_origin prints the normalized scheme://host[:port] of an absolute URL.
# Any parse failure (missing scheme, missing host, userinfo section) exits
# non-zero: a malformed or credential-bearing endpoint is never treated as
# a plain origin mismatch. The raw URL is deliberately kept out of every
# diagnostic — a hostile discovery document must not be able to smuggle
# user:password@ material into the probe's own output.
url_origin() {
  local u="$1" prefix authority
  case "${u}" in
    http://*)  prefix="http://" ;;
    https://*) prefix="https://" ;;
    *) die "endpoint URL has no http(s) scheme" ;;
  esac
  authority="${u#"${prefix}"}"
  authority="${authority%%/*}"
  authority="${authority%%\?*}"
  authority="${authority%%#*}"
  # userinfo is forbidden on an endpoint: fail closed on it instead of
  # stripping it — stripped credentials would silently normalize a
  # credential-bearing discovery value.
  [[ "${authority}" != *"@"* ]] \
    || die "endpoint URL contains forbidden userinfo"
  [[ -n "${authority}" ]] || die "endpoint URL has no host"
  echo "${prefix}${authority}"
}

# Every protocol endpoint the reverse proxy must expose: absent, malformed
# or served from a different origin (scheme, host or PORT) fails closed.
REQUIRED_ENDPOINTS=(authorization_endpoint token_endpoint jwks_uri userinfo_endpoint end_session_endpoint device_authorization_endpoint)
for key in "${REQUIRED_ENDPOINTS[@]}"; do
  value="$(endpoint "${key}")"
  [[ "${value}" != "(absent)" ]] || die "required discovery endpoint ${key} is missing"
  origin="$(url_origin "${value}")"
  [[ "${origin}" == "${PROBE_ORIGIN}" ]] \
    || die "endpoint ${key} origin ${origin} differs from the probed origin ${PROBE_ORIGIN}"
done
log "discovery checks: issuer and ${#REQUIRED_ENDPOINTS[@]} endpoints all served from ${PROBE_ORIGIN}"

# Discovery results are logged only now that every value has been proven
# safe to print: the issuer equals PROBE_ORIGIN and each endpoint passed
# the userinfo, host and origin checks above.
log "discovery results (validated):"
log "  issuer:                      ${ISSUER}"
for key in "${REQUIRED_ENDPOINTS[@]}"; do
  log "  ${key}: $(endpoint "${key}")"
done

# --- step 2: authorize redirect probe -----------------------------------------
log "issuing authorization request (one pending auth request will be left unused)"
STATE="topology-probe-$(date +%s)"
HEADERS="$(curl -sS -o /dev/null -D - -G "${PROBE_ORIGIN}/oauth/v2/authorize" \
  --data-urlencode "client_id=${CLIENT_ID}" \
  --data-urlencode "redirect_uri=${REDIRECT_URI}" \
  --data-urlencode "response_type=code" \
  --data-urlencode "scope=openid" \
  --data-urlencode "state=${STATE}")" \
  || die "authorize endpoint unreachable (is the probe app registered?)"

STATUS="$(echo "${HEADERS}" | head -1 | awk '{print $2}')"
LOCATION="$(printf '%s\n' "${HEADERS}" | grep -i '^location:' | tail -1 \
  | sed -E 's/^[Ll][Oo][Cc][Aa][Tt][Ii][Oo][Nn]:[[:space:]]*//' | tr -d '\r' || true)"

log "authorize status: ${STATUS}"
if [[ -z "${LOCATION}" ]]; then
  die "no Location header in the authorize response (status ${STATUS}); expected a 3xx redirect"
fi
case "${STATUS}" in
  301|302|303|307|308) ;;
  *) die "unexpected authorize status ${STATUS}; expected a 3xx redirect" ;;
esac

# Redact the authRequest value: it is provider-credential-grade material.
AUTH_REQ="$(printf '%s' "${LOCATION}" | sed -nE 's/.*[?&]authRequest=([^&]+).*/\1/p' || true)"
REDACTED="(none)"
if [[ -n "${AUTH_REQ}" ]]; then
  REDACTED="${AUTH_REQ:0:8}… (redacted, ${#AUTH_REQ} chars)"
fi
log "observed login redirect: ${LOCATION%%\?*}?authRequest=${REDACTED}"

# --- step 3: path-prefix preservation verdict --------------------------------
EXPECTED_PREFIX="${INTERACTION_BASE}/login?authRequest="
if [[ "${LOCATION}" == "${EXPECTED_PREFIX}"* ]]; then
  log "prefix preserved: YES"
  log "the /_interaction path prefix survives ZITADEL's login redirect construction"
  exit 0
fi

log "prefix preserved: NO"
if [[ "${LOCATION}" == "${PROBE_ORIGIN}/login?"* ]]; then
  log "observed a LoginV1-style redirect to ${PROBE_ORIGIN}/login: the probe app is"
  log "not configured with LoginVersion = LoginV2 (provisioner backfill missing?)."
else
  log "observed redirect does not start with ${EXPECTED_PREFIX}."
  log "Deployment must fall back to a dedicated interaction host (ADR-0005 §1)."
fi
exit 1
