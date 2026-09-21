#!/usr/bin/env bash
set -euo pipefail

if [[ -z "${UP_TEST_REDIS_URL:-}" ]]; then
  echo "UP_TEST_REDIS_URL must point to a disposable Redis database" >&2
  exit 2
fi

previous_prefix="${UP_TEST_REDIS_KEY_PREFIX-}"
previous_token="${UP_TEST_DISPOSABLE_RUN_TOKEN-}"
run_token="$(od -An -N6 -tx1 /dev/urandom | tr -d ' \n')"
export UP_TEST_DISPOSABLE_RUN_TOKEN="$run_token"
export UP_TEST_REDIS_KEY_PREFIX="up:local-it:${run_token}:"
cleanup() {
  export UP_TEST_REDIS_KEY_PREFIX="$previous_prefix"
  export UP_TEST_DISPOSABLE_RUN_TOKEN="$previous_token"
}
trap cleanup EXIT

go test -race -count=1 ./internal/riskdefense ./internal/registration
go test -race -count=1 ./internal/adapters/httpapi -run 'Test(TrustedClientIP|ClientNetwork|Registration)'
listed="$(go test -tags=integration ./internal/adapters/redis -list 'TestIntegration_(Registration|RiskStoreRegistration)')"
grep -q '^TestIntegration_' <<<"$listed" || { echo "Redis abuse matrix selected zero tests" >&2; exit 2; }
go test -race -tags=integration -count=1 ./internal/adapters/redis -run 'TestIntegration_(Registration|RiskStoreRegistration)'
