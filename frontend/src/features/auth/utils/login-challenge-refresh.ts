import { isApiError } from "@/lib/api/api-error";

/**
 * Step-up proofs are single-use. Once a step-up-backed login has failed, the
 * page and any provider state must be recreated before credentials are
 * submitted again.
 */
export function shouldRefreshLoginChallenge(error: unknown): boolean {
  return isApiError(error) && error.requiresChallengeRefresh === true;
}

/** Executes the login-only full-page reset and reports whether it handled the error. */
export function refreshLoginChallengeIfRequired(
  error: unknown,
  reload: () => void = () => window.location.reload(),
): boolean {
  if (!shouldRefreshLoginChallenge(error)) return false;
  reload();
  return true;
}
