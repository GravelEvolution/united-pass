import { isApiError } from "@/lib/api/api-error";

/**
 * A registration CAPTCHA is bound to one form intent and its provider proof is
 * single-use. Both an attempted proof and a cancelled/unavailable interactive
 * prompt make that intent unsuitable for another submit. The registration UI
 * replaces only the intent, preserving the user's uncontrolled form fields.
 */
export function shouldRefreshRegistrationIntent(error: unknown): boolean {
  if (!isApiError(error)) return false;
  if (error.requiresChallengeRefresh === true) return true;
  return error.code === "step_up_required"
    && error.stepUp?.method === "interactive_captcha";
}

export type RegistrationIntentRefreshResult =
  | { handled: false }
  | { handled: true; ready: boolean };

/**
 * Discards the unusable intent before awaiting its replacement. It never
 * retries registration itself: the person reviews the preserved form and
 * explicitly submits again.
 */
export async function refreshRegistrationIntentIfRequired(
  error: unknown,
  discardCurrent: () => void,
  prepareReplacement: () => Promise<boolean>,
): Promise<RegistrationIntentRefreshResult> {
  if (!shouldRefreshRegistrationIntent(error)) return { handled: false };
  discardCurrent();
  return { handled: true, ready: await prepareReplacement() };
}
