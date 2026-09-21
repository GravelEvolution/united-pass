import { isApiError } from "@/lib/api/api-error";

// A form intent is single-use once provisioning is reached, and a failed or
// cancelled risk challenge also spends the one chain replay. Refresh after
// every ambiguous/post-validation failure, while preserving the same intent
// for the explicit minimum-age response so the user can simply wait and retry.
export function registrationIntentNeedsRefresh(errorValue: unknown): boolean {
  if (!isApiError(errorValue)) return true;
  if (errorValue.code === "registration.form_not_ready" || errorValue.code === "registration.closed") {
    return false;
  }
  return errorValue.requiresChallengeRefresh === true
    || errorValue.code === "registration.form_invalid"
    || errorValue.code === "registration.conflict"
    || errorValue.code === "validation.failed"
    || errorValue.code === "step_up_required"
    || errorValue.kind === "network"
    || errorValue.kind === "server_error"
    || errorValue.kind === "unauthorized"
    || errorValue.kind === "conflict"
    || errorValue.kind === "validation";
}
