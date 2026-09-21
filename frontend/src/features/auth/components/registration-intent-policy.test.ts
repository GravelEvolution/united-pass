import { describe, expect, it } from "vitest";
import type { ApiError } from "@/lib/api/api-error";
import { registrationIntentNeedsRefresh } from "./registration-intent-policy";

function apiError(overrides: Partial<ApiError>): ApiError {
  return { kind: "server_error", message: "failed", ...overrides };
}

describe("registrationIntentNeedsRefresh", () => {
  it.each([
    apiError({ kind: "validation", code: "registration.form_invalid" }),
    apiError({ kind: "conflict", code: "registration.conflict" }),
    apiError({ kind: "validation", code: "validation.failed" }),
    apiError({ kind: "unauthorized", code: "step_up_required" }),
    apiError({ kind: "unauthorized" }),
    apiError({ kind: "network" }),
    apiError({ kind: "server_error" }),
    apiError({ kind: "validation", requiresChallengeRefresh: true }),
  ])("refreshes an intent after a consumed or ambiguous request %#", (error) => {
    expect(registrationIntentNeedsRefresh(error)).toBe(true);
  });

  it.each([
    apiError({ kind: "validation", code: "registration.form_not_ready" }),
    apiError({ kind: "not_found", code: "registration.closed" }),
    apiError({ kind: "rate_limited" }),
  ])("preserves an intent that is explicitly still reusable %#", (error) => {
    expect(registrationIntentNeedsRefresh(error)).toBe(false);
  });

  it("refreshes after an unclassified client exception", () => {
    expect(registrationIntentNeedsRefresh(new Error("unknown"))).toBe(true);
  });
});
