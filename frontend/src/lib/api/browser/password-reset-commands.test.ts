import { afterEach, describe, expect, it, vi } from "vitest";
import { isApiError } from "@/lib/api/api-error";
import { confirmPasswordReset, requestPasswordReset } from "./password-reset-commands";

type FetchCall = {
  url: string;
  init: RequestInit;
};

function stubFetch(response: Response): { calls: FetchCall[] } {
  const calls: FetchCall[] = [];
  vi.stubGlobal(
    "fetch",
    vi.fn(async (url: string, init: RequestInit) => {
      calls.push({ url, init });
      return response;
    }),
  );
  return { calls };
}

function jsonResponse(body: string, status = 200): Response {
  return new Response(body, {
    status,
    headers: { "Content-Type": "application/json" },
  });
}

function bodyOf(call: FetchCall): Record<string, unknown> {
  return JSON.parse(String(call.init.body)) as Record<string, unknown>;
}

afterEach(() => {
  vi.unstubAllGlobals();
});

describe("requestPasswordReset", () => {
  it("posts the identifier to the reset request endpoint", async () => {
    const { calls } = stubFetch(jsonResponse('{"status":"accepted"}', 202));

    await requestPasswordReset({ identifier: "ving@example.com" });

    expect(calls).toHaveLength(1);
    expect(calls[0].url).toBe("/api/v1/auth/password-reset");
    expect(calls[0].init.method).toBe("POST");
    expect(bodyOf(calls[0])).toEqual({ identifier: "ving@example.com" });
  });

  it("surfaces rate limiting as a normalized ApiError", async () => {
    stubFetch(jsonResponse('{"error":{"code":"rate_limited","message":"slow down"}}', 429));

    const error = await requestPasswordReset({ identifier: "ving@example.com" }).catch((caught: unknown) => caught);
    expect(isApiError(error) && error.kind === "rate_limited").toBe(true);
  });
});

describe("confirmPasswordReset", () => {
  it("posts token and new password to the confirmation endpoint", async () => {
    const { calls } = stubFetch(new Response(null, { status: 204 }));

    await confirmPasswordReset({ token: "raw-token", newPassword: "Ving123456789." });

    expect(calls).toHaveLength(1);
    expect(calls[0].url).toBe("/api/v1/auth/password-reset/confirm");
    expect(calls[0].init.method).toBe("POST");
    expect(bodyOf(calls[0])).toEqual({ token: "raw-token", newPassword: "Ving123456789." });
  });

  it("keeps the stable invalid-token code", async () => {
    stubFetch(jsonResponse('{"error":{"code":"password.reset_token_invalid","message":"invalid"}}', 422));

    const error = await confirmPasswordReset({ token: "bad", newPassword: "Ving123456789." }).catch((caught: unknown) => caught);
    expect(isApiError(error) && error.code === "password.reset_token_invalid").toBe(true);
  });
});
