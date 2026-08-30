import { afterEach, describe, expect, it, vi } from "vitest";
import {
  createRegistration,
  resendRegistrationEmail,
  verifyRegistrationEmail,
} from "./registration-commands";

type FetchCall = { url: string; init: RequestInit };

function stubFetch(body: unknown, status = 200): FetchCall[] {
  const calls: FetchCall[] = [];
  vi.stubGlobal("fetch", vi.fn(async (url: string, init: RequestInit) => {
    calls.push({ url, init });
    return new Response(JSON.stringify(body), {
      status,
      headers: { "Content-Type": "application/json" },
    });
  }));
  return calls;
}

function requestBody(call: FetchCall): Record<string, unknown> {
  return JSON.parse(String(call.init.body)) as Record<string, unknown>;
}

afterEach(() => vi.unstubAllGlobals());

describe("registration commands", () => {
  it("creates a registration without sending password confirmation", async () => {
    const calls = stubFetch({
      status: "verification_required",
      registrationToken: "opaque-token",
      expiresAt: "2026-08-18T13:00:00Z",
    }, 201);

    const result = await createRegistration({
      username: "moonstone",
      displayName: "月石选手",
      email: "player@example.com",
      password: "correct horse battery staple",
      acceptedTerms: true,
      requestId: "request-1",
    });

    expect(calls[0].url).toBe("/api/v1/registrations");
    expect(calls[0].init.method).toBe("POST");
    expect(requestBody(calls[0])).toEqual({
      username: "moonstone",
      displayName: "月石选手",
      email: "player@example.com",
      password: "correct horse battery staple",
      acceptedTerms: true,
      requestId: "request-1",
    });
    expect(result.registrationToken).toBe("opaque-token");
  });

  it("verifies the fragment credentials and returns the validated request ID", async () => {
    const calls = stubFetch({ status: "verified", requestId: "request-1" });
    const result = await verifyRegistrationEmail({
      userId: "user_0123456789abcdef0123456789abcdef",
      code: "one-time-code",
      requestId: "request-1",
    });

    expect(calls[0].url).toBe("/api/v1/registrations/email/verify");
    expect(requestBody(calls[0])).toEqual({
      userId: "user_0123456789abcdef0123456789abcdef",
      code: "one-time-code",
      requestId: "request-1",
    });
    expect(result).toEqual({ status: "verified", requestId: "request-1" });
  });

  it("resends using only the opaque registration token", async () => {
    const calls = stubFetch({ status: "verification_sent" }, 202);
    await resendRegistrationEmail("opaque-token");

    expect(calls[0].url).toBe("/api/v1/registrations/email/resend");
    expect(requestBody(calls[0])).toEqual({ registrationToken: "opaque-token" });
  });
});
