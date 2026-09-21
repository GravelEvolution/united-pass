//
// Copyright (c) 2026 Chen Jiajie(Ariakage)
//
// Description: Real account profile/contact browser command contract tests
//

import { afterEach, describe, expect, it, vi } from "vitest";
import { browserCommands } from "./browser-commands";
import { ApiResponseShapeError } from "@/lib/api/response-validators";

type FetchCall = { url: string; init: RequestInit };

function stubFetch(responses: Response[]): FetchCall[] {
  const calls: FetchCall[] = [];
  vi.stubGlobal("document", { cookie: "up_csrf=csrf-profile" });
  vi.stubGlobal("fetch", vi.fn(async (url: string, init: RequestInit) => {
    calls.push({ url, init });
    const response = responses.shift();
    if (!response) throw new Error("missing test response");
    return response;
  }));
  return calls;
}

function jsonResponse(value: unknown, status = 200): Response {
  return new Response(JSON.stringify(value), {
    status,
    headers: { "Content-Type": "application/json" },
  });
}

function bodyOf(call: FetchCall): Record<string, unknown> {
  return JSON.parse(String(call.init.body)) as Record<string, unknown>;
}

function headerOf(call: FetchCall, name: string): string | null {
  return new Headers(call.init.headers as HeadersInit).get(name);
}

afterEach(() => vi.unstubAllGlobals());

describe("account profile browser commands", () => {
  it("persists display name and nickname through the real profile endpoint", async () => {
    const calls = stubFetch([new Response(null, { status: 204 })]);

    await browserCommands.updateProfile({ displayName: "月石用户", nickname: "小月" });

    expect(calls[0].url).toBe("/api/v1/me/profile");
    expect(calls[0].init.method).toBe("PATCH");
    expect(bodyOf(calls[0])).toEqual({ displayName: "月石用户", nickname: "小月" });
    expect(headerOf(calls[0], "X-CSRF-Token")).toBe("csrf-profile");
  });

  it("uploads the exact sanitized file as multipart and validates the persisted URL", async () => {
    const calls = stubFetch([jsonResponse({ avatarUrl: "/api/v1/media/avatars/user_abc123?v=3" })]);
    const file = new File([new Uint8Array([0xff, 0xd8, 0xff, 0xd9])], "avatar.jpg", {
      type: "image/jpeg",
    });

    await expect(browserCommands.uploadAvatar(file)).resolves.toEqual({
      avatarUrl: "/api/v1/media/avatars/user_abc123?v=3",
    });

    expect(calls[0].url).toBe("/api/v1/me/avatar");
    expect(calls[0].init.method).toBe("POST");
    expect(headerOf(calls[0], "Content-Type")).toBeNull();
    expect(headerOf(calls[0], "X-CSRF-Token")).toBe("csrf-profile");
    const form = calls[0].init.body as FormData;
    const uploaded = form.get("file");
    expect(uploaded).toBeInstanceOf(File);
    expect((uploaded as File).name).toBe("avatar.jpg");
  });

  it("rejects an avatar response that could load an uncontrolled origin", async () => {
    stubFetch([jsonResponse({ avatarUrl: "https://attacker.example/avatar.png" })]);
    const file = new File([new Uint8Array([1])], "avatar.jpg", { type: "image/jpeg" });

    await expect(browserCommands.uploadAvatar(file)).rejects.toThrow(ApiResponseShapeError);
  });
});

describe("account contact browser commands", () => {
  it("sends the six-character alphanumeric email code unchanged", async () => {
    const requestId = "email_change_0123456789abcdef0123456789abcdef";
    const calls = stubFetch([
      jsonResponse({ status: "verification_required", requestId }, 202),
      jsonResponse({ status: "verified", email: "new@example.com" }),
    ]);

    await expect(browserCommands.requestEmailChange("new@example.com")).resolves.toEqual({ requestId });
    await browserCommands.verifyEmailChange(requestId, "A1B2C3");

    expect(calls[0].url).toBe("/api/v1/me/email-change");
    expect(bodyOf(calls[0])).toEqual({ email: "new@example.com" });
    expect(calls[1].url).toBe("/api/v1/me/email-change/verify");
    expect(bodyOf(calls[1])).toEqual({ requestId, code: "A1B2C3" });
  });

  it("uses the real phone-change endpoints without changing the SMS code", async () => {
    const requestId = "phone_verify_0123456789abcdef0123456789abcdef";
    const calls = stubFetch([
      jsonResponse({ status: "verification_required", requestId }, 202),
      jsonResponse({ status: "verified", phone: "+8613800138000" }),
    ]);

    await expect(browserCommands.requestPhoneChange("13800138000")).resolves.toEqual({ requestId });
    await browserCommands.verifyPhoneChange(requestId, "246810");

    expect(calls[0].url).toBe("/api/v1/me/phone-change");
    expect(calls[1].url).toBe("/api/v1/me/phone-change/verify");
    expect(bodyOf(calls[1])).toEqual({ requestId, code: "246810" });
  });

  it("fails closed when begin-contact response omits the request capability", async () => {
    stubFetch([jsonResponse({ status: "verification_required" }, 202)]);
    await expect(browserCommands.requestEmailChange("new@example.com")).rejects.toThrow(
      ApiResponseShapeError,
    );
  });
});
