//
// Copyright (c) 2026 Chen Jiajie(Ariakage)
//
// Author: Chen Jiajie(Ariakage) <ariakage233@gmail.com>
// Date: 2026-08-16
// Description: Real HTTP contract tests for the final production browser seams
//

import { afterEach, describe, expect, it, vi } from "vitest";
import { browserCommands } from "./browser-commands";

type FetchCall = { url: string; init: RequestInit };

function stubFetch(response: Response): FetchCall[] {
  const calls: FetchCall[] = [];
  vi.stubGlobal("document", { cookie: "up_csrf=csrf-value" });
  vi.stubGlobal("fetch", vi.fn(async (url: string, init: RequestInit) => {
    calls.push({ url, init });
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

describe("final production browser seams", () => {
  it("creates an application and initial client through the atomic backend route", async () => {
    const calls = stubFetch(jsonResponse({
      applicationId: "app_real", clientId: "client_real", clientSecret: "shown-once",
    }, 201));
    const input = {
      application: {
        name: "Portal", description: "Production", audience: "internal" as const,
        ownerId: "user_owner",
      },
      initialClient: {
        name: "Web", profile: "web_server" as const,
        redirectUris: ["https://portal.example.test/callback"], logoutUri: "",
        allowedScopes: ["openid"], consentMode: "always" as const,
      },
    };

    await expect(browserCommands.createApplicationWithInitialClient(input)).resolves.toEqual({
      applicationId: "app_real", clientId: "client_real", clientSecret: "shown-once",
    });
    expect(calls[0].url).toBe("/api/v1/admin/applications/with-initial-client");
    expect(calls[0].init.method).toBe("POST");
    expect(bodyOf(calls[0])).toEqual(input);
    expect(headerOf(calls[0], "X-CSRF-Token")).toBe("csrf-value");
  });

  it("creates a child client without leaking applicationId into the JSON body", async () => {
    const calls = stubFetch(jsonResponse({ clientId: "client_child", clientSecret: "once" }, 201));
    await browserCommands.createOAuthClient({
      applicationId: "app/real", name: "SPA", profile: "spa_mobile",
      redirectUris: ["https://spa.example.test/callback"], logoutUri: "",
      allowedScopes: ["openid"], consentMode: "first_authorization",
    });

    expect(calls[0].url).toBe("/api/v1/admin/applications/app%2Freal/clients");
    expect(bodyOf(calls[0])).not.toHaveProperty("applicationId");
    expect(bodyOf(calls[0])).toMatchObject({ name: "SPA", profile: "spa_mobile" });
  });

  it("persists profile, avatar and verified-contact operations through real routes", async () => {
    let calls = stubFetch(new Response(null, { status: 204 }));
    await browserCommands.updateProfile({ displayName: "Updated", nickname: "U" });
    expect(calls[0].url).toBe("/api/v1/me");
    expect(calls[0].init.method).toBe("PATCH");

    vi.unstubAllGlobals();
    calls = stubFetch(jsonResponse({ avatarUrl: "/api/v1/media/avatars/avt_0123456789abcdef0123456789abcdef.png" }, 201));
    const file = new File([new Uint8Array([1, 2, 3])], "avatar.png", { type: "image/png" });
    await browserCommands.uploadAvatar(file);
    expect(calls[0].url).toBe("/api/v1/me/avatar");
    expect(calls[0].init.body).toBeInstanceOf(FormData);
    expect(headerOf(calls[0], "Content-Type")).toBeNull();

    vi.unstubAllGlobals();
    calls = stubFetch(jsonResponse({ requestId: "contact_capability" }, 201));
    await expect(browserCommands.requestEmailChange("new@example.test")).resolves.toEqual({
      requestId: "contact_capability",
    });
    expect(calls[0].url).toBe("/api/v1/me/email-change-requests");
    expect(bodyOf(calls[0])).toEqual({ value: "new@example.test" });
  });
});
